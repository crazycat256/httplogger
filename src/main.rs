mod browser;
mod ca;
mod config;
mod filter;
mod http_raw;
mod proxy;
mod server;
mod storage;
mod websocket;

use anyhow::{bail, Context, Result};
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{error, info};

enum Command {
    Help,
    Init { force: bool },
    Proxy { key_path: Option<PathBuf> },
    Launch {
        key_path: Option<PathBuf>,
        browser: Option<String>,
        browser_args: Vec<String>,
    },
}

fn usage() -> &'static str {
    "usage: httplogger <command>

commands:
  init              create httplogger.yml, CA, and browser home
  proxy [--key PATH]  start MITM proxy (Ctrl+C to stop)
  launch [--key PATH] [NAME|PATH] [--] [browser args...]  start proxy and browser

launch:
  browser args are only forwarded after --"
}

fn split_at_double_dash(mut args: Vec<String>) -> (Vec<String>, Vec<String>) {
    if let Some(pos) = args.iter().position(|arg| arg == "--") {
        let browser_args = args.split_off(pos + 1);
        args.pop();
        (args, browser_args)
    } else {
        (args, Vec::new())
    }
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--help" || arg == "-h")
}

fn help_target(args: &[String]) -> bool {
    let end = args.iter().position(|arg| arg == "--").unwrap_or(args.len());
    wants_help(&args[..end])
}

fn workspace_root() -> Result<PathBuf> {
    env::var("WORKSPACE_ROOT")
        .map(PathBuf::from)
        .or_else(|_| env::current_dir().context("failed to get current directory"))
}

fn take_flag(args: &mut Vec<String>, flags: &[&str], value_name: &str) -> Result<Option<String>> {
    let mut value = None;
    let mut index = 0;
    while index < args.len() {
        if flags.iter().any(|flag| args[index] == *flag) {
            let flag = args.remove(index);
            if index >= args.len() {
                bail!("{flag} requires {value_name}");
            }
            if value.is_some() {
                bail!("{} may only be specified once", flags[0]);
            }
            value = Some(args.remove(index));
            continue;
        }
        index += 1;
    }
    Ok(value)
}

fn take_first_positional(args: &mut Vec<String>) -> Option<String> {
    let index = args.iter().position(|arg| !arg.starts_with('-'))?;
    Some(args.remove(index))
}

fn parse_command() -> Result<Command> {
    let mut args: Vec<String> = env::args().skip(1).collect();

    if help_target(&args) {
        return Ok(Command::Help);
    }

    match args.first().map(String::as_str) {
        Some("init") => {
            args.remove(0);
            let force = args.iter().any(|arg| arg == "--force");
            if args.iter().any(|arg| arg != "--force") {
                bail!("usage: httplogger init [--force]");
            }
            Ok(Command::Init { force })
        }
        Some("proxy") => {
            args.remove(0);
            let key_path = take_flag(&mut args, &["--key"], "a path to the CA private key PEM file")?
                .map(PathBuf::from);
            if !args.is_empty() {
                bail!("usage: httplogger proxy [--key <ca-key.pem>]");
            }
            Ok(Command::Proxy { key_path })
        }
        Some("launch") => {
            args.remove(0);
            let (mut httplogger_args, browser_args) = split_at_double_dash(args);
            if wants_help(&httplogger_args) {
                return Ok(Command::Help);
            }
            let key_path = take_flag(
                &mut httplogger_args,
                &["--key"],
                "a path to the CA private key PEM file",
            )?
            .map(PathBuf::from);
            let browser = take_first_positional(&mut httplogger_args);
            if !httplogger_args.is_empty() {
                bail!(
                    "unexpected argument(s): {}\n\n{}",
                    httplogger_args.join(" "),
                    usage()
                );
            }
            Ok(Command::Launch {
                key_path,
                browser,
                browser_args,
            })
        }
        Some(_) => bail!("{}\n\nunknown command: {}", usage(), args[0]),
        None => bail!("{}", usage()),
    }
}

struct Session {
    root: PathBuf,
    config: Arc<config::AppConfig>,
    ca: ca::CaMaterial,
    home: PathBuf,
}

fn prepare_session(key_path: Option<PathBuf>) -> Result<Session> {
    let root = workspace_root()?;
    let config = Arc::new(config::load_or_init(&root)?);
    let ca = ca::ensure_ca(&root, key_path)?;
    let home = browser::ensure_browser_home(
        &root,
        &ca.cert_pem,
        config.mitm_proxy_port,
        config.user_agent.as_deref(),
    )?;
    Ok(Session {
        root,
        config,
        ca,
        home,
    })
}

fn run_init(force: bool) -> Result<()> {
    let root = workspace_root()?;
    let path = config::init_config(&root, force)?;
    println!("created {}", path.display());
    let ca = ca::ensure_ca(&root, None)?;
    let config = config::load_or_init(&root)?;
    browser::ensure_browser_home(
        &root,
        &ca.cert_pem,
        config.mitm_proxy_port,
        config.user_agent.as_deref(),
    )?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "httplogger=info,hudsucker=warn,hudsucker::proxy::internal=off".into()
            }),
        )
        .init();

    match parse_command()? {
        Command::Help => {
            println!("{}", usage());
            Ok(())
        }
        Command::Init { force } => run_init(force),
        Command::Proxy { key_path } => run_proxy_only(key_path).await,
        Command::Launch {
            key_path,
            browser,
            browser_args,
        } => run_launch(key_path, browser, browser_args).await,
    }
}

async fn run_proxy_only(key_path: Option<PathBuf>) -> Result<()> {
    let session = prepare_session(key_path)?;
    browser::print_proxy_usage(
        &session.root,
        session.config.mitm_proxy_port,
        &session.ca.cert_path,
        session.config.user_agent.as_deref(),
    )?;

    server::run(
        &session.root,
        session.config,
        session.ca,
        async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to listen for Ctrl+C");
            info!("shutting down (Ctrl+C)");
        },
    )
    .await
}

async fn run_launch(
    key_path: Option<PathBuf>,
    browser: Option<String>,
    browser_args: Vec<String>,
) -> Result<()> {
    let session = prepare_session(key_path)?;

    let selection = browser::resolve_browser(browser.as_deref())?;
    info!(
        browser = %selection.executable.display(),
        kind = ?selection.kind,
        "selected browser"
    );

    let browser_child = browser::launch(
        &selection,
        &session.home,
        session.config.mitm_proxy_port,
        session.config.user_agent.as_deref(),
        &browser_args,
    )?;
    let browser_child = Arc::new(Mutex::new(browser_child));
    let (browser_exit_tx, browser_exit_rx) = tokio::sync::oneshot::channel();

    {
        let watch_child = Arc::clone(&browser_child);
        std::thread::spawn(move || {
            loop {
                let done = {
                    let mut guard = watch_child.lock().expect("browser child mutex poisoned");
                    match guard.try_wait() {
                        Ok(Some(status)) => {
                            info!(?status, "browser exited");
                            true
                        }
                        Ok(None) => false,
                        Err(err) => {
                            error!(%err, "failed to poll browser process");
                            true
                        }
                    }
                };
                if done {
                    let _ = browser_exit_tx.send(());
                    return;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        });
    }

    let shutdown_child = Arc::clone(&browser_child);
    server::run(
        &session.root,
        session.config,
        session.ca,
        async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("shutting down (Ctrl+C)");
                    if let Ok(mut child) = shutdown_child.lock() {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                }
                _ = browser_exit_rx => {
                    info!("shutting down (browser closed)");
                }
            }
        },
    )
    .await?;
    Ok(())
}
