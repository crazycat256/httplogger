use anyhow::{bail, Context, Result};
use std::env;
use std::ffi::OsStr;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tracing::info;

pub const BROWSER_HOME_DIR: &str = "home";
const CHROME_PROFILE_DIR: &str = "chrome-profile";
const FIREFOX_BASE_DIR: &str = ".mozilla/firefox";
const FIREFOX_PROFILE_ENTRY: &str = "httplogger.default";
const FIREFOX_PROFILES_INI: &str = "[General]
StartWithLastProfile=1
Version=2

[Profile0]
Name=httplogger
IsRelative=1
Path=httplogger.default
Default=1
";

fn firefox_profile_dir(home: &Path) -> PathBuf {
    home.join(FIREFOX_BASE_DIR).join(FIREFOX_PROFILE_ENTRY)
}

const CHROMIUM_FAMILY: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome-stable",
    "google-chrome",
    "brave-browser",
    "microsoft-edge-stable",
    "vivaldi-stable",
];
const FIREFOX_FAMILY: &[&str] = &[
    "firefox",
    "firefox-esr",
    "librewolf",
    "waterfox",
    "floorp",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserKind {
    Chromium,
    Firefox,
}

#[derive(Debug, Clone)]
pub struct BrowserSelection {
    pub kind: BrowserKind,
    pub executable: PathBuf,
}

pub fn browser_home(workspace_root: &Path) -> PathBuf {
    workspace_root.join(BROWSER_HOME_DIR)
}

pub fn ensure_browser_home(
    workspace_root: &Path,
    ca_pem: &str,
    proxy_port: u16,
    user_agent: Option<&str>,
) -> Result<PathBuf> {
    let home = browser_home(workspace_root);
    std::fs::create_dir_all(&home).context("failed to create browser home")?;

    let ca_path = home.join("ca.pem");
    if !ca_path.exists() {
        std::fs::write(&ca_path, ca_pem).context("failed to write CA certificate")?;
    }

    if !home.join(".pki").exists() {
        setup_chromium_home(&home, &ca_path)?;
    }

    let firefox_profile = firefox_profile_dir(&home);
    if !firefox_profile.join("cert9.db").exists() {
        setup_firefox_profile(&home, &ca_path)?;
    }
    write_firefox_user_js(&firefox_profile, proxy_port, user_agent)?;

    if let Some(real_home) = real_user_home() {
        link_desktop_integration(&home, &real_home)?;
    }

    Ok(home)
}

pub fn resolve_browser(browser: Option<&str>) -> Result<BrowserSelection> {
    if let Some(spec) = browser {
        resolve_explicit(spec)
    } else {
        resolve_default_webbrowser()
    }
}

pub fn print_proxy_usage(
    workspace_root: &Path,
    proxy_port: u16,
    ca_cert_path: &Path,
    user_agent: Option<&str>,
) -> Result<()> {
    let color = std::io::stdout().is_terminal();
    let home = browser_home(workspace_root)
        .canonicalize()
        .unwrap_or_else(|_| browser_home(workspace_root));
    let ca_cert = ca_cert_path
        .canonicalize()
        .unwrap_or_else(|_| ca_cert_path.to_path_buf());
    let proxy = format!("http://127.0.0.1:{proxy_port}");

    println!();
    println!(
        "{}",
        paint(color, "\x1b[1;32m", &format!("MITM proxy listening on {proxy}"))
    );
    println!();

    if find_family_executable(CHROMIUM_FAMILY).is_some() {
        println!(
            "{}",
            paint(
                color,
                "\x1b[1;33m",
                &format!("Chromium-based (CA trusted via ./{BROWSER_HOME_DIR}/.pki):")
            )
        );
        println!(
            "{}",
            paint(
                color,
                "\x1b[36m",
                &format_shell_command(
                    &home,
                    "chromium",
                    &chromium_argv(&home, proxy_port, user_agent),
                )
            )
        );
        println!();
    }

    if find_family_executable(FIREFOX_FAMILY).is_some() {
        println!(
            "{}",
            paint(
                color,
                "\x1b[1;33m",
                &format!(
                    "Firefox-based (CA trusted via ./{BROWSER_HOME_DIR}/{FIREFOX_BASE_DIR}/{FIREFOX_PROFILE_ENTRY}):"
                )
            )
        );
        println!(
            "{}",
            paint(
                color,
                "\x1b[36m",
                &format_shell_command(
                    &home,
                    "firefox",
                    &firefox_argv(&firefox_profile_dir(&home), &[]),
                ),
            )
        );
        println!();
    }

    println!(
        "{}",
        paint(color, "\x1b[1;33m", "CA certificate (manual import):")
    );
    println!(
        "{}",
        paint(color, "\x1b[2m", &ca_cert.display().to_string())
    );
    println!();
    Ok(())
}

fn paint(color: bool, code: &str, text: &str) -> String {
    if color {
        format!("{code}{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn chromium_argv(home: &Path, proxy_port: u16, user_agent: Option<&str>) -> Vec<String> {
    let profile_dir = home.join(CHROME_PROFILE_DIR);
    let mut args = vec![
        format!("--user-data-dir={}", profile_dir.display()),
        "--no-first-run".into(),
        "--disable-sync".into(),
        "--disable-background-networking".into(),
        "--disable-features=ChromeWhatsNew".into(),
        format!("--proxy-server=http://127.0.0.1:{proxy_port}"),
        "--proxy-bypass-list=<-loopback>".into(),
    ];
    if let Some(user_agent) = user_agent {
        args.push(format!("--user-agent={user_agent}"));
    }
    args
}

fn firefox_argv(profile: &Path, extra_args: &[String]) -> Vec<String> {
    let mut args = vec![
        "-no-remote".into(),
        "-profile".into(),
        profile.display().to_string(),
    ];
    if !extra_args.iter().any(|arg| is_url_like(arg)) {
        args.push("-url".into());
        args.push("about:newtab".into());
    }
    args
}

fn is_url_like(arg: &str) -> bool {
    arg.starts_with("http://") || arg.starts_with("https://") || arg.starts_with("about:")
}

fn format_shell_command(home: &Path, binary: &str, args: &[String]) -> String {
    let mut parts = vec![
        format!("HOME={}", shell_quote(&home.display().to_string())),
        binary.to_string(),
    ];
    parts.extend(args.iter().map(|arg| shell_quote(arg)));
    parts.join(" ")
}

/// Desktop session paths (respects XDG_* when set on the host).
struct SessionPaths {
    config: PathBuf,
    cache: PathBuf,
    state: PathBuf,
    data_share: PathBuf,
}

fn session_paths(real_home: &Path) -> SessionPaths {
    SessionPaths {
        config: xdg_path("XDG_CONFIG_HOME", real_home, ".config"),
        cache: xdg_path("XDG_CACHE_HOME", real_home, ".cache"),
        state: xdg_path("XDG_STATE_HOME", real_home, ".local/state"),
        data_share: xdg_path("XDG_DATA_HOME", real_home, ".local/share"),
    }
}

fn link_desktop_integration(ssl_home: &Path, real_home: &Path) -> Result<()> {
    let session = session_paths(real_home);

    symlink_if_absent(&ssl_home.join(".config"), &session.config)?;
    symlink_if_absent(&ssl_home.join(".cache"), &session.cache)?;

    std::fs::create_dir_all(ssl_home.join(".local")).context("failed to create .local")?;
    symlink_if_absent(&ssl_home.join(".local/state"), &session.state)?;
    link_local_share_entries(ssl_home, &session.data_share)?;

    for name in [".kde", ".kde4"] {
        let target = real_home.join(name);
        if target.exists() {
            symlink_if_absent(&ssl_home.join(name), &target)?;
        }
    }

    Ok(())
}

fn link_local_share_entries(ssl_home: &Path, real_share: &Path) -> Result<()> {
    let fake_share = ssl_home.join(".local/share");
    std::fs::create_dir_all(&fake_share).context("failed to create .local/share")?;

    if !real_share.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(real_share).with_context(|| {
        format!("failed to read {}", real_share.display())
    })? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "pki" {
            continue;
        }
        symlink_if_absent(&fake_share.join(&name), &entry.path())?;
    }

    Ok(())
}

#[cfg(unix)]
fn symlink_if_absent(link: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    if link.symlink_metadata().is_ok() || link.exists() {
        return Ok(());
    }
    if !target.exists() {
        return Ok(());
    }
    let target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());
    symlink(&target, link).with_context(|| {
        format!(
            "failed to symlink {} -> {}",
            link.display(),
            target.display()
        )
    })
}

#[cfg(not(unix))]
fn symlink_if_absent(_link: &Path, _target: &Path) -> Result<()> {
    Ok(())
}

fn real_user_home() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

fn xdg_path(var: &str, real_home: &Path, relative_default: &str) -> PathBuf {
    env::var_os(var)
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| real_home.join(relative_default))
}

pub fn launch(
    selection: &BrowserSelection,
    home: &Path,
    proxy_port: u16,
    user_agent: Option<&str>,
    extra_args: &[String],
) -> Result<std::process::Child> {
    match selection.kind {
        BrowserKind::Chromium => launch_chromium(
            &selection.executable,
            home,
            proxy_port,
            user_agent,
            extra_args,
        ),
        BrowserKind::Firefox => launch_firefox(&selection.executable, home, extra_args),
    }
}

fn resolve_explicit(spec: &str) -> Result<BrowserSelection> {
    let path = resolve_binary(spec).ok_or_else(|| {
        if spec.contains('/') || spec.contains('\\') {
            anyhow::anyhow!("browser not found: {spec}")
        } else {
            anyhow::anyhow!("browser not found in PATH: {spec}")
        }
    })?;

    let kind = classify_executable(&path)
        .ok_or_else(|| anyhow::anyhow!("unsupported browser: {}", path.display()))?;
    Ok(BrowserSelection {
        kind,
        executable: path,
    })
}

fn resolve_default_webbrowser() -> Result<BrowserSelection> {
    let mut candidates = Vec::new();

    if let Ok(browser) = env::var("BROWSER") {
        for cmdline in browser.split(if cfg!(windows) { ';' } else { ':' }) {
            let cmdline = cmdline.trim();
            if cmdline.is_empty() {
                continue;
            }
            let cmd = cmdline.split_whitespace().next().unwrap_or(cmdline);
            if let Some(path) = resolve_binary(cmd) {
                candidates.push(path);
            }
        }
    }

    if let Some(desktop) = os_default_browser_desktop() {
        let name = desktop
            .strip_suffix(".desktop")
            .unwrap_or(desktop.as_str());
        if let Some(path) = which(name) {
            candidates.insert(0, path);
        }
    }

    if let Some(path) = find_family_executable(CHROMIUM_FAMILY) {
        candidates.push(path);
    }
    if let Some(path) = find_family_executable(FIREFOX_FAMILY) {
        candidates.push(path);
    }

    let mut seen = Vec::new();
    for path in candidates {
        if seen.iter().any(|prev: &PathBuf| prev == &path) {
            continue;
        }
        seen.push(path.clone());
        if let Some(kind) = classify_executable(&path) {
            return Ok(BrowserSelection { kind, executable: path });
        }
    }

    bail!(
        "no supported browser found (install chromium or firefox, or pass NAME|PATH to launch)"
    )
}

fn os_default_browser_desktop() -> Option<String> {
    let output = Command::new("xdg-settings")
        .args(["get", "default-web-browser"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resolve_binary(spec: &str) -> Option<PathBuf> {
    if spec.contains('/') || spec.contains('\\') {
        let path = PathBuf::from(spec);
        path.is_file().then_some(path)
    } else {
        which(spec)
    }
}

fn find_family_executable(family: &[&str]) -> Option<PathBuf> {
    family.iter().find_map(|name| which(name))
}

fn classify_executable(path: &Path) -> Option<BrowserKind> {
    let base = path
        .file_name()
        .and_then(OsStr::to_str)?
        .to_lowercase();

    if is_firefox_like(&base) {
        Some(BrowserKind::Firefox)
    } else if is_chromium_like(&base) {
        Some(BrowserKind::Chromium)
    } else {
        None
    }
}

fn is_firefox_like(base: &str) -> bool {
    base.contains("firefox")
        || base.contains("librewolf")
        || base.contains("waterfox")
        || base.contains("floorp")
        || base.contains("zen")
        || base.contains("iceweasel")
        || base.contains("seamonkey")
        || base.contains("palemoon")
        || base == "mozilla"
}

fn is_chromium_like(base: &str) -> bool {
    base.contains("chrom")
        || base.contains("brave")
        || base.contains("vivaldi")
        || base.contains("msedge")
        || base.contains("edge")
        || base.contains("opera")
        || (base.contains("chrome") && !base.contains("chromedriver"))
}

fn setup_chromium_home(home: &Path, ca_path: &Path) -> Result<()> {
    let nssdb = home.join(".local/share/pki/nssdb");
    let legacy_nssdb = home.join(".pki/nssdb");
    std::fs::create_dir_all(&legacy_nssdb).context("failed to create legacy nssdb directory")?;
    std::fs::create_dir_all(&nssdb).context("failed to create nssdb directory")?;

    for nssdb_path in [&nssdb, &legacy_nssdb] {
        init_nssdb(nssdb_path)?;
        import_ca(nssdb_path, ca_path)?;
    }

    info!(dir = %home.display(), "Chromium NSS trust store initialised");
    Ok(())
}

fn setup_firefox_profile(home: &Path, ca_path: &Path) -> Result<()> {
    let firefox_dir = home.join(FIREFOX_BASE_DIR);
    let profile = firefox_profile_dir(home);
    std::fs::create_dir_all(&profile).context("failed to create firefox profile")?;

    let profiles_ini = firefox_dir.join("profiles.ini");
    if !profiles_ini.exists() {
        std::fs::write(&profiles_ini, FIREFOX_PROFILES_INI)
            .with_context(|| format!("failed to write {}", profiles_ini.display()))?;
    }

    init_nssdb(&profile)?;
    import_ca(&profile, ca_path)?;

    info!(dir = %profile.display(), "Firefox NSS trust store initialised");
    Ok(())
}

fn write_firefox_user_js(
    profile: &Path,
    proxy_port: u16,
    user_agent: Option<&str>,
) -> Result<()> {
    strip_firstrun_prefs_from_prefs_js(profile)?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    let mut prefs = format!(
        r#"user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", {proxy_port});
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", {proxy_port});
user_pref("network.proxy.share_proxy_settings", true);
user_pref("network.proxy.allow_hijacking_localhost", true);
user_pref("network.proxy.no_proxies_on", "");
user_pref("browser.aboutwelcome.enabled", false);
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("datareporting.policy.dataSubmissionPolicyAcceptedVersion", 999);
user_pref("datareporting.policy.dataSubmissionPolicyNotifiedTime", "{now_ms}");
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("identity.fxaccounts.enabled", false);
user_pref("services.sync.enabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
"#
    );
    if let Some(user_agent) = user_agent {
        prefs.push_str(&format!(
            "user_pref(\"general.useragent.override\", {user_agent:?});\n"
        ));
    }
    std::fs::write(profile.join("user.js"), prefs).context("failed to write firefox user.js")?;
    Ok(())
}

fn strip_firstrun_prefs_from_prefs_js(profile: &Path) -> Result<()> {
    let prefs_path = profile.join("prefs.js");
    if !prefs_path.is_file() {
        return Ok(());
    }

    let content = std::fs::read_to_string(&prefs_path)
        .with_context(|| format!("failed to read {}", prefs_path.display()))?;
    let lines: Vec<&str> = content.lines().collect();
    let filtered: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| {
            !line.contains("startup.homepage_welcome")
                && !line.contains("trailhead.firstrun")
                && !line.contains("datareporting.policy.dataSubmissionPolicy")
                && !line.contains("browser.aboutwelcome")
        })
        .collect();

    if filtered.len() == lines.len() {
        return Ok(());
    }

    let mut out = filtered.join("\n");
    out.push('\n');
    std::fs::write(&prefs_path, out)
        .with_context(|| format!("failed to write {}", prefs_path.display()))?;
    Ok(())
}

fn init_nssdb(nssdb_path: &Path) -> Result<()> {
    if nssdb_path.join("cert9.db").exists() {
        return Ok(());
    }

    let db = format!("sql:{}", nssdb_path.display());
    run_certutil(&["-N", "-d", &db, "--empty-password"])
}

fn import_ca(nssdb_path: &Path, ca_path: &Path) -> Result<()> {
    let db = format!("sql:{}", nssdb_path.display());
    let nickname = "httplogger-ca";

    let _ = run_certutil(&["-D", "-d", &db, "-n", nickname]);
    run_certutil(&[
        "-A",
        "-d",
        &db,
        "-t",
        "C,,",
        "-n",
        nickname,
        "-i",
        ca_path.to_str().unwrap(),
    ])
}

fn run_certutil(args: &[&str]) -> Result<()> {
    let output = Command::new("certutil")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to run certutil {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("certutil failed: {stderr}");
    }

    Ok(())
}

fn launch_chromium(
    chromium: &Path,
    home: &Path,
    proxy_port: u16,
    user_agent: Option<&str>,
    extra_args: &[String],
) -> Result<std::process::Child> {
    let profile_dir = home.join(CHROME_PROFILE_DIR);
    std::fs::create_dir_all(&profile_dir).context("failed to create chrome profile")?;

    info!(
        binary = %chromium.display(),
        proxy_port,
        profile = %profile_dir.display(),
        user_agent = user_agent.unwrap_or("(default)"),
        "launching Chromium"
    );

    let mut cmd = Command::new(chromium);
    cmd.env("HOME", home);
    cmd.args(chromium_argv(home, proxy_port, user_agent));
    cmd.args(extra_args).stdin(Stdio::null());

    cmd.spawn().context("failed to spawn Chromium")
}

fn launch_firefox(
    firefox: &Path,
    home: &Path,
    extra_args: &[String],
) -> Result<std::process::Child> {
    let profile = firefox_profile_dir(home);
    info!(
        binary = %firefox.display(),
        profile = %profile.display(),
        "launching Firefox"
    );

    let mut cmd = Command::new(firefox);
    cmd.env("HOME", home);
    cmd.args(firefox_argv(&profile, extra_args))
        .args(extra_args)
        .stdin(Stdio::null());

    cmd.spawn().context("failed to spawn Firefox")
}

fn which(cmd: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
