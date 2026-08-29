use anyhow::Result;
use hudsucker::{Proxy, certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::ca::CaMaterial;
use crate::config::AppConfig;
use crate::peek;
use crate::proxy::CaptureHandler;
use crate::storage::RequestStore;
use crate::tls_mimic::{self, FingerprintStore};

pub async fn run(
    workspace_root: &Path,
    config: Arc<AppConfig>,
    ca: CaMaterial,
    fingerprints: FingerprintStore,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let proxy_port = config.mitm_proxy_port;
    let store = Arc::new(RequestStore::open(workspace_root)?);
    let handler = CaptureHandler::new(Arc::clone(&config), Arc::clone(&store));

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
    let authority = RcgenAuthority::new(ca.issuer, 1_000, aws_lc_rs::default_provider());
    let https = tls_mimic::https_connector(fingerprints.clone())?;
    let websocket_connect = tls_mimic::websocket_connect(fingerprints.clone());

    let public = TcpListener::bind(proxy_addr).await?;
    let internal = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let internal_addr = internal.local_addr()?;
    tokio::spawn(async move {
        if let Err(err) = peek::forward_loop(public, internal_addr, fingerprints).await {
            error!(%err, "ClientHello peek forwarder stopped");
        }
    });

    info!(
        workspace = %workspace_root.display(),
        proxy_port,
        scope = ?config.scope,
        ca_cert = %ca.cert_path.display(),
        "HTTP logger started"
    );
    info!(addr = %proxy_addr, "MITM proxy listening");
    info!(
        cert = %ca.cert_path.display(),
        "import this CA certificate into client trust stores"
    );

    let mut client = hudsucker::hyper_util::client::legacy::Client::builder(
        hudsucker::hyper_util::rt::TokioExecutor::new(),
    );
    client
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .http2_adaptive_window(false)
        .http2_initial_stream_window_size(6_291_456)
        .http2_initial_connection_window_size(15_728_640)
        .http2_max_header_list_size(262_144)
        .http2_max_frame_size(None::<u32>);

    let store_for_shutdown = Arc::clone(&store);
    let proxy = Proxy::builder()
        .with_listener(internal)
        .with_ca(authority)
        .with_http_connector(https)
        .with_client(client)
        .with_http_handler(handler.clone())
        .with_websocket_handler(handler)
        .with_websocket_connect(websocket_connect)
        .with_graceful_shutdown(async move {
            shutdown.await;
            if let Err(err) = store_for_shutdown.export_csv() {
                error!(%err, "failed to export requests.csv on shutdown");
            }
        })
        .build()
        .expect("failed to build proxy");

    if let Err(err) = proxy.start().await {
        error!(%err, "proxy stopped with error");
    }

    store.export_csv()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_hello::{
        EXT_ALPS_NEW, EXT_ALPS_OLD, compare_hellos, extract_client_hello, join_hex, without_grease,
    };
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn capture_client_hello(
        listener: tokio::net::TcpListener,
    ) -> crate::tls_hello::ClientHelloInfo {
        let (mut stream, _) = listener.accept().await.expect("dump accept");
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut tmp))
                .await
                .expect("dump read timeout")
                .expect("dump read");
            assert_ne!(n, 0, "dump eof before ClientHello");
            buf.extend_from_slice(&tmp[..n]);
            if let Some((hello, _)) = extract_client_hello(&buf) {
                return hello;
            }
            assert!(buf.len() < 64 * 1024, "ClientHello too large");
        }
    }

    fn spawn_chromium(proxy_port: Option<u16>, url: &str, user_data: &Path) -> std::process::Child {
        let exe = ["chromium", "chromium-browser", "google-chrome"]
            .iter()
            .find(|name| {
                std::process::Command::new(name)
                    .arg("--version")
                    .output()
                    .is_ok()
            })
            .copied()
            .expect("chromium not installed");
        let mut cmd = std::process::Command::new(exe);
        cmd.args([
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--ignore-certificate-errors",
            &format!("--user-data-dir={}", user_data.display()),
        ]);
        if let Some(port) = proxy_port {
            cmd.arg(format!("--proxy-server=http://127.0.0.1:{port}"));
        }
        cmd.arg(url)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn chromium")
    }

    #[tokio::test]
    async fn chromium_clienthello_is_mirrored_upstream() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter("httplogger=debug")
            .try_init();
        let root = std::env::temp_dir().join(format!(
            "httplogger-mimic-{}-{}",
            std::process::id(),
            free_port()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let proxy_port = free_port();
        std::fs::write(
            root.join("httplogger.yml"),
            format!("scope: [\"*\"]\nmitmProxyPort: {proxy_port}\n"),
        )
        .unwrap();
        let ca = crate::ca::ensure_ca(&root, None).unwrap();
        let config = Arc::new(crate::config::load_or_init(&root).unwrap());
        let fingerprints = FingerprintStore::new();
        let fingerprints_for_server = fingerprints.clone();

        let dump = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dump_port = dump.local_addr().unwrap().port();
        let dump_task = tokio::spawn(capture_client_hello(dump));

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let server_root = root.clone();
        let server_task = tokio::spawn(async move {
            run(
                &server_root,
                config,
                ca,
                fingerprints_for_server,
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("proxy did not start");

        let profile = root.join("chrome-profile");
        std::fs::create_dir_all(&profile).unwrap();
        let url = format!("https://localhost:{dump_port}/");
        let mut child = spawn_chromium(Some(proxy_port), &url, &profile);

        let outbound = tokio::time::timeout(Duration::from_secs(20), dump_task)
            .await
            .expect("timed out waiting for outbound ClientHello")
            .expect("dump task failed");

        let inbound = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(hello) = fingerprints.latest_hello() {
                    return hello;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for inbound ClientHello");

        assert!(
            fingerprints.has_profile(),
            "TLS mimic profile was not compiled"
        );

        let _ = child.kill();
        let _ = child.wait();
        let _ = stop_tx.send(());
        let _ = server_task.await;

        println!("inbound  {}", inbound.summary());
        println!(
            "inbound  ciphers={}",
            join_hex(without_grease(&inbound.cipher_suites))
        );
        println!(
            "inbound  extensions={}",
            join_hex(without_grease(&inbound.extensions))
        );
        println!(
            "inbound  groups={}",
            join_hex(without_grease(&inbound.groups))
        );
        println!(
            "inbound  sigalgs={}",
            join_hex(without_grease(&inbound.signature_algorithms))
        );
        println!("outbound {}", outbound.summary());
        println!(
            "outbound ciphers={}",
            join_hex(without_grease(&outbound.cipher_suites))
        );
        println!(
            "outbound extensions={}",
            join_hex(without_grease(&outbound.extensions))
        );
        println!(
            "outbound groups={}",
            join_hex(without_grease(&outbound.groups))
        );
        println!(
            "outbound sigalgs={}",
            join_hex(without_grease(&outbound.signature_algorithms))
        );

        let diffs = compare_hellos(&inbound, &outbound);
        if diffs.is_empty() {
            println!("ClientHello mimic: parsed fields match (GREASE values ignored)");
        } else {
            println!("ClientHello mimic diffs ({}):", diffs.len());
            for diff in &diffs {
                println!("  - {diff}");
            }
        }

        assert!(
            !without_grease(&inbound.extensions).is_empty(),
            "inbound ClientHello has no extensions"
        );
        assert!(
            !without_grease(&outbound.extensions).is_empty(),
            "outbound ClientHello has no extensions"
        );
        assert!(diffs.is_empty(), "ClientHello field mismatch: {diffs:#?}");
    }

    #[tokio::test]
    async fn chromium_websocket_clienthello_is_mirrored_upstream() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter("httplogger=debug")
            .try_init();
        let root = std::env::temp_dir().join(format!(
            "httplogger-ws-mimic-{}-{}",
            std::process::id(),
            free_port()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let proxy_port = free_port();
        std::fs::write(
            root.join("httplogger.yml"),
            format!("scope: [\"*\"]\nmitmProxyPort: {proxy_port}\n"),
        )
        .unwrap();
        let ca = crate::ca::ensure_ca(&root, None).unwrap();
        let config = Arc::new(crate::config::load_or_init(&root).unwrap());
        let fingerprints = FingerprintStore::new();
        let fingerprints_for_server = fingerprints.clone();

        let dump = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dump_port = dump.local_addr().unwrap().port();
        let dump_task = tokio::spawn(capture_client_hello(dump));

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let server_root = root.clone();
        let server_task = tokio::spawn(async move {
            run(
                &server_root,
                config,
                ca,
                fingerprints_for_server,
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("proxy did not start");

        let profile = root.join("chrome-profile");
        std::fs::create_dir_all(&profile).unwrap();
        let url = format!(
            "data:text/html,<script>new WebSocket('wss://127.0.0.1:{dump_port}/')</script>"
        );
        let mut child = spawn_chromium(Some(proxy_port), &url, &profile);

        let outbound = tokio::time::timeout(Duration::from_secs(20), dump_task)
            .await
            .expect("timed out waiting for outbound WSS ClientHello")
            .expect("dump task failed");

        let inbound = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(hello) = fingerprints.latest_hello() {
                    return hello;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for inbound WSS ClientHello");

        let _ = child.kill();
        let _ = child.wait();
        let _ = stop_tx.send(());
        let _ = server_task.await;

        println!("ws inbound  {}", inbound.summary());
        println!("ws outbound {}", outbound.summary());

        assert_eq!(
            outbound.alpn,
            vec![b"http/1.1".to_vec()],
            "WSS upstream ALPN should be http/1.1, got {:?}",
            outbound
                .alpn
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect::<Vec<_>>()
        );
        assert!(
            outbound.grease(),
            "WSS upstream ClientHello has no GREASE (looks like rustls, not Chrome)"
        );

        let mut expected = inbound.clone();
        expected.alpn = vec![b"http/1.1".to_vec()];
        // WSS hop is HTTP/1.1 Upgrade: no ALPS. BoringSSL drops SNI for IP
        // literals (0x0000); Chrome still sends it on the MITM hello.
        expected
            .extensions
            .retain(|id| *id != EXT_ALPS_NEW && *id != EXT_ALPS_OLD && *id != 0x0000);

        let diffs = compare_hellos(&expected, &outbound);
        assert!(
            diffs.is_empty(),
            "WSS ClientHello field mismatch: {diffs:#?}"
        );
    }
}
