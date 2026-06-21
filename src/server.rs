use anyhow::Result;
use hudsucker::{
    certificate_authority::RcgenAuthority,
    rustls::crypto::aws_lc_rs,
    Proxy,
};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info};

use crate::ca::CaMaterial;
use crate::config::AppConfig;
use crate::proxy::CaptureHandler;
use crate::storage::RequestStore;

pub async fn run(
    workspace_root: &Path,
    config: Arc<AppConfig>,
    ca: CaMaterial,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let proxy_port = config.mitm_proxy_port;
    let store = Arc::new(RequestStore::open(workspace_root)?);
    let handler = CaptureHandler::new(Arc::clone(&config), Arc::clone(&store));

    let proxy_addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
    let authority = RcgenAuthority::new(ca.issuer, 1_000, aws_lc_rs::default_provider());

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

    let store_for_shutdown = Arc::clone(&store);
    let proxy = Proxy::builder()
        .with_addr(proxy_addr)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler.clone())
        .with_websocket_handler(handler)
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
