use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::debug;

use crate::tls_hello::extract_client_hello;
use crate::tls_mimic::FingerprintStore;

pub async fn forward_loop(
    public: TcpListener,
    backend: SocketAddr,
    store: FingerprintStore,
) -> Result<()> {
    loop {
        let (client, _) = public.accept().await?;
        let store = store.clone();
        tokio::spawn(async move {
            if let Err(err) = proxy_conn(client, backend, store).await {
                debug!(%err, "peek forwarder connection closed");
            }
        });
    }
}

async fn proxy_conn(client: TcpStream, backend: SocketAddr, store: FingerprintStore) -> Result<()> {
    let server = TcpStream::connect(backend).await?;
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;

    let (mut client_r, mut client_w) = client.into_split();
    let (mut server_r, mut server_w) = server.into_split();

    let c2s = async {
        let mut buf = vec![0u8; 16 * 1024];
        let mut pending = Vec::new();
        let mut looking_for_hello = true;
        let mut seen_http_headers = false;
        let mut connect_authority = None;
        loop {
            let n = client_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            if looking_for_hello {
                pending.extend_from_slice(chunk);
                if !seen_http_headers {
                    if let Some(end) = find_double_crlf(&pending) {
                        seen_http_headers = true;
                        let is_connect = pending.starts_with(b"CONNECT ");
                        if is_connect {
                            connect_authority = parse_connect_authority(&pending[..end]);
                        }
                        let rest = pending.split_off(end);
                        pending = rest;
                        if !is_connect {
                            looking_for_hello = false;
                        }
                    }
                }
                if looking_for_hello && seen_http_headers && !pending.is_empty() {
                    if pending[0] != 0x16 {
                        looking_for_hello = false;
                    } else if let Some((hello, _)) = extract_client_hello(&pending) {
                        if let Some(authority) = &connect_authority {
                            store.observe(authority, hello);
                        }
                        looking_for_hello = false;
                        pending.clear();
                    } else if pending.len() > 32 * 1024 {
                        looking_for_hello = false;
                        pending.clear();
                    }
                }
            }
            server_w.write_all(chunk).await?;
        }
        server_w.shutdown().await?;
        anyhow::Ok(())
    };

    let s2c = async {
        tokio::io::copy(&mut server_r, &mut client_w).await?;
        client_w.shutdown().await?;
        anyhow::Ok(())
    };

    tokio::try_join!(c2s, s2c)?;
    Ok(())
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_connect_authority(headers: &[u8]) -> Option<String> {
    let line = headers.split(|byte| *byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
    let mut parts = line.split_whitespace();
    (parts.next()? == "CONNECT")
        .then(|| parts.next().map(str::to_owned))
        .flatten()
}
