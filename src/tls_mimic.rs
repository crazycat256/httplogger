use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use boring::error::ErrorStack;
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration, SslConnector,
    SslConnectorBuilder, SslMethod, SslRef, SslVerifyMode, SslVersion,
};
use boring::x509::X509;
use boring::x509::store::X509StoreBuilder;
use foreign_types::ForeignTypeRef;
use hudsucker::hyper::{Request, Uri};
use hudsucker::tokio_tungstenite::tungstenite;
use hudsucker::{WebsocketConnect, WebsocketIo};
use hyper_boring::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::tls_hello::{ClientHelloInfo, EXT_ALPN, alpn_wire, is_grease, without_grease};

#[derive(Clone)]
pub struct FingerprintStore {
    inner: Arc<RwLock<StoreState>>,
}

#[derive(Default)]
struct StoreState {
    hello: Option<ClientHelloInfo>,
    profiles: HashMap<String, Arc<CompiledProfile>>,
    revisions: HashMap<String, u64>,
}

struct CompiledProfile {
    identity: String,
    hello: ClientHelloInfo,
    connector: SslConnector,
}

impl FingerprintStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreState::default())),
        }
    }

    pub fn observe(&self, authority: &str, hello: ClientHelloInfo) {
        let authority = authority_key(authority);
        let identity = hello.identity_key();
        let revision = {
            let mut guard = self.inner.write().expect("fingerprint lock poisoned");
            guard.hello = Some(hello.clone());
            if guard
                .profiles
                .get(&authority)
                .is_some_and(|p| p.identity == identity)
            {
                return;
            }
            // Keep the HTTPS (h2) profile. A later dedicated WSS CONNECT often
            // peeks ALPN http/1.1 only; overwriting would make subsequent HTTPS
            // look like HTTP/1.1. WSS outbound forces http/1.1 itself.
            if guard.profiles.get(&authority).is_some_and(|p| {
                p.hello.alpn.iter().any(|proto| proto.as_slice() == b"h2")
                    && !hello.alpn.iter().any(|proto| proto.as_slice() == b"h2")
            }) {
                return;
            }
            let revision = guard.revisions.entry(authority.clone()).or_default();
            *revision = revision.wrapping_add(1);
            *revision
        };
        match compile_profile(hello.clone()) {
            Ok(connector) => {
                let mut guard = self.inner.write().expect("fingerprint lock poisoned");
                if guard.revisions.get(&authority) != Some(&revision) {
                    return;
                }
                info!(summary = %hello.summary(), "mirroring browser ClientHello on upstream TLS");
                guard.profiles.insert(
                    authority,
                    Arc::new(CompiledProfile {
                        identity,
                        hello,
                        connector,
                    }),
                );
            }
            Err(err) => {
                let mut guard = self.inner.write().expect("fingerprint lock poisoned");
                if guard.revisions.get(&authority) == Some(&revision) {
                    guard.profiles.remove(&authority);
                }
                warn!(%err, summary = %hello.summary(), "failed to compile TLS mimic profile");
            }
        }
    }

    #[cfg(test)]
    pub fn latest_hello(&self) -> Option<ClientHelloInfo> {
        self.inner
            .read()
            .expect("fingerprint lock poisoned")
            .hello
            .clone()
    }

    #[cfg(test)]
    pub fn has_profile(&self) -> bool {
        !self
            .inner
            .read()
            .expect("fingerprint lock poisoned")
            .profiles
            .is_empty()
    }

    fn current(&self, uri: &Uri) -> Option<Arc<CompiledProfile>> {
        let authority = uri.authority().map(|value| authority_key(value.as_str()))?;
        self.inner
            .read()
            .expect("fingerprint lock poisoned")
            .profiles
            .get(&authority)
            .cloned()
    }
}

fn authority_key(authority: &str) -> String {
    let authority = authority.to_ascii_lowercase();
    if authority
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        authority
    } else {
        format!("{authority}:443")
    }
}

pub fn https_connector(store: FingerprintStore) -> Result<HttpsConnector<HttpConnector>> {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);

    let builder = fallback_builder()?;
    let mut https = HttpsConnector::with_connector(http, builder)
        .context("failed to build BoringSSL HTTPS connector")?;
    let store_for_ssl = store.clone();
    https.set_callback(move |cfg, uri| apply_connect_config(cfg, uri, &store));
    https.set_ssl_callback(move |ssl, uri| apply_ssl(ssl, uri, &store_for_ssl));
    Ok(https)
}

pub fn websocket_connect(store: FingerprintStore) -> WebsocketConnect {
    Arc::new(move |req| {
        let store = store.clone();
        Box::pin(async move { connect_websocket(store, req).await })
    })
}

async fn connect_websocket(
    store: FingerprintStore,
    request: Request<()>,
) -> Result<
    (
        hudsucker::WebsocketStream,
        tungstenite::handshake::client::Response,
    ),
    tungstenite::Error,
> {
    let uri = request.uri().clone();
    let (host, port) = ws_host_port(&uri)?;
    let tls = matches!(uri.scheme_str(), Some("wss") | Some("https"));
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(tungstenite::Error::Io)?;
    tcp.set_nodelay(true).map_err(tungstenite::Error::Io)?;

    let stream: Box<dyn WebsocketIo> = if tls {
        Box::new(boring_ws_handshake(&store, &uri, &host, tcp).await?)
    } else {
        Box::new(tcp)
    };
    hudsucker::tokio_tungstenite::client_async_with_config(request, stream, None).await
}

async fn boring_ws_handshake(
    store: &FingerprintStore,
    uri: &Uri,
    domain: &str,
    tcp: TcpStream,
) -> Result<tokio_boring::SslStream<TcpStream>, tungstenite::Error> {
    let profile = store.current(uri);
    let fallback = if profile.is_none() {
        Some(fallback_builder().map_err(tls_io_err)?.build())
    } else {
        None
    };
    let connector = profile
        .as_ref()
        .map(|p| &p.connector)
        .or(fallback.as_ref())
        .expect("websocket TLS connector");
    let mut cfg = connector.configure().map_err(tls_io_err)?;
    if let Some(profile) = profile.as_ref() {
        if let Err(err) = cfg.set_ssl_context(profile.connector.context()) {
            debug!(%err, "websocket set_ssl_context failed");
        }
        cfg.set_permute_extensions(profile.hello.grease());
        cfg.set_enable_ech_grease(profile.hello.has_ech());
        apply_ssl_crypto(&cfg, &profile.hello);
    } else {
        cfg.set_permute_extensions(true);
        cfg.set_enable_ech_grease(true);
    }
    // Dedicated WSS is HTTP/1.1 Upgrade. Advertising h2 here makes the
    // origin pick HTTP/2 and the tungstenite handshake fails.
    cfg.set_alpn_protos(&alpn_wire(&[b"http/1.1".to_vec()]))
        .map_err(tls_io_err)?;
    // Chrome sends SNI even for IP literals. BoringSSL skips it for IPs unless set here.
    if let Err(err) = cfg.set_hostname(domain) {
        debug!(%err, "websocket SNI failed");
    }
    tokio_boring::connect(cfg, domain, tcp)
        .await
        .map_err(|err| tls_io_err(err.to_string()))
}

fn apply_ssl_crypto(ssl: &SslRef, hello: &ClientHelloInfo) {
    if let Err(err) = set_raw_groups_ssl(ssl, hello) {
        debug!(%err, "websocket SSL_set1_groups failed");
    }
    if let Err(err) = set_raw_sigalgs_ssl(ssl, hello) {
        debug!(%err, "websocket SSL_set1_sigalgs failed");
    }
    if let Err(err) = set_key_shares_ssl(ssl, hello) {
        debug!(%err, "websocket SSL_set1_client_key_shares failed");
    }
}

fn ws_host_port(uri: &Uri) -> Result<(String, u16), tungstenite::Error> {
    let host = uri.host().ok_or(tungstenite::Error::Url(
        tungstenite::error::UrlError::NoHostName,
    ))?;
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
        .to_string();
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("wss") | Some("https") => 443,
        _ => 80,
    });
    Ok((host, port))
}

fn tls_io_err(err: impl std::fmt::Display) -> tungstenite::Error {
    tungstenite::Error::Io(io::Error::other(err.to_string()))
}

fn apply_connect_config(
    cfg: &mut ConnectConfiguration,
    uri: &Uri,
    store: &FingerprintStore,
) -> Result<(), ErrorStack> {
    if let Some(profile) = store.current(uri) {
        if let Err(err) = cfg.set_ssl_context(profile.connector.context()) {
            debug!(%err, "set_ssl_context failed");
        }
        cfg.set_permute_extensions(profile.hello.grease());
        cfg.set_enable_ech_grease(profile.hello.has_ech());
        if !profile.hello.alpn.is_empty() {
            cfg.set_alpn_protos(&alpn_wire(&profile.hello.alpn))?;
        }
        let ssl: &SslRef = cfg;
        if let Err(err) = set_alps_ssl(ssl, &profile.hello) {
            debug!(%err, "ALPS on connect config failed");
        }
    } else {
        cfg.set_permute_extensions(true);
        cfg.set_enable_ech_grease(true);
    }
    Ok(())
}

fn apply_ssl(ssl: &mut SslRef, uri: &Uri, store: &FingerprintStore) -> Result<(), ErrorStack> {
    if let Some(profile) = store.current(uri) {
        let hello = &profile.hello;
        if !hello.alpn.is_empty() {
            let wire = alpn_wire(&hello.alpn);
            unsafe {
                boring_sys::SSL_set_alpn_protos(ssl.as_ptr(), wire.as_ptr(), wire.len());
            }
        }
        if let Err(err) = set_raw_groups_ssl(ssl, hello) {
            debug!(%err, "SSL_set1_groups failed");
        }
        if let Err(err) = set_raw_sigalgs_ssl(ssl, hello) {
            debug!(%err, "SSL_set1_sigalgs failed");
        }
        if let Err(err) = set_key_shares_ssl(ssl, hello) {
            debug!(%err, "SSL_set1_client_key_shares failed");
        }
        if let Err(err) = set_alps_ssl(ssl, hello) {
            warn!(%err, "SSL_add_application_settings failed");
        }
    } else if let Err(err) = add_default_alps(ssl) {
        debug!(%err, "default ALPS failed");
    }
    Ok(())
}

fn add_default_alps(ssl: &SslRef) -> Result<(), ErrorStack> {
    let ok = unsafe {
        boring_sys::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), 1);
        boring_sys::SSL_add_application_settings(
            ssl.as_ptr(),
            b"h2".as_ptr(),
            2,
            std::ptr::null(),
            0,
        )
    };
    if ok != 1 {
        return Err(ErrorStack::get());
    }
    Ok(())
}

fn set_raw_sigalgs_ssl(ssl: &SslRef, hello: &ClientHelloInfo) -> Result<(), ErrorStack> {
    let values: Vec<i32> = without_grease(&hello.signature_algorithms)
        .into_iter()
        .map(i32::from)
        .collect();
    if values.is_empty() {
        return Ok(());
    }
    let ok = unsafe { boring_sys::SSL_set1_sigalgs(ssl.as_ptr(), values.as_ptr(), values.len()) };
    if ok != 1 {
        return Err(ErrorStack::get());
    }
    Ok(())
}

fn set_raw_groups_ssl(ssl: &SslRef, hello: &ClientHelloInfo) -> Result<(), ErrorStack> {
    let values: Vec<i32> = without_grease(&hello.groups)
        .into_iter()
        .map(i32::from)
        .collect();
    if values.is_empty() {
        return Ok(());
    }
    let ok = unsafe { boring_sys::SSL_set1_groups(ssl.as_ptr(), values.as_ptr(), values.len()) };
    if ok != 1 {
        return Err(ErrorStack::get());
    }
    Ok(())
}

fn set_key_shares_ssl(ssl: &SslRef, hello: &ClientHelloInfo) -> Result<(), ErrorStack> {
    let shares = without_grease(&hello.key_share_groups);
    if shares.is_empty() {
        return Ok(());
    }
    let ok = unsafe {
        boring_sys::SSL_set1_client_key_shares(ssl.as_ptr(), shares.as_ptr(), shares.len())
    };
    if ok != 1 {
        return Err(ErrorStack::get());
    }
    Ok(())
}

fn set_alps_ssl(ssl: &SslRef, hello: &ClientHelloInfo) -> Result<(), ErrorStack> {
    let Some(new_codepoint) = hello.alps_new_codepoint() else {
        return Ok(());
    };
    if !hello.alpn.iter().any(|p| p == b"h2") {
        return Ok(());
    }
    let ok = unsafe {
        boring_sys::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), i32::from(new_codepoint));
        boring_sys::SSL_add_application_settings(
            ssl.as_ptr(),
            b"h2".as_ptr(),
            2,
            std::ptr::null(),
            0,
        )
    };
    if ok != 1 {
        return Err(ErrorStack::get());
    }
    Ok(())
}

fn compile_profile(hello: ClientHelloInfo) -> Result<SslConnector> {
    let mut builder = base_builder()?;
    set_version_range(&mut builder, &hello)?;
    builder.set_grease_enabled(hello.grease());
    builder.set_permute_extensions(hello.grease());

    let ciphers = openssl_cipher_list(&hello.cipher_suites);
    if !ciphers.is_empty() {
        builder
            .set_cipher_list(&ciphers)
            .with_context(|| format!("set_cipher_list({ciphers})"))?;
    }

    let groups = openssl_group_list(&hello.groups);
    if !groups.is_empty() {
        builder
            .set_curves_list(&groups)
            .with_context(|| format!("set_curves_list({groups})"))?;
    }

    let sigalgs = openssl_sigalg_list(&hello.signature_algorithms);
    if !sigalgs.is_empty()
        && let Err(err) = builder.set_sigalgs_list(&sigalgs)
    {
        warn!(%err, sigalgs, "set_sigalgs_list failed; continuing without it");
    }

    if hello.has_ocsp() {
        builder.enable_ocsp_stapling();
    }
    if hello.has_sct() {
        builder.enable_signed_cert_timestamps();
    }
    if hello.has_brotli_cert() {
        builder.add_certificate_compression_algorithm(BrotliCertCompression)?;
    }
    if hello.extensions.contains(&EXT_ALPN) && !hello.alpn.is_empty() {
        builder.set_alpn_protos(&alpn_wire(&hello.alpn))?;
    }

    Ok(builder.build())
}

fn base_builder() -> Result<SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_verify(SslVerifyMode::PEER);
    builder.set_verify_cert_store(root_store()?)?;
    Ok(builder)
}

fn fallback_builder() -> Result<SslConnectorBuilder> {
    let mut builder = base_builder()?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.enable_ocsp_stapling();
    builder.enable_signed_cert_timestamps();
    builder.add_certificate_compression_algorithm(BrotliCertCompression)?;
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    let _ = builder.set_cipher_list(
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
    );
    let _ = builder.set_curves_list("X25519MLKEM768:X25519:P-256:P-384");
    let _ = builder.set_sigalgs_list(
        "mldsa44:mldsa65:mldsa87:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
    );
    Ok(builder)
}

fn set_version_range(builder: &mut SslConnectorBuilder, hello: &ClientHelloInfo) -> Result<()> {
    let tls12 = hello.supported_versions.contains(&0x0303);
    let tls13 = hello.supported_versions.contains(&0x0304);
    if !tls12 && !tls13 {
        return Ok(());
    }
    let min = if tls12 {
        SslVersion::TLS1_2
    } else {
        SslVersion::TLS1_3
    };
    let max = if tls13 {
        SslVersion::TLS1_3
    } else {
        SslVersion::TLS1_2
    };
    builder.set_min_proto_version(Some(min))?;
    builder.set_max_proto_version(Some(max))?;
    Ok(())
}

fn root_store() -> Result<boring::x509::store::X509Store, ErrorStack> {
    let mut builder = X509StoreBuilder::new()?;
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        if let Ok(cert) = X509::from_der(der.as_ref()) {
            builder.add_cert(cert)?;
        }
    }
    Ok(builder.build())
}

struct BrotliCertCompression;

impl CertificateCompressor for BrotliCertCompression {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let mut writer = brotli::CompressorWriter::new(output, 4096, 5, 22);
        writer.write_all(input)
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let mut reader = brotli::Decompressor::new(input, 4096);
        io::copy(&mut reader, output)?;
        Ok(())
    }
}

fn openssl_cipher_list(ciphers: &[u16]) -> String {
    without_grease(ciphers)
        .into_iter()
        .filter_map(tls12_cipher_name)
        .collect::<Vec<_>>()
        .join(":")
}

fn openssl_group_list(groups: &[u16]) -> String {
    without_grease(groups)
        .into_iter()
        .filter_map(group_name)
        .collect::<Vec<_>>()
        .join(":")
}

fn openssl_sigalg_list(algs: &[u16]) -> String {
    without_grease(algs)
        .into_iter()
        .filter_map(sigalg_name)
        .collect::<Vec<_>>()
        .join(":")
}

fn tls12_cipher_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x1301 | 0x1302 | 0x1303 | 0x1304 | 0x1305 => return None,
        0xc02b => "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xc02f => "ECDHE-RSA-AES128-GCM-SHA256",
        0xc02c => "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xc030 => "ECDHE-RSA-AES256-GCM-SHA384",
        0xcca9 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        0xcca8 => "ECDHE-RSA-CHACHA20-POLY1305",
        0xc013 => "ECDHE-RSA-AES128-SHA",
        0xc014 => "ECDHE-RSA-AES256-SHA",
        0x009c => "AES128-GCM-SHA256",
        0x009d => "AES256-GCM-SHA384",
        0x002f => "AES128-SHA",
        0x0035 => "AES256-SHA",
        0xc009 => "ECDHE-ECDSA-AES128-SHA",
        0xc00a => "ECDHE-ECDSA-AES256-SHA",
        _ => {
            if !is_grease(id) {
                debug!(id = format!("{id:#06x}"), "unmapped TLS 1.2 cipher");
            }
            return None;
        }
    })
}

fn group_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x001d => "X25519",
        0x0017 => "P-256",
        0x0018 => "P-384",
        0x0019 => "P-521",
        0x001e => "X448",
        0x0100 => "ffdhe2048",
        0x0101 => "ffdhe3072",
        0x11ec => "X25519MLKEM768",
        0x11eb => "SecP256r1MLKEM768",
        0x6399 => "X25519Kyber768Draft00",
        _ => {
            debug!(id = format!("{id:#06x}"), "unmapped TLS group");
            return None;
        }
    })
}

fn sigalg_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        0x0809 => "rsa_pss_pss_sha256",
        0x080a => "rsa_pss_pss_sha384",
        0x080b => "rsa_pss_pss_sha512",
        0x0401 => "rsa_pkcs1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0201 => "rsa_pkcs1_sha1",
        0x0203 => "ecdsa_sha1",
        0x0303 => "ecdsa_sha384",
        0x0904 => "mldsa44",
        0x0905 => "mldsa65",
        0x0906 => "mldsa87",
        _ => {
            debug!(
                id = format!("{id:#06x}"),
                "unmapped TLS signature algorithm"
            );
            return None;
        }
    })
}
