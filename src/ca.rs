use anyhow::{bail, Context, Result};
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair,
};
use std::fs;
use std::path::{Path, PathBuf};

pub const CA_KEY_FILE: &str = "ca-key.pem";
pub const CA_CERT_FILE: &str = "ca.pem";

pub struct CaMaterial {
    pub issuer: Issuer<'static, KeyPair>,
    pub cert_pem: String,
    pub cert_path: PathBuf,
}

pub fn default_ca_paths(workspace_root: &Path) -> (PathBuf, PathBuf) {
    (
        workspace_root.join(CA_KEY_FILE),
        workspace_root.join(CA_CERT_FILE),
    )
}

/// Certificate PEM beside the key: `ca-key.pem` → `ca.pem`, else same stem + `.pem`.
pub fn cert_path_for_key(key_path: &Path) -> PathBuf {
    let file_name = key_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(CA_KEY_FILE);
    let cert_name = if let Some(stem) = file_name.strip_suffix("-key.pem") {
        format!("{stem}.pem")
    } else if let Some(stem) = file_name.strip_suffix(".pem") {
        format!("{stem}-cert.pem")
    } else {
        CA_CERT_FILE.to_string()
    };
    key_path
        .parent()
        .map(|parent| parent.join(&cert_name))
        .unwrap_or_else(|| PathBuf::from(cert_name))
}

pub fn ensure_ca(workspace_root: &Path, key_path: Option<PathBuf>) -> Result<CaMaterial> {
    let key_path = key_path.unwrap_or_else(|| default_ca_paths(workspace_root).0);
    if !key_path.exists() {
        let cert_path = cert_path_for_key(&key_path);
        generate_key_pair(&key_path, &cert_path, false)?;
    }
    load_ca(&key_path)
}

pub fn generate_key_pair(key_path: &Path, cert_path: &Path, force: bool) -> Result<()> {
    if !force && (key_path.exists() || cert_path.exists()) {
        bail!(
            "CA files already exist ({} and/or {}); delete them to regenerate",
            key_path.display(),
            cert_path.display()
        );
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let key_pair = KeyPair::generate().context("failed to generate CA key pair")?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "httplogger CA");

    let cert = params
        .self_signed(&key_pair)
        .context("failed to sign CA certificate")?;

    fs::write(key_path, key_pair.serialize_pem())
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    fs::write(cert_path, cert.pem())
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    restrict_private_key_permissions(key_path)?;

    Ok(())
}

pub fn load_ca(key_path: &Path) -> Result<CaMaterial> {
    let cert_path = cert_path_for_key(key_path);
    let key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("failed to read {}", key_path.display()))?;
    let cert_pem = fs::read_to_string(&cert_path)
        .with_context(|| format!("failed to read {}", cert_path.display()))?;

    let key_pair =
        KeyPair::from_pem(&key_pem).with_context(|| format!("invalid {}", key_path.display()))?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)
        .context("failed to build CA issuer from PEM files")?;

    Ok(CaMaterial {
        issuer,
        cert_pem,
        cert_path,
    })
}

#[cfg(unix)]
fn restrict_private_key_permissions(key_path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = fs::metadata(key_path)
        .with_context(|| format!("failed to stat {}", key_path.display()))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(key_path, perms)
        .with_context(|| format!("failed to chmod 600 {}", key_path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private_key_permissions(_key_path: &Path) -> Result<()> {
    Ok(())
}
