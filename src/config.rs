use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_MITM_PROXY_PORT: u16 = 8079;
pub const CONFIG_FILE: &str = "httplogger.yml";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpRequestFilterConfig {
    #[serde(default = "default_exclude_resource_types")]
    pub exclude_resource_types: Vec<String>,
    #[serde(default = "default_exclude_extensions")]
    pub exclude_extensions: Vec<String>,
    #[serde(default = "default_exclude_mime_types")]
    pub exclude_mime_types: Vec<String>,
    #[serde(default)]
    pub include_methods: Vec<String>,
    #[serde(default)]
    pub exclude_url_patterns: Vec<String>,
    #[serde(default = "default_skip_requests_without_origin")]
    pub skip_requests_without_origin: bool,
    #[serde(default)]
    pub skip_empty_responses: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    #[serde(default = "default_scope")]
    pub scope: Vec<String>,
    #[serde(default = "default_mitm_proxy_port")]
    pub mitm_proxy_port: u16,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub filters: HttpRequestFilterConfig,
}

impl Default for HttpRequestFilterConfig {
    fn default() -> Self {
        Self {
            exclude_resource_types: default_exclude_resource_types(),
            exclude_extensions: default_exclude_extensions(),
            exclude_mime_types: default_exclude_mime_types(),
            include_methods: Vec::new(),
            exclude_url_patterns: Vec::new(),
            skip_requests_without_origin: default_skip_requests_without_origin(),
            skip_empty_responses: false,
        }
    }
}

fn default_scope() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_mitm_proxy_port() -> u16 {
    DEFAULT_MITM_PROXY_PORT
}

fn default_skip_requests_without_origin() -> bool {
    true
}

fn default_exclude_resource_types() -> Vec<String> {
    vec![
        "stylesheet".into(),
        "image".into(),
        "font".into(),
        "media".into(),
        "ping".into(),
        "events".into(),
        "beacon".into(),
    ]
}

fn default_exclude_extensions() -> Vec<String> {
    vec![
        ".css".into(),
        ".woff".into(),
        ".woff2".into(),
        ".ttf".into(),
        ".otf".into(),
        ".eot".into(),
        ".png".into(),
        ".jpg".into(),
        ".jpeg".into(),
        ".gif".into(),
        ".svg".into(),
        ".ico".into(),
        ".webp".into(),
        ".avif".into(),
        ".mp4".into(),
        ".webm".into(),
        ".mp3".into(),
        ".wav".into(),
        ".map".into(),
    ]
}

fn default_exclude_mime_types() -> Vec<String> {
    vec![
        "text/css".into(),
        "image/*".into(),
        "font/*".into(),
        "audio/*".into(),
        "video/*".into(),
    ]
}

pub const DEFAULT_CONFIG_YAML: &str = r#"# Scope = targets to analyze.
# Each entry supports:
# - an exact domain: example.com
# - a wildcard subdomain pattern: "*.example.com"
# - a base URL: https://example.com/app
# - "*" to analyze everything (except browser-internal background traffic)
scope:
    - "*"

# CA key/cert (ca-key.pem, ca.pem) and browser home (home/) are created on first run.
# Browser choice: `httplogger launch [NAME|PATH]` (default: system browser).
# Bodies are stored as httplogger/requests/00001.req and .res;
# WebSocket sessions as httplogger/websockets/00001.ws.json;
# metadata.db and requests.csv live in httplogger/.
mitmProxyPort: 8079
# Optional browser user-agent (Chromium flag / Firefox user.js).
# userAgent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
filters:
    excludeResourceTypes:
        - stylesheet
        - image
        - font
        - media
        - ping
        - events
        - beacon
    excludeExtensions:
        - .css
        - .woff
        - .woff2
        - .ttf
        - .otf
        - .eot
        - .png
        - .jpg
        - .jpeg
        - .gif
        - .svg
        - .ico
        - .webp
        - .avif
        - .mp4
        - .webm
        - .mp3
        - .wav
        - .map
    excludeMimeTypes:
        - text/css
        - image/*
        - font/*
        - audio/*
        - video/*
    includeMethods: []
    excludeUrlPatterns: []
    skipRequestsWithoutOrigin: true
    skipEmptyResponses: false
"#;

pub fn config_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join(CONFIG_FILE)
}

/// Write the default httplogger.yml. Refuses to overwrite unless `force` is true.
pub fn init_config(workspace_root: &Path, force: bool) -> Result<PathBuf> {
    let path = config_path(workspace_root);
    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists (run `init --force` to overwrite)",
            path.display()
        );
    }

    fs::write(&path, DEFAULT_CONFIG_YAML)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

/// Load httplogger.yml, creating it with defaults when missing.
pub fn load_or_init(workspace_root: &Path) -> Result<AppConfig> {
    let path = config_path(workspace_root);
    if !path.exists() {
        init_config(workspace_root, false)?;
    }

    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    parse_config(&raw)
}

fn parse_config(raw: &str) -> Result<AppConfig> {
    serde_yaml::from_str(raw).context("invalid httplogger.yml")
}
