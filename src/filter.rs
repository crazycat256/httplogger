use crate::config::HttpRequestFilterConfig;
use url::Url;

#[derive(Debug, Clone)]
pub struct HttpRequestFilterInput {
    pub method: String,
    pub url: String,
    pub resource_type: String,
    pub mime_type: Option<String>,
    pub status_code: Option<u16>,
    pub has_response_body: Option<bool>,
    pub page_url: Option<String>,
}

pub fn matches_http_request_scope(
    page_url: Option<&str>,
    request_url: &str,
    patterns: &[String],
) -> bool {
    if let Some(page) = page_url {
        if matches_scope(page, patterns) {
            return true;
        }
    }
    matches_scope(request_url, patterns)
}

pub fn matches_scope(target: &str, patterns: &[String]) -> bool {
    let target_url = try_parse_http_url(target);
    let hostname = target_url
        .as_ref()
        .map(|u| u.host_str().unwrap_or(target))
        .unwrap_or(target);

    for raw_pattern in patterns {
        let pattern = raw_pattern.trim();
        if pattern.is_empty() {
            continue;
        }

        if pattern == "*" {
            return true;
        }

        if let Some(base_url) = try_parse_http_url(pattern) {
            if let Some(ref target_parsed) = target_url {
                if url_matches_base(target_parsed, &base_url) {
                    return true;
                }
            } else if hostname_matches_pattern(hostname, base_url.host_str().unwrap_or("")) {
                return true;
            }
            continue;
        }

        if hostname_matches_pattern(hostname, pattern) {
            return true;
        }
    }

    false
}

pub fn should_filter_http_request(
    input: &HttpRequestFilterInput,
    filters: &HttpRequestFilterConfig,
) -> bool {
    let method = normalize_method(&input.method);
    let resource_type = input.resource_type.trim().to_lowercase();

    if !filters.include_methods.is_empty() {
        let allowed: Vec<String> = filters
            .include_methods
            .iter()
            .map(|m| normalize_method(m))
            .collect();
        if !allowed.contains(&method) {
            return true;
        }
    }

    let excluded_types: Vec<String> = filters
        .exclude_resource_types
        .iter()
        .map(|v| v.to_lowercase())
        .collect();
    if excluded_types.contains(&resource_type) {
        return true;
    }

    let pathname = url_pathname(&input.url);
    for ext in &filters.exclude_extensions {
        let normalized_ext = if ext.starts_with('.') {
            ext.to_lowercase()
        } else {
            format!(".{}", ext.to_lowercase())
        };
        if pathname.ends_with(&normalized_ext) {
            return true;
        }
    }

    if let Some(ref mime_type) = input.mime_type {
        for pattern in &filters.exclude_mime_types {
            if mime_matches(pattern, mime_type) {
                return true;
            }
        }
    }

    for pattern in &filters.exclude_url_patterns {
        if url_matches_pattern(pattern, &input.url) {
            return true;
        }
    }

    if filters.skip_requests_without_origin
        && input.page_url.is_none()
        && input.resource_type != "main_frame"
    {
        return true;
    }

    if filters.skip_empty_responses {
        let status = input.status_code.unwrap_or(0);
        if (status == 204 || status == 304) && input.has_response_body == Some(false) {
            return true;
        }
    }

    false
}

fn normalize_method(method: &str) -> String {
    method.trim().to_uppercase()
}

fn url_pathname(url: &str) -> String {
    Url::parse(url)
        .map(|u| u.path().to_lowercase())
        .unwrap_or_else(|_| url.to_lowercase())
}

fn mime_matches(pattern: &str, mime_type: &str) -> bool {
    let normalized_pattern = pattern.trim().to_lowercase();
    let normalized_mime = mime_type.trim().to_lowercase();
    if normalized_pattern.is_empty() {
        return false;
    }
    if let Some(prefix) = normalized_pattern.strip_suffix('*') {
        return normalized_mime.starts_with(prefix);
    }
    normalized_mime == normalized_pattern
}

fn url_matches_pattern(pattern: &str, url: &str) -> bool {
    let normalized_pattern = pattern.trim().to_lowercase();
    if normalized_pattern.is_empty() {
        return false;
    }
    let normalized_url = url.to_lowercase();

    if normalized_pattern.contains('*') {
        return wildcard_match(&normalized_pattern, &normalized_url);
    }

    normalized_url.contains(&normalized_pattern)
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return text == pattern;
    }

    let mut pos = 0usize;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if index == 0 {
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
            continue;
        }

        if index == parts.len() - 1 && !pattern.ends_with('*') {
            return text.ends_with(part) && pos <= text.len().saturating_sub(part.len());
        }

        let Some(found) = text[pos..].find(part) else {
            return false;
        };
        pos += found + part.len();
    }

    true
}

fn try_parse_http_url(value: &str) -> Option<Url> {
    Url::parse(value)
        .ok()
        .filter(|u| u.scheme() == "http" || u.scheme() == "https")
}

fn hostname_matches_pattern(hostname: &str, pattern: &str) -> bool {
    let normalized_host = hostname.to_lowercase();
    let normalized_pattern = pattern.to_lowercase();

    if normalized_pattern == "*" {
        return true;
    }

    if let Some(suffix) = normalized_pattern.strip_prefix("*.") {
        let suffix = format!(".{suffix}");
        return normalized_host.ends_with(&suffix) && normalized_host.len() > suffix.len();
    }

    normalized_host == normalized_pattern
}

fn normalize_path(pathname: &str) -> String {
    if pathname.is_empty() || pathname == "/" {
        return "/".to_string();
    }
    if pathname.ends_with('/') {
        pathname[..pathname.len() - 1].to_string()
    } else {
        pathname.to_string()
    }
}

fn url_matches_base(target: &Url, base: &Url) -> bool {
    if target.scheme() != base.scheme() {
        return false;
    }
    if target.host_str() != base.host_str() {
        return false;
    }

    let target_port = target
        .port_or_known_default()
        .unwrap_or(if target.scheme() == "https" { 443 } else { 80 });
    let base_port = base
        .port_or_known_default()
        .unwrap_or(if base.scheme() == "https" { 443 } else { 80 });
    if target_port != base_port {
        return false;
    }

    let base_path = normalize_path(base.path());
    if base_path == "/" {
        return true;
    }

    let target_path = normalize_path(target.path());
    target_path == base_path || target_path.starts_with(&format!("{base_path}/"))
}
