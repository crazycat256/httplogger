use anyhow::{Context, Result};
use brotli::Decompressor;
use flate2::read::{DeflateDecoder, GzDecoder};
use hudsucker::hyper::{header::HeaderMap, Request, Response, Uri, Version};
use hudsucker::Body;
use std::io::Read;
use url::Url;

pub struct HeaderBodySplit<'a> {
    pub headers_raw: &'a [u8],
    pub body_raw: &'a [u8],
}

/// Split an HTTP message into raw header block (including terminator) and body.
pub fn split_headers_and_body(raw: &[u8]) -> Option<HeaderBodySplit<'_>> {
    if let Some(crlf_sep) = find_subslice(raw, b"\r\n\r\n") {
        return Some(HeaderBodySplit {
            headers_raw: &raw[..crlf_sep + 4],
            body_raw: &raw[crlf_sep + 4..],
        });
    }

    if let Some(lf_sep) = find_subslice(raw, b"\n\n") {
        return Some(HeaderBodySplit {
            headers_raw: &raw[..lf_sep + 2],
            body_raw: &raw[lf_sep + 2..],
        });
    }

    split_headers_and_body_without_blank_line(raw)
}

/// Fallback when headers are followed directly by the body (missing blank line).
fn split_headers_and_body_without_blank_line(raw: &[u8]) -> Option<HeaderBodySplit<'_>> {
    let mut line_start = 0;
    let mut first_line = true;

    while line_start < raw.len() {
        let line_end = match raw[line_start..].iter().position(|&b| b == b'\n') {
            Some(index) => line_start + index,
            None => {
                if first_line {
                    return None;
                }
                return Some(HeaderBodySplit {
                    headers_raw: &raw[..line_start],
                    body_raw: &raw[line_start..],
                });
            }
        };

        let line = trim_line_ending(&raw[line_start..line_end]);

        if line.is_empty() {
            let body_start = line_end_after(line_end, raw);
            return Some(HeaderBodySplit {
                headers_raw: &raw[..body_start],
                body_raw: &raw[body_start..],
            });
        }

        if !first_line && !is_header_field_line(line) {
            return Some(HeaderBodySplit {
                headers_raw: &raw[..line_start],
                body_raw: &raw[line_start..],
            });
        }

        first_line = false;
        line_start = line_end_after(line_end, raw);
    }

    None
}

fn line_end_after(line_end: usize, raw: &[u8]) -> usize {
    if raw[line_end..].starts_with(b"\r\n") {
        line_end + 2
    } else {
        line_end + 1
    }
}

fn trim_line_ending(line: &[u8]) -> &[u8] {
    if line.ends_with(b"\r") {
        &line[..line.len() - 1]
    } else {
        line
    }
}

fn is_header_field_line(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    if colon == 0 {
        return false;
    }
    line[..colon]
        .iter()
        .all(|&b| (0x21..=0x7e).contains(&b) || b == b'\t')
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn latin1_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

fn latin1_bytes(text: &str) -> Vec<u8> {
    text.chars().map(|c| c as u8).collect()
}

fn header_lines(headers_raw: &[u8]) -> Vec<String> {
    let text = latin1_to_string(headers_raw);
    let mut lines: Vec<String> = text
        .split('\n')
        .map(|line| line.trim_end_matches('\r').to_string())
        .collect();
    if lines.last().map(|line| line.is_empty()).unwrap_or(false) {
        lines.pop();
    }
    if lines.first().is_some_and(|line| line.contains('\r')) {
        lines = lines
            .into_iter()
            .map(|line| line.trim_end_matches('\r').to_string())
            .collect();
    }
    lines
}

/// Read a header value from raw header bytes (case-insensitive).
pub fn parse_header_value(headers_raw: &[u8], name: &str) -> Option<String> {
    let target = name.to_lowercase();
    for line in header_lines(headers_raw) {
        let Some((header_name, value)) = split_header_line(&line) else {
            continue;
        };
        if header_name != target {
            continue;
        }
        return Some(value);
    }
    None
}

fn split_header_line(line: &str) -> Option<(String, String)> {
    if line.starts_with(':') {
        let rest = &line[1..];
        let colon = rest.find(':')?;
        let name = format!(":{}", &rest[..colon]).to_lowercase();
        let value = rest[colon + 1..].trim().to_string();
        return Some((name, value));
    }

    let colon = line.find(':')?;
    if colon == 0 {
        return None;
    }
    Some((
        line[..colon].trim().to_lowercase(),
        line[colon + 1..].trim().to_string(),
    ))
}

pub fn parse_content_encoding(headers_raw: &[u8]) -> Option<String> {
    parse_header_value(headers_raw, "content-encoding")
}

pub fn decompress_body(body: &[u8], encoding: &str) -> Result<Vec<u8>> {
    let primary = encoding.split(',').next().unwrap_or("").trim().to_lowercase();
    match primary.as_str() {
        "gzip" | "x-gzip" => {
            let mut decoder = GzDecoder::new(body);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).context("gzip decompress failed")?;
            Ok(out)
        }
        "deflate" => {
            let mut decoder = DeflateDecoder::new(body);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .context("deflate decompress failed")?;
            Ok(out)
        }
        "br" => {
            let mut out = Vec::new();
            let mut decoder = Decompressor::new(body, 4096);
            decoder
                .read_to_end(&mut out)
                .context("brotli decompress failed")?;
            Ok(out)
        }
        other => anyhow::bail!("unsupported content-encoding: {other}"),
    }
}

/// Prepare an HTTP message for on-disk storage.
/// Without Content-Encoding: write the raw bytes unchanged.
/// With Content-Encoding: write raw headers + decompressed body.
pub fn prepare_message_for_disk(raw: &[u8]) -> Vec<u8> {
    let Some(split) = split_headers_and_body(raw) else {
        return raw.to_vec();
    };

    let Some(encoding) = parse_content_encoding(split.headers_raw) else {
return raw.to_vec();
    };

    match decompress_body(split.body_raw, &encoding) {
        Ok(decompressed) => {
            let mut out = Vec::with_capacity(split.headers_raw.len() + decompressed.len());
            out.extend_from_slice(split.headers_raw);
            out.extend_from_slice(&decompressed);
            out
        }
        Err(_) => raw.to_vec(),
    }
}

pub fn first_line(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == b'\n');
    let slice = match end {
        Some(index) => &raw[..index],
        None => raw,
    };
    latin1_to_string(slice).trim_end_matches('\r').to_string()
}

pub fn parse_request_line(raw: &[u8]) -> Option<(String, String)> {
    let line = first_line(raw);
    let parts: Vec<&str> = line.split(' ').collect();
    if parts.len() < 2 {
        return None;
    }
    Some((parts[0].to_string(), parts[1].to_string()))
}

pub fn resolve_request_url(raw: &[u8]) -> Option<String> {
    let (_method, target) = parse_request_line(raw)?;
    if target.starts_with("http://") || target.starts_with("https://") {
        return Some(target);
    }
    let host = request_host_from_raw(raw)?;
    let scheme = parse_header_value(raw, ":scheme")
        .or_else(|| parse_header_value(raw, "x-forwarded-proto"))
        .unwrap_or_else(|| "https".to_string());
    Some(absolute_http_url(&target, &host, &scheme))
}

pub fn parse_response_status(raw: &[u8]) -> Option<u16> {
    let line = first_line(raw);
    if !line.starts_with("HTTP/") {
        return None;
    }
    let mut parts = line.split_whitespace();
    parts.next()?;
    parts.next()?.parse().ok()
}

pub fn extract_origin_from_url(url: Option<&str>) -> Option<String> {
    let url = url?;
    let parsed = Url::parse(url).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?;
    let default_port = if parsed.scheme() == "https" { 443 } else { 80 };
    match parsed.port_or_known_default() {
        Some(port) if port != default_port => {
            Some(format!("{}://{}:{}", parsed.scheme(), host, port))
        }
        _ => Some(format!("{}://{}", parsed.scheme(), host)),
    }
}

pub fn serialize_request(req: &Request<Body>, body: &[u8]) -> Vec<u8> {
    let method = req.method().as_str();
    let target = req.uri().to_string();
    let version = http_version_string(req.version());
    let header_block = serialize_raw_headers(req.headers());
    let mut out = latin1_bytes(&format!("{method} {target} HTTP/{version}\r\n{header_block}\r\n\r\n"));
    out.extend_from_slice(body);
    out
}

pub fn serialize_response(res: &Response<Body>, body: &[u8]) -> Vec<u8> {
    let version = http_version_string(res.version());
    let status = res.status().as_u16();
    let status_text = res.status().canonical_reason().unwrap_or("");
    let header_block = serialize_raw_headers(res.headers());
    let mut out = latin1_bytes(&format!(
        "HTTP/{version} {status} {status_text}\r\n{header_block}\r\n\r\n"
    ));
    out.extend_from_slice(body);
    out
}

fn serialize_raw_headers(headers: &HeaderMap) -> String {
    let mut lines = Vec::new();
    for (name, value) in headers.iter() {
        let value = value.to_str().unwrap_or("");
        lines.push(format!("{}: {value}", name.as_str()));
    }
    lines.join("\r\n")
}

fn http_version_string(version: Version) -> &'static str {
    match version {
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2",
        Version::HTTP_3 => "3",
        _ => "1.1",
    }
}

pub fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let target = name.to_lowercase();
    for (key, value) in headers.iter() {
        if key.as_str().to_lowercase() == target {
            return value.to_str().ok().map(str::to_string);
        }
    }
    None
}

pub fn request_url_from_message(req: &Request<Body>, is_ssl: bool) -> Option<String> {
    let target = req.uri().to_string();
    if target.starts_with("http://") || target.starts_with("https://") {
        return Some(target);
    }

    let host = request_host(req.headers(), req.uri())?;
    let scheme = req
        .uri()
        .scheme_str()
        .map(str::to_string)
        .or_else(|| header_value(req.headers(), ":scheme"))
        .unwrap_or_else(|| if is_ssl { "https".into() } else { "http".into() });
    Some(absolute_http_url(&target, &host, &scheme))
}

/// Host for HTTP/1.x (`Host`) or HTTP/2 (`:authority`), else URI authority.
fn request_host(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    header_value(headers, "host")
        .or_else(|| header_value(headers, ":authority"))
        .or_else(|| uri.authority().map(|authority| authority.to_string()))
}

fn request_host_from_raw(raw: &[u8]) -> Option<String> {
    parse_header_value(raw, "host").or_else(|| parse_header_value(raw, ":authority"))
}

pub fn page_url_from_request(req: &Request<Body>) -> Option<String> {
    header_value(req.headers(), "referer").or_else(|| header_value(req.headers(), "origin"))
}

/// Browser-internal traffic: sync/telemetry (sec-fetch) or requests from UI
/// pages that are not real web origins (chrome://, chrome-untrusted://, …).
pub fn is_browser_internal_request(req: &Request<Body>) -> bool {
    if header_value(req.headers(), "sec-fetch-site").is_some_and(|site| {
        site.eq_ignore_ascii_case("none")
    }) && header_value(req.headers(), "sec-fetch-dest")
        .is_some_and(|dest| dest.eq_ignore_ascii_case("empty"))
    {
        return true;
    }

    for header in ["origin", "referer"] {
        let Some(value) = header_value(req.headers(), header) else {
            continue;
        };
        if is_browser_ui_origin(&value) {
            return true;
        }
    }

    false
}

fn is_browser_ui_origin(value: &str) -> bool {
    if value.eq_ignore_ascii_case("null") {
        return false;
    }
    let Ok(parsed) = Url::parse(value) else {
        return false;
    };
    !matches!(parsed.scheme(), "http" | "https")
}

pub fn infer_resource_type(req: &Request<Body>, url: &str) -> String {
    if let Some(dest) = header_value(req.headers(), "sec-fetch-dest") {
        let mapped = match dest.to_lowercase().as_str() {
            "document" => "main_frame",
            "iframe" => "sub_frame",
            "script" => "script",
            "style" => "stylesheet",
            "image" => "image",
            "font" => "font",
            "empty" => "fetch",
            _ => "",
        };
        if !mapped.is_empty() {
            return mapped.to_string();
        }
    }

    if let Some(mode) = header_value(req.headers(), "sec-fetch-mode") {
        match mode.to_lowercase().as_str() {
            "navigate" => return "main_frame".to_string(),
            "cors" | "no-cors" => return "fetch".to_string(),
            _ => {}
        }
    }

    if let Ok(parsed) = Url::parse(url) {
        let pathname = parsed.path().to_lowercase();
        if pathname.ends_with(".js") {
            return "script".to_string();
        }
        if pathname.ends_with(".css") {
            return "stylesheet".to_string();
        }
    }

    "other".to_string()
}

fn absolute_http_url(target: &str, host: &str, scheme: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("{scheme}://{host}{target}")
    }
}
