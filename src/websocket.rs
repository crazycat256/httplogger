use base64::{engine::general_purpose::STANDARD, Engine as _};
use hudsucker::tokio_tungstenite::tungstenite::Message;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use url::Url;

use crate::storage::{now_iso, WebSocketRecorder};

pub fn direction_from_context(ctx: &hudsucker::WebSocketContext) -> &'static str {
    match ctx {
        hudsucker::WebSocketContext::ClientToServer { .. } => "c2s",
        hudsucker::WebSocketContext::ServerToClient { .. } => "s2c",
    }
}

/// Scheme-agnostic endpoint key: `http://host/` and `ws://host/` must match.
pub fn normalize_ws_endpoint(url: &str) -> String {
    match Url::parse(url) {
        Ok(u) => {
            let authority = u.authority();
            let path = u.path();
            if path.is_empty() || path == "/" {
                authority.to_string()
            } else {
                format!("{authority}{path}")
            }
        }
        Err(_) => url.to_string(),
    }
}

pub fn ws_session_key(client_addr: SocketAddr, url: &str) -> (SocketAddr, String) {
    (client_addr, normalize_ws_endpoint(url))
}

pub fn session_key(ctx: &hudsucker::WebSocketContext) -> (SocketAddr, String) {
    match ctx {
        hudsucker::WebSocketContext::ClientToServer { src, dst, .. } => {
            ws_session_key(*src, &dst.to_string())
        }
        hudsucker::WebSocketContext::ServerToClient { src, dst, .. } => {
            ws_session_key(*dst, &src.to_string())
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebSocketCaptureFile {
    pub id: i64,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_url: Option<String>,
    pub opened_at: String,
    pub request: String,
    pub messages: Vec<WebSocketMessageRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebSocketMessageRecord {
    pub direction: String,
    pub timestamp: String,
    #[serde(flatten)]
    pub payload: WebSocketMessagePayload,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WebSocketMessagePayload {
    Text {
        data: String,
    },
    Binary {
        data: String,
    },
    Ping {
        data: String,
    },
    Pong {
        data: String,
    },
    Close {
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<u16>,
        reason: String,
    },
}

fn bytes_to_string(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

pub fn encode_message(message: &Message) -> WebSocketMessagePayload {
    match message {
        Message::Text(text) => WebSocketMessagePayload::Text {
            data: text.to_string(),
        },
        Message::Binary(bytes) => WebSocketMessagePayload::Binary {
            data: STANDARD.encode(bytes),
        },
        Message::Ping(bytes) => WebSocketMessagePayload::Ping {
            data: bytes_to_string(bytes),
        },
        Message::Pong(bytes) => WebSocketMessagePayload::Pong {
            data: bytes_to_string(bytes),
        },
        Message::Close(frame) => {
            let (code, reason) = frame
                .as_ref()
                .map(|frame| (Some(frame.code.into()), frame.reason.to_string()))
                .unwrap_or((None, String::new()));
            WebSocketMessagePayload::Close { code, reason }
        }
        Message::Frame(frame) => WebSocketMessagePayload::Binary {
            data: STANDARD.encode(frame.payload()),
        },
    }
}

/// Outer object is indented; each entry in `messages` is one compact JSON line (easy to grep).
pub fn serialize_capture_file(capture: &WebSocketCaptureFile) -> Result<String, serde_json::Error> {
    let mut out = String::from("{\n");
    out.push_str(&format!("  \"id\": {},\n", capture.id));
    out.push_str(&format!("  \"url\": {},\n", serde_json::to_string(&capture.url)?));
    if let Some(page_url) = &capture.page_url {
        out.push_str(&format!("  \"pageUrl\": {},\n", serde_json::to_string(page_url)?));
    }
    out.push_str(&format!(
        "  \"openedAt\": {},\n",
        serde_json::to_string(&capture.opened_at)?
    ));
    out.push_str(&format!(
        "  \"request\": {},\n",
        serde_json::to_string(&capture.request)?
    ));
    out.push_str("  \"messages\": [\n");

    for (index, message) in capture.messages.iter().enumerate() {
        out.push_str("    ");
        out.push_str(&serde_json::to_string(message)?);
        if index + 1 < capture.messages.len() {
            out.push(',');
        }
        out.push('\n');
    }

    out.push_str("  ]\n");
    out.push('}');
    Ok(out)
}

pub fn record_message(
    recorder: &Arc<WebSocketRecorder>,
    direction: &str,
    message: &Message,
) -> Result<(), anyhow::Error> {
    let entry = WebSocketMessageRecord {
        direction: direction.to_string(),
        timestamp: now_iso(),
        payload: encode_message(message),
    };
    recorder.push_message(entry)
}

pub struct WebSocketSessionRegistry {
    pending: Mutex<std::collections::HashMap<(std::net::SocketAddr, String), std::collections::VecDeque<Arc<WebSocketRecorder>>>>,
    active: Mutex<std::collections::HashMap<(std::net::SocketAddr, String), Arc<WebSocketRecorder>>>,
}

impl WebSocketSessionRegistry {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(std::collections::HashMap::new()),
            active: Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn register_pending(
        &self,
        key: (std::net::SocketAddr, String),
        recorder: Arc<WebSocketRecorder>,
    ) {
        self.pending
            .lock()
            .expect("ws pending mutex poisoned")
            .entry(key)
            .or_default()
            .push_back(recorder);
    }

    pub fn resolve_recorder(
        &self,
        key: (std::net::SocketAddr, String),
    ) -> Option<Arc<WebSocketRecorder>> {
        let mut active = self.active.lock().expect("ws active mutex poisoned");
        if let Some(recorder) = active.get(&key) {
            return Some(recorder.clone());
        }

        let mut pending = self.pending.lock().expect("ws pending mutex poisoned");
        let recorder = pending.get_mut(&key)?.pop_front()?;
        if pending.get(&key).is_some_and(|queue| queue.is_empty()) {
            pending.remove(&key);
        }
        active.insert(key.clone(), recorder.clone());
        Some(recorder)
    }

    pub fn close_session(&self, key: (std::net::SocketAddr, String)) {
        self.active.lock().expect("ws active mutex poisoned").remove(&key);
    }
}
