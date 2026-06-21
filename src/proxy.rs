use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hudsucker::{
    hyper::{Method, Request, Response},
    Body, HttpContext, HttpHandler, RequestOrResponse, WebSocketContext, WebSocketHandler,
};
use hudsucker::tokio_tungstenite::tungstenite::Message;
use http_body_util::BodyExt;
use tracing::{error, info, warn};

use crate::config::AppConfig;
use crate::filter::{matches_http_request_scope, should_filter_http_request, HttpRequestFilterInput};
use crate::http_raw::{
    header_value, infer_resource_type, is_browser_internal_request, page_url_from_request,
    parse_header_value, parse_response_status, request_url_from_message, resolve_request_url,
    serialize_request, serialize_response, split_headers_and_body,
};
use crate::storage::{now_iso, RequestStore};
use crate::websocket::{
    direction_from_context, record_message, session_key, ws_session_key, WebSocketSessionRegistry,
};

const MAX_CAPTURE_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct CaptureHandler {
    config: Arc<AppConfig>,
    store: Arc<RequestStore>,
    pending: Arc<Mutex<HashMap<SocketAddr, VecDeque<QueueEntry>>>>,
    ws_sessions: Arc<WebSocketSessionRegistry>,
}

enum QueueEntry {
    Skipped,
    Captured(PendingFlow),
}

struct PendingFlow {
    request_sent_at: String,
    request_raw: Vec<u8>,
    request_body_bytes: usize,
    page_url: Option<String>,
    method: String,
    url: String,
    resource_type: String,
}

impl CaptureHandler {
    pub fn new(config: Arc<AppConfig>, store: Arc<RequestStore>) -> Self {
        Self {
            config,
            store,
            pending: Arc::new(Mutex::new(HashMap::new())),
            ws_sessions: Arc::new(WebSocketSessionRegistry::new()),
        }
    }

    fn push_skip(&self, client_addr: SocketAddr) {
        self.push_entry(client_addr, QueueEntry::Skipped);
    }

    fn push_entry(&self, client_addr: SocketAddr, entry: QueueEntry) {
        self.pending
            .lock()
            .expect("pending mutex poisoned")
            .entry(client_addr)
            .or_default()
            .push_back(entry);
    }

    fn pop_entry(&self, client_addr: SocketAddr) -> Option<QueueEntry> {
        let mut guard = self.pending.lock().expect("pending mutex poisoned");
        let queue = guard.get_mut(&client_addr)?;
        let entry = queue.pop_front()?;
        if queue.is_empty() {
            guard.remove(&client_addr);
        }
        Some(entry)
    }

    fn filter_input(
        method: &str,
        url: &str,
        resource_type: &str,
        page_url: Option<String>,
        mime_type: Option<String>,
        status_code: Option<u16>,
        has_response_body: Option<bool>,
    ) -> HttpRequestFilterInput {
        HttpRequestFilterInput {
            method: method.to_string(),
            url: url.to_string(),
            resource_type: resource_type.to_string(),
            mime_type,
            status_code,
            has_response_body,
            page_url,
        }
    }
}

impl HttpHandler for CaptureHandler {
    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        if req.method() == Method::CONNECT {
            return req.into();
        }

        if header_value(req.headers(), "upgrade")
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        {
            return self.handle_websocket_upgrade(ctx, req).await;
        }

        if is_browser_internal_request(&req) {
            self.push_skip(ctx.client_addr);
            return req.into();
        }

        let is_ssl = req.uri().scheme_str() == Some("https")
            || header_value(req.headers(), ":scheme").is_some_and(|v| v == "https");

        let url = match request_url_from_message(&req, is_ssl) {
            Some(url) => url,
            None => {
                self.push_skip(ctx.client_addr);
                return req.into();
            }
        };

        let resource_type = infer_resource_type(&req, &url);
        let page_url = page_url_from_request(&req)
            .or_else(|| (resource_type == "main_frame").then(|| url.clone()));

        if !matches_http_request_scope(page_url.as_deref(), &url, &self.config.scope) {
            self.push_skip(ctx.client_addr);
            return req.into();
        }

        if should_filter_http_request(
            &Self::filter_input(
                req.method().as_str(),
                &url,
                &resource_type,
                page_url.clone(),
                None,
                None,
                None,
            ),
            &self.config.filters,
        ) {
            self.push_skip(ctx.client_addr);
            return req.into();
        }

        let (parts, body) = req.into_parts();
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(err) => {
                warn!(%err, "skipping request capture due to body read failure");
                self.push_skip(ctx.client_addr);
                return Request::from_parts(parts, Body::empty()).into();
            }
        };

        if body_bytes.len() > MAX_CAPTURE_BODY_BYTES {
            self.push_skip(ctx.client_addr);
            return Request::from_parts(parts, Body::from(body_bytes)).into();
        }

        let rebuilt = Request::from_parts(parts.clone(), Body::from(body_bytes.clone()));
        let request_raw = serialize_request(&rebuilt, &body_bytes);
        let resolved_url = resolve_request_url(&request_raw).unwrap_or(url);

        self.push_entry(
            ctx.client_addr,
            QueueEntry::Captured(PendingFlow {
                request_sent_at: now_iso(),
                request_raw,
                request_body_bytes: body_bytes.len(),
                page_url,
                method: rebuilt.method().as_str().to_string(),
                url: resolved_url,
                resource_type,
            }),
        );

        Request::from_parts(parts, Body::from(body_bytes)).into()
    }

    async fn handle_response(
        &mut self,
        ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        let Some(entry) = self.pop_entry(ctx.client_addr) else {
            return res;
        };
        let QueueEntry::Captured(flow) = entry else {
            return res;
        };

        let (parts, body) = res.into_parts();
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(err) => {
                warn!(%err, "skipping response capture due to body read failure");
                return Response::from_parts(parts, Body::empty());
            }
        };

        if flow.request_body_bytes + body_bytes.len() > MAX_CAPTURE_BODY_BYTES {
            return Response::from_parts(parts, Body::from(body_bytes));
        }

        let rebuilt = Response::from_parts(parts.clone(), Body::from(body_bytes.clone()));
        let response_raw = serialize_response(&rebuilt, &body_bytes);

        let status_code = parse_response_status(&response_raw);
        let mime_type = parse_header_value(&response_raw, "content-type")
            .map(|v| v.split(';').next().unwrap_or("").trim().to_string())
            .filter(|v| !v.is_empty());
        let has_response_body = split_headers_and_body(&response_raw)
            .is_some_and(|split| !split.body_raw.is_empty());

        if should_filter_http_request(
            &Self::filter_input(
                &flow.method,
                &flow.url,
                &flow.resource_type,
                flow.page_url.clone(),
                mime_type.clone(),
                status_code,
                Some(has_response_body),
            ),
            &self.config.filters,
        ) {
            return Response::from_parts(parts, Body::from(body_bytes));
        }

        match self.store.persist_flow(
            &flow.request_raw,
            Some(&response_raw),
            &flow.request_sent_at,
            Some(&now_iso()),
            flow.page_url.as_deref(),
            &flow.method,
            &flow.url,
            &flow.resource_type,
            status_code,
            mime_type.as_deref(),
        ) {
            Ok(id) => info!(
                id,
                method = %flow.method,
                url = %flow.url,
                status = ?status_code,
                "stored HTTP flow"
            ),
            Err(err) => error!(%err, "failed to persist HTTP flow"),
        }

        Response::from_parts(parts, Body::from(body_bytes))
    }
}

impl CaptureHandler {
    async fn handle_websocket_upgrade(
        &self,
        ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let is_ssl = matches!(
            req.uri().scheme_str(),
            Some("https") | Some("wss")
        ) || header_value(req.headers(), ":scheme")
            .is_some_and(|v| v == "https" || v == "wss");

        let url = match request_url_from_message(&req, is_ssl) {
            Some(url) => url,
            None => return req.into(),
        };

        let page_url = page_url_from_request(&req);
        if !matches_http_request_scope(page_url.as_deref(), &url, &self.config.scope) {
            return req.into();
        }

        let (parts, body) = req.into_parts();
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(err) => {
                warn!(%err, "skipping websocket capture due to body read failure");
                return Request::from_parts(parts, Body::empty()).into();
            }
        };

        if body_bytes.len() > MAX_CAPTURE_BODY_BYTES {
            return Request::from_parts(parts, Body::from(body_bytes)).into();
        }

        let rebuilt = Request::from_parts(parts.clone(), Body::from(body_bytes.clone()));
        let request_raw = serialize_request(&rebuilt, &body_bytes);

        match self.store.create_websocket_session(
            &request_raw,
            &url,
            page_url.as_deref(),
            &now_iso(),
        ) {
            Ok(recorder) => {
                let key = ws_session_key(ctx.client_addr, &url);
                self.ws_sessions.register_pending(key, recorder.clone());
                info!(
                    id = recorder.id(),
                    url = %url,
                    file = %recorder.relative_path(),
                    "registered websocket session"
                );
            }
            Err(err) => error!(%err, "failed to create websocket session"),
        }

        Request::from_parts(parts, Body::from(body_bytes)).into()
    }
}

impl WebSocketHandler for CaptureHandler {
    async fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        let key = session_key(ctx);
        let Some(recorder) = self.ws_sessions.resolve_recorder(key.clone()) else {
            return Some(message);
        };

        let direction = direction_from_context(ctx);
        match record_message(&recorder, direction, &message) { Err(err) => {
            error!(%err, id = recorder.id(), "failed to record websocket message");
        } _ => if matches!(message, Message::Text(_) | Message::Binary(_)) {
            info!(
                id = recorder.id(),
                direction,
                "stored websocket message"
            );
        }}

        if matches!(message, Message::Close(_)) {
            self.ws_sessions.close_session(key);
        }

        Some(message)
    }
}
