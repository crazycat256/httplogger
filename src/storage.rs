use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::http_raw::{extract_origin_from_url, prepare_message_for_disk};
use crate::websocket::WebSocketCaptureFile;

const DATA_DIR: &str = "httplogger";
const REQUESTS_DIR: &str = "requests";
const WEBSOCKETS_DIR: &str = "websockets";
const METADATA_DB_FILE: &str = "metadata.db";
const REQUESTS_CSV_FILE: &str = "requests.csv";

#[derive(Debug, Clone)]
pub struct HttpRequestRecord {
    pub id: i64,
    pub page_origin: String,
    pub method: String,
    pub url: String,
    pub status_code: Option<i64>,
    pub resource_type: String,
    pub mime_type: Option<String>,
    pub initiator_type: String,
    pub initiator_url: Option<String>,
    pub page_url: Option<String>,
    pub frame_url: Option<String>,
    pub request_sent_at: String,
    pub response_received_at: Option<String>,
    pub req_path: String,
    pub res_path: Option<String>,
}

pub struct RequestStore {
    data_root: PathBuf,
    db: Mutex<Connection>,
}

impl RequestStore {
    pub fn open(workspace_root: &Path) -> Result<Self> {
        let data_root = workspace_root.join(DATA_DIR);
        fs::create_dir_all(&data_root)
            .with_context(|| format!("failed to create {}", data_root.display()))?;

        let db_path = data_root.join(METADATA_DB_FILE);
        let conn = Connection::open(&db_path)
            .with_context(|| format!("failed to open {}", db_path.display()))?;
        ensure_schema(&conn)?;

        Ok(Self {
            data_root,
            db: Mutex::new(conn),
        })
    }

    pub fn persist_flow(
        &self,
        request_raw: &[u8],
        response_raw: Option<&[u8]>,
        request_sent_at: &str,
        response_received_at: Option<&str>,
        page_url: Option<&str>,
        method: &str,
        url: &str,
        resource_type: &str,
        status_code: Option<u16>,
        mime_type: Option<&str>,
    ) -> Result<i64> {
        let page_origin = extract_origin_from_url(page_url)
            .or_else(|| extract_origin_from_url(Some(url)));
        let page_origin = page_origin.context("missing page origin")?;

        let id = {
            let conn = self.db.lock().expect("db mutex poisoned");
            conn.execute(
                "INSERT OR IGNORE INTO origins (origin) VALUES (?1);",
                params![page_origin],
            )?;

            conn.execute(
                "INSERT INTO http_requests (
                    page_origin, method, url, status_code, resource_type, mime_type,
                    initiator_type, initiator_url, page_url, frame_url,
                    request_sent_at, response_received_at, req_path, res_path
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14);",
                params![
                    page_origin,
                    method,
                    url,
                    status_code.map(i64::from),
                    resource_type,
                    mime_type,
                    resource_type,
                    page_url,
                    page_url,
                    Option::<&str>::None,
                    request_sent_at,
                    response_received_at,
                    "",
                    Option::<&str>::None,
                ],
            )?;

            conn.last_insert_rowid()
        };

        let req_file_name = format!("{id:05}.req");
        let res_file_name = format!("{id:05}.res");
        let req_relative_path = format!("{DATA_DIR}/{REQUESTS_DIR}/{req_file_name}");
        let res_relative_path = format!("{DATA_DIR}/{REQUESTS_DIR}/{res_file_name}");

        let requests_dir = self.data_root.join(REQUESTS_DIR);
        fs::create_dir_all(&requests_dir)
            .with_context(|| format!("failed to create {}", requests_dir.display()))?;

        fs::write(
            requests_dir.join(&req_file_name),
            prepare_message_for_disk(request_raw),
        )?;

        let mut res_path: Option<String> = None;
        if let Some(response_raw) = response_raw {
            fs::write(
                requests_dir.join(&res_file_name),
                prepare_message_for_disk(response_raw),
            )?;
            res_path = Some(res_relative_path);
        }

        {
            let conn = self.db.lock().expect("db mutex poisoned");
            conn.execute(
                "UPDATE http_requests SET req_path = ?1, res_path = ?2 WHERE id = ?3;",
                params![req_relative_path, res_path, id],
            )?;
        }

        self.export_csv()?;
        Ok(id)
    }

    pub fn export_csv(&self) -> Result<()> {
        let records = self.get_all_records()?;
        let csv = to_requests_csv(&records);
        fs::write(self.data_root.join(REQUESTS_CSV_FILE), csv)?;
        Ok(())
    }

    fn get_all_records(&self) -> Result<Vec<HttpRequestRecord>> {
        let conn = self.db.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, page_origin, method, url, status_code, resource_type, mime_type,
                    initiator_type, initiator_url, page_url, frame_url,
                    request_sent_at, response_received_at, req_path, res_path
             FROM http_requests
             ORDER BY id ASC;",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(HttpRequestRecord {
                id: row.get(0)?,
                page_origin: row.get(1)?,
                method: row.get(2)?,
                url: row.get(3)?,
                status_code: row.get(4)?,
                resource_type: row.get(5)?,
                mime_type: row.get(6)?,
                initiator_type: row.get(7)?,
                initiator_url: row.get(8)?,
                page_url: row.get(9)?,
                frame_url: row.get(10)?,
                request_sent_at: row.get(11)?,
                response_received_at: row.get(12)?,
                req_path: row.get(13)?,
                res_path: row.get(14)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>()
            .context("failed to read http_requests")
    }

    pub fn create_websocket_session(
        &self,
        request_raw: &[u8],
        url: &str,
        page_url: Option<&str>,
        opened_at: &str,
    ) -> Result<Arc<WebSocketRecorder>> {
        let page_origin = extract_origin_from_url(page_url)
            .or_else(|| extract_origin_from_url(Some(url)));

        let id = {
            let conn = self.db.lock().expect("db mutex poisoned");
            if let Some(ref page_origin) = page_origin {
                conn.execute(
                    "INSERT OR IGNORE INTO origins (origin) VALUES (?1);",
                    params![page_origin],
                )?;
            }

            conn.execute(
                "INSERT INTO websocket_sessions (url, page_url, page_origin, opened_at, file_path)
                 VALUES (?1, ?2, ?3, ?4, ?5);",
                params![url, page_url, page_origin, opened_at, ""],
            )?;
            conn.last_insert_rowid()
        };

        let file_name = format!("{id:05}.ws.json");
        let relative_path = format!("{DATA_DIR}/{WEBSOCKETS_DIR}/{file_name}");
        let websockets_dir = self.data_root.join(WEBSOCKETS_DIR);
        fs::create_dir_all(&websockets_dir)
            .with_context(|| format!("failed to create {}", websockets_dir.display()))?;

        let file_path = websockets_dir.join(&file_name);
        let request = String::from_utf8_lossy(request_raw).into_owned();

        let recorder = Arc::new(WebSocketRecorder {
            id,
            url: url.to_string(),
            page_url: page_url.map(str::to_string),
            opened_at: opened_at.to_string(),
            request,
            file_path,
            relative_path: relative_path.clone(),
            messages: Mutex::new(Vec::new()),
        });
        recorder.flush()?;

        {
            let conn = self.db.lock().expect("db mutex poisoned");
            conn.execute(
                "UPDATE websocket_sessions SET file_path = ?1 WHERE id = ?2;",
                params![relative_path, id],
            )?;
        }

        Ok(recorder)
    }
}

pub struct WebSocketRecorder {
    id: i64,
    url: String,
    page_url: Option<String>,
    opened_at: String,
    request: String,
    file_path: PathBuf,
    relative_path: String,
    messages: Mutex<Vec<crate::websocket::WebSocketMessageRecord>>,
}

impl WebSocketRecorder {
    pub fn id(&self) -> i64 {
        self.id
    }

    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub fn push_message(
        &self,
        message: crate::websocket::WebSocketMessageRecord,
    ) -> Result<()> {
        self.messages
            .lock()
            .expect("ws messages mutex poisoned")
            .push(message);
        self.flush()
    }

    fn flush(&self) -> Result<()> {
        let messages = self
            .messages
            .lock()
            .expect("ws messages mutex poisoned")
            .clone();
        let capture = WebSocketCaptureFile {
            id: self.id,
            url: self.url.clone(),
            page_url: self.page_url.clone(),
            opened_at: self.opened_at.clone(),
            request: self.request.clone(),
            messages,
        };
        let json = crate::websocket::serialize_capture_file(&capture)
            .context("failed to encode websocket JSON")?;
        fs::write(&self.file_path, json)
            .with_context(|| format!("failed to write {}", self.file_path.display()))?;
        Ok(())
    }
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS origins (
            origin TEXT PRIMARY KEY
        );

        CREATE TABLE IF NOT EXISTS http_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_origin TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER,
            resource_type TEXT NOT NULL,
            mime_type TEXT,
            initiator_type TEXT NOT NULL,
            initiator_url TEXT,
            page_url TEXT,
            frame_url TEXT,
            request_sent_at TEXT NOT NULL,
            response_received_at TEXT,
            req_path TEXT NOT NULL,
            res_path TEXT,
            FOREIGN KEY (page_origin) REFERENCES origins(origin) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_http_requests_origin ON http_requests(page_origin);
        CREATE INDEX IF NOT EXISTS idx_http_requests_sent_at ON http_requests(request_sent_at);

        CREATE TABLE IF NOT EXISTS websocket_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            page_url TEXT,
            page_origin TEXT,
            opened_at TEXT NOT NULL,
            file_path TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_websocket_sessions_opened_at ON websocket_sessions(opened_at);
        ",
    )?;
    Ok(())
}

pub fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn to_requests_csv(records: &[HttpRequestRecord]) -> String {
    let header = [
        "id",
        "method",
        "url",
        "status_code",
        "resource_type",
        "mime_type",
        "initiator_type",
        "initiator_url",
        "page_origin",
        "page_url",
        "frame_url",
        "request_sent_at",
        "response_received_at",
        "req_file",
        "res_file",
    ]
    .join(",");

    let rows: Vec<String> = records
        .iter()
        .map(|record| {
            [
                record.id.to_string(),
                csv_escape(&record.method),
                csv_escape(&record.url),
                record
                    .status_code
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
                csv_escape(&record.resource_type),
                csv_escape(record.mime_type.as_deref().unwrap_or("")),
                csv_escape(&record.initiator_type),
                csv_escape(record.initiator_url.as_deref().unwrap_or("")),
                csv_escape(&record.page_origin),
                csv_escape(record.page_url.as_deref().unwrap_or("")),
                csv_escape(record.frame_url.as_deref().unwrap_or("")),
                csv_escape(&record.request_sent_at),
                csv_escape(record.response_received_at.as_deref().unwrap_or("")),
                csv_escape(&record.req_path),
                csv_escape(record.res_path.as_deref().unwrap_or("")),
            ]
            .join(",")
        })
        .collect();

    let mut out = String::new();
    out.push_str(&header);
    out.push('\n');
    for row in rows {
        out.push_str(&row);
        out.push('\n');
    }
    out
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
