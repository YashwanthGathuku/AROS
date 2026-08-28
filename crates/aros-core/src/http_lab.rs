use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid http response")]
    Invalid,
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

pub fn http_get(
    host: &str,
    port: u16,
    path: &str,
    cookie: Option<&str>,
) -> Result<HttpResponse, HttpError> {
    let cookie_header = cookie
        .map(|value| format!("Cookie: {value}\r\n"))
        .unwrap_or_default();
    http_exchange(host, port, "GET", path, None, cookie_header.as_str())
}

pub fn http_get_bearer(
    host: &str,
    port: u16,
    path: &str,
    token: &str,
) -> Result<HttpResponse, HttpError> {
    let headers = format!("Authorization: Bearer {token}\r\n");
    http_exchange(host, port, "GET", path, None, &headers)
}

/// Minimal HTTP/1.1 exchange for loopback daemon/fixture traffic.
pub fn http_exchange(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    extra_headers: &str,
) -> Result<HttpResponse, HttpError> {
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let payload = body.unwrap_or(&[]);
    let content_len = if body.is_some() {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        )
    } else {
        String::new()
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n{extra_headers}{content_len}\r\n"
    );
    stream.write_all(request.as_bytes())?;
    if !payload.is_empty() {
        stream.write_all(payload)?;
    }
    let _ = stream.shutdown(Shutdown::Write);
    let mut buffer = String::new();
    stream.read_to_string(&mut buffer)?;
    parse_response(&buffer)
}

pub fn http_post_json(
    host: &str,
    port: u16,
    path: &str,
    json: &str,
) -> Result<HttpResponse, HttpError> {
    http_exchange(host, port, "POST", path, Some(json.as_bytes()), "")
}

pub fn http_post_json_bearer(
    host: &str,
    port: u16,
    path: &str,
    json: &str,
    token: &str,
) -> Result<HttpResponse, HttpError> {
    let headers = format!("Authorization: Bearer {token}\r\n");
    http_exchange(host, port, "POST", path, Some(json.as_bytes()), &headers)
}

fn parse_response(raw: &str) -> Result<HttpResponse, HttpError> {
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or(HttpError::Invalid)?;
    Ok(HttpResponse {
        status,
        body: body.to_string(),
    })
}
