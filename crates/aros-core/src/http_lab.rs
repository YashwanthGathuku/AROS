use std::io::{Read, Write};
use std::net::TcpStream;
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

/// Minimal HTTP/1.1 GET for local fixture experiments. Not a general client.
pub fn http_get(
    host: &str,
    port: u16,
    path: &str,
    cookie: Option<&str>,
) -> Result<HttpResponse, HttpError> {
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let cookie_header = cookie
        .map(|c| format!("Cookie: {c}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n{cookie_header}\r\n"
    );
    stream.write_all(req.as_bytes())?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    parse_response(&buf)
}

fn parse_response(raw: &str) -> Result<HttpResponse, HttpError> {
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or(HttpError::Invalid)?;
    Ok(HttpResponse {
        status,
        body: body.to_string(),
    })
}
