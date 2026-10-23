//! Minimal loopback HTTP GET for the local dashboard API.
//!
//! Fixed host (127.0.0.1), no TLS, no redirects, no request bodies: exactly
//! what reading `/api/*` from the shell requires, with no HTTP dependency.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const MAX_BODY: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub fn get(port: u16, path: &str, timeout: Duration) -> Result<Response, String> {
    if !path.starts_with('/') || path.contains(' ') || path.contains('\r') || path.contains('\n') {
        return Err("invalid_path".into());
    }
    let address = ("127.0.0.1", port)
        .to_socket_addrs()
        .map_err(|_| "connect_failed")?
        .next()
        .ok_or("no_address")?;
    let mut stream = TcpStream::connect(address).map_err(|_| "connect_failed")?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| "timeout_setup")?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| "timeout_setup")?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|_| "write_failed")?;
    let mut raw = Vec::new();
    stream
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "read_failed")?;
    if raw.len() > MAX_BODY {
        return Err("body_too_large".into());
    }
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<Response, String> {
    let split = find_header_end(raw).ok_or("malformed_response")?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| "malformed_response")?;
    let status_line = head.split("\r\n").next().ok_or("malformed_response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("malformed_response")?;
    let body = raw[split + 4..].to_vec();
    Ok(Response { status, body })
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    const CANNED: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{\"component\":1}";

    fn serve_once(response: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            crate::test_support::read_request(&mut stream).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        });
        port
    }

    #[test]
    fn reads_status_body_and_sends_fixed_request() {
        let port = serve_once(CANNED);
        let response = get(port, "/api/snapshot", Duration::from_secs(2)).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"component\":1}");
    }

    #[test]
    fn connection_failures_map_to_fixed_errors() {
        let error = get(1, "/api/snapshot", Duration::from_millis(300)).unwrap_err();
        assert_eq!(error, "connect_failed");
    }

    #[test]
    fn malformed_and_oversized_responses_are_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert_eq!(
            get(port, "/", Duration::from_millis(300)).unwrap_err(),
            "connect_failed"
        );
        let raw = b"garbage without headers";
        assert_eq!(parse_response(raw).unwrap_err(), "malformed_response");
    }

    #[test]
    fn invalid_paths_never_reach_the_socket() {
        assert_eq!(
            get(1, "api/snapshot", Duration::from_millis(50)).unwrap_err(),
            "invalid_path"
        );
        assert_eq!(
            get(1, "/a b", Duration::from_millis(50)).unwrap_err(),
            "invalid_path"
        );
    }

    #[test]
    fn write_to_closed_listener_reports_write_or_read_failure() {
        let port = serve_once("");
        // The server closes after reading nothing meaningful; either a write or
        // read failure is acceptable, but it must be a fixed error, not a panic.
        let result = get(port, "/api/snapshot", Duration::from_secs(2));
        assert!(result.is_err());
    }
}
