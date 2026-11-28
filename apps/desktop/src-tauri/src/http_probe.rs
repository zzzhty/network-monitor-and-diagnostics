//! Minimal loopback HTTP GET for the local dashboard API.
//!
//! Fixed host (127.0.0.1), no TLS, no redirects, no request bodies: exactly
//! what reading `/api/*` from the shell requires, with no HTTP dependency.
//!
//! `timeout` is an overall deadline for the call, not an inactivity timer.
//! `read_to_end` would keep going while a peer dribbles bytes, so a higher
//! port in the startup scan could hold the shell after a lower port had
//! already answered. The handshake has its own shorter cap: on the
//! windows-2022 desktop-shell job for 6e08315, unbounded connects across
//! 8765–8796 spent 64.73s inside
//! `ensure_server_reports_missing_cli_deterministically`.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MAX_BODY: usize = 4 * 1024 * 1024;
/// Loopback handshake cap. A closed port refuses immediately; a port that
/// never completes the handshake must not inherit the multi-second read budget.
const CONNECT_BUDGET: Duration = Duration::from_millis(200);
/// How often a blocked read rechecks the deadline and the cancel flag.
const READ_SLICE: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub fn get(port: u16, path: &str, timeout: Duration) -> Result<Response, String> {
    get_cancellable(port, path, timeout, &AtomicBool::new(false))
}

/// Same as [`get`], but returns as soon as `cancel` is set.
///
/// The startup scan sets that flag once a lower port has already matched.
/// Scoped threads are joined before the scan returns, so a higher port that
/// kept sending would otherwise hold the whole scan for as long as the bytes
/// continued.
pub(crate) fn get_cancellable(
    port: u16,
    path: &str,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<Response, String> {
    if !path.starts_with('/') || path.contains(' ') || path.contains('\r') || path.contains('\n') {
        return Err("invalid_path".into());
    }
    if cancel.load(Ordering::Acquire) {
        return Err("read_failed".into());
    }
    let deadline = Instant::now() + timeout;
    let address = ("127.0.0.1", port)
        .to_socket_addrs()
        .map_err(|_| "connect_failed")?
        .next()
        .ok_or("no_address")?;
    let connect_budget = timeout.min(CONNECT_BUDGET);
    let mut stream =
        TcpStream::connect_timeout(&address, connect_budget).map_err(|_| "connect_failed")?;
    let write_budget = time_left(deadline).ok_or("read_failed")?;
    stream
        .set_write_timeout(Some(write_budget))
        .map_err(|_| "timeout_setup")?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|_| "write_failed")?;
    let raw = read_message(&mut stream, deadline, cancel)?;
    parse_response(&raw)
}

fn time_left(deadline: Instant) -> Option<Duration> {
    let left = deadline.checked_duration_since(Instant::now())?;
    (left >= Duration::from_millis(1)).then_some(left)
}

fn read_message(
    stream: &mut TcpStream,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, String> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err("read_failed".into());
        }
        if let Some(end) = complete_message_end(&raw) {
            if end > MAX_BODY {
                return Err("body_too_large".into());
            }
            raw.truncate(end);
            return Ok(raw);
        }
        if raw.len() > MAX_BODY {
            return Err("body_too_large".into());
        }
        let Some(left) = time_left(deadline) else {
            return Err("read_failed".into());
        };
        stream
            .set_read_timeout(Some(left.min(READ_SLICE)))
            .map_err(|_| "timeout_setup")?;
        match stream.read(&mut buf) {
            Ok(0) => return Ok(raw),
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => return Err("read_failed".into()),
        }
    }
}

/// Byte length of one HTTP message once headers and `Content-Length` are in
/// hand. A peer that keeps writing after that is ignored. Without
/// `Content-Length`, the caller waits for EOF or the deadline.
fn complete_message_end(raw: &[u8]) -> Option<usize> {
    let split = find_header_end(raw)?;
    let head = std::str::from_utf8(raw.get(..split)?).ok()?;
    let mut length = None;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse().ok();
        }
    }
    let length = length?;
    let end = split.checked_add(4)?.checked_add(length)?;
    (raw.len() >= end).then_some(end)
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

    const CANNED: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"component\":1}";

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
    fn refused_connect_does_not_consume_the_read_timeout() {
        // Port 1 stays closed. The read budget is intentionally long: before
        // connect_timeout, Windows spent about two seconds in connect and
        // never applied this 30s value. The handshake cap is 200ms.
        let started = std::time::Instant::now();
        let error = get(1, "/api/snapshot", Duration::from_secs(30)).unwrap_err();
        assert_eq!(error, "connect_failed");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "refused connect waited {elapsed:?}"
        );
    }

    #[test]
    fn malformed_and_oversized_responses_are_rejected() {
        // cargo test runs in parallel. Binding 127.0.0.1:0 and dropping it
        // lets another test reuse that ephemeral port, so the connect is
        // accepted and the read fails. Port 1 stays closed here.
        assert_eq!(
            get(1, "/", Duration::from_millis(300)).unwrap_err(),
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
    fn bytes_after_content_length_do_not_hold_the_read() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = crate::test_support::read_request(&mut stream);
            let _ = stream.write_all(CANNED.as_bytes());
            for _ in 0..100 {
                std::thread::sleep(Duration::from_millis(30));
                if stream.write_all(b"x").is_err() {
                    break;
                }
            }
        });
        let started = std::time::Instant::now();
        let response = get(port, "/api/snapshot", Duration::from_secs(2)).unwrap();
        let elapsed = started.elapsed();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"component\":1}");
        assert!(
            elapsed < Duration::from_millis(800),
            "complete response waited {elapsed:?}"
        );
        let _ = server.join();
    }

    #[test]
    fn a_trickle_cannot_outlive_the_overall_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = crate::test_support::read_request(&mut stream);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n");
            for _ in 0..200 {
                std::thread::sleep(Duration::from_millis(30));
                if stream.write_all(b"x").is_err() {
                    break;
                }
            }
        });
        let started = std::time::Instant::now();
        let error = get(port, "/api/snapshot", Duration::from_millis(400)).unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(error, "read_failed");
        assert!(
            elapsed < Duration::from_millis(1200),
            "trickle waited {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(300),
            "trickle returned early at {elapsed:?}"
        );
        let _ = server.join();
    }

    #[test]
    fn cancel_stops_a_trickle_before_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&cancel);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = crate::test_support::read_request(&mut stream);
            flag.store(true, Ordering::Release);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n");
            for _ in 0..200 {
                std::thread::sleep(Duration::from_millis(30));
                if stream.write_all(b"x").is_err() {
                    break;
                }
            }
        });
        let started = std::time::Instant::now();
        let error =
            get_cancellable(port, "/api/snapshot", Duration::from_secs(5), &cancel).unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(error, "read_failed");
        assert!(
            elapsed < Duration::from_secs(1),
            "cancelled trickle waited {elapsed:?}"
        );
        let _ = server.join();
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
