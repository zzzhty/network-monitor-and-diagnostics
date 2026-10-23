//! Single-shot loopback HTTP mock for shell/poller unit tests. No GUI, no
//! real processes: handlers answer each connection with a canned response.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

pub struct MockServer {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Accepted sockets can inherit a nonblocking listener's mode on macOS.
/// A finite deadline also keeps malformed/idle fixture clients from hanging Drop.
pub(crate) fn read_request(stream: &mut TcpStream) -> io::Result<String> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    read_headers(stream)
}

fn read_headers(reader: &mut impl Read) -> io::Result<String> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 512];
    loop {
        let available = (4096 - request.len()).min(buffer.len());
        if available == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let read = match reader.read(&mut buffer[..available]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        request.extend_from_slice(&buffer[..read]);
        if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&request[..end + 4]).into_owned());
        }
    }
}

/// Serve `handler(request-line-and-headers)` per connection until dropped.
pub fn serve(handler: impl Fn(&str) -> (u16, Option<String>) + Send + 'static) -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        while !stop_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let Ok(request) = read_request(&mut stream) else {
                        continue;
                    };
                    let (status, body) = handler(&request);
                    let head =
                        format!("HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n");
                    match body {
                        Some(body) => {
                            let response =
                                format!("{head}Content-Length: {}\r\n\r\n{}", body.len(), body);
                            let _ = stream.write_all(response.as_bytes());
                        }
                        None => {
                            let _ = stream.write_all(head.as_bytes());
                        }
                    }
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    });
    MockServer {
        port,
        stop,
        handle: Some(handle),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::{Shutdown, TcpStream};
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    const REQUEST: &[u8] = b"GET /api/capabilities HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";

    struct Fragments {
        source: Cursor<&'static [u8]>,
        interrupt: bool,
    }

    impl Read for Fragments {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.interrupt {
                self.interrupt = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.source.read(&mut buffer[..1])
        }
    }

    #[test]
    fn fragmented_request_reaches_handler_only_after_complete_headers() {
        let mut reader = Fragments {
            source: Cursor::new(REQUEST),
            interrupt: false,
        };
        assert_eq!(read_headers(&mut reader).unwrap().as_bytes(), REQUEST);
    }

    #[test]
    fn interrupted_reads_resume_the_same_request() {
        let mut reader = Fragments {
            source: Cursor::new(REQUEST),
            interrupt: true,
        };
        assert_eq!(read_headers(&mut reader).unwrap().as_bytes(), REQUEST);
    }

    #[test]
    fn incomplete_or_oversized_headers_are_rejected() {
        for input in [b"".as_slice(), b"GET /api/capabilities HTTP/1.1\r\n"] {
            assert_eq!(
                read_headers(&mut Cursor::new(input)).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        let huge = b"x".repeat(4097);
        assert_eq!(
            read_headers(&mut Cursor::new(huge)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn valid_headers_at_the_size_limit_are_accepted() {
        let mut request = b"x".repeat(4092);
        request.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            read_headers(&mut Cursor::new(&request)).unwrap().as_bytes(),
            request
        );
    }

    #[test]
    fn loopback_get_sends_complete_headers_and_reads_the_canned_body() {
        let server = serve(|request| {
            assert!(request.starts_with("GET /api/capabilities HTTP/1.1\r\n"));
            assert!(request.ends_with("\r\n\r\n"));
            (200, Some("{\"component\":\"nmd-observability\"}".into()))
        });
        let response =
            crate::http_probe::get(server.port(), "/api/capabilities", Duration::from_secs(2))
                .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"{\"component\":\"nmd-observability\"}");
    }

    #[test]
    fn delayed_and_fragmented_nonblocking_connection_is_read_completely() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        // Force the inherited BSD mode on every platform; keep both peers
        // alive until the read result is checked, including on a failed read.
        stream.set_nonblocking(true).unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            client.write_all(&REQUEST[..1]).unwrap();
            std::thread::sleep(Duration::from_millis(20));
            client.write_all(&REQUEST[1..]).unwrap();
        });
        let request = read_request(&mut stream);
        writer.join().unwrap();
        assert_eq!(request.unwrap().as_bytes(), REQUEST);
    }

    #[test]
    fn truncated_connection_is_not_dispatched_and_next_request_succeeds() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let server = serve(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            (200, Some("{}".into()))
        });
        let mut truncated = TcpStream::connect(("127.0.0.1", server.port())).unwrap();
        truncated.write_all(b"GET /partial HTTP/1.1\r\n").unwrap();
        truncated.shutdown(Shutdown::Write).unwrap();
        let response =
            crate::http_probe::get(server.port(), "/api/capabilities", Duration::from_secs(2))
                .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
