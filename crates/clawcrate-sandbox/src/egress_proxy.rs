use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::str;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(not(test))]
const MAX_ACTIVE_PROXY_HANDLERS: usize = 64;
#[cfg(test)]
const MAX_ACTIVE_PROXY_HANDLERS: usize = 8;
const MAX_REQUEST_LINE_BYTES: usize = 4096;
const MAX_HEADER_LINE_BYTES: usize = 8192;
const MAX_HEADER_COUNT: usize = 64;
const MAX_HEADER_BYTES_TOTAL: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct EgressProxyConfig {
    pub allowed_domains: Vec<String>,
    pub enforce_sni: bool,
    pub max_active_handlers: usize,
}

impl EgressProxyConfig {
    pub fn from_allowed_domains(allowed_domains: Vec<String>) -> Self {
        Self {
            allowed_domains,
            enforce_sni: true,
            max_active_handlers: MAX_ACTIVE_PROXY_HANDLERS,
        }
    }
}

#[derive(Debug)]
pub struct EgressProxyHandle {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl EgressProxyHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn proxy_env_vars(&self) -> Vec<(String, String)> {
        let proxy_url = format!("http://{}", self.addr);
        vec![
            ("HTTP_PROXY".to_string(), proxy_url.clone()),
            ("HTTPS_PROXY".to_string(), proxy_url.clone()),
            ("ALL_PROXY".to_string(), proxy_url.clone()),
            ("http_proxy".to_string(), proxy_url.clone()),
            ("https_proxy".to_string(), proxy_url.clone()),
            ("all_proxy".to_string(), proxy_url),
            (
                "NO_PROXY".to_string(),
                "localhost,127.0.0.1,::1".to_string(),
            ),
            (
                "no_proxy".to_string(),
                "localhost,127.0.0.1,::1".to_string(),
            ),
        ]
    }

    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for EgressProxyHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EgressProxyError {
    #[error("no allowed domains configured for filtered mode")]
    MissingAllowedDomains,
    #[error("failed to bind egress proxy listener on loopback: {0}")]
    Bind(#[source] io::Error),
    #[error("failed to configure egress proxy listener: {0}")]
    ConfigureListener(#[source] io::Error),
}

pub fn start_egress_proxy(
    config: EgressProxyConfig,
) -> Result<EgressProxyHandle, EgressProxyError> {
    let allowed_domains = normalize_allowed_domains(&config.allowed_domains);
    if allowed_domains.is_empty() {
        return Err(EgressProxyError::MissingAllowedDomains);
    }

    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(EgressProxyError::Bind)?;
    listener
        .set_nonblocking(true)
        .map_err(EgressProxyError::ConfigureListener)?;
    let addr = listener
        .local_addr()
        .map_err(EgressProxyError::ConfigureListener)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_thread = shutdown.clone();
    let active_handlers = Arc::new(AtomicUsize::new(0));
    let enforce_sni = config.enforce_sni;
    let max_active_handlers = config.max_active_handlers.max(1);

    let join = thread::spawn(move || loop {
        if shutdown_thread.load(Ordering::SeqCst) {
            break;
        }

        match listener.accept() {
            Ok((mut stream, _peer_addr)) => {
                if !try_acquire_handler_slot(&active_handlers, max_active_handlers) {
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
                    let _ = write_http_response(&mut stream, 503, "Service Unavailable");
                    continue;
                }

                let allowed = allowed_domains.clone();
                let active_handlers_for_thread = active_handlers.clone();
                thread::spawn(move || {
                    let _slot_guard = ActiveHandlerSlotGuard::new(active_handlers_for_thread);
                    let _ = handle_client_connection(stream, &allowed, enforce_sni);
                });
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    });

    Ok(EgressProxyHandle {
        addr,
        shutdown,
        join: Some(join),
    })
}

fn try_acquire_handler_slot(active_handlers: &AtomicUsize, max_active_handlers: usize) -> bool {
    active_handlers
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            (current < max_active_handlers).then_some(current + 1)
        })
        .is_ok()
}

#[derive(Debug)]
struct ActiveHandlerSlotGuard {
    active_handlers: Arc<AtomicUsize>,
}

impl ActiveHandlerSlotGuard {
    fn new(active_handlers: Arc<AtomicUsize>) -> Self {
        Self { active_handlers }
    }
}

impl Drop for ActiveHandlerSlotGuard {
    fn drop(&mut self) {
        self.active_handlers.fetch_sub(1, Ordering::SeqCst);
    }
}

enum LimitedLineRead {
    Eof,
    Line(Vec<u8>),
    TooLong,
}

fn read_limited_line(reader: &mut impl BufRead, max_bytes: usize) -> io::Result<LimitedLineRead> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(LimitedLineRead::Eof);
            }
            return Ok(LimitedLineRead::Line(line));
        }

        let remaining_capacity = max_bytes.saturating_sub(line.len());
        if remaining_capacity == 0 {
            return Ok(LimitedLineRead::TooLong);
        }

        if let Some(newline_index) = available.iter().position(|byte| *byte == b'\n') {
            let take_len = newline_index + 1;
            if take_len > remaining_capacity {
                return Ok(LimitedLineRead::TooLong);
            }
            line.extend_from_slice(&available[..take_len]);
            reader.consume(take_len);
            return Ok(LimitedLineRead::Line(line));
        }

        let available_len = available.len();
        let take_len = available_len.min(remaining_capacity);
        line.extend_from_slice(&available[..take_len]);
        reader.consume(take_len);
        if take_len < available_len {
            return Ok(LimitedLineRead::TooLong);
        }
    }
}

fn handle_client_connection(
    mut client: TcpStream,
    allowed_domains: &[String],
    enforce_sni: bool,
) -> io::Result<()> {
    client.set_nodelay(true)?;
    let mut reader = BufReader::new(client.try_clone()?);

    let request_line_bytes = match read_limited_line(&mut reader, MAX_REQUEST_LINE_BYTES)? {
        LimitedLineRead::Eof => return Ok(()),
        LimitedLineRead::TooLong => {
            write_http_response(&mut client, 400, "Bad Request")?;
            return Ok(());
        }
        LimitedLineRead::Line(line) => line,
    };
    let request_line = match str::from_utf8(&request_line_bytes) {
        Ok(line) => line,
        Err(_) => {
            write_http_response(&mut client, 400, "Bad Request")?;
            return Ok(());
        }
    };

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("CONNECT") {
        write_http_response(&mut client, 405, "Method Not Allowed")?;
        return Ok(());
    }

    let (target_host, target_port) = match parse_connect_target(target) {
        Some(value) => value,
        None => {
            write_http_response(&mut client, 400, "Bad Request")?;
            return Ok(());
        }
    };

    let mut header_count = 0usize;
    let mut header_bytes_total = 0usize;
    loop {
        match read_limited_line(&mut reader, MAX_HEADER_LINE_BYTES)? {
            LimitedLineRead::Eof => return Ok(()),
            LimitedLineRead::TooLong => {
                write_http_response(&mut client, 431, "Request Header Fields Too Large")?;
                return Ok(());
            }
            LimitedLineRead::Line(line) => {
                header_bytes_total = header_bytes_total.saturating_add(line.len());
                if header_bytes_total > MAX_HEADER_BYTES_TOTAL {
                    write_http_response(&mut client, 431, "Request Header Fields Too Large")?;
                    return Ok(());
                }

                if line == b"\r\n" || line == b"\n" {
                    break;
                }

                header_count = header_count.saturating_add(1);
                if header_count > MAX_HEADER_COUNT {
                    write_http_response(&mut client, 431, "Request Header Fields Too Large")?;
                    return Ok(());
                }
            }
        }
    }

    if !is_host_allowed(&target_host, allowed_domains) {
        write_http_response(&mut client, 403, "Forbidden")?;
        return Ok(());
    }

    let upstream = match TcpStream::connect((target_host.as_str(), target_port)) {
        Ok(stream) => stream,
        Err(_) => {
            write_http_response(&mut client, 502, "Bad Gateway")?;
            return Ok(());
        }
    };
    upstream.set_nodelay(true)?;

    write_http_response(&mut client, 200, "Connection Established")?;

    if enforce_sni && target_port == 443 {
        let tls_preface = peek_tls_preface(&mut client)?;
        let Some(sni) = extract_sni_from_client_hello(&tls_preface) else {
            let _ = client.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
            return Ok(());
        };
        if !hostnames_match(&target_host, &sni) || !is_host_allowed(&sni, allowed_domains) {
            let _ = client.shutdown(Shutdown::Both);
            let _ = upstream.shutdown(Shutdown::Both);
            return Ok(());
        }
    }

    tunnel_bidirectional(client, upstream)
}

fn tunnel_bidirectional(mut client: TcpStream, mut upstream: TcpStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;
    let forward = thread::spawn(move || {
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });

    let _ = io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = forward.join();
    Ok(())
}

fn peek_tls_preface(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;

    let mut peek_buf = [0_u8; 4096];
    let prefetched = match stream.peek(&mut peek_buf) {
        Ok(0) => {
            stream.set_read_timeout(None)?;
            return Ok(Vec::new());
        }
        Ok(n) => n,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::UnexpectedEof
            ) =>
        {
            stream.set_read_timeout(None)?;
            return Ok(Vec::new());
        }
        Err(error) => {
            stream.set_read_timeout(None)?;
            return Err(error);
        }
    };
    stream.set_read_timeout(None)?;
    Ok(peek_buf[..prefetched].to_vec())
}

fn write_http_response(stream: &mut TcpStream, status: u16, reason: &str) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n"
    )?;
    stream.flush()
}

fn parse_connect_target(value: &str) -> Option<(String, u16)> {
    if value.is_empty() {
        return None;
    }

    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find("]:")?;
        let host = &rest[..end];
        let port = rest[(end + 2)..].parse::<u16>().ok()?;
        return Some((normalize_host(host), port));
    }

    let (host, port) = value.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Some((normalize_host(host), port))
}

fn is_host_allowed(host: &str, allowed_domains: &[String]) -> bool {
    let host = normalize_host(host);
    if host.is_empty() {
        return false;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return allowed_domains.iter().any(|rule| rule == &ip.to_string());
    }

    allowed_domains.iter().any(|rule| {
        if let Some(suffix) = rule.strip_prefix("*.") {
            host.ends_with(&format!(".{suffix}"))
        } else {
            host == *rule
        }
    })
}

fn hostnames_match(expected: &str, observed: &str) -> bool {
    normalize_host(expected) == normalize_host(observed)
}

fn normalize_host(value: &str) -> String {
    value
        .trim()
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

fn normalize_allowed_domains(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| normalize_host(value))
        .filter(|value| !value.is_empty())
        .collect()
}

fn extract_sni_from_client_hello(record: &[u8]) -> Option<String> {
    if record.len() < 5 || record[0] != 22 {
        return None;
    }

    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() < 5 + record_len {
        return None;
    }

    let handshake = &record[5..(5 + record_len)];
    if handshake.len() < 4 || handshake[0] != 1 {
        return None;
    }

    let hello_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
    if handshake.len() < 4 + hello_len {
        return None;
    }

    let mut cursor = 4;
    cursor += 2; // legacy_version
    cursor += 32; // random
    if cursor >= handshake.len() {
        return None;
    }

    let session_id_len = *handshake.get(cursor)? as usize;
    cursor += 1 + session_id_len;
    if cursor + 2 > handshake.len() {
        return None;
    }

    let cipher_len = u16::from_be_bytes([handshake[cursor], handshake[cursor + 1]]) as usize;
    cursor += 2 + cipher_len;
    if cursor >= handshake.len() {
        return None;
    }

    let compression_len = *handshake.get(cursor)? as usize;
    cursor += 1 + compression_len;
    if cursor + 2 > handshake.len() {
        return None;
    }

    let extensions_len = u16::from_be_bytes([handshake[cursor], handshake[cursor + 1]]) as usize;
    cursor += 2;
    let extensions_end = cursor.checked_add(extensions_len)?;
    if extensions_end > handshake.len() {
        return None;
    }

    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([handshake[cursor], handshake[cursor + 1]]);
        let ext_len = u16::from_be_bytes([handshake[cursor + 2], handshake[cursor + 3]]) as usize;
        cursor += 4;
        let ext_end = cursor.checked_add(ext_len)?;
        if ext_end > extensions_end {
            return None;
        }

        if ext_type == 0 {
            let ext = &handshake[cursor..ext_end];
            return parse_server_name_extension(ext).map(|name| normalize_host(&name));
        }

        cursor = ext_end;
    }

    None
}

fn parse_server_name_extension(ext: &[u8]) -> Option<String> {
    if ext.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    if ext.len() < 2 + list_len {
        return None;
    }

    let mut cursor = 2;
    while cursor + 3 <= 2 + list_len {
        let name_type = ext[cursor];
        let name_len = u16::from_be_bytes([ext[cursor + 1], ext[cursor + 2]]) as usize;
        cursor += 3;
        let end = cursor.checked_add(name_len)?;
        if end > 2 + list_len || end > ext.len() {
            return None;
        }
        if name_type == 0 {
            let value = str::from_utf8(&ext[cursor..end]).ok()?;
            return Some(value.to_string());
        }
        cursor = end;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{
        extract_sni_from_client_hello, is_host_allowed, parse_connect_target, start_egress_proxy,
        try_acquire_handler_slot, EgressProxyConfig, MAX_ACTIVE_PROXY_HANDLERS, MAX_HEADER_COUNT,
        MAX_HEADER_LINE_BYTES,
    };
    use std::io::{ErrorKind, Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::sync::{Mutex, OnceLock};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn domain_matching_supports_exact_and_wildcard_rules() {
        let rules = vec!["example.com".to_string(), "*.pkg.dev".to_string()];
        assert!(is_host_allowed("example.com", &rules));
        assert!(is_host_allowed("registry.pkg.dev", &rules));
        assert!(!is_host_allowed("pkg.dev", &rules));
        assert!(!is_host_allowed("evil.com", &rules));
    }

    #[test]
    fn connect_target_parser_supports_host_port_and_ipv6() {
        assert_eq!(
            parse_connect_target("example.com:443"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_connect_target("[::1]:8443"),
            Some(("::1".to_string(), 8443))
        );
        assert_eq!(parse_connect_target("missing-port"), None);
    }

    #[test]
    fn parses_sni_from_tls_client_hello_record() {
        let record = make_client_hello("registry.npmjs.org");
        let parsed = extract_sni_from_client_hello(&record).expect("extract sni");
        assert_eq!(parsed, "registry.npmjs.org");
    }

    #[test]
    fn proxy_denies_disallowed_connect_targets() {
        let _guard = proxy_network_test_lock();
        let proxy = start_egress_proxy(EgressProxyConfig {
            allowed_domains: vec!["allowed.test".to_string()],
            enforce_sni: false,
            max_active_handlers: MAX_ACTIVE_PROXY_HANDLERS,
        })
        .expect("start proxy");

        let mut stream =
            std::net::TcpStream::connect(proxy.addr()).expect("connect to local egress proxy");
        write!(
            stream,
            "CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n"
        )
        .expect("write connect request");

        let response = read_http_response_header(&mut stream);
        assert!(response.contains("403 Forbidden"));
        proxy.shutdown();
    }

    #[test]
    fn proxy_allows_connect_to_allowed_domain() {
        let _guard = proxy_network_test_lock();
        let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind upstream");
        let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
        let upstream_thread = thread::spawn(move || {
            let (mut socket, _) = upstream_listener.accept().expect("accept upstream");
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("set upstream read timeout");
            let mut buffer = [0_u8; 256];
            loop {
                match socket.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(error)
                        if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
        });

        let proxy = start_egress_proxy(EgressProxyConfig {
            allowed_domains: vec!["localhost".to_string()],
            enforce_sni: false,
            max_active_handlers: MAX_ACTIVE_PROXY_HANDLERS,
        })
        .expect("start proxy");

        let mut stream =
            std::net::TcpStream::connect(proxy.addr()).expect("connect to local egress proxy");
        let request = format!(
            "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        stream
            .write_all(request.as_bytes())
            .expect("write connect request");

        let response = read_http_response_header_with_timeout(&mut stream, Duration::from_secs(3));
        assert!(
            response.contains("200 Connection Established"),
            "unexpected CONNECT response: {response}"
        );
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown client write-half");
        upstream_thread.join().expect("join upstream thread");
        proxy.shutdown();
    }

    #[test]
    fn proxy_strict_sni_denies_missing_client_hello_preface() {
        let _guard = proxy_network_test_lock();
        let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind upstream");
        let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
        let upstream_thread = thread::spawn(move || {
            let (mut socket, _) = upstream_listener.accept().expect("accept upstream");
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("set upstream read timeout");
            let mut buffer = [0_u8; 256];
            loop {
                match socket.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(error)
                        if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
        });

        let proxy = start_egress_proxy(EgressProxyConfig {
            allowed_domains: vec!["localhost".to_string()],
            enforce_sni: true,
            max_active_handlers: MAX_ACTIVE_PROXY_HANDLERS,
        })
        .expect("start proxy");

        let mut stream =
            std::net::TcpStream::connect(proxy.addr()).expect("connect to local egress proxy");
        let request = format!(
            "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        stream
            .write_all(request.as_bytes())
            .expect("write connect request");

        let response = read_http_response_header_with_timeout(&mut stream, Duration::from_secs(3));
        assert!(
            response.contains("200 Connection Established"),
            "unexpected CONNECT response: {response}"
        );

        thread::sleep(Duration::from_millis(400));
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set read timeout");
        let mut buf = [0_u8; 1];
        let n = stream.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0, "strict SNI should close missing ClientHello preface");
        let _ = stream.shutdown(Shutdown::Both);

        upstream_thread.join().expect("join upstream thread");
        proxy.shutdown();
    }

    #[test]
    fn proxy_rejects_oversized_header_line() {
        let _guard = proxy_network_test_lock();
        let proxy = start_egress_proxy(EgressProxyConfig {
            allowed_domains: vec!["allowed.test".to_string()],
            enforce_sni: false,
            max_active_handlers: MAX_ACTIVE_PROXY_HANDLERS,
        })
        .expect("start proxy");

        let mut stream =
            std::net::TcpStream::connect(proxy.addr()).expect("connect to local egress proxy");
        let oversized = "a".repeat(MAX_HEADER_LINE_BYTES + 128);
        let request =
            format!("CONNECT allowed.test:443 HTTP/1.1\r\nX-Oversized: {oversized}\r\n\r\n");
        if let Err(error) = stream.write_all(request.as_bytes()) {
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionAborted
                ),
                "unexpected write error for oversized header request: {error}"
            );
        }

        let response = read_http_response_header(&mut stream);
        assert!(
            response.is_empty() || response.contains("431 Request Header Fields Too Large"),
            "unexpected oversized-header response: {response}"
        );
        proxy.shutdown();
    }

    #[test]
    fn proxy_rejects_excessive_header_count() {
        let _guard = proxy_network_test_lock();
        let proxy = start_egress_proxy(EgressProxyConfig {
            allowed_domains: vec!["allowed.test".to_string()],
            enforce_sni: false,
            max_active_handlers: MAX_ACTIVE_PROXY_HANDLERS,
        })
        .expect("start proxy");

        let mut stream =
            std::net::TcpStream::connect(proxy.addr()).expect("connect to local egress proxy");
        let mut request = String::from("CONNECT allowed.test:443 HTTP/1.1\r\n");
        for index in 0..(MAX_HEADER_COUNT + 1) {
            request.push_str(&format!("X-{index}: v\r\n"));
        }
        request.push_str("\r\n");
        if let Err(error) = stream.write_all(request.as_bytes()) {
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionAborted
                ),
                "unexpected write error for excessive-header-count request: {error}"
            );
        }

        let response = read_http_response_header(&mut stream);
        assert!(
            response.is_empty() || response.contains("431 Request Header Fields Too Large"),
            "unexpected excessive-header-count response: {response}"
        );
        proxy.shutdown();
    }

    #[test]
    fn proxy_enforces_bounded_concurrency_under_connection_flood() {
        let _guard = proxy_network_test_lock();
        let active_handlers = Arc::new(AtomicUsize::new(0));
        let successful_acquisitions = Arc::new(AtomicUsize::new(0));
        let max_handlers = 4usize;
        let mut workers = Vec::new();

        for _ in 0..64 {
            let active_handlers = active_handlers.clone();
            let successful_acquisitions = successful_acquisitions.clone();
            workers.push(thread::spawn(move || {
                if try_acquire_handler_slot(active_handlers.as_ref(), max_handlers) {
                    successful_acquisitions.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        for worker in workers {
            worker.join().expect("join limiter worker");
        }

        assert_eq!(
            successful_acquisitions.load(Ordering::SeqCst),
            max_handlers,
            "handler slot limiter should cap concurrent acquires under contention"
        );
    }

    fn read_http_response_header(stream: &mut std::net::TcpStream) -> String {
        read_http_response_header_with_timeout(stream, Duration::from_secs(1))
    }

    fn proxy_network_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("acquire proxy network test lock")
    }

    fn read_http_response_header_with_timeout(
        stream: &mut std::net::TcpStream,
        timeout: Duration,
    ) -> String {
        let _ = stream.set_nonblocking(true);

        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 128];
        let deadline = Instant::now() + timeout;
        while !bytes.windows(4).any(|window| window == b"\r\n\r\n") && Instant::now() < deadline {
            let n = match stream.read(&mut chunk) {
                Ok(n) => n,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("read response chunk: {error}"),
            };
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..n]);
            if bytes.len() > 4096 {
                break;
            }
        }

        let _ = stream.set_nonblocking(false);
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn make_client_hello(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let mut sni_list = Vec::new();
        sni_list.push(0); // host_name
        sni_list.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni_list.extend_from_slice(host_bytes);

        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&sni_list);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes()); // server_name extension type
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        let mut hello = Vec::new();
        hello.push(1); // ClientHello
        hello.extend_from_slice(&[0, 0, 0]); // placeholder handshake length
        hello.extend_from_slice(&0x0303_u16.to_be_bytes()); // TLS 1.2 legacy version
        hello.extend_from_slice(&[0_u8; 32]); // random
        hello.push(0); // session_id len
        hello.extend_from_slice(&2_u16.to_be_bytes()); // cipher suites len
        hello.extend_from_slice(&0x1301_u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
        hello.push(1); // compression len
        hello.push(0); // compression method null
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let handshake_len = hello.len() - 4;
        hello[1] = ((handshake_len >> 16) & 0xff) as u8;
        hello[2] = ((handshake_len >> 8) & 0xff) as u8;
        hello[3] = (handshake_len & 0xff) as u8;

        let mut record = Vec::new();
        record.push(22); // handshake record
        record.extend_from_slice(&0x0301_u16.to_be_bytes()); // legacy record version
        record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);
        record
    }
}
