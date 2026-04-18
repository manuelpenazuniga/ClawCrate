use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct EgressProxyConfig {
    pub allowed_domains: Vec<String>,
    pub enforce_sni: bool,
}

impl EgressProxyConfig {
    pub fn from_allowed_domains(allowed_domains: Vec<String>) -> Self {
        Self {
            allowed_domains,
            enforce_sni: true,
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
    let enforce_sni = config.enforce_sni;

    let join = thread::spawn(move || loop {
        if shutdown_thread.load(Ordering::SeqCst) {
            break;
        }

        match listener.accept() {
            Ok((stream, _peer_addr)) => {
                let allowed = allowed_domains.clone();
                thread::spawn(move || {
                    let _ = handle_client_connection(stream, &allowed, enforce_sni);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    });

    Ok(EgressProxyHandle {
        addr,
        shutdown,
        join: Some(join),
    })
}

fn handle_client_connection(
    mut client: TcpStream,
    allowed_domains: &[String],
    enforce_sni: bool,
) -> io::Result<()> {
    client.set_nodelay(true)?;
    let mut reader = BufReader::new(client.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
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

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    if !is_host_allowed(&target_host, allowed_domains) {
        write_http_response(&mut client, 403, "Forbidden")?;
        return Ok(());
    }

    let mut upstream = match TcpStream::connect((target_host.as_str(), target_port)) {
        Ok(stream) => stream,
        Err(_) => {
            write_http_response(&mut client, 502, "Bad Gateway")?;
            return Ok(());
        }
    };
    upstream.set_nodelay(true)?;

    write_http_response(&mut client, 200, "Connection Established")?;

    let preface = read_tls_preface(&mut client)?;
    if !preface.is_empty() {
        if enforce_sni && target_port == 443 {
            if let Some(sni) = extract_sni_from_client_hello(&preface) {
                if !hostnames_match(&target_host, &sni) || !is_host_allowed(&sni, allowed_domains) {
                    let _ = client.shutdown(Shutdown::Both);
                    let _ = upstream.shutdown(Shutdown::Both);
                    return Ok(());
                }
            }
        }
        upstream.write_all(&preface)?;
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

fn read_tls_preface(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;

    let mut header = [0_u8; 5];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
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
    }

    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0_u8; payload_len];
    if let Err(error) = stream.read_exact(&mut payload) {
        stream.set_read_timeout(None)?;
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::UnexpectedEof
        ) {
            return Ok(Vec::new());
        }
        return Err(error);
    }
    stream.set_read_timeout(None)?;

    let mut record = header.to_vec();
    record.extend_from_slice(&payload);
    Ok(record)
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
        EgressProxyConfig,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

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
        let proxy = start_egress_proxy(EgressProxyConfig {
            allowed_domains: vec!["allowed.test".to_string()],
            enforce_sni: false,
        })
        .expect("start proxy");

        let mut stream =
            std::net::TcpStream::connect(proxy.addr()).expect("connect to local egress proxy");
        write!(
            stream,
            "CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n"
        )
        .expect("write connect request");

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read connect response");
        assert!(response.contains("403 Forbidden"));
        proxy.shutdown();
    }

    #[test]
    fn proxy_allows_connect_to_allowed_domain() {
        let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind upstream");
        let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
        let upstream_thread = thread::spawn(move || {
            let (mut socket, _) = upstream_listener.accept().expect("accept upstream");
            let mut buf = [0_u8; 4];
            socket.read_exact(&mut buf).expect("read forwarded payload");
            assert_eq!(&buf, b"ping");
        });

        let proxy = start_egress_proxy(EgressProxyConfig {
            allowed_domains: vec!["localhost".to_string()],
            enforce_sni: false,
        })
        .expect("start proxy");

        let mut stream =
            std::net::TcpStream::connect(proxy.addr()).expect("connect to local egress proxy");
        write!(
            stream,
            "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        )
        .expect("write connect request");

        let mut response = [0_u8; 128];
        let n = stream.read(&mut response).expect("read connect response");
        let response = String::from_utf8_lossy(&response[..n]);
        assert!(response.contains("200 Connection Established"));

        stream.write_all(b"ping").expect("write tunneled payload");
        let _ = stream.shutdown(std::net::Shutdown::Both);
        upstream_thread.join().expect("join upstream thread");
        proxy.shutdown();
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
