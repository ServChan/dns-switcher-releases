//! Минимальный клиент DNS-over-HTTPS для проверки серверов.
//! Подключается к конкретному IP, а имя из шаблона передаёт в TLS (SNI) и в Host,
//! как это делает сама Windows. Системный DNS при этом не нужен.

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.into() };
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("протоколы TLS по умолчанию")
                .with_root_certificates(roots)
                .with_no_client_auth();
            // Windows ходит к DoH по HTTP/2, часть серверов другого не принимает.
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Arc::new(config)
        })
        .clone()
}

/// Разбирает шаблон вида https://host[:port]/path на части.
fn split_template(template: &str) -> Result<(String, u16, String), String> {
    let rest = template
        .trim()
        .strip_prefix("https://")
        .ok_or("шаблон DoH должен начинаться с https://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/dns-query"),
    };
    // Шаблоны вида {?dns} встречаются в RFC 8484, для POST они не нужны.
    let path = path.split('{').next().unwrap_or(path).to_string();
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().map_err(|_| "неверный порт в шаблоне DoH")?)
        }
        _ => (authority.to_string(), 443),
    };
    Ok((host, port, path))
}

/// Отправляет DNS-сообщение на `ip` по шаблону DoH и возвращает ответ.
pub fn query(ip: IpAddr, template: &str, message: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    let (host, port, path) = split_template(template)?;
    let tcp = TcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout)
        .map_err(|_| "нет соединения".to_string())?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();

    let name = ServerName::try_from(host.clone()).map_err(|_| "неверное имя в шаблоне DoH".to_string())?;
    let conn = ClientConnection::new(tls_config(), name).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).map_err(|e| describe_io(&e))?;
    }
    if tls.conn.alpn_protocol() == Some(b"h2") {
        return h2_post(&mut tls, &host, &path, message);
    }

    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DnsSwitcher\r\n\
         Accept: application/dns-message\r\nContent-Type: application/dns-message\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        message.len()
    )
    .into_bytes();
    request.extend_from_slice(message);
    tls.write_all(&request).map_err(|e| describe_io(&e))?;

    let mut raw = Vec::new();
    match tls.read_to_end(&mut raw) {
        Ok(_) => {}
        // Многие серверы закрывают соединение без close_notify, ответ при этом полный.
        Err(e) if e.kind() == ErrorKind::UnexpectedEof && !raw.is_empty() => {}
        Err(e) => return Err(describe_io(&e)),
    }
    parse_http(&raw)
}

type Tls = StreamOwned<ClientConnection, TcpStream>;

const FRAME_DATA: u8 = 0;
const FRAME_HEADERS: u8 = 1;
const FRAME_RST_STREAM: u8 = 3;
const FRAME_SETTINGS: u8 = 4;
const FRAME_GOAWAY: u8 = 7;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_ACK: u8 = 0x1;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Поле HPACK «литерал без индексации» с именем из статической таблицы.
fn hpack_literal(out: &mut Vec<u8>, name_index: u8, value: &str) {
    if name_index < 15 {
        out.push(name_index);
    } else {
        out.push(0x0F);
        out.push(name_index - 15);
    }
    let bytes = value.as_bytes();
    let mut len = bytes.len();
    if len < 127 {
        out.push(len as u8);
    } else {
        out.push(127);
        len -= 127;
        while len >= 128 {
            out.push((len % 128 + 128) as u8);
            len /= 128;
        }
        out.push(len as u8);
    }
    out.extend_from_slice(bytes);
}

/// Один POST-запрос по HTTP/2 на потоке 1. Заголовки ответа разбираем только
/// ради кода статуса, тело проверяет вызывающий как DNS-ответ.
fn h2_post(tls: &mut Tls, host: &str, path: &str, message: &[u8]) -> Result<Vec<u8>, String> {
    let mut block = vec![0x83, 0x87]; // :method POST, :scheme https
    hpack_literal(&mut block, 4, path); // :path
    hpack_literal(&mut block, 1, host); // :authority
    hpack_literal(&mut block, 31, "application/dns-message"); // content-type
    hpack_literal(&mut block, 19, "application/dns-message"); // accept
    hpack_literal(&mut block, 28, &message.len().to_string()); // content-length

    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(frame(FRAME_SETTINGS, 0, 0, &[]));
    out.extend(frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &block));
    out.extend(frame(FRAME_DATA, FLAG_END_STREAM, 1, message));
    tls.write_all(&out).map_err(|e| describe_io(&e))?;

    let mut body = Vec::new();
    loop {
        let mut head = [0u8; 9];
        tls.read_exact(&mut head).map_err(|e| describe_io(&e))?;
        let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
        let (kind, flags) = (head[3], head[4]);
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7FFF_FFFF;
        if len > 1 << 20 {
            return Err("слишком большой ответ".into());
        }
        let mut payload = vec![0u8; len];
        tls.read_exact(&mut payload).map_err(|e| describe_io(&e))?;

        match kind {
            FRAME_SETTINGS if flags & FLAG_ACK == 0 => {
                tls.write_all(&frame(FRAME_SETTINGS, FLAG_ACK, 0, &[])).map_err(|e| describe_io(&e))?;
            }
            FRAME_HEADERS if stream == 1 => {
                // Статус 200 почти всегда закодирован одним байтом 0x88 (индекс 8).
                if let Some(code) = payload.first().and_then(|b| match b {
                    0x89 => Some(204),
                    0x8A => Some(206),
                    0x8B => Some(304),
                    0x8C => Some(400),
                    0x8D => Some(404),
                    0x8E => Some(500),
                    _ => None,
                }) {
                    return Err(format!("HTTP {code}"));
                }
                if flags & FLAG_END_STREAM != 0 {
                    return Err("пустой ответ".into());
                }
            }
            FRAME_DATA if stream == 1 => {
                body.extend_from_slice(&payload);
                if flags & FLAG_END_STREAM != 0 {
                    return Ok(body);
                }
            }
            FRAME_RST_STREAM => return Err("сервер сбросил запрос".into()),
            FRAME_GOAWAY => return Err("сервер закрыл соединение".into()),
            _ => {}
        }
    }
}

fn describe_io(e: &std::io::Error) -> String {
    match e.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => "нет ответа".into(),
        ErrorKind::InvalidData => format!("ошибка TLS: {e}"),
        _ => e.to_string(),
    }
}

fn parse_http(raw: &[u8]) -> Result<Vec<u8>, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("сервер прислал неполный ответ")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let body = &raw[split + 4..];
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("сервер прислал не HTTP-ответ")?;
    if status != 200 {
        return Err(format!("HTTP {status}"));
    }
    let chunked = head
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"));
    Ok(if chunked { dechunk(body) } else { body.to_vec() })
}

fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = body.windows(2).position(|w| w == b"\r\n") {
        let size_text = String::from_utf8_lossy(&body[..eol]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        if size == 0 || body.len() < eol + 2 + size {
            break;
        }
        out.extend_from_slice(&body[eol + 2..eol + 2 + size]);
        body = &body[(eol + 4 + size).min(body.len())..];
    }
    out
}
