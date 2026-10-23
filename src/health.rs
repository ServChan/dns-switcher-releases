//! Проверка доступности DNS-серверов: каждый адрес проверяется тем способом,
//! которым его будет использовать Windows (обычный DNS по UDP или DoH).

use crate::config::DnsServer;
use crate::doh;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(3);
/// Имя для пробного запроса. Для серверов обхода ограничений это заодно
/// проверяет, что они отвечают на нужные домены.
const PROBE_NAME: &str = "chatgpt.com";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Method {
    Udp,
    Doh,
}

#[derive(Clone, Debug)]
pub struct IpHealth {
    pub ip: String,
    pub result: Result<u32, String>,
}

#[derive(Clone, Debug)]
pub struct Health {
    pub method: Method,
    pub ips: Vec<IpHealth>,
}

impl Health {
    pub fn ok_count(&self) -> usize {
        self.ips.iter().filter(|h| h.result.is_ok()).count()
    }

    /// Сервер жив, если отвечает хотя бы один адрес: Windows сама переходит
    /// на следующий адрес из списка.
    pub fn alive(&self) -> bool {
        self.ok_count() > 0
    }

    pub fn best_ms(&self) -> Option<u32> {
        self.ips.iter().filter_map(|h| h.result.as_ref().ok().copied()).min()
    }

    pub fn first_error(&self) -> Option<&str> {
        self.ips.iter().find_map(|h| h.result.as_ref().err().map(String::as_str))
    }
}

/// Копия сервера, где адреса, ответившие на проверке, стоят первыми (по скорости).
/// Windows опрашивает адреса по порядку, так она не будет ждать мёртвый.
pub fn prefer_working(server: &DnsServer, health: &Health) -> DnsServer {
    let rank = |ip: &String| -> (u8, u32) {
        match health.ips.iter().find(|h| &h.ip == ip).map(|h| &h.result) {
            Some(Ok(ms)) => (0, *ms),
            None => (1, 0),
            Some(Err(_)) => (2, 0),
        }
    };
    let mut out = server.clone();
    out.ipv4.sort_by_key(|ip| rank(ip));
    out.ipv6.sort_by_key(|ip| rank(ip));
    out
}

pub fn method_for(server: &DnsServer, use_doh: bool) -> Method {
    if server.has_doh() && (use_doh || server.doh_only) { Method::Doh } else { Method::Udp }
}

/// Адреса, которые имеет смысл проверять: IPv4, а IPv6 только если IPv4 нет.
fn probe_ips(server: &DnsServer) -> Vec<String> {
    if server.ipv4.is_empty() { server.ipv6.clone() } else { server.ipv4.clone() }
}

/// Проверяет все адреса сервера параллельно.
pub fn check(server: &DnsServer, use_doh: bool) -> Health {
    let method = method_for(server, use_doh);
    let template = server.doh.clone();
    let handles: Vec<_> = probe_ips(server)
        .into_iter()
        .map(|ip| {
            let template = template.clone();
            std::thread::spawn(move || {
                let result = match ip.parse::<IpAddr>() {
                    Err(_) => Err("неверный адрес".to_string()),
                    Ok(addr) => check_ip(addr, method, &template),
                };
                IpHealth { ip, result }
            })
        })
        .collect();
    let ips = handles.into_iter().filter_map(|h| h.join().ok()).collect();
    Health { method, ips }
}

fn check_ip(ip: IpAddr, method: Method, template: &str) -> Result<u32, String> {
    let id = query_id();
    let message = build_query(id, PROBE_NAME);
    let start = Instant::now();
    let reply = match method {
        Method::Udp => udp_exchange(ip, &message)?,
        Method::Doh => doh::query(ip, template, &message, TIMEOUT)?,
    };
    validate_reply(&reply, id)?;
    Ok(start.elapsed().as_millis().min(u32::MAX as u128) as u32)
}

/// Есть ли вообще интернет. Нужно, чтобы не переключать DNS, когда отвалился
/// весь канал, а не отдельный сервер.
pub fn internet_ok() -> bool {
    const CONTROL: [&str; 4] = ["1.1.1.1:443", "8.8.8.8:443", "77.88.8.8:443", "9.9.9.9:443"];
    let handles: Vec<_> = CONTROL
        .iter()
        .map(|addr| {
            let addr: SocketAddr = addr.parse().unwrap();
            std::thread::spawn(move || TcpStream::connect_timeout(&addr, TIMEOUT).is_ok())
        })
        .collect();
    handles.into_iter().any(|h| h.join().unwrap_or(false))
}

fn udp_exchange(ip: IpAddr, message: &[u8]) -> Result<Vec<u8>, String> {
    let bind: SocketAddr = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let sock = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(TIMEOUT)).map_err(|e| e.to_string())?;
    sock.send_to(message, SocketAddr::new(ip, 53)).map_err(|_| "сеть недоступна".to_string())?;
    let deadline = Instant::now() + TIMEOUT;
    let mut buf = [0u8; 1500];
    loop {
        let (n, from) = sock.recv_from(&mut buf).map_err(|_| "нет ответа".to_string())?;
        if from.ip() == ip && n >= 12 && buf[..2] == message[..2] {
            return Ok(buf[..n].to_vec());
        }
        if Instant::now() > deadline {
            return Err("нет ответа".into());
        }
    }
}

fn validate_reply(reply: &[u8], id: u16) -> Result<(), String> {
    if reply.len() < 12 || u16::from_be_bytes([reply[0], reply[1]]) != id || reply[2] & 0x80 == 0 {
        return Err("неверный ответ".into());
    }
    match reply[3] & 0x0f {
        0 => Ok(()),
        2 => Err("сбой сервера (SERVFAIL)".into()),
        5 => Err("запрос отклонён (REFUSED)".into()),
        code => Err(format!("ошибка сервера {code}")),
    }
}

fn query_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    ((nanos >> 8) as u16) ^ COUNTER.fetch_add(0x9e37, Ordering::Relaxed)
}

fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, один вопрос
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]); // конец имени, тип A, класс IN
    q
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_servers;

    /// Обращается к настоящим серверам: `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_check_default_servers() {
        println!("internet_ok = {}", internet_ok());
        for server in default_servers() {
            for use_doh in [false, true] {
                if !use_doh && server.doh_only {
                    continue;
                }
                let h = check(&server, use_doh);
                let parts: Vec<String> = h
                    .ips
                    .iter()
                    .map(|i| match &i.result {
                        Ok(ms) => format!("{} {ms} мс", i.ip),
                        Err(e) => format!("{} ОШИБКА {e}", i.ip),
                    })
                    .collect();
                println!("{:<18} {:?}: {}", server.name, h.method, parts.join(" | "));
            }
        }
    }
}
