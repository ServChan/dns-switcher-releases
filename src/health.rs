//! Проверка DNS-серверов. Каждый адрес проверяется тем способом, которым его
//! будет использовать Windows (обычный DNS по UDP или DoH). Для серверов обхода
//! ограничений ИИ проверка идёт дальше: DNS выдаёт адреса своих прокси, и мы
//! устанавливаем с каждым TLS-соединение с нужным именем (SNI), как браузер.
//! Ответ DNS ещё не значит, что прокси за ним работает.

use crate::config::DnsServer;
use crate::doh;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(3);
/// Имя для проверки самого DNS.
const PROBE_NAME: &str = "chatgpt.com";
/// Дольше этого Windows ответа не ждёт и переходит к следующему адресу,
/// а значит, к страховочным Cloudflare и Google без обхода ограничений.
pub const SLOW_MS: u32 = 1500;
/// Сервисы, которые проверяются у серверов обхода ограничений ИИ.
pub const AI_PROBES: [(&str, &str); 2] = [("ChatGPT", "chatgpt.com"), ("Gemini", "gemini.google.com")];
/// Сколько прокси из ответа проверять у одного сервиса.
const MAX_PROXIES: usize = 8;

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

/// Проверка одного сервиса (ChatGPT, Gemini) через прокси, которые выдал DNS.
#[derive(Clone, Debug)]
pub struct ServiceHealth {
    pub name: &'static str,
    /// Ошибка, если DNS не дал адресов для этого сервиса.
    pub dns_error: Option<String>,
    pub proxies: Vec<(Ipv4Addr, Result<u32, String>)>,
}

impl ServiceHealth {
    pub fn ok_count(&self) -> usize {
        self.proxies.iter().filter(|(_, r)| r.is_ok()).count()
    }

    pub fn works(&self) -> bool {
        self.dns_error.is_none() && self.ok_count() > 0
    }

    pub fn fully(&self) -> bool {
        self.works() && self.ok_count() == self.proxies.len()
    }

    pub fn best_ms(&self) -> Option<u32> {
        self.proxies.iter().filter_map(|(_, r)| r.as_ref().ok().copied()).min()
    }

    pub fn first_error(&self) -> Option<&str> {
        self.dns_error
            .as_deref()
            .or_else(|| self.proxies.iter().find_map(|(_, r)| r.as_ref().err().map(String::as_str)))
    }
}

/// Насколько сервер годится, от лучшего к худшему.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    /// Всё работает и быстро.
    Good,
    /// Сервисы открываются, но часть прокси не отвечает: возможны сбои.
    PartialProxies,
    /// DNS отвечает дольше, чем ждёт Windows: она уйдёт на страховочные адреса.
    Slow,
    /// Хотя бы один сервис не открывается совсем.
    ServiceDown,
    /// DNS не отвечает.
    Dead,
}

impl Grade {
    /// Годится, чтобы оставаться на сервере: сервисы открываются и DNS быстрый.
    /// Если не отвечает часть прокси, браузер сам пробует другой адрес.
    pub fn acceptable(self) -> bool {
        self <= Grade::PartialProxies
    }
}

#[derive(Clone, Debug)]
pub struct Health {
    pub method: Method,
    pub ips: Vec<IpHealth>,
    pub services: Vec<ServiceHealth>,
}

impl Health {
    pub fn best_ms(&self) -> Option<u32> {
        self.ips.iter().filter_map(|h| h.result.as_ref().ok().copied()).min()
    }

    pub fn grade(&self) -> Grade {
        let Some(ms) = self.best_ms() else { return Grade::Dead };
        if self.services.iter().any(|s| !s.works()) {
            Grade::ServiceDown
        } else if ms > SLOW_MS {
            Grade::Slow
        } else if self.services.iter().any(|s| !s.fully()) {
            Grade::PartialProxies
        } else {
            Grade::Good
        }
    }

    /// Что не так, одной фразой для журнала. None, если всё хорошо.
    pub fn problem(&self) -> Option<String> {
        match self.grade() {
            Grade::Good => None,
            Grade::Dead => Some(format!(
                "не отвечает: {}",
                self.ips.iter().find_map(|h| h.result.as_ref().err()).map(String::as_str).unwrap_or("нет ответа")
            )),
            Grade::Slow => Some(format!("отвечает слишком медленно: DNS {}", seconds(self.best_ms().unwrap_or(0)))),
            Grade::ServiceDown => {
                let down: Vec<String> = self
                    .services
                    .iter()
                    .filter(|s| !s.works())
                    .map(|s| format!("{} не открывается: {}", s.name, s.first_error().unwrap_or("нет ответа")))
                    .collect();
                Some(down.join("; "))
            }
            Grade::PartialProxies => {
                let partial: Vec<String> = self
                    .services
                    .iter()
                    .filter(|s| !s.fully())
                    .map(|s| format!("{}: работает {} из {} прокси", s.name, s.ok_count(), s.proxies.len()))
                    .collect();
                Some(partial.join("; "))
            }
        }
    }

    /// Состояние одной строкой для журнала: что работает или что не так.
    pub fn summary(&self) -> String {
        if let Some(problem) = self.problem() {
            return problem;
        }
        let dns = seconds(self.best_ms().unwrap_or(0));
        if self.services.is_empty() {
            format!("работает, DNS {dns}")
        } else {
            let names: Vec<&str> = self.services.iter().map(|s| s.name).collect();
            format!("работает: {} открываются, DNS {dns}", names.join(" и "))
        }
    }
}

pub fn seconds(ms: u32) -> String {
    if ms < 1000 { format!("{ms} мс") } else { format!("{:.1} с", ms as f32 / 1000.0).replace('.', ",") }
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

/// Проверяет все адреса сервера параллельно, а для серверов обхода ИИ ещё и прокси.
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
                    Ok(addr) => retry_once(|| resolve(addr, method, &template, PROBE_NAME).map(|(ms, _)| ms)),
                };
                IpHealth { ip, result }
            })
        })
        .collect();
    let ips: Vec<IpHealth> = handles.into_iter().filter_map(|h| h.join().ok()).collect();

    // Сервисы спрашиваем у самого быстрого рабочего адреса: его Windows и выберет.
    let fastest = ips
        .iter()
        .filter_map(|h| h.result.as_ref().ok().map(|ms| (*ms, h.ip.clone())))
        .min()
        .and_then(|(_, ip)| ip.parse::<IpAddr>().ok());
    let services = match (server.ai_bypass, fastest) {
        (true, Some(dns_ip)) => {
            let handles: Vec<_> = AI_PROBES
                .iter()
                .map(|&(name, domain)| {
                    let template = template.clone();
                    std::thread::spawn(move || check_service(name, domain, dns_ip, method, &template))
                })
                .collect();
            handles.into_iter().filter_map(|h| h.join().ok()).collect()
        }
        _ => Vec::new(),
    };
    Health { method, ips, services }
}

fn check_service(name: &'static str, domain: &str, dns_ip: IpAddr, method: Method, template: &str) -> ServiceHealth {
    let addrs = match resolve(dns_ip, method, template, domain) {
        Ok((_, addrs)) if addrs.is_empty() => {
            return ServiceHealth { name, dns_error: Some("DNS не дал адресов".into()), proxies: Vec::new() };
        }
        Ok((_, addrs)) => addrs,
        Err(e) => return ServiceHealth { name, dns_error: Some(e), proxies: Vec::new() },
    };
    let domain = domain.to_string();
    let handles: Vec<_> = addrs
        .into_iter()
        .take(MAX_PROXIES)
        .map(|addr| {
            let domain = domain.clone();
            std::thread::spawn(move || (addr, retry_once(|| tls_probe(addr, &domain))))
        })
        .collect();
    let proxies = handles.into_iter().filter_map(|h| h.join().ok()).collect();
    ServiceHealth { name, dns_error: None, proxies }
}

/// Полное TLS-рукопожатие с прокси под именем сервиса. Сертификат проверяется:
/// прокси обхода передают TLS насквозь, и отвечать должен настоящий сервер.
fn tls_probe(addr: Ipv4Addr, domain: &str) -> Result<u32, String> {
    if addr.is_unspecified() {
        return Err("сервер вернул 0.0.0.0".into());
    }
    let start = Instant::now();
    let tcp = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(addr), 443), TIMEOUT)
        .map_err(|_| "прокси не отвечает".to_string())?;
    tcp.set_read_timeout(Some(TIMEOUT)).ok();
    tcp.set_write_timeout(Some(TIMEOUT)).ok();
    let name = ServerName::try_from(domain.to_string()).map_err(|_| "неверное имя".to_string())?;
    let conn = ClientConnection::new(doh::tls_config(), name).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).map_err(|e| match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "TLS не завершился".to_string(),
            std::io::ErrorKind::InvalidData => format!("ошибка TLS: {e}"),
            _ => "соединение сброшено".to_string(),
        })?;
    }
    Ok(start.elapsed().as_millis().min(u32::MAX as u128) as u32)
}

/// Повторяет неудачную проверку один раз: разовые сбои сети (сброс соединения,
/// испорченный TLS-пакет) не должны выглядеть как отказ сервера.
fn retry_once<T>(mut f: impl FnMut() -> Result<T, String>) -> Result<T, String> {
    f().or_else(|_| {
        std::thread::sleep(Duration::from_millis(300));
        f()
    })
}

/// DNS-запрос типа A к одному адресу сервера: время ответа и адреса из ответа.
fn resolve(ip: IpAddr, method: Method, template: &str, name: &str) -> Result<(u32, Vec<Ipv4Addr>), String> {
    let id = query_id();
    let message = build_query(id, name);
    let start = Instant::now();
    let reply = match method {
        Method::Udp => udp_exchange(ip, &message)?,
        Method::Doh => doh::query(ip, template, &message, TIMEOUT)?,
    };
    validate_reply(&reply, id)?;
    let ms = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
    Ok((ms, parse_a_records(&reply)))
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
        3 => Err("имя не найдено (NXDOMAIN)".into()),
        5 => Err("запрос отклонён (REFUSED)".into()),
        code => Err(format!("ошибка сервера {code}")),
    }
}

/// Пропускает имя в DNS-сообщении (с учётом сжатия) и возвращает позицию после него.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len as usize;
    }
}

/// Адреса A из раздела ответов (CNAME по дороге пропускаются).
fn parse_a_records(msg: &[u8]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if msg.len() < 12 {
        return out;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = 12;
    for _ in 0..qd {
        match skip_name(msg, pos) {
            Some(p) => pos = p + 4,
            None => return out,
        }
    }
    for _ in 0..an {
        let Some(p) = skip_name(msg, pos) else { break };
        let Some(head) = msg.get(p..p + 10) else { break };
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let len = u16::from_be_bytes([head[8], head[9]]) as usize;
        let data = p + 10;
        if kind == 1 && len == 4 {
            if let Some(b) = msg.get(data..data + 4) {
                out.push(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            }
        }
        pos = data + len;
    }
    out
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

    #[test]
    fn parses_a_records_through_cname() {
        // Ответ: вопрос gemini.google.com, CNAME на www.google.com (сжатое имя), затем A 1.2.3.4.
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend_from_slice(b"\x06gemini\x06google\x03com\x00\x00\x01\x00\x01");
        m.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6]);
        m.extend_from_slice(b"\x03www\xC0\x13");
        m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert_eq!(parse_a_records(&m), vec![Ipv4Addr::new(1, 2, 3, 4)]);
    }

    fn svc(results: &[Result<u32, String>]) -> ServiceHealth {
        ServiceHealth {
            name: "ChatGPT",
            dns_error: None,
            proxies: results.iter().map(|r| (Ipv4Addr::LOCALHOST, r.clone())).collect(),
        }
    }

    fn health(dns_ms: Option<u32>, services: Vec<ServiceHealth>) -> Health {
        let result = dns_ms.ok_or_else(|| "нет ответа".to_string());
        Health { method: Method::Udp, ips: vec![IpHealth { ip: "1.1.1.1".into(), result }], services }
    }

    #[test]
    fn grades_from_best_to_worst() {
        assert_eq!(health(Some(50), vec![svc(&[Ok(80)])]).grade(), Grade::Good);
        assert_eq!(health(Some(50), vec![svc(&[Ok(80), Err("x".into())])]).grade(), Grade::PartialProxies);
        assert_eq!(health(Some(5000), vec![svc(&[Ok(80)])]).grade(), Grade::Slow);
        assert_eq!(health(Some(50), vec![svc(&[Err("x".into())])]).grade(), Grade::ServiceDown);
        assert_eq!(health(None, vec![]).grade(), Grade::Dead);
        assert!(Grade::Good < Grade::PartialProxies && Grade::Slow < Grade::ServiceDown);
    }

    /// Обращается к настоящим серверам: `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_check_default_servers() {
        println!("internet_ok = {}", internet_ok());
        for server in default_servers() {
            let h = check(&server, true);
            let ips: Vec<String> = h
                .ips
                .iter()
                .map(|i| match &i.result {
                    Ok(ms) => format!("{} {ms}мс", i.ip),
                    Err(e) => format!("{} ОШИБКА {e}", i.ip),
                })
                .collect();
            println!("{:<18} {:?} {:?}: {}", server.name, h.method, h.grade(), ips.join(" | "));
            for s in &h.services {
                let px: Vec<String> = s
                    .proxies
                    .iter()
                    .map(|(a, r)| match r {
                        Ok(ms) => format!("{a} {ms}мс"),
                        Err(e) => format!("{a} {e}"),
                    })
                    .collect();
                println!("    {:<8} {}/{} {:?} {}", s.name, s.ok_count(), s.proxies.len(), s.dns_error, px.join(", "));
            }
        }
    }
}
