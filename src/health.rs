//! Проверка DNS-серверов. Каждый адрес проверяется тем способом, которым его
//! будет использовать Windows (обычный DNS по UDP или DoH). Для серверов обхода
//! ограничений ИИ проверка идёт дальше: DNS выдаёт адреса своих прокси, и мы
//! устанавливаем с каждым TLS-соединение с нужным именем (SNI), как браузер.
//! Ответ DNS ещё не значит, что прокси за ним работает.

use crate::config::{DnsServer, Probe};
use crate::doh;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_sys::Win32::NetworkManagement::Dns::{
    DNS_QUERY_BYPASS_CACHE, DNS_RECORDW, DNS_TYPE_A, DnsFree, DnsFreeRecordList, DnsQuery_W,
};

const TIMEOUT: Duration = Duration::from_secs(3);
/// Имя для проверки самого DNS.
const PROBE_NAME: &str = "chatgpt.com";
/// Дольше этого Windows ответа не ждёт и переходит к следующему адресу,
/// а значит, к страховочным Cloudflare и Google без обхода ограничений.
pub const SLOW_MS: u32 = 1500;
/// Эталонный DNS: с ним сравниваем ответы, чтобы понять, подменяет ли сервер адрес.
const REFERENCE: [(&str, &str); 2] = [
    ("1.1.1.1", "https://cloudflare-dns.com/dns-query"),
    ("8.8.8.8", "https://dns.google/dns-query"),
];
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
/// Сколько прокси из ответа проверять у одного сервиса.
const MAX_PROXIES: usize = 8;
/// Сколько TLS-соединений открывать одновременно при полной проверке.
const FULL_PARALLEL: usize = 3;
/// Сколько прокси перебирать в обычной проверке до вывода «сервис не открывается».
const QUICK_PROXIES: usize = 4;

/// Насколько подробно проверять. Обычная проверка бережная: прокси пробуются по
/// одному до первого рабочего, сервисы по очереди. Десятки одновременных
/// TLS-соединений сеть может принять за подозрительные и портить их, и тогда
/// здоровый сервер выглядит сломанным.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Depth {
    /// Для защиты и периодических проверок: «открывается ли сервис».
    Quick,
    /// По кнопке «Проверить»: каждый прокси, не больше трёх соединений сразу.
    Full,
}

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
    pub name: String,
    pub domain: String,
    /// Сервер подменяет адрес на свой прокси. false: отдаёт настоящий адрес, обхода нет.
    /// None: сравнить не удалось (эталонный DNS не ответил).
    pub proxied: Option<bool>,
    /// Сервер отдаёт настоящий IPv6-адрес сервиса: при работающем IPv6 браузер пойдёт мимо прокси.
    pub ipv6_leak: bool,
    /// Ошибка, если DNS не дал адресов для этого сервиса.
    pub dns_error: Option<String>,
    pub proxies: Vec<(Ipv4Addr, Result<u32, String>)>,
}

impl ServiceHealth {
    pub fn ok_count(&self) -> usize {
        self.proxies.iter().filter(|(_, r)| r.is_ok()).count()
    }

    pub fn works(&self) -> bool {
        self.dns_error.is_none() && self.proxied != Some(false) && self.ok_count() > 0
    }

    pub fn fully(&self) -> bool {
        self.works() && self.ok_count() == self.proxies.len()
    }

    pub fn best_ms(&self) -> Option<u32> {
        self.proxies.iter().filter_map(|(_, r)| r.as_ref().ok().copied()).min()
    }

    pub fn first_error(&self) -> Option<&str> {
        if self.proxied == Some(false) {
            return Some("сервер отдаёт настоящий адрес, обхода нет");
        }
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
    pub fn code(self) -> u8 {
        self as u8
    }

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
            let names: Vec<&str> = self.services.iter().map(|s| s.name.as_str()).collect();
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

/// Проверяет все адреса сервера параллельно, а для серверов обхода ИИ ещё и
/// включённые сервисы из `probes`.
pub fn check(server: &DnsServer, use_doh: bool, probes: &[Probe], depth: Depth) -> Health {
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

    // Сервисы спрашиваем у рабочих адресов DNS начиная с самого быстрого: его Windows
    // и выберет, а остальные подстрахуют, если запрос к нему сорвётся.
    let mut working: Vec<(u32, IpAddr)> = ips
        .iter()
        .filter_map(|h| Some((*h.result.as_ref().ok()?, h.ip.parse::<IpAddr>().ok()?)))
        .collect();
    working.sort();
    let dns_ips: Vec<IpAddr> = working.into_iter().map(|(_, ip)| ip).collect();
    // Сервисы по очереди: так в каждый момент открыто не больше нескольких соединений.
    let services = match (server.ai_bypass, dns_ips.is_empty()) {
        (true, false) => probes
            .iter()
            .filter(|p| p.enabled)
            .map(|p| check_service(p.name.clone(), p.domain.clone(), &dns_ips, method, &template, depth))
            .collect(),
        _ => Vec::new(),
    };
    Health { method, ips, services }
}

fn check_service(
    name: String,
    domain: String,
    dns_ips: &[IpAddr],
    method: Method,
    template: &str,
    depth: Depth,
) -> ServiceHealth {
    let mut out = ServiceHealth { name, domain: domain.clone(), proxied: None, ipv6_leak: false, dns_error: None, proxies: Vec::new() };
    // Запрос по DoH сам идёт по TLS и иногда портится в сети: повторяем и пробуем
    // другие адреса сервера, прежде чем считать, что адреса сервиса нет.
    let mut answer = Err("нет ответа".to_string());
    let mut dns_ip = dns_ips[0];
    for &ip in dns_ips {
        answer = retry(2, || resolve(ip, method, template, &domain));
        dns_ip = ip;
        if answer.is_ok() {
            break;
        }
    }
    let addrs = match answer {
        Ok((_, addrs)) if addrs.is_empty() => {
            out.dns_error = Some("DNS не дал адресов".into());
            return out;
        }
        Ok((_, addrs)) => addrs,
        Err(e) => {
            out.dns_error = Some(e);
            return out;
        }
    };
    // Подменяет ли сервер адрес: ответ, совпадающий с эталонным, значит обхода нет.
    if let Some(real) = reference(&domain, QTYPE_A) {
        let real: Vec<Ipv4Addr> = real.iter().filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        }).collect();
        if !real.is_empty() {
            out.proxied = Some(!addrs.iter().any(|a| real.contains(a)));
        }
    }
    // IPv6: если сервер отдаёт настоящий AAAA, браузер с IPv6 пойдёт напрямую.
    if let Ok(v6) = resolve_any(dns_ip, method, template, &domain, QTYPE_AAAA) {
        if let Some(real6) = reference(&domain, QTYPE_AAAA) {
            out.ipv6_leak = v6.iter().any(|a| real6.contains(a));
        }
    }
    let addrs: Vec<Ipv4Addr> = addrs.into_iter().take(MAX_PROXIES).collect();
    match depth {
        // По одному до первого рабочего: браузер тоже идёт к одному прокси.
        Depth::Quick => {
            for addr in addrs.into_iter().take(QUICK_PROXIES) {
                // До трёх попыток: в сети бывают одиночные испорченные рукопожатия,
                // а у некоторых серверов прокси всего один.
                let result = retry(3, || tls_probe(addr, &domain));
                let ok = result.is_ok();
                out.proxies.push((addr, result));
                if ok {
                    break;
                }
            }
        }
        Depth::Full => {
            for chunk in addrs.chunks(FULL_PARALLEL) {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|&addr| {
                        let domain = domain.clone();
                        std::thread::spawn(move || (addr, retry_once(|| tls_probe(addr, &domain))))
                    })
                    .collect();
                out.proxies.extend(handles.into_iter().filter_map(|h| h.join().ok()));
            }
        }
    }
    out
}

/// Ошибка TLS по-русски и коротко: исходные тексты rustls длинные и английские.
pub fn tls_error_text(e: &std::io::Error) -> String {
    let text = e.to_string();
    if text.contains("InvalidContentType") || text.contains("corrupt message") {
        "ответ не похож на TLS: соединение испорчено по пути".into()
    } else if text.contains("certificate") || text.contains("Certificate") {
        "чужой сертификат: соединение подменено".into()
    } else if text.contains("alert") || text.contains("Alert") {
        "сервер прервал защищённое соединение".into()
    } else {
        "ошибка защищённого соединения".into()
    }
}

/// Ответ эталонного DNS (Cloudflare, затем Google) по DoH. Кэшируется на 10 минут.
fn reference(domain: &str, qtype: u16) -> Option<Vec<IpAddr>> {
    static CACHE: OnceLock<Mutex<HashMap<(String, u16), (Instant, Vec<IpAddr>)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (domain.to_string(), qtype);
    if let Some((at, ips)) = cache.lock().ok()?.get(&key) {
        if at.elapsed() < Duration::from_secs(600) {
            return Some(ips.clone());
        }
    }
    for (ip, template) in REFERENCE {
        let Ok(addr) = ip.parse::<IpAddr>() else { continue };
        if let Ok(ips) = retry_once(|| resolve_any(addr, Method::Doh, template, domain, qtype)) {
            cache.lock().ok()?.insert(key, (Instant::now(), ips.clone()));
            return Some(ips);
        }
    }
    None
}

/// Как отвечает сама Windows: системный резолвер в обход кэша.
pub fn system_resolve(domain: &str) -> Result<Vec<Ipv4Addr>, String> {
    let name: Vec<u16> = domain.encode_utf16().chain(std::iter::once(0)).collect();
    let mut results = std::ptr::null_mut();
    let status = unsafe {
        DnsQuery_W(
            name.as_ptr(),
            DNS_TYPE_A,
            DNS_QUERY_BYPASS_CACHE,
            std::ptr::null_mut(),
            &mut results,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(format!("Windows не смогла узнать адрес (код {status})"));
    }
    let mut out = Vec::new();
    let mut cur = results as *const DNS_RECORDW;
    while !cur.is_null() {
        let rec = unsafe { &*cur };
        if rec.wType == DNS_TYPE_A {
            out.push(Ipv4Addr::from(unsafe { rec.Data.A.IpAddress }.to_ne_bytes()));
        }
        cur = rec.pNext;
    }
    unsafe { DnsFree(results as *const _, DnsFreeRecordList) };
    Ok(out)
}

/// Сквозная проверка: получает ли Windows ответы от выбранного сервера.
#[derive(Clone, Debug)]
pub struct EndToEnd {
    pub domain: String,
    pub system: Result<Vec<Ipv4Addr>, String>,
    /// Windows отдаёт адреса прокси этого сервера.
    pub via_server: Option<bool>,
    /// Windows отдаёт настоящие адреса сервиса: обход не действует.
    pub real: Option<bool>,
}

impl EndToEnd {
    pub fn ok(&self) -> bool {
        self.via_server != Some(false)
    }
}

/// Сверяет ответ Windows для первого проверяемого сервиса с ответом сервера.
pub fn end_to_end(server: &DnsServer, health: &Health) -> Option<EndToEnd> {
    let service = health.services.iter().find(|s| s.dns_error.is_none())?;
    let mut server_ips: Vec<Ipv4Addr> = health.services.iter().flat_map(|s| s.proxies.iter().map(|(a, _)| *a)).collect();
    server_ips.extend(server.ipv4.iter().filter_map(|s| s.parse::<Ipv4Addr>().ok()));
    let system = system_resolve(&service.domain);
    let (via_server, real) = match &system {
        Ok(ips) if !ips.is_empty() => {
            let via = ips.iter().any(|a| server_ips.contains(a));
            let real = reference(&service.domain, QTYPE_A).map(|r| ips.iter().any(|a| r.contains(&IpAddr::V4(*a))));
            (Some(via), real)
        }
        _ => (None, None),
    };
    Some(EndToEnd { domain: service.domain.clone(), system, via_server, real })
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
            std::io::ErrorKind::InvalidData => tls_error_text(&e),
            _ => "соединение сброшено".to_string(),
        })?;
    }
    Ok(start.elapsed().as_millis().min(u32::MAX as u128) as u32)
}

/// Повторяет неудачную проверку один раз: разовые сбои сети (сброс соединения,
/// испорченный TLS-пакет) не должны выглядеть как отказ сервера.
fn retry_once<T>(f: impl FnMut() -> Result<T, String>) -> Result<T, String> {
    retry(2, f)
}

/// До `attempts` попыток с паузой 400 мс; возвращает первую удачу или последнюю ошибку.
/// Повторяются только быстрые случайные сбои (испорченный TLS, сброс соединения):
/// если адрес не отвечает вовсе, повтор лишь затянул бы проверку на секунды.
fn retry<T>(attempts: u32, mut f: impl FnMut() -> Result<T, String>) -> Result<T, String> {
    let mut last = f();
    for _ in 1..attempts {
        match &last {
            Ok(_) => break,
            Err(e) if is_silence(e) => break,
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(400));
        last = f();
    }
    last
}

/// Ошибка «адрес молчит»: повторять бесполезно.
fn is_silence(e: &str) -> bool {
    ["не отвечает", "нет ответа", "нет соединения", "не завершился"].iter().any(|w| e.contains(w))
}

/// Запрос любого типа: адреса из ответа (A или AAAA).
fn resolve_any(ip: IpAddr, method: Method, template: &str, name: &str, qtype: u16) -> Result<Vec<IpAddr>, String> {
    let id = query_id();
    let message = build_query_type(id, name, qtype);
    let reply = match method {
        Method::Udp => udp_exchange(ip, &message)?,
        Method::Doh => doh::query(ip, template, &message, TIMEOUT)?,
    };
    validate_reply(&reply, id)?;
    let (v4, v6) = parse_answers(&reply);
    Ok(v4.into_iter().map(IpAddr::V4).chain(v6.into_iter().map(IpAddr::V6)).collect())
}

/// DNS-запрос типа A к одному адресу сервера: время ответа и адреса из ответа.
fn resolve(ip: IpAddr, method: Method, template: &str, name: &str) -> Result<(u32, Vec<Ipv4Addr>), String> {
    let id = query_id();
    let message = build_query_type(id, name, QTYPE_A);
    let start = Instant::now();
    let reply = match method {
        Method::Udp => udp_exchange(ip, &message)?,
        Method::Doh => doh::query(ip, template, &message, TIMEOUT)?,
    };
    validate_reply(&reply, id)?;
    let ms = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
    Ok((ms, parse_answers(&reply).0))
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

/// Адреса A и AAAA из раздела ответов (CNAME по дороге пропускаются).
fn parse_answers(msg: &[u8]) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    let mut out = Vec::new();
    let mut out6 = Vec::new();
    if msg.len() < 12 {
        return (out, out6);
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = 12;
    for _ in 0..qd {
        match skip_name(msg, pos) {
            Some(p) => pos = p + 4,
            None => return (out, out6),
        }
    }
    for _ in 0..an {
        let Some(p) = skip_name(msg, pos) else { break };
        let Some(head) = msg.get(p..p + 10) else { break };
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let len = u16::from_be_bytes([head[8], head[9]]) as usize;
        let data = p + 10;
        if kind == QTYPE_A && len == 4 {
            if let Some(b) = msg.get(data..data + 4) {
                out.push(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            }
        } else if kind == QTYPE_AAAA && len == 16 {
            if let Some(b) = msg.get(data..data + 16) {
                let bytes: [u8; 16] = b.try_into().unwrap_or([0; 16]);
                out6.push(Ipv6Addr::from(bytes));
            }
        }
        pos = data + len;
    }
    (out, out6)
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

fn build_query_type(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, один вопрос
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // конец имени
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]); // класс IN
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
        assert_eq!(parse_answers(&m).0, vec![Ipv4Addr::new(1, 2, 3, 4)]);
    }

    fn svc(results: &[Result<u32, String>]) -> ServiceHealth {
        ServiceHealth {
            name: "ChatGPT".into(),
            domain: "chatgpt.com".into(),
            proxied: Some(true),
            ipv6_leak: false,
            dns_error: None,
            proxies: results.iter().map(|r| (Ipv4Addr::LOCALHOST, r.clone())).collect(),
        }
    }

    fn health(dns_ms: Option<u32>, services: Vec<ServiceHealth>) -> Health {
        let result = dns_ms.ok_or_else(|| "нет ответа".to_string());
        Health { method: Method::Udp, ips: vec![IpHealth { ip: "1.1.1.1".into(), result }], services }
    }

    #[test]
    fn retry_repeats_flaky_errors_but_not_silence() {
        let mut calls = 0;
        let r: Result<(), String> = retry(3, || {
            calls += 1;
            Err("ответ не похож на TLS: соединение испорчено по пути".into())
        });
        assert!(r.is_err());
        assert_eq!(calls, 3);
        let mut calls = 0;
        let _ = retry::<()>(3, || {
            calls += 1;
            Err("прокси не отвечает".into())
        });
        assert_eq!(calls, 1);
        let mut calls = 0;
        let r = retry(3, || {
            calls += 1;
            if calls < 2 { Err("соединение сброшено".to_string()) } else { Ok(calls) }
        });
        assert_eq!(r, Ok(2));
    }

    #[test]
    fn tls_errors_are_short_and_russian() {
        let e = std::io::Error::new(std::io::ErrorKind::InvalidData, "received corrupt message of type InvalidContentType");
        assert_eq!(tls_error_text(&e), "ответ не похож на TLS: соединение испорчено по пути");
        let e = std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid peer certificate: UnknownIssuer");
        assert_eq!(tls_error_text(&e), "чужой сертификат: соединение подменено");
    }

    #[test]
    fn grades_from_best_to_worst() {
        assert_eq!(health(Some(50), vec![svc(&[Ok(80)])]).grade(), Grade::Good);
        assert_eq!(health(Some(50), vec![svc(&[Ok(80), Err("x".into())])]).grade(), Grade::PartialProxies);
        assert_eq!(health(Some(5000), vec![svc(&[Ok(80)])]).grade(), Grade::Slow);
        assert_eq!(health(Some(50), vec![svc(&[Err("x".into())])]).grade(), Grade::ServiceDown);
        assert_eq!(health(None, vec![]).grade(), Grade::Dead);
        assert!(Grade::Good < Grade::PartialProxies && Grade::Slow < Grade::ServiceDown);
        let mut not_proxied = svc(&[Ok(80)]);
        not_proxied.proxied = Some(false);
        assert_eq!(health(Some(50), vec![not_proxied]).grade(), Grade::ServiceDown);
    }

    /// Сколько раз бережная проверка ошибочно признаёт рабочий сервер сломанным:
    /// `cargo test -- --ignored --nocapture live_quick_stability`.
    #[test]
    #[ignore]
    fn live_quick_stability() {
        let probes = crate::config::default_probes();
        for name in ["GeoHide EU", "MagicDNS"] {
            let server = default_servers().into_iter().find(|s| s.name == name).unwrap();
            let mut bad = Vec::new();
            for _ in 0..20 {
                let h = check(&server, true, &probes, Depth::Quick);
                if !h.grade().acceptable() {
                    bad.push(h.problem().unwrap_or_default());
                }
                std::thread::sleep(Duration::from_secs(2));
            }
            println!("{name}: плохих {} из 20 {:?}", bad.len(), bad);
        }
    }

    /// Как распределены во времени сбои TLS: раз в секунду одно рукопожатие.
    #[test]
    #[ignore]
    fn live_tls_burst_pattern() {
        for (ip, domain) in [("37.221.93.128", "claude.ai"), ("37.221.93.128", "gemini.google.com"), ("94.249.177.102", "claude.ai")] {
            let addr: Ipv4Addr = ip.parse().unwrap();
            let line: String = (0..40)
                .map(|_| {
                    let ok = tls_probe(addr, domain).is_ok();
                    std::thread::sleep(Duration::from_millis(1000));
                    if ok { '+' } else { 'x' }
                })
                .collect();
            println!("{ip} {domain:<18} {line}");
        }
    }

    /// Обращается к настоящим серверам: `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_check_default_servers() {
        println!("internet_ok = {}", internet_ok());
        let probes = crate::config::default_probes();
        for server in default_servers() {
            let started = Instant::now();
            let h = check(&server, true, &probes, Depth::Quick);
            println!("  ({:.1} с) {}", started.elapsed().as_secs_f32(), h.problem().unwrap_or_else(|| "работает".into()));
            let ips: Vec<String> = h
                .ips
                .iter()
                .map(|i| match &i.result {
                    Ok(ms) => format!("{} {ms}мс", i.ip),
                    Err(e) => format!("{} ОШИБКА {e}", i.ip),
                })
                .collect();
            println!("{:<18} {:?} {:?}: {}", server.name, h.method, h.grade(), ips.join(" | "));
            if server.name == "MagicDNS" {
                println!("    сквозная проверка: {:?}", end_to_end(&server, &h));
            }
            for s in &h.services {
                let px: Vec<String> = s
                    .proxies
                    .iter()
                    .map(|(a, r)| match r {
                        Ok(ms) => format!("{a} {ms}мс"),
                        Err(e) => format!("{a} {e}"),
                    })
                    .collect();
                println!(
                    "    {:<10} {}/{} proxied={:?} v6leak={} {:?} {}",
                    s.name, s.ok_count(), s.proxies.len(), s.proxied, s.ipv6_leak, s.dns_error, px.join(", ")
                );
            }
        }
    }
}
