use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

/// Один DNS-сервис из списка.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DnsServer {
    pub name: String,
    #[serde(default)]
    pub ipv4: Vec<String>,
    #[serde(default)]
    pub ipv6: Vec<String>,
    /// Шаблон DNS-over-HTTPS, например https://dns.google/dns-query.
    #[serde(default)]
    pub doh: String,
    /// Сервис предназначен для обхода региональных ограничений ИИ-сервисов.
    #[serde(default)]
    pub ai_bypass: bool,
    /// Сервис не отвечает по обычному DNS (порт 53), работает только через DoH.
    #[serde(default)]
    pub doh_only: bool,
    #[serde(default)]
    pub note: String,
}

impl DnsServer {
    pub fn all_ips(&self) -> impl Iterator<Item = &String> {
        self.ipv4.iter().chain(self.ipv6.iter())
    }

    pub fn has_doh(&self) -> bool {
        !self.doh.trim().is_empty()
    }

    /// Проверяет поля и возвращает понятное сообщение об ошибке.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Укажите название сервера.".into());
        }
        if self.ipv4.is_empty() && self.ipv6.is_empty() {
            return Err("Укажите хотя бы один IP-адрес.".into());
        }
        for ip in &self.ipv4 {
            match ip.parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => {}
                _ => return Err(format!("«{ip}» не похож на IPv4-адрес. Пример: 1.1.1.1")),
            }
        }
        for ip in &self.ipv6 {
            match ip.parse::<IpAddr>() {
                Ok(IpAddr::V6(_)) => {}
                _ => {
                    return Err(format!(
                        "«{ip}» не похож на IPv6-адрес. Пример: 2606:4700:4700::1111"
                    ));
                }
            }
        }
        let doh = self.doh.trim();
        if !doh.is_empty() && !doh.starts_with("https://") {
            return Err("Шаблон DoH должен начинаться с https://".into());
        }
        if self.doh_only && doh.is_empty() {
            return Err("Сервер помечен как «только DoH», но шаблон DoH не указан.".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub servers: Vec<DnsServer>,
    /// Включать шифрование (DoH) для серверов, у которых указан шаблон.
    #[serde(default = "default_true")]
    pub use_doh: bool,
    #[serde(default)]
    pub failover: Failover,
}

/// Куда переключаться, когда не отвечает ни один сервер нужной группы.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum LastResort {
    /// На обычные публичные DNS из списка, затем на DNS от роутера.
    Regular,
    /// Сразу на DNS от роутера или провайдера.
    Dhcp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Failover {
    pub enabled: bool,
    pub interval_secs: u64,
    /// Возвращаться к выбранному вручную серверу, когда он снова отвечает.
    pub return_to_preferred: bool,
    pub last_resort: LastResort,
    /// Следить в фоне и после закрытия окна (задание в Планировщике).
    #[serde(default)]
    pub background: bool,
    /// Дописывать Cloudflare и Google последними адресами на подключении.
    #[serde(default = "default_true")]
    pub safety_net: bool,
}

impl Default for Failover {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            return_to_preferred: true,
            last_resort: LastResort::Regular,
            background: false,
            safety_net: true,
        }
    }
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            servers: default_servers(),
            use_doh: true,
            failover: Failover::default(),
        }
    }
}

fn server(
    name: &str,
    ipv4: &[&str],
    ipv6: &[&str],
    doh: &str,
    ai_bypass: bool,
    note: &str,
) -> DnsServer {
    DnsServer {
        name: name.into(),
        ipv4: ipv4.iter().map(|s| s.to_string()).collect(),
        ipv6: ipv6.iter().map(|s| s.to_string()).collect(),
        doh: doh.into(),
        ai_bypass,
        doh_only: false,
        note: note.into(),
    }
}

/// Начальный список. Адреса сверены с сайтами сервисов в октябре 2026.
pub fn default_servers() -> Vec<DnsServer> {
    let mut dns_ai = server(
        "dns-ai",
        &["194.87.196.13", "45.151.102.219"],
        &["2a00:b700:5::3:62", "2a12:5940:d4ef::219"],
        "https://dns.dns-ai.ru/dns-query",
        true,
        "dns-ai.ru. Только зашифрованный DNS: обычный порт 53 не отвечает.",
    );
    dns_ai.doh_only = true;

    vec![
        server(
            "GeoHide DNS",
            &["37.230.192.51", "159.194.200.33", "193.233.112.88"],
            &[],
            "https://dns.geohide.ru/dns-query",
            true,
            "geohide.ru. ChatGPT, Gemini, Claude и другие ИИ-сервисы.",
        ),
        server(
            "Comss DNS",
            &["83.220.169.155", "212.109.195.93"],
            &[],
            "https://dns.comss.one/dns-query",
            true,
            "comss.one. ИИ-сервисы, плюс блокировка рекламы и трекеров.",
        ),
        server(
            "Xbox-DNS",
            &["111.88.96.54", "111.88.96.55"],
            &["2a00:ab00:1233:26::50", "2a00:ab00:1233:26::51"],
            "https://xbox-dns.ru/dns-query",
            true,
            "xbox-dns.ru. Xbox Live, игры, ChatGPT, Claude, Gemini, Copilot.",
        ),
        dns_ai,
        server(
            "MagicDNS",
            &["109.120.132.43", "94.249.177.102"],
            &[],
            "https://dns.magicdns.ru/dns-query",
            true,
            "magicdns.ru. Claude, Gemini, ChatGPT, Perplexity, Cursor и ещё 30+ сервисов.",
        ),
        server(
            "AdGuard DNS",
            &["94.140.14.14", "94.140.15.15"],
            &["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
            "https://dns.adguard-dns.com/dns-query",
            false,
            "Блокирует рекламу и трекеры.",
        ),
        server(
            "Google Public DNS",
            &["8.8.8.8", "8.8.4.4"],
            &["2001:4860:4860::8888", "2001:4860:4860::8844"],
            "https://dns.google/dns-query",
            false,
            "",
        ),
        server(
            "Cloudflare",
            &["1.1.1.1", "1.0.0.1"],
            &["2606:4700:4700::1111", "2606:4700:4700::1001"],
            "https://cloudflare-dns.com/dns-query",
            false,
            "",
        ),
    ]
}

/// Папка настроек: %APPDATA%\DnsSwitcher.
pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("DnsSwitcher")
}

fn config_path() -> PathBuf {
    data_dir().join("config.json")
}

/// Записывает файл целиком через временный, чтобы второй процесс не прочитал половину.
pub fn write_atomic(path: &std::path::Path, text: &str) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Не удалось создать папку настроек: {e}"))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text)
        .and_then(|_| std::fs::rename(&tmp, path))
        .map_err(|e| format!("Не удалось сохранить {}: {e}", path.display()))
}

impl Config {
    pub fn load() -> Self {
        std::fs::read_to_string(config_path())
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(&config_path(), &text)
    }

    pub fn find(&self, name: &str) -> Option<&DnsServer> {
        self.servers.iter().find(|s| s.name == name)
    }
}

/// Разбирает список адресов, введённых через запятую, пробел или перевод строки.
pub fn parse_ip_list(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}
