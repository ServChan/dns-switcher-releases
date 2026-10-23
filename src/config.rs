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
    /// Сервер из стартового списка: его адреса может обновлять подписанный список с сервера.
    #[serde(default)]
    pub builtin: bool,
    /// Пользователь менял этот сервер вручную: обновления списка его не трогают.
    #[serde(default)]
    pub edited: bool,
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
    /// Версия стартового списка, с которой сохранён этот список.
    #[serde(default)]
    pub defaults_version: u32,
    /// Простой режим с крупными подсказками или подробный со всем списком.
    #[serde(default)]
    pub ui_mode: UiMode,
    /// Сервисы, которые проверяются через серверы обхода ограничений.
    #[serde(default = "default_probes")]
    pub probes: Vec<Probe>,
    #[serde(default)]
    pub notify: Notify,
    #[serde(default)]
    pub updates: Updates,
    /// Стандартные серверы, которые пользователь удалил: обновление списка их не вернёт.
    #[serde(default)]
    pub hidden_builtin: Vec<String>,
    /// Версия подписанного списка серверов, уже применённая к этому списку.
    #[serde(default)]
    pub remote_list_version: u32,
    #[serde(default)]
    pub theme: ThemeChoice,
    /// Подключения, на которых программа выключила IPv6 (чтобы можно было вернуть).
    #[serde(default)]
    pub ipv6_disabled: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub enum ThemeChoice {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub enum UiMode {
    #[default]
    Simple,
    Advanced,
}

/// Сервис, доступность которого проверяется через прокси серверов для ИИ.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Probe {
    pub name: String,
    pub domain: String,
    pub enabled: bool,
}

pub fn default_probes() -> Vec<Probe> {
    let p = |name: &str, domain: &str, enabled: bool| Probe { name: name.into(), domain: domain.into(), enabled };
    vec![
        p("ChatGPT", "chatgpt.com", true),
        p("Gemini", "gemini.google.com", true),
        p("Claude", "claude.ai", true),
        p("AI Studio", "aistudio.google.com", false),
        p("NotebookLM", "notebooklm.google.com", false),
        p("Copilot", "copilot.microsoft.com", false),
        p("Perplexity", "www.perplexity.ai", false),
    ]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notify {
    /// Уведомлять о переключении на резервный сервер и о возврате.
    pub switches: bool,
    /// Уведомлять о проблемах, которые программа сама не исправит (браузер, IPv6).
    pub problems: bool,
}

impl Default for Notify {
    fn default() -> Self {
        Self { switches: true, problems: true }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Updates {
    /// Раз в день проверять, нет ли новой версии программы.
    pub app: bool,
    /// Раз в день подтягивать подписанный список серверов с актуальными адресами.
    pub server_list: bool,
}

impl Default for Updates {
    fn default() -> Self {
        Self { app: true, server_list: true }
    }
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
            defaults_version: DEFAULTS_VERSION,
            ui_mode: UiMode::Simple,
            probes: default_probes(),
            notify: Notify::default(),
            updates: Updates::default(),
            hidden_builtin: Vec::new(),
            remote_list_version: embedded_list().version,
            theme: ThemeChoice::System,
            ipv6_disabled: Vec::new(),
        }
    }
}

#[cfg(test)]
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
        builtin: true,
        edited: false,
    }
}

/// Список серверов в виде, в котором он публикуется: release/servers.json.
/// Тот же файл встроен в программу как стартовый список.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerList {
    pub version: u32,
    pub servers: Vec<DnsServer>,
}

const EMBEDDED_LIST: &str = include_str!("../release/servers.json");

pub fn embedded_list() -> ServerList {
    let mut list: ServerList = serde_json::from_str(EMBEDDED_LIST).expect("release/servers.json разбирается");
    for s in &mut list.servers {
        s.builtin = true;
    }
    list
}

/// Начальный список: release/servers.json. Адреса и порядок по замерам в октябре 2026;
/// в группе ИИ выше стоят серверы, у которых прокси для ChatGPT и Gemini открываются.
/// Порядок задаёт очередь резервных серверов.
pub fn default_servers() -> Vec<DnsServer> {
    embedded_list().servers
}

/// Версия стартового списка. Когда она растёт, сохранённые списки обновляются в `migrate`.
pub const DEFAULTS_VERSION: u32 = 4;

/// Стартовый список версии 2 (с пулом GeoHide RU, у которого не работают прокси).
const DEFAULTS_V2: [(&str, &[&str]); 10] = [
    ("GeoHide EU", &["143.20.64.192", "45.13.237.213", "37.221.93.128"]),
    ("MagicDNS", &["109.120.132.43", "94.249.177.102"]),
    ("dns-ai", &["194.87.196.13", "45.151.102.219"]),
    ("GeoHide US", &["192.255.159.240", "192.255.159.241"]),
    ("Comss DNS", &["83.220.169.155", "212.109.195.93"]),
    ("Xbox-DNS", &["111.88.96.54", "111.88.96.55"]),
    ("GeoHide RU", &["37.230.192.51", "159.194.200.33", "193.233.112.88"]),
    ("AdGuard DNS", &["94.140.14.14", "94.140.15.15"]),
    ("Google Public DNS", &["8.8.8.8", "8.8.4.4"]),
    ("Cloudflare", &["1.1.1.1", "1.0.0.1"]),
];

/// Названия и адреса стартового списка версии 1: так понимаем, что список не правили.
const DEFAULTS_V1: [(&str, &[&str]); 8] = [
    ("GeoHide DNS", &["37.230.192.51", "159.194.200.33", "193.233.112.88"]),
    ("Comss DNS", &["83.220.169.155", "212.109.195.93"]),
    ("Xbox-DNS", &["111.88.96.54", "111.88.96.55"]),
    ("dns-ai", &["194.87.196.13", "45.151.102.219"]),
    ("MagicDNS", &["109.120.132.43", "94.249.177.102"]),
    ("AdGuard DNS", &["94.140.14.14", "94.140.15.15"]),
    ("Google Public DNS", &["8.8.8.8", "8.8.4.4"]),
    ("Cloudflare", &["1.1.1.1", "1.0.0.1"]),
];

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
        let mut cfg: Self = std::fs::read_to_string(config_path())
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        if cfg.migrate() {
            let _ = cfg.save();
            // Выбранный сервер мог называться «GeoHide DNS».
            let mut st = crate::state::RuntimeState::load();
            let mut renamed = false;
            for slot in [&mut st.preferred, &mut st.active] {
                if slot.as_deref() == Some("GeoHide DNS") {
                    *slot = Some(if cfg.find("GeoHide RU").is_some() { "GeoHide RU" } else { "GeoHide EU" }.into());
                    renamed = true;
                }
            }
            if renamed {
                let _ = st.save();
            }
        }
        cfg
    }

    /// Обновляет список, сохранённый со старым стартовым набором. Нетронутый список
    /// заменяется новым целиком; изменённый получает только новые серверы.
    /// Возвращает true, если что-то поменялось.
    fn migrate(&mut self) -> bool {
        if self.defaults_version >= DEFAULTS_VERSION {
            return false;
        }
        let same_as = |list: &[(&str, &[&str])]| {
            self.servers.len() == list.len()
                && self.servers.iter().zip(list).all(|(s, (name, ips))| s.name == *name && s.ipv4 == *ips)
        };
        let was = self.defaults_version;
        if same_as(&DEFAULTS_V1) || same_as(&DEFAULTS_V2) {
            self.servers = default_servers();
        } else if self.defaults_version < 2 {
            // GeoHide разделился на пулы: прежний сервер — это пул RU.
            if self.find("GeoHide RU").is_none() {
                if let Some(old) = self.servers.iter_mut().find(|s| s.name == "GeoHide DNS") {
                    old.name = "GeoHide RU".into();
                }
            }
            let fresh = default_servers();
            let first_ai = self.servers.iter().position(|s| s.ai_bypass).unwrap_or(0);
            for (offset, name) in ["GeoHide EU", "GeoHide US"].into_iter().enumerate() {
                if self.find(name).is_none() {
                    if let Some(s) = fresh.iter().find(|s| s.name == name) {
                        self.servers.insert((first_ai + offset).min(self.servers.len()), s.clone());
                    }
                }
            }
        }
        if was < 4 {
            // Серверы, совпадающие со стартовыми, отмечаются как стандартные:
            // их адреса сможет обновлять подписанный список.
            let fresh = default_servers();
            for s in &mut self.servers {
                if let Some(f) = fresh.iter().find(|f| f.name == s.name) {
                    s.builtin = true;
                    s.edited = s.ipv4 != f.ipv4 || s.doh != f.doh;
                }
            }
            // Список уже был: человек пользовался программой и знает её подробный вид.
            self.ui_mode = UiMode::Advanced;
        }
        self.defaults_version = DEFAULTS_VERSION;
        true
    }

    pub fn save(&self) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(&config_path(), &text)
    }

    pub fn find(&self, name: &str) -> Option<&DnsServer> {
        self.servers.iter().find(|s| s.name == name)
    }

    /// Применяет подписанный список с сервера. Трогает только стандартные серверы,
    /// которые пользователь не менял; удалённые им не возвращает; `keep` (выбранный
    /// и активный сервер) не удаляет. Возвращает, что поменялось, для журнала.
    pub fn apply_server_list(&mut self, list: &ServerList, keep: &[String]) -> Vec<String> {
        if list.version <= self.remote_list_version {
            return Vec::new();
        }
        let mut changes = Vec::new();
        for r in &list.servers {
            match self.servers.iter_mut().find(|s| s.name == r.name) {
                Some(s) if s.builtin && !s.edited => {
                    let same = s.ipv4 == r.ipv4 && s.ipv6 == r.ipv6 && s.doh == r.doh && s.doh_only == r.doh_only;
                    if !same {
                        changes.push(format!("«{}»: новые адреса", r.name));
                    }
                    s.ipv4 = r.ipv4.clone();
                    s.ipv6 = r.ipv6.clone();
                    s.doh = r.doh.clone();
                    s.doh_only = r.doh_only;
                    s.note = r.note.clone();
                    s.ai_bypass = r.ai_bypass;
                }
                Some(_) => {}
                None if self.hidden_builtin.contains(&r.name) => {}
                None => {
                    let mut new = r.clone();
                    new.builtin = true;
                    new.edited = false;
                    // В конец своей группы: порядок задаёт очередь резерва.
                    let at = self.servers.iter().rposition(|s| s.ai_bypass == r.ai_bypass).map(|i| i + 1).unwrap_or(self.servers.len());
                    self.servers.insert(at, new);
                    changes.push(format!("добавлен «{}»", r.name));
                }
            }
        }
        let names: Vec<&str> = list.servers.iter().map(|s| s.name.as_str()).collect();
        self.servers.retain(|s| {
            let keep_it = !s.builtin || s.edited || names.contains(&s.name.as_str()) || keep.contains(&s.name);
            if !keep_it {
                changes.push(format!("убран «{}»", s.name));
            }
            keep_it
        });
        self.remote_list_version = list.version;
        changes
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v1_list() -> Vec<DnsServer> {
        DEFAULTS_V1
            .iter()
            .map(|(name, ips)| server(name, ips, &[], "https://example.org/dns-query", true, ""))
            .collect()
    }

    #[test]
    fn untouched_v1_list_becomes_new_defaults() {
        let mut cfg = Config { servers: v1_list(), defaults_version: 0, ..Config::default() };
        assert!(cfg.migrate());
        let names: Vec<_> = cfg.servers.iter().map(|s| s.name.as_str()).collect();
        let fresh: Vec<_> = default_servers().into_iter().map(|s| s.name).collect();
        assert_eq!(names, fresh);
        assert!(!cfg.migrate());
    }

    #[test]
    fn untouched_v2_list_drops_geohide_ru() {
        let servers = DEFAULTS_V2.iter().map(|(name, ips)| server(name, ips, &[], "", true, "")).collect();
        let mut cfg = Config { servers, defaults_version: 2, ..Config::default() };
        assert!(cfg.migrate());
        assert!(cfg.find("GeoHide RU").is_none());
        assert_eq!(cfg.servers.len(), default_servers().len());
    }

    #[test]
    fn embedded_list_is_valid() {
        let list = embedded_list();
        assert!(list.servers.iter().all(|s| s.builtin && s.validate().is_ok()));
        assert!(list.servers.iter().any(|s| s.ai_bypass) && list.servers.iter().any(|s| !s.ai_bypass));
    }

    #[test]
    fn server_list_update_respects_user_changes() {
        let mut cfg = Config::default();
        cfg.servers.iter_mut().find(|s| s.name == "Comss DNS").unwrap().edited = true;
        cfg.hidden_builtin.push("Новый".into());
        cfg.servers.push(server("Мой DNS", &["10.0.0.1"], &[], "", false, ""));
        cfg.servers.last_mut().unwrap().builtin = false;

        let mut list = embedded_list();
        list.version += 1;
        list.servers.retain(|s| s.name != "Xbox-DNS" && s.name != "GeoHide US");
        let eu = list.servers.iter_mut().find(|s| s.name == "GeoHide EU").unwrap();
        eu.ipv4 = vec!["5.175.161.3".into()];
        let comss = list.servers.iter_mut().find(|s| s.name == "Comss DNS").unwrap();
        comss.ipv4 = vec!["9.9.9.9".into()];
        list.servers.push(server("Свежий", &["10.1.1.1"], &[], "", true, ""));
        list.servers.push(server("Новый", &["10.2.2.2"], &[], "", true, ""));

        let changes = cfg.apply_server_list(&list, &["GeoHide US".to_string()]);
        assert_eq!(cfg.find("GeoHide EU").unwrap().ipv4, ["5.175.161.3"]);
        assert_ne!(cfg.find("Comss DNS").unwrap().ipv4, ["9.9.9.9"], "изменённый вручную не трогаем");
        assert!(cfg.find("Xbox-DNS").is_none(), "убранный из списка удаляется");
        assert!(cfg.find("GeoHide US").is_some(), "выбранный сервер не удаляем");
        assert!(cfg.find("Новый").is_none(), "удалённый пользователем не возвращаем");
        assert!(cfg.find("Мой DNS").is_some());
        let fresh = cfg.servers.iter().position(|s| s.name == "Свежий").unwrap();
        let first_regular = cfg.servers.iter().position(|s| !s.ai_bypass).unwrap();
        assert!(fresh < first_regular, "новый сервер для ИИ встаёт в свою группу");
        assert!(!changes.is_empty());
        assert!(cfg.apply_server_list(&list, &[]).is_empty(), "та же версия второй раз не применяется");
    }

    #[test]
    fn edited_list_keeps_user_servers_and_gains_pools() {
        let mut list = v1_list();
        list.push(server("Мой DNS", &["10.0.0.1"], &[], "", false, ""));
        let mut cfg = Config { servers: list, defaults_version: 0, ..Config::default() };
        assert!(cfg.migrate());
        let names: Vec<_> = cfg.servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(&names[..3], ["GeoHide EU", "GeoHide US", "GeoHide RU"]);
        assert!(names.contains(&"Мой DNS"));
        assert!(!names.contains(&"GeoHide DNS"));
    }
}
