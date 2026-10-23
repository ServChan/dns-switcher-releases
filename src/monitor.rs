//! Защита от сбоев: периодически проверяет активный DNS-сервер и при отказе
//! переключает подключения на следующий рабочий сервер, а потом возвращает
//! выбранный пользователем, когда тот оживёт.
//!
//! Следит ровно один процесс: окно программы или фоновое задание
//! (`dns-switcher.exe --watch`). Кто первым занял именованный мьютекс, тот и следит,
//! второй ждёт и подхватит слежение, если первый завершится.

use crate::apply::{self, Action};
use crate::config::{Config, DnsServer, LastResort};
use crate::health::{self, Grade, Health};
use crate::net::{self, Adapter};
use crate::state::{self, RuntimeState};
use crate::tasks;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{CreateMutexW, OpenMutexW};

const LOCK_NAME: &str = "Local\\DnsSwitcherWatch";
const SYNCHRONIZE: u32 = 0x0010_0000;
/// Сколько проверок подряд сервер должен не отвечать, чтобы переключиться.
const FAILS_TO_SWITCH: u32 = 2;
/// Сколько проверок подряд выбранный сервер должен отвечать, чтобы к нему вернуться.
const OKS_TO_RETURN: u32 = 2;

/// Окно держит мьютекс само: так оно отличает своё слежение от фонового.
pub static IN_PROCESS_WATCHING: AtomicBool = AtomicBool::new(false);

struct WatchLock(HANDLE);

impl Drop for WatchLock {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn acquire_lock() -> Option<WatchLock> {
    let name = wide(LOCK_NAME);
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if h.is_null() {
        return None;
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe { CloseHandle(h) };
        return None;
    }
    Some(WatchLock(h))
}

/// Следит ли сейчас какой-нибудь процесс.
pub fn someone_watching() -> bool {
    let name = wide(LOCK_NAME);
    let h = unsafe { OpenMutexW(SYNCHRONIZE, 0, name.as_ptr()) };
    if h.is_null() {
        return false;
    }
    unsafe { CloseHandle(h) };
    true
}

/// Слежение в фоновом задании.
pub fn background_watching() -> bool {
    someone_watching() && !IN_PROCESS_WATCHING.load(Ordering::Relaxed)
}

/// Главный цикл. Работает, пока `stop` не станет true.
pub fn run_loop(stop: Arc<AtomicBool>, in_process: bool) {
    while !stop.load(Ordering::Relaxed) {
        if let Some(lock) = acquire_lock() {
            if in_process {
                IN_PROCESS_WATCHING.store(true, Ordering::Relaxed);
            }
            let mut watcher = Watcher::default();
            while !stop.load(Ordering::Relaxed) {
                let cfg = Config::load();
                if cfg.failover.enabled {
                    watcher.tick(&cfg);
                } else {
                    watcher = Watcher::default();
                }
                sleep_checked(&stop, Duration::from_secs(cfg.failover.interval_secs.max(10)));
            }
            IN_PROCESS_WATCHING.store(false, Ordering::Relaxed);
            drop(lock);
        } else {
            sleep_checked(&stop, Duration::from_secs(10));
        }
    }
}

fn sleep_checked(stop: &AtomicBool, total: Duration) {
    let step = Duration::from_millis(500);
    let mut left = total;
    while left > Duration::ZERO && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(step.min(left));
        left = left.saturating_sub(step);
    }
}

fn server_has_ip(s: &DnsServer, ip: &IpAddr) -> bool {
    s.all_ips().any(|x| x.parse::<IpAddr>().ok().as_ref() == Some(ip))
}

#[derive(Default)]
struct Watcher {
    fail_streak: u32,
    return_streak: u32,
    offline_logged: bool,
    /// Уже записали в журнал, что лучше текущего сервера ничего нет.
    stuck_logged: bool,
}

impl Watcher {
    fn tick(&mut self, cfg: &Config) {
        let mut st = RuntimeState::load();
        if st.preferred.is_none() {
            *self = Watcher::default();
            return;
        }
        let adapters: Vec<Adapter> = net::list_adapters()
            .unwrap_or_default()
            .into_iter()
            .filter(|a| st.adapters.contains(&a.guid))
            .collect();
        let up: Vec<&Adapter> = adapters.iter().filter(|a| a.up).collect();
        if up.is_empty() {
            return; // нет подключения: проверять нечего
        }

        if st.on_dhcp_fallback {
            self.leave_dhcp(cfg, &mut st, &adapters);
            return;
        }

        let Some(active) = st.active.as_ref().and_then(|n| cfg.find(n)).cloned() else {
            return;
        };

        // DNS поменяли в обход программы: не воюем с пользователем.
        let in_use = up.iter().any(|a| a.dns.first().is_some_and(|ip| server_has_ip(&active, ip)));
        if !in_use {
            let other = cfg
                .servers
                .iter()
                .find(|s| up.iter().any(|a| a.dns.first().is_some_and(|ip| server_has_ip(s, ip))));
            match other {
                Some(s) => {
                    state::log(&format!("На подключении теперь «{}». Слежу за ним.", s.name));
                    st.active = Some(s.name.clone());
                    st.preferred = Some(s.name.clone());
                }
                None => {
                    state::log(
                        "DNS на подключении изменён вне программы. Автопереключение приостановлено до следующего «Применить».",
                    );
                    st.active = None;
                    st.preferred = None;
                }
            }
            let _ = st.save();
            *self = Watcher::default();
            return;
        }

        let health = health::check(&active, cfg.use_doh);
        let grade = health.grade();
        if grade.acceptable() {
            if self.fail_streak > 0 {
                state::log(&format!("«{}» снова работает нормально.", active.name));
            }
            self.fail_streak = 0;
            self.offline_logged = false;
            self.stuck_logged = false;
            if cfg.failover.return_to_preferred && st.active != st.preferred {
                self.try_return(cfg, &mut st, &adapters);
            }
            return;
        }

        if grade == Grade::Dead && !health::internet_ok() {
            if !self.offline_logged {
                state::log("Нет доступа в интернет. DNS не переключаю, жду, когда связь вернётся.");
                self.offline_logged = true;
            }
            return;
        }
        self.offline_logged = false;
        self.fail_streak += 1;
        let reason = health.problem().unwrap_or_default();
        if self.fail_streak < FAILS_TO_SWITCH {
            state::log(&format!(
                "«{}» — {reason}. Перепроверю через {} с.",
                active.name, cfg.failover.interval_secs
            ));
            return;
        }

        // Ищем замену строго лучше текущего: сначала в той же группе, по порядку списка.
        let (same, fallback) = candidates(cfg, &active);
        let checked = check_all(cfg, &same);
        if let Some((s, h)) = best(&checked, grade) {
            if switch_to(cfg, &mut st, &adapters, &health::prefer_working(&s, &h)) {
                state::log(&format!("Переключено с «{}» на «{}». Причина: «{}» — {reason}.", active.name, s.name, active.name));
                state::log(&choice_note(&s.name, &h, &checked));
                *self = Watcher::default();
                return;
            }
        }
        if grade == Grade::Dead {
            let checked_fallback = check_all(cfg, &fallback);
            if let Some((s, h)) = best(&checked_fallback, Grade::Dead) {
                if switch_to(cfg, &mut st, &adapters, &health::prefer_working(&s, &h)) {
                    state::log(&format!(
                        "Переключено с «{}» на обычный DNS «{}»: серверы для ИИ не подошли. \
                         Интернет работает, ИИ-сервисы могут не открываться.",
                        active.name, s.name
                    ));
                    state::log(&format!("Серверы для ИИ: {}.", candidates_note(&checked, None)));
                    *self = Watcher::default();
                    return;
                }
            }
            go_dhcp(&mut st, &adapters, &format!("«{}» и все резервные серверы не отвечают", active.name));
            *self = Watcher::default();
            return;
        }
        // Текущий работает хотя бы частично, а лучше нет: оставляем и ищем дальше.
        if !self.stuck_logged {
            state::log(&format!(
                "«{}» — {reason}. Лучше вариантов сейчас нет, оставляю его. Проверены: {}.",
                active.name,
                candidates_note(&checked, None)
            ));
            self.stuck_logged = true;
        }
    }

    /// Вернуться к выбранному вручную серверу, если он стабильно работает.
    fn try_return(&mut self, cfg: &Config, st: &mut RuntimeState, adapters: &[Adapter]) {
        let Some(preferred) = st.preferred.as_ref().and_then(|n| cfg.find(n)).cloned() else { return };
        let h = health::check(&preferred, cfg.use_doh);
        if h.grade().acceptable() {
            self.return_streak += 1;
        } else {
            self.return_streak = 0;
        }
        if self.return_streak >= OKS_TO_RETURN && switch_to(cfg, st, adapters, &health::prefer_working(&preferred, &h)) {
            self.return_streak = 0;
            state::log(&format!("«{}» снова работает, вернул его.", preferred.name));
        }
    }

    /// Сейчас стоит DNS от роутера. Как только подходящий сервер ответит, ставим лучший.
    fn leave_dhcp(&mut self, cfg: &Config, st: &mut RuntimeState, adapters: &[Adapter]) {
        let Some(preferred) = st.preferred.as_ref().and_then(|n| cfg.find(n)).cloned() else { return };
        let (same, fallback) = candidates(cfg, &preferred);
        let mut first = vec![preferred.clone()];
        first.extend(same);
        let mut checked = check_all(cfg, &first);
        let mut found = best(&checked, Grade::Dead);
        if found.is_none() {
            checked = check_all(cfg, &fallback);
            found = best(&checked, Grade::Dead);
        }
        if let Some((s, h)) = found {
            if switch_to(cfg, st, adapters, &health::prefer_working(&s, &h)) {
                state::log(&format!("«{}» отвечает, переключил на него с DNS от роутера.", s.name));
                state::log(&choice_note(&s.name, &h, &checked));
            }
        }
    }
}

/// Резервные серверы: та же группа в порядке списка (порядок задаёт приоритет),
/// и отдельно обычные DNS на крайний случай, если это разрешено настройками.
fn candidates(cfg: &Config, current: &DnsServer) -> (Vec<DnsServer>, Vec<DnsServer>) {
    let usable = |s: &&DnsServer| s.name != current.name && (!s.doh_only || cfg.use_doh);
    let same = cfg.servers.iter().filter(|s| s.ai_bypass == current.ai_bypass).filter(usable).cloned().collect();
    let fallback = if current.ai_bypass && cfg.failover.last_resort == LastResort::Regular {
        cfg.servers.iter().filter(|s| !s.ai_bypass).filter(usable).cloned().collect()
    } else {
        Vec::new()
    };
    (same, fallback)
}

/// Почему выбран именно этот сервер: его состояние и состояние остальных проверенных.
fn choice_note(chosen: &str, health: &Health, checked: &[(DnsServer, Health)]) -> String {
    let others = candidates_note(checked, Some(chosen));
    let rule = "выбирается лучший по проверке, при равенстве тот, что выше в списке";
    if others.is_empty() {
        format!("Выбран «{chosen}» ({rule}): {}.", health.summary())
    } else {
        format!("Выбран «{chosen}» ({rule}): {}. Остальные: {others}.", health.summary())
    }
}

/// Состояние проверенных серверов через точку с запятой, кроме `skip`.
fn candidates_note(checked: &[(DnsServer, Health)], skip: Option<&str>) -> String {
    checked
        .iter()
        .filter(|(s, _)| Some(s.name.as_str()) != skip)
        .map(|(s, h)| format!("«{}» — {}", s.name, h.summary()))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Проверяет серверы параллельно, порядок списка сохраняется.
fn check_all(cfg: &Config, servers: &[DnsServer]) -> Vec<(DnsServer, Health)> {
    let handles: Vec<_> = servers
        .iter()
        .cloned()
        .map(|s| {
            let use_doh = cfg.use_doh;
            std::thread::spawn(move || {
                let h = health::check(&s, use_doh);
                (s, h)
            })
        })
        .collect();
    handles.into_iter().filter_map(|h| h.join().ok()).collect()
}

/// Лучший сервер с оценкой строже `than`; при равной оценке выигрывает стоящий выше в списке.
fn best(checked: &[(DnsServer, Health)], than: Grade) -> Option<(DnsServer, Health)> {
    checked
        .iter()
        .enumerate()
        .filter(|(_, (_, h))| h.grade() < than)
        .min_by_key(|(i, (_, h))| (h.grade(), *i))
        .map(|(_, pair)| pair.clone())
}

fn switch_to(cfg: &Config, st: &mut RuntimeState, adapters: &[Adapter], server: &DnsServer) -> bool {
    let action = Action::Apply {
        server: server.clone(),
        use_doh: cfg.use_doh,
        safety_net: cfg.failover.safety_net,
    };
    let outcomes = apply::run(&action, adapters);
    let ok = outcomes.iter().any(|o| o.result.is_ok());
    if !ok {
        let errors: Vec<String> = outcomes
            .iter()
            .filter_map(|o| o.result.as_ref().err().map(|e| format!("{}: {e}", o.adapter)))
            .collect();
        state::log(&format!("Не удалось поставить «{}»: {}", server.name, errors.join("; ")));
        return false;
    }
    st.active = Some(server.name.clone());
    st.on_dhcp_fallback = false;
    let _ = st.save();
    true
}

fn go_dhcp(st: &mut RuntimeState, adapters: &[Adapter], reason: &str) {
    let outcomes = apply::run(&Action::Reset, adapters);
    if outcomes.iter().any(|o| o.result.is_ok()) {
        st.on_dhcp_fallback = true;
        let _ = st.save();
        state::log(&format!(
            "{reason}. Временно включён DNS от роутера, чтобы интернет работал. Верну сервер, когда он ответит."
        ));
    } else {
        state::log(&format!("{reason}. Переключить на DNS от роутера тоже не удалось."));
    }
}

// ---------- Фоновое задание ----------

pub fn task_installed() -> bool {
    tasks::exists(tasks::WATCHDOG)
}

/// Создаёт задание «при входе в Windows» для текущего exe и сразу запускает его.
pub fn install_task() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    install_task_for(&exe)
}

pub fn install_task_for(exe: &std::path::Path) -> Result<(), String> {
    tasks::create(
        tasks::WATCHDOG,
        exe,
        "--watch",
        true,
        "Переключатель DNS: проверяет DNS-серверы и переключает на резервный при сбое.",
    )?;
    tasks::run(tasks::WATCHDOG).map_err(|e| format!("Задание создано, но не запустилось: {e}"))
}

pub fn remove_task() -> Result<(), String> {
    tasks::remove(tasks::WATCHDOG)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn names(list: Vec<DnsServer>) -> Vec<String> {
        list.into_iter().map(|s| s.name).collect()
    }

    #[test]
    fn candidates_keep_list_order_and_split_regular() {
        let cfg = Config::default();
        let comss = cfg.find("Comss DNS").unwrap();
        let (same, fallback) = candidates(&cfg, comss);
        let ai: Vec<String> = cfg.servers.iter().filter(|s| s.ai_bypass && s.name != "Comss DNS").map(|s| s.name.clone()).collect();
        assert_eq!(names(same), ai);
        assert_eq!(names(fallback), ["AdGuard DNS", "Google Public DNS", "Cloudflare"]);
    }

    #[test]
    fn candidates_skip_doh_only_without_doh_and_respect_dhcp_choice() {
        let mut cfg = Config::default();
        cfg.use_doh = false;
        cfg.failover.last_resort = LastResort::Dhcp;
        let (same, fallback) = candidates(&cfg, cfg.find("GeoHide EU").unwrap());
        assert!(!names(same).contains(&"dns-ai".to_string()));
        assert!(fallback.is_empty());
    }

    #[test]
    fn regular_server_has_no_separate_fallback() {
        let cfg = Config::default();
        let (same, fallback) = candidates(&cfg, cfg.find("Google Public DNS").unwrap());
        assert_eq!(names(same), ["AdGuard DNS", "Cloudflare"]);
        assert!(fallback.is_empty());
    }

    fn fake(name: &str, dns_ms: Option<u32>, proxy_ok: bool) -> (DnsServer, Health) {
        use crate::health::{IpHealth, Method, ServiceHealth};
        let server = DnsServer {
            name: name.into(),
            ipv4: vec!["1.1.1.1".into()],
            ipv6: vec![],
            doh: String::new(),
            ai_bypass: true,
            doh_only: false,
            note: String::new(),
        };
        let proxy = if proxy_ok { Ok(50) } else { Err("прокси не отвечает".to_string()) };
        let h = Health {
            method: Method::Udp,
            ips: vec![IpHealth { ip: "1.1.1.1".into(), result: dns_ms.ok_or_else(|| "нет ответа".to_string()) }],
            services: vec![ServiceHealth { name: "Gemini", dns_error: None, proxies: vec![(std::net::Ipv4Addr::LOCALHOST, proxy)] }],
        };
        (server, h)
    }

    #[test]
    fn choice_note_explains_without_nested_brackets() {
        let list = vec![fake("GeoHide EU", Some(200), false), fake("dns-ai", Some(30), true)];
        let note = choice_note("dns-ai", &list[1].1, &list);
        assert!(note.starts_with("Выбран «dns-ai»"));
        assert!(note.contains("«GeoHide EU» — Gemini не открывается: прокси не отвечает"));
        assert!(!note.contains("dns-ai» —"));
        let reason = fake("MagicDNS", None, true).1.problem().unwrap();
        assert_eq!(reason, "не отвечает: нет ответа");
        assert!(!reason.contains('('));
    }

    #[test]
    fn best_prefers_quality_then_list_order() {
        let list = vec![
            fake("slow", Some(5000), true),
            fake("broken", Some(40), false),
            fake("good-a", Some(60), true),
            fake("good-b", Some(30), true),
        ];
        assert_eq!(best(&list, Grade::Dead).unwrap().0.name, "good-a");
        assert!(best(&list[..2], Grade::Slow).is_none());
        assert_eq!(best(&list[..2], Grade::ServiceDown).unwrap().0.name, "slow");
    }
}
