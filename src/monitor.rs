//! Защита от сбоев: периодически проверяет активный DNS-сервер и при отказе
//! переключает подключения на следующий рабочий сервер, а потом возвращает
//! выбранный пользователем, когда тот оживёт.
//!
//! Следит ровно один процесс: окно программы или фоновое задание
//! (`dns-switcher.exe --watch`). Кто первым занял именованный мьютекс, тот и следит,
//! второй ждёт и подхватит слежение, если первый завершится.

use crate::apply::{self, Action};
use crate::config::{Config, DnsServer, LastResort};
use crate::health;
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
        if health.alive() {
            if self.fail_streak > 0 {
                state::log(&format!("«{}» снова отвечает.", active.name));
            }
            self.fail_streak = 0;
            self.offline_logged = false;
            if cfg.failover.return_to_preferred && st.active != st.preferred {
                self.try_return(cfg, &mut st, &adapters);
            }
            return;
        }

        if !health::internet_ok() {
            if !self.offline_logged {
                state::log("Нет доступа в интернет. DNS не переключаю, жду, когда связь вернётся.");
                self.offline_logged = true;
            }
            return;
        }
        self.offline_logged = false;
        self.fail_streak += 1;
        let reason = health.first_error().unwrap_or("нет ответа").to_string();
        if self.fail_streak < FAILS_TO_SWITCH {
            state::log(&format!(
                "«{}» не отвечает ({reason}). Перепроверю через {} с.",
                active.name, cfg.failover.interval_secs
            ));
            return;
        }

        self.fail_streak = 0;
        self.return_streak = 0;
        for candidate in candidates(cfg, &active) {
            let h = health::check(candidate, cfg.use_doh);
            if !h.alive() {
                continue;
            }
            if switch_to(cfg, &mut st, &adapters, &health::prefer_working(candidate, &h)) {
                state::log(&format!(
                    "Переключено: «{}» не отвечает ({reason}), теперь работает «{}».",
                    active.name, candidate.name
                ));
                return;
            }
        }
        go_dhcp(&mut st, &adapters, &format!("«{}» и все резервные серверы не отвечают", active.name));
    }

    /// Вернуться к выбранному вручную серверу, если он стабильно отвечает.
    fn try_return(&mut self, cfg: &Config, st: &mut RuntimeState, adapters: &[Adapter]) {
        let Some(preferred) = st.preferred.as_ref().and_then(|n| cfg.find(n)).cloned() else { return };
        let h = health::check(&preferred, cfg.use_doh);
        if h.alive() {
            self.return_streak += 1;
        } else {
            self.return_streak = 0;
        }
        if self.return_streak >= OKS_TO_RETURN && switch_to(cfg, st, adapters, &health::prefer_working(&preferred, &h)) {
            self.return_streak = 0;
            state::log(&format!("«{}» снова работает, вернул его.", preferred.name));
        }
    }

    /// Сейчас стоит DNS от роутера. Как только любой подходящий сервер ответит, ставим его.
    fn leave_dhcp(&mut self, cfg: &Config, st: &mut RuntimeState, adapters: &[Adapter]) {
        let Some(preferred) = st.preferred.as_ref().and_then(|n| cfg.find(n)).cloned() else { return };
        let mut order = vec![&preferred];
        order.extend(candidates(cfg, &preferred));
        for s in order {
            let h = health::check(s, cfg.use_doh);
            if h.alive() && switch_to(cfg, st, adapters, &health::prefer_working(s, &h)) {
                state::log(&format!("«{}» отвечает, переключил на него с DNS от роутера.", s.name));
                return;
            }
        }
    }
}

/// Резервные серверы по порядку: сначала остальные из той же группы (в порядке списка,
/// начиная со следующего), потом обычные DNS, если так разрешено настройками.
fn candidates<'a>(cfg: &'a Config, current: &DnsServer) -> Vec<&'a DnsServer> {
    let usable = |s: &&DnsServer| s.name != current.name && (!s.doh_only || cfg.use_doh);
    let pos = cfg.servers.iter().position(|s| s.name == current.name).unwrap_or(0);
    let rotated = cfg.servers[pos + 1..].iter().chain(cfg.servers[..pos].iter());
    let mut out: Vec<&DnsServer> = rotated.clone().filter(|s| s.ai_bypass == current.ai_bypass).filter(usable).collect();
    if current.ai_bypass && cfg.failover.last_resort == LastResort::Regular {
        out.extend(cfg.servers.iter().filter(|s| !s.ai_bypass).filter(usable));
    }
    out
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

    fn names(list: Vec<&DnsServer>) -> Vec<String> {
        list.into_iter().map(|s| s.name.clone()).collect()
    }

    #[test]
    fn candidates_follow_list_order_then_regular() {
        let cfg = Config::default();
        let comss = cfg.find("Comss DNS").unwrap();
        assert_eq!(
            names(candidates(&cfg, comss)),
            ["Xbox-DNS", "dns-ai", "MagicDNS", "GeoHide DNS", "AdGuard DNS", "Google Public DNS", "Cloudflare"]
        );
    }

    #[test]
    fn candidates_skip_doh_only_without_doh_and_respect_dhcp_choice() {
        let mut cfg = Config::default();
        cfg.use_doh = false;
        cfg.failover.last_resort = LastResort::Dhcp;
        let geo = cfg.find("GeoHide DNS").unwrap();
        assert_eq!(names(candidates(&cfg, geo)), ["Comss DNS", "Xbox-DNS", "MagicDNS"]);
    }

    #[test]
    fn regular_server_falls_back_only_to_regular() {
        let cfg = Config::default();
        let google = cfg.find("Google Public DNS").unwrap();
        assert_eq!(names(candidates(&cfg, google)), ["Cloudflare", "AdGuard DNS"]);
    }
}
