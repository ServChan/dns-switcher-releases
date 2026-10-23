//! Защита от сбоев: периодически проверяет активный DNS-сервер и при отказе
//! переключает подключения на следующий рабочий сервер, а потом возвращает
//! выбранный пользователем, когда тот оживёт.
//!
//! Следит ровно один процесс: окно программы или фоновое задание
//! (`dns-switcher.exe --watch`). Кто первым занял именованный мьютекс, тот и следит,
//! второй ждёт и подхватит слежение, если первый завершится.

use crate::apply::{self, Action};
use crate::config::{Config, DnsServer, LastResort};
use crate::health::{self, Depth, Grade, Health};
use crate::net::{self, Adapter};
use crate::state::{self, RuntimeState, Snapshot};
use crate::{browsers, tasks, tray, update};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;
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
/// Сколько проверок подряд выбранный сервер должен работать, чтобы к нему вернуться.
/// Если он снова сломался вскоре после возврата, порог удваивается (до MAX_RETURN).
const OKS_TO_RETURN: u32 = 3;
const MAX_RETURN: u32 = 30;
/// Сбой в течение этого времени после возврата считается «снова сбоит».
const FLAP_WINDOW: Duration = Duration::from_secs(30 * 60);
/// Столько стабильной работы после возврата сбрасывает порог к обычному.
const CALM_AFTER: Duration = Duration::from_secs(2 * 3600);
/// Как часто проверять все серверы для истории надёжности.
const SWEEP_EVERY: Duration = Duration::from_secs(300);
/// Сколько последних оценок хранить на сервер.
const HISTORY_LEN: usize = 6;
/// Как часто смотреть настройки браузеров.
const BROWSERS_EVERY: Duration = Duration::from_secs(600);

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
            tray::start("Переключатель DNS: защита от сбоев");
            let mut watcher = Watcher::default();
            while !stop.load(Ordering::Relaxed) {
                let cfg = Config::load();
                if cfg.failover.enabled {
                    watcher.tick(&cfg);
                } else {
                    watcher.reset();
                    tray::set_tip("Переключатель DNS: защита выключена");
                }
                sleep_checked(&stop, Duration::from_secs(cfg.failover.interval_secs.max(10)));
            }
            tray::stop();
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
        // «Проверить сейчас» в меню значка прерывает ожидание.
        if tray::CHECK_NOW.swap(false, Ordering::Relaxed) {
            return;
        }
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
    /// Сколько проверок подряд Windows получает ответы не от выбранного сервера.
    e2e_fail: u32,
    mem: Memory,
}

/// То, что переживает смену сервера: история и уже показанные предупреждения.
#[derive(Default)]
struct Memory {
    history: HashMap<String, VecDeque<Grade>>,
    last_sweep: Option<Instant>,
    last_browsers: Option<Instant>,
    /// Какие браузеры со своим DNS уже показаны в уведомлении.
    browsers_told: String,
    ipv6_told: bool,
    snapshot: Snapshot,
    /// Когда защита последний раз вернулась к выбранному серверу.
    returned_at: Option<Instant>,
    /// Сколько удачных проверок подряд нужно для возврата (растёт, если сервер сбоит).
    return_needed: u32,
}

impl Watcher {
    fn reset(&mut self) {
        let mem = std::mem::take(&mut self.mem);
        *self = Watcher { mem, ..Watcher::default() };
    }

    fn remember(&mut self, name: &str, grade: Grade) {
        let h = self.mem.history.entry(name.to_string()).or_default();
        h.push_back(grade);
        while h.len() > HISTORY_LEN {
            h.pop_front();
        }
        self.mem.snapshot.history.insert(name.to_string(), h.iter().map(|g| g.code()).collect());
    }

    /// Средняя оценка за последние проверки (в десятых), для выбора резерва.
    fn history_rank(&self, name: &str) -> u32 {
        match self.mem.history.get(name).filter(|h| !h.is_empty()) {
            Some(h) => h.iter().map(|g| g.code() as u32 * 10).sum::<u32>() / h.len() as u32,
            None => 20,
        }
    }

    /// Раз в несколько минут проверяет все серверы для ИИ: так у резерва есть история.
    fn sweep(&mut self, cfg: &Config) {
        if self.mem.last_sweep.is_some_and(|t| t.elapsed() < SWEEP_EVERY) {
            return;
        }
        self.mem.last_sweep = Some(Instant::now());
        let ai: Vec<DnsServer> = cfg.servers.iter().filter(|s| s.ai_bypass).cloned().collect();
        for (s, h) in check_all(cfg, &ai) {
            self.remember(&s.name, h.grade());
        }
        self.mem.snapshot.save();
    }

    /// Браузеры со своим DNS: предупреждаем один раз, пока набор не изменится.
    fn check_browsers(&mut self, cfg: &Config) {
        if self.mem.last_browsers.is_some_and(|t| t.elapsed() < BROWSERS_EVERY) {
            return;
        }
        self.mem.last_browsers = Some(Instant::now());
        let own: Vec<String> = browsers::detect()
            .into_iter()
            .filter(|b| b.bypasses_windows())
            .map(|b| b.name.to_string())
            .collect();
        let told = own.join(", ");
        if told != self.mem.browsers_told {
            if !own.is_empty() {
                state::log(&format!(
                    "{} пользуется своим защищённым DNS в обход Windows: обход ограничений там не действует.",
                    told
                ));
                if cfg.notify.problems {
                    tray::notify(
                        "Браузер обходит DNS Windows",
                        &format!("{told}: обход ограничений там не работает. Откройте программу, чтобы исправить."),
                        true,
                    );
                }
            }
            self.mem.browsers_told = told;
        }
    }

    /// Раз в день: подписанный список серверов и новая версия программы.
    fn check_updates(&mut self, cfg: &Config) {
        if !update::configured() {
            return;
        }
        let mut us = update::UpdateState::load();
        let now = update::now_secs();
        if cfg.updates.server_list && now.saturating_sub(us.last_list_check) >= update::CHECK_EVERY_SECS {
            us.last_list_check = now;
            match update::fetch_server_list() {
                Ok(list) => {
                    let st = RuntimeState::load();
                    let keep: Vec<String> = [st.preferred, st.active].into_iter().flatten().collect();
                    let mut fresh = Config::load();
                    let changes = fresh.apply_server_list(&list, &keep);
                    if fresh.remote_list_version != cfg.remote_list_version {
                        let _ = fresh.save();
                    }
                    if !changes.is_empty() {
                        state::log(&format!("Список серверов обновлён до версии {}: {}.", list.version, changes.join(", ")));
                    }
                }
                Err(e) => state::log(&format!("Список серверов не обновлён: {e}.")),
            }
        }
        if cfg.updates.app && now.saturating_sub(us.last_app_check) >= update::CHECK_EVERY_SECS {
            us.last_app_check = now;
            match update::check_app() {
                Ok(Some(m)) => {
                    if us.notified_version != m.version {
                        state::log(&format!("Доступна новая версия {}.", m.version));
                        tray::notify(
                            &format!("Доступна версия {}", m.version),
                            "Откройте Переключатель DNS и нажмите «Обновить».",
                            false,
                        );
                        us.notified_version = m.version.clone();
                    }
                    us.available = Some(m);
                }
                Ok(None) => us.available = None,
                Err(e) => state::log(&format!("Проверка обновлений не удалась: {e}.")),
            }
        }
        us.save();
    }

    /// Защита ушла с выбранного сервера. Если это случилось вскоре после возврата
    /// к нему, сервер сбоит: в следующий раз возвращаемся только после более долгой
    /// стабильной работы, чтобы не прыгать туда-обратно.
    fn note_left_preferred(&mut self, left: &str, st: &RuntimeState) {
        if st.preferred.as_deref() != Some(left) {
            return;
        }
        let flapping = self.mem.returned_at.is_some_and(|t| t.elapsed() < FLAP_WINDOW);
        self.mem.return_needed = if flapping {
            (self.mem.return_needed.max(OKS_TO_RETURN) * 2).min(MAX_RETURN)
        } else {
            OKS_TO_RETURN
        };
        if flapping {
            state::log(&format!(
                "«{left}» снова сбоит вскоре после возврата. Верну его, только когда он проработает без сбоев {} проверок подряд.",
                self.mem.return_needed
            ));
        }
    }

    fn tick(&mut self, cfg: &Config) {
        self.check_browsers(cfg);
        self.check_updates(cfg);
        self.sweep(cfg);
        let mut st = RuntimeState::load();
        if st.preferred.is_none() {
            self.reset();
            tray::set_tip("Переключатель DNS: сервер не выбран");
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
            self.reset();
            return;
        }

        let health = health::check(&active, cfg.use_doh, &cfg.probes, Depth::Quick);
        let mut grade = health.grade();
        // Причина, когда сбой нашла сквозная проверка, а не проверка самого сервера.
        let mut forced_reason: Option<String> = None;
        self.remember(&active.name, grade);

        // IPv6: сервер отдаёт настоящий адрес, а у подключения есть IPv6 — обход течёт.
        let leak: Vec<&str> = health.services.iter().filter(|s| s.ipv6_leak).map(|s| s.name.as_str()).collect();
        if !leak.is_empty() && up.iter().any(|a| a.has_ipv6) {
            if !self.mem.ipv6_told {
                state::log(&format!(
                    "«{}» отдаёт настоящий IPv6-адрес для {}, а у подключения есть IPv6: эти сервисы могут открываться мимо прокси.",
                    active.name,
                    leak.join(", ")
                ));
                if cfg.notify.problems {
                    tray::notify("Возможна утечка через IPv6", &format!("{} могут открываться мимо прокси.", leak.join(", ")), true);
                }
                self.mem.ipv6_told = true;
            }
        } else {
            self.mem.ipv6_told = false;
        }

        if grade.acceptable() {
            // Сквозная проверка: доходят ли ответы этого сервера до Windows.
            if let Some(e2e) = health::end_to_end(&active, &health) {
                self.mem.snapshot.e2e_ok = e2e.via_server;
                self.mem.snapshot.e2e_detail = match &e2e.system {
                    Ok(ips) => format!(
                        "{} через Windows: {}",
                        e2e.domain,
                        ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ")
                    ),
                    Err(e) => format!("{}: {e}", e2e.domain),
                };
                if e2e.ok() {
                    self.e2e_fail = 0;
                } else {
                    self.e2e_fail += 1;
                    let why = if e2e.real == Some(true) {
                        "Windows получает настоящие адреса: похоже, ушла на страховочные Cloudflare и Google"
                    } else {
                        "Windows получает ответы не от этого сервера"
                    };
                    if self.e2e_fail == 1 {
                        state::log(&format!("«{}» — {why}. Применяю его заново.", active.name));
                        switch_to(cfg, &mut st, &adapters, &health::prefer_working(&active, &health));
                    } else {
                        state::log(&format!("«{}» — {why}, повторное применение не помогло.", active.name));
                        grade = Grade::Slow;
                        forced_reason = Some(why.to_string());
                    }
                }
            }
            self.mem.snapshot.save();
        }

        if grade.acceptable() {
            if self.fail_streak > 0 {
                state::log(&format!("«{}» снова работает нормально.", active.name));
            }
            // Долго без сбоев после возврата: порог возврата снова обычный.
            if st.active == st.preferred && self.mem.returned_at.is_some_and(|t| t.elapsed() > CALM_AFTER) {
                self.mem.return_needed = OKS_TO_RETURN;
                self.mem.returned_at = None;
            }
            self.fail_streak = 0;
            self.offline_logged = false;
            self.stuck_logged = false;
            tray::set_tip(&format!("Переключатель DNS: «{}», всё работает", active.name));
            if cfg.failover.return_to_preferred && st.active != st.preferred {
                self.try_return(cfg, &mut st, &adapters);
            }
            return;
        }
        tray::set_tip(&format!("Переключатель DNS: «{}» работает плохо, проверяю", active.name));

        if grade == Grade::Dead && !health::internet_ok() {
            if !self.offline_logged {
                state::log("Нет доступа в интернет. DNS не переключаю, жду, когда связь вернётся.");
                self.offline_logged = true;
            }
            return;
        }
        self.offline_logged = false;
        self.fail_streak += 1;
        let reason = match &forced_reason {
            Some(r) => r.clone(),
            None => health.problem().unwrap_or_default(),
        };
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
        for (s, h) in &checked {
            self.remember(&s.name, h.grade());
        }
        if let Some((s, h)) = best(&checked, grade, |n| self.history_rank(n)) {
            if switch_to(cfg, &mut st, &adapters, &health::prefer_working(&s, &h)) {
                self.note_left_preferred(&active.name, &st);
                state::log(&format!("Переключено с «{}» на «{}». Причина: «{}» — {reason}.", active.name, s.name, active.name));
                state::log(&choice_note(&s.name, &h, &checked));
                if cfg.notify.switches {
                    tray::notify(
                        &format!("Переключено на «{}»", s.name),
                        &format!("«{}» — {reason}.", active.name),
                        false,
                    );
                }
                self.mem.snapshot.save();
                self.reset();
                return;
            }
        }
        if grade == Grade::Dead {
            let checked_fallback = check_all(cfg, &fallback);
            if let Some((s, h)) = best(&checked_fallback, Grade::Dead, |n| self.history_rank(n)) {
                if switch_to(cfg, &mut st, &adapters, &health::prefer_working(&s, &h)) {
                    if cfg.notify.switches {
                        tray::notify(
                            &format!("Переключено на обычный DNS «{}»", s.name),
                            "Серверы для ИИ не отвечают. Интернет работает, ИИ-сервисы могут не открываться.",
                            true,
                        );
                    }
                    state::log(&format!(
                        "Переключено с «{}» на обычный DNS «{}»: серверы для ИИ не подошли. \
                         Интернет работает, ИИ-сервисы могут не открываться.",
                        active.name, s.name
                    ));
                    state::log(&format!("Серверы для ИИ: {}.", candidates_note(&checked, None)));
                    self.reset();
                    return;
                }
            }
            go_dhcp(&mut st, &adapters, &format!("«{}» и все резервные серверы не отвечают", active.name));
            if cfg.notify.switches {
                tray::notify(
                    "Включён DNS от роутера",
                    "Ни один сервер не отвечает. Интернет работает, ИИ-сервисы не откроются, пока сервер не вернётся.",
                    true,
                );
            }
            self.reset();
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
        let h = health::check(&preferred, cfg.use_doh, &cfg.probes, Depth::Quick);
        if h.grade().acceptable() {
            self.return_streak += 1;
        } else {
            self.return_streak = 0;
        }
        let needed = self.mem.return_needed.max(OKS_TO_RETURN);
        if self.return_streak >= needed && switch_to(cfg, st, adapters, &health::prefer_working(&preferred, &h)) {
            self.return_streak = 0;
            self.mem.returned_at = Some(Instant::now());
            state::log(&format!("«{}» снова работает, вернул его.", preferred.name));
            if cfg.notify.switches {
                tray::notify(&format!("Снова «{}»", preferred.name), "Выбранный вами сервер снова работает.", false);
            }
        }
    }

    /// Сейчас стоит DNS от роутера. Как только подходящий сервер ответит, ставим лучший.
    fn leave_dhcp(&mut self, cfg: &Config, st: &mut RuntimeState, adapters: &[Adapter]) {
        let Some(preferred) = st.preferred.as_ref().and_then(|n| cfg.find(n)).cloned() else { return };
        let (same, fallback) = candidates(cfg, &preferred);
        let mut first = vec![preferred.clone()];
        first.extend(same);
        let mut checked = check_all(cfg, &first);
        let mut found = best(&checked, Grade::Dead, |n| self.history_rank(n));
        if found.is_none() {
            checked = check_all(cfg, &fallback);
            found = best(&checked, Grade::Dead, |n| self.history_rank(n));
        }
        if let Some((s, h)) = found {
            if switch_to(cfg, st, adapters, &health::prefer_working(&s, &h)) {
                state::log(&format!("«{}» отвечает, переключил на него с DNS от роутера.", s.name));
                state::log(&choice_note(&s.name, &h, &checked));
                if cfg.notify.switches {
                    tray::notify(&format!("Снова работает «{}»", s.name), "DNS от роутера больше не нужен.", false);
                }
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
pub(crate) fn candidates_note(checked: &[(DnsServer, Health)], skip: Option<&str>) -> String {
    checked
        .iter()
        .filter(|(s, _)| Some(s.name.as_str()) != skip)
        .map(|(s, h)| format!("«{}» — {}", s.name, h.summary()))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Проверяет серверы параллельно, порядок списка сохраняется.
/// Проверяет серверы по очереди, порядок списка сохраняется. По очереди, а не все
/// сразу: всплеск соединений сеть портит, и сравнение выходит нечестным.
pub(crate) fn check_all(cfg: &Config, servers: &[DnsServer]) -> Vec<(DnsServer, Health)> {
    servers
        .iter()
        .map(|s| (s.clone(), health::check(s, cfg.use_doh, &cfg.probes, Depth::Quick)))
        .collect()
}

/// Лучший сервер с оценкой строже `than`. При равной оценке выигрывает более
/// надёжный по истории (`rank`, меньше — лучше), затем стоящий выше в списке.
pub(crate) fn best(checked: &[(DnsServer, Health)], than: Grade, rank: impl Fn(&str) -> u32) -> Option<(DnsServer, Health)> {
    checked
        .iter()
        .enumerate()
        .filter(|(_, (_, h))| h.grade() < than)
        .min_by_key(|(i, (s, h))| (h.grade(), rank(&s.name), *i))
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
            builtin: false,
            edited: false,
        };
        let proxy = if proxy_ok { Ok(50) } else { Err("прокси не отвечает".to_string()) };
        let h = Health {
            method: Method::Udp,
            ips: vec![IpHealth { ip: "1.1.1.1".into(), result: dns_ms.ok_or_else(|| "нет ответа".to_string()) }],
            services: vec![ServiceHealth {
                name: "Gemini".into(),
                domain: "gemini.google.com".into(),
                proxied: Some(true),
                ipv6_leak: false,
                dns_error: None,
                proxies: vec![(std::net::Ipv4Addr::LOCALHOST, proxy)],
            }],
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
    fn return_threshold_grows_when_server_keeps_failing() {
        let st = RuntimeState { preferred: Some("A".into()), active: Some("A".into()), ..Default::default() };
        let mut w = Watcher::default();
        w.note_left_preferred("A", &st);
        assert_eq!(w.mem.return_needed, OKS_TO_RETURN, "первый сбой: обычный порог");
        // Вернулись и почти сразу снова ушли: порог растёт до предела.
        for expected in [6, 12, 24, MAX_RETURN, MAX_RETURN] {
            w.mem.returned_at = Some(Instant::now());
            w.note_left_preferred("A", &st);
            assert_eq!(w.mem.return_needed, expected);
        }
        // Уход с резервного сервера порог не трогает.
        w.note_left_preferred("B", &st);
        assert_eq!(w.mem.return_needed, MAX_RETURN);
    }

    #[test]
    fn best_prefers_quality_then_list_order() {
        let list = vec![
            fake("slow", Some(5000), true),
            fake("broken", Some(40), false),
            fake("good-a", Some(60), true),
            fake("good-b", Some(30), true),
        ];
        let flat = |_: &str| 0;
        assert_eq!(best(&list, Grade::Dead, flat).unwrap().0.name, "good-a");
        assert!(best(&list[..2], Grade::Slow, flat).is_none());
        assert_eq!(best(&list[..2], Grade::ServiceDown, flat).unwrap().0.name, "slow");
        // При равной оценке выигрывает более надёжный по истории.
        let history = |n: &str| if n == "good-b" { 0 } else { 15 };
        assert_eq!(best(&list, Grade::Dead, history).unwrap().0.name, "good-b");
    }
}
