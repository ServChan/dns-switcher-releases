mod diagram;
mod settings;
mod simple;

use crate::apply::{self, Action, Outcome};
use crate::browsers;
use crate::config::{Config, DnsServer, Failover, LastResort, ThemeChoice, UiMode, default_servers, parse_ip_list};
use crate::health::{self, EndToEnd, Grade, Health, Method};
use crate::install;
use crate::monitor;
use crate::net::{self, Adapter};
use crate::state::{self, RuntimeState};
use crate::update;
use std::path::PathBuf;
use crate::theme::{self, Palette, palette, semibold};
use eframe::egui::{
    self, Align, Color32, CornerRadius, Frame, Id, Key, Layout, Margin, Modal, Rect, Response,
    RichText, Role, Sense, Stroke, StrokeKind, TextStyle, UiBuilder, Vec2, WidgetInfo, pos2,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

const ROW_HEIGHT: f32 = 44.0;
const DETAILS_WIDTH: f32 = 350.0;
const GUTTER: i8 = 16;
/// Как часто окно перечитывает адаптеры, состояние и журнал.
const REFRESH_EVERY: Duration = Duration::from_secs(3);
/// Как часто окно само перепроверяет все серверы.
const SWEEP_EVERY: Duration = Duration::from_secs(120);
const INTERVALS: [(u64, &str); 4] = [(15, "15 с"), (30, "30 с"), (60, "1 мин"), (120, "2 мин")];

enum Done {
    Applied(String),
    Reset,
}

enum Msg {
    Done { done: Done, outcomes: Vec<Outcome> },
    Health { name: String, health: Health },
    Task(Result<bool, String>),
    Browsers(Vec<browsers::BrowserDns>),
    BrowserFixed(String, Result<(), String>),
    E2e(Option<EndToEnd>),
    AutoPicked(Vec<(DnsServer, Health)>),
    UpdateChecked(Result<Option<update::Manifest>, String>),
    UpdateDownloaded(Result<PathBuf, String>),
    ListUpdated(Result<(u32, Vec<String>), String>),
    Ipv6(String, bool, Result<(), String>),
}

/// Что показано в окне.
#[derive(Clone, Copy, PartialEq)]
enum View {
    Main,
    Settings(Section),
    Help,
}

#[derive(Clone, Copy, PartialEq)]
enum Section {
    Appearance,
    Protection,
    Checks,
    Notifications,
    Browsers,
    Updates,
    About,
}

#[derive(Clone)]
enum HealthView {
    Running,
    Done(Health),
}

#[derive(Clone, Copy, PartialEq)]
enum StatusKind {
    Success,
    Warning,
    Error,
}

struct Status {
    kind: StatusKind,
    text: String,
}

enum Confirm {
    Delete(usize),
    RestoreDefaults,
    Reset,
}

#[derive(Default)]
struct Editor {
    index: Option<usize>,
    name: String,
    ipv4: String,
    ipv6: String,
    doh: String,
    note: String,
    ai_bypass: bool,
    doh_only: bool,
    /// Редактируется стандартный сервер: после сохранения он помечается изменённым.
    builtin: bool,
    error: Option<String>,
}

impl Editor {
    fn new_server() -> Self {
        Self { ai_bypass: true, ..Default::default() }
    }

    fn from_server(index: usize, s: &DnsServer) -> Self {
        Self {
            index: Some(index),
            name: s.name.clone(),
            ipv4: s.ipv4.join(", "),
            ipv6: s.ipv6.join(", "),
            doh: s.doh.clone(),
            note: s.note.clone(),
            ai_bypass: s.ai_bypass,
            doh_only: s.doh_only,
            builtin: s.builtin,
            error: None,
        }
    }

    fn to_server(&self) -> DnsServer {
        DnsServer {
            name: self.name.trim().to_string(),
            ipv4: parse_ip_list(&self.ipv4),
            ipv6: parse_ip_list(&self.ipv6),
            doh: self.doh.trim().to_string(),
            ai_bypass: self.ai_bypass,
            doh_only: self.doh_only,
            note: self.note.trim().to_string(),
            builtin: self.builtin,
            edited: self.builtin,
        }
    }
}

enum DialogResult {
    Open,
    Accept,
    Cancel,
}

/// Действие из строки списка, выполняется после отрисовки списка.
enum RowAction {
    Apply(usize),
    Edit(usize),
    Delete(usize),
    Move(usize, bool),
}

pub struct DnsApp {
    config: Config,
    runtime: RuntimeState,
    log_tail: Vec<String>,
    adapters: Vec<Adapter>,
    adapter_error: Option<String>,
    chosen: HashSet<String>,
    show_inactive: bool,
    selected: Option<usize>,
    editor: Option<Editor>,
    confirm: Option<Confirm>,
    show_log: bool,
    view: View,
    browsers: Vec<browsers::BrowserDns>,
    last_browsers: Instant,
    e2e: Option<EndToEnd>,
    updates: update::UpdateState,
    update_busy: Option<String>,
    auto_picking: bool,
    new_probe: (String, String),
    /// Ход и итог исправления браузеров: показывается прямо в их плашке.
    browser_note: HashMap<String, (bool, String)>,
    /// Контекст окна: фоновые действия просят по нему перерисовку.
    ctx: egui::Context,
    /// Время файла настроек, которое окно уже видело.
    config_stamp: Option<std::time::SystemTime>,
    status: Option<Status>,
    busy: Option<String>,
    task_busy: bool,
    health: HashMap<String, HealthView>,
    last_refresh: Instant,
    last_sweep: Instant,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    is_admin: bool,
    _watch_stop: Arc<AtomicBool>,
}

impl DnsApp {
    pub fn new(ctx: &egui::Context) -> Self {
        theme::install(ctx);
        let (tx, rx) = channel();

        // Окно тоже следит за DNS, если фоновое задание не делает это само.
        let watch_stop = Arc::new(AtomicBool::new(false));
        if crate::elevate::is_admin() {
            let stop = watch_stop.clone();
            std::thread::spawn(move || monitor::run_loop(stop, true));
        }

        let runtime = RuntimeState::load();
        let mut app = Self {
            config: Config::load(),
            runtime,
            log_tail: state::read_log(200),
            adapters: Vec::new(),
            adapter_error: None,
            chosen: HashSet::new(),
            show_inactive: false,
            selected: None,
            editor: None,
            confirm: None,
            show_log: false,
            view: View::Main,
            browsers: Vec::new(),
            last_browsers: Instant::now(),
            e2e: None,
            updates: update::UpdateState::load(),
            update_busy: None,
            auto_picking: false,
            new_probe: Default::default(),
            browser_note: HashMap::new(),
            config_stamp: crate::config::config_stamp(),
            ctx: ctx.clone(),
            status: None,
            busy: None,
            task_busy: false,
            health: HashMap::new(),
            last_refresh: Instant::now(),
            last_sweep: Instant::now(),
            tx,
            rx,
            is_admin: crate::elevate::is_admin(),
            _watch_stop: watch_stop,
        };
        app.refresh_adapters();
        // Выбраны подключения из прошлого «Применить», иначе все подключённые к интернету.
        let remembered: HashSet<String> = app
            .runtime
            .adapters
            .iter()
            .filter(|g| app.adapters.iter().any(|a| &a.guid == *g))
            .cloned()
            .collect();
        app.chosen = if remembered.is_empty() {
            app.adapters.iter().filter(|a| a.up && a.has_gateway).map(|a| a.guid.clone()).collect()
        } else {
            remembered
        };
        app.selected = app
            .adapters
            .iter()
            .filter(|a| app.chosen.contains(&a.guid))
            .find_map(|a| app.server_in_use(a));
        settings::apply_theme(ctx, app.config.theme);
        app.start_sweep(ctx);
        app.start_browser_scan(ctx);
        // Свежая версия проверяется при открытии окна не чаще раза в день.
        if app.config.updates.app
            && update::configured()
            && update::now_secs().saturating_sub(app.updates.last_app_check) >= update::CHECK_EVERY_SECS
        {
            app.check_update(ctx);
        }
        #[cfg(debug_assertions)]
        app.debug_setup(ctx);
        app
    }

    /// Только для отладочной сборки: снимки экрана диалогов и светлой темы.
    #[cfg(debug_assertions)]
    fn debug_setup(&mut self, ctx: &egui::Context) {
        if std::env::var("DNS_SWITCHER_DEBUG_THEME").as_deref() == Ok("light") {
            ctx.set_theme(egui::Theme::Light);
        }
        match std::env::var("DNS_SWITCHER_DEBUG_MODE").as_deref() {
            Ok("simple") => self.config.ui_mode = UiMode::Simple,
            Ok("advanced") => self.config.ui_mode = UiMode::Advanced,
            _ => {}
        }
        if let Ok(name) = std::env::var("DNS_SWITCHER_DEBUG_SELECT") {
            self.selected = self.config.servers.iter().position(|s| s.name == name);
        }
        match std::env::var("DNS_SWITCHER_DEBUG_DIALOG").as_deref() {
            Ok("failover") => self.view = View::Settings(Section::Protection),
            Ok("settings") => self.view = View::Settings(Section::Appearance),
            Ok("browsers") => self.view = View::Settings(Section::Browsers),
            Ok("updates") => self.view = View::Settings(Section::Updates),
            Ok("checks") => self.view = View::Settings(Section::Checks),
            Ok("help") => self.view = View::Help,
            Ok("log") => self.show_log = true,
            Ok("editor") => self.editor = Some(Editor::new_server()),
            Ok("confirm") => self.confirm = Some(Confirm::Reset),
            _ => {}
        }
    }

    fn refresh_adapters(&mut self) {
        match net::list_adapters() {
            Ok(list) => {
                self.adapters = list;
                self.adapter_error = None;
            }
            Err(e) => self.adapter_error = Some(e),
        }
        let known: HashSet<_> = self.adapters.iter().map(|a| a.guid.clone()).collect();
        self.chosen.retain(|g| known.contains(g));
    }

    /// Периодически подхватывает изменения от защиты от сбоев.
    fn periodic(&mut self, ctx: &egui::Context) {
        if self.last_refresh.elapsed() >= REFRESH_EVERY {
            self.last_refresh = Instant::now();
            if self.busy.is_none() {
                self.refresh_adapters();
            }
            self.runtime = RuntimeState::load();
            self.log_tail = state::read_log(200);
            self.updates = update::UpdateState::load();
            self.reload_config_if_changed();
        }
        if self.last_browsers.elapsed() >= Duration::from_secs(30) {
            self.start_browser_scan(ctx);
        }
        if self.last_sweep.elapsed() >= SWEEP_EVERY {
            self.start_sweep(ctx);
        }
        ctx.request_repaint_after(REFRESH_EVERY);
    }

    /// Индекс сервера из списка, который сейчас стоит первым DNS на адаптере.
    fn server_in_use(&self, adapter: &Adapter) -> Option<usize> {
        let first = adapter.dns.first()?;
        self.config.servers.iter().position(|s| {
            s.all_ips().any(|ip| ip.parse::<IpAddr>().ok().as_ref() == Some(first))
        })
    }

    fn servers_in_use(&self) -> HashSet<usize> {
        self.adapters
            .iter()
            .filter(|a| self.chosen.contains(&a.guid))
            .filter_map(|a| self.server_in_use(a))
            .collect()
    }

    fn save_config(&mut self) {
        // Фоновая защита могла записать свежий список серверов: не затираем его.
        if crate::config::config_stamp() != self.config_stamp {
            let disk = Config::load();
            if disk.remote_list_version > self.config.remote_list_version {
                self.config.servers = disk.servers;
                self.config.remote_list_version = disk.remote_list_version;
            }
        }
        if let Err(e) = self.config.save() {
            self.set_status(StatusKind::Error, e);
        }
        self.config_stamp = crate::config::config_stamp();
    }

    /// Настройки изменил другой процесс: перечитываем, сохраняя выбранный сервер.
    fn reload_config_if_changed(&mut self) {
        let stamp = crate::config::config_stamp();
        if stamp == self.config_stamp || self.editor.is_some() {
            return;
        }
        let selected = self.selected.and_then(|i| self.config.servers.get(i)).map(|s| s.name.clone());
        self.config = Config::load();
        self.config_stamp = stamp;
        self.selected = selected.and_then(|n| self.config.servers.iter().position(|s| s.name == n));
    }

    fn set_status(&mut self, kind: StatusKind, text: impl Into<String>) {
        self.status = Some(Status { kind, text: text.into() });
    }

    fn chosen_adapters(&self) -> Vec<Adapter> {
        self.adapters.iter().filter(|a| self.chosen.contains(&a.guid)).cloned().collect()
    }

    fn chosen_names(&self) -> String {
        let names: Vec<String> = self.chosen_adapters().into_iter().map(|a| a.name).collect();
        names.join(", ")
    }

    /// Почему сейчас нельзя менять DNS, если нельзя.
    fn blocker(&self) -> Option<&'static str> {
        if !self.is_admin {
            Some("Нужны права администратора: нажмите «Перезапустить с правами администратора» вверху окна.")
        } else if self.chosen.is_empty() {
            Some("Отметьте сверху хотя бы одно подключение.")
        } else {
            None
        }
    }

    fn apply_server(&mut self, ctx: &egui::Context, index: usize) {
        if self.busy.is_some() || self.blocker().is_some() {
            return;
        }
        let Some(mut server) = self.config.servers.get(index).cloned() else { return };
        if let Some(HealthView::Done(h)) = self.health.get(&server.name) {
            server = health::prefer_working(&server, h);
        }
        self.selected = Some(index);
        let done = Done::Applied(server.name.clone());
        let action = Action::Apply {
            server,
            use_doh: self.config.use_doh,
            safety_net: self.config.failover.safety_net,
        };
        self.start_action(ctx, action, done);
    }

    fn start_action(&mut self, ctx: &egui::Context, action: Action, done: Done) {
        let adapters = self.chosen_adapters();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        self.busy = Some(match &done {
            Done::Applied(name) => format!("применяю «{name}»"),
            Done::Reset => "сбрасываю DNS".to_string(),
        });
        self.status = None;
        std::thread::spawn(move || {
            let outcomes = apply::run(&action, &adapters);
            let _ = tx.send(Msg::Done { done, outcomes });
            ctx.request_repaint();
        });
    }

    fn start_sweep(&mut self, ctx: &egui::Context) {
        self.last_sweep = Instant::now();
        let use_doh = self.config.use_doh;
        for server in self.config.servers.clone() {
            self.health.insert(server.name.clone(), HealthView::Running);
            let tx = self.tx.clone();
            let ctx = ctx.clone();
            let probes = self.config.probes.clone();
            std::thread::spawn(move || {
                let health = health::check(&server, use_doh, &probes);
                let _ = tx.send(Msg::Health { name: server.name, health });
                ctx.request_repaint();
            });
        }
    }

    fn set_background(&mut self, ctx: &egui::Context, enable: bool) {
        self.task_busy = true;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = if enable { monitor::install_task() } else { monitor::remove_task() };
            let _ = tx.send(Msg::Task(result.map(|_| enable)));
            ctx.request_repaint();
        });
    }

    fn poll_messages(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Health { name, health } => {
                    // Для сервера, который сейчас стоит, заодно сквозная проверка через Windows.
                    if self.active_server().is_some_and(|s| s.name == name) {
                        let server = self.active_server().unwrap();
                        let (tx, h) = (self.tx.clone(), health.clone());
                        std::thread::spawn(move || {
                            let _ = tx.send(Msg::E2e(health::end_to_end(&server, &h)));
                        });
                    }
                    self.health.insert(name, HealthView::Done(health));
                }
                Msg::E2e(e) => self.e2e = e,
                Msg::Browsers(list) => self.browsers = list,
                Msg::BrowserFixed(name, result) => match result {
                    Ok(()) => {
                        state::log(&format!("{name} переключён на DNS Windows."));
                        self.browser_note.insert(name.clone(), (true, "Исправлено: браузер пользуется DNS Windows.".into()));
                        self.set_status(StatusKind::Success, format!("{name} теперь пользуется DNS Windows: обход работает и в нём."));
                    }
                    Err(e) => {
                        self.browser_note.insert(name.clone(), (false, e.clone()));
                        self.set_status(StatusKind::Error, e);
                    }
                },
                Msg::AutoPicked(checked) => self.finish_auto_pick(checked),
                Msg::UpdateChecked(result) => {
                    self.update_busy = None;
                    let mut us = update::UpdateState::load();
                    us.last_app_check = update::now_secs();
                    match result {
                        Ok(found) => {
                            if found.is_none() {
                                self.set_status(StatusKind::Success, format!("Установлена последняя версия {}.", install::VERSION));
                            }
                            us.available = found;
                        }
                        Err(e) => self.set_status(StatusKind::Error, format!("Проверка обновлений не удалась: {e}.")),
                    }
                    us.save();
                    self.updates = us;
                }
                Msg::UpdateDownloaded(result) => {
                    self.update_busy = None;
                    match result.and_then(|path| update::run_update(&path)) {
                        // Установщик сам закроет эту копию и откроет новую.
                        Ok(()) => std::process::exit(0),
                        Err(e) => self.set_status(StatusKind::Error, format!("Обновление не удалось: {e}.")),
                    }
                }
                Msg::ListUpdated(result) => {
                    self.update_busy = None;
                    match result {
                        Ok((version, changes)) => {
                            self.config = Config::load();
                            let text = if changes.is_empty() {
                                format!("Список серверов актуален (версия {version}).")
                            } else {
                                format!("Список серверов обновлён до версии {version}: {}.", changes.join(", "))
                            };
                            self.set_status(StatusKind::Success, text);
                            self.start_sweep_quiet();
                        }
                        Err(e) => self.set_status(StatusKind::Error, format!("Список серверов не обновлён: {e}.")),
                    }
                }
                Msg::Ipv6(name, enabled, result) => match result {
                    Ok(()) => {
                        if enabled {
                            self.config.ipv6_disabled.retain(|n| n != &name);
                            state::log(&format!("IPv6 снова включён на подключении {name}."));
                        } else if !self.config.ipv6_disabled.contains(&name) {
                            self.config.ipv6_disabled.push(name.clone());
                            state::log(&format!("IPv6 выключен на подключении {name}, чтобы сервисы не открывались мимо прокси."));
                        }
                        self.save_config();
                        self.refresh_adapters();
                        self.set_status(
                            StatusKind::Success,
                            if enabled { format!("IPv6 снова включён на {name}.") } else { format!("IPv6 выключен на {name}.") },
                        );
                    }
                    Err(e) => self.set_status(StatusKind::Error, format!("Не удалось изменить IPv6 на {name}: {e}")),
                },
                Msg::Done { done, outcomes } => {
                    self.busy = None;
                    self.finish_action(done, outcomes);
                    self.refresh_adapters();
                }
                Msg::Task(result) => {
                    self.task_busy = false;
                    match result {
                        Ok(true) => {
                            state::log("Включена фоновая защита: задание в Планировщике запускается при входе в Windows.");
                            self.set_status(StatusKind::Success, "Фоновая защита включена. Она продолжит работать и после закрытия окна.");
                        }
                        Ok(false) => {
                            state::log("Фоновая защита выключена.");
                            self.set_status(StatusKind::Success, "Фоновая защита выключена. Пока окно открыто, следит оно.");
                        }
                        Err(e) => {
                            self.config.failover.background = monitor::task_installed();
                            self.save_config();
                            self.set_status(StatusKind::Error, e);
                        }
                    }
                }
            }
        }
    }

    fn finish_action(&mut self, done: Done, outcomes: Vec<Outcome>) {
        let names: Vec<&str> = outcomes.iter().map(|o| o.adapter.as_str()).collect();
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        for o in &outcomes {
            match &o.result {
                Ok(w) => warnings.extend(w.iter().map(|w| format!("{}: {w}", o.adapter))),
                Err(e) => errors.push(format!("{}: {e}", o.adapter)),
            }
        }
        let any_ok = outcomes.iter().any(|o| o.result.is_ok());
        if any_ok {
            // Запоминаем выбор: за ним следит защита от сбоев.
            let mut st = RuntimeState::load();
            match &done {
                Done::Applied(name) => {
                    st.preferred = Some(name.clone());
                    st.active = Some(name.clone());
                    st.adapters = self.chosen.iter().cloned().collect();
                    state::log(&format!("Вручную применён «{name}» для: {}.", names.join(", ")));
                }
                Done::Reset => {
                    st.preferred = None;
                    st.active = None;
                    state::log(&format!("DNS сброшен на автоматический для: {}.", names.join(", ")));
                }
            }
            st.on_dhcp_fallback = false;
            if let Err(e) = st.save() {
                warnings.push(e);
            }
            self.runtime = st;
        }

        let what = match &done {
            Done::Applied(name) => format!("«{name}» применён"),
            Done::Reset => "DNS сброшен на автоматический".to_string(),
        };
        if !errors.is_empty() {
            self.set_status(StatusKind::Error, errors.join("\n"));
        } else if !warnings.is_empty() {
            self.set_status(StatusKind::Warning, format!("{what}, но есть замечания.\n{}", warnings.join("\n")));
        } else {
            self.set_status(StatusKind::Success, format!("{what} для: {}. Кэш DNS очищен.", names.join(", ")));
        }
        self.log_tail = state::read_log(200);
    }

    fn move_server(&mut self, index: usize, down: bool) {
        let group = self.config.servers[index].ai_bypass;
        let same: Vec<usize> = (0..self.config.servers.len())
            .filter(|&i| self.config.servers[i].ai_bypass == group)
            .collect();
        let Some(pos) = same.iter().position(|&i| i == index) else { return };
        let other = if down { same.get(pos + 1) } else { pos.checked_sub(1).and_then(|p| same.get(p)) };
        if let Some(&other) = other {
            self.config.servers.swap(index, other);
            if self.selected == Some(index) {
                self.selected = Some(other);
            }
            self.save_config();
        }
    }

    // ---------- Подключения и защита ----------

    fn connection_card(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        card(p).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(section_title("Подключения"));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let blocker = self.blocker();
                    let reset = ui
                        .add_enabled(blocker.is_none() && self.busy.is_none(), egui::Button::new("Сбросить DNS"))
                        .on_hover_text("Вернуть автоматическое получение DNS от роутера или провайдера.")
                        .on_disabled_hover_text(blocker.unwrap_or("Дождитесь окончания текущей операции."));
                    if reset.clicked() {
                        self.confirm = Some(Confirm::Reset);
                    }
                    if ui.button("Обновить").on_hover_text("Перечитать подключения и их DNS.").clicked() {
                        self.refresh_adapters();
                    }
                });
            });
            ui.add_space(6.0);

            let hidden = self.adapters.iter().filter(|a| !a.up && !self.chosen.contains(&a.guid)).count();
            let visible: Vec<Adapter> = self
                .adapters
                .iter()
                .filter(|a| a.up || self.show_inactive || self.chosen.contains(&a.guid))
                .cloned()
                .collect();
            ui.horizontal_wrapped(|ui| {
                for a in &visible {
                    let on = self.chosen.contains(&a.guid);
                    let text = if a.up { a.name.clone() } else { format!("{} (отключено)", a.name) };
                    if chip(ui, p, on, &text).on_hover_text(&a.description).clicked() {
                        if on {
                            self.chosen.remove(&a.guid);
                        } else {
                            self.chosen.insert(a.guid.clone());
                        }
                    }
                }
                if hidden > 0 || self.show_inactive {
                    let text = if self.show_inactive {
                        "Скрыть отключённые".to_string()
                    } else {
                        format!("Показать отключённые ({hidden})")
                    };
                    if ui.link(RichText::new(text).color(p.accent_text)).clicked() {
                        self.show_inactive = !self.show_inactive;
                    }
                }
            });

            let chosen = self.chosen_adapters();
            ui.add_space(4.0);
            if chosen.is_empty() {
                ui.label(RichText::new("Отметьте подключение, к которому применять DNS.").color(p.text_weak));
            }
            for a in &chosen {
                self.adapter_line(ui, p, a);
            }

            ui.add_space(8.0);
            divider(ui, p);
            ui.add_space(8.0);
            self.protection_line(ui, p);

            if !self.is_admin {
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Нет прав администратора, поэтому DNS менять нельзя.").color(p.warn_text));
                    if ui.button("Перезапустить с правами администратора").clicked()
                        && crate::elevate::relaunch_as_admin(&["--wait-gui".to_string()]).is_ok()
                    {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            }
            if let Some(e) = &self.adapter_error {
                ui.label(RichText::new(format!("Не удалось прочитать подключения: {e}")).color(p.danger_text));
            }
        });
    }

    fn adapter_line(&self, ui: &mut egui::Ui, p: &Palette, a: &Adapter) {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.label(RichText::new(&a.name).family(semibold()));
            ui.label(RichText::new("—").color(p.text_weak));
            match self.server_in_use(a) {
                Some(i) => ui.label(RichText::new(&self.config.servers[i].name).color(p.accent_text)),
                None if !a.static_dns => ui.label("DNS от роутера"),
                None => ui.label("свой DNS"),
            };
            let mut rest = Vec::new();
            if !a.dns.is_empty() {
                let ips: Vec<String> = a.dns.iter().map(|ip| ip.to_string()).collect();
                rest.push(ips.join(", "));
            }
            rest.push(if a.static_dns { "задан вручную" } else { "автоматически (DHCP)" }.to_string());
            if a.dns.iter().any(|ip| a.doh_ips.contains(ip)) {
                rest.push("зашифрован (DoH)".to_string());
            }
            ui.label(RichText::new(format!("·  {}", rest.join("  ·  "))).color(p.text_weak));
        });
    }

    fn protection_line(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let f = &self.config.failover;
        let every = interval_text(f.interval_secs);
        let rt = &self.runtime;
        let (state_text, color) = if !f.enabled {
            ("выключена".to_string(), p.text_weak)
        } else if rt.on_dhcp_fallback {
            ("все серверы не отвечали, временно стоит DNS от роутера".to_string(), p.warn_text)
        } else if let (Some(active), Some(pref)) = (&rt.active, &rt.preferred) {
            if active != pref {
                (format!("«{pref}» не отвечал, сейчас работает резервный «{active}»"), p.warn_text)
            } else {
                (format!("следит за «{active}», проверка каждые {every}"), p.success_text)
            }
        } else {
            ("включится после «Применить»".to_string(), p.text_weak)
        };
        let mode = if !f.enabled {
            ""
        } else if f.background && monitor::background_watching() {
            "работает в фоне, даже когда окно закрыто"
        } else if f.background {
            "фоновое задание запускается…"
        } else {
            "работает, пока открыто окно"
        };

        ui.horizontal(|ui| {
            ui.label(RichText::new("Защита от сбоев").family(semibold()));
            ui.label(RichText::new(state_text).color(color));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Настроить").clicked() {
                    self.view = View::Settings(Section::Protection);
                }
                if ui.button("Журнал").clicked() {
                    self.log_tail = state::read_log(200);
                    self.show_log = true;
                }
            });
        });
        if let Some(last) = self.log_tail.last() {
            let line = if mode.is_empty() { last.clone() } else { format!("{mode}  ·  {last}") };
            ui.add(egui::Label::new(RichText::new(line).small().color(p.text_weak)).truncate());
        } else if !mode.is_empty() {
            ui.label(RichText::new(mode).small().color(p.text_weak));
        }
    }

    // ---------- Список серверов ----------

    fn servers_list(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        let ctx = ui.ctx().clone();
        let in_use = self.servers_in_use();
        let mut action = None;

        ui.horizontal(|ui| {
            ui.label(section_title("Серверы"));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Добавить сервер").clicked() {
                    self.editor = Some(Editor::new_server());
                }
                let checking = self.health.values().any(|h| matches!(h, HealthView::Running));
                let text = if checking { "Проверяю…" } else { "Проверить все" };
                if ui
                    .button(text)
                    .on_hover_text("Проверить каждый адрес каждого сервера и показать время ответа.")
                    .clicked()
                    && !checking
                {
                    self.start_sweep(&ctx);
                }
            });
        });
        ui.add_space(8.0);

        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            for (ai, title, hint) in [
                (
                    true,
                    "Для обхода региональных ограничений ИИ",
                    "ChatGPT, Gemini, Claude и другие сервисы, закрытые для России",
                ),
                (false, "Обычные DNS", "Публичные серверы без обхода ограничений, резерв на крайний случай"),
            ] {
                let indices: Vec<usize> = (0..self.config.servers.len())
                    .filter(|&i| self.config.servers[i].ai_bypass == ai)
                    .collect();
                ui.horizontal(|ui| {
                    ui.label(RichText::new(title).family(semibold()));
                    ui.label(RichText::new(indices.len().to_string()).color(p.text_weak));
                });
                ui.label(RichText::new(hint).small().color(p.text_weak));
                ui.add_space(6.0);

                if indices.is_empty() {
                    let text = if ai {
                        "Пока пусто. Добавьте сервер и отметьте «Для обхода региональных ограничений ИИ»."
                    } else {
                        "Пока пусто. Нажмите «Добавить сервер», чтобы добавить свой DNS."
                    };
                    card(p).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new(text).color(p.text_weak));
                    });
                } else {
                    card(p).inner_margin(Margin::same(4)).show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        for i in indices {
                            if let Some(a) = self.server_row(ui, p, i, in_use.contains(&i)) {
                                action = Some(a);
                            }
                        }
                    });
                }
                ui.add_space(16.0);
            }

            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Порядок в списке задаёт очередь резервных серверов.").small().color(p.text_weak),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.link(RichText::new("Восстановить стандартный список").small().color(p.accent_text)).clicked() {
                        self.confirm = Some(Confirm::RestoreDefaults);
                    }
                });
            });
            ui.add_space(4.0);
        });

        // Стрелки вверх и вниз переключают выбранный сервер.
        if self.editor.is_none()
            && self.confirm.is_none()
            && self.view == View::Main
            && !self.show_log
            && !ctx.egui_wants_keyboard_input()
        {
            let (up, down) = ctx.input(|i| (i.key_pressed(Key::ArrowUp), i.key_pressed(Key::ArrowDown)));
            if up || down {
                self.move_selection(down);
            }
        }

        match action {
            Some(RowAction::Apply(i)) => self.apply_server(&ctx, i),
            Some(RowAction::Edit(i)) => self.editor = Some(Editor::from_server(i, &self.config.servers[i])),
            Some(RowAction::Delete(i)) => self.confirm = Some(Confirm::Delete(i)),
            Some(RowAction::Move(i, down)) => self.move_server(i, down),
            None => {}
        }
    }

    /// Порядок на экране: сначала серверы для ИИ, затем обычные.
    fn display_order(&self) -> Vec<usize> {
        let s = &self.config.servers;
        (0..s.len()).filter(|&i| s[i].ai_bypass).chain((0..s.len()).filter(|&i| !s[i].ai_bypass)).collect()
    }

    fn move_selection(&mut self, down: bool) {
        let order = self.display_order();
        if order.is_empty() {
            return;
        }
        let pos = self.selected.and_then(|s| order.iter().position(|&i| i == s));
        let next = match (pos, down) {
            (None, _) => 0,
            (Some(p), true) => (p + 1).min(order.len() - 1),
            (Some(p), false) => p.saturating_sub(1),
        };
        self.selected = Some(order[next]);
    }

    fn server_row(&mut self, ui: &mut egui::Ui, p: &Palette, index: usize, in_use: bool) -> Option<RowAction> {
        let server = &self.config.servers[index];
        let selected = self.selected == Some(index);
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), ROW_HEIGHT), Sense::click());
        resp.widget_info(|| WidgetInfo::selected(Role::RadioButton, true, selected, &server.name));

        let painter = ui.painter();
        let fill = if selected {
            p.surface_selected
        } else if resp.hovered() {
            p.surface_hover
        } else {
            Color32::TRANSPARENT
        };
        painter.rect_filled(rect, CornerRadius::same(5), fill);
        if selected {
            let bar = Rect::from_min_size(rect.left_top() + Vec2::new(0.0, 12.0), Vec2::new(3.0, rect.height() - 24.0));
            painter.rect_filled(bar, CornerRadius::same(2), p.accent);
        }
        if resp.has_focus() {
            painter.rect_stroke(rect, CornerRadius::same(5), Stroke::new(2.0, p.accent), StrokeKind::Inside);
        }

        let mut action = None;
        if resp.clicked() {
            self.selected = Some(index);
        }
        if resp.double_clicked() {
            action = Some(RowAction::Apply(index));
        }
        resp.on_hover_text("Двойной щелчок применяет сервер, правый щелчок открывает меню.")
            .context_menu(|ui| {
                if ui.button("Применить").clicked() {
                    action = Some(RowAction::Apply(index));
                }
                if ui.button("Выше в очереди").clicked() {
                    action = Some(RowAction::Move(index, false));
                }
                if ui.button("Ниже в очереди").clicked() {
                    action = Some(RowAction::Move(index, true));
                }
                if ui.button("Изменить").clicked() {
                    action = Some(RowAction::Edit(index));
                }
                if ui.button("Удалить").clicked() {
                    action = Some(RowAction::Delete(index));
                }
            });

        let inner = rect.shrink2(Vec2::new(14.0, 0.0));
        let mut row = ui.new_child(UiBuilder::new().max_rect(inner).layout(Layout::left_to_right(Align::Center)));
        let family = if selected { semibold() } else { egui::FontFamily::Proportional };
        row.label(RichText::new(&server.name).family(family));
        if server.doh_only {
            badge(&mut row, p.surface_hover, p.text_weak, "только DoH");
        }
        row.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if let Some(h) = self.health.get(&server.name) {
                let (text, color) = health_summary(p, h);
                ui.label(RichText::new(text).small().color(color));
            }
            if in_use {
                badge(ui, p.accent_soft, p.accent_text, "используется");
            }
        });
        action
    }

    // ---------- Панель выбранного сервера ----------

    fn details_panel(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        let ctx = ui.ctx().clone();
        card(p).inner_margin(Margin::same(20)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(ui.available_height());

            let Some(index) = self.selected.filter(|&i| i < self.config.servers.len()) else {
                ui.add_space(ui.available_height() * 0.35);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("Сервер не выбран").family(semibold()).size(16.0));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Выберите сервер в списке. Здесь появятся его адреса и кнопка «Применить».")
                            .color(p.text_weak),
                    );
                });
                return;
            };
            let server = self.config.servers[index].clone();
            let in_use = self.servers_in_use().contains(&index);
            let mut action = None;

            egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                ui.heading(&server.name);
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    if server.ai_bypass {
                        badge(ui, p.accent_soft, p.accent_text, "Обход ограничений ИИ");
                    } else {
                        badge(ui, p.surface_hover, p.text_weak, "Обычный DNS");
                    }
                    if server.doh_only {
                        badge(ui, p.surface_hover, p.text_weak, "только DoH");
                    } else if server.has_doh() {
                        badge(ui, p.surface_hover, p.text_weak, "есть DoH");
                    }
                    if in_use {
                        badge(ui, p.accent_soft, p.accent_text, "используется");
                    }
                });
                if !server.note.is_empty() {
                    ui.add_space(10.0);
                    ui.add(egui::Label::new(RichText::new(&server.note).color(p.text_weak)).wrap());
                }
                if let Some(HealthView::Done(h)) = self.health.get(&server.name) {
                    if !h.services.is_empty() {
                        ui.add_space(10.0);
                        ui.horizontal_wrapped(|ui| {
                            for s in &h.services {
                                let (state, fill, color) = if s.fully() {
                                    ("открывается", p.accent_soft, p.accent_text)
                                } else if s.works() {
                                    ("с перебоями", p.surface_hover, p.warn_text)
                                } else {
                                    ("не открывается", p.surface_hover, p.danger_text)
                                };
                                badge(ui, fill, color, &format!("{}: {state}", s.name));
                            }
                        });
                    }
                }
                ui.add_space(18.0);

                let blocker = self.blocker();
                let busy = self.busy.is_some();
                let label = if busy {
                    "Применяю…"
                } else if in_use {
                    "Применить ещё раз"
                } else {
                    "Применить"
                };
                if accent_button(ui, p, label, busy, blocker.is_none(), true).clicked() && !busy {
                    action = Some(RowAction::Apply(index));
                }
                ui.add_space(2.0);
                match blocker {
                    Some(b) => ui.add(egui::Label::new(RichText::new(b).small().color(p.warn_text)).wrap()),
                    None => ui.label(RichText::new(format!("Для: {}", self.chosen_names())).small().color(p.text_weak)),
                };
                ui.add_space(4.0);
                if ui
                    .checkbox(&mut self.config.use_doh, "Шифровать запросы (DoH)")
                    .on_hover_text(
                        "Провайдер не увидит и не подменит DNS-запросы. Нужна Windows 11. \
                         Для серверов «только DoH» шифрование обязательно.",
                    )
                    .changed()
                {
                    self.save_config();
                    self.start_sweep(&ctx);
                }
                self.status_block(ui, p);

                ui.add_space(14.0);
                divider(ui, p);
                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    ui.label(RichText::new("Доступность").family(semibold()));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("Проверить").clicked() {
                            self.health.insert(server.name.clone(), HealthView::Running);
                            let tx = self.tx.clone();
                            let (s, use_doh, ctx) = (server.clone(), self.config.use_doh, ctx.clone());
                            let probes = self.config.probes.clone();
                            std::thread::spawn(move || {
                                let health = health::check(&s, use_doh, &probes);
                                let _ = tx.send(Msg::Health { name: s.name, health });
                                ctx.request_repaint();
                            });
                        }
                    });
                });
                ui.add_space(4.0);
                self.health_details(ui, p, &server);

                ui.add_space(12.0);
                egui::Grid::new("details").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                    let key = |ui: &mut egui::Ui, t: &str| {
                        ui.label(RichText::new(t).color(p.text_weak));
                    };
                    if !server.ipv6.is_empty() {
                        key(ui, "IPv6");
                        ui.label(RichText::new(server.ipv6.join("\n")).monospace());
                        ui.end_row();
                    }
                    if server.has_doh() {
                        key(ui, "DoH");
                        ui.add(egui::Label::new(RichText::new(&server.doh).monospace()).wrap());
                        ui.end_row();
                    }
                });

                ui.add_space(16.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Изменить").clicked() {
                        action = Some(RowAction::Edit(index));
                    }
                    if ui.button("Выше").on_hover_text("Раньше в очереди резервных серверов.").clicked() {
                        action = Some(RowAction::Move(index, false));
                    }
                    if ui.button("Ниже").on_hover_text("Позже в очереди резервных серверов.").clicked() {
                        action = Some(RowAction::Move(index, true));
                    }
                    if ui.button(RichText::new("Удалить").color(p.danger_text)).clicked() {
                        action = Some(RowAction::Delete(index));
                    }
                });
            });

            match action {
                Some(RowAction::Apply(i)) => self.apply_server(&ctx, i),
                Some(RowAction::Edit(i)) => self.editor = Some(Editor::from_server(i, &self.config.servers[i])),
                Some(RowAction::Delete(i)) => self.confirm = Some(Confirm::Delete(i)),
                Some(RowAction::Move(i, down)) => self.move_server(i, down),
                None => {}
            }
        });
    }

    /// Состояние каждого адреса выбранного сервера.
    fn health_details(&self, ui: &mut egui::Ui, p: &Palette, server: &DnsServer) {
        match self.health.get(&server.name) {
            None => {
                ui.label(RichText::new("Ещё не проверялся.").color(p.text_weak));
            }
            Some(HealthView::Running) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Проверяю адреса…").color(p.text_weak));
                });
            }
            Some(HealthView::Done(h)) => {
                let how = match h.method {
                    Method::Udp => "обычный DNS-запрос",
                    Method::Doh => "запрос по DoH (HTTPS)",
                };
                for ip in &h.ips {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&ip.ip).monospace());
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| match &ip.result {
                            Ok(ms) => ui.label(RichText::new(format!("работает, {ms} мс")).color(p.success_text)),
                            Err(_) => ui.label(RichText::new("не отвечает").color(p.danger_text)),
                        });
                    });
                    if let Err(e) = &ip.result {
                        ui.add(egui::Label::new(RichText::new(e).small().color(p.text_weak)).wrap());
                    }
                }
                ui.label(RichText::new(format!("Проверка: {how}.")).small().color(p.text_weak));
                if h.best_ms().is_some_and(|ms| ms > health::SLOW_MS) {
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "DNS отвечает дольше 1,5 с: Windows не дождётся и уйдёт на страховочные \
                                 Cloudflare и Google, а через них ИИ-сервисы не откроются.",
                            )
                            .small()
                            .color(p.warn_text),
                        )
                        .wrap(),
                    );
                }
                if !h.services.is_empty() {
                    ui.add_space(10.0);
                    ui.label(RichText::new("Сервисы через этот DNS").family(semibold()));
                    ui.add_space(2.0);
                    for s in &h.services {
                        let total = s.proxies.len();
                        let (text, color) = if let Some(e) = &s.dns_error {
                            (format!("не открывается: {e}"), p.danger_text)
                        } else if !s.works() {
                            (format!("не открывается: {}", s.first_error().unwrap_or("нет ответа")), p.danger_text)
                        } else if s.fully() {
                            let ms = s.best_ms().map(health::seconds).unwrap_or_default();
                            (format!("открывается, {ms}"), p.success_text)
                        } else {
                            (format!("работает {} из {total} прокси", s.ok_count()), p.warn_text)
                        };
                        ui.horizontal(|ui| {
                            ui.label(&s.name);
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(text).color(color));
                            });
                        });
                    }
                    ui.label(
                        RichText::new("Проверка: TLS-соединение с прокси, которые выдал DNS.").small().color(p.text_weak),
                    );
                }
            }
        }
    }

    fn status_block(&self, ui: &mut egui::Ui, p: &Palette) {
        let Some(status) = &self.status else { return };
        if self.busy.is_some() {
            return;
        }
        let (color, title) = match status.kind {
            StatusKind::Success => (p.success_text, "Готово"),
            StatusKind::Warning => (p.warn_text, "Внимание"),
            StatusKind::Error => (p.danger_text, "Не получилось"),
        };
        ui.add_space(8.0);
        Frame::new()
            .fill(p.bg)
            .stroke(Stroke::new(1.0, p.border))
            .corner_radius(CornerRadius::same(6))
            .inner_margin(Margin::same(10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new(title).family(semibold()).color(color));
                ui.add(egui::Label::new(RichText::new(&status.text).color(p.text)).wrap());
            });
    }

    // ---------- Диалоги ----------

    fn editor_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut ed) = self.editor.take() else { return };
        let mut result = DialogResult::Open;
        modal(ctx, "server-editor").show(ctx, |ui| {
            let p = palette(ui);
            ui.set_width(500.0);
            ui.heading(if ed.index.is_some() { "Изменить сервер" } else { "Новый сервер" });
            ui.add_space(14.0);
            egui::Grid::new("editor-grid").num_columns(2).spacing([14.0, 10.0]).show(ui, |ui| {
                field(ui, "Название", &mut ed.name, "Например, Мой DNS");
                field(ui, "IPv4-адреса", &mut ed.ipv4, "Через запятую: 1.1.1.1, 1.0.0.1");
                field(ui, "IPv6-адреса", &mut ed.ipv6, "Необязательно");
                field(ui, "Шаблон DoH", &mut ed.doh, "https://…/dns-query, необязательно");
                field(ui, "Примечание", &mut ed.note, "Необязательно");
            });
            ui.add_space(10.0);
            ui.checkbox(&mut ed.ai_bypass, "Для обхода региональных ограничений ИИ");
            ui.checkbox(&mut ed.doh_only, "Работает только через DoH (обычный порт 53 закрыт)");
            if let Some(err) = &ed.error {
                ui.add_space(8.0);
                ui.label(RichText::new(err).color(p.danger_text));
            }
            ui.add_space(18.0);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if accent_button(ui, p, "Сохранить", false, true, false).clicked() || ui.input(|i| i.key_pressed(Key::Enter)) {
                    result = DialogResult::Accept;
                }
                if secondary_button(ui, "Отмена").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                    result = DialogResult::Cancel;
                }
            });
        });

        match result {
            DialogResult::Open => self.editor = Some(ed),
            DialogResult::Cancel => {}
            DialogResult::Accept => {
                let server = ed.to_server();
                let duplicate = self
                    .config
                    .servers
                    .iter()
                    .enumerate()
                    .any(|(i, s)| Some(i) != ed.index && s.name.to_lowercase() == server.name.to_lowercase());
                let check = if duplicate {
                    Err("Сервер с таким названием уже есть. Выберите другое название.".to_string())
                } else {
                    server.validate()
                };
                match check {
                    Err(e) => {
                        ed.error = Some(e);
                        self.editor = Some(ed);
                    }
                    Ok(()) => {
                        let index = match ed.index {
                            Some(i) => {
                                let old = std::mem::replace(&mut self.config.servers[i], server.clone());
                                if old.name != server.name {
                                    self.rename_in_state(&old.name, &server.name);
                                }
                                i
                            }
                            None => {
                                self.config.servers.push(server.clone());
                                self.config.servers.len() - 1
                            }
                        };
                        self.selected = Some(index);
                        self.save_config();
                        self.health.insert(server.name.clone(), HealthView::Running);
                        let tx = self.tx.clone();
                        let (use_doh, ctx) = (self.config.use_doh, ctx.clone());
                        let probes = self.config.probes.clone();
                        std::thread::spawn(move || {
                            let health = health::check(&server, use_doh, &probes);
                            let _ = tx.send(Msg::Health { name: server.name, health });
                            ctx.request_repaint();
                        });
                    }
                }
            }
        }
    }

    /// Переименованный сервер должен остаться выбранным для защиты от сбоев.
    fn rename_in_state(&mut self, old: &str, new: &str) {
        let mut st = RuntimeState::load();
        let mut changed = false;
        for slot in [&mut st.preferred, &mut st.active] {
            if slot.as_deref() == Some(old) {
                *slot = Some(new.to_string());
                changed = true;
            }
        }
        if changed {
            let _ = st.save();
            self.runtime = st;
        }
    }

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(confirm) = self.confirm.take() else { return };
        let (title, text, accept) = match &confirm {
            Confirm::Delete(i) => (
                "Удалить сервер?".to_string(),
                format!("«{}» пропадёт из списка. Настройки подключений не изменятся.", self.config.servers[*i].name),
                "Удалить",
            ),
            Confirm::RestoreDefaults => (
                "Восстановить стандартный список?".to_string(),
                "Добавленные и изменённые вами серверы заменятся начальным набором.".to_string(),
                "Восстановить",
            ),
            Confirm::Reset => (
                "Сбросить DNS?".to_string(),
                format!(
                    "Подключения ({}) снова будут получать DNS автоматически от роутера или провайдера. \
                     Шифрование DoH для них отключится, защита от сбоев перестанет следить.",
                    self.chosen_names()
                ),
                "Сбросить",
            ),
        };
        let destructive = !matches!(confirm, Confirm::Reset);

        let mut result = DialogResult::Open;
        modal(ctx, "confirm").show(ctx, |ui| {
            let p = palette(ui);
            ui.set_width(420.0);
            ui.heading(title);
            ui.add_space(8.0);
            ui.label(text);
            ui.add_space(20.0);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let accept_btn = if destructive {
                    danger_button(ui, p, accept)
                } else {
                    accent_button(ui, p, accept, false, true, false)
                };
                if accept_btn.clicked() {
                    result = DialogResult::Accept;
                }
                if secondary_button(ui, "Отмена").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                    result = DialogResult::Cancel;
                }
            });
        });

        match result {
            DialogResult::Open => self.confirm = Some(confirm),
            DialogResult::Cancel => {}
            DialogResult::Accept => match confirm {
                Confirm::Delete(i) => {
                    let removed = self.config.servers.remove(i);
                    if removed.builtin && !self.config.hidden_builtin.contains(&removed.name) {
                        self.config.hidden_builtin.push(removed.name.clone());
                    }
                    let name = removed.name;
                    self.selected = match self.selected {
                        Some(s) if s == i => None,
                        Some(s) if s > i => Some(s - 1),
                        other => other,
                    };
                    self.health.remove(&name);
                    self.save_config();
                    self.set_status(StatusKind::Success, format!("«{name}» удалён из списка."));
                }
                Confirm::RestoreDefaults => {
                    self.config.servers = default_servers();
                    self.selected = None;
                    self.save_config();
                    self.start_sweep(ctx);
                    self.set_status(StatusKind::Success, "Стандартный список восстановлен.");
                }
                Confirm::Reset => self.start_action(ctx, Action::Reset, Done::Reset),
            },
        }
    }

    fn log_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_log {
            return;
        }
        let mut close = false;
        modal(ctx, "log").show(ctx, |ui| {
            let p = palette(ui);
            ui.set_width(640.0);
            ui.heading("Журнал");
            ui.add_space(4.0);
            ui.label(RichText::new("Переключения и сбои, новые сверху.").color(p.text_weak));
            ui.add_space(10.0);
            card(p).fill(p.bg).show(ui, |ui| {
                ui.set_width(ui.available_width());
                egui::ScrollArea::vertical().max_height(360.0).auto_shrink([false, true]).show(ui, |ui| {
                    if self.log_tail.is_empty() {
                        ui.label(RichText::new("Пока событий нет. Они появятся после первого «Применить».").color(p.text_weak));
                    }
                    for line in self.log_tail.iter().rev() {
                        let (time, text) = line.split_at(line.find("  ").unwrap_or(0));
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(time).monospace().color(p.text_weak));
                            ui.label(text.trim());
                        });
                    }
                });
            });
            ui.add_space(14.0);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if accent_button(ui, p, "Закрыть", false, true, false).clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                    close = true;
                }
            });
        });
        if close {
            self.show_log = false;
        }
    }
}

// ---------- Действия окна: подбор, браузеры, обновления, IPv6 ----------

impl DnsApp {
    /// «Подобрать лучший сервер»: проверить все серверы для ИИ и включить лучший.
    fn start_auto_pick(&mut self, ctx: &egui::Context) {
        if self.auto_picking || self.blocker().is_some() {
            return;
        }
        self.auto_picking = true;
        self.status = None;
        let cfg = self.config.clone();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        for s in cfg.servers.iter().filter(|s| s.ai_bypass) {
            self.health.insert(s.name.clone(), HealthView::Running);
        }
        std::thread::spawn(move || {
            let ai: Vec<DnsServer> = cfg.servers.iter().filter(|s| s.ai_bypass).cloned().collect();
            let checked = monitor::check_all(&cfg, &ai);
            let _ = tx.send(Msg::AutoPicked(checked));
            ctx.request_repaint();
        });
    }

    fn finish_auto_pick(&mut self, checked: Vec<(DnsServer, Health)>) {
        self.auto_picking = false;
        for (s, h) in &checked {
            self.health.insert(s.name.clone(), HealthView::Done(h.clone()));
        }
        let snapshot = state::Snapshot::load();
        let rank = |name: &str| snapshot.reliability(name).map(|r| 100 - r).unwrap_or(50);
        match monitor::best(&checked, Grade::Dead, rank) {
            Some((s, h)) if h.grade() < Grade::ServiceDown => {
                let Some(index) = self.config.servers.iter().position(|x| x.name == s.name) else { return };
                self.selected = Some(index);
                let server = health::prefer_working(&s, &h);
                let done = Done::Applied(s.name.clone());
                let action = Action::Apply {
                    server,
                    use_doh: self.config.use_doh,
                    safety_net: self.config.failover.safety_net,
                };
                state::log(&monitor::candidates_note(&checked, None));
                let ctx = self.ctx.clone();
                self.start_action(&ctx, action, done);
            }
            _ => self.set_status(
                StatusKind::Error,
                format!(
                    "Сейчас ни один сервер для ИИ не открывает все сервисы. Проверены: {}.",
                    monitor::candidates_note(&checked, None)
                ),
            ),
        }
    }

    /// Перепроверка без смены статуса (после обновления списка).
    fn start_sweep_quiet(&mut self) {
        self.last_sweep = Instant::now() - SWEEP_EVERY;
    }

    fn start_browser_scan(&mut self, ctx: &egui::Context) {
        self.last_browsers = Instant::now();
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(Msg::Browsers(browsers::detect()));
            ctx.request_repaint();
        });
    }

    fn fix_browser(&mut self, ctx: &egui::Context, b: &browsers::BrowserDns) {
        let note = if b.running { format!("Закрываю {}, исправляю и открываю снова…", b.name) } else { "Исправляю…".to_string() };
        self.browser_note.insert(b.name.to_string(), (true, note));
        let (tx, ctx, b) = (self.tx.clone(), ctx.clone(), b.clone());
        std::thread::spawn(move || {
            // Свежие сведения: браузер мог уже закрыться.
            let fresh = browsers::detect().into_iter().find(|x| x.name == b.name).unwrap_or(b);
            let result = browsers::close_fix_reopen(&fresh);
            let _ = tx.send(Msg::BrowserFixed(fresh.name.to_string(), result));
            let _ = tx.send(Msg::Browsers(browsers::detect()));
            ctx.request_repaint();
        });
    }

    fn check_update(&mut self, ctx: &egui::Context) {
        if !update::configured() || self.update_busy.is_some() {
            return;
        }
        self.update_busy = Some("Проверяю обновления…".into());
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(Msg::UpdateChecked(update::check_app()));
            ctx.request_repaint();
        });
    }

    fn download_update(&mut self, ctx: &egui::Context, m: update::Manifest) {
        self.update_busy = Some(format!("Скачиваю версию {}…", m.version));
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(Msg::UpdateDownloaded(update::download_app(&m)));
            ctx.request_repaint();
        });
    }

    fn update_list_now(&mut self, ctx: &egui::Context) {
        if !update::configured() {
            return;
        }
        self.update_busy = Some("Обновляю список серверов…".into());
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        let keep: Vec<String> = [self.runtime.preferred.clone(), self.runtime.active.clone()].into_iter().flatten().collect();
        std::thread::spawn(move || {
            let result = update::fetch_server_list().map(|list| {
                let mut cfg = Config::load();
                let changes = cfg.apply_server_list(&list, &keep);
                let _ = cfg.save();
                (list.version, changes)
            });
            let _ = tx.send(Msg::ListUpdated(result));
            ctx.request_repaint();
        });
    }

    fn set_ipv6(&mut self, adapter: &str, enabled: bool) {
        let (tx, name) = (self.tx.clone(), adapter.to_string());
        std::thread::spawn(move || {
            let result = net::set_ipv6(&name, enabled);
            let _ = tx.send(Msg::Ipv6(name, enabled, result));
        });
    }

    /// Верхняя строка: режим, справка, настройки, обновление.
    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        let ctx = ui.ctx().clone();
        ui.horizontal(|ui| {
            ui.label(RichText::new(install::APP_NAME).family(semibold()).size(17.0));
            ui.add_space(12.0);
            if self.view == View::Main {
                let mut mode = self.config.ui_mode;
                ui.selectable_value(&mut mode, UiMode::Simple, "Простой режим");
                ui.selectable_value(&mut mode, UiMode::Advanced, "Подробный режим");
                if mode != self.config.ui_mode {
                    self.config.ui_mode = mode;
                    self.save_config();
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Настройки").clicked() {
                    self.view = View::Settings(Section::Appearance);
                }
                if ui.button("Как это работает").clicked() {
                    self.view = View::Help;
                }
                if let Some(m) = self.updates.available.clone() {
                    let text = match &self.update_busy {
                        Some(b) => b.clone(),
                        None => format!("Обновить до {}", m.version),
                    };
                    if accent_button(ui, p, &text, self.update_busy.is_some(), self.update_busy.is_none(), false)
                        .on_hover_text(if m.notes.is_empty() { "Новая версия программы.".to_string() } else { m.notes.clone() })
                        .clicked()
                    {
                        self.download_update(&ctx, m);
                    }
                }
            });
        });
    }

    /// Жёлтые плашки: что мешает обходу и что с этим сделать.
    fn banners(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        let ctx = ui.ctx().clone();
        let banner = |ui: &mut egui::Ui, add: &mut dyn FnMut(&mut egui::Ui)| {
            ui.add_space(8.0);
            Frame::new()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, p.warn_text))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(Margin::symmetric(14, 10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_wrapped(|ui| add(ui));
                });
        };

        if !self.is_admin {
            banner(ui, &mut |ui: &mut egui::Ui| {
                ui.label(RichText::new("Нет прав администратора:").family(semibold()).color(p.warn_text));
                ui.label("без них программа не может менять DNS.");
                if ui.button("Перезапустить с правами администратора").clicked()
                    && crate::elevate::relaunch_as_admin(&["--wait-gui".to_string()]).is_ok()
                {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        }

        for b in self.bypassing_browsers().into_iter().cloned().collect::<Vec<_>>() {
            banner(ui, &mut |ui: &mut egui::Ui| {
                ui.label(RichText::new(format!("{} обходит DNS Windows:", b.name)).family(semibold()).color(p.warn_text));
                ui.label("у него свой защищённый DNS, поэтому обход в нём не работает.");
                if b.can_fix() {
                    let label = if b.running { format!("Закрыть {} и исправить", b.name) } else { "Исправить".to_string() };
                    let hover = if b.running {
                        "Браузер закроется как обычно, переключится на DNS Windows и откроется снова. Вкладки сохранятся, \
                         если в нём включено «Продолжить работу с того же места»."
                    } else {
                        "Браузер начнёт пользоваться DNS Windows."
                    };
                    if ui.button(label).on_hover_text(hover).clicked() {
                        self.fix_browser(&ctx, &b);
                    }
                    if let Some((ok, note)) = self.browser_note.get(b.name) {
                        ui.label(RichText::new(note).small().color(if *ok { p.text_weak } else { p.danger_text }));
                    }
                } else {
                    ui.label(
                        RichText::new(format!("Задано политикой. Вручную: {} → «Безопасный DNS» → выключить.", b.settings_url))
                            .small()
                            .color(p.text_weak),
                    );
                }
            });
        }

        // IPv6: сервер отдаёт настоящий адрес, а у подключения есть IPv6.
        let leak: Vec<String> = match self.active_server().and_then(|s| match self.health.get(&s.name) {
            Some(HealthView::Done(h)) => Some(h.clone()),
            _ => None,
        }) {
            Some(h) => h.services.iter().filter(|s| s.ipv6_leak).map(|s| s.name.clone()).collect(),
            None => Vec::new(),
        };
        let v6_adapters: Vec<String> = self.chosen_adapters().into_iter().filter(|a| a.up && a.has_ipv6).map(|a| a.name).collect();
        if !leak.is_empty() && !v6_adapters.is_empty() {
            banner(ui, &mut |ui: &mut egui::Ui| {
                ui.label(RichText::new("Утечка через IPv6:").family(semibold()).color(p.warn_text));
                ui.label(format!("{} могут открываться напрямую, мимо прокси.", leak.join(", ")));
                for a in &v6_adapters {
                    if ui
                        .button(format!("Выключить IPv6 на {a}"))
                        .on_hover_text("Вернуть можно в настройках, раздел «Проверка серверов».")
                        .clicked()
                    {
                        self.set_ipv6(a, false);
                    }
                }
            });
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.poll_messages();
        self.periodic(&ctx);
        let bg = palette(ui).bg;
        let page = |m: Margin| Frame::new().fill(bg).inner_margin(m);

        egui::Panel::top("topbar")
            .show_separator_line(false)
            .frame(page(Margin { left: GUTTER, right: GUTTER, top: 12, bottom: 4 }))
            .show(ui, |ui| {
                self.top_bar(ui);
                if self.view == View::Main {
                    self.banners(ui);
                }
            });

        match (self.view, self.config.ui_mode) {
            (View::Settings(section), _) => {
                egui::CentralPanel::default_margins()
                    .frame(page(Margin::same(GUTTER)))
                    .show(ui, |ui| self.settings_view(ui, section));
            }
            (View::Help, _) => {
                egui::CentralPanel::default_margins()
                    .frame(page(Margin::same(GUTTER)))
                    .show(ui, |ui| self.help_view(ui));
            }
            (View::Main, UiMode::Simple) => {
                egui::CentralPanel::default_margins()
                    .frame(page(Margin::same(GUTTER)))
                    .show(ui, |ui| self.simple_view(ui));
            }
            (View::Main, UiMode::Advanced) => {
                egui::Panel::top("connection")
                    .show_separator_line(false)
                    .frame(page(Margin { left: GUTTER, right: GUTTER, top: 8, bottom: 4 }))
                    .show(ui, |ui| self.connection_card(ui));
                egui::Panel::right("details")
                    .exact_size(DETAILS_WIDTH)
                    .resizable(false)
                    .show_separator_line(false)
                    .frame(page(Margin { left: 0, right: GUTTER, top: 12, bottom: GUTTER }))
                    .show(ui, |ui| self.details_panel(ui));
                egui::CentralPanel::default_margins()
                    .frame(page(Margin { left: GUTTER, right: GUTTER, top: 12, bottom: GUTTER }))
                    .show(ui, |ui| self.servers_list(ui));
            }
        }

        self.editor_dialog(&ctx);
        self.confirm_dialog(&ctx);
        self.log_dialog(&ctx);
    }
}

// ---------- Мелкие элементы ----------

/// Модальное окно в общем стиле: карточка с отступами 24 px и тенью.
fn modal(ctx: &egui::Context, id: &str) -> Modal {
    let p = if ctx.theme() == egui::Theme::Dark { &theme::DARK } else { &theme::LIGHT };
    let style = ctx.global_style();
    Modal::new(Id::unique(id)).frame(
        Frame::new()
            .fill(p.surface)
            .stroke(Stroke::new(1.0, p.border))
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(24))
            .shadow(style.visuals.window_shadow),
    )
}

fn interval_text(secs: u64) -> String {
    INTERVALS
        .iter()
        .find(|(s, _)| *s == secs)
        .map(|(_, t)| t.to_string())
        .unwrap_or_else(|| format!("{secs} с"))
}

/// Короткая сводка для строки списка. Состояние передано словами, не только цветом.
fn health_summary(p: &Palette, h: &HealthView) -> (String, Color32) {
    match h {
        HealthView::Running => ("проверка…".into(), p.text_weak),
        HealthView::Done(h) if h.ips.is_empty() => ("нет адресов".into(), p.text_weak),
        HealthView::Done(h) => {
            let ms = h.best_ms().map(health::seconds).unwrap_or_default();
            match h.grade() {
                Grade::Good => (format!("работает · {ms}"), p.text_weak),
                Grade::PartialProxies => (format!("часть прокси не отвечает · {ms}"), p.warn_text),
                Grade::Slow => (format!("медленно · {ms}"), p.warn_text),
                Grade::ServiceDown => {
                    let down: Vec<&str> = h.services.iter().filter(|s| !s.works()).map(|s| s.name.as_str()).collect();
                    let verb = if down.len() > 1 { "не открываются" } else { "не открывается" };
                    (format!("{} {verb}", down.join(" и ")), p.danger_text)
                }
                Grade::Dead => ("не отвечает".into(), p.danger_text),
            }
        }
    }
}

fn card(p: &Palette) -> Frame {
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(14))
}

fn section_title(text: &str) -> RichText {
    RichText::new(text).family(semibold()).size(16.0)
}

fn divider(ui: &mut egui::Ui, p: &Palette) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::ZERO, p.border);
}

/// Небольшая метка фиксированной высоты, текст не переносится.
fn badge(ui: &mut egui::Ui, fill: Color32, text_color: Color32, text: &str) {
    let font = TextStyle::Small.resolve(ui.style());
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, text_color);
    let size = Vec2::new(galley.size().x + 16.0, 22.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    resp.widget_info(|| WidgetInfo::labeled(Role::Label, true, text));
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(4), fill);
    painter.galley(pos2(rect.left() + 8.0, rect.center().y - galley.size().y / 2.0), galley, text_color);
}

/// Переключаемая «таблетка» выбора подключения. Отмеченная показывает галочку,
/// поэтому состояние читается не только по цвету.
fn chip(ui: &mut egui::Ui, p: &Palette, on: bool, text: &str) -> Response {
    let font = TextStyle::Body.resolve(ui.style());
    let galley = ui.painter().layout_no_wrap(text.to_string(), font, Color32::PLACEHOLDER);
    let check_w = if on { 18.0 } else { 0.0 };
    let size = Vec2::new(galley.size().x + 28.0 + check_w, 30.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    resp.widget_info(|| WidgetInfo::selected(Role::CheckBox, true, on, text));

    let (fill, stroke, color) = match (on, resp.hovered()) {
        (true, _) => (p.accent_soft, Stroke::new(1.0, p.accent), p.accent_text),
        (false, true) => (p.surface_hover, Stroke::new(1.0, p.border_strong), p.text),
        (false, false) => (p.surface, Stroke::new(1.0, p.border_strong), p.text),
    };
    let painter = ui.painter();
    painter.rect(rect, CornerRadius::same(15), fill, stroke, StrokeKind::Inside);
    if resp.has_focus() {
        painter.rect_stroke(rect.expand(2.0), CornerRadius::same(17), Stroke::new(2.0, p.accent), StrokeKind::Outside);
    }
    let mut x = rect.left() + 14.0;
    if on {
        let c = pos2(x + 6.0, rect.center().y);
        let s = Stroke::new(1.8, color);
        painter.line_segment([c + Vec2::new(-5.0, 0.0), c + Vec2::new(-1.5, 3.5)], s);
        painter.line_segment([c + Vec2::new(-1.5, 3.5), c + Vec2::new(5.0, -4.0)], s);
        x += check_w;
    }
    painter.galley(pos2(x, rect.center().y - galley.size().y / 2.0), galley, color);
    resp
}

fn field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.label(label);
    ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(hint)
            .desired_width(f32::INFINITY)
            .margin(Margin::symmetric(8, 6)),
    );
    ui.end_row();
}

/// Главная кнопка. Во время работы остаётся яркой, а рядом с надписью крутится индикатор.
fn accent_button(ui: &mut egui::Ui, p: &Palette, text: &str, busy: bool, enabled: bool, wide: bool) -> Response {
    let size = if wide { Vec2::new(ui.available_width(), 40.0) } else { Vec2::new(110.0, 32.0) };
    let btn = egui::Button::new((egui::Atom::grow(), RichText::new(text).family(semibold()).color(p.on_accent), egui::Atom::grow()))
        .fill(p.accent)
        .stroke(Stroke::NONE)
        .min_size(size);
    let resp = ui.add_enabled(enabled, btn);
    if busy {
        let r = resp.rect;
        let spinner = Rect::from_center_size(pos2(r.left() + 24.0, r.center().y), Vec2::splat(16.0));
        egui::Spinner::new().color(p.on_accent).paint_at(ui, spinner);
    }
    resp
}

fn secondary_button(ui: &mut egui::Ui, text: &str) -> Response {
    ui.add(egui::Button::new(text).min_size(Vec2::new(96.0, 32.0)))
}

fn danger_button(ui: &mut egui::Ui, p: &Palette, text: &str) -> Response {
    let btn = egui::Button::new((egui::Atom::grow(), RichText::new(text).family(semibold()).color(p.on_danger), egui::Atom::grow()))
        .fill(p.danger_fill)
        .stroke(Stroke::NONE)
        .min_size(Vec2::new(110.0, 32.0));
    ui.add(btn)
}
