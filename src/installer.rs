//! Мастер установки и удаления. Открывается, когда программа запущена не из
//! папки установки (например, DnsSwitcher-Setup.exe из «Загрузок»), или по
//! `--uninstall` из «Приложений» Windows.

use crate::elevate;
use crate::install::{self, InstallOptions, Step, UninstallOptions};
use crate::theme::{self, Palette, palette, semibold};
use eframe::egui::{
    self, Align, Atom, Color32, ColorImage, CornerRadius, Frame, Key, Layout, Margin, Rect, RichText, Sense,
    Stroke, TextureHandle, Vec2, pos2,
};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};

pub const INSTALLER_TITLE: &str = "Установка — Переключатель DNS";

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Install,
    Uninstall,
}

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Welcome,
    Options,
    UninstallConfirm,
    Progress,
    Finish,
}

#[derive(Clone, Copy, PartialEq)]
enum Maintenance {
    Update,
    Remove,
}

#[derive(Clone, PartialEq)]
enum StepState {
    Pending,
    Running,
    Done,
    Failed(String),
}

enum WorkerMsg {
    Started(usize),
    Finished(usize, Result<(), String>),
}

pub enum Choice {
    Stay,
    /// «Запустить без установки».
    RunPortable,
}

pub struct Wizard {
    mode: Mode,
    page: Page,
    /// Уже установленная версия и её папка.
    existing: Option<(String, PathBuf)>,
    maintenance: Maintenance,
    opts: InstallOptions,
    dir_text: String,
    un: UninstallOptions,
    manages_dns: bool,
    plan: Vec<Step>,
    states: Vec<StepState>,
    worker: Option<Receiver<WorkerMsg>>,
    browse: Option<Receiver<Option<PathBuf>>>,
    launch_after: bool,
    entered_uninstall_directly: bool,
    icon: TextureHandle,
    is_admin: bool,
}

impl Wizard {
    pub fn new(ctx: &egui::Context, mode: Mode) -> Self {
        theme::install(ctx);
        let rgba = include_bytes!("../assets/icon-64.rgba");
        let icon = ctx.load_texture("app-icon", ColorImage::from_rgba_unmultiplied([64, 64], rgba), Default::default());
        let existing = install::installed_version().zip(install::installed_dir());
        let dir = existing.as_ref().map(|(_, d)| d.clone()).unwrap_or_else(install::default_dir);
        let manages_dns = install::manages_dns();
        Self {
            mode,
            page: if mode == Mode::Uninstall { Page::UninstallConfirm } else { Page::Welcome },
            existing,
            maintenance: Maintenance::Update,
            dir_text: dir.to_string_lossy().to_string(),
            opts: InstallOptions {
                dir,
                start_menu: true,
                desktop: true,
                no_uac: true,
                background: true,
            },
            un: UninstallOptions { reset_dns: manages_dns, remove_settings: false },
            manages_dns,
            plan: Vec::new(),
            states: Vec::new(),
            worker: None,
            browse: None,
            launch_after: true,
            entered_uninstall_directly: mode == Mode::Uninstall,
            icon,
            is_admin: elevate::is_admin(),
        }
        .debug_page()
    }

    /// Только для отладочной сборки: открыть нужную страницу для снимков экрана.
    #[cfg_attr(not(debug_assertions), allow(unused_mut))]
    fn debug_page(mut self) -> Self {
        #[cfg(debug_assertions)]
        {
            let page = std::env::var("DNS_SWITCHER_DEBUG_PAGE").unwrap_or_default();
            let fake_progress = |w: &mut Self, mode: Mode, failed: bool| {
                w.mode = mode;
                w.plan = match mode {
                    Mode::Install => install::install_plan(),
                    Mode::Uninstall => install::uninstall_plan(&UninstallOptions { reset_dns: true, remove_settings: false }),
                };
                w.states = vec![StepState::Pending; w.plan.len()];
                w.states[0] = StepState::Done;
                w.states[1] = StepState::Done;
                w.states[2] = if failed {
                    StepState::Failed("Не удалось создать ярлык: доступ запрещён.".into())
                } else {
                    StepState::Running
                };
                w.page = Page::Progress;
            };
            match page.as_str() {
                "options" => self.page = Page::Options,
                "progress" => fake_progress(&mut self, Mode::Install, false),
                "failed" => fake_progress(&mut self, Mode::Install, true),
                "finish" => self.page = Page::Finish,
                "uninstall" => {
                    self.mode = Mode::Uninstall;
                    self.manages_dns = true;
                    self.un.reset_dns = true;
                    self.page = Page::UninstallConfirm;
                }
                "update" => self.existing = Some(("0.9.0".into(), install::default_dir())),
                _ => {}
            }
        }
        self
    }

    // ---------- Работа ----------

    fn start_install(&mut self, ctx: &egui::Context) {
        self.mode = Mode::Install;
        self.opts.dir = PathBuf::from(self.dir_text.trim());
        self.plan = install::install_plan();
        self.run_from(ctx, 0);
    }

    fn start_uninstall(&mut self, ctx: &egui::Context) {
        self.mode = Mode::Uninstall;
        self.plan = install::uninstall_plan(&self.un);
        self.run_from(ctx, 0);
    }

    /// Запускает шаги начиная с `first` (так работает и «Повторить»).
    fn run_from(&mut self, ctx: &egui::Context, first: usize) {
        if first == 0 {
            self.states = vec![StepState::Pending; self.plan.len()];
        }
        for s in &mut self.states[first..] {
            *s = StepState::Pending;
        }
        self.page = Page::Progress;
        let (tx, rx) = channel();
        let plan = self.plan.clone();
        let (mode, opts, dir) = (self.mode, self.opts.clone(), self.existing.as_ref().map(|(_, d)| d.clone()));
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            for (i, step) in plan.iter().enumerate().skip(first) {
                let _ = tx.send(WorkerMsg::Started(i));
                ctx.request_repaint();
                let result = match mode {
                    Mode::Install => install::run_install_step(*step, &opts),
                    Mode::Uninstall => install::run_uninstall_step(*step, dir.as_deref()),
                };
                let failed = result.is_err();
                let _ = tx.send(WorkerMsg::Finished(i, result));
                ctx.request_repaint();
                if failed {
                    break;
                }
            }
        });
        self.worker = Some(rx);
    }

    fn poll(&mut self) {
        if let Some(rx) = &self.worker {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    WorkerMsg::Started(i) => self.states[i] = StepState::Running,
                    WorkerMsg::Finished(i, Ok(())) => self.states[i] = StepState::Done,
                    WorkerMsg::Finished(i, Err(e)) => self.states[i] = StepState::Failed(e),
                }
            }
            if self.states.iter().all(|s| *s == StepState::Done) {
                self.worker = None;
                self.page = Page::Finish;
            }
        }
        if let Some(rx) = &self.browse {
            if let Ok(picked) = rx.try_recv() {
                self.browse = None;
                if let Some(mut dir) = picked {
                    if !dir.ends_with("DnsSwitcher") {
                        dir.push("DnsSwitcher");
                    }
                    self.dir_text = dir.to_string_lossy().to_string();
                }
            }
        }
    }

    fn browse_folder(&mut self) {
        let (tx, rx) = channel();
        let start = PathBuf::from(self.dir_text.trim());
        std::thread::spawn(move || {
            let start = start.parent().map(PathBuf::from).unwrap_or(start);
            let picked = rfd::FileDialog::new().set_title("Куда установить программу").set_directory(start).pick_folder();
            let _ = tx.send(picked);
        });
        self.browse = Some(rx);
    }

    fn failed_index(&self) -> Option<usize> {
        self.states.iter().position(|s| matches!(s, StepState::Failed(_)))
    }

    fn updating(&self) -> bool {
        self.existing.is_some()
    }

    // ---------- Отрисовка ----------

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Choice {
        self.poll();
        let ctx = ui.ctx().clone();
        let p = palette(ui);
        let mut choice = Choice::Stay;

        egui::Panel::top("wizard-header")
            .show_separator_line(false)
            .frame(Frame::new().fill(p.surface).inner_margin(Margin::symmetric(24, 18)))
            .show(ui, |ui| self.header(ui, p));
        egui::Panel::top("wizard-header-line")
            .show_separator_line(false)
            .exact_size(1.0)
            .frame(Frame::new().fill(p.border))
            .show(ui, |_| {});
        egui::Panel::bottom("wizard-footer")
            .show_separator_line(false)
            .frame(Frame::new().fill(p.surface).inner_margin(Margin::symmetric(24, 14)))
            .show(ui, |ui| self.footer(ui, p, &ctx));
        egui::Panel::bottom("wizard-footer-line")
            .show_separator_line(false)
            .exact_size(1.0)
            .frame(Frame::new().fill(p.border))
            .show(ui, |_| {});
        egui::CentralPanel::default_margins()
            .frame(Frame::new().fill(p.bg).inner_margin(Margin::symmetric(28, 22)))
            .show(ui, |ui| {
                egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| match self.page {
                    Page::Welcome => {
                        if self.welcome(ui, p) {
                            choice = Choice::RunPortable;
                        }
                    }
                    Page::Options => self.options(ui, p),
                    Page::UninstallConfirm => self.uninstall_confirm(ui, p),
                    Page::Progress => self.progress(ui, p),
                    Page::Finish => self.finish(ui, p),
                });
            });
        choice
    }

    fn header(&self, ui: &mut egui::Ui, p: &Palette) {
        let (title, steps): (&str, &[Page]) = match self.mode {
            Mode::Install => (
                if self.updating() { "Обновление Переключателя DNS" } else { "Установка Переключателя DNS" },
                &[Page::Welcome, Page::Options, Page::Progress, Page::Finish],
            ),
            Mode::Uninstall => ("Удаление Переключателя DNS", &[Page::UninstallConfirm, Page::Progress, Page::Finish]),
        };
        let subtitle = match self.page {
            Page::Welcome => "Начало",
            Page::Options => "Параметры",
            Page::UninstallConfirm => "Что удалить",
            Page::Progress if self.mode == Mode::Install => "Установка",
            Page::Progress => "Удаление",
            Page::Finish => "Готово",
        };
        ui.horizontal(|ui| {
            ui.add(egui::Image::new(&self.icon).fit_to_exact_size(Vec2::splat(40.0)));
            ui.add_space(6.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(title).family(semibold()).size(18.0));
                ui.label(RichText::new(subtitle).color(p.text_weak));
            });
            if let Some(n) = steps.iter().position(|s| *s == self.page) {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(format!("Шаг {} из {}", n + 1, steps.len())).color(p.text_weak));
                });
            }
        });
    }

    fn welcome(&mut self, ui: &mut egui::Ui, p: &Palette) -> bool {
        let mut portable = false;
        if !self.is_admin {
            admin_notice(ui, p);
            ui.add_space(16.0);
        }
        if let Some((version, dir)) = self.existing.clone() {
            ui.label(RichText::new("Программа уже установлена").family(semibold()).size(20.0));
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!("Версия {version} в папке {}.", dir.display())).color(p.text_weak),
            );
            ui.add_space(16.0);
            choice_card(
                ui,
                p,
                &mut self.maintenance,
                Maintenance::Update,
                &format!("Обновить до версии {}", install::VERSION),
                "Список серверов, настройки и журнал сохранятся.",
            );
            ui.add_space(8.0);
            choice_card(
                ui,
                p,
                &mut self.maintenance,
                Maintenance::Remove,
                "Удалить программу",
                "Можно сразу вернуть DNS подключений на автоматический.",
            );
            return false;
        }

        ui.label(RichText::new("Быстрая смена DNS и защита от сбоев").family(semibold()).size(22.0));
        ui.add_space(8.0);
        ui.add(
            egui::Label::new(
                RichText::new(
                    "Переключайте DNS в один щелчок, открывайте ИИ-сервисы через специальные серверы \
                     и не теряйте интернет, если какой-то сервер перестал отвечать.",
                )
                .color(p.text_weak),
            )
            .wrap(),
        );
        ui.add_space(20.0);
        feature(ui, p, "Обход ограничений ИИ", "GeoHide, Comss, dns-ai, MagicDNS и другие серверы для ChatGPT, Gemini, Claude.");
        feature(ui, p, "Защита от сбоев", "Проверяет сервер и сама переключает на резервный, страхует через Google и Cloudflare.");
        feature(ui, p, "Шифрование", "DNS-over-HTTPS в Windows 11: провайдер не видит и не подменяет запросы.");
        ui.add_space(18.0);
        ui.label(RichText::new(format!("Версия {} · около 7 МБ", install::VERSION)).small().color(p.text_weak));
        ui.add_space(6.0);
        if ui.link(RichText::new("Запустить без установки").color(p.accent_text)).clicked() {
            portable = true;
        }
        portable
    }

    fn options(&mut self, ui: &mut egui::Ui, p: &Palette) {
        group_title(ui, "Папка установки");
        ui.horizontal(|ui| {
            let browse_w = 96.0;
            let updating = self.updating();
            let edit = egui::TextEdit::singleline(&mut self.dir_text)
                .desired_width(ui.available_width() - browse_w - 8.0)
                .margin(Margin::symmetric(8, 6));
            ui.add_enabled(!updating, edit);
            let picking = self.browse.is_some();
            if ui
                .add_enabled(!updating && !picking, egui::Button::new("Обзор…").min_size(Vec2::new(browse_w, 30.0)))
                .clicked()
            {
                self.browse_folder();
            }
        });
        let dir = PathBuf::from(self.dir_text.trim());
        if self.updating() {
            hint(ui, p, "При обновлении папка не меняется.");
        } else if self.dir_text.trim().is_empty() {
            ui.label(RichText::new("Укажите папку установки.").small().color(p.danger_text));
        } else if !install::is_protected_dir(&dir) {
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Папка вне Program Files: файл программы сможет подменить любая программа, \
                         а запускается он с правами администратора. Надёжнее оставить Program Files.",
                    )
                    .small()
                    .color(p.warn_text),
                )
                .wrap(),
            );
        }

        ui.add_space(18.0);
        group_title(ui, "Ярлыки");
        ui.checkbox(&mut self.opts.start_menu, "В меню «Пуск»");
        ui.checkbox(&mut self.opts.desktop, "На рабочем столе");

        ui.add_space(18.0);
        group_title(ui, "Запуск и защита");
        ui.checkbox(&mut self.opts.no_uac, "Открывать без запроса прав администратора (UAC)");
        hint(
            ui,
            p,
            "Программе нужны права администратора, чтобы менять DNS. С этой настройкой ярлык \
             открывает её сразу, без окна подтверждения: через задание в Планировщике.",
        );
        ui.add_space(8.0);
        ui.checkbox(&mut self.opts.background, "Фоновая защита от сбоев");
        hint(
            ui,
            p,
            "Запускается при входе в Windows и работает, даже когда окно закрыто: если DNS-сервер \
             перестал отвечать, переключает на резервный.",
        );
    }

    fn uninstall_confirm(&mut self, ui: &mut egui::Ui, p: &Palette) {
        if !self.is_admin {
            admin_notice(ui, p);
            ui.add_space(16.0);
        }
        ui.label(RichText::new("Удалить Переключатель DNS?").family(semibold()).size(22.0));
        ui.add_space(8.0);
        ui.add(
            egui::Label::new(
                RichText::new(
                    "Будут удалены программа, ярлыки, задания Планировщика и запись в «Приложениях» Windows.",
                )
                .color(p.text_weak),
            )
            .wrap(),
        );
        ui.add_space(18.0);
        if self.manages_dns {
            ui.checkbox(&mut self.un.reset_dns, "Вернуть DNS подключений на автоматический");
            hint(
                ui,
                p,
                "Подключения снова получат DNS от роутера или провайдера. Если снять галочку, \
                 останутся текущие серверы, но следить за ними будет некому.",
            );
            ui.add_space(8.0);
        }
        ui.checkbox(&mut self.un.remove_settings, "Удалить список серверов, настройки и журнал");
        hint(ui, p, "Оставьте, если собираетесь установить программу снова.");
    }

    fn progress(&self, ui: &mut egui::Ui, p: &Palette) {
        let done = self.states.iter().filter(|s| **s == StepState::Done).count();
        let failed = self.failed_index().is_some();
        let headline = match (self.mode, failed) {
            (_, true) => "Не получилось",
            (Mode::Install, false) => "Устанавливаю…",
            (Mode::Uninstall, false) => "Удаляю…",
        };
        ui.label(RichText::new(headline).family(semibold()).size(20.0));
        ui.add_space(10.0);
        bar(ui, p, done as f32 / self.plan.len().max(1) as f32, 6.0);
        ui.add_space(16.0);
        for (step, state) in self.plan.iter().zip(&self.states) {
            ui.horizontal(|ui| {
                step_mark(ui, p, state);
                ui.add_space(4.0);
                let text = RichText::new(step.title());
                let text = match state {
                    StepState::Pending => text.color(p.text_weak),
                    StepState::Running => text.family(semibold()),
                    StepState::Done => text.color(p.text),
                    StepState::Failed(_) => text.family(semibold()).color(p.danger_text),
                };
                ui.label(text);
            });
            if let StepState::Failed(e) = state {
                ui.horizontal(|ui| {
                    ui.add_space(30.0);
                    ui.add(egui::Label::new(RichText::new(e).color(p.text)).wrap());
                });
            }
            ui.add_space(4.0);
        }
    }

    fn finish(&mut self, ui: &mut egui::Ui, p: &Palette) {
        ui.add_space(10.0);
        let (title, text) = match self.mode {
            Mode::Install => (
                if self.updating() { "Программа обновлена" } else { "Программа установлена" },
                "Переключатель DNS есть в меню «Пуск». Выберите сервер и нажмите «Применить», \
                 после этого защита от сбоев начнёт следить за ним.",
            ),
            Mode::Uninstall => (
                "Программа удалена",
                if self.un.remove_settings {
                    "Удалены программа, задания, ярлыки и настройки."
                } else {
                    "Список серверов и настройки остались в %APPDATA%\\DnsSwitcher."
                },
            ),
        };
        ui.horizontal(|ui| {
            success_mark(ui, p, 28.0);
            ui.add_space(6.0);
            ui.label(RichText::new(title).family(semibold()).size(22.0));
        });
        ui.add_space(10.0);
        ui.add(egui::Label::new(RichText::new(text).color(p.text_weak)).wrap());
        if self.mode == Mode::Install {
            ui.add_space(18.0);
            Frame::new()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, p.border))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(Margin::same(16))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let on_off = |v: bool| if v { "включён" } else { "выключен" };
                    let shortcuts = match (self.opts.start_menu, self.opts.desktop) {
                        (true, true) => "меню «Пуск» и рабочий стол",
                        (true, false) => "меню «Пуск»",
                        (false, true) => "рабочий стол",
                        (false, false) => "не созданы",
                    };
                    egui::Grid::new("summary").num_columns(2).spacing([18.0, 8.0]).show(ui, |ui| {
                        let row = |ui: &mut egui::Ui, k: &str, v: String| {
                            ui.label(RichText::new(k).color(p.text_weak));
                            ui.add(egui::Label::new(v).wrap());
                            ui.end_row();
                        };
                        row(ui, "Папка", self.opts.dir.to_string_lossy().to_string());
                        row(ui, "Ярлыки", shortcuts.to_string());
                        row(ui, "Запуск без UAC", on_off(self.opts.no_uac).to_string());
                        row(
                            ui,
                            "Фоновая защита",
                            if self.opts.background { "включена" } else { "выключена" }.to_string(),
                        );
                    });
                });
            ui.add_space(16.0);
            ui.checkbox(&mut self.launch_after, "Открыть Переключатель DNS");
        }
    }

    fn footer(&mut self, ui: &mut egui::Ui, p: &Palette, ctx: &egui::Context) {
        let close = || ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        let enter = ui.input(|i| i.key_pressed(Key::Enter)) && !ctx.egui_wants_keyboard_input();
        let escape = ui.input(|i| i.key_pressed(Key::Escape));
        let running = self.worker.is_some() && self.failed_index().is_none();

        ui.horizontal(|ui| {
            let can_cancel = !running && self.page != Page::Finish;
            if can_cancel && (secondary(ui, if self.page == Page::Progress { "Закрыть" } else { "Отмена" }).clicked() || escape) {
                close();
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| match self.page {
                Page::Welcome => {
                    if primary(ui, p, "Далее", true).clicked() || enter {
                        self.page = if self.updating() && self.maintenance == Maintenance::Remove {
                            Page::UninstallConfirm
                        } else {
                            Page::Options
                        };
                    }
                }
                Page::Options => {
                    let ok = !self.dir_text.trim().is_empty() && self.is_admin;
                    let label = if self.updating() { "Обновить" } else { "Установить" };
                    let resp = primary(ui, p, label, ok);
                    let resp = if self.is_admin { resp } else { resp.on_disabled_hover_text("Нужны права администратора.") };
                    if resp.clicked() || (enter && ok) {
                        self.start_install(ctx);
                    }
                    if secondary(ui, "Назад").clicked() {
                        self.page = Page::Welcome;
                    }
                }
                Page::UninstallConfirm => {
                    if danger(ui, p, "Удалить", self.is_admin).clicked() {
                        self.start_uninstall(ctx);
                    }
                    if !self.entered_uninstall_directly && secondary(ui, "Назад").clicked() {
                        self.page = Page::Welcome;
                    }
                }
                Page::Progress => {
                    if let Some(i) = self.failed_index() {
                        if primary(ui, p, "Повторить", true).clicked() {
                            self.run_from(ctx, i);
                        }
                    }
                }
                Page::Finish => {
                    if primary(ui, p, "Готово", true).clicked() || enter {
                        if self.mode == Mode::Install && self.launch_after {
                            let _ = install::launch(&self.opts.dir);
                        }
                        close();
                    }
                }
            });
        });
    }
}

// ---------- Мелкие элементы ----------

fn admin_notice(ui: &mut egui::Ui, p: &Palette) {
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Нужны права администратора").family(semibold()).color(p.warn_text));
            ui.add(
                egui::Label::new("Без них не получится записать файлы в Program Files и изменить настройки Windows.")
                    .wrap(),
            );
            ui.add_space(6.0);
            if ui.button("Перезапустить с правами администратора").clicked() {
                let args: Vec<String> = std::env::args().skip(1).collect();
                if elevate::relaunch_as_admin(&args).is_ok() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        });
}

fn feature(ui: &mut egui::Ui, p: &Palette, title: &str, text: &str) {
    ui.horizontal_top(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(14.0, 20.0), Sense::hover());
        ui.painter().circle_filled(pos2(rect.left() + 5.0, rect.center().y), 4.0, p.accent);
        ui.vertical(|ui| {
            ui.label(RichText::new(title).family(semibold()));
            ui.add(egui::Label::new(RichText::new(text).color(p.text_weak)).wrap());
        });
    });
    ui.add_space(10.0);
}

fn choice_card<T: PartialEq + Copy>(ui: &mut egui::Ui, p: &Palette, value: &mut T, option: T, title: &str, text: &str) {
    let selected = *value == option;
    let resp = Frame::new()
        .fill(if selected { p.surface_selected } else { p.surface })
        .stroke(Stroke::new(if selected { 1.5 } else { 1.0 }, if selected { p.accent } else { p.border }))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.radio_value(value, option, RichText::new(title).family(semibold()));
            ui.horizontal(|ui| {
                ui.add_space(26.0);
                ui.add(egui::Label::new(RichText::new(text).color(p.text_weak)).wrap());
            });
        })
        .response
        .interact(Sense::click());
    if resp.clicked() {
        *value = option;
    }
}

fn group_title(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).family(semibold()));
    ui.add_space(4.0);
}

fn hint(ui: &mut egui::Ui, p: &Palette, text: &str) {
    ui.horizontal(|ui| {
        ui.add_space(26.0);
        ui.add(egui::Label::new(RichText::new(text).small().color(p.text_weak)).wrap());
    });
}

fn bar(ui: &mut egui::Ui, p: &Palette, fraction: f32, height: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::hover());
    let r = CornerRadius::same((height / 2.0) as u8);
    ui.painter().rect_filled(rect, r, p.border);
    let mut fill = rect;
    fill.set_width(rect.width() * fraction.clamp(0.0, 1.0));
    ui.painter().rect_filled(fill, r, p.accent);
}

fn step_mark(ui: &mut egui::Ui, p: &Palette, state: &StepState) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
    let c = rect.center();
    let painter = ui.painter();
    match state {
        StepState::Pending => {
            painter.circle_stroke(c, 8.0, Stroke::new(1.5, p.border_strong));
        }
        StepState::Running => {
            egui::Spinner::new().color(p.accent).paint_at(ui, Rect::from_center_size(c, Vec2::splat(18.0)));
        }
        StepState::Done => draw_check(painter, c, 9.0, p.success_text, p.surface),
        StepState::Failed(_) => {
            painter.circle_filled(c, 9.0, p.danger_fill);
            let s = Stroke::new(1.8, Color32::WHITE);
            painter.line_segment([c + Vec2::new(-3.5, -3.5), c + Vec2::new(3.5, 3.5)], s);
            painter.line_segment([c + Vec2::new(3.5, -3.5), c + Vec2::new(-3.5, 3.5)], s);
        }
    }
}

fn success_mark(ui: &mut egui::Ui, p: &Palette, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    draw_check(ui.painter(), rect.center(), size / 2.0, p.success_text, p.surface);
}

fn draw_check(painter: &egui::Painter, c: egui::Pos2, radius: f32, fill: Color32, mark: Color32) {
    painter.circle_filled(c, radius, fill);
    let k = radius / 9.0;
    let s = Stroke::new(2.0 * k.max(0.9), mark);
    painter.line_segment([c + Vec2::new(-4.0, 0.5) * k, c + Vec2::new(-1.2, 3.3) * k], s);
    painter.line_segment([c + Vec2::new(-1.2, 3.3) * k, c + Vec2::new(4.5, -3.0) * k], s);
}

fn primary(ui: &mut egui::Ui, p: &Palette, text: &str, enabled: bool) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new((Atom::grow(), RichText::new(text).family(semibold()).color(p.on_accent), Atom::grow()))
            .fill(p.accent)
            .stroke(Stroke::NONE)
            .min_size(Vec2::new(120.0, 34.0)),
    )
}

fn danger(ui: &mut egui::Ui, p: &Palette, text: &str, enabled: bool) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new((Atom::grow(), RichText::new(text).family(semibold()).color(p.on_danger), Atom::grow()))
            .fill(p.danger_fill)
            .stroke(Stroke::NONE)
            .min_size(Vec2::new(120.0, 34.0)),
    )
}

fn secondary(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(egui::Button::new((Atom::grow(), text, Atom::grow())).min_size(Vec2::new(96.0, 34.0)))
}
