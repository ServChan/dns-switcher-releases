//! Окно установки. Показывается, когда программа запущена не из папки установки
//! (например, DnsSwitcher-Setup.exe из «Загрузок»).

use crate::install;
use crate::theme::{self, palette, semibold};
use eframe::egui::{self, Align, ColorImage, CornerRadius, Frame, Layout, Margin, RichText, Stroke, TextureHandle, Vec2};
use std::sync::mpsc::{Receiver, channel};

enum Stage {
    Ready,
    Installing(Receiver<Result<(), String>>),
    Done,
    Failed(String),
}

pub enum Choice {
    Stay,
    /// Пользователь выбрал «Запустить без установки».
    RunPortable,
}

pub struct InstallerApp {
    stage: Stage,
    desktop: bool,
    launch_after: bool,
    existing: Option<String>,
    icon: Option<TextureHandle>,
}

impl InstallerApp {
    pub fn new(ctx: &egui::Context) -> Self {
        theme::install(ctx);
        let rgba = include_bytes!("../assets/icon-64.rgba");
        let image = ColorImage::from_rgba_unmultiplied([64, 64], rgba);
        Self {
            stage: Stage::Ready,
            desktop: true,
            launch_after: true,
            existing: install::installed_version(),
            icon: Some(ctx.load_texture("app-icon", image, Default::default())),
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        let (tx, rx) = channel();
        let desktop = self.desktop;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(install::install(desktop));
            ctx.request_repaint();
        });
        self.stage = Stage::Installing(rx);
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Choice {
        let ctx = ui.ctx().clone();
        let p = palette(ui);
        let mut choice = Choice::Stay;

        if let Stage::Installing(rx) = &self.stage {
            if let Ok(result) = rx.try_recv() {
                self.stage = match result {
                    Ok(()) if self.launch_after => match install::launch_installed() {
                        Ok(()) => {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            Stage::Done
                        }
                        Err(e) => Stage::Failed(e),
                    },
                    Ok(()) => Stage::Done,
                    Err(e) => Stage::Failed(e),
                };
            }
        }

        egui::CentralPanel::default_margins()
            .frame(Frame::new().fill(p.bg).inner_margin(Margin::same(28)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if let Some(icon) = &self.icon {
                        ui.add(egui::Image::new(icon).fit_to_exact_size(Vec2::splat(48.0)));
                    }
                    ui.add_space(6.0);
                    ui.vertical(|ui| {
                        ui.heading(install::APP_NAME);
                        ui.label(RichText::new(format!("Версия {}", install::VERSION)).color(p.text_weak));
                    });
                });
                ui.add_space(14.0);
                ui.add(
                    egui::Label::new(
                        "Быстрая смена DNS, серверы для обхода региональных ограничений ИИ \
                         и автоматическое переключение на резервный сервер при сбое.",
                    )
                    .wrap(),
                );
                ui.add_space(18.0);

                Frame::new()
                    .fill(p.surface)
                    .stroke(Stroke::new(1.0, p.border))
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::same(16))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new("Папка установки").color(p.text_weak));
                        ui.label(RichText::new(install::install_dir().to_string_lossy()).monospace());
                        if let Some(v) = &self.existing {
                            ui.add_space(8.0);
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!(
                                        "Уже установлена версия {v}. Она будет обновлена, \
                                         список серверов и настройки сохранятся."
                                    ))
                                    .color(p.accent_text),
                                )
                                .wrap(),
                            );
                        }
                        ui.add_space(10.0);
                        let ready = matches!(self.stage, Stage::Ready | Stage::Failed(_));
                        ui.add_enabled_ui(ready, |ui| {
                            ui.checkbox(&mut self.desktop, "Ярлык на рабочем столе");
                            ui.checkbox(&mut self.launch_after, "Запустить после установки");
                        });
                    });

                ui.add_space(12.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "Программа меняет сетевые настройки Windows, поэтому всегда запускается \
                             от имени администратора: при запуске Windows попросит подтверждение.",
                        )
                        .small()
                        .color(p.text_weak),
                    )
                    .wrap(),
                );

                ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                    match &self.stage {
                        Stage::Ready | Stage::Failed(_) => {
                            if ui.link(RichText::new("Запустить без установки").color(p.accent_text)).clicked() {
                                choice = Choice::RunPortable;
                            }
                            ui.add_space(8.0);
                            let label = if self.existing.is_some() { "Обновить" } else { "Установить" };
                            if big_button(ui, p, label).clicked() {
                                self.start(&ctx);
                            }
                            if let Stage::Failed(e) = &self.stage {
                                ui.add_space(8.0);
                                ui.add(egui::Label::new(RichText::new(e).color(p.text)).wrap());
                                ui.label(RichText::new("Не получилось").family(semibold()).color(p.danger_text));
                            }
                        }
                        Stage::Installing(_) => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label("Устанавливаю…");
                            });
                        }
                        Stage::Done => {
                            ui.horizontal(|ui| {
                                if ui.button("Закрыть").clicked() {
                                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                }
                                if big_button_inline(ui, p, "Открыть программу").clicked() {
                                    if install::launch_installed().is_ok() {
                                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                    }
                                }
                            });
                            ui.add_space(8.0);
                            ui.label(
                                RichText::new("Готово. Программа есть в меню «Пуск».").family(semibold()).color(p.success_text),
                            );
                        }
                    }
                });
            });
        choice
    }
}

fn big_button(ui: &mut egui::Ui, p: &theme::Palette, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new((egui::Atom::grow(), RichText::new(text).family(semibold()).color(p.on_accent), egui::Atom::grow()))
            .fill(p.accent)
            .stroke(Stroke::NONE)
            .min_size(Vec2::new(ui.available_width(), 40.0)),
    )
}

fn big_button_inline(ui: &mut egui::Ui, p: &theme::Palette, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new((egui::Atom::grow(), RichText::new(text).family(semibold()).color(p.on_accent), egui::Atom::grow()))
            .fill(p.accent)
            .stroke(Stroke::NONE)
            .min_size(Vec2::new(160.0, 32.0)),
    )
}
