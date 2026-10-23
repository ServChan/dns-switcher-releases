#![windows_subsystem = "windows"]

mod apply;
mod browsers;
mod config;
mod doh;
mod elevate;
mod health;
mod install;
mod installer;
mod monitor;
mod net;
mod state;
mod sys;
mod tasks;
mod theme;
mod tray;
mod ui;
mod update;

use eframe::egui;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);
    // Фоновая защита из Планировщика заданий: без окна, только слежение.
    if has("--watch") {
        monitor::run_loop(Arc::new(AtomicBool::new(false)), false);
        return Ok(());
    }
    if !elevate::ensure_admin(&args) {
        return Ok(()); // работу продолжает копия с правами администратора
    }
    // Тихое обновление из скачанного установщика: без окна мастера.
    if has("--update") {
        if let Err(e) = install::silent_update() {
            state::log(&format!("Обновление не удалось: {e}"));
            elevate::message_box(&format!("Обновление не удалось.\n\n{e}"));
        }
        return Ok(());
    }

    // Запуск не из папки установки открывает мастер (в отладочной сборке не мешает).
    let wizard = if has("--uninstall") {
        Some(installer::Mode::Uninstall)
    } else if cfg!(debug_assertions) {
        std::env::var_os("DNS_SWITCHER_DEBUG_INSTALLER").map(|_| installer::Mode::Install)
    } else if !install::running_installed() && !has("--portable") {
        Some(installer::Mode::Install)
    } else {
        None
    };
    // Второе окно программы не открываем, а выводим вперёд первое.
    // Отладочной сборке правило не мешает: её окно открывается рядом с установленным.
    let gui_lock = match wizard {
        Some(_) => None,
        None if cfg!(debug_assertions) => None,
        None => match elevate::single_instance(has("--wait-gui")) {
            Some(lock) => Some(lock),
            None => return Ok(()),
        },
    };

    let (title, size, min) = match wizard {
        Some(_) => (installer::INSTALLER_TITLE, [660.0, 660.0], [580.0, 560.0]),
        None => (elevate::WINDOW_TITLE, MAIN_SIZE, [760.0, 560.0]),
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size(size)
            .with_min_inner_size(min)
            .with_resizable(wizard.is_none())
            .with_icon(egui::IconData {
                rgba: include_bytes!("../assets/icon-64.rgba").to_vec(),
                width: 64,
                height: 64,
            }),
        ..Default::default()
    };
    eframe::run_native(
        title,
        options,
        Box::new(move |cc| {
            let root = match wizard {
                Some(mode) => Root::Wizard(installer::Wizard::new(&cc.egui_ctx, mode)),
                None => Root::Main { app: ui::DnsApp::new(&cc.egui_ctx), _lock: gui_lock },
            };
            Ok(Box::new(root))
        }),
    )
}

const MAIN_SIZE: [f32; 2] = [980.0, 780.0];

enum Root {
    Wizard(installer::Wizard),
    Main { app: ui::DnsApp, _lock: Option<elevate::GuiLock> },
}

impl eframe::App for Root {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        match self {
            Root::Main { app, .. } => app.ui(ui),
            Root::Wizard(wizard) => {
                if let installer::Choice::RunPortable = wizard.ui(ui) {
                    let ctx = ui.ctx().clone();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Title(elevate::WINDOW_TITLE.into()));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Resizable(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(MAIN_SIZE.into()));
                    *self = Root::Main { app: ui::DnsApp::new(&ctx), _lock: elevate::single_instance(false) };
                }
            }
        }
    }
}
