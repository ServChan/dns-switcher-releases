#![windows_subsystem = "windows"]

mod apply;
mod config;
mod doh;
mod health;
mod install;
mod installer;
mod monitor;
mod net;
mod state;
mod theme;
mod ui;

use eframe::egui;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);
    // Фоновая защита из Планировщика заданий: без окна, только слежение.
    if has("--watch") {
        monitor::run_loop(Arc::new(AtomicBool::new(false)), false);
        return Ok(());
    }
    if has("--uninstall") {
        install::uninstall_interactive();
        return Ok(());
    }
    // Запуск не из Program Files открывает установщик (в отладочной сборке не мешает).
    let show_installer = if cfg!(debug_assertions) {
        std::env::var_os("DNS_SWITCHER_DEBUG_INSTALLER").is_some()
    } else {
        !install::running_installed() && !has("--portable")
    };
    let size = if show_installer { [560.0, 560.0] } else { MAIN_SIZE };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Переключатель DNS")
            .with_inner_size(size)
            .with_min_inner_size([760.0, 560.0])
            .with_icon(egui::IconData {
                rgba: include_bytes!("../assets/icon-64.rgba").to_vec(),
                width: 64,
                height: 64,
            }),
        ..Default::default()
    };
    eframe::run_native(
        "Переключатель DNS",
        options,
        Box::new(move |cc| {
            let root = if show_installer {
                Root::Installer(installer::InstallerApp::new(&cc.egui_ctx))
            } else {
                Root::Main(ui::DnsApp::new(&cc.egui_ctx))
            };
            Ok(Box::new(root))
        }),
    )
}

const MAIN_SIZE: [f32; 2] = [980.0, 780.0];

enum Root {
    Installer(installer::InstallerApp),
    Main(ui::DnsApp),
}

impl eframe::App for Root {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        match self {
            Root::Main(app) => app.ui(ui),
            Root::Installer(inst) => {
                if let installer::Choice::RunPortable = inst.ui(ui) {
                    let ctx = ui.ctx().clone();
                    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(MAIN_SIZE.into()));
                    *self = Root::Main(ui::DnsApp::new(&ctx));
                }
            }
        }
    }
}

pub fn is_admin() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}
