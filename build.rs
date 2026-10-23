use embed_manifest::manifest::{DpiAwareness, ExecutionLevel};
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    // Права администратора программа запрашивает сама при запуске (src/elevate.rs):
    // так ярлык может открывать её через задание Планировщика без окна UAC.
    let level = ExecutionLevel::AsInvoker;
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest(
            new_manifest("DnsSwitcher")
                .requested_execution_level(level)
                .dpi_awareness(DpiAwareness::PerMonitorV2),
        )
        .expect("не удалось встроить манифест");
        winresource::WindowsResource::new()
            .set_icon("assets/icon.ico")
            .set("FileDescription", "Переключатель DNS")
            .set("ProductName", "Переключатель DNS")
            .compile()
            .expect("не удалось встроить значок");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon.ico");
}
