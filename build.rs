use embed_manifest::manifest::{DpiAwareness, ExecutionLevel};
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    // Смена DNS требует прав администратора, поэтому Windows сразу спросит их при запуске.
    // DNS_SWITCHER_AS_INVOKER=1 собирает версию без запроса прав (для отладки интерфейса).
    println!("cargo:rerun-if-env-changed=DNS_SWITCHER_AS_INVOKER");
    let level = if std::env::var_os("DNS_SWITCHER_AS_INVOKER").is_some() {
        ExecutionLevel::AsInvoker
    } else {
        ExecutionLevel::RequireAdministrator
    };
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
