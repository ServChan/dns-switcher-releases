//! Установка и удаление. Программа устанавливает сама себя: копирует свой exe
//! в Program Files, создаёт ярлыки и запись в «Приложениях» Windows.

use crate::apply::{self, Action};
use crate::monitor;
use crate::net;
use crate::state::{self, RuntimeState};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    IDYES, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_YESNO, MessageBoxW,
};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

pub const APP_NAME: &str = "Переключатель DNS";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const EXE_NAME: &str = "dns-switcher.exe";
const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DnsSwitcher";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DETACHED_PROCESS: u32 = 0x0000_0008;

pub fn install_dir() -> PathBuf {
    let base = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| r"C:\Program Files".into());
    base.join("DnsSwitcher")
}

pub fn installed_exe() -> PathBuf {
    install_dir().join(EXE_NAME)
}

fn same_path(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Программа запущена из папки установки.
pub fn running_installed() -> bool {
    std::env::current_exe().map(|exe| same_path(&exe, &installed_exe())).unwrap_or(false)
}

/// Версия, записанная в «Приложениях», если программа уже установлена.
pub fn installed_version() -> Option<String> {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(UNINSTALL_KEY)
        .and_then(|k| k.get_value::<String, _>("DisplayVersion"))
        .ok()
        .filter(|_| installed_exe().exists())
}

fn start_menu_link() -> PathBuf {
    let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| r"C:\ProgramData".into());
    base.join(r"Microsoft\Windows\Start Menu\Programs").join(format!("{APP_NAME}.lnk"))
}

fn desktop_link() -> PathBuf {
    let base = std::env::var_os("PUBLIC").map(PathBuf::from).unwrap_or_else(|| r"C:\Users\Public".into());
    base.join("Desktop").join(format!("{APP_NAME}.lnk"))
}

/// Останавливает фоновое задание и другие копии программы, чтобы exe можно было заменить.
fn stop_other_instances() {
    let _ = apply::run_tool("schtasks", &["/End", "/TN", monitor::TASK_NAME]);
    let pid_filter = format!("PID ne {}", std::process::id());
    let _ = apply::run_tool("taskkill", &["/F", "/IM", EXE_NAME, "/FI", &pid_filter]);
    std::thread::sleep(std::time::Duration::from_millis(700));
}

pub fn install(desktop_shortcut: bool) -> Result<(), String> {
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = install_dir();
    let target = installed_exe();
    stop_other_instances();

    std::fs::create_dir_all(&dir).map_err(|e| format!("Не удалось создать {}: {e}", dir.display()))?;
    if !same_path(&source, &target) {
        let mut last_err = None;
        for _ in 0..10 {
            match std::fs::copy(&source, &target) {
                Ok(_) => {
                    last_err = None;
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(400));
                }
            }
        }
        if let Some(e) = last_err {
            return Err(format!("Не удалось скопировать программу в {}: {e}", dir.display()));
        }
    }

    register_uninstall(&target)?;
    create_shortcut(&start_menu_link(), &target)?;
    if desktop_shortcut {
        create_shortcut(&desktop_link(), &target)?;
    }

    // Фоновое задание указывает на exe; пересоздаём его, чтобы оно смотрело на новую копию.
    if monitor::task_installed() {
        monitor::install_task_for(&target)?;
    }
    state::log(&format!("Установлена версия {VERSION} в {}.", dir.display()));
    Ok(())
}

fn register_uninstall(exe: &Path) -> Result<(), String> {
    let (key, _) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .create_subkey(UNINSTALL_KEY)
        .map_err(|e| format!("Не удалось записать сведения об установке: {e}"))?;
    let exe_text = exe.to_string_lossy().to_string();
    let size_kb = std::fs::metadata(exe).map(|m| (m.len() / 1024) as u32).unwrap_or(0);
    let set = |name: &str, value: &str| key.set_value(name, &value.to_string());
    set("DisplayName", APP_NAME)
        .and_then(|_| set("DisplayVersion", VERSION))
        .and_then(|_| set("Publisher", "DnsSwitcher"))
        .and_then(|_| set("DisplayIcon", &exe_text))
        .and_then(|_| set("InstallLocation", &install_dir().to_string_lossy()))
        .and_then(|_| set("UninstallString", &format!("\"{exe_text}\" --uninstall")))
        .and_then(|_| key.set_value("NoModify", &1u32))
        .and_then(|_| key.set_value("NoRepair", &1u32))
        .and_then(|_| key.set_value("EstimatedSize", &size_kb))
        .map_err(|e| format!("Не удалось записать сведения об установке: {e}"))
}

fn create_shortcut(link: &Path, target: &Path) -> Result<(), String> {
    let q = |p: &Path| p.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{}'); \
         $s.TargetPath = '{}'; $s.WorkingDirectory = '{}'; $s.IconLocation = '{},0'; \
         $s.Description = 'Смена DNS, обход ограничений ИИ и защита от сбоев'; $s.Save()",
        q(link),
        q(target),
        q(target.parent().unwrap_or(Path::new("."))),
        q(target)
    );
    apply::run_tool("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script])
        .map_err(|e| format!("Не удалось создать ярлык {}: {e}", link.display()))
}

/// Запускает установленную программу отдельно от установщика.
pub fn launch_installed() -> Result<(), String> {
    Command::new(installed_exe())
        .creation_flags(DETACHED_PROCESS)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Не удалось запустить программу: {e}"))
}

// ---------- Удаление ----------

fn message(text: &str, flags: u32) -> i32 {
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (text, title) = (wide(text), wide(APP_NAME));
    unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), flags) }
}

/// `dns-switcher.exe --uninstall`, вызывается из «Приложений» Windows.
pub fn uninstall_interactive() {
    let ask = format!("Удалить «{APP_NAME}»?\n\nСписок серверов и журнал в %APPDATA%\\DnsSwitcher останутся.");
    if message(&ask, MB_YESNO | MB_ICONQUESTION) != IDYES {
        return;
    }

    let st = RuntimeState::load();
    let managed = st.active.is_some() || st.on_dhcp_fallback;
    let reset_dns = managed
        && message(
            "Вернуть DNS подключений на автоматический (от роутера или провайдера)?\n\n\
             «Нет» оставит текущие DNS-серверы. Защита от сбоев после удаления работать не будет.",
            MB_YESNO | MB_ICONQUESTION,
        ) == IDYES;

    let _ = monitor::remove_task();
    stop_other_instances();
    if reset_dns {
        let adapters: Vec<_> = net::list_adapters()
            .unwrap_or_default()
            .into_iter()
            .filter(|a| st.adapters.contains(&a.guid))
            .collect();
        apply::run(&Action::Reset, &adapters);
        let _ = RuntimeState::default().save();
    }
    let _ = std::fs::remove_file(start_menu_link());
    let _ = std::fs::remove_file(desktop_link());
    let _ = RegKey::predef(HKEY_LOCAL_MACHINE).delete_subkey_all(UNINSTALL_KEY);
    state::log("Программа удалена.");

    // Свой exe удалить нельзя, пока он работает: папку удалит cmd через пару секунд.
    let dir = install_dir();
    if running_installed() {
        let cmd = format!("ping -n 3 127.0.0.1 >nul & rmdir /s /q \"{}\"", dir.display());
        let _ = Command::new("cmd")
            .args(["/C", &cmd])
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
            .spawn();
    } else {
        let _ = std::fs::remove_dir_all(&dir);
    }
    message(&format!("«{APP_NAME}» удалён."), MB_OK | MB_ICONINFORMATION);
}
