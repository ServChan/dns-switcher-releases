//! Установка и удаление. Программа устанавливает сама себя: копирует свой exe
//! в выбранную папку, создаёт ярлыки, задания Планировщика и запись в «Приложениях».
//! Работа разбита на шаги, чтобы мастер показывал прогресс.

use crate::apply::{self, Action};
use crate::config::{Config, data_dir};
use crate::net;
use crate::state::{self, RuntimeState};
use crate::{monitor, tasks};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

pub const APP_NAME: &str = "Переключатель DNS";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const EXE_NAME: &str = "dns-switcher.exe";
const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DnsSwitcher";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DETACHED_PROCESS: u32 = 0x0000_0008;
/// Папка для скачанных обновлений внутри папки установки: туда может писать только администратор.
pub const UPDATES_DIR: &str = "updates";

#[derive(Clone)]
pub struct InstallOptions {
    pub dir: PathBuf,
    pub start_menu: bool,
    pub desktop: bool,
    pub no_uac: bool,
    pub background: bool,
}

#[derive(Clone)]
pub struct UninstallOptions {
    pub reset_dns: bool,
    pub remove_settings: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Step {
    StopRunning,
    CopyFiles,
    Shortcuts,
    Register,
    Launcher,
    Background,
    RemoveTasks,
    ResetDns,
    RemoveShortcuts,
    Unregister,
    RemoveSettings,
    RemoveFiles,
}

impl Step {
    pub fn title(self) -> &'static str {
        match self {
            Step::StopRunning => "Закрываю запущенную программу",
            Step::CopyFiles => "Копирую файлы",
            Step::Shortcuts => "Создаю ярлыки",
            Step::Register => "Добавляю в «Приложения» Windows",
            Step::Launcher => "Настраиваю запуск без запроса UAC",
            Step::Background => "Настраиваю фоновую защиту от сбоев",
            Step::RemoveTasks => "Убираю задания из Планировщика",
            Step::ResetDns => "Возвращаю автоматический DNS",
            Step::RemoveShortcuts => "Удаляю ярлыки",
            Step::Unregister => "Убираю из «Приложений» Windows",
            Step::RemoveSettings => "Удаляю список серверов и настройки",
            Step::RemoveFiles => "Удаляю файлы программы",
        }
    }
}

pub fn install_plan() -> Vec<Step> {
    vec![Step::StopRunning, Step::CopyFiles, Step::Shortcuts, Step::Register, Step::Launcher, Step::Background]
}

pub fn uninstall_plan(opts: &UninstallOptions) -> Vec<Step> {
    let mut plan = vec![Step::StopRunning, Step::RemoveTasks];
    if opts.reset_dns {
        plan.push(Step::ResetDns);
    }
    plan.extend([Step::RemoveShortcuts, Step::Unregister]);
    if opts.remove_settings {
        plan.push(Step::RemoveSettings);
    }
    plan.push(Step::RemoveFiles);
    plan
}

// ---------- Где что лежит ----------

pub fn default_dir() -> PathBuf {
    let base = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| r"C:\Program Files".into());
    base.join("DnsSwitcher")
}

/// Папка, куда программа уже установлена.
pub fn installed_dir() -> Option<PathBuf> {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(UNINSTALL_KEY)
        .and_then(|k| k.get_value::<String, _>("InstallLocation"))
        .ok()
        .map(PathBuf::from)
        .filter(|d| d.join(EXE_NAME).exists())
}

pub fn installed_version() -> Option<String> {
    installed_dir()?;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(UNINSTALL_KEY)
        .and_then(|k| k.get_value::<String, _>("DisplayVersion"))
        .ok()
}

fn same_path(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Программа запущена из папки установки.
pub fn running_installed() -> bool {
    let Some(dir) = installed_dir() else { return false };
    std::env::current_exe().map(|exe| same_path(&exe, &dir.join(EXE_NAME))).unwrap_or(false)
}

/// Папка внутри Program Files: менять там файлы может только администратор.
/// Это важно, потому что задания запускают программу с наивысшими правами.
pub fn is_protected_dir(dir: &Path) -> bool {
    ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .any(|var| std::env::var_os(var).is_some_and(|base| crate::sys::is_inside(dir, Path::new(&base))))
}

/// Копия, установленная прежними версиями вне Program Files: её задания запускали бы
/// с правами администратора файл, который может подменить любая программа.
/// Убирает такие задания и пишет в журнал, что делать.
pub fn drop_unsafe_tasks() {
    let Some(dir) = installed_dir() else { return };
    if is_protected_dir(&dir) {
        return;
    }
    let mut removed = Vec::new();
    for name in [tasks::LAUNCHER, tasks::WATCHDOG] {
        if tasks::exists(name) && tasks::remove(name).is_ok() {
            removed.push(name);
        }
    }
    if !removed.is_empty() {
        state::log(&format!(
            "Программа установлена вне Program Files ({}), поэтому задания {} убраны: через них можно было \
             подменить программу и получить права администратора. Чтобы вернуть фоновую защиту и запуск \
             без UAC, переустановите программу в Program Files.",
            dir.display(),
            removed.join(" и ")
        ));
    }
}

/// Программа сейчас управляет DNS подключений (было «Применить»).
pub fn manages_dns() -> bool {
    let st = RuntimeState::load();
    st.active.is_some() || st.on_dhcp_fallback
}

fn start_menu_link() -> PathBuf {
    let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| r"C:\ProgramData".into());
    base.join(r"Microsoft\Windows\Start Menu\Programs").join(format!("{APP_NAME}.lnk"))
}

fn desktop_link() -> PathBuf {
    let base = std::env::var_os("PUBLIC").map(PathBuf::from).unwrap_or_else(|| r"C:\Users\Public".into());
    base.join("Desktop").join(format!("{APP_NAME}.lnk"))
}

// ---------- Выполнение шагов ----------

pub fn run_install_step(step: Step, opts: &InstallOptions) -> Result<(), String> {
    let exe = opts.dir.join(EXE_NAME);
    match step {
        Step::StopRunning => {
            stop_other_instances();
            Ok(())
        }
        Step::CopyFiles => copy_self(&opts.dir, &exe),
        Step::Shortcuts => {
            for (want, link) in [(opts.start_menu, start_menu_link()), (opts.desktop, desktop_link())] {
                if want {
                    create_shortcut(&link, &exe)?;
                } else {
                    let _ = std::fs::remove_file(link);
                }
            }
            Ok(())
        }
        Step::Register => register_uninstall(&opts.dir, &exe),
        Step::Launcher => {
            if opts.no_uac {
                tasks::create(
                    tasks::LAUNCHER,
                    &exe,
                    "",
                    false,
                    "Переключатель DNS: открывает программу с правами администратора без запроса UAC.",
                )
            } else {
                tasks::remove(tasks::LAUNCHER)
            }
        }
        Step::Background => {
            let mut cfg = Config::load();
            cfg.failover.background = opts.background;
            if opts.background {
                cfg.failover.enabled = true;
            }
            cfg.save()?;
            let result = if opts.background { monitor::install_task_for(&exe) } else { monitor::remove_task() };
            state::log(&format!("Установлена версия {VERSION} в {}.", opts.dir.display()));
            result
        }
        _ => Ok(()),
    }
}

pub fn run_uninstall_step(step: Step, dir: Option<&Path>) -> Result<(), String> {
    match step {
        Step::StopRunning => {
            stop_other_instances();
            Ok(())
        }
        Step::RemoveTasks => tasks::remove(tasks::WATCHDOG).and(tasks::remove(tasks::LAUNCHER)),
        Step::ResetDns => {
            let st = RuntimeState::load();
            let adapters: Vec<_> = net::list_adapters()
                .unwrap_or_default()
                .into_iter()
                .filter(|a| st.adapters.contains(&a.guid))
                .collect();
            let outcomes = apply::run(&Action::Reset, &adapters);
            let _ = RuntimeState::default().save();
            match outcomes.iter().find_map(|o| o.result.as_ref().err()) {
                Some(e) => Err(format!("DNS не сброшен: {e}")),
                None => Ok(()),
            }
        }
        Step::RemoveShortcuts => {
            let _ = std::fs::remove_file(start_menu_link());
            let _ = std::fs::remove_file(desktop_link());
            Ok(())
        }
        Step::Unregister => {
            state::log("Программа удалена.");
            match RegKey::predef(HKEY_LOCAL_MACHINE).delete_subkey_all(UNINSTALL_KEY) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("Не удалось убрать запись: {e}")),
                _ => Ok(()),
            }
        }
        Step::RemoveSettings => match std::fs::remove_dir_all(data_dir()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("Не удалось удалить настройки: {e}")),
            _ => Ok(()),
        },
        Step::RemoveFiles => {
            // Папку запоминает мастер до начала: запись в реестре к этому шагу уже удалена.
            // Удаляются только свои файлы: папку могли выбрать общую (например, D:\Tools),
            // и чужое в ней должно остаться. Сама папка удаляется, только если опустела.
            let Some(dir) = dir else { return Ok(()) };
            let _ = std::fs::remove_dir_all(dir.join(UPDATES_DIR));
            if running_from(dir) {
                schedule_dir_removal(dir);
                return Ok(());
            }
            match std::fs::remove_file(dir.join(EXE_NAME)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    Err(format!("Не удалось удалить {}: {e}", dir.join(EXE_NAME).display()))
                }
                _ => {
                    let _ = std::fs::remove_dir(dir);
                    Ok(())
                }
            }
        }
        _ => Ok(()),
    }
}

fn running_from(dir: &Path) -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| same_path(p, dir)))
        .unwrap_or(false)
}

/// Свой exe удалить нельзя, пока он работает: cmd удалит его после выхода,
/// повторяя попытки до двух минут, а затем папку, если в ней больше ничего нет.
fn schedule_dir_removal(dir: &Path) {
    let d = dir.display();
    let exe = dir.join(EXE_NAME);
    let e = exe.display();
    let cmd = format!(
        "/C \"for /L %i in (1,1,120) do @(if exist \"{e}\" (del /f /q \"{e}\" 2>nul & ping -n 2 127.0.0.1 >nul)) & rmdir \"{d}\" 2>nul\""
    );
    let _ = Command::new(crate::sys::tool("cmd"))
        .raw_arg(cmd)
        .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
        .spawn();
}

/// Останавливает фоновое задание и другие копии программы, чтобы exe можно было заменить.
fn stop_other_instances() {
    let _ = apply::run_tool("schtasks", &["/End", "/TN", tasks::WATCHDOG]);
    crate::sys::terminate_others(EXE_NAME);
    std::thread::sleep(std::time::Duration::from_millis(700));
}

fn copy_self(dir: &Path, target: &Path) -> Result<(), String> {
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("Не удалось создать {}: {e}", dir.display()))?;
    if same_path(&source, target) {
        return Ok(());
    }
    let mut last_err = None;
    for _ in 0..10 {
        match std::fs::copy(&source, target) {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
        }
    }
    Err(format!(
        "Не удалось скопировать программу в {}: {}. Закройте её, если она открыта, и нажмите «Повторить».",
        dir.display(),
        last_err.map(|e| e.to_string()).unwrap_or_default()
    ))
}

fn register_uninstall(dir: &Path, exe: &Path) -> Result<(), String> {
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
        .and_then(|_| set("InstallLocation", &dir.to_string_lossy()))
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

/// Параметры уже установленной копии: обновление сохраняет их как есть.
pub fn current_options() -> InstallOptions {
    InstallOptions {
        dir: installed_dir().unwrap_or_else(default_dir),
        start_menu: start_menu_link().exists(),
        desktop: desktop_link().exists(),
        no_uac: tasks::exists(tasks::LAUNCHER),
        background: tasks::exists(tasks::WATCHDOG),
    }
}

/// `--update`: тихое обновление без окна мастера, затем запуск программы.
pub fn silent_update() -> Result<(), String> {
    let opts = current_options();
    for step in install_plan() {
        run_install_step(step, &opts).map_err(|e| format!("{}: {e}", step.title()))?;
    }
    launch(&opts.dir)
}

/// Запускает установленную программу отдельно от установщика.
pub fn launch(dir: &Path) -> Result<(), String> {
    // Разрешаем новому окну выйти на передний план: иначе Windows откроет его позади.
    unsafe { windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow(u32::MAX) };
    Command::new(dir.join(EXE_NAME))
        .creation_flags(DETACHED_PROCESS)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Не удалось запустить программу: {e}"))
}
