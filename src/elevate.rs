//! Права администратора и единственный экземпляр окна.
//!
//! Программа запускается с обычными правами и сама поднимает их: через задание
//! «DnsSwitcher Launcher» без запроса UAC, если его создал установщик, иначе
//! через стандартный запрос UAC.

use crate::{install, tasks};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, IsIconic, MB_ICONWARNING, MB_OK, MessageBoxW, SW_RESTORE, SW_SHOWNORMAL, SetForegroundWindow,
    ShowWindow,
};

pub const WINDOW_TITLE: &str = "Переключатель DNS";
const GUI_LOCK: &str = "Local\\DnsSwitcherGui";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Простое окно сообщения, когда своего окна у процесса нет.
pub fn message_box(text: &str) {
    let (text, title) = (wide(text), wide(WINDOW_TITLE));
    unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONWARNING) };
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

/// Перезапускает текущий exe с правами администратора (запрос UAC).
pub fn relaunch_as_admin(args: &[String]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let params = args
        .iter()
        .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ");
    let (verb, file, params) = (wide("runas"), wide(&exe.to_string_lossy()), wide(&params));
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // Значение больше 32 означает успех; иначе пользователь отказал в UAC или ошибка.
    if result as usize > 32 { Ok(()) } else { Err("Права администратора не получены.".into()) }
}

/// Решает, продолжать ли работу в этом процессе. `false`: запущена копия
/// с правами администратора, а этот процесс должен завершиться.
pub fn ensure_admin(args: &[String]) -> bool {
    if is_admin() || cfg!(debug_assertions) || args.iter().any(|a| a == "--no-elevate") {
        return true;
    }
    // Ярлык установленной программы: быстрый запуск через задание без UAC.
    if args.is_empty() && install::running_installed() && tasks::exists(tasks::LAUNCHER) && tasks::run(tasks::LAUNCHER).is_ok()
    {
        return false;
    }
    // Если в UAC отказали, окно откроется без прав и предложит запросить их снова.
    relaunch_as_admin(args).is_err()
}

/// Не даёт открыть второе окно: выводит вперёд уже открытое и возвращает None.
pub struct GuiLock(HANDLE);

impl Drop for GuiLock {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Один мастер установки за раз: два одновременных мастера мешали бы друг другу
/// копировать файлы и создавать задания. None — мастер уже открыт.
pub fn setup_lock() -> Option<GuiLock> {
    let name = wide("Local\\DnsSwitcherSetup");
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if h.is_null() {
        return None;
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe { CloseHandle(h) };
        return None;
    }
    Some(GuiLock(h))
}

/// `wait`: окно перезапускается с правами администратора, а старая копия
/// ещё закрывается, поэтому ждём её до пяти секунд.
pub fn single_instance(wait: bool) -> Option<GuiLock> {
    let name = wide(GUI_LOCK);
    let attempts = if wait { 25 } else { 1 };
    for attempt in 0..attempts {
        let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        // Пустой дескриптор: мьютекс создала копия с правами администратора, и обычному
        // процессу доступ к нему закрыт. Это тоже значит, что окно уже открыто.
        if !h.is_null() {
            if unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
                return Some(GuiLock(h));
            }
            unsafe { CloseHandle(h) };
        }
        if attempt + 1 < attempts {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
    let title = wide(WINDOW_TITLE);
    let hwnd = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
    if !hwnd.is_null() {
        unsafe {
            if IsIconic(hwnd) != 0 {
                ShowWindow(hwnd, SW_RESTORE);
            }
            SetForegroundWindow(hwnd);
        }
    }
    None
}
