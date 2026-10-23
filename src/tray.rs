//! Значок в области уведомлений и уведомления Windows. Значок держит процесс,
//! который ведёт защиту от сбоев: окно программы или фоновое задание.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIIF_WARNING, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, ChangeWindowMessageFilterEx, CreatePopupMenu, MSGFLT_ALLOW, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW,
    GetCursorPos, GetMessageW, LoadIconW, MF_SEPARATOR, MF_STRING, MSG, PostMessageW, PostQuitMessage,
    RegisterClassW, RegisterWindowMessageW, SetForegroundWindow, TPM_BOTTOMALIGN, TPM_RETURNCMD, TPM_RIGHTBUTTON,
    TrackPopupMenu, TranslateMessage, WM_APP, WM_CLOSE, WM_DESTROY, WM_LBUTTONUP, WM_RBUTTONUP, WNDCLASSW,
};

const WM_TRAY: u32 = WM_APP + 1;
const CMD_OPEN: usize = 1;
const CMD_CHECK: usize = 2;

/// Окно значка; 0, пока значка нет.
static HWND_VALUE: AtomicIsize = AtomicIsize::new(0);
/// Подсказка значка: нужна, чтобы вернуть его после перезапуска Проводника.
static TIP: Mutex<String> = Mutex::new(String::new());
/// «Проверить сейчас» из меню: цикл защиты проверяет этот флаг во время ожидания.
pub static CHECK_NOW: AtomicBool = AtomicBool::new(false);
static TASKBAR_CREATED: AtomicIsize = AtomicIsize::new(0);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn copy_into(dst: &mut [u16], text: &str) {
    let src: Vec<u16> = text.encode_utf16().take(dst.len() - 1).collect();
    dst[..src.len()].copy_from_slice(&src);
    dst[src.len()] = 0;
}

fn hwnd() -> HWND {
    HWND_VALUE.load(Ordering::Relaxed) as HWND
}

fn base_data(hwnd: HWND) -> NOTIFYICONDATAW {
    let mut d: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    d.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    d.hWnd = hwnd;
    d.uID = 1;
    d
}

fn add_icon(hwnd: HWND) {
    let mut d = base_data(hwnd);
    d.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    d.uCallbackMessage = WM_TRAY;
    // Значок программы лежит в ресурсах exe под номером 1 (build.rs).
    d.hIcon = unsafe { LoadIconW(GetModuleHandleW(std::ptr::null()), 1 as *const u16) };
    copy_into(&mut d.szTip, &TIP.lock().map(|t| t.clone()).unwrap_or_default());
    unsafe { Shell_NotifyIconW(NIM_ADD, &d) };
}

/// Показывает значок в отдельном потоке. Повторный вызов ничего не делает.
pub fn start(tip: &str) {
    if HWND_VALUE.load(Ordering::Relaxed) != 0 {
        return;
    }
    if let Ok(mut t) = TIP.lock() {
        *t = tip.to_string();
    }
    std::thread::spawn(|| unsafe {
        let class = wide("DnsSwitcherTray");
        let instance = GetModuleHandleW(std::ptr::null());
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = instance;
        wc.lpszClassName = class.as_ptr();
        RegisterClassW(&wc);
        let title = wide("DnsSwitcherTray");
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return;
        }
        let msg_name = wide("TaskbarCreated");
        let taskbar_created = RegisterWindowMessageW(msg_name.as_ptr());
        TASKBAR_CREATED.store(taskbar_created as isize, Ordering::Relaxed);
        // Защита работает с правами администратора, а Проводник — без них. Windows не
        // пропускает его сообщения «снизу вверх», пока окно само их не разрешит:
        // иначе щелчки по значку и его возврат после перезапуска Проводника теряются.
        for message in [WM_TRAY, taskbar_created] {
            ChangeWindowMessageFilterEx(hwnd, message, MSGFLT_ALLOW, std::ptr::null_mut());
        }
        HWND_VALUE.store(hwnd as isize, Ordering::Relaxed);
        add_icon(hwnd);
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        HWND_VALUE.store(0, Ordering::Relaxed);
    });
}

/// Убирает значок (защиту остановили).
pub fn stop() {
    let h = hwnd();
    if !h.is_null() {
        unsafe { PostMessageW(h, WM_CLOSE, 0, 0) };
    }
}

/// Обновляет подсказку при наведении на значок.
pub fn set_tip(text: &str) {
    if let Ok(mut t) = TIP.lock() {
        if *t == text {
            return;
        }
        *t = text.to_string();
    }
    let h = hwnd();
    if h.is_null() {
        return;
    }
    let mut d = base_data(h);
    d.uFlags = NIF_TIP;
    copy_into(&mut d.szTip, text);
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
}

/// Уведомление Windows от имени программы.
pub fn notify(title: &str, body: &str, warning: bool) {
    let h = hwnd();
    if h.is_null() {
        return;
    }
    let mut d = base_data(h);
    d.uFlags = NIF_INFO;
    copy_into(&mut d.szInfoTitle, title);
    copy_into(&mut d.szInfo, body);
    d.dwInfoFlags = if warning { NIIF_WARNING } else { NIIF_INFO };
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
}

/// Открывает окно программы. Если оно уже открыто, новая копия выведет его вперёд.
fn open_window() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe).spawn();
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let taskbar = TASKBAR_CREATED.load(Ordering::Relaxed) as u32;
    if taskbar != 0 && msg == taskbar {
        add_icon(hwnd);
        return 0;
    }
    match msg {
        WM_TRAY => {
            match lparam as u32 {
                WM_LBUTTONUP => open_window(),
                WM_RBUTTONUP => unsafe { show_menu(hwnd) },
                _ => {}
            }
            0
        }
        WM_CLOSE => {
            let d = base_data(hwnd);
            unsafe {
                Shell_NotifyIconW(NIM_DELETE, &d);
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

unsafe fn show_menu(hwnd: HWND) {
    unsafe {
        let menu = CreatePopupMenu();
        let open = wide("Открыть Переключатель DNS");
        let check = wide("Проверить сейчас");
        AppendMenuW(menu, MF_STRING, CMD_OPEN, open.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, CMD_CHECK, check.as_ptr());
        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        // Без этого меню не закрывается щелчком мимо него.
        SetForegroundWindow(hwnd);
        let cmd = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
            pt.x,
            pt.y,
            0,
            hwnd,
            std::ptr::null(),
        );
        DestroyMenu(menu);
        match cmd as usize {
            CMD_OPEN => open_window(),
            CMD_CHECK => CHECK_NOW.store(true, Ordering::Relaxed),
            _ => {}
        }
    }
}
