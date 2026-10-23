//! Системные мелочи, которые нужно делать аккуратно, потому что программа работает
//! с правами администратора: пути к утилитам Windows и процессы своего сеанса.

use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{CloseHandle, HWND, LPARAM};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsWindowVisible, PostMessageW, WM_CLOSE};

fn windows_dir() -> PathBuf {
    std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// Полный путь к утилите Windows. По голому имени Windows сначала ищет exe рядом
/// с запущенной программой: подложенный туда «taskkill.exe» получил бы права
/// администратора. Поэтому системные утилиты вызываются только по полному пути.
pub fn tool(name: &str) -> PathBuf {
    let dir = windows_dir();
    match name {
        "powershell" => dir.join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
        "explorer" => dir.join("explorer.exe"),
        other => {
            let file = if other.ends_with(".exe") { other.to_string() } else { format!("{other}.exe") };
            dir.join("System32").join(file)
        }
    }
}

/// Открывает папку или адрес в Проводнике.
pub fn open_in_explorer(target: impl AsRef<std::ffi::OsStr>) {
    let _ = std::process::Command::new(tool("explorer")).arg(target).spawn();
}

pub struct Proc {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    (unsafe { ProcessIdToSessionId(pid, &mut session) } != 0).then_some(session)
}

/// Процессы текущего сеанса Windows. Чужие сеансы (другой пользователь, RDP)
/// программа не трогает.
pub fn processes() -> Vec<Proc> {
    let mut out = Vec::new();
    let mine = session_of(unsafe { GetCurrentProcessId() });
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap as isize == -1 {
            return out;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut entry) != 0;
        while ok {
            let pid = entry.th32ProcessID;
            if mine.is_some() && session_of(pid) == mine {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                out.push(Proc { pid, path: process_path(pid), name });
            }
            ok = Process32NextW(snap, &mut entry) != 0;
        }
        CloseHandle(snap);
    }
    out
}

fn process_path(pid: u32) -> String {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return String::new();
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) != 0;
        CloseHandle(h);
        if ok { String::from_utf16_lossy(&buf[..len as usize]) } else { String::new() }
    }
}

/// Видимые окна процессов.
pub fn visible_windows(pids: &[u32]) -> Vec<HWND> {
    struct Ctx<'a> {
        pids: &'a [u32],
        found: Vec<HWND>,
    }
    unsafe extern "system" fn each(hwnd: HWND, lparam: LPARAM) -> i32 {
        let ctx = unsafe { &mut *(lparam as *mut Ctx) };
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
        if ctx.pids.contains(&pid) && unsafe { IsWindowVisible(hwnd) } != 0 {
            ctx.found.push(hwnd);
        }
        1
    }
    let mut ctx = Ctx { pids, found: Vec::new() };
    unsafe { EnumWindows(Some(each), &mut ctx as *mut Ctx as LPARAM) };
    ctx.found
}

/// Просит окна закрыться, как при нажатии на крестик.
pub fn close_windows(windows: &[HWND]) {
    for &hwnd in windows {
        unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) };
    }
}

pub fn terminate(pids: &[u32]) {
    for &pid in pids {
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if !h.is_null() {
                TerminateProcess(h, 1);
                CloseHandle(h);
            }
        }
    }
}

/// Завершает другие копии exe с таким именем в своём сеансе (не себя).
pub fn terminate_others(exe_name: &str) {
    let me = unsafe { GetCurrentProcessId() };
    let pids: Vec<u32> = processes()
        .into_iter()
        .filter(|p| p.pid != me && p.name.eq_ignore_ascii_case(exe_name))
        .map(|p| p.pid)
        .collect();
    terminate(&pids);
}

/// `dir` лежит внутри `base` (сравнение по целым компонентам пути, без учёта регистра).
pub fn is_inside(dir: &Path, base: &Path) -> bool {
    // «C:\Program Files\..\Users» лишь выглядит вложенной папкой.
    use std::path::Component;
    if dir.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
        return false;
    }
    let norm = |p: &Path| p.to_string_lossy().trim_end_matches('\\').to_lowercase();
    let (d, b) = (norm(dir), norm(base));
    !b.is_empty() && (d == b || d.starts_with(&format!("{b}\\")))
}

/// Случайный суффикс для временных файлов: имя нельзя угадать заранее.
pub fn random_suffix() -> String {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        bytes = (n as u64).to_le_bytes();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_are_absolute_system_paths() {
        for name in ["taskkill", "schtasks", "netsh", "cmd", "powershell", "explorer", "ipconfig"] {
            let p = tool(name);
            assert!(p.is_absolute(), "{name}: {}", p.display());
            assert!(p.exists(), "{name}: {}", p.display());
        }
    }

    #[test]
    fn inside_compares_whole_components() {
        let pf = Path::new(r"C:\Program Files");
        assert!(is_inside(Path::new(r"C:\Program Files\DnsSwitcher"), pf));
        assert!(is_inside(Path::new(r"c:\program files"), pf));
        assert!(!is_inside(Path::new(r"C:\Program FilesX\DnsSwitcher"), pf));
        assert!(!is_inside(Path::new(r"C:\Users\u\Downloads"), pf));
        assert!(!is_inside(Path::new(r"C:\Program Files\..\Users\Public"), pf));
    }
}
