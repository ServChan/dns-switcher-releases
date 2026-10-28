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

/// Папки Windows спрашиваются у самой системы, а не берутся из переменных
/// окружения: переменные пользователь может переопределить в своём реестре
/// (HKCU\Environment), и они попадут в процесс, запущенный с правами администратора.
fn api_dir(f: unsafe extern "system" fn(windows_sys::core::PWSTR, u32) -> u32, fallback: &str) -> PathBuf {
    let mut buf = [0u16; 512];
    let n = unsafe { f(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return PathBuf::from(fallback);
    }
    PathBuf::from(String::from_utf16_lossy(&buf[..n]))
}

pub fn system_dir() -> PathBuf {
    api_dir(windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW, r"C:\Windows\System32")
}

fn windows_dir() -> PathBuf {
    api_dir(windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW, r"C:\Windows")
}

#[derive(Clone, Copy)]
pub enum Folder {
    ProgramFiles,
    ProgramFilesX86,
    ProgramData,
    PublicDesktop,
    CommonPrograms,
    RoamingAppData,
    LocalAppData,
}

/// Известная папка Windows (SHGetKnownFolderPath).
pub fn known_folder(f: Folder) -> Option<PathBuf> {
    use windows_sys::Win32::UI::Shell::*;
    let id = match f {
        Folder::ProgramFiles => FOLDERID_ProgramFiles,
        Folder::ProgramFilesX86 => FOLDERID_ProgramFilesX86,
        Folder::ProgramData => FOLDERID_ProgramData,
        Folder::PublicDesktop => FOLDERID_PublicDesktop,
        Folder::CommonPrograms => FOLDERID_CommonPrograms,
        Folder::RoamingAppData => FOLDERID_RoamingAppData,
        Folder::LocalAppData => FOLDERID_LocalAppData,
    };
    let mut out: windows_sys::core::PWSTR = std::ptr::null_mut();
    let hr = unsafe { SHGetKnownFolderPath(&id, 0, std::ptr::null_mut(), &mut out) };
    let path = (hr >= 0 && !out.is_null()).then(|| {
        let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
        PathBuf::from(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) }))
    });
    unsafe { windows_sys::Win32::System::Com::CoTaskMemFree(out as *const _) };
    path
}

/// Путь — ссылка (символическая или junction), а не обычная папка или файл.
pub fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_attributes() & 0x400 != 0)
}

/// Владелец — администраторы или система: обычный пользователь эту папку не создавал.
pub fn owned_by_admins(path: &Path) -> bool {
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{IsWellKnownSid, OWNER_SECURITY_INFORMATION, WinBuiltinAdministratorsSid, WinLocalSystemSid};
    let name: Vec<u16> = path.as_os_str().encode_wide_z();
    let mut owner = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    let ok = rc == 0
        && !owner.is_null()
        && unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0 || IsWellKnownSid(owner, WinLocalSystemSid) != 0 };
    if !sd.is_null() {
        unsafe { windows_sys::Win32::Foundation::LocalFree(sd) };
    }
    ok
}

trait WideZ {
    fn encode_wide_z(&self) -> Vec<u16>;
}

impl WideZ for std::ffi::OsStr {
    fn encode_wide_z(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}

/// Пользователь, который сидит за этим сеансом Windows (ДОМЕН\имя). При вводе
/// пароля чужой учётной записи администратора в окне UAC процесс работает от неё,
/// а сеанс остаётся за обычным пользователем.
pub fn session_user() -> Option<String> {
    use windows_sys::Win32::System::RemoteDesktop::*;
    let query = |class| -> Option<String> {
        let mut buf: windows_sys::core::PWSTR = std::ptr::null_mut();
        let mut bytes = 0u32;
        let ok = unsafe { WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, class, &mut buf, &mut bytes) } != 0;
        if !ok || buf.is_null() {
            return None;
        }
        let len = (0..).take_while(|&i| unsafe { *buf.add(i) } != 0).count();
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(buf, len) });
        unsafe { WTSFreeMemory(buf as *mut _) };
        Some(text)
    };
    let user = query(WTSUserName).filter(|u| !u.is_empty())?;
    let domain = query(WTSDomainName).unwrap_or_default();
    Some(if domain.is_empty() { user } else { format!("{domain}\\{user}") })
}

/// Пользователь, от имени которого работает этот процесс (ДОМЕН\имя).
pub fn process_user() -> Option<String> {
    use windows_sys::Win32::Security::Authentication::Identity::{GetUserNameExW, NameSamCompatible};
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    let ok = unsafe { GetUserNameExW(NameSamCompatible, buf.as_mut_ptr(), &mut len) };
    ok.then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

/// Полный путь к утилите Windows. По голому имени Windows сначала ищет exe рядом
/// с запущенной программой: подложенный туда «taskkill.exe» получил бы права
/// администратора. Поэтому системные утилиты вызываются только по полному пути.
pub fn tool(name: &str) -> PathBuf {
    match name {
        "powershell" => system_dir().join(r"WindowsPowerShell\v1.0\powershell.exe"),
        "explorer" => windows_dir().join("explorer.exe"),
        other => {
            let file = if other.ends_with(".exe") { other.to_string() } else { format!("{other}.exe") };
            system_dir().join(file)
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
    fn known_folders_resolve() {
        let pf = known_folder(Folder::ProgramFiles).unwrap();
        assert!(pf.is_absolute() && pf.exists(), "{}", pf.display());
        assert!(known_folder(Folder::ProgramData).unwrap().exists());
        assert!(owned_by_admins(&known_folder(Folder::ProgramData).unwrap()), "ProgramData принадлежит системе");
        assert!(!owned_by_admins(&std::env::temp_dir()), "временная папка пользователя — его собственная");
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
