//! Браузеры со своим защищённым DNS. Такой браузер не спрашивает Windows, поэтому
//! смена DNS в программе на него не действует: обход ограничений там не работает.

use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{CloseHandle, HWND, LPARAM};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsWindowVisible, PostMessageW, WM_CLOSE};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DnsMode {
    /// Пользуется DNS Windows: программа на него действует.
    System,
    /// «Автоматически»: DNS Windows, при известном провайдере с шифрованием. Тоже годится.
    Automatic,
    /// Свой защищённый DNS: Windows и программа в обход.
    Own,
}

#[derive(Clone, Debug)]
pub struct BrowserDns {
    pub name: &'static str,
    pub mode: DnsMode,
    /// Адрес своего DNS, если он задан.
    pub template: String,
    /// Настройка задана политикой: изменить её может только администратор политик.
    pub by_policy: bool,
    pub running: bool,
    /// Где в браузере выключить вручную.
    pub settings_url: &'static str,
    /// Имя процесса, например chrome.exe.
    pub exe: &'static str,
    /// Часть пути к exe, по которой браузер отличается от соседей с тем же именем
    /// процесса (Chrome и Chromium — оба chrome.exe, Opera и Opera GX — opera.exe).
    path_hint: &'static str,
    kind: Kind,
}

#[derive(Clone, Debug)]
enum Kind {
    Chromium { local_state: PathBuf },
    Firefox { prefs: Vec<PathBuf> },
}

impl BrowserDns {
    pub fn bypasses_windows(&self) -> bool {
        self.mode == DnsMode::Own
    }

    pub fn can_fix(&self) -> bool {
        self.bypasses_windows() && !self.by_policy
    }
}

struct Chromium {
    name: &'static str,
    exe: &'static str,
    /// Возможные папки профиля относительно %LOCALAPPDATA% (или %APPDATA%, если `roaming`).
    dirs: &'static [&'static str],
    roaming: bool,
    policy: &'static str,
    settings_url: &'static str,
    path_hint: &'static str,
}

const CHROMIUM: [Chromium; 9] = [
    Chromium {
        name: "Google Chrome",
        exe: "chrome.exe",
        dirs: &[r"Google\Chrome\User Data"],
        roaming: false,
        policy: r"SOFTWARE\Policies\Google\Chrome",
        settings_url: "chrome://settings/security",
        path_hint: r"\google\chrome\",
    },
    Chromium {
        name: "Chromium",
        exe: "chrome.exe",
        dirs: &[r"Chromium\User Data"],
        roaming: false,
        policy: r"SOFTWARE\Policies\Chromium",
        settings_url: "chrome://settings/security",
        path_hint: r"\chromium\",
    },
    Chromium {
        name: "Microsoft Edge",
        exe: "msedge.exe",
        dirs: &[r"Microsoft\Edge\User Data"],
        roaming: false,
        policy: r"SOFTWARE\Policies\Microsoft\Edge",
        settings_url: "edge://settings/privacy",
        path_hint: r"\microsoft\edge\",
    },
    Chromium {
        name: "Яндекс Браузер",
        exe: "browser.exe",
        dirs: &[r"Yandex\YandexBrowser\User Data"],
        roaming: false,
        policy: r"SOFTWARE\Policies\YandexBrowser",
        settings_url: "browser://settings/system",
        path_hint: r"\yandex\",
    },
    Chromium {
        name: "Brave",
        exe: "brave.exe",
        dirs: &[r"BraveSoftware\Brave-Browser\User Data"],
        roaming: false,
        policy: r"SOFTWARE\Policies\BraveSoftware\Brave",
        settings_url: "brave://settings/security",
        path_hint: r"\bravesoftware\",
    },
    Chromium {
        name: "Opera",
        exe: "opera.exe",
        dirs: &[r"Opera Software\Opera Stable"],
        roaming: true,
        policy: r"SOFTWARE\Policies\Opera Software\Opera",
        settings_url: "opera://settings/privacy",
        path_hint: r"\opera\",
    },
    Chromium {
        name: "Opera GX",
        exe: "opera.exe",
        dirs: &[r"Opera Software\Opera GX Stable"],
        roaming: true,
        policy: r"SOFTWARE\Policies\Opera Software\Opera GX",
        settings_url: "opera://settings/privacy",
        path_hint: r"\opera gx\",
    },
    Chromium {
        name: "Comet",
        exe: "comet.exe",
        dirs: &[r"Perplexity\Comet\User Data", r"Comet\User Data"],
        roaming: false,
        policy: r"SOFTWARE\Policies\Perplexity\Comet",
        settings_url: "comet://settings/security",
        path_hint: r"\comet\",
    },
    Chromium {
        name: "Vivaldi",
        exe: "vivaldi.exe",
        dirs: &[r"Vivaldi\User Data"],
        roaming: false,
        policy: r"SOFTWARE\Policies\Vivaldi",
        settings_url: "vivaldi://settings/security",
        path_hint: r"\vivaldi\",
    },
];

/// Все установленные браузеры и их режим DNS.
pub fn detect() -> Vec<BrowserDns> {
    let procs = processes();
    let mut out = Vec::new();
    for b in &CHROMIUM {
        let base = std::env::var_os(if b.roaming { "APPDATA" } else { "LOCALAPPDATA" }).map(PathBuf::from);
        let Some(local_state) = base.and_then(|base| {
            b.dirs.iter().map(|d| base.join(d).join("Local State")).find(|p| p.exists())
        }) else {
            continue;
        };
        let (mut mode, mut template) = chromium_setting(&local_state);
        let policy = chromium_policy(b.policy);
        let by_policy = policy.is_some();
        if let Some((m, t)) = policy {
            mode = m;
            template = t;
        }
        out.push(BrowserDns {
            name: b.name,
            mode,
            template,
            by_policy,
            running: false,
            settings_url: b.settings_url,
            exe: b.exe,
            path_hint: b.path_hint,
            kind: Kind::Chromium { local_state },
        });
    }
    if let Some(ff) = firefox() {
        out.push(ff);
    }
    for b in &mut out {
        b.running = !browser_pids(b, &procs).is_empty();
    }
    out
}

fn chromium_mode(text: &str) -> DnsMode {
    match text {
        "secure" => DnsMode::Own,
        "off" => DnsMode::System,
        _ => DnsMode::Automatic,
    }
}

fn chromium_setting(local_state: &Path) -> (DnsMode, String) {
    let json: serde_json::Value = std::fs::read_to_string(local_state)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let doh = &json["dns_over_https"];
    let mode = chromium_mode(doh["mode"].as_str().unwrap_or("automatic"));
    (mode, doh["templates"].as_str().unwrap_or_default().to_string())
}

fn chromium_policy(key: &str) -> Option<(DnsMode, String)> {
    for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        if let Ok(k) = RegKey::predef(root).open_subkey(key) {
            if let Ok(mode) = k.get_value::<String, _>("DnsOverHttpsMode") {
                let template = k.get_value::<String, _>("DnsOverHttpsTemplates").unwrap_or_default();
                return Some((chromium_mode(&mode), template));
            }
        }
    }
    None
}

fn firefox() -> Option<BrowserDns> {
    let root = PathBuf::from(std::env::var_os("APPDATA")?).join(r"Mozilla\Firefox");
    let ini = std::fs::read_to_string(root.join("profiles.ini")).ok()?;
    let mut prefs = Vec::new();
    let mut is_relative = true;
    for line in ini.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            is_relative = true;
        } else if let Some(v) = line.strip_prefix("IsRelative=") {
            is_relative = v == "1";
        } else if let Some(p) = line.strip_prefix("Path=") {
            let dir = if is_relative { root.join(p.replace('/', "\\")) } else { PathBuf::from(p) };
            let file = dir.join("prefs.js");
            if file.exists() {
                prefs.push(file);
            }
        }
    }
    if prefs.is_empty() {
        return None;
    }
    // Режимы TRR: 2 и 3 — свой DoH, остальное — DNS системы.
    let mut mode = DnsMode::System;
    let mut template = String::new();
    for file in &prefs {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        if let Some(m) = firefox_pref(&text, "network.trr.mode").and_then(|v| v.parse::<u32>().ok()) {
            if m == 2 || m == 3 {
                mode = DnsMode::Own;
                template = firefox_pref(&text, "network.trr.uri").unwrap_or_default();
            }
        }
    }
    let by_policy = std::env::var_os("ProgramFiles")
        .map(|p| PathBuf::from(p).join(r"Mozilla Firefox\distribution\policies.json"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .is_some_and(|t| t.contains("DNSOverHTTPS"));
    Some(BrowserDns {
        name: "Firefox",
        mode,
        template,
        by_policy,
        running: false,
        settings_url: "about:preferences#privacy",
        exe: "firefox.exe",
        path_hint: "",
        kind: Kind::Firefox { prefs },
    })
}

/// Значение `user_pref("имя", значение);` из prefs.js без кавычек.
fn firefox_pref(text: &str, name: &str) -> Option<String> {
    let needle = format!("user_pref(\"{name}\",");
    let line = text.lines().find(|l| l.trim_start().starts_with(&needle))?;
    let value = line.trim_start()[needle.len()..].trim().trim_end_matches(';').trim_end_matches(')').trim();
    Some(value.trim_matches('"').to_string())
}

// ---------- Процессы браузера ----------

struct Proc {
    pid: u32,
    name: String,
    path: String,
}

fn processes() -> Vec<Proc> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap as isize == -1 {
            return out;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut entry) != 0;
        while ok {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            out.push(Proc { pid: entry.th32ProcessID, path: process_path(entry.th32ProcessID), name });
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

/// Процессы именно этого браузера: имя exe и, где нужно, часть пути.
fn browser_pids(b: &BrowserDns, procs: &[Proc]) -> Vec<u32> {
    procs
        .iter()
        .filter(|p| p.name.eq_ignore_ascii_case(b.exe))
        .filter(|p| b.path_hint.is_empty() || p.path.to_lowercase().contains(b.path_hint))
        .map(|p| p.pid)
        .collect()
}

/// Просит видимые окна процессов закрыться, как при нажатии на крестик.
fn close_windows(pids: &[u32]) {
    struct Ctx<'a> {
        pids: &'a [u32],
    }
    unsafe extern "system" fn each(hwnd: HWND, lparam: LPARAM) -> i32 {
        let ctx = unsafe { &*(lparam as *const Ctx) };
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
        if ctx.pids.contains(&pid) && unsafe { IsWindowVisible(hwnd) } != 0 {
            unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) };
        }
        1
    }
    let ctx = Ctx { pids };
    unsafe { EnumWindows(Some(each), &ctx as *const Ctx as LPARAM) };
}

fn terminate(pids: &[u32]) {
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

/// Закрывает браузер, исправляет его DNS и открывает снова. Закрытие штатное:
/// браузер сохраняет вкладки. Если он не закрылся за 10 секунд (например, работает
/// в фоне), его процессы завершаются принудительно.
pub fn close_fix_reopen(b: &BrowserDns) -> Result<(), String> {
    let procs = processes();
    let pids = browser_pids(b, &procs);
    let exe_path = procs
        .iter()
        .find(|p| pids.contains(&p.pid) && !p.path.is_empty())
        .map(|p| PathBuf::from(&p.path));
    let was_running = !pids.is_empty();
    if was_running {
        close_windows(&pids);
        for _ in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if browser_pids(b, &processes()).is_empty() {
                break;
            }
        }
        let left = browser_pids(b, &processes());
        if !left.is_empty() {
            terminate(&left);
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }
        if !browser_pids(b, &processes()).is_empty() {
            return Err(format!("{} не закрылся. Закройте его вручную и нажмите «Исправить» ещё раз.", b.name));
        }
        // Браузер дописывает настройки при выходе: даём ему закончить.
        std::thread::sleep(std::time::Duration::from_millis(800));
    }
    let mut fresh = b.clone();
    fresh.running = false;
    fix(&fresh)?;
    if let (true, Some(path)) = (was_running, exe_path) {
        // Открываем от имени пользователя через Проводник, а не с правами администратора.
        let _ = std::process::Command::new("explorer").arg(path).spawn();
    }
    Ok(())
}

/// Переводит браузер на DNS Windows. Браузер должен быть закрыт, иначе при выходе
/// он перезапишет файл настроек. Рядом остаётся резервная копия.
pub fn fix(b: &BrowserDns) -> Result<(), String> {
    if b.by_policy {
        return Err(format!("В {} режим DNS задан политикой, программа его не меняет.", b.name));
    }
    if b.running {
        return Err(format!("Закройте {} полностью и нажмите «Исправить» ещё раз.", b.name));
    }
    match &b.kind {
        Kind::Chromium { local_state } => {
            let text = std::fs::read_to_string(local_state).map_err(|e| e.to_string())?;
            let mut json: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            backup(local_state)?;
            json["dns_over_https"]["mode"] = serde_json::Value::String("automatic".into());
            json["dns_over_https"]["templates"] = serde_json::Value::String(String::new());
            let text = serde_json::to_string(&json).map_err(|e| e.to_string())?;
            std::fs::write(local_state, text).map_err(|e| format!("Не удалось сохранить настройки {}: {e}", b.name))
        }
        Kind::Firefox { prefs } => {
            for file in prefs {
                let text = std::fs::read_to_string(file).map_err(|e| e.to_string())?;
                if !text.contains("\"network.trr.mode\"") {
                    continue;
                }
                backup(file)?;
                let fixed: Vec<String> = text
                    .lines()
                    .map(|l| {
                        if l.trim_start().starts_with("user_pref(\"network.trr.mode\",") {
                            "user_pref(\"network.trr.mode\", 5);".to_string()
                        } else {
                            l.to_string()
                        }
                    })
                    .collect();
                std::fs::write(file, fixed.join("\n") + "\n").map_err(|e| e.to_string())?;
            }
            Ok(())
        }
    }
}

fn backup(file: &Path) -> Result<(), String> {
    let mut name = file.file_name().unwrap_or_default().to_os_string();
    name.push(".dnsswitcher-backup");
    std::fs::copy(file, file.with_file_name(name))
        .map(|_| ())
        .map_err(|e| format!("Не удалось сделать резервную копию {}: {e}", file.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_firefox_prefs() {
        let text = "user_pref(\"network.trr.mode\", 3);\nuser_pref(\"network.trr.uri\", \"https://x.example/dns-query\");\n";
        assert_eq!(firefox_pref(text, "network.trr.mode").as_deref(), Some("3"));
        assert_eq!(firefox_pref(text, "network.trr.uri").as_deref(), Some("https://x.example/dns-query"));
    }

    #[test]
    fn fix_switches_chromium_to_windows_dns_and_keeps_other_settings() {
        let dir = std::env::temp_dir().join(format!("dns-switcher-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("Local State");
        std::fs::write(
            &file,
            r#"{"browser":{"enabled_labs_experiments":["x"]},"dns_over_https":{"mode":"secure","templates":"https://dns.geohide.ru:444/dns-query"}}"#,
        )
        .unwrap();
        let (mode, template) = chromium_setting(&file);
        assert_eq!(mode, DnsMode::Own);
        let b = BrowserDns {
            name: "Test",
            mode,
            template,
            by_policy: false,
            running: false,
            settings_url: "",
            exe: "nonexistent-browser.exe",
            path_hint: "",
            kind: Kind::Chromium { local_state: file.clone() },
        };
        fix(&b).unwrap();
        assert_eq!(chromium_setting(&file).0, DnsMode::Automatic);
        let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(json["browser"]["enabled_labs_experiments"][0], "x");
        assert!(dir.join("Local State.dnsswitcher-backup").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn chrome_and_chromium_processes_do_not_mix() {
        let procs = vec![
            Proc { pid: 1, name: "chrome.exe".into(), path: r"C:\Program Files\Google\Chrome\Application\chrome.exe".into() },
            Proc { pid: 2, name: "chrome.exe".into(), path: r"C:\Users\u\AppData\Local\Chromium\Application\chrome.exe".into() },
            Proc { pid: 3, name: "opera.exe".into(), path: r"C:\Users\u\AppData\Local\Programs\Opera GX\opera.exe".into() },
        ];
        let make = |c: &Chromium| BrowserDns {
            name: c.name,
            mode: DnsMode::Own,
            template: String::new(),
            by_policy: false,
            running: false,
            settings_url: "",
            exe: c.exe,
            path_hint: c.path_hint,
            kind: Kind::Firefox { prefs: vec![] },
        };
        let by = |name: &str| make(CHROMIUM.iter().find(|c| c.name == name).unwrap());
        assert_eq!(browser_pids(&by("Google Chrome"), &procs), [1]);
        assert_eq!(browser_pids(&by("Chromium"), &procs), [2]);
        assert_eq!(browser_pids(&by("Opera GX"), &procs), [3]);
        assert!(browser_pids(&by("Opera"), &procs).is_empty());
    }

    #[test]
    fn chromium_modes() {
        assert_eq!(chromium_mode("secure"), DnsMode::Own);
        assert_eq!(chromium_mode("off"), DnsMode::System);
        assert_eq!(chromium_mode("automatic"), DnsMode::Automatic);
    }

    /// Смотрит браузеры этого компьютера: `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_detect() {
        for b in detect() {
            println!("{:<16} {:?} policy={} running={} {}", b.name, b.mode, b.by_policy, b.running, b.template);
        }
    }
}
