//! Применение и сброс DNS. Адреса задаются через netsh, шифрование DoH через
//! таблицу `netsh dns encryption` и ключи Dnscache в реестре (так же делает
//! окно «Параметры» в Windows 11).

use crate::config::DnsServer;
use crate::net::{Adapter, DNSCACHE_IFACES};
use std::os::windows::process::CommandExt;
use std::process::Command;
use windows_sys::Win32::Globalization::{CP_OEMCP, MultiByteToWideChar};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Что сделать с выбранными адаптерами.
#[derive(Clone)]
pub enum Action {
    /// `safety_net`: дописать Cloudflare и Google последними адресами.
    Apply { server: DnsServer, use_doh: bool, safety_net: bool },
    Reset,
}

/// Страховка: если основной сервер не ответит, Windows сама перейдёт на эти
/// адреса, и интернет не пропадёт, даже когда программа не запущена.
fn safety_servers() -> Vec<DnsServer> {
    let make = |name: &str, v4: &str, v6: &str, doh: &str| DnsServer {
        name: name.into(),
        ipv4: vec![v4.into()],
        ipv6: vec![v6.into()],
        doh: doh.into(),
        ai_bypass: false,
        doh_only: false,
        note: String::new(),
    };
    vec![
        make("Cloudflare", "1.1.1.1", "2606:4700:4700::1111", "https://cloudflare-dns.com/dns-query"),
        make("Google Public DNS", "8.8.8.8", "2001:4860:4860::8888", "https://dns.google/dns-query"),
    ]
}

/// Итог операции для одного адаптера.
pub struct Outcome {
    pub adapter: String,
    pub result: Result<Vec<String>, String>,
}

pub fn run(action: &Action, adapters: &[Adapter]) -> Vec<Outcome> {
    // Окно и защита от сбоев могут менять DNS одновременно; выполняем по очереди.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut outcomes: Vec<Outcome> = adapters
        .iter()
        .map(|a| Outcome {
            adapter: a.name.clone(),
            result: match action {
                Action::Apply { server, use_doh, safety_net } => apply(a, server, *use_doh, *safety_net),
                Action::Reset => reset(a).map(|_| Vec::new()),
            },
        })
        .collect();

    if let Err(e) = run_tool("ipconfig", &["/flushdns"]) {
        if let Some(first) = outcomes.first_mut() {
            if let Ok(warnings) = &mut first.result {
                warnings.push(format!("Кэш DNS не очищен: {e}"));
            }
        }
    }
    outcomes
}

fn apply(adapter: &Adapter, server: &DnsServer, use_doh: bool, safety_net: bool) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    if server.doh_only && !(use_doh && server.has_doh()) {
        return Err(format!(
            "{} отвечает только по DoH. Включите «Шифровать запросы (DoH)» и повторите.",
            server.name
        ));
    }

    // Основной сервер и страховка без повторяющихся адресов.
    let mut chain = vec![server.clone()];
    if safety_net {
        for mut extra in safety_servers() {
            extra.ipv4.retain(|ip| !chain.iter().any(|s| s.ipv4.contains(ip)));
            // IPv6-страховка нужна, только если основной сервер сам работает по IPv6.
            if server.ipv6.is_empty() {
                extra.ipv6.clear();
            }
            extra.ipv6.retain(|ip| !chain.iter().any(|s| s.ipv6.contains(ip)));
            if !extra.ipv4.is_empty() || !extra.ipv6.is_empty() {
                chain.push(extra);
            }
        }
    }

    // Сначала шифрование: если оно не включится для сервера «только DoH»,
    // адреса не меняем, иначе сайты перестанут открываться.
    clear_doh_flags(&adapter.guid);
    for (i, s) in chain.iter().enumerate() {
        if !(use_doh && s.has_doh()) {
            continue;
        }
        if let Err(e) = enable_doh(adapter, s) {
            if i == 0 && s.doh_only {
                clear_doh_flags(&adapter.guid);
                return Err(format!("Не удалось включить DoH, без него {} не работает. {e}", s.name));
            }
            warnings.push(format!("DoH для {} не включён, запросы к нему пойдут без шифрования. {e}", s.name));
        }
    }

    let v4: Vec<String> = chain.iter().flat_map(|s| s.ipv4.iter().cloned()).collect();
    let v6: Vec<String> = chain.iter().flat_map(|s| s.ipv6.iter().cloned()).collect();
    set_family(adapter.index, "ipv4", &v4)?;
    if adapter.ipv6_index != 0 {
        set_family(adapter.ipv6_index, "ipv6", &v6)?;
    }
    Ok(warnings)
}

fn reset(adapter: &Adapter) -> Result<(), String> {
    clear_doh_flags(&adapter.guid);
    let idx = adapter.index.to_string();
    netsh(&["interface", "ipv4", "set", "dnsservers", &format!("name={idx}"), "source=dhcp"])?;
    if adapter.ipv6_index != 0 {
        let idx6 = adapter.ipv6_index.to_string();
        netsh(&["interface", "ipv6", "set", "dnsservers", &format!("name={idx6}"), "source=dhcp"])?;
    }
    Ok(())
}

/// Задаёт список серверов одного семейства. Пустой список возвращает DHCP.
fn set_family(index: u32, family: &str, ips: &[String]) -> Result<(), String> {
    let name = format!("name={index}");
    let Some((first, rest)) = ips.split_first() else {
        return netsh(&["interface", family, "set", "dnsservers", &name, "source=dhcp"]);
    };
    netsh(&[
        "interface",
        family,
        "set",
        "dnsservers",
        &name,
        "source=static",
        &format!("address={first}"),
        "register=primary",
        "validate=no",
    ])?;
    for (i, ip) in rest.iter().enumerate() {
        netsh(&[
            "interface",
            family,
            "add",
            "dnsservers",
            &name,
            &format!("address={ip}"),
            &format!("index={}", i + 2),
            "validate=no",
        ])?;
    }
    Ok(())
}

fn enable_doh(adapter: &Adapter, server: &DnsServer) -> Result<(), String> {
    let template = server.doh.trim();
    for ip in server.all_ips() {
        let args = |verb: &'static str| {
            vec![
                "dns".to_string(),
                verb.to_string(),
                "encryption".to_string(),
                format!("server={ip}"),
                format!("dohtemplate={template}"),
                "autoupgrade=yes".to_string(),
                "udpfallback=no".to_string(),
            ]
        };
        // add падает, если адрес уже есть в таблице; тогда обновляем запись.
        let added = netsh_owned(&args("add"));
        if added.is_err() {
            netsh_owned(&args("set")).map_err(|e| {
                format!("Похоже, эта версия Windows не поддерживает DoH (нужна Windows 11). {e}")
            })?;
        }
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let guid = adapter.guid.to_lowercase();
    let reg_err = |e: std::io::Error| format!("Не удалось записать настройки DoH в реестр: {e}");
    for (sub, ips) in [("Doh", &server.ipv4), ("Doh6", &server.ipv6)] {
        for ip in ips {
            let path = format!(r"{DNSCACHE_IFACES}\{guid}\DohInterfaceSettings\{sub}\{ip}");
            let (key, _) = hklm.create_subkey(path).map_err(reg_err)?;
            // 1 = «только зашифрованные», шаблон берётся из таблицы netsh dns encryption.
            key.set_value("DohFlags", &1u64).map_err(reg_err)?;
        }
    }
    Ok(())
}

fn clear_doh_flags(guid: &str) {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey_with_flags(
        format!(r"{DNSCACHE_IFACES}\{}", guid.to_lowercase()),
        winreg::enums::KEY_ALL_ACCESS,
    ) {
        let _ = key.delete_subkey_all("DohInterfaceSettings");
    }
}

fn netsh(args: &[&str]) -> Result<(), String> {
    run_tool("netsh", args)
}

fn netsh_owned(args: &[String]) -> Result<(), String> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    netsh(&refs)
}

pub fn run_tool(program: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Не удалось запустить {program}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let mut text = oem_to_string(&out.stdout);
    text.push_str(&oem_to_string(&out.stderr));
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    Err(if text.is_empty() {
        format!("{program} завершился с кодом {:?}", out.status.code())
    } else {
        text
    })
}

/// Консольные утилиты Windows пишут в OEM-кодировке (cp866 для русской системы).
fn oem_to_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    unsafe {
        let len = MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), bytes.len() as i32, std::ptr::null_mut(), 0);
        if len <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut wide = vec![0u16; len as usize];
        MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), bytes.len() as i32, wide.as_mut_ptr(), len);
        String::from_utf16_lossy(&wide)
    }
}
