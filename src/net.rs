//! Чтение сетевых адаптеров и их текущих DNS-настроек.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    GetAdaptersAddresses, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

pub const DNSCACHE_IFACES: &str =
    r"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters";

#[derive(Clone, Debug)]
pub struct Adapter {
    pub index: u32,
    /// 0, если IPv6 на адаптере выключен.
    pub ipv6_index: u32,
    /// GUID адаптера в виде `{...}`.
    pub guid: String,
    pub name: String,
    pub description: String,
    pub up: bool,
    pub has_gateway: bool,
    pub dns: Vec<IpAddr>,
    /// DNS задан вручную (иначе получен автоматически по DHCP).
    pub static_dns: bool,
    /// Адреса, для которых на этом адаптере включено шифрование DoH.
    pub doh_ips: Vec<IpAddr>,
    /// У адаптера есть глобальный IPv6-адрес: сайты могут открываться по IPv6.
    pub has_ipv6: bool,
}

pub fn list_adapters() -> Result<Vec<Adapter>, String> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64>;
    loop {
        // u64 даёт нужное выравнивание для IP_ADAPTER_ADDRESSES_LH.
        buf = vec![0u64; (size as usize).div_ceil(8)];
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        match ret {
            NO_ERROR => break,
            ERROR_BUFFER_OVERFLOW => continue,
            code => return Err(format!("GetAdaptersAddresses вернул код {code}")),
        }
    }

    let mut adapters = Vec::new();
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        let a = unsafe { &*cur };
        cur = a.Next;
        if a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
            continue;
        }
        let guid = unsafe { pstr_to_string(a.AdapterName) };
        let index = unsafe { a.Anonymous1.Anonymous.IfIndex };

        let mut dns = Vec::new();
        let mut p = a.FirstDnsServerAddress;
        while !p.is_null() {
            let entry = unsafe { &*p };
            if let Some(ip) = unsafe { socket_address_to_ip(&entry.Address) } {
                if !is_placeholder_dns(&ip) {
                    dns.push(ip);
                }
            }
            p = entry.Next;
        }

        let mut has_ipv6 = false;
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            let entry = unsafe { &*u };
            if let Some(IpAddr::V6(v6)) = unsafe { socket_address_to_ip(&entry.Address) } {
                // Глобальные адреса начинаются с 2000::/3.
                if v6.segments()[0] & 0xe000 == 0x2000 {
                    has_ipv6 = true;
                }
            }
            u = entry.Next;
        }

        adapters.push(Adapter {
            index,
            has_ipv6,
            ipv6_index: a.Ipv6IfIndex,
            static_dns: has_static_dns(&guid),
            doh_ips: read_doh_ips(&guid),
            guid,
            name: unsafe { pwstr_to_string(a.FriendlyName) },
            description: unsafe { pwstr_to_string(a.Description) },
            up: a.OperStatus == IfOperStatusUp,
            has_gateway: !a.FirstGatewayAddress.is_null(),
            dns,
        });
    }
    Ok(adapters)
}

/// Windows показывает fec0:0:0:ffff::1..3, когда IPv6-DNS не настроен. Это не реальные серверы.
fn is_placeholder_dns(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfec0 && s[1] == 0 && s[2] == 0 && s[3] == 0xffff
        }
        IpAddr::V4(_) => false,
    }
}

/// Включает или выключает IPv6 на подключении (привязка ms_tcpip6).
pub fn set_ipv6(adapter_name: &str, enabled: bool) -> Result<(), String> {
    let verb = if enabled { "Enable-NetAdapterBinding" } else { "Disable-NetAdapterBinding" };
    let script = format!(
        "{verb} -Name '{}' -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction Stop",
        adapter_name.replace('\'', "''")
    );
    crate::apply::run_tool("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script])
}

fn has_static_dns(guid: &str) -> bool {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    ["Tcpip", "Tcpip6"].iter().any(|svc| {
        let path = format!(r"SYSTEM\CurrentControlSet\Services\{svc}\Parameters\Interfaces\{guid}");
        hklm.open_subkey(path)
            .and_then(|k| k.get_value::<String, _>("NameServer"))
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    })
}

fn read_doh_ips(guid: &str) -> Vec<IpAddr> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut out = Vec::new();
    for sub in ["Doh", "Doh6"] {
        let path = format!(r"{DNSCACHE_IFACES}\{guid}\DohInterfaceSettings\{sub}");
        let Ok(key) = hklm.open_subkey(path) else { continue };
        for name in key.enum_keys().flatten() {
            let enabled = key
                .open_subkey(&name)
                .and_then(|k| k.get_value::<u64, _>("DohFlags"))
                .map(|f| f != 0)
                .unwrap_or(false);
            if let (true, Ok(ip)) = (enabled, name.parse()) {
                out.push(ip);
            }
        }
    }
    out
}

unsafe fn socket_address_to_ip(sa: &SOCKET_ADDRESS) -> Option<IpAddr> {
    if sa.lpSockaddr.is_null() {
        return None;
    }
    let family = unsafe { (*(sa.lpSockaddr as *const SOCKADDR)).sa_family };
    match family {
        AF_INET => {
            let v4 = unsafe { &*(sa.lpSockaddr as *const SOCKADDR_IN) };
            let raw = unsafe { v4.sin_addr.S_un.S_addr };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(raw))))
        }
        AF_INET6 => {
            let v6 = unsafe { &*(sa.lpSockaddr as *const SOCKADDR_IN6) };
            Some(IpAddr::V6(Ipv6Addr::from(unsafe { v6.sin6_addr.u.Byte })))
        }
        _ => None,
    }
}

unsafe fn pwstr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

unsafe fn pstr_to_string(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(p as *const std::ffi::c_char) }
        .to_string_lossy()
        .into_owned()
}
