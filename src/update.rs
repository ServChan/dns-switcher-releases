//! Обновления из репозитория выпусков: подписанный список серверов и новая
//! версия программы. Всё скачанное проверяется подписью ed25519; открытый ключ
//! встраивается при сборке из assets/updater.pub (scripts/release/new-updater-key.ps1).

use crate::config::{ServerList, data_dir, write_atomic};
use crate::doh;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const REPO: &str = "ServChan/dns-switcher";
const LIST_URL: &str = "https://raw.githubusercontent.com/ServChan/dns-switcher/main/servers.json";
const MANIFEST_URL: &str = "https://github.com/ServChan/dns-switcher/releases/latest/download/latest.json";
const PUBKEY: Option<&str> = option_env!("DNS_SWITCHER_UPDATER_PUBKEY");
const TIMEOUT: Duration = Duration::from_secs(20);
/// Как часто проверять обновления сами по себе.
pub const CHECK_EVERY_SECS: u64 = 24 * 3600;

/// Ключ проверки подписи встроен: обновления можно включать.
pub fn configured() -> bool {
    PUBKEY.is_some_and(|k| !k.trim().is_empty())
}

/// Описание выпуска (latest.json в выпуске на GitHub).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub pub_date: String,
    pub url: String,
    pub sha256: String,
    /// Подпись ed25519 содержимого exe, base64.
    pub signature: String,
    /// Подпись ed25519 строки «версия и хеш» (`release_text`): без неё старый
    /// подписанный установщик можно было бы выдать за новую версию.
    #[serde(default)]
    pub release_signature: String,
}

/// Что подписывается вместе с версией: так версию нельзя подменить отдельно от файла.
pub fn release_text(version: &str, sha256: &str) -> String {
    format!("dns-switcher-release\n{}\n{}\n", version.trim(), sha256.trim().to_lowercase())
}

/// Версия вида 1.2.3: только цифры и точки, она попадает в имена и сравнения.
fn valid_version(v: &str) -> bool {
    !v.is_empty() && v.len() <= 20 && v.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Когда что проверялось; хранится рядом с настройками.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateState {
    pub last_app_check: u64,
    pub last_list_check: u64,
    /// Новая версия, о которой уже сказали уведомлением.
    pub notified_version: String,
    /// Последняя найденная новая версия: окно показывает её без сети.
    pub available: Option<Manifest>,
}

fn state_path() -> PathBuf {
    data_dir().join("updates.json")
}

impl UpdateState {
    pub fn load() -> Self {
        std::fs::read_to_string(state_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self) {
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = write_atomic(&state_path(), &text);
        }
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// a новее b: сравнение версий вида 1.2.3.
pub fn newer(a: &str, b: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> { v.trim_start_matches('v').split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    parse(a) > parse(b)
}

fn verify(data: &[u8], signature_b64: &str) -> Result<(), String> {
    let key = PUBKEY.ok_or("обновления ещё не настроены: нет ключа проверки подписи")?;
    let key: [u8; 32] = B64
        .decode(key.trim())
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or("встроенный ключ проверки подписи повреждён")?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| "встроенный ключ проверки подписи повреждён".to_string())?;
    let sig: [u8; 64] = B64
        .decode(signature_b64.trim())
        .ok()
        .and_then(|s| s.try_into().ok())
        .ok_or("подпись повреждена")?;
    key.verify(data, &Signature::from_bytes(&sig))
        .map_err(|_| "подпись не совпала: файл мог быть подменён, обновление отменено".to_string())
}

/// Новая версия программы, если она есть.
pub fn check_app() -> Result<Option<Manifest>, String> {
    let body = http_get(MANIFEST_URL)?;
    let m: Manifest = serde_json::from_slice(&body).map_err(|_| "описание выпуска не разобралось".to_string())?;
    if !valid_version(&m.version) {
        return Err("в описании выпуска неверная версия".into());
    }
    Ok(newer(&m.version, crate::install::VERSION).then_some(m))
}

/// Скачивает установщик новой версии и проверяет хеш и подпись. Описание выпуска
/// берётся свежее с GitHub, а не из сохранённого updates.json.
pub fn download_app() -> Result<PathBuf, String> {
    let m = check_app()?.ok_or("новой версии нет")?;
    download_verified(&m)
}

fn download_verified(m: &Manifest) -> Result<PathBuf, String> {
    if !valid_version(&m.version) || !newer(&m.version, crate::install::VERSION) {
        return Err("это не новая версия".into());
    }
    verify(release_text(&m.version, &m.sha256).as_bytes(), &m.release_signature)
        .map_err(|_| "подпись версии не совпала: описание выпуска могли подменить, обновление отменено".to_string())?;
    let data = http_get(&m.url)?;
    let hash: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
    if !hash.eq_ignore_ascii_case(m.sha256.trim()) {
        return Err("файл скачался не полностью или изменён: хеш не совпал".into());
    }
    verify(&data, &m.signature)?;
    // Проверенный файл кладём в папку установки, куда пишет только администратор:
    // во временной папке его успели бы подменить до запуска с правами администратора.
    let dir = crate::install::installed_dir()
        .filter(|d| crate::install::is_protected_dir(d))
        .map(|d| d.join(crate::install::UPDATES_DIR))
        .ok_or("обновлять из программы можно только копию, установленную в Program Files; скачайте новую версию со страницы выпусков")?;
    // Прежние скачанные установщики больше не нужны.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("не удалось создать {}: {e}", dir.display()))?;
    // Своё имя: прежний установщик мог ещё работать (например, показывать ошибку).
    let path = dir.join(format!("DnsSwitcher-Setup-{}.exe", crate::sys::random_suffix()));
    std::fs::write(&path, &data).map_err(|e| format!("не удалось сохранить установщик: {e}"))?;
    Ok(path)
}

/// Запускает скачанный установщик в режиме тихого обновления.
pub fn run_update(installer: &PathBuf) -> Result<(), String> {
    std::process::Command::new(installer)
        .arg("--update")
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("не удалось запустить обновление: {e}"))
}

/// Подписанный список серверов с актуальными адресами.
pub fn fetch_server_list() -> Result<ServerList, String> {
    let body = http_get(LIST_URL)?;
    let sig = http_get(&format!("{LIST_URL}.sig"))?;
    verify(&body, &String::from_utf8_lossy(&sig))?;
    serde_json::from_slice(&body).map_err(|_| "список серверов не разобрался".to_string())
}

// ---------- HTTPS GET ----------

/// GET по HTTPS (HTTP/1.1) с переходом по перенаправлениям GitHub.
fn http_get(url: &str) -> Result<Vec<u8>, String> {
    let mut url = url.to_string();
    for _ in 0..6 {
        // Соединение изредка портится по пути (испорченная TLS-запись) или рвётся,
        // пока DNS только что сменили: до трёх попыток с паузой.
        let mut attempt = get_once(&url);
        for pause in [1, 3] {
            if attempt.is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_secs(pause));
            attempt = get_once(&url);
        }
        let (status, headers, body) = attempt?;
        match status {
            200 => return Ok(body),
            301 | 302 | 303 | 307 | 308 => {
                url = header(&headers, "location").ok_or("перенаправление без адреса")?.to_string();
            }
            404 => return Err("на сервере обновлений этого файла нет".into()),
            code => return Err(format!("сервер обновлений ответил {code}")),
        }
    }
    Err("слишком много перенаправлений".into())
}

fn header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn get_once(url: &str) -> Result<(u16, String, Vec<u8>), String> {
    let rest = url.strip_prefix("https://").ok_or("поддерживается только https")?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let addr = (host, 443)
        .to_socket_addrs()
        .map_err(|_| format!("не удалось найти {host}: нет интернета?"))?
        .next()
        .ok_or_else(|| format!("не удалось найти {host}"))?;
    let tcp = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|_| format!("{host} не отвечает"))?;
    tcp.set_read_timeout(Some(TIMEOUT)).ok();
    tcp.set_write_timeout(Some(TIMEOUT)).ok();
    let name = ServerName::try_from(host.to_string()).map_err(|_| "неверный адрес".to_string())?;
    let conn = ClientConnection::new(doh::tls_config_http1(), name).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, tcp);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DnsSwitcher/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        crate::install::VERSION
    );
    tls.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    match tls.read_to_end(&mut raw) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof && !raw.is_empty() => {}
        Err(e) => return Err(format!("загрузка прервалась: {e}")),
    }
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("неполный ответ сервера")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = &raw[split + 4..];
    let chunked = header(&head, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    Ok((status, head, if chunked { doh::dechunk(body) } else { body.to_vec() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Настоящий репозиторий выпусков: `cargo test -- --ignored --nocapture live_update`.
    #[test]
    #[ignore]
    fn live_update_roundtrip() {
        assert!(configured(), "ключ проверки не встроен");
        let list = fetch_server_list().expect("список серверов скачался и подпись совпала");
        println!("список версии {}: {} серверов", list.version, list.servers.len());
        let body = http_get(MANIFEST_URL).expect("описание выпуска скачалось");
        let m: Manifest = serde_json::from_slice(&body).expect("описание выпуска разобралось");
        println!("выпуск {} ({})", m.version, m.url);
        verify(release_text(&m.version, &m.sha256).as_bytes(), &m.release_signature).expect("подпись версии совпала");
        let data = http_get(&m.url).expect("установщик скачался");
        verify(&data, &m.signature).expect("подпись установщика совпала");
        println!("установщик проверен: {} байт", data.len());
        let mut broken = m.clone();
        broken.version = "99.0.0".into();
        assert!(download_verified(&broken).is_err(), "подменённая версия отвергается");
    }

    #[test]
    fn versions_are_digits_and_dots() {
        assert!(valid_version("1.0.2"));
        assert!(!valid_version(r"1\..\..\x"));
        assert!(!valid_version("1..2"));
        assert!(!valid_version(""));
    }

    #[test]
    fn compares_versions() {
        assert!(newer("1.0.10", "1.0.9"));
        assert!(newer("v1.1.0", "1.0.2"));
        assert!(!newer("1.0.2", "1.0.2"));
        assert!(!newer("1.0.1", "1.0.2"));
    }

    #[test]
    fn verifies_signatures() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let data = b"servers";
        let sig = B64.encode(key.sign(data).to_bytes());
        let public = B64.encode(key.verifying_key().to_bytes());
        // Проверка подписи с явным ключом, как это делает verify().
        let vk = VerifyingKey::from_bytes(&B64.decode(&public).unwrap().try_into().unwrap()).unwrap();
        let s: [u8; 64] = B64.decode(&sig).unwrap().try_into().unwrap();
        assert!(vk.verify(data, &Signature::from_bytes(&s)).is_ok());
        assert!(vk.verify(b"other", &Signature::from_bytes(&s)).is_err());
    }
}
