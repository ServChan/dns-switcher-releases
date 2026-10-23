//! Рабочее состояние (какой сервер выбран и какой сейчас стоит) и журнал событий.
//! Хранится отдельно от настроек: его меняют и окно, и фоновая защита.

use crate::config::{data_dir, write_atomic};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RuntimeState {
    /// Сервер, который пользователь выбрал вручную.
    pub preferred: Option<String>,
    /// Сервер, который сейчас стоит на адаптерах (может быть резервным).
    pub active: Option<String>,
    /// GUID адаптеров, к которым применяли DNS.
    pub adapters: Vec<String>,
    /// Все серверы не отвечали, и адаптеры переведены на DNS от роутера.
    #[serde(default)]
    pub on_dhcp_fallback: bool,
}

fn state_path() -> PathBuf {
    data_dir().join("state.json")
}

impl RuntimeState {
    pub fn load() -> Self {
        std::fs::read_to_string(state_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(&state_path(), &text)
    }
}

// ---------- Снимок защиты для окна ----------

/// Что знает защита: история проверок серверов и сквозная проверка через Windows.
/// Пишет процесс защиты, читает окно (надёжность серверов, состояние цепочки).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub updated: String,
    /// Последние оценки по серверам, от старых к новым: 0 — работает … 4 — не отвечает.
    pub history: std::collections::HashMap<String, Vec<u8>>,
    /// Последняя сквозная проверка: получает ли Windows ответы от выбранного сервера.
    pub e2e_ok: Option<bool>,
    pub e2e_detail: String,
}

fn snapshot_path() -> PathBuf {
    data_dir().join("health.json")
}

impl Snapshot {
    pub fn load() -> Self {
        std::fs::read_to_string(snapshot_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&mut self) {
        self.updated = now_text();
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = write_atomic(&snapshot_path(), &text);
        }
    }

    /// Доля «годных» проверок сервера в процентах, если история есть.
    pub fn reliability(&self, name: &str) -> Option<u32> {
        let h = self.history.get(name).filter(|h| !h.is_empty())?;
        let good = h.iter().filter(|g| **g <= 1).count();
        Some((good * 100 / h.len()) as u32)
    }
}

// ---------- Журнал ----------

const LOG_KEEP_LINES: usize = 400;

fn log_path() -> PathBuf {
    data_dir().join("events.log")
}

fn now_text() -> String {
    let mut t: SYSTEMTIME = unsafe { std::mem::zeroed() };
    unsafe { GetLocalTime(&mut t) };
    format!(
        "{:02}.{:02}.{} {:02}:{:02}:{:02}",
        t.wDay, t.wMonth, t.wYear, t.wHour, t.wMinute, t.wSecond
    )
}

/// Добавляет строку в журнал. Когда журнал разрастается, старые строки отрезаются.
pub fn log(text: &str) {
    // Тесты не пишут в настоящий журнал программы.
    if cfg!(test) {
        return;
    }
    let path = log_path();
    let _ = std::fs::create_dir_all(data_dir());
    let line = format!("{}  {}\n", now_text(), text.replace('\n', " "));
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
    if std::fs::metadata(&path).map(|m| m.len() > 96 * 1024).unwrap_or(false) {
        let lines = read_log(LOG_KEEP_LINES);
        let _ = write_atomic(&path, &(lines.join("\n") + "\n"));
    }
}

/// Последние `n` строк журнала, старые сверху.
pub fn read_log(n: usize) -> Vec<String> {
    let text = std::fs::read_to_string(log_path()).unwrap_or_default();
    let lines: Vec<String> = text.lines().filter(|l| !l.trim().is_empty()).map(String::from).collect();
    lines[lines.len().saturating_sub(n)..].to_vec()
}
