//! Задания Планировщика: фоновая защита от сбоев и запуск без запроса UAC.

use crate::apply;
use std::path::Path;

/// Фоновая защита: `dns-switcher.exe --watch` при входе в Windows.
pub const WATCHDOG: &str = "DnsSwitcher Watchdog";
/// Запуск окна с правами администратора без подтверждения UAC.
pub const LAUNCHER: &str = "DnsSwitcher Launcher";

pub fn exists(name: &str) -> bool {
    apply::run_tool("schtasks", &["/Query", "/TN", name]).is_ok()
}

pub fn run(name: &str) -> Result<(), String> {
    apply::run_tool("schtasks", &["/Run", "/TN", name])
}

pub fn remove(name: &str) -> Result<(), String> {
    let _ = apply::run_tool("schtasks", &["/End", "/TN", name]);
    if !exists(name) {
        return Ok(());
    }
    apply::run_tool("schtasks", &["/Delete", "/TN", name, "/F"])
        .map_err(|e| format!("Не удалось удалить задание «{name}» из Планировщика: {e}"))
}

/// Создаёт (или пересоздаёт) задание с наивысшими правами для текущего пользователя.
/// `at_logon` добавляет запуск при входе в Windows, иначе задание запускается по требованию.
pub fn create(name: &str, exe: &Path, args: &str, at_logon: bool, description: &str) -> Result<(), String> {
    let user = format!(
        "{}\\{}",
        std::env::var("USERDOMAIN").unwrap_or_default(),
        std::env::var("USERNAME").unwrap_or_default()
    );
    let user = xml_escape(&user);
    let triggers = if at_logon {
        format!("<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>")
    } else {
        String::new()
    };
    // Фоновая защита работает в одном экземпляре; окно можно открывать повторно,
    // тогда новая копия просто выведет уже открытое окно вперёд.
    let instances = if at_logon { "IgnoreNew" } else { "Parallel" };
    let restart = if at_logon { "<RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>" } else { "" };
    let arguments = if args.is_empty() { String::new() } else { format!("<Arguments>{}</Arguments>", xml_escape(args)) };
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>{description}</Description></RegistrationInfo>
  {triggers}
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>{instances}</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    {restart}
  </Settings>
  <Actions Context="Author">
    <Exec><Command>{exe}</Command>{arguments}</Exec>
  </Actions>
</Task>
"#,
        description = xml_escape(description),
        exe = xml_escape(&exe.to_string_lossy()),
    );

    // schtasks принимает XML в UTF-16 с BOM.
    let path = std::env::temp_dir().join(format!("dns-switcher-{}.xml", std::process::id()));
    let mut bytes = vec![0xFF, 0xFE];
    for unit in xml.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    let path_text = path.to_string_lossy().to_string();
    let created = apply::run_tool("schtasks", &["/Create", "/TN", name, "/XML", &path_text, "/F"]);
    let _ = std::fs::remove_file(&path);
    created.map_err(|e| format!("Не удалось создать задание «{name}» в Планировщике: {e}"))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
