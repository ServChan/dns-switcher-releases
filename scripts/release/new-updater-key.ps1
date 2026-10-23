# Создаёт ключ подписи обновлений один раз. Закрытый ключ уходит в диспетчер
# учётных данных, открытый записывается в assets\updater.pub и встраивается в
# программу при сборке: по нему установленные копии проверяют обновления.
#
# Потеря закрытого ключа означает, что установленные копии больше не примут
# обновления, поэтому сохраните его резервную копию (например, в менеджере паролей).

param([switch]$Force)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\credentials.ps1"

if (-not $Force -and $null -ne [DnsSwitcherRelease.Cred]::Read($UpdaterKeyTarget)) {
    throw 'Ключ уже есть. Новый ключ сломает обновление установленных копий; если это и нужно, запустите с -Force.'
}

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
cargo build --release --bin dns-switcher-sign --manifest-path "$root\Cargo.toml" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'не собрался dns-switcher-sign' }
$out = & "$root\target\release\dns-switcher-sign.exe" keygen
$private = ($out | Where-Object { $_ -like 'PRIVATE=*' }) -replace '^PRIVATE=', ''
$public = ($out | Where-Object { $_ -like 'PUBLIC=*' }) -replace '^PUBLIC=', ''
if (-not $private -or -not $public) { throw 'ключ не создан' }

Set-ReleaseSecret $UpdaterKeyTarget $private
[IO.File]::WriteAllText("$root\assets\updater.pub", $public, (New-Object Text.UTF8Encoding $false))
Write-Output "Открытый ключ: $public"
Write-Output 'Записан в assets\updater.pub; закрытый — в диспетчере учётных данных.'
