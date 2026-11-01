# Подписывает release\servers.json и с -Publish выкладывает его в репозиторий
# выпусков: установленные копии раз в день подтягивают оттуда актуальные адреса.
#
#   scripts\release\publish-servers.ps1             # только проверить и подписать
#   scripts\release\publish-servers.ps1 -Publish    # и выложить
#
# Перед публикацией поднимите "version" в release\servers.json: копии применяют
# только список новее уже применённого.

param(
    [string]$Repo = 'ServChan/dns-switcher',
    [switch]$Publish
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\credentials.ps1"

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$list = Join-Path $root 'release\servers.json'
# Подпись считается по точным байтам, а git на Windows может менять переводы строк:
# приводим файл к LF и подписываем именно его.
$text = (Get-Content -Raw -Encoding UTF8 $list) -replace "`r`n", "`n"
$json = $text | ConvertFrom-Json
if (-not $json.version -or -not $json.servers) { throw 'в servers.json нет version или servers' }
$utf8 = New-Object Text.UTF8Encoding $false
[IO.File]::WriteAllText($list, $text, $utf8)

cargo build --release --bin dns-switcher-sign --manifest-path "$root\Cargo.toml" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'не собрался dns-switcher-sign' }
$env:DNS_SWITCHER_SIGNING_KEY = Get-ReleaseSecret $UpdaterKeyTarget
try {
    $signature = (& "$root\target\release\dns-switcher-sign.exe" sign $list).Trim()
} finally {
    Remove-Item Env:DNS_SWITCHER_SIGNING_KEY -ErrorAction SilentlyContinue
}
$sig = "$list.sig"
[IO.File]::WriteAllText($sig, $signature, $utf8)
Write-Output "Подписан список версии $($json.version): $($json.servers.Count) серверов"

if (-not $Publish) { return }

$work = Join-Path ([IO.Path]::GetTempPath()) ("dns-switcher-list-" + [guid]::NewGuid())
gh repo clone $Repo $work -- --depth 1 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "не удалось получить $Repo (gh repo create $Repo --public, если его ещё нет)" }
try {
    # Программа берёт список с ветки main; в пустом репозитории её ещё нет.
    git -C $work checkout -B main 2>&1 | Out-Null
    Set-Content -Path "$work\.gitattributes" -Value '* -text' -NoNewline -Encoding ascii
    Copy-Item -Force $list "$work\servers.json"
    Copy-Item -Force $sig "$work\servers.json.sig"
    git -C $work add servers.json servers.json.sig
    git -C $work commit -m "Список серверов, версия $($json.version)" | Out-Null
    git -C $work push -u origin main 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'не удалось отправить список' }
    Write-Output "Опубликовано: https://github.com/$Repo/blob/main/servers.json"
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
