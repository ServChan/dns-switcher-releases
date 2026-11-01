# Собирает подписанный выпуск и с -Publish выкладывает его в репозиторий выпусков,
# откуда программа берёт обновления.
#
#   scripts\release\publish.ps1 -Notes "Что изменилось"              # только собрать
#   scripts\release\publish.ps1 -NotesFile notes.txt -Publish         # собрать и выложить
#
# Версия берётся из Cargo.toml: сначала поднимите её.
# Ключ подписи читается из диспетчера учётных данных (new-updater-key.ps1).

param(
    [string]$Notes = '',
    [string]$NotesFile = '',
    [string]$Repo = 'ServChan/dns-switcher',
    [switch]$Publish
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\credentials.ps1"

function Invoke-Native([scriptblock]$Command) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Command 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" }
        } | Where-Object { $_ -and $_ -ne 'System.Management.Automation.RemoteException' }
    } finally {
        $ErrorActionPreference = $saved
    }
}

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$version = (Select-String -Path "$root\Cargo.toml" -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches.Groups[1].Value
$tag = "v$version"
if ($NotesFile) { $Notes = Get-Content -Raw -Encoding UTF8 $NotesFile }
$Notes = $Notes.Trim()
if ($Publish -and -not $Notes) { throw 'Опишите изменения: -Notes или -NotesFile' }
if (-not (Test-Path "$root\assets\updater.pub")) { throw 'Нет assets\updater.pub: создайте ключ, scripts\release\new-updater-key.ps1' }

# Пути сборочной машины не должны попасть в exe.
$env:RUSTFLAGS = "--remap-path-prefix=$($env:USERPROFILE)=~ --remap-path-prefix=$root=."
try {
    Invoke-Native { cargo build --release --manifest-path "$root\Cargo.toml" } | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'сборка не удалась' }
} finally {
    Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
}

$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$setup = Join-Path $dist 'DnsSwitcher-Setup.exe'
Copy-Item -Force "$root\target\release\dns-switcher.exe" $setup
$signer = "$root\target\release\dns-switcher-sign.exe"

$env:DNS_SWITCHER_SIGNING_KEY = Get-ReleaseSecret $UpdaterKeyTarget
try {
    $public = & $signer pubkey
    if ($public.Trim() -ne (Get-Content -Raw "$root\assets\updater.pub").Trim()) {
        throw 'Ключ в диспетчере учётных данных не совпадает с assets\updater.pub'
    }
    $signature = (& $signer sign $setup).Trim()
    $sha = (& $signer sha256 $setup).Trim()
    # Подпись версии вместе с хешем: так в описании выпуска нельзя выдать старый
    # установщик за новую версию (см. update::release_text).
    $releaseText = Join-Path $dist 'release.txt'
    [IO.File]::WriteAllText($releaseText, "dns-switcher-release`n$version`n$($sha.ToLower())`n", (New-Object Text.UTF8Encoding $false))
    $releaseSignature = (& $signer sign $releaseText).Trim()
    Remove-Item $releaseText
} finally {
    Remove-Item Env:DNS_SWITCHER_SIGNING_KEY -ErrorAction SilentlyContinue
}

$manifest = [ordered]@{
    version   = $version
    notes     = $Notes
    pub_date  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    url       = "https://github.com/$Repo/releases/download/$tag/DnsSwitcher-Setup.exe"
    sha256    = $sha
    signature = $signature
    release_signature = $releaseSignature
}
$latest = Join-Path $dist 'latest.json'
[IO.File]::WriteAllText($latest, ($manifest | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
Write-Output "Готово: $setup ($version)"
Write-Output "Описание выпуска: $latest"

if (-not $Publish) { return }

Invoke-Native { gh repo view $Repo --json name } | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Нет репозитория $Repo. Создайте его (публичным, иначе обновления не скачаются): gh repo create $Repo --public"
}
$notesPath = Join-Path $dist 'notes.md'
[IO.File]::WriteAllText($notesPath, $Notes, (New-Object Text.UTF8Encoding $false))
Invoke-Native { gh release create $tag $setup $latest --repo $Repo --title "Переключатель DNS $version" --notes-file $notesPath }
if ($LASTEXITCODE -ne 0) { throw 'выпуск не создан' }
Write-Output "Опубликовано: https://github.com/$Repo/releases/tag/$tag"
