<p align="center"><img src="assets/icon.png" width="96" alt="DNS Switcher icon"></p>

# Переключатель DNS / DNS Switcher

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue?style=flat-square)](README.md)
[![Rust](https://img.shields.io/badge/Rust-2024-orange?style=flat-square&logo=rust)](Cargo.toml)
[![Release](https://img.shields.io/github/v/release/ServChan/dns-switcher?style=flat-square)](https://github.com/ServChan/dns-switcher/releases/latest)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

Windows 10/11 app that keeps a list of DNS servers, applies or resets one in a single click, and falls back safely when a server stops working.

**Руководство / User guide:** [Русский](docs/USER_GUIDE_RU.md) · [English](docs/USER_GUIDE_EN.md)

**Скачать / Download:** [DnsSwitcher-Setup.exe](https://github.com/ServChan/dns-switcher/releases/latest)

## Русский

### Что это

Программа для Windows 10/11: список DNS-серверов, применение и сброс в один щелчок, отдельная группа серверов для обхода региональных ограничений ИИ и защита от сбоев.

### Возможности

- **Простой режим**: одна карточка «всё ли работает», цепочка «Компьютер → Браузер → DNS → Прокси → ИИ-сервисы» и кнопка «Подобрать лучший сервер». **Подробный режим**: весь список, ручной выбор, проверка каждого адреса и прокси.
- **Шифрование DoH** (Windows 11): шаблон в `netsh dns encryption`, для адаптера режим «только зашифрованные».
- **Проверка до самого сервиса**: DNS по UDP или DoH, затем TLS-соединение с прокси для ChatGPT, Gemini, Claude, AI Studio, NotebookLM, Copilot, Perplexity и своих сервисов. Сверка с эталонным DNS показывает, подменяет ли сервер адрес, и ловит утечку через IPv6.
- **Сквозная проверка через Windows**: доходят ли ответы выбранного сервера до системы.
- **Браузеры со своим защищённым DNS** (Chrome, Chromium, Edge, Яндекс, Brave, Opera, Opera GX, Comet, Vivaldi, Firefox): находит и исправляет.
- **Защита от сбоев**: после двух плохих проверок подряд переключается на лучший сервер, затем на обычные DNS и DNS от роутера, а потом возвращается к выбранному. Работает в фоне через Планировщик, со значком и уведомлениями.
- **Обновления**: раз в день подписанный список серверов и проверка новой версии. Всё скачанное проверяется подписью ed25519.

### Установка

Скачайте `DnsSwitcher-Setup.exe` из [выпусков](https://github.com/ServChan/dns-switcher/releases/latest) и запустите. Мастер предложит папку, ярлыки, запуск без запроса UAC и фоновую защиту. Программе нужны права администратора.

### Сборка

```
cargo build --release
```

Результат: `target\release\dns-switcher.exe` (он же установщик). Значок перерисовывается скриптом `python tools/make_icon.py`. Проверка серверов на живой сети: `cargo test -- --ignored --nocapture`. Выпуск и отладочные режимы описаны в [руководстве](docs/USER_GUIDE_RU.md#для-разработки).

## English

### What It Is

A Windows 10/11 app with a list of DNS servers, one-click apply and reset, a dedicated group of servers for getting around regional restrictions on AI services, and failure protection.

### Features

- **Simple mode**: one "is everything working" card, the Computer → Browser → DNS → Proxy → AI services chain, and a "Find the best server" button. **Advanced mode**: the full list, manual selection, a check of every address and proxy.
- **DoH encryption** (Windows 11): a template in `netsh dns encryption` and "encrypted only" mode for the adapter.
- **Checks reach the service itself**: DNS over UDP or DoH, then a TLS connection to the proxies for ChatGPT, Gemini, Claude, AI Studio, NotebookLM, Copilot, Perplexity and your own services. Comparison with a reference DNS shows whether a server really rewrites the address and catches IPv6 leaks.
- **End-to-end check through Windows**: confirms that answers from the selected server reach the system.
- **Browsers with their own secure DNS** (Chrome, Chromium, Edge, Yandex, Brave, Opera, Opera GX, Comet, Vivaldi, Firefox): detected and fixed.
- **Failure protection**: after two bad checks in a row it moves to the best server, then to regular DNS and the router's DNS, and later returns to your choice. Runs in the background through Task Scheduler, with a tray icon and notifications.
- **Updates**: a signed server list once a day and a check for new versions. Everything downloaded is verified with an ed25519 signature.

### Installation

Download `DnsSwitcher-Setup.exe` from [Releases](https://github.com/ServChan/dns-switcher/releases/latest) and run it. The wizard offers a folder, shortcuts, launching without a UAC prompt and background protection. The app needs administrator rights. The interface is in Russian.

### Building

```
cargo build --release
```

Output: `target\release\dns-switcher.exe`, which is also the installer. Redraw the icon with `python tools/make_icon.py`. Live server checks: `cargo test -- --ignored --nocapture`. Releasing and debug modes are covered in the [guide](docs/USER_GUIDE_EN.md#for-developers).

## Лицензия / License

MIT, см. / see [LICENSE](LICENSE).
