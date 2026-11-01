# DNS Switcher: User Guide

[Русская версия](USER_GUIDE_RU.md)

The app's interface is in Russian; names below are translated.

## Installation

Run outside the install folder, `DnsSwitcher-Setup.exe` opens a wizard: start, options (folder, shortcuts, launching without UAC, background protection), progress with a Retry button, and a summary. If the app is already installed, the wizard offers to update or remove it.

The app needs administrator rights and asks for them itself. With the "open without an administrator prompt" option the installer creates a "DnsSwitcher Launcher" task, and the shortcut opens the app without a UAC window.

## Simple and Advanced Mode

Simple mode is for when you just want things to work: a card shows the state of the chain, and "Find the best server" chooses for you. The "How it works" section explains the chain with diagrams.

Advanced mode shows the full list, manual selection and a check of every address and proxy.

## Servers

Starting list: GeoHide EU, MagicDNS, dns-ai, GeoHide US, Comss DNS, Xbox-DNS (for AI services, their order sets the fallback queue), AdGuard DNS, Google Public DNS, Cloudflare (regular). A list update changes only the standard servers you have not edited.

## Failure Protection

After two bad checks in a row the app moves to the best-checking server, on a tie to the one with the better history, then to the one higher in the list. Regular DNS and the router's DNS come next. Once the selected server works again, the app returns to it. Cloudflare and Google stay as the last addresses for safety.

Log: `%APPDATA%\DnsSwitcher\events.log`.

## Browsers

A browser with its own secure DNS bypasses the Windows setting. The app finds such browsers and fixes the setting by closing and reopening the browser.

## Removal

Settings → Apps starts the same wizard (`dns-switcher.exe --uninstall`). There you can return DNS to automatic and delete the settings.

## For Developers

The signing key is created once with `scripts\release\new-updater-key.ps1` (the private key goes to Credential Manager, the public key to `assets\updater.pub`, embedded at build time).

- Release: `scripts\release\publish.ps1 -Notes "..." -Publish`.
- Server list: raise `version` in `release\servers.json`, then run `scripts\release\publish-servers.ps1 -Publish`.

The app reads `servers.json` and `servers.json.sig` from the root of the `main` branch and new versions from this repository's releases.

Debug builds do not ask for administrator rights. `DNS_SWITCHER_DEBUG_INSTALLER=1` opens the install wizard (`DNS_SWITCHER_DEBUG_PAGE=options|progress|failed|finish|update|uninstall` picks a page), `DNS_SWITCHER_DEBUG_THEME=light` turns on the light theme, `DNS_SWITCHER_DEBUG_DIALOG=failover|log|editor|confirm` opens a dialog.
