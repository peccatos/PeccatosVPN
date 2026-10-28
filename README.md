# PeccatosVPN — Rust VLESS VPN Supervisor

> **Status: fully working, production-ready.**
> The system-wide TUN mode routes all Windows traffic through the VPN and is verified
> end-to-end: chatgpt.com responds through the tunnel, the external IP changes, DNS is
> resolved via the proxy.

A complete VPN client written in Rust with a terminal UI (ratatui): discovers and
validates VLESS configs from public sources, connects through a local SOCKS proxy, and
**runs a system-level TUN adapter that captures all OS traffic**. It supervises two
external cores — `sing-box` (TUN) and `xray` (VLESS+xHTTP behind a CDN) — hiding the
entire complexity behind a single TUI.

## Features

- **System-wide VPN with zero configuration** — press `t`, a TUN adapter comes up, and
  all Windows traffic (browsers, terminal, any app) flows through the VLESS server.
  Verified with chatgpt.com and other services that block Russian IPs.
- **Smart working-key discovery** — [STR BYPASS cyberportal](https://warp-gen.cyb-portal.org/)
  subscriptions (site-verified keys), parallel validation of all profiles (8 workers,
  live ping per row), automatic persistence of only proven-working configs into a
  local library.
- **Live monitoring** — health-check every 20 seconds (through the TUN when active);
  status switches to `СОЕДИНЕНИЕ ПОТЕРЯНО` (connection lost) when the channel dies,
  one-keypress reconnect.
- **Three modes on demand** — one-shot check (`c`), local SOCKS proxy (`Enter`),
  system-wide TUN (`t`), one-click Chrome through the VPN (`b`).
- **Robustness** — process and temp-config cleanup on exit, orphaned-process sweep on
  startup, automatic UAC elevation, `--debug` mode with a full event log.

## Workflow

```
cargo run -- --tui
  → g          (fetch fresh keys from the cyberportal)
  → a          (parallel check: REACHABLE/FAILED + ping per profile)
  → Enter      (connect — local SOCKS proxy)
  → t          (system TUN — all OS traffic through the VPN)
  → browser    (chatgpt.com opens with no proxy settings whatsoever)
```

## Installation (once)

```powershell
git clone https://github.com/peccatos/PeccatosVPN
cd PeccatosVPN

# Cores (binaries are not stored in git, ~150 MB):
winget install XTLS.Xray-core
irm https://raw.githubusercontent.com/SagerNet/sing-box/release/install.ps1 | iex
# then place xray.exe (+ wintun.dll, geoip.dat, geosite.dat) → tools/xray/
# and sing-box.exe (+ libcronet.dll) → tools/sing-box/
```

Core lookup order: `--singbox-path`/`XRAY_PATH` → `tools/<core>/` → PATH → WinGet.

## Usage

```powershell
cargo run -- --tui            # TUI (requests admin rights via UAC automatically)
cargo run -- --tui --debug    # + full log to debug.log (processes, events, panics)
```

### TUI keys

| Key | Action |
|---|---|
| `↑`/`↓`, `j`/`k` | select profile |
| `Enter` | connect — Xray runs as a SOCKS proxy at `127.0.0.1:<port>` |
| `t` | **system TUN** — all OS traffic through the VPN |
| `a` | parallel check of all profiles (8 workers) + ping |
| `c` | one-shot profile check |
| `p` | pin the current working connection (survives list refreshes) |
| `b` | launch Chrome through the VPN proxy (separate browser profile) |
| `u` | scan a custom URL (subscription / JSON / HTML) |
| `g` | fetch public sources |
| `x` | clean up dead key files |
| `r` | rescan `servers/` |
| `d` | disconnect (TUN + Xray) |
| `q` | quit with auto-cleanup |

### CLI mode (no TUI)

```powershell
cargo run -- --tunnel --profile servers\profile.vless
# core selection is automatic:
#   reality+tcp/grpc  → sing-box (TUN + VLESS directly)
#   tls+xhttp (CDN)   → Xray + sing-box TUN via a SOCKS bridge
```

## Architecture (the interesting part for review)

```
src/
├── tui.rs          # TUI orchestrator: events, worker threads, connect, TUN
├── discovery.rs    # source parsing: plain text / JSON / HTML → VLESS profiles
├── vless.rs        # vless:// link parsing, static validation
├── xray.rs         # xray.exe supervisor: config, spawn, health-checks, zombie sweep
├── singbox.rs      # sing-box supervisor: TUN configs (direct and SOCKS-bridge)
├── tun.rs          # core selection based on profile transport
├── debug_log.rs    # thread-safe debug log (--debug)
└── xray_config.rs  # Xray config generation from a profile
```

Engineering problems that were genuinely fun to solve:

- **The routing loop**: for VLESS servers specified by IP, a `domain` routing rule never
  matches, so the core's own outbound connection went straight into its own TUN →
  deadlock. Fix: an `ip_cidr → direct` rule for IP hosts (covered by the
  `builds_tun_config_ip_host_gets_ip_rule` test).
- **The log deadlock**: `stdout(piped)` with no reader blocks the child process once
  the OS pipe buffer (~64 KB) fills under system-wide traffic. Core logs now go to files.
- **The lying health-check**: a system-wide probe without a TUN adapter routes through
  Wi-Fi and returns a false "alive". The adapter is now verified via WMI before probing.
- **Parallel validation**: a pool of 8 threads with an `Arc<Mutex<queue>>`; each worker
  runs its own short-lived xray process, and the UI stays responsive (events via mpsc).
- **Scanner hardening**: the public import blocks private/reserved endpoints, so the
  tool can never be turned into an internal network scanner.

## Supported transports

- VLESS + Reality + TCP / gRPC
- VLESS + TLS + xHTTP (behind a CDN — via Xray, sing-box raises the TUN)

Profiles with `security=none`, `type=ws`, or unknown parameters are rejected at
validation time. Files with a UTF-8 BOM are parsed correctly.

## Quality

```powershell
cargo fmt -- --check
cargo test                        # 15 tests: parsers, configs, validation
cargo clippy --all-targets -- -- -D warnings
cargo build --release
```

Manual verification: `Get-NetAdapter -Name vpn-helper`, `Get-NetRoute`, external IP
change (`curl https://api.ipify.org` before/after `t`); after quit — no processes, no
adapters, no routes left behind.

## Limitations (honestly)

- Free public VLESS servers live for hours — the app copes (health-checks, quick
  reconnect, working-key persistence), but a 24/7 setup needs your own server.
- TUN mode is Windows-only (wintun); the SOCKS mode is cross-platform.
- One external VPN at a time: competing clients (Amnezia etc.) must be disabled.

## Stack

Rust 2021 · ratatui/crossterm (TUI) · reqwest (networking) · serde_json (configs) ·
clap (CLI) · external cores: xray-core + sing-box

---

# vpn-helper — VLESS VPN-супервизор на Rust

> **Статус: полностью рабочий проект, готов к использованию.**
> Системный TUN-режим поднимает весь трафик Windows через VPN и проверен end-to-end:
> chatgpt.com отвечает через туннель, внешний IP меняется, DNS идёт через прокси.

Полноценный VPN-клиент на Rust с терминальным интерфейсом (ratatui): поиск и проверка
VLESS-конфигов из публичных источников, подключение через локальный SOCKS-прокси и
**системный TUN-режим, заворачивающий весь трафик ОС**. Управляет двумя внешними ядрами —
`sing-box` (TUN) и `xray` (VLESS+xHTTP за CDN), скрывая всю сложность за одним TUI.

## Что умеет

- **Системный VPN без настройки** — клавиша `t` поднимает TUN-адаптер, весь трафик Windows
  (браузеры, терминал, любые приложения) идёт через VLESS-сервер. Работает с chatgpt.com
  и другими сервисами, блокирующими российские IP.
- **Умный поиск рабочих ключей** — подписки [киберпортала STR BYPASS](https://warp-gen.cyb-portal.org/)
  (проверенные сайтом ключи), параллельная проверка всех профилей (8 воркеров, ping в реальном времени),
  автосохранение только подтверждённо рабочих конфигов в локальную библиотеку.
- **Живой мониторинг** — health-check каждые 20 секунд (через TUN, если он поднят), статус
  `СОЕДИНЕНИЕ ПОТЕРЯНО` при смерти канала, перезапуск одним нажатием.
- **Три режима на выбор** — разовая проверка (`c`), локальный SOCKS-прокси (`Enter`),
  системный TUN (`t`), запуск Chrome через VPN (`b`).
- **Надёжность** — автоочистка процессов и временных конфигов при выходе, зачистка
  потерянных процессов при старте, UAC-elevation автоматом, `--debug` с полным логом.

## Скриншот workflow

```
cargo run -- --tui
  → g          (подтянуть свежие ключи с киберпортала)
  → a          (параллельная проверка всех: REACHABLE/FAILED + ping)
  → Enter      (подключиться — SOCKS-прокси)
  → t          (системный TUN — весь трафик ОС через VPN)
  → браузер    (chatgpt.com открывается без единой настройки прокси)
```

## Установка (один раз)

```powershell
git clone https://github.com/peccatos/Xray-SingBox-VPN
cd Xray-SingBox-VPN

# Ядра (бинарники не хранятся в git, ~150 МБ):
winget install XTLS.Xray-core
irm https://raw.githubusercontent.com/SagerNet/sing-box/release/install.ps1 | iex
# затем xray.exe (+ wintun.dll, geoip.dat, geosite.dat) → tools/xray/
# и sing-box.exe (+ libcronet.dll) → tools/sing-box/
```

Поиск ядер: `--singbox-path`/`XRAY_PATH` → `tools/<core>/` → PATH → WinGet.

## Запуск

```powershell
cargo run -- --tui            # TUI (сам запросит права администратора через UAC)
cargo run -- --tui --debug    # + полный лог в debug.log (процессы, события, паники)
```

### Клавиши TUI

| Клавиша | Действие |
|---|---|
| `↑`/`↓`, `j`/`k` | выбор профиля |
| `Enter` | подключить — Xray работает как SOCKS-прокси `127.0.0.1:<port>` |
| `t` | **системный TUN** — весь трафик ОС через VPN |
| `a` | параллельная проверка всех профилей (8 воркеров) + ping |
| `c` | разовая проверка профиля |
| `p` | закрепить рабочее подключение (переживает обновления списка) |
| `b` | Chrome через VPN-прокси (отдельный профиль браузера) |
| `u` | просканировать свой URL (подписка/JSON/HTML) |
| `g` | подтянуть публичные источники |
| `x` | почистить мёртвые файлы ключей |
| `r` | пересканировать `servers/` |
| `d` | отключить (TUN + Xray) |
| `q` | выход с автоочисткой |

### CLI-режим (без TUI)

```powershell
cargo run -- --tunnel --profile servers\profile.vless
# выбор ядра автоматический:
#   reality+tcp/grpc  → sing-box (TUN + VLESS напрямую)
#   tls+xhttp (CDN)   → Xray + sing-box TUN через SOCKS-мост
```

## Архитектура (интересное для ревью)

```
src/
├── tui.rs          # TUI-оркестратор: события, потоки-воркеры, подключение, TUN
├── discovery.rs    # парсинг источников: plain text / JSON / HTML → VLESS-профили
├── vless.rs        # парсинг vless://-ссылок, статическая валидация
├── xray.rs         # супервизор xray.exe: конфиг, запуск, health-check, очистка зомби
├── singbox.rs      # супервизор sing-box: TUN-конфиги (direct и SOCKS-мост)
├── tun.rs          # выбор ядра по транспорту профиля
├── debug_log.rs    # потокобезопасный отладочный лог (--debug)
└── xray_config.rs  # генерация Xray-конфигов из профиля
```

Технические решения, которые было интересно находить:

- **Маршрутная петля**: для VLESS-серверов по IP `domain`-правило маршрутизации не
  срабатывает, и исходящий коннект ядра уходил в собственный TUN → тупик. Решение —
  `ip_cidr → direct` для IP-хостов (покрыто тестом `builds_tun_config_ip_host_gets_ip_rule`).
- **Deadlock на логах**: `stdout(piped)` без читателя блокирует дочерний процесс при
  переполнении буфера ОС (~64 КБ) под системным трафиком. Логи ядер пишутся в файлы.
- **Врущий health-check**: системный чек без TUN-адаптера ходит через Wi-Fi и возвращает
  ложное «жив». Теперь адаптер проверяется WMI до запроса.
- **Параллельная проверка**: пул из 8 потоков с `Arc<Mutex<queue>>`, каждый воркер гоняет
  свой короткоживущий xray-процесс; UI не блокируется (события через mpsc).
- **Защита от сканирования**: публичный импорт блокирует private/reserved endpoints.

## Поддерживаемые транспорты

- VLESS + Reality + TCP / gRPC
- VLESS + TLS + xHTTP (за CDN — через Xray, sing-box поднимает TUN)

Профили с `security=none`, `type=ws`, неизвестными параметрами отклоняются на этапе
валидации. Файлы с UTF-8 BOM читаются корректно.

## Качество

```powershell
cargo fmt -- --check
cargo test                        # 15 тестов: парсеры, конфиги, валидация
cargo clippy --all-targets -- -- -D warnings
cargo build --release
```

Проверка результата руками: `Get-NetAdapter -Name vpn-helper`, `Get-NetRoute`,
смена внешнего IP (`curl https://api.ipify.org` до/после `t`), после выхода — ни
процессов, ни адаптеров, ни маршрутов.

## Ограничения (честно)

- Бесплатные публичные VLESS-серверы живут часы — приложение это переживает
  (health-check, быстрый переподключение, сохранение рабочих), но для 24/7
  нужен свой сервер.
- TUN-режим — Windows only (wintun); SOCKS-режим кроссплатформенный.
- Один внешний VPN одновременно: конкурирующие клиенты (Amnezia и т.п.) нужно отключать.

## Стек

Rust 2021 · ratatui/crossterm (TUI) · reqwest (network) · serde_json (конфиги) ·
clap (CLI) · внешние ядра xray-core + sing-box
