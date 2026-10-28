# vpn-helper

**English below ↓ / English first, Russian after**

Rust supervisor for VLESS profiles: profile validation and liveness checks through a local Xray SOCKS proxy, plus a full system-level Windows TUN VPN. Two cores are used — `sing-box` (TUN + Reality/gRPC) and `xray` (VLESS+xHTTP behind a CDN). Core binaries are not stored in git (~150 MB); fetch them once after cloning.

## Core installation (once, after clone)

```powershell
# sing-box: run the official installer or download manually
irm https://raw.githubusercontent.com/SagerNet/sing-box/release/install.ps1 | iex
# Xray
winget install XTLS.Xray-core
# then copy xray.exe (+ wintun.dll, geoip.dat, geosite.dat) into tools/xray/
# and sing-box.exe (+ libcronet.dll) into tools/sing-box/
```

Core lookup order: `--singbox-path`/`XRAY_PATH` → `tools/<core>/` next to the binary → PATH → WinGet package. Under WSL the Linux build uses native `xray`/`sing-box` from PATH (Windows `.exe` files in tools/ are skipped).

## System VPN

Run Windows Terminal as administrator:

```powershell
cargo run -- --tunnel --profile servers\profile.vless

# core selection is automatic, based on the profile transport:
#   reality+tcp, reality+grpc, tls+tcp  -> sing-box directly (TUN + VLESS)
#   tls+xhttp (CDN keys)                -> Xray (VLESS+xhttp) + sing-box TUN via a local SOCKS bridge
```

`--tunnel` validates the generated config with `sing-box check`, waits for the TUN interface and its active Windows route to appear (up to 30 s), then runs a system-path reachability smoke test: DNS and plain HTTPS without a SOCKS proxy, with bounded timeouts and retries. This confirms the interface/route and system network reachability, but does not prove that the HTTPS request actually egressed through the new TUN (competing VPNs, split routing, or a connected-subnet-only route can mask it). The check is a startup smoke test, not a VPN egress or DNS-leak verification. Only after a successful smoke does the core keep running until Ctrl+C. On error or stop, the process and temporary runtime are cleaned up; keep a config copy for diagnostics with `--tunnel-config`.

Supported profiles at this stage:

- VLESS + Reality + TCP;
- VLESS + Reality + gRPC;
- VLESS + TLS + xHTTP (via Xray; the sing-box bridge raises the TUN).

Profiles with `security=none`, `type=ws`, `tls+tcp` and unknown parameters are rejected before launch. Do not use profiles from untrusted sources without inspection. Public import blocks local/private/reserved endpoints so the tool cannot be turned into an internal network scanner.

Key files with a UTF-8 BOM are parsed correctly (BOM is stripped).

## TUI: connect, check, and system-wide TUN

```powershell
cargo run -- --tui
```

On Windows the app requests UAC elevation automatically at startup (needed for the system TUN mode) and relaunches itself as administrator.

The TUI scans `servers/` for profiles; `g` fetches fresh public keys. The primary source is the [STR BYPASS cyberportal](https://warp-gen.cyb-portal.org/) subscriptions (CP-002/005/007/008) — site-verified keys in the supported transports (xhttp+tls, reality+tcp), refreshed by the portal daily. Sources in plain text, JSON and HTML are all parsed; a custom URL can be scanned with `u`.

Keys:

| Key | Action |
|---|---|
| `↑`/`↓` or `j`/`k` | select profile |
| `Enter` | **connect** — Xray stays running as a local SOCKS proxy (`127.0.0.1:<port>`) |
| `t` | **system-wide TUN** — route all OS traffic through the current connection (sing-box; admin required) |
| `c` | one-shot check of the selected profile (Xray starts, HTTPS via SOCKS, Xray stops) |
| `a` | check **all** profiles in parallel (8 workers), live status + ping per row |
| `p` | pin the current working connection (survives list refreshes) |
| `b` | launch Chrome through the VPN proxy (separate browser profile) |
| `u` | scan a custom URL (subscription, keys.json, HTML page) |
| `x` | clean up dead local key files |
| `g` | fetch public sources |
| `r` | rescan `servers/` |
| `d` | disconnect (stops TUN and Xray) |
| `q`/Esc | quit (auto-cleanup) |

Working profiles (reachable check or successful connect) are **persisted to `servers/`** (`public-<host>-<port>.txt`), so your local library only accumulates keys proven to work. A health-check runs every 20 s against chatgpt.com; if the proxy dies the status switches to `СОЕДИНЕНИЕ ПОТЕРЯНО` (red).

Note: `Enter`/`c`/`b` modes give you a local SOCKS proxy — only apps pointed at the proxy use the VPN. For all-OS traffic press `t` after connecting (TUN via sing-box). Parallel checking (`a`) keeps running while connected: each profile is checked by its own short-lived Xray process, not through the active tunnel.

## A note on public keys

Free public VLESS servers (vless-checker etc.) are short-lived: keys work for hours, then the same server stops responding. The application handles this correctly — it finds, starts, checks, reports honestly and cleans up. For a reliable connection you need your own or a paid server; with one, everything works without code changes. Also note: some ISPs deploy DPI that filters VLESS-shaped traffic — a server can be TCP-reachable while the VLESS handshake never completes. If every public key fails while plain HTTPS works, that is the likely cause.

## Build and checks

```powershell
cargo fmt -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

For manual acceptance testing, record your network state before launch; after launch use the PowerShell cmdlets `Get-NetAdapter -Name vpn-helper`, `Get-NetRoute`, `Get-DnsClientServerAddress`, and check your external IPv4/IPv6 and DNS leaks. After Ctrl+C, make sure the sing-box process, TUN interface and created routes are gone; relaunch to verify a clean restart. The smoke test does not replace a DNS-leak check and does not by itself prove the external IP changed. Do not run the native TUN from WSL: use the Windows release binary via interop.

---

# vpn-helper (по-русски)

Rust-супервизор для VLESS-профилей: валидация профилей и проверка живости через локальный Xray SOCKS, плюс полноценный системный Windows TUN VPN. Использует два ядра — `sing-box` (TUN + Reality/gRPC) и `xray` (VLESS+xHTTP за CDN). Бинарники ядер в git не хранятся (~150 МБ); подтягиваются одной командой после клона.

## Установка ядер (один раз после клона)

```powershell
# sing-box: официальный инсталлер или скачайте вручную
irm https://raw.githubusercontent.com/SagerNet/sing-box/release/install.ps1 | iex
# Xray
winget install XTLS.Xray-core
# затем скопируйте xray.exe (+ wintun.dll, geoip.dat, geosite.dat) в tools/xray/
# и sing-box.exe (+ libcronet.dll) в tools/sing-box/
```

Ядра ищутся по очереди: `--singbox-path`/`XRAY_PATH` → `tools/<core>/` рядом с бинарником → PATH → WinGet-пакет. В WSL Linux-сборка использует нативный `xray`/`sing-box` из PATH (Windows-`.exe` из tools/ пропускаются).

## Системный VPN

Запускайте Windows Terminal от имени администратора:

```powershell
cargo run -- --tunnel --profile servers\profile.vless

# выбор ядра автоматический по транспорту профиля:
#   reality+tcp, reality+grpc, tls+tcp  -> sing-box напрямую (TUN + VLESS)
#   tls+xhttp (CDN-ключи)               -> Xray (VLESS+xhttp) + sing-box TUN через локальный SOCKS-мост
```

`--tunnel` сначала проверяет конфигурацию через `sing-box check`, затем ждёт появления активного TUN-интерфейса и связанного с ним активного маршрута Windows (до 30 секунд) и выполняет system-path reachability smoke: DNS и HTTPS без SOCKS-прокси, с ограниченными таймаутами и повторами. Это подтверждает наличие интерфейса/маршрута и доступность системной сети, но не доказывает, что эффективный маршрут HTTPS-запроса выбрал именно новый TUN (например, при конкурирующем VPN, split routing или если на интерфейсе виден лишь подключённый subnet route). Проверка является стартовым smoke, а не проверкой VPN egress или DNS leak. Только после успешного smoke core остаётся запущенным до Ctrl+C. При ошибке или остановке процесс и временный runtime очищаются; для диагностики можно сохранить копию через `--tunnel-config`.

Поддерживаемые профили на текущем этапе:

- VLESS + Reality + TCP;
- VLESS + Reality + gRPC;
- VLESS + TLS + xHTTP (через Xray; sing-box-мост поднимает TUN).

Профили с `security=none`, `type=ws`, `tls+tcp` и неизвестными параметрами отклоняются до запуска. Не используйте профили из недоверенных источников без проверки. Публичный импорт блокирует локальные/private/reserved endpoints, чтобы не превращать Xray/sing-box в средство внутреннего сканирования.

Файлы ключей с UTF-8 BOM читаются корректно (BOM отбрасывается).

## TUI: подключение, проверка и системный TUN

```powershell
cargo run -- --tui
```

При старте на Windows приложение само запрашивает повышение прав через UAC (нужно для системного TUN) и перезапускается от администратора.

TUI сканирует `servers/` на профили; `g` подтягивает свежие публичные ключи. Основной источник — подписки [киберпортала STR BYPASS](https://warp-gen.cyb-portal.org/) (CP-002/005/007/008): проверенные сайтом ключи в поддерживаемых транспортах (xhttp+tls, reality+tcp), портал обновляет их ежедневно. Разбираются источники в plain text, JSON и HTML; свой URL сканируется клавишей `u`.

Клавиши:

| Клавиша | Действие |
|---|---|
| `↑`/`↓` или `j`/`k` | выбор профиля |
| `Enter` | **подключить** — Xray остаётся работать как локальный SOCKS-прокси (`127.0.0.1:<порт>`) |
| `t` | **системный TUN** — весь трафик ОС через текущее подключение (sing-box; нужны права админа) |
| `c` | разовая проверка выбранного профиля (Xray стартует, HTTPS через SOCKS, Xray останавливается) |
| `a` | проверка **всех** профилей параллельно (8 воркеров), статусы и ping в реальном времени |
| `p` | закрепить текущее рабочее подключение (переживает обновления списка) |
| `b` | запустить Chrome через VPN-прокси (отдельный профиль браузера) |
| `u` | просканировать свой URL (подписка, keys.json, HTML-страница) |
| `x` | почистить мёртвые локальные файлы ключей |
| `g` | загрузить публичные источники |
| `r` | пересканировать `servers/` |
| `d` | отключить (останавливает TUN и Xray) |
| `q`/Esc | выход (автоочистка) |

Рабочие профили (успешная проверка или подключение) **сохраняются в `servers/`** (`public-<host>-<port>.txt`) — в локальной библиотеке копятся только подтверждённо живые ключи. Каждые 20 с идёт health-check через chatgpt.com; если прокси умер, статус переключается на `СОЕДИНЕНИЕ ПОТЕРЯНО` (красный).

Учтите: `Enter`/`c`/`b` дают локальный SOCKS-прокси — VPN работает только у приложений, которым прокси указан. Для всего трафика ОС нажмите `t` после подключения. Параллельная проверка (`a`) работает и при активном подключении: каждый профиль проверяется своим короткоживущим Xray-процессом, а не через активный туннель.

## Про публичные ключи

Бесплатные публичные VLESS-серверы (vless-checker и т.п.) живут недолго: ключи работают часы, потом тот же сервер перестаёт отвечать. Приложение обрабатывает это правильно — находит, поднимает, проверяет, честно отчитывается и чистит за собой. Для стабильного подключения нужен свой или платный сервер — с ним всё заработает без изменений кода. Учтите также: некоторые провайдеры применяют DPI, который фильтрует трафик с признаками VLESS — сервер может быть TCP-доступен, но VLESS-хендшейк так и не проходит. Если все публичные ключи падают, а обычный HTTPS работает — это, скорее всего, оно.

## Сборка и проверки

```powershell
cargo fmt -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

Для ручной acceptance-проверки до запуска зафиксируйте состояние сети, а после запуска используйте PowerShell cmdlets `Get-NetAdapter -Name vpn-helper`, `Get-NetRoute`, `Get-DnsClientServerAddress` и проверьте внешний IPv4/IPv6 и DNS leak. После Ctrl+C убедитесь, что процесс sing-box, TUN-интерфейс и созданные маршруты исчезли; повторите запуск, чтобы проверить чистый restart. Smoke не заменяет проверку DNS leak и не доказывает сам по себе, что внешний IP изменился. Не запускайте native TUN из WSL: используйте Windows release binary через interop.