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

## TUI and local checking

```powershell
cargo run -- --tui
```

The TUI scans `servers/` for profiles; pressing `c` starts Xray solely to check HTTPS through a local SOCKS port. This is **not** a system VPN and does not change Windows routes.

Public sources (`g`) include the vless-checker keys.json (refreshed every ~30 minutes, keys with latency metrics). JSON sources are parsed automatically: keys are extracted from `best`/`top10[].key` fields.

Keys: `↑`/`↓` or `j`/`k` — select; `c`/Enter — SOCKS check; `r` — rescan; `g` — fetch allowed HTTPS sources; `q`/Esc — quit.

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

## TUI и локальная проверка

```powershell
cargo run -- --tui
```

TUI ищет профили в `servers` и по клавише `c` запускает Xray только для проверки HTTPS через локальный SOCKS. Это **не** системный VPN и не меняет маршруты Windows.

Публичные источники (`g`) включают keys.json vless-checker (обновляется каждые ~30 минут, ключи с метриками latency). JSON-источники разбираются автоматически: ключи извлекаются из полей `best`/`top10[].key`.

Клавиши: `↑`/`↓` или `j`/`k` — выбор; `c`/Enter — SOCKS-проверка; `r` — пересканировать; `g` — загрузить разрешённые HTTPS-источники; `q`/Esc — выход.

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