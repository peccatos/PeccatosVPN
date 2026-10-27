# vpn-helper

Rust supervisor для VLESS-профилей: проверка через локальный Xray SOCKS и полноценный системный Windows TUN. Использует два ядра — `sing-box.exe` (TUN + Reality/gRPC) и `xray.exe` (VLESS+xHTTP за CDN). Оба ядра подтягиваются в `tools/` одной командой (бинарники в git не хранятся — 150 МБ).

## Установка ядер (один раз после клона)

```powershell
# Windows: скрипт подтянет sing-box и Xray в tools/
irm https://raw.githubusercontent.com/SagerNet/sing-box/release/install.ps1 | iex   # или скачайте вручную
winget install XTLS.Xray-core                                                       # Xray
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

## Сборка и проверки

```powershell
cargo fmt -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

Для ручной acceptance-проверки до запуска зафиксируйте состояние сети, а после запуска используйте PowerShell cmdlets `Get-NetAdapter -Name vpn-helper`, `Get-NetRoute`, `Get-DnsClientServerAddress` и проверьте внешний IPv4/IPv6 и DNS leak. После Ctrl+C убедитесь, что процесс sing-box, TUN-интерфейс и созданные маршруты исчезли; повторите запуск, чтобы проверить чистый restart. Smoke не заменяет проверку DNS leak и не доказывает сам по себе, что внешний IP изменился или HTTPS ушёл именно через этот TUN при наличии конкурирующего VPN/split routing. Не запускайте native TUN из WSL: используйте Windows release binary через interop.
# vpn2
