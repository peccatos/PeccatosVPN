use crate::{
    discovery::{self, DiscoveryResult},
    server_scan::{EndpointCandidate, ProbeStatus},
    singbox,
    vless::{ProfileState, VlessProfile},
    xray,
};
use anyhow::{Context, Result};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Terminal,
};
use std::{
    fs,
    io,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

/// Период health-check работающего VPN-соединения.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(20);

/// Число одновременных проверок профилей (клавиша a).
/// 8 процессов Xray параллельно: быстрый проход, умеренная нагрузка на CPU/сеть.
const CHECK_ALL_PARALLELISM: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeView {
    NotChecked,
    Checking,
    Reachable,
    Unreachable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Lost,
}

impl ConnectionState {
    fn label(self) -> &'static str {
        match self {
            Self::Disconnected => "ОТКЛЮЧЕНО",
            Self::Connecting => "ПОДКЛЮЧЕНИЕ",
            Self::Connected => "ПОДКЛЮЧЕНО",
            Self::Lost => "СОЕДИНЕНИЕ ПОТЕРЯНО",
        }
    }

    fn is_active(self) -> bool {
        matches!(self, Self::Connected)
    }
}

struct CandidateRow {
    endpoint: EndpointCandidate,
    profile_index: usize,
    valid: bool,
    probe: ProbeView,
    /// Задержка проверки в мс (проставляется после успешного чека).
    ping: Option<u64>,
    error: Option<String>,
}

struct App {
    /// Локальный каталог для сохранения рабочих профилей (servers/).
    servers_dir: std::path::PathBuf,
    profiles: Vec<VlessProfile>,
    candidates: Vec<CandidateRow>,
    selected: usize,
    status: ConnectionState,
    message: String,
    current: Option<(String, u16)>,
    runtime: Option<xray::RunningXray>,
    busy: bool,
    /// Идёт ли фоновая проверка всех профилей (клавиша a).
    check_all_running: bool,
    /// Индекс профиля, который сейчас проверяется в check-all (для отображения).
    check_all_current: Option<usize>,
    /// Закреплённое рабочее подключение (host, port) — клавиша p.
    pinned: Option<(String, u16)>,
    /// Активный ввод URL для сканирования (клавиша u): Some(набранный текст).
    url_input: Option<String>,
    /// Запущенный системный TUN (sing-box) — клавиша t.
    tun: Option<singbox::RunningSingBox>,
    should_quit: bool,
    request_id: u64,
}

impl App {
    fn new(discovery: DiscoveryResult, servers_dir: &Path) -> Self {
        let profiles = discovery
            .profiles
            .iter()
            .map(|item| item.profile.clone())
            .collect::<Vec<_>>();
        let rows = profiles
            .iter()
            .enumerate()
            .map(|(profile_index, profile)| CandidateRow {
                endpoint: EndpointCandidate {
                    host: profile.host.clone(),
                    port: profile.port,
                    scheme: Some("vless".into()),
                    source: profile.source.clone(),
                },
                profile_index,
                valid: matches!(&profile.state, ProfileState::Valid),
                probe: ProbeView::NotChecked,
                ping: None,
                error: None,
            })
            .collect::<Vec<_>>();
        let message = if rows.is_empty() {
            "VLESS-профили не найдены".to_string()
        } else {
            "Выберите валидный профиль и нажмите c: Xray запустится автоматически".to_string()
        };
        Self {
            servers_dir: servers_dir.to_path_buf(),
            profiles,
            candidates: rows,
            selected: 0,
            status: ConnectionState::Disconnected,
            message,
            current: None,
            runtime: None,
            busy: false,
            check_all_running: false,
            check_all_current: None,
            pinned: None,
            url_input: None,
            tun: None,
            should_quit: false,
            request_id: 0,
        }
    }

    fn selected_endpoint(&self) -> Option<EndpointCandidate> {
        self.candidates
            .get(self.selected)
            .map(|row| row.endpoint.clone())
    }

    fn move_selection(&mut self, delta: isize) {
        if self.candidates.is_empty() {
            return;
        }
        let last = self.candidates.len() - 1;
        self.selected = if delta < 0 {
            self.selected.saturating_sub(delta.unsigned_abs())
        } else {
            (self.selected + delta as usize).min(last)
        };
    }

    fn reset_discovery(&mut self, discovery: DiscoveryResult) {
        let runtime = self.runtime.take();
        let current = self.current.take();
        let pinned = self.pinned.take();
        let servers_dir = self.servers_dir.clone();
        *self = Self::new(discovery, &servers_dir);
        self.runtime = runtime;
        self.current = current.clone();
        self.pinned = pinned.clone();
        // Возврат выделения на закреплённый или сохранённый профиль.
        let target = pinned.or(current);
        if let Some((host, port)) = target {
            if let Some(index) = self_position(&self.candidates, &host, port) {
                self.selected = index;
            }
        }
    }

    /// Слияние списков: локальные профили сохраняются, новые из `incoming`
    /// дописываются. Дубликаты (host+port+security+transport+sni) склеиваются.
    fn merge_discovery(&mut self, incoming: DiscoveryResult) {
        let existing_keys = self
            .profiles
            .iter()
            .map(profile_fingerprint)
            .collect::<Vec<_>>();
        for item in incoming.profiles {
            let fingerprint = profile_fingerprint(&item.profile);
            if existing_keys.contains(&fingerprint) {
                continue;
            }
            let profile_index = self.profiles.len();
            self.profiles.push(item.profile.clone());
            self.candidates.push(CandidateRow {
                endpoint: EndpointCandidate {
                    host: item.profile.host.clone(),
                    port: item.profile.port,
                    scheme: Some("vless".into()),
                    source: item.profile.source.clone(),
                },
                profile_index,
                valid: matches!(&item.profile.state, ProfileState::Valid),
                probe: ProbeView::NotChecked,
                ping: None,
                error: None,
            });
        }
    }
}

/// Ключ идентичности профиля (совпадает с discovery::profile_key).
/// Поиск строки кандидата по host:port.
fn self_position(rows: &[CandidateRow], host: &str, port: u16) -> Option<usize> {
    rows.iter()
        .position(|row| row.endpoint.host == host && row.endpoint.port == port)
}

fn profile_fingerprint(profile: &VlessProfile) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        profile.host.to_ascii_lowercase(),
        profile.port,
        profile.security,
        profile.transport,
        profile.sni.as_deref().unwrap_or("")
    )
}

enum WorkerEvent {
    /// true — источник публичный (списки объединяются), false — локальный (заменяется).
    ScanFinished(u64, bool, DiscoveryResult),
    ProbeFinished(u64, usize, ProbeStatus, Option<u64>),
    Connected(u64, usize, xray::RunningXray, Option<u64>),
    HealthChecked(u64, bool),
    /// Начата проверка профиля `index` в рамках check-all (клавиша a).
    CheckAllStarted(u64, usize),
    /// Один профиль в check-all проверен (ping — мс при успехе).
    CheckAllItem(u64, usize, ProbeStatus, Option<u64>),
    /// Check-all завершён (ok — число рабочих, failed — число отвалившихся).
    CheckAllFinished(u64, usize, usize),
    /// Системный TUN поднят.
    TunUp(u64, singbox::RunningSingBox),
    /// TUN не удалось поднять.
    TunFailed(u64),
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        terminal::disable_raw_mode().ok();
        execute!(io::stdout(), LeaveAlternateScreen, cursor::Show).ok();
    }
}

pub fn run(servers_dir: &Path, mut disconnect: impl FnMut() -> Result<()>) -> Result<()> {
    let mut stdout = io::stdout();
    terminal::enable_raw_mode().context("Не удалось включить raw mode")?;
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
    let _guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let (tx, rx) = mpsc::channel();
    let discovery = discovery::scan_directory(servers_dir);
    let mut app = App::new(discovery, servers_dir);
    app.message = format!(
        "Локально найдено профилей: {} • Нажмите g для публичных источников",
        app.profiles.len()
    );
    let mut last_health_check = Instant::now();

    while !app.should_quit {
        terminal.draw(|frame| render(frame, &app))?;
        while let Ok(event) = rx.try_recv() {
            apply_worker_event(&mut app, event);
        }
        // Health-check: раз в HEALTH_CHECK_INTERVAL проверяем живость прокси.
        if app.status.is_active()
            && app.runtime.is_some()
            && last_health_check.elapsed() >= HEALTH_CHECK_INTERVAL
        {
            last_health_check = Instant::now();
            let id = app.request_id;
            let port = app
                .runtime
                .as_ref()
                .map(xray::RunningXray::socks_port)
                .expect("runtime проверён выше");
            let tx = tx.clone();
            thread::spawn(move || {
                let healthy = xray::check_traffic(port).is_ok();
                let _ = tx.send(WorkerEvent::HealthChecked(id, healthy));
            });
        }
        if !event::poll(Duration::from_millis(150))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        // Режим ввода URL (u): клавиши идут в строку, а не в горячие клавиши.
        if app.url_input.is_some() {
            handle_url_input(&mut app, key, &tx)?;
            continue;
        }
        handle_key(&mut app, key, servers_dir, &tx)?;
    }

    if let Some(mut tun) = app.tun.take() {
        let _ = tun.stop();
    }
    if let Some(runtime) = app.runtime.take() {
        let _ = runtime.stop();
    }
    if let Err(error) = disconnect() {
        app.message = format!("Отключение завершилось ошибкой: {error}");
    }
    Ok(())
}

/// Обработка клавиш в режиме ввода URL (после клавиши u).
fn handle_url_input(app: &mut App, key: KeyEvent, tx: &mpsc::Sender<WorkerEvent>) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            app.url_input = None;
            app.message = "Ввод URL отменён".into();
        }
        KeyCode::Enter => {
            let url = app.url_input.take().unwrap_or_default();
            if url.trim().is_empty() {
                app.message = "Пустой URL — отмена".into();
                return Ok(());
            }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                app.message = "URL должен начинаться с http:// или https://".into();
                return Ok(());
            }
            app.busy = true;
            app.message = format!("Загрузка и скан {url}...");
            app.request_id += 1;
            let id = app.request_id;
            let tx = tx.clone();
            thread::spawn(move || {
                let result = fetch_single_source(&url);
                let _ = tx.send(WorkerEvent::ScanFinished(id, true, result));
            });
        }
        KeyCode::Backspace => {
            if let Some(input) = app.url_input.as_mut() {
                input.pop();
            }
        }
        KeyCode::Char(ch) => {
            if let Some(input) = app.url_input.as_mut() {
                input.push(if key.modifiers.contains(crossterm::event::KeyModifiers::SHIFT) {
                    ch.to_ascii_uppercase()
                } else {
                    ch
                });
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_key(
    app: &mut App,
    key: KeyEvent,
    servers_dir: &Path,
    tx: &mpsc::Sender<WorkerEvent>,
) -> Result<()> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
        KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
        KeyCode::Char('?') => {
            app.message = "↑↓/j k • Enter подкл • t системный TUN • p пин • c тест • a все • u URL • x чистка • b браузер • r локально • g public • d откл • q выход".into();
        }
        KeyCode::Char('u') if !app.busy && app.url_input.is_none() => {
            app.url_input = Some(String::new());
            app.message = "Введите URL (http://...): Enter — скан, Esc — отмена".into();
        }
        KeyCode::Char('x') if !app.busy && !app.check_all_running => {
            // Удаляем локальные файлы, чьи профили не работают (не REACHABLE).
            let mut removed = 0;
            let dead: Vec<PathBuf> = app
                .candidates
                .iter()
                .filter(|row| row.probe != ProbeView::Reachable)
                .filter_map(|row| {
                    let path = Path::new(row.endpoint.source.as_path());
                    (path.is_absolute() && path.is_file()).then(|| path.to_path_buf())
                })
                .collect();
            for path in dead {
                if fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
            }
            app.message = format!("Чистка: удалено файлов с мёртвыми профилями: {removed}");
        }
        KeyCode::Char('p') if !app.busy => {
            // Пин: закрепить текущее подключение (host, port). Переживает
            // обновления списков (g/r): строка ищется заново и выделяется.
            let Some((host, port)) = app.current.clone() else {
                app.message = "Нет активного подключения для пина — сначала Enter".into();
                return Ok(());
            };
            app.pinned = Some((host.clone(), port));
            if let Some(index) = self_position(&app.candidates, &host, port) {
                app.selected = index;
            }
            app.message = format!("Закреплено {host}:{port} — переживёт g/r/a");
        }
        KeyCode::Char('t') if !app.busy => {
            // Системный TUN: весь трафик ОС через VPN (нужны права администратора).
            if app.tun.is_some() {
                app.message = "TUN уже активен — нажмите d для отключения".into();
                return Ok(());
            }
            let Some(runtime) = app.runtime.as_ref() else {
                app.message =
                    "Сначала подключитесь (Enter), затем поднимайте системный TUN (t)".into();
                return Ok(());
            };
            let Some(profile) = app.profiles.get(app.candidates[app.selected].profile_index).cloned() else {
                app.message = "Профиль не найден".into();
                return Ok(());
            };
            let _ = profile;
            let socks_port = runtime.socks_port();
            app.busy = true;
            app.message = "Запуск системного TUN-интерфейса...".into();
            app.request_id += 1;
            let id = app.request_id;
            let tx = tx.clone();
            thread::spawn(move || {
                let event = match singbox::start_for_tui(
                    None,
                    &profile,
                    Some(socks_port),
                    1500,
                    "vpn-helper",
                ) {
                    Ok(mut running) => {
                        // Ждём готовности TUN-интерфейса до 30 сек.
                        let deadline = Instant::now() + Duration::from_secs(30);
                        let mut ready = false;
                        while Instant::now() < deadline {
                            match running.tun_ready("vpn-helper") {
                                Ok(true) => {
                                    ready = true;
                                    break;
                                }
                                Ok(false) => thread::sleep(Duration::from_millis(400)),
                                Err(_) => break,
                            }
                        }
                        if ready {
                            WorkerEvent::TunUp(id, running)
                        } else {
                            let _ = running.stop();
                            WorkerEvent::TunFailed(id)
                        }
                    }
                    Err(error) => {
                        let _ = error;
                        WorkerEvent::TunFailed(id)
                    }
                };
                let _ = tx.send(event);
            });
        }
        KeyCode::Char('b') if !app.busy => {
            // Запуск Chrome через VPN-прокси (отдельный профиль, чтобы не мешать основному).
            let Some(runtime) = app.runtime.as_ref() else {
                app.message = "Сначала подключитесь (Enter), затем запускайте браузер (b)".into();
                return Ok(());
            };
            let port = runtime.socks_port();
            let chrome_paths = [
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files\Google\Chrome Beta\Application\chrome.exe",
                // Edge как запасной вариант (те же флаги)
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            ];
            let Some(chrome) = chrome_paths.iter().find(|p| Path::new(p).is_file()) else {
                app.message = "Chrome/Edge не найдены в стандартных путях".into();
                return Ok(());
            };
            let profile_dir = std::env::temp_dir().join("vpn-helper-chrome-profile");
            let _ = fs::create_dir_all(&profile_dir);
            let launched = std::process::Command::new(chrome)
                .arg(format!("--proxy-server=socks5://127.0.0.1:{port}"))
                .arg("--proxy-bypass-list=<-loopback>")
                .arg(format!("--user-data-dir={}", profile_dir.display()))
                .arg("https://chatgpt.com")
                .spawn();
            match launched {
                Ok(child) => {
                    app.message = format!(
                        "Браузер запущен через VPN (PID {}), SOCKS 127.0.0.1:{port}",
                        child.id()
                    );
                }
                Err(error) => {
                    app.message = format!("Не удалось запустить браузер: {error}");
                }
            }
        }
        KeyCode::Char('a') if !app.busy && !app.check_all_running => {
            let valid_indices: Vec<usize> = app
                .candidates
                .iter()
                .enumerate()
                .filter(|(_, row)| row.valid)
                .map(|(index, _)| index)
                .collect();
            if valid_indices.is_empty() {
                app.message = "Нет валидных профилей для проверки".into();
                return Ok(());
            }
            app.check_all_running = true;
            let worker_count = CHECK_ALL_PARALLELISM.min(valid_indices.len());
            app.message = format!(
                "Параллельная проверка {} профилей ({} потока)...",
                valid_indices.len(),
                worker_count
            );
            app.request_id += 1;
            let id = app.request_id;
            let profiles = valid_indices
                .iter()
                .filter_map(|&index| app.profiles.get(app.candidates[index].profile_index).cloned())
                .collect::<Vec<_>>();
            let tx = tx.clone();
            thread::spawn(move || {
                // Очередь задач: (индекс строки, профиль). Воркеры разбирают её конкурентно.
                let queue = std::sync::Arc::new(std::sync::Mutex::new(
                    valid_indices.into_iter().zip(profiles).collect::<Vec<_>>(),
                ));
                let results =
                    std::sync::Arc::new(std::sync::Mutex::new((0_usize, 0_usize))); // (ok, failed)
                let mut workers = Vec::with_capacity(worker_count);
                for _ in 0..worker_count {
                    let queue = std::sync::Arc::clone(&queue);
                    let results = std::sync::Arc::clone(&results);
                    let tx = tx.clone();
                    workers.push(thread::spawn(move || loop {
                        // Атомарно забираем следующую задачу из очереди.
                        let Some((row_index, profile)) =
                            queue.lock().map(|mut q| q.pop()).ok().flatten()
                        else {
                            break;
                        };
                        let _ = tx.send(WorkerEvent::CheckAllStarted(id, row_index));
                        let (status, ping) = match xray::start(&profile) {
                            Ok(runtime) => {
                                let (result, ping) =
                                    xray::check_traffic_with_ping(runtime.socks_port())
                                        .map(|elapsed| {
                                            (
                                                ProbeStatus::Reachable,
                                                Some(elapsed.as_millis() as u64),
                                            )
                                        })
                                        .unwrap_or_else(|error| {
                                            (
                                                ProbeStatus::Unreachable(error.to_string()),
                                                None,
                                            )
                                        });
                                let _ = runtime.stop();
                                (result, ping)
                            }
                            Err(error) => (ProbeStatus::Unreachable(error.to_string()), None),
                        };
                        if matches!(status, ProbeStatus::Reachable) {
                            results.lock().map(|mut r| r.0 += 1).ok();
                        } else {
                            results.lock().map(|mut r| r.1 += 1).ok();
                        }
                        let _ = tx.send(WorkerEvent::CheckAllItem(id, row_index, status, ping));
                    }));
                }
                let mut ok = 0;
                let mut failed = 0;
                for worker in workers {
                    let _ = worker.join();
                }
                if let Ok(counts) = results.lock() {
                    ok = counts.0;
                    failed = counts.1;
                }
                let _ = tx.send(WorkerEvent::CheckAllFinished(id, ok, failed));
            });
        }
        KeyCode::Char('g') | KeyCode::Char('G') if !app.busy => {
            app.busy = true;
            app.message = "Загрузка публичных sources...".into();
            app.request_id += 1;
            let id = app.request_id;
            let tx = tx.clone();
            thread::spawn(move || {
                let result = fetch_public_sources();
                let _ = tx.send(WorkerEvent::ScanFinished(id, true, result));
            });
        }
        KeyCode::Char('r') if !app.busy => {
            app.busy = true;
            app.message = "Чтение локальных ресурсов...".into();
            app.request_id += 1;
            let id = app.request_id;
            let servers_dir = servers_dir.to_path_buf();
            let tx = tx.clone();
            thread::spawn(move || {
                let result = discovery::scan_directory(&servers_dir);
                let _ = tx.send(WorkerEvent::ScanFinished(id, false, result));
            });
        }
        KeyCode::Enter if !app.busy => {
            // «Подключить VPN»: Xray запускается и остаётся работать до отключения.
            if app.runtime.is_some() {
                app.message = "VPN уже подключён — сначала нажмите d для отключения".into();
                return Ok(());
            }
            let Some(endpoint) = app.selected_endpoint() else {
                app.message = "Нет профиля для подключения".into();
                return Ok(());
            };
            if !app.candidates[app.selected].valid {
                app.message = "Профиль не прошёл статическую валидацию".into();
                return Ok(());
            }
            app.busy = true;
            app.status = ConnectionState::Connecting;
            app.message = format!("Запуск VPN через {}...", endpoint.label());
            app.candidates[app.selected].probe = ProbeView::Checking;
            app.candidates[app.selected].ping = None;
            app.request_id += 1;
            let id = app.request_id;
            let index = app.selected;
            let tx = tx.clone();
            let profile = app
                .profiles
                .get(app.candidates[app.selected].profile_index)
                .cloned();
            thread::spawn(move || {
                let event = match profile {
                    Some(profile) => match xray::start(&profile) {
                        Ok(runtime) => {
                            // Замеряем пинг сразу после старта, чтобы колонка Ping
                            // заполнилась и для активного подключения.
                            let ping = xray::check_traffic_with_ping(runtime.socks_port())
                                .ok()
                                .map(|elapsed| elapsed.as_millis() as u64);
                            if ping.is_none() {
                                // Стартовый чек не прошёл: сервер мёртв, отключаемся.
                                let _ = runtime.stop();
                                WorkerEvent::ProbeFinished(
                                    id,
                                    index,
                                    ProbeStatus::Unreachable(
                                        "Стартовый health-check не прошёл".into(),
                                    ),
                                    None,
                                )
                            } else {
                                WorkerEvent::Connected(id, index, runtime, ping)
                            }
                        }
                        Err(error) => WorkerEvent::ProbeFinished(
                            id,
                            index,
                            ProbeStatus::Unreachable(error.to_string()),
                            None,
                        ),
                    },
                    None => WorkerEvent::ProbeFinished(id, index, ProbeStatus::NotChecked, None),
                };
                let _ = tx.send(event);
            });
        }
        KeyCode::Char('c') if !app.busy => {
            let Some(endpoint) = app.selected_endpoint() else {
                app.message = "Нет профиля для проверки".into();
                return Ok(());
            };
            if !app.candidates[app.selected].valid {
                app.message = "Профиль не прошёл статическую валидацию".into();
                return Ok(());
            }
            app.busy = true;
            app.message = format!("Запуск безопасного теста {}...", endpoint.label());
            app.candidates[app.selected].probe = ProbeView::Checking;
            app.candidates[app.selected].ping = None;
            app.request_id += 1;
            let id = app.request_id;
            let index = app.selected;
            let tx = tx.clone();
            let profile = app
                .profiles
                .get(app.candidates[app.selected].profile_index)
                .cloned();
            thread::spawn(move || {
                let result = profile.map_or(
                    (ProbeStatus::NotChecked, None),
                    |profile| match xray::start(&profile) {
                        Ok(runtime) => {
                            let (result, ping) =
                                xray::check_traffic_with_ping(runtime.socks_port())
                                    .map(|elapsed| {
                                        (
                                            ProbeStatus::Reachable,
                                            Some(elapsed.as_millis() as u64),
                                        )
                                    })
                                    .unwrap_or_else(|error| {
                                        (ProbeStatus::Unreachable(error.to_string()), None)
                                    });
                            let _ = runtime.stop();
                            (result, ping)
                        }
                        Err(error) => (ProbeStatus::Unreachable(error.to_string()), None),
                    },
                );
                let _ = tx.send(WorkerEvent::ProbeFinished(id, index, result.0, result.1));
            });
        }
        KeyCode::Char('d') if !app.busy => {
            // Сначала гасим TUN, затем Xray.
            if let Some(mut tun) = app.tun.take() {
                let _ = tun.stop();
                app.message = "TUN-интерфейс остановлен. ".into();
            }
            if let Some(runtime) = app.runtime.take() {
                let socks_port = runtime.socks_port();
                if let Err(error) = runtime.stop() {
                    app.message = format!("Ошибка остановки Xray: {error}");
                } else {
                    app.message =
                        format!("VPN отключён (локальный SOCKS 127.0.0.1:{socks_port} остановлен)");
                }
            } else {
                app.message = "VPN не подключён".into();
            }
            app.status = ConnectionState::Disconnected;
            app.current = None;
        }
        _ => {}
    }
    Ok(())
}

fn fetch_public_sources() -> DiscoveryResult {
    let mut combined = DiscoveryResult::default();
    for url in discovery::PUBLIC_SOURCES {
        let result = fetch_single_source(url);
        combined.files_seen += result.files_seen;
        combined.files_read += result.files_read;
        combined.urls_found += result.urls_found;
        combined.diagnostics.extend(result.diagnostics);
        for mut found in result.profiles {
            if let Some(existing) = combined.profiles.iter_mut().find(|item| {
                item.profile.host == found.profile.host
                    && item.profile.port == found.profile.port
                    && item.profile.uuid() == found.profile.uuid()
            }) {
                existing.duplicate_count += 1 + found.duplicate_count;
            } else {
                found.source.display = url.to_string();
                combined.profiles.push(found);
            }
        }
    }
    combined
}

/// Загружает один источник (URL) и сканит его содержимое на VLESS-ключи.
/// Понимает plain text, JSON и HTML.
fn fetch_single_source(url: &str) -> DiscoveryResult {
    let client = match reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("vpn-helper/0.1 (public-config-import)")
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            return DiscoveryResult {
                diagnostics: vec![format!("Не удалось создать HTTPS client: {error}")],
                ..DiscoveryResult::default()
            }
        }
    };
    let fetched = client
        .get(url)
        .send()
        .and_then(|response| response.error_for_status());
    match fetched {
        Ok(response) => match response.bytes() {
            Ok(bytes) if bytes.len() <= 16 * 1024 * 1024 => {
                let text = String::from_utf8_lossy(&bytes);
                let mut result = discovery::scan_public_source(&text, url);
                result.files_seen = 1;
                result.files_read = 1;
                for item in result.profiles.iter_mut() {
                    item.source.display = url.to_string();
                }
                result
            }
            Ok(_) => DiscoveryResult {
                diagnostics: vec![format!("Источник слишком большой: {url}")],
                ..DiscoveryResult::default()
            },
            Err(error) => DiscoveryResult {
                diagnostics: vec![format!("Не удалось прочитать источник {url}: {error}")],
                ..DiscoveryResult::default()
            },
        },
        Err(error) => DiscoveryResult {
            diagnostics: vec![format!("Не удалось загрузить источник {url}: {error}")],
            ..DiscoveryResult::default()
        },
    }
}

fn apply_worker_event(app: &mut App, event: WorkerEvent) {
    match event {
        WorkerEvent::ScanFinished(id, is_public, result) if id == app.request_id => {
            app.busy = false;
            if is_public {
                let before = app.profiles.len();
                let found = result.profiles.len();
                app.merge_discovery(result);
                app.message = format!(
                    "Публичные источники: найдено {}, добавлено {} (всего {})",
                    found,
                    app.profiles.len() - before,
                    app.profiles.len()
                );
            } else {
                app.reset_discovery(result);
                app.message = format!("Найдено профилей: {}", app.profiles.len());
            }
        }
        WorkerEvent::Connected(id, index, runtime, ping) if id == app.request_id => {
            app.busy = false;
            let socks_port = runtime.socks_port();
            app.runtime = Some(runtime);
            app.status = ConnectionState::Connected;
            if let Some(row) = app.candidates.get_mut(index) {
                app.current = Some((row.endpoint.host.clone(), row.endpoint.port));
                row.probe = ProbeView::Reachable;
                row.ping = ping;
                // Подтверждённо рабочий конфиг — сохраняем в локальную библиотеку.
                if let Some(profile) = app.profiles.get(row.profile_index) {
                    if discovery::persist_working_profile(&app.servers_dir, profile) {
                        app.message = format!(
                            "VPN подключён (SOCKS 127.0.0.1:{socks_port}), конфиг сохранён в {}",
                            app.servers_dir.display()
                        );
                    }
                }
            }
            app.message = format!(
                "VPN подключён: локальный SOCKS-прокси 127.0.0.1:{socks_port} активен. "
            );
        }
        WorkerEvent::ProbeFinished(id, index, ProbeStatus::Reachable, ping)
            if id == app.request_id =>
        {
            app.busy = false;
            app.message = "HTTPS-запрос успешно прошёл через локальный Xray SOCKS".into();
            if let Some(row) = app.candidates.get_mut(index) {
                row.probe = ProbeView::Reachable;
                row.ping = ping;
            }
        }
        WorkerEvent::ProbeFinished(id, index, ProbeStatus::Unreachable(error), _)
            if id == app.request_id =>
        {
            app.busy = false;
            app.message = error.clone();
            if let Some(row) = app.candidates.get_mut(index) {
                row.probe = ProbeView::Unreachable;
                row.error = Some(error);
                row.ping = None;
            }
        }
        WorkerEvent::ProbeFinished(id, _, ProbeStatus::NotChecked, _) if id == app.request_id => {
            app.busy = false;
        }
        WorkerEvent::CheckAllStarted(id, index) if id == app.request_id => {
            app.check_all_current = Some(index);
            if let Some(row) = app.candidates.get_mut(index) {
                row.probe = ProbeView::Checking;
                row.ping = None;
            }
        }
        WorkerEvent::CheckAllItem(id, index, status, ping) if id == app.request_id => {
            app.check_all_current = None;
            if let Some(row) = app.candidates.get_mut(index) {
                match status {
                    ProbeStatus::Reachable => {
                        row.probe = ProbeView::Reachable;
                        row.ping = ping;
                        // Рабочий конфиг уходит в локальную библиотеку.
                        if let Some(profile) = app.profiles.get(row.profile_index) {
                            let _ = discovery::persist_working_profile(&app.servers_dir, profile);
                        }
                    }
                    ProbeStatus::Unreachable(ref error) => {
                        row.probe = ProbeView::Unreachable;
                        row.error = Some(error.clone());
                        row.ping = None;
                    }
                    ProbeStatus::NotChecked => {}
                }
            }
        }
        WorkerEvent::CheckAllFinished(id, ok, failed) if id == app.request_id => {
            app.check_all_running = false;
            app.check_all_current = None;
            app.message = format!(
                "Проверка завершена: рабочих {ok}, нерабочих {failed}. Выбирай REACHABLE и жми Enter"
            );
        }
        WorkerEvent::TunUp(id, running) if id == app.request_id => {
            app.busy = false;
            app.tun = Some(running);
            app.message = "Системный TUN активен: весь трафик ОС идёт через VPN".into();
        }
        WorkerEvent::TunFailed(id) if id == app.request_id => {
            app.busy = false;
            app.message =
                "TUN не поднялся (проверьте права администратора и наличие sing-box)".into();
        }
        WorkerEvent::HealthChecked(id, healthy) if id == app.request_id => {
            if healthy {
                if app.status.is_active() {
                    app.message = "Health-check: соединение живо (chatgpt.com доступен)".into();
                }
            } else if app.status.is_active() {
                // Прокси не отвечает: переводим в Lost, Xray оставляем —
                // пользователь может переподключиться (d → Enter) или подождать.
                app.status = ConnectionState::Lost;
                app.message =
                    "Health-check не прошёл: сервер перестал отвечать. Нажмите d, затем Enter для переподключения".into();
            }
        }
        _ => {}
    }
}

fn render(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = frame.area();
    let outer = Block::default().style(Style::default().bg(Color::Rgb(12, 16, 24)));
    frame.render_widget(outer, area);
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " VPN HELPER ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "• LOCAL + PUBLIC SOURCES",
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" VPN CONTROL "),
    );
    frame.render_widget(header, layout[0]);

    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(layout[1].inner(Margin {
            vertical: 1,
            horizontal: 1,
        }));
    render_summary(frame, app, main[0]);
    render_table(frame, app, main[1]);
    // В режиме ввода URL (u) EVENT-панель превращается в строку ввода.
    let message = if let Some(input) = app.url_input.as_ref() {
        Paragraph::new(Line::from(vec![
            Span::styled("URL: ", Style::default().fg(Color::Cyan)),
            Span::raw(input.clone()),
            Span::styled("▏", Style::default().fg(Color::Cyan)),
        ]))
        .block(Block::default().borders(Borders::ALL).title(" INPUT URL "))
    } else {
        Paragraph::new(Text::from(app.message.as_str()))
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL).title(" EVENT "))
    };
    frame.render_widget(message, main[2]);

    let footer = Paragraph::new(
        " ↑↓ select   [Enter] connect   t TUN system-wide   p pin   a all   u URL   b browser   x clean   d off   g public   ? help   q quit ",
    )
    .style(Style::default().fg(Color::Black).bg(Color::Cyan))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, layout[2]);
}

fn render_summary(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let (status_color, icon) = if app.busy {
        (Color::Yellow, "●")
    } else if app.status.is_active() {
        (Color::Green, "●")
    } else if app.status == ConnectionState::Lost {
        (Color::Red, "●")
    } else {
        (Color::DarkGray, "○")
    };
    let current = app
        .current
        .as_ref()
        .map_or("—".into(), |(host, port)| format!("{host}:{port}"));
    let text = Line::from(vec![
        Span::raw(" Status  "),
        Span::styled(
            format!("{icon} {}", app.status.label()),
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("     Current endpoint  "),
        Span::styled(current, Style::default().fg(Color::White)),
    ]);
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" CONNECTION ")),
        area,
    );
}

fn render_table(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let header = Row::new(vec!["", "Endpoint", "Port", "Probe", "Ping", "Source"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let rows = app.candidates.iter().enumerate().map(|(index, row)| {
        let probe = match row.probe {
            ProbeView::NotChecked if !row.valid => {
                Span::styled("INVALID", Style::default().fg(Color::Red))
            }
            ProbeView::NotChecked => Span::styled("—", Style::default().fg(Color::DarkGray)),
            ProbeView::Checking => Span::styled("CHECKING", Style::default().fg(Color::Yellow)),
            ProbeView::Reachable => Span::styled("REACHABLE", Style::default().fg(Color::Green)),
            ProbeView::Unreachable => Span::styled("FAILED", Style::default().fg(Color::Red)),
        };
        let ping = match (row.ping, row.probe) {
            (Some(ms), _) => {
                let color = if ms < 500 {
                    Color::Green
                } else if ms < 2000 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                Span::styled(format!("{ms}ms"), Style::default().fg(color))
            }
            (None, ProbeView::Reachable) => Span::styled("?", Style::default().fg(Color::Green)),
            _ => Span::styled("—", Style::default().fg(Color::DarkGray)),
        };
        let marker = if let Some((host, port)) = &app.pinned {
            if &row.endpoint.host == host && row.endpoint.port == *port {
                "📌"
            } else if index == app.selected {
                "▶"
            } else {
                " "
            }
        } else if index == app.selected {
            "▶"
        } else {
            " "
        };
        Row::new(vec![
            Cell::from(marker),
            Cell::from(row.endpoint.host.clone()),
            Cell::from(row.endpoint.port.to_string()),
            Cell::from(probe),
            Cell::from(ping),
            Cell::from(if row.valid {
                row.endpoint.source.display().to_string()
            } else {
                "INVALID PROFILE".to_string()
            }),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Percentage(30),
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .column_spacing(1)
    .row_highlight_style(
        Style::default()
            .bg(Color::Rgb(20, 75, 95))
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("");
    let mut state = TableState::default();
    state.select((!app.candidates.is_empty()).then_some(app.selected));
    frame.render_stateful_widget(table, area, &mut state);
}
