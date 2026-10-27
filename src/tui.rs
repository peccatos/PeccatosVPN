use crate::{
    discovery::{self, DiscoveryResult},
    server_scan::{EndpointCandidate, ProbeStatus},
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
use std::{io, path::Path, sync::mpsc, thread, time::Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeView {
    NotChecked,
    Checking,
    Reachable,
    Unreachable,
}

struct CandidateRow {
    endpoint: EndpointCandidate,
    profile_index: usize,
    valid: bool,
    probe: ProbeView,
    error: Option<String>,
}

struct App {
    profiles: Vec<VlessProfile>,
    candidates: Vec<CandidateRow>,
    selected: usize,
    status: String,
    message: String,
    current: Option<(String, u16)>,
    busy: bool,
    should_quit: bool,
    request_id: u64,
}

impl App {
    fn new(discovery: DiscoveryResult) -> Self {
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
                error: None,
            })
            .collect::<Vec<_>>();
        let message = if rows.is_empty() {
            "VLESS-профили не найдены".to_string()
        } else {
            "Выберите валидный профиль и нажмите c: Xray запустится автоматически".to_string()
        };
        Self {
            profiles,
            candidates: rows,
            selected: 0,
            status: "ОТКЛЮЧЕНО".to_string(),
            message,
            current: None,
            busy: false,
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
        *self = Self::new(discovery);
    }
}

enum WorkerEvent {
    ScanFinished(u64, DiscoveryResult),
    ProbeFinished(u64, usize, ProbeStatus),
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
    let mut app = App::new(discovery);
    app.message = format!(
        "Локально найдено профилей: {} • Нажмите g для публичных источников",
        app.profiles.len()
    );

    while !app.should_quit {
        terminal.draw(|frame| render(frame, &app))?;
        while let Ok(event) = rx.try_recv() {
            apply_worker_event(&mut app, event);
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
        handle_key(&mut app, key, servers_dir, &tx)?;
    }

    if let Err(error) = disconnect() {
        app.message = format!("Отключение завершилось ошибкой: {error}");
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
            app.message =
                "↑↓/j k выбор • c/Enter тест • r локально • g remote sources • d отключить • q выход".into();
        }
        KeyCode::Char('g') | KeyCode::Char('G') if !app.busy => {
            app.busy = true;
            app.status = "ЗАГРУЗКА ИСТОЧНИКОВ".into();
            app.message = "Загрузка явно настроенных HTTPS sources...".into();
            app.request_id += 1;
            let id = app.request_id;
            let tx = tx.clone();
            thread::spawn(move || {
                let result = fetch_public_sources();
                let _ = tx.send(WorkerEvent::ScanFinished(id, result));
            });
        }
        KeyCode::Char('r') if !app.busy => {
            app.busy = true;
            app.status = "СКАНИРОВАНИЕ".into();
            app.message = "Чтение локальных ресурсов...".into();
            app.request_id += 1;
            let id = app.request_id;
            let servers_dir = servers_dir.to_path_buf();
            let tx = tx.clone();
            thread::spawn(move || {
                let result = discovery::scan_directory(&servers_dir);
                let _ = tx.send(WorkerEvent::ScanFinished(id, result));
            });
        }
        KeyCode::Char('c') | KeyCode::Enter if !app.busy => {
            let Some(endpoint) = app.selected_endpoint() else {
                app.message = "Нет профиля для проверки".into();
                return Ok(());
            };
            if !app.candidates[app.selected].valid {
                app.message = "Профиль не прошёл статическую валидацию".into();
                return Ok(());
            }
            app.busy = true;
            app.status = "ЗАПУСК XRAY".into();
            app.message = format!("Запуск безопасного теста {}...", endpoint.label());
            app.candidates[app.selected].probe = ProbeView::Checking;
            app.request_id += 1;
            let id = app.request_id;
            let index = app.selected;
            let tx = tx.clone();
            let profile = app
                .profiles
                .get(app.candidates[app.selected].profile_index)
                .cloned();
            thread::spawn(move || {
                let result = profile.map_or(ProbeStatus::NotChecked, |profile| {
                    match xray::start(&profile) {
                        Ok(runtime) => {
                            let result = xray::check_traffic(runtime.socks_port())
                                .map(|_| ProbeStatus::Reachable)
                                .unwrap_or_else(|error| {
                                    ProbeStatus::Unreachable(error.to_string())
                                });
                            let _ = runtime.stop();
                            result
                        }
                        Err(error) => ProbeStatus::Unreachable(error.to_string()),
                    }
                });
                let _ = tx.send(WorkerEvent::ProbeFinished(id, index, result));
            });
        }
        KeyCode::Char('d') if !app.busy => {
            app.busy = true;
            app.status = "ОТКЛЮЧЕНИЕ".into();
            app.message = "Остановка управляемого процесса...".into();
            // The actual cleanup runs after leaving the UI loop; this keeps rendering responsive.
            app.should_quit = true;
        }
        _ => {}
    }
    Ok(())
}

fn fetch_public_sources() -> DiscoveryResult {
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
    let mut combined = DiscoveryResult::default();
    for url in discovery::PUBLIC_SOURCES {
        let fetched = client
            .get(*url)
            .send()
            .and_then(|response| response.error_for_status());
        match fetched {
            Ok(response) => match response.bytes() {
                Ok(bytes) if bytes.len() <= 16 * 1024 * 1024 => {
                    let text = String::from_utf8_lossy(&bytes);
                    let result = discovery::scan_public_source(&text, url);
                    combined.files_seen += 1;
                    combined.files_read += 1;
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
                Ok(_) => combined
                    .diagnostics
                    .push(format!("Источник слишком большой: {url}")),
                Err(error) => combined
                    .diagnostics
                    .push(format!("Не удалось прочитать источник {url}: {error}")),
            },
            Err(error) => combined
                .diagnostics
                .push(format!("Не удалось загрузить источник {url}: {error}")),
        }
    }
    combined
}

fn apply_worker_event(app: &mut App, event: WorkerEvent) {
    match event {
        WorkerEvent::ScanFinished(id, result) if id == app.request_id => {
            app.busy = false;
            app.reset_discovery(result);
            app.message = format!("Найдено профилей: {}", app.profiles.len());
        }
        WorkerEvent::ProbeFinished(id, index, ProbeStatus::Reachable) if id == app.request_id => {
            app.busy = false;
            app.status = "WORKING (XRAY + HTTPS)".into();
            app.message = "HTTPS-запрос успешно прошёл через локальный Xray SOCKS".into();
            if let Some(row) = app.candidates.get_mut(index) {
                row.probe = ProbeView::Reachable;
            }
        }
        WorkerEvent::ProbeFinished(id, index, ProbeStatus::Unreachable(error))
            if id == app.request_id =>
        {
            app.busy = false;
            app.status = "НЕДОСТУПЕН".into();
            app.message = error.clone();
            if let Some(row) = app.candidates.get_mut(index) {
                row.probe = ProbeView::Unreachable;
                row.error = Some(error);
            }
        }
        WorkerEvent::ProbeFinished(id, _, ProbeStatus::NotChecked) if id == app.request_id => {
            app.busy = false;
            app.status = "НЕ ПРОВЕРЕН".into();
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
    let message = Paragraph::new(Text::from(app.message.as_str()))
        .wrap(Wrap { trim: true })
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().borders(Borders::ALL).title(" EVENT "));
    frame.render_widget(message, main[2]);

    let footer = Paragraph::new(
        " ↑↓/j k select   c/Enter test   d disconnect   r local scan   g public sources   ? help   q/Esc quit ",
    )
    .style(Style::default().fg(Color::Black).bg(Color::Cyan))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, layout[2]);
}

fn render_summary(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let (status_color, icon) = if app.busy {
        (Color::Yellow, "●")
    } else if app.status.starts_with("ДОСТИЖИМ") {
        (Color::Green, "●")
    } else if app.status == "ОШИБКА" || app.status == "НЕДОСТУПЕН" {
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
            format!("{icon} {}", app.status),
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
    let header = Row::new(vec!["", "Endpoint", "Port", "Probe", "Source"]).style(
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
        Row::new(vec![
            Cell::from(if index == app.selected { "▶" } else { " " }),
            Cell::from(row.endpoint.host.clone()),
            Cell::from(row.endpoint.port.to_string()),
            Cell::from(probe),
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
            Constraint::Percentage(32),
            Constraint::Length(7),
            Constraint::Length(12),
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
