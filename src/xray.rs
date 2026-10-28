use crate::{vless::VlessProfile, xray_config};
use crate::dlog;
use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use std::{
    env, fs,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub struct RunningXray {
    child: Child,
    config: PathBuf,
    socks_port: u16,
}

pub fn check_traffic(port: u16) -> Result<()> {
    let client = Client::builder()
        .proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))?)
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .build()?;
    // ChatGPT — лучший индикатор живого проксированного трафика.
    // Сам HTTP-ответ уже доказывает работу прокси: статус может быть любым
    // (Cloudflare отдаёт 403 без JS и это нормально).
    let response = client.get("https://chatgpt.com/").send()?;
    let status = response.status();
    if !status.is_success() && !status.is_client_error() && !status.is_server_error() {
        bail!("Неожиданный ответ от chatgpt.com: HTTP {status}");
    }
    Ok(())
}

/// Проверка трафика с замером задержки: возвращает пинг в миллисекундах.
pub fn check_traffic_with_ping(port: u16) -> Result<Duration> {
    let started = Instant::now();
    check_traffic(port)?;
    Ok(started.elapsed())
}

/// Системный health-check при активном TUN: прямой запрос без прокси.
/// Если TUN жив — запрос уходит в туннель, как у обычных приложений.
/// ВАЖНО: использовать только при активном TUN, иначе проверяет
/// прямую сеть (и всегда «успешно» из РФ мимо VPN).
pub fn check_traffic_system() -> Result<()> {
    let client = Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .build()?;
    let response = client.get("https://chatgpt.com/").send()?;
    let status = response.status();
    if !status.is_success() && !status.is_client_error() && !status.is_server_error() {
        bail!("Неожиданный ответ от chatgpt.com: HTTP {status}");
    }
    Ok(())
}

/// Зачистка потерянных xray-процессов от прошлых сессий (TUI закрыт
/// аварийно — kill терминала, паника). Наши процессы опознаются по
/// аргументу `-c ...vpn-helper-xray-<pid>\config.json` в командной строке.
/// Возвращает число завершённых процессов. Текущий PID не трогаем.
pub fn cleanup_orphaned_xray() -> usize {
    let marker = "vpn-helper-xray-";
    let own_dir = format!("vpn-helper-xray-{}", std::process::id());
    let output = if cfg!(windows) {
        std::process::Command::new("wmic")
            .args(["process", "where", "name='xray.exe'", "get", "ProcessId,CommandLine"])
            .output()
    } else {
        std::process::Command::new("sh")
            .args(["-c", "ps -eo pid,args | grep '[x]ray.*vpn-helper-xray-'"])
            .output()
    };
    let Ok(output) = output else {
        return 0;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut killed = 0;
    for line in text.lines() {
        // Формат wmic: <commandline> <pid> — pid последнее число в строке;
        // формат ps: <pid> <args> — pid первое число.
        if !line.contains(marker) {
            continue;
        }
        let pid = if cfg!(windows) {
            line.split_whitespace()
                .filter_map(|token| token.parse::<u32>().ok())
                .next_back()
        } else {
            line.split_whitespace()
                .filter_map(|token| token.parse::<u32>().ok())
                .next()
        };
        let Some(pid) = pid else { continue };
        if pid == std::process::id() {
            continue;
        }
        // Не убиваем процессы, чей каталог конфига относится к текущему PID.
        if line.contains(&own_dir) {
            continue;
        }
        let result = if cfg!(windows) {
            std::process::Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        } else {
            std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        };
        if result.is_ok_and(|status| status.success()) {
            killed += 1;
        }
    }
    killed
}

impl RunningXray {
    pub fn socks_port(&self) -> u16 {
        self.socks_port
    }

    pub fn stop(mut self) -> Result<()> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.config);
        if let Some(parent) = self.config.parent() {
            let _ = fs::remove_dir(parent);
        }
        Ok(())
    }
}

impl Drop for RunningXray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = fs::remove_file(&self.config);
    }
}

pub fn discover() -> Option<PathBuf> {
    if let Ok(path) = env::var("XRAY_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    // Бандл в комплекте: tools/xray/xray(.exe) рядом с бинарником или в корне проекта.
    // На non-Windows берём только нативный xray: Windows-бандл tools/xray/xray.exe
    // из Linux-сборки (WSL) не запускается напрямую.
    {
        let names: &[&str] = if cfg!(windows) {
            &["xray.exe", "xray"]
        } else {
            &["xray"]
        };
        let exe_dir = env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf));
        let candidates = [
            exe_dir.clone(),
            exe_dir
                .as_ref()
                .and_then(|dir| dir.parent().map(Path::to_path_buf)),
            env::current_dir().ok(),
        ];
        if let Some(path) = candidates
            .iter()
            .flatten()
            .flat_map(|dir| {
                let sub = dir.join("tools").join("xray");
                names
                    .iter()
                    .map(move |name| sub.join(name))
                    .chain(names.iter().map(|name| dir.join(name)))
            })
            .find(|path| path.is_file())
        {
            return Some(path);
        }
    }
    if let Some(path) = find_on_path() {
        return Some(path);
    }

    // In WSL, WinGet installs Xray on the mounted Windows filesystem and
    // does not expose LOCALAPPDATA to Linux processes.
    let package_roots = if cfg!(windows) {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|local| local.join("Microsoft\\WinGet\\Packages"))
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        let mut roots = Vec::new();
        if let Ok(entries) = fs::read_dir("/mnt/c/Users") {
            for entry in entries.flatten() {
                roots.push(entry.path().join("AppData/Local/Microsoft/WinGet/Packages"));
            }
        }
        roots
    };

    package_roots.into_iter().find_map(|packages| {
        let mut matches = fs::read_dir(packages)
            .ok()?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|v| v.to_str())
                    .is_some_and(|v| v.starts_with("XTLS.Xray-core_"))
            });
        matches.find_map(|path| {
            let exe = path.join("xray.exe");
            exe.is_file().then_some(exe)
        })
    })
}

fn find_on_path() -> Option<PathBuf> {
    let separator = if cfg!(windows) { ';' } else { ':' };
    let names: &[&str] = if cfg!(windows) {
        &["xray.exe", "xray"]
    } else {
        &["xray", "xray.exe"]
    };
    env::var_os("PATH")?
        .to_string_lossy()
        .split(separator)
        .map(PathBuf::from)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|path| path.is_file())
}

pub fn start(profile: &VlessProfile) -> Result<RunningXray> {
    let binary =
        discover().context("Xray не найден в PATH или WinGet. Установите XTLS.Xray-core")?;
    let (listener, port) = free_listener()?;
    drop(listener);
    let config = build_config(profile, port)?;
    let directory = config
        .parent()
        .context("Не удалось определить каталог Xray config")?;
    let xray_config_path = process_path_for_binary(&config, &binary);
    let mut test = Command::new(&binary);
    let test_output = test
        .arg("run")
        .arg("-test")
        .arg("-c")
        .arg(&xray_config_path)
        .output()?;
    if !test_output.status.success() {
        let stderr_str = String::from_utf8_lossy(&test_output.stderr);
        let stdout_str = String::from_utf8_lossy(&test_output.stdout);
        let detail = stderr_str
            .lines()
            .chain(stdout_str.lines())
            .rfind(|line| !line.trim().is_empty())
            .unwrap_or("Xray config test failed");
        bail!("Xray config test failed: {}", redact_xray_error(detail));
    }
    let mut child = Command::new(&binary)
        .arg("run")
        .arg("-c")
        .arg(&xray_config_path)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("Не удалось запустить {}", binary.display()))?;
    dlog!(
        "xray: started pid={} port={} profile={}:{}",
        child.id(),
        port,
        profile.host,
        profile.port
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            dlog!("xray: socks ready pid={}", child.id());
            return Ok(RunningXray {
                child,
                config,
                socks_port: port,
            });
        }
        if child.try_wait()?.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = fs::remove_file(&config);
    dlog!("xray: FAILED to open SOCKS port in 5s, pid killed");
    bail!("Xray не открыл локальный SOCKS-порт")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XrayBinaryType {
    Windows,
    Linux,
}

fn detect_xray_binary_type(binary: &PathBuf) -> XrayBinaryType {
    if cfg!(windows) {
        return XrayBinaryType::Windows;
    }
    if binary.extension().and_then(|e| e.to_str()) == Some("exe") {
        return XrayBinaryType::Windows;
    }
    if let Ok(output) = std::process::Command::new("file").arg(binary).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("ELF")
            || stdout.contains("executable")
                && !stdout.contains("PE32")
                && !stdout.contains("Windows")
        {
            return XrayBinaryType::Linux;
        }
    }
    XrayBinaryType::Linux
}

fn process_path_for_binary(path: &std::path::Path, binary: &PathBuf) -> PathBuf {
    if cfg!(windows) {
        return path.to_path_buf();
    }
    if matches!(detect_xray_binary_type(binary), XrayBinaryType::Windows) {
        let value = path.to_string_lossy();
        if let Some(rest) = value.strip_prefix("/mnt/") {
            let mut parts = rest.splitn(2, '/');
            if let (Some(drive), Some(path)) = (parts.next(), parts.next()) {
                return PathBuf::from(format!(
                    "{}:\\{}",
                    drive.to_uppercase(),
                    path.replace('/', "\\")
                ));
            }
        }
    }
    path.to_path_buf()
}

fn redact_xray_error(error: &str) -> String {
    error
        .replace("uuid", "credential")
        .replace("publicKey", "key")
}

fn free_listener() -> Result<(TcpListener, u16)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

fn build_config(profile: &VlessProfile, socks_port: u16) -> Result<PathBuf> {
    let config_json = xray_config::build_config(profile, socks_port)?;
    let temp_root = if cfg!(windows) {
        env::temp_dir()
    } else {
        // A Windows xray.exe launched through WSL cannot read Linux /tmp paths.
        // Prefer the Windows user that owns the current project, rather than
        // taking the first directory under /mnt/c/Users (which may be Public).
        let mut candidates = Vec::new();
        if let Some(pwd) = env::var_os("PWD") {
            let pwd = PathBuf::from(pwd);
            for ancestor in pwd.ancestors() {
                if ancestor.file_name().and_then(|name| name.to_str()) == Some("Users") {
                    if let Some(user) = pwd
                        .strip_prefix(ancestor)
                        .ok()
                        .and_then(|rest| rest.components().next())
                    {
                        candidates.push(ancestor.join(user.as_os_str()).join("AppData/Local/Temp"));
                    }
                    break;
                }
            }
        }
        if let Some(user) = env::var_os("USER") {
            candidates.push(
                PathBuf::from("/mnt/c/Users")
                    .join(user)
                    .join("AppData/Local/Temp"),
            );
        }
        candidates.push(PathBuf::from("/mnt/c/Windows/Temp"));
        candidates
            .into_iter()
            .find(|path| path.is_dir() && fs::metadata(path).is_ok())
            .unwrap_or_else(env::temp_dir)
    };
    let dir_name = format!("vpn-helper-xray-{}", std::process::id());
    let dir = {
        let preferred = temp_root.join(&dir_name);
        match fs::create_dir_all(&preferred) {
            Ok(()) => preferred,
            Err(_) if !cfg!(windows) => {
                let fallback = PathBuf::from("/mnt/c/Windows/Temp").join(&dir_name);
                fs::create_dir_all(&fallback)
                    .context("Не удалось создать временный каталог для Xray")?;
                fallback
            }
            Err(error) => return Err(error.into()),
        }
    };
    let path = dir.join("config.json");
    fs::write(&path, serde_json::to_vec_pretty(&config_json)?)?;
    Ok(path)
}
