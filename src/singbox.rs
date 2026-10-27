use crate::{vless::VlessProfile, Args};
use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const READINESS_TIMEOUT: Duration = Duration::from_secs(30);
const SMOKE_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(400);
const HEALTH_ENDPOINTS: &[&str] = &[
    "https://www.gstatic.com/generate_204",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://example.com/",
];

pub struct RunningSingBox {
    child: Child,
    runtime_dir: PathBuf,
    config_path: PathBuf,
    keep_config: Option<PathBuf>,
    child_stopped: bool,
    cleaned: bool,
}

impl RunningSingBox {
    pub fn stop(&mut self) -> Result<()> {
        self.stop_child()?;
        self.cleanup()
    }

    fn stop_child(&mut self) -> Result<()> {
        if self.child_stopped {
            return Ok(());
        }
        if self.child.try_wait()?.is_none() {
            self.child
                .kill()
                .context("Не удалось остановить sing-box")?;
        }
        self.child
            .wait()
            .context("Не удалось дождаться завершения sing-box")?;
        self.child_stopped = true;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.child_stopped {
            bail!("Нельзя удалить runtime до остановки sing-box");
        }
        if self.cleaned {
            return Ok(());
        }
        let preserve_result = if let Some(destination) = &self.keep_config {
            (|| {
                if let Some(parent) = destination
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("Не удалось создать каталог {}", parent.display())
                    })?;
                }
                fs::copy(&self.config_path, destination).with_context(|| {
                    format!(
                        "Не удалось сохранить конфигурацию в {}",
                        destination.display()
                    )
                })?;
                Ok(())
            })()
        } else {
            Ok(())
        };
        let remove_result = fs::remove_dir_all(&self.runtime_dir)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .with_context(|| {
                format!(
                    "Не удалось удалить runtime-каталог {}",
                    self.runtime_dir.display()
                )
            });
        self.cleaned = preserve_result.is_ok() && remove_result.is_ok();
        preserve_result.and(remove_result)
    }
}

impl Drop for RunningSingBox {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.stop_child();
            let _ = self.cleanup();
        }
    }
}

pub fn run(args: &Args, profile: &VlessProfile) -> Result<()> {
    let mode = CoreMode::Direct;
    run_with_mode(args, profile, mode)
}

/// Туннель через локальный SOCKS-порт (обычно Xray с xhttp-транспортом):
/// sing-box поднимает TUN и направляет трафик в SOCKS, Xray несёт VLESS.
pub fn run_via_socks(args: &Args, profile: &VlessProfile, socks_port: u16) -> Result<()> {
    let mode = CoreMode::ViaSocks(socks_port);
    run_with_mode(args, profile, mode)
}

pub enum CoreMode {
    Direct,
    ViaSocks(u16),
}

fn run_with_mode(args: &Args, profile: &VlessProfile, mode: CoreMode) -> Result<()> {
    let binary = discover(args.singbox_path.as_deref())
        .context("sing-box не найден. Укажите --singbox-path или добавьте sing-box.exe в PATH")?;
    let config = match &mode {
        CoreMode::Direct => build_config(profile, args.mtu, &args.tun_name)?,
        CoreMode::ViaSocks(port) => build_config_via_socks(profile, args.mtu, &args.tun_name, *port)?,
    };
    let runtime_dir = unique_runtime_dir()?;
    let config_path = runtime_dir.join("config.json");
    let config_bytes = serde_json::to_vec_pretty(&config)?;
    if let Err(error) = fs::write(&config_path, config_bytes) {
        let _ = fs::remove_dir_all(&runtime_dir);
        return Err(error.into());
    }

    let check = match Command::new(&binary)
        .args(["check", "-c"])
        .arg(&config_path)
        .output()
        .with_context(|| format!("Не удалось проверить {}", binary.display()))
    {
        Ok(check) => check,
        Err(error) => {
            let _ = fs::remove_dir_all(&runtime_dir);
            return Err(error);
        }
    };
    if !check.status.success() {
        let detail = String::from_utf8_lossy(&check.stderr);
        let _ = fs::remove_dir_all(&runtime_dir);
        bail!("sing-box отклонил конфигурацию: {}", redact(&detail));
    }

    let mut command = Command::new(&binary);
    command
        .args(["run", "-c"])
        .arg(&config_path)
        .stdin(Stdio::null());
    command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let child = match command
        .spawn()
        .with_context(|| format!("Не удалось запустить {}", binary.display()))
    {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_dir_all(&runtime_dir);
            return Err(error);
        }
    };
    let mut running = RunningSingBox {
        child,
        runtime_dir,
        config_path,
        keep_config: args.tunnel_config.clone(),
        child_stopped: false,
        cleaned: false,
    };

    let run_result = (|| {
        readiness_check(&mut running, &args.tun_name)?;
        traffic_smoke(&mut running)?;
        eprintln!(
            "Smoke-подключение успешно: найден TUN-интерфейс с активным маршрутом; DNS/HTTPS доступны через системную сеть."
        );
        wait_for_ctrl_c(&mut running)
    })();
    let stop_result = running.stop();
    match (run_result, stop_result) {
        (Err(run_error), Err(stop_error)) => {
            Err(run_error.context(format!("cleanup также завершился ошибкой: {stop_error}")))
        }
        (Err(run_error), Ok(())) => Err(run_error),
        (Ok(()), Err(stop_error)) => Err(stop_error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn readiness_check(running: &mut RunningSingBox, interface_name: &str) -> Result<()> {
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let mut last_state = String::from("интерфейс или маршрут пока не обнаружен");
    while Instant::now() < deadline {
        if let Some(status) = running.child.try_wait()? {
            bail!("sing-box завершился до готовности TUN: {status}");
        }
        match windows_tun_ready(interface_name) {
            Ok(true) => return Ok(()),
            Ok(false) => last_state = "ожидается интерфейс или активный маршрут".into(),
            Err(error) => last_state = error.to_string(),
        }
        thread::sleep(POLL_INTERVAL);
    }
    bail!(
        "TUN не готов за {} секунд: {last_state}",
        READINESS_TIMEOUT.as_secs()
    )
}

#[cfg(windows)]
fn windows_tun_ready(interface_name: &str) -> Result<bool> {
    let script = r#"$ErrorActionPreference='Stop'; $a=Get-NetAdapter | Where-Object { $_.Name -ceq $env:VPN_HELPER_TUN_NAME -and $_.Status -eq 'Up' } | Select-Object -First 1; if ($null -eq $a) { 'false'; exit 0 }; $routes=Get-NetRoute -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Alive' -and $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1','::/0','::/1','8000::/1') }; if ($null -eq $routes) { 'false' } else { 'true' }"#;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("VPN_HELPER_TUN_NAME", interface_name)
        .output()
        .context("Не удалось запросить состояние TUN/маршрута через PowerShell")?;
    if !output.status.success() {
        bail!("PowerShell не смог проверить TUN/маршрут");
    }
    parse_readiness_output(&String::from_utf8_lossy(&output.stdout))
}

fn parse_readiness_output(output: &str) -> Result<bool> {
    match output.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => bail!("Неожиданный ответ при проверке TUN/маршрута"),
    }
}

#[cfg(not(windows))]
fn windows_tun_ready(_interface_name: &str) -> Result<bool> {
    bail!("Системный TUN smoke доступен только в Windows-сборке")
}

fn traffic_smoke(running: &mut RunningSingBox) -> Result<()> {
    let client = Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(7))
        .build()
        .context("Не удалось создать HTTPS клиент для system-path smoke")?;
    let deadline = Instant::now() + SMOKE_TIMEOUT;
    let mut last_error = None;
    while Instant::now() < deadline {
        if let Some(status) = running.child.try_wait()? {
            bail!("sing-box завершился во время smoke-проверки: {status}");
        }
        let dns_ok = match std::net::ToSocketAddrs::to_socket_addrs(&("example.com", 443)) {
            Ok(addresses) => {
                if addresses.into_iter().next().is_some() {
                    true
                } else {
                    last_error = Some("DNS: example.com разрешился без адресов".to_string());
                    false
                }
            }
            Err(error) => {
                last_error = Some(format!("DNS: {error}"));
                false
            }
        };
        if !dns_ok {
            thread::sleep(POLL_INTERVAL);
            continue;
        }
        let mut https_ok = false;
        for endpoint in HEALTH_ENDPOINTS {
            if Instant::now() >= deadline {
                break;
            }
            match client.get(*endpoint).send() {
                Ok(response) if is_success_status(response.status()) => {
                    https_ok = true;
                    break;
                }
                Ok(response) => {
                    last_error = Some(format!("{endpoint}: HTTP {}", response.status()))
                }
                Err(error) => last_error = Some(format!("{endpoint}: {error}")),
            }
        }
        if https_ok {
            match client.get("https://example.com/").send() {
                Ok(response) if is_success_status(response.status()) => return Ok(()),
                Ok(response) => {
                    last_error = Some(format!("HTTPS after DNS: HTTP {}", response.status()))
                }
                Err(error) => last_error = Some(format!("HTTPS after DNS: {error}")),
            }
        }
        thread::sleep(POLL_INTERVAL);
    }
    let detail = last_error
        .as_deref()
        .unwrap_or("нет ответа от HTTPS endpoints");
    bail!(
        "System-path DNS/HTTPS smoke не прошёл за {} секунд: {detail}",
        SMOKE_TIMEOUT.as_secs()
    )
}

pub fn discover(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit.filter(|path| path.is_file()) {
        return Some(path.to_path_buf());
    }
    // Бинарник в комплекте: tools/sing-box/sing-box(.exe) рядом с бинарником или в корне проекта.
    // На non-Windows берём только нативный sing-box: Windows-бандл tools/sing-box/sing-box.exe
    // из Linux-сборки (WSL) не запускается напрямую.
    {
        let names: &[&str] = if cfg!(windows) {
            &["sing-box.exe", "sing-box"]
        } else {
            &["sing-box"]
        };
        let exe_dir = env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf));
        let candidates = [
            exe_dir.clone(),
            exe_dir.as_ref().and_then(|dir| dir.parent().map(Path::to_path_buf)),
            env::current_dir().ok(),
        ];
        if let Some(path) = candidates.iter().flatten().flat_map(|dir| {
            let sub = dir.join("tools").join("sing-box");
            names
                .iter()
                .map(move |name| sub.join(name))
                .chain(names.iter().map(|name| dir.join(name)))
        }).find(|path| path.is_file()) {
            return Some(path);
        }
    }
    if let Ok(path) = env::var("SING_BOX_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    let names: &[&str] = if cfg!(windows) {
        &["sing-box.exe", "sing-box"]
    } else {
        &["sing-box", "sing-box.exe"]
    };
    env::var_os("PATH")?
        .to_string_lossy()
        .split(if cfg!(windows) { ';' } else { ':' })
        .map(PathBuf::from)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|path| path.is_file())
}

fn wait_for_ctrl_c(running: &mut RunningSingBox) -> Result<()> {
    let stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stopped.clone();
    ctrlc::set_handler(move || flag.store(true, std::sync::atomic::Ordering::Relaxed))
        .context("Не удалось установить обработчик Ctrl+C")?;
    while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
        if let Some(status) = running.child.try_wait()? {
            bail!("sing-box завершился раньше времени: {status}");
        }
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

pub fn build_config(profile: &VlessProfile, mtu: u16, interface_name: &str) -> Result<Value> {
    if interface_name.is_empty() || interface_name.chars().any(char::is_control) {
        bail!("Недопустимое имя TUN-интерфейса");
    }
    let outbound = outbound(profile)?;
    // Домен прокси-сервера резолвим локально (мимо туннеля), иначе DNS-петля:
    // proxy-dns ходит через прокси, а прокси требует резолва собственного домена.
    let host_domain = Value::String(profile.host.clone());
    Ok(json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [
                { "type": "udp", "tag": "local-dns", "server": "1.1.1.1" },
                { "type": "https", "tag": "proxy-dns", "server": "1.1.1.1", "detour": "proxy" }
            ],
            "final": "proxy-dns",
            "strategy": "prefer_ipv4"
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "interface_name": interface_name,
            "address": ["172.19.0.1/30"], "mtu": mtu,
            "auto_route": true, "strict_route": true, "stack": "system"
        }],
        "outbounds": [outbound, {"type":"direct","tag":"direct"}, {"type":"block","tag":"block"}],
        "route": {
            "auto_detect_interface": true,
            "default_domain_resolver": "local-dns",
            "final": "proxy",
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"domain": [host_domain], "action": "route", "outbound": "direct"},
                {"ip_is_private": true, "action": "route", "outbound": "direct"}
            ]
        }
    }))
}

/// Конфиг для SOCKS-моста: TUN-интерфейс sing-box направляет весь трафик
/// в локальный SOCKS-порт (обычно Xray с VLESS+xhttp за CDN).
/// profile используется только для host (правило маршрутизации домена прокси-сервера).
pub fn build_config_via_socks(
    profile: &VlessProfile,
    mtu: u16,
    interface_name: &str,
    socks_port: u16,
) -> Result<Value> {
    if interface_name.is_empty() || interface_name.chars().any(char::is_control) {
        bail!("Недопустимое имя TUN-интерфейса");
    }
    let host_domain = Value::String(profile.host.clone());
    Ok(json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [
                { "type": "udp", "tag": "local-dns", "server": "1.1.1.1" },
                { "type": "https", "tag": "proxy-dns", "server": "1.1.1.1", "detour": "proxy" }
            ],
            "final": "proxy-dns",
            "strategy": "prefer_ipv4"
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "interface_name": interface_name,
            "address": ["172.19.0.1/30"], "mtu": mtu,
            "auto_route": true, "strict_route": true, "stack": "system"
        }],
        "outbounds": [
            {"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": socks_port},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "auto_detect_interface": true,
            "default_domain_resolver": "local-dns",
            "final": "proxy",
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"domain": [host_domain], "action": "route", "outbound": "direct"},
                {"ip_is_private": true, "action": "route", "outbound": "direct"}
            ]
        }
    }))
}

fn outbound(profile: &VlessProfile) -> Result<Value> {
    let query = profile.params();
    let mut tls =
        json!({"enabled": true, "server_name": profile.sni.as_deref().unwrap_or(&profile.host)});
    match profile.security.as_str() {
        "reality" => {
            tls["reality"] = json!({"enabled": true, "public_key": query.get("pbk").cloned().unwrap_or_default(), "short_id": query.get("sid").cloned().unwrap_or_default()});
            tls["utls"] = json!({"enabled": true, "fingerprint": query.get("fp").cloned().unwrap_or_else(|| "chrome".into())});
        }
        "tls" => {}
        other => bail!("sing-box security не поддерживается: {other}"),
    }
    let mut result = json!({
        "type": "vless", "tag": "proxy", "server": profile.host,
        "server_port": profile.port, "uuid": profile.uuid(), "flow": profile.flow.clone().unwrap_or_default(), "tls": tls
    });
    match profile.transport.as_str() {
        "tcp" => {}
        "grpc" => {
            result["transport"] = json!({"type":"grpc", "service_name": query.get("serviceName").cloned().unwrap_or_default()})
        }
        "xhttp" | "splithttp" => {
            result["transport"] = json!({
                "type": "http",
                "path": query.get("path").cloned().unwrap_or_default(),
                "host": query.get("host").cloned().unwrap_or_default()
            })
        }
        other => bail!("sing-box transport не поддерживается: {other}"),
    }
    Ok(result)
}

fn unique_runtime_dir() -> Result<PathBuf> {
    let dir = env::temp_dir().join(format!(
        "vpn-helper-singbox-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn is_success_status(status: reqwest::StatusCode) -> bool {
    status.is_success()
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

fn redact(value: &str) -> String {
    value
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .unwrap_or("unknown error")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless;
    use std::path::Path;

    #[test]
    fn builds_tun_config() {
        let p = vless::parse_for_test("vless://8c8a8681-5444-4e18-a427-54f19eea6a77@host.invalid:443?security=reality&pbk=public&fp=firefox&type=tcp&sni=host.invalid", Path::new("x")).unwrap();
        let config = build_config(&p, 1400, "vpn-helper").unwrap();
        assert_eq!(config["inbounds"][0]["type"], "tun");
        assert_eq!(config["inbounds"][0]["interface_name"], "vpn-helper");
        assert_eq!(config["inbounds"][0]["auto_route"], true);
        assert_eq!(config["inbounds"][0]["strict_route"], true);
        assert_eq!(config["outbounds"][0]["type"], "vless");
        assert_eq!(config["route"]["rules"][0]["action"], "sniff");
        assert_eq!(config["route"]["rules"][1]["action"], "hijack-dns");
        // домен прокси-сервера резолвится локально, чтобы избежать DNS-петли
        assert_eq!(config["route"]["rules"][2]["action"], "route");
        // домен прокси-сервера резолвится локально (default_domain_resolver), петли нет
        assert_eq!(config["route"]["default_domain_resolver"], "local-dns");
        assert_eq!(config["dns"]["servers"][0]["tag"], "local-dns");
        assert!(is_success_status(reqwest::StatusCode::NO_CONTENT));
        assert!(!is_success_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(parse_readiness_output("true").unwrap());
        assert!(!parse_readiness_output("false\r\n").unwrap());
        assert!(parse_readiness_output("unexpected").is_err());
    }

    #[test]
    fn builds_socks_bridge_config() {
        let p = vless::parse_for_test("vless://8c8a8681-5444-4e18-a427-54f19eea6a77@host.invalid:443?security=tls&sni=host.invalid&type=xhttp&path=/x", Path::new("x")).unwrap();
        let config = build_config_via_socks(&p, 1400, "vpn-helper", 54321).unwrap();
        assert_eq!(config["outbounds"][0]["type"], "socks");
        assert_eq!(config["outbounds"][0]["server"], "127.0.0.1");
        assert_eq!(config["outbounds"][0]["server_port"], 54321);
        // TUN и route остаются теми же, что и в прямом конфиге
        assert_eq!(config["inbounds"][0]["type"], "tun");
        assert_eq!(config["inbounds"][0]["interface_name"], "vpn-helper");
        assert_eq!(config["route"]["default_domain_resolver"], "local-dns");
        assert_eq!(config["route"]["final"], "proxy");
    }
}
