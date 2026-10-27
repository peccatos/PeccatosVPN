use crate::{singbox, vless::VlessProfile, xray, Args};
use anyhow::{bail, Result};

pub fn run(args: &Args, profile: &VlessProfile) -> Result<()> {
    if !cfg!(windows) {
        bail!("TUN доступен только в Windows-сборке; из WSL запускайте Windows vpn-helper.exe через interop");
    }
    if !is_elevated() {
        bail!("TUN требует запуска Windows Terminal от имени администратора");
    }
    match select_core(profile) {
        CoreSelection::SingBoxDirect => singbox::run(args, profile),
        CoreSelection::XraySocks => {
            // xhttp за CDN sing-box не поддерживает (CDN отвечает 421 Misdirected Request):
            // поднимаем Xray с VLESS+xhttp и направляем TUN sing-box в его SOCKS-порт.
            let xray_runtime = xray::start(profile)?;
            let result = singbox::run_via_socks(args, profile, xray_runtime.socks_port());
            // Xray живёт столько же, сколько туннель
            let _ = xray_runtime.stop();
            result
        }
        CoreSelection::NeedsXray => bail!(
            "Профиль с type=xhttp требует Xray-core (sing-box несовместим с CDN-транспортом). \
             Установите: winget install XTLS.Xray-core — или положите xray.exe в tools/xray/"
        ),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreSelection {
    SingBoxDirect,
    XraySocks,
    NeedsXray,
}

pub fn select_core(profile: &VlessProfile) -> CoreSelection {
    if profile.transport == "xhttp" || profile.transport == "splithttp" {
        if xray::discover().is_some() {
            CoreSelection::XraySocks
        } else {
            CoreSelection::NeedsXray
        }
    } else {
        CoreSelection::SingBoxDirect
    }
}

fn is_elevated() -> bool {
    if !cfg!(windows) {
        return false;
    }
    std::process::Command::new("net")
        .args(["session"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
