mod discovery;
pub mod server_scan;
mod singbox;
mod tui;
mod tun;
mod vless;
mod xray;
mod xray_config;

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub(crate) struct Args {
    /// Запустить интерактивный TUI для проверки профилей
    #[arg(long, conflicts_with = "tunnel")]
    pub(crate) tui: bool,
    /// Запустить выбранный профиль как системный Windows TUN VPN
    #[arg(long, conflicts_with = "tui")]
    pub(crate) tunnel: bool,
    /// Каталог VLESS-профилей
    #[arg(long, default_value = "servers")]
    pub(crate) servers_dir: PathBuf,
    /// Файл VLESS-профиля для --tunnel
    #[arg(long)]
    pub(crate) profile: Option<PathBuf>,
    /// Явный путь к sing-box.exe (также используется SING_BOX_PATH/PATH)
    #[arg(long)]
    pub(crate) singbox_path: Option<PathBuf>,
    /// Сохранить конфигурацию для диагностики вместо удаления после остановки
    #[arg(long)]
    pub(crate) tunnel_config: Option<PathBuf>,
    /// MTU виртуального интерфейса
    #[arg(long, default_value_t = 1500, value_parser = clap::value_parser!(u16).range(576..=9000))]
    pub(crate) mtu: u16,
    /// Имя TUN-интерфейса
    #[arg(long, default_value = "vpn-helper")]
    pub(crate) tun_name: String,
    /// Подробные логи внешнего core
    #[arg(long, short = 'v')]
    pub(crate) verbose: bool,
}

fn load_profile(args: &Args) -> Result<vless::VlessProfile> {
    let path = args
        .profile
        .as_deref()
        .context("Для --tunnel требуется --profile <путь-к-vless-файлу>")?;
    let profile = vless::load_path(path)?;
    match &profile.state {
        vless::ProfileState::Valid => Ok(profile),
        vless::ProfileState::Invalid(reason) => bail!("Профиль невалиден: {reason}"),
        vless::ProfileState::Unsupported(reason) => bail!("Профиль не поддерживается: {reason}"),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.tunnel {
        let profile = load_profile(&args)?;
        return tun::run(&args, &profile);
    }
    if args.tui {
        return tui::run(&args.servers_dir, || Ok(()));
    }
    bail!("Укажите --tui или --tunnel --profile <файл>; используйте --help")
}
