use std::path::PathBuf;
use tedge_config::get_config_dir;
use tedge_config::system_services::*;

// on linux, we use systemd
#[cfg(target_os = "linux")]
mod systemd_watchdog;
#[cfg(target_os = "linux")]
use systemd_watchdog as watchdog;
#[cfg(target_os = "linux")]
mod error;

// on non-linux, we do nothing for now
#[cfg(not(target_os = "linux"))]
mod dummy_watchdog;
#[cfg(not(target_os = "linux"))]
use dummy_watchdog as watchdog;

#[derive(Debug, clap::Parser)]
#[clap(
name = clap::crate_name!(),
version = clap::crate_version!(),
about = clap::crate_description!()
)]
pub struct WatchdogOpt {
    #[command(flatten)]
    pub log_args: LogConfigArgs,

    /// Start the watchdog from custom path
    ///
    /// [env: TEDGE_CONFIG_DIR, default: /etc/tedge]
    #[clap(
        long = "config-dir",
        default_value = get_config_dir().into_os_string(),
        hide_env_values = true,
        hide_default_value = true,
    )]
    pub config_dir: PathBuf,
}

pub async fn run(watchdog_opt: WatchdogOpt) -> Result<(), anyhow::Error> {
    let tedge_config_location =
        tedge_config::TEdgeConfigLocation::from_custom_root(watchdog_opt.config_dir.clone());

    log_init(
        "tedge-watchdog",
        &watchdog_opt.log_args,
        &tedge_config_location.tedge_config_root_path,
    )?;

    watchdog::start_watchdog(watchdog_opt.config_dir).await
}
