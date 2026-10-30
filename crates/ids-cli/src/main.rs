use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ids_engine::PortScanConfig;
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "rustguard",
    version,
    about = "Defensive intrusion detection system"
)]
struct Cli {
    /// TOML configuration file to load.
    #[arg(short, long, global = true, default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the detector (capture and detection are added in later phases).
    Run,
    /// Run the local HTTP API used by the dashboard.
    ServeApi {
        /// Address to listen on. The API is localhost-only by default.
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        /// Network interface to capture passively for TCP scans.
        #[arg(long)]
        interface: Option<String>,
        /// Detection window size in seconds.
        #[arg(long, default_value_t = 60)]
        window_seconds: u64,
        /// Distinct destination ports from one source that trigger a vertical scan.
        #[arg(long, default_value_t = 12)]
        unique_ports: usize,
        /// Distinct destination hosts from one source that trigger a horizontal sweep.
        #[arg(long, default_value_t = 12)]
        unique_hosts: usize,
        /// Minimum time between alerts for one source address.
        #[arg(long, default_value_t = 300)]
        cooldown_seconds: u64,
    },
    /// List interfaces available to the live packet-capture backend.
    ListInterfaces,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Config {
    network: NetworkConfig,
    sources: SourcesConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct NetworkConfig {
    home_net: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SourcesConfig {
    interfaces: Vec<String>,
    logs: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing();

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => {
            let config = load_config(&cli.config)?;
            tracing::info!(config = %cli.config.display(), "RustGuard configuration loaded");
            tracing::info!(
                home_networks = config.network.home_net.len(),
                interfaces = config.sources.interfaces.len(),
                log_sources = config.sources.logs.len(),
                "Phase 0 setup is ready; detection sources will be connected in later phases"
            );
        }
        Command::ServeApi {
            bind,
            interface,
            window_seconds,
            unique_ports,
            unique_hosts,
            cooldown_seconds,
        } => {
            let detection_config = PortScanConfig {
                window: Duration::from_secs(window_seconds),
                unique_ports,
                unique_hosts,
                cooldown: Duration::from_secs(cooldown_seconds),
                ..PortScanConfig::default()
            };
            ids_api::serve(bind, interface, detection_config).await?;
        }
        Command::ListInterfaces => {
            for interface in ids_capture::list_interfaces().map_err(anyhow::Error::msg)? {
                println!(
                    "{}\t{}",
                    interface.name,
                    interface.description.unwrap_or_default()
                );
            }
        }
    }
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn load_config(path: &PathBuf) -> Result<Config> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read configuration file {}", path.display()))?;
    toml::from_str(&raw)
        .with_context(|| format!("failed to parse TOML configuration {}", path.display()))
}
