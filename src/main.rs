mod app;
mod config;
mod dns;
mod doctor;
mod flow;
mod hostcmd;
mod hotspot;
mod proxy;
mod redirector;

use anyhow::{Context, Result};
use app::HProxyApp;
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use config::{
    AppConfig, DnsConfig, DnsMode, HotspotBand, HotspotConfig, LocalPorts, ProxyConfig,
    ProxyPreflightConfig, TransparentPolicy,
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "hproxy")]
#[command(about = "Transparent proxy gateway for Windows Mobile Hotspot clients")]
struct Cli {
    /// Write diagnostics to this file. By default hproxy emits no debug log.
    #[arg(long, global = true, conflicts_with = "log_stderr")]
    log_file: Option<PathBuf>,
    /// Write diagnostics to stderr for foreground debugging.
    #[arg(long, global = true)]
    log_stderr: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start hotspot transparent proxy mode.
    Up(UpArgs),
    /// Stop proxy datapath and hotspot state owned by hproxy.
    Down,
    /// Show current app status.
    Status,
    /// Attempt rollback to normal STA-only networking.
    Recover,
    /// Validate host capabilities and configuration without starting.
    Doctor(DoctorArgs),
}

#[derive(Debug, Parser)]
struct UpArgs {
    #[arg(long, default_value = "VirtualProxyAP")]
    ssid: String,
    #[arg(long, default_value = "11102017")]
    password: String,
    #[arg(long, default_value = "two-ghz")]
    band: BandArg,
    #[arg(long, default_value = "direct")]
    outbound: ProxyConfig,
    #[arg(long)]
    proxy_tls_insecure: bool,
    #[arg(long)]
    skip_proxy_probe: bool,
    #[arg(long, default_value = "1.1.1.1:443")]
    proxy_probe_target: SocketAddr,
    #[arg(long, default_value_t = 5_000)]
    proxy_probe_timeout_ms: u64,
    #[arg(long, default_value_t = 16_000)]
    transparent_tcp_port: u16,
    #[arg(long, default_value_t = 1053)]
    dns_proxy_port: u16,
    #[arg(long, default_value = "1.1.1.1:53")]
    dns_upstream: SocketAddr,
    #[arg(long, default_value_t = 5_000)]
    dns_timeout_ms: u64,
    #[arg(long, default_value = "forward")]
    dns_mode: DnsModeArg,
}

#[derive(Debug, Parser)]
struct DoctorArgs {
    #[arg(long)]
    outbound: Option<ProxyConfig>,
    #[arg(long)]
    proxy_tls_insecure: bool,
    #[arg(long)]
    proxy_probe_target: Option<SocketAddr>,
    #[arg(long, default_value_t = 5_000)]
    proxy_probe_timeout_ms: u64,
    #[arg(long)]
    windivert_open_probe: bool,
    #[arg(long, default_value_t = 1053)]
    windivert_probe_dns_port: u16,
    #[arg(long)]
    hotspot_live_probe: bool,
    #[arg(long, default_value = "VirtualProxyAP")]
    hotspot_ssid: String,
    #[arg(long, default_value = "11102017")]
    hotspot_password: String,
    #[arg(long, default_value = "two-ghz")]
    hotspot_band: BandArg,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BandArg {
    Auto,
    TwoGhz,
    FiveGhz,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DnsModeArg {
    Forward,
    Gateway,
}

impl From<DnsModeArg> for DnsMode {
    fn from(value: DnsModeArg) -> Self {
        match value {
            DnsModeArg::Forward => DnsMode::Forward,
            DnsModeArg::Gateway => DnsMode::Gateway,
        }
    }
}

impl From<BandArg> for HotspotBand {
    fn from(value: BandArg) -> Self {
        match value {
            BandArg::Auto => HotspotBand::Auto,
            BandArg::TwoGhz => HotspotBand::TwoGhz,
            BandArg::FiveGhz => HotspotBand::FiveGhz,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(&cli)?;
    let app = HProxyApp::default();

    match cli.command {
        Command::Up(args) => {
            let outbound_proxy = apply_tls_flag(args.outbound, args.proxy_tls_insecure);
            let proxy_preflight = ProxyPreflightConfig {
                enabled: !args.skip_proxy_probe && !outbound_proxy.is_direct(),
                target: args.proxy_probe_target,
                timeout_ms: args.proxy_probe_timeout_ms,
            };
            let config = AppConfig {
                hotspot: HotspotConfig {
                    ssid: args.ssid,
                    password: args.password,
                    band: args.band.into(),
                },
                outbound_proxy,
                proxy_preflight,
                dns: DnsConfig {
                    upstream: args.dns_upstream,
                    timeout_ms: args.dns_timeout_ms,
                    mode: args.dns_mode.into(),
                },
                policy: TransparentPolicy::default(),
                ports: LocalPorts {
                    transparent_tcp: args.transparent_tcp_port,
                    dns_proxy: args.dns_proxy_port,
                },
            };
            app.up(config).await?;
        }
        Command::Down => app.down().await?,
        Command::Status => app.status().await?,
        Command::Recover => app.recover().await?,
        Command::Doctor(args) => {
            app.doctor(
                args.outbound
                    .map(|outbound| apply_tls_flag(outbound, args.proxy_tls_insecure)),
                args.proxy_probe_target,
                args.proxy_probe_timeout_ms,
                args.windivert_open_probe,
                args.windivert_probe_dns_port,
                args.hotspot_live_probe.then_some(HotspotConfig {
                    ssid: args.hotspot_ssid,
                    password: args.hotspot_password,
                    band: args.hotspot_band.into(),
                }),
            )
            .await?
        }
    }

    Ok(())
}

fn apply_tls_flag(outbound: ProxyConfig, proxy_tls_insecure: bool) -> ProxyConfig {
    if proxy_tls_insecure {
        outbound.with_tls_skip_verify(true)
    } else {
        outbound
    }
}

fn init_logging(cli: &Cli) -> Result<()> {
    if let Some(path) = &cli.log_file {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open log file {}", path.display()))?;
        let writer = SharedLogWriter(Arc::new(Mutex::new(file)));
        tracing_subscriber::fmt()
            .with_env_filter(default_env_filter())
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .init();
    } else if cli.log_stderr {
        tracing_subscriber::fmt()
            .with_env_filter(default_env_filter())
            .init();
    }

    Ok(())
}

fn default_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

#[derive(Clone)]
struct SharedLogWriter(Arc<Mutex<std::fs::File>>);

impl Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log file lock poisoned").write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().expect("log file lock poisoned").flush()
    }
}
