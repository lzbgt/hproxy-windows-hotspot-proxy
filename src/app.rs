use std::{io::Write, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::{
    config::{AppConfig, DnsMode, HotspotConfig, ProxyConfig, ProxyPreflightConfig},
    dns::DnsProxy,
    doctor::{run_build_tool_probe, run_host_probe, run_windivert_probe},
    flow::FlowTable,
    hotspot::{HotspotController, InterfaceDiscovery, WindowsHotspot},
    proxy::{
        Destination, GatewayTcpProxy, TcpConnector, TransparentTcpProxy, connector_from_config,
    },
    redirector::{
        PacketRedirector, RedirectorConfig, RedirectorPreflightConfig, WinDivertRedirector,
    },
};

pub struct HProxyApp {
    hotspot: Arc<dyn HotspotController>,
    interfaces: Arc<dyn InterfaceDiscovery>,
    redirector: Arc<dyn PacketRedirector>,
}

impl Default for HProxyApp {
    fn default() -> Self {
        let hotspot = Arc::new(WindowsHotspot);
        Self {
            hotspot: hotspot.clone(),
            interfaces: hotspot,
            redirector: Arc::new(WinDivertRedirector::default()),
        }
    }
}

impl HProxyApp {
    pub async fn up(&self, config: AppConfig) -> Result<()> {
        config.validate()?;
        info!("starting hproxy for SSID '{}'", config.hotspot.ssid);

        let connector = connector_from_config(&config.outbound_proxy)
            .context("create outbound proxy connector")?;
        probe_outbound_if_enabled(connector.clone(), config.proxy_preflight)
            .await
            .context("preflight outbound proxy")?;
        let flow_table = FlowTable::new(65_536);
        let mut listener_tasks = Vec::new();
        let mut hotspot_started = false;
        let mut redirector_started = false;

        let startup_result: Result<()> = async {
            let tcp_proxy = TransparentTcpProxy::bind(
                config.ports.transparent_tcp,
                flow_table.clone(),
                connector.clone(),
            )
            .await
            .context("bind transparent TCP proxy")?;
            let gateway_http_proxy = if config.dns.mode == DnsMode::Gateway {
                Some(
                    GatewayTcpProxy::bind(80, connector.clone())
                        .await
                        .context("bind gateway HTTP proxy")?,
                )
            } else {
                None
            };
            let gateway_https_proxy = if config.dns.mode == DnsMode::Gateway {
                Some(
                    GatewayTcpProxy::bind(443, connector.clone())
                        .await
                        .context("bind gateway HTTPS proxy")?,
                )
            } else {
                None
            };

            self.redirector
                .preflight(RedirectorPreflightConfig {
                    dns_proxy_port: config.ports.dns_proxy,
                })
                .await
                .context("preflight WinDivert redirector")?;

            self.hotspot
                .start(&config.hotspot)
                .await
                .context("start Windows hotspot")?;
            hotspot_started = true;

            let hotspot = self
                .interfaces
                .discover_hotspot()
                .await
                .context("discover hotspot interface")?;
            let hotspot_summary = hotspot.clone();
            let gateway_ip = match hotspot.gateway_ip {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(_) => None,
            };
            if config.dns.mode == DnsMode::Gateway && gateway_ip.is_none() {
                bail!("DNS gateway mode requires an IPv4 hotspot gateway");
            }

            let dns_proxy = DnsProxy::bind(config.ports.dns_proxy, config.dns.clone(), gateway_ip)
                .await
                .context("bind DNS proxy")?;

            listener_tasks.push(tokio::spawn(tcp_proxy.run()));
            listener_tasks.push(tokio::spawn(dns_proxy.run()));
            if let Some(gateway_http_proxy) = gateway_http_proxy {
                listener_tasks.push(tokio::spawn(gateway_http_proxy.run()));
            }
            if let Some(gateway_https_proxy) = gateway_https_proxy {
                listener_tasks.push(tokio::spawn(gateway_https_proxy.run()));
            }

            self.redirector
                .start(
                    RedirectorConfig {
                        hotspot,
                        ports: config.ports,
                        policy: config.policy,
                    },
                    flow_table,
                )
                .await
                .context("start WinDivert redirector")?;
            redirector_started = true;
            println!("hotspot SSID: {}", config.hotspot.ssid);
            println!("hotspot gateway: {}", hotspot_summary.gateway_ip);
            println!(
                "hotspot subnet: {}/{}",
                hotspot_summary.subnet.address, hotspot_summary.subnet.prefix_len
            );
            println!(
                "hotspot interface index: {}",
                hotspot_summary.interface_index
            );
            println!(
                "local transparent TCP port: {}",
                config.ports.transparent_tcp
            );
            println!("local DNS proxy port: {}", config.ports.dns_proxy);
            if config.dns.mode == DnsMode::Gateway {
                println!(
                    "DNS gateway mode: A records answer {}",
                    hotspot_summary.gateway_ip
                );
                println!("gateway HTTP proxy port: 80");
                println!("gateway HTTPS proxy port: 443");
            }
            println!("hproxy is running; press Ctrl+C to stop hotspot and datapath");
            std::io::stdout().flush().ok();
            Ok(())
        }
        .await;

        if let Err(err) = startup_result {
            self.rollback_startup(&mut listener_tasks, redirector_started, hotspot_started)
                .await;
            return Err(err);
        }

        tokio::signal::ctrl_c().await?;
        abort_listener_tasks(&mut listener_tasks);
        self.down().await
    }

    pub async fn down(&self) -> Result<()> {
        info!("stopping hproxy datapath");
        self.redirector.stop().await?;
        self.hotspot.stop().await?;
        Ok(())
    }

    pub async fn status(&self) -> Result<()> {
        let status = self.hotspot.status().await?;
        println!("hotspot: {status:?}");
        if let Some(access_point) = self.hotspot.access_point().await? {
            println!("hotspot SSID: {}", access_point.ssid);
        }
        println!("datapath: unknown from status; inspect the running hproxy up console");
        Ok(())
    }

    pub async fn recover(&self) -> Result<()> {
        info!("recovering STA-only networking");
        self.redirector.stop().await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.hotspot.stop().await?;
        Ok(())
    }

    async fn rollback_startup(
        &self,
        listener_tasks: &mut Vec<JoinHandle<Result<()>>>,
        redirector_started: bool,
        hotspot_started: bool,
    ) {
        info!("rolling back hproxy startup");
        abort_listener_tasks(listener_tasks);

        if redirector_started && let Err(err) = self.redirector.stop().await {
            warn!("redirector rollback failed: {err:#}");
        }

        if hotspot_started && let Err(err) = self.hotspot.stop().await {
            warn!("hotspot rollback failed: {err:#}");
        }
    }

    pub async fn doctor(
        &self,
        outbound: Option<ProxyConfig>,
        proxy_probe_target: Option<SocketAddr>,
        proxy_probe_timeout_ms: u64,
        windivert_open_probe: bool,
        windivert_probe_dns_port: u16,
        hotspot_live_probe: Option<HotspotConfig>,
    ) -> Result<()> {
        println!("host OS: {}", std::env::consts::OS);
        println!("windows hotspot control: {}", cfg!(windows));
        println!("WinDivert datapath: {}", cfg!(windows));

        let windivert = run_windivert_probe();
        println!(
            "WinDivert files present: {}",
            format_bool(windivert.files_present())
        );
        println!(
            "WinDivert usable on this host: {}",
            format_bool(windivert.usable_on_this_host())
        );
        println!(
            "WinDivert.dll: {}",
            windivert
                .dll_path
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "missing".to_string())
        );
        println!(
            "WinDivert64.sys: {}",
            windivert
                .driver_path
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "missing".to_string())
        );
        if windivert_open_probe {
            if windivert_probe_dns_port == 0 {
                bail!("WinDivert DNS probe port must be greater than 0");
            }
            self.redirector
                .preflight(RedirectorPreflightConfig {
                    dns_proxy_port: windivert_probe_dns_port,
                })
                .await
                .context("open WinDivert preflight handles")?;
            println!("WinDivert open probe: ok");
        } else {
            println!("WinDivert open probe: skipped; pass --windivert-open-probe to test it");
        }

        let probe = run_host_probe()?;
        if probe.probe_available {
            println!("host probe: available through powershell.exe");
            println!(
                "wifi driver: {}",
                probe.wifi_driver.as_deref().unwrap_or("unknown")
            );
            println!(
                "legacy hostednetwork supported: {}",
                format_optional_bool(probe.hosted_network_supported)
            );
            println!(
                "station mode supported: {}",
                format_optional_bool(probe.station_supported)
            );
            println!(
                "classic soft ap supported: {}",
                format_optional_bool(probe.soft_ap_supported)
            );
            println!(
                "wi-fi direct go supported: {}",
                format_optional_bool(probe.wifi_direct_go_supported)
            );
            println!(
                "p2p max mobile ap clients: {}",
                probe
                    .p2p_max_mobile_ap_clients
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            println!(
                "wi-fi direct virtual adapters: {}",
                probe.wifi_direct_virtual_adapters
            );
            println!(
                "mobile hotspot service: {}",
                probe
                    .mobile_hotspot_service_status
                    .as_deref()
                    .unwrap_or("unknown")
            );
            println!(
                "mobile hotspot path likely supported: {}",
                format_optional_bool(probe.mobile_hotspot_likely_supported())
            );
        } else {
            println!("host probe: unavailable; powershell.exe was not found");
        }

        if let Some(hotspot_config) = hotspot_live_probe {
            self.run_hotspot_live_probe(&hotspot_config).await?;
        } else {
            println!("hotspot live probe: skipped; pass --hotspot-live-probe to start and stop it");
        }

        let build_tools = run_build_tool_probe()?;
        if build_tools.probe_available {
            println!(
                "windows native toolchain ready: {}",
                format_optional_bool(build_tools.native_windows_toolchain_ready())
            );
            println!(
                "wfp driver sdk ready: {}",
                format_optional_bool(build_tools.wfp_driver_sdk_ready())
            );
            println!(
                "windows rustc: {}",
                build_tools.rustc_version.as_deref().unwrap_or("missing")
            );
            println!(
                "windows cargo: {}",
                build_tools.cargo_version.as_deref().unwrap_or("missing")
            );
            println!(
                "windows dotnet sdk: {}",
                build_tools
                    .dotnet_sdk_version
                    .as_deref()
                    .unwrap_or("missing")
            );
            println!(
                "visual studio: {}",
                build_tools
                    .visual_studio_path
                    .as_deref()
                    .unwrap_or("missing")
            );
            println!(
                "msvc toolset: {}",
                build_tools.msvc_version.as_deref().unwrap_or("missing")
            );
            println!(
                "cl.exe: {}",
                build_tools.cl_path.as_deref().unwrap_or("missing")
            );
            println!(
                "msbuild: {}",
                build_tools.msbuild_path.as_deref().unwrap_or("missing")
            );
            println!(
                "windows sdk: {}",
                build_tools
                    .windows_sdk_version
                    .as_deref()
                    .unwrap_or("missing")
            );
            println!(
                "signtool: {}",
                build_tools.signtool_path.as_deref().unwrap_or("missing")
            );
            println!(
                "wfp header: {}",
                build_tools.wfp_header_path.as_deref().unwrap_or("missing")
            );
        } else {
            println!("windows build tool probe: unavailable; powershell.exe was not found");
        }

        if let Some(proxy) = outbound {
            proxy.validate()?;
            let connector = connector_from_config(&proxy)?;
            println!("outbound proxy config: ok");

            if let Some(target) = proxy_probe_target {
                if proxy_probe_timeout_ms == 0 {
                    bail!("proxy probe timeout must be greater than 0");
                }

                probe_outbound_connector(connector, target, proxy_probe_timeout_ms).await?;
                println!("outbound proxy probe to {target}: ok");
            } else {
                println!("outbound proxy probe: skipped; pass --proxy-probe-target to test it");
            }
        }

        Ok(())
    }

    async fn run_hotspot_live_probe(&self, hotspot_config: &HotspotConfig) -> Result<()> {
        println!("hotspot live probe: starting SSID {}", hotspot_config.ssid);
        self.hotspot
            .start(hotspot_config)
            .await
            .context("hotspot live probe start")?;

        let probe_result: Result<()> = async {
            let status = self.hotspot.status().await?;
            println!("hotspot live probe status: {status:?}");
            if status != crate::hotspot::HotspotStatus::Running {
                bail!("hotspot live probe expected Running but Windows reported {status:?}");
            }

            match self.hotspot.access_point().await? {
                Some(access_point) => {
                    println!("hotspot live probe SSID: {}", access_point.ssid);
                }
                None => {
                    println!("hotspot live probe SSID: unknown");
                }
            }

            let runtime = self
                .interfaces
                .discover_hotspot()
                .await
                .context("hotspot live probe discover private Wi-Fi Direct interface")?;
            println!(
                "hotspot live probe private interface index: {}",
                runtime.interface_index
            );
            println!("hotspot live probe gateway: {}", runtime.gateway_ip);
            println!(
                "hotspot live probe subnet: {}/{}",
                runtime.subnet.address, runtime.subnet.prefix_len
            );
            Ok(())
        }
        .await;

        if let Err(err) = &probe_result {
            println!("hotspot live probe: failed before cleanup: {err:#}");
        }

        let stop_result = self
            .hotspot
            .stop()
            .await
            .context("hotspot live probe cleanup stop");
        match stop_result {
            Ok(()) => println!("hotspot live probe cleanup: stopped"),
            Err(err) => {
                if probe_result.is_err() {
                    return Err(err).context("hotspot live probe cleanup after earlier failure");
                }
                return Err(err);
            }
        }

        probe_result?;
        println!("hotspot live probe: ok");
        Ok(())
    }
}

async fn probe_outbound_if_enabled(
    connector: Arc<dyn TcpConnector>,
    config: ProxyPreflightConfig,
) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }
    probe_outbound_connector(connector, config.target, config.timeout_ms).await
}

async fn probe_outbound_connector(
    connector: Arc<dyn TcpConnector>,
    target: SocketAddr,
    timeout_ms: u64,
) -> Result<()> {
    if timeout_ms == 0 {
        bail!("proxy probe timeout must be greater than 0");
    }

    let destination = Destination::from_ip(target.ip(), target.port());
    timeout(
        Duration::from_millis(timeout_ms),
        connector.connect(destination),
    )
    .await
    .with_context(|| format!("proxy probe to {target} timed out after {timeout_ms} ms"))?
    .with_context(|| format!("proxy probe to {target} failed"))?;
    Ok(())
}

fn abort_listener_tasks(listener_tasks: &mut Vec<JoinHandle<Result<()>>>) {
    for task in listener_tasks.drain(..) {
        task.abort();
    }
}

fn format_optional_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn format_bool(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{SocketAddr, TcpListener, UdpSocket},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use anyhow::{Result, bail};
    use async_trait::async_trait;

    use super::*;
    use crate::{
        config::{
            DnsConfig, HostEndpoint, HotspotBand, HotspotConfig, LocalPorts, ProxyConfig,
            ProxyKind, ProxyPreflightConfig, TransparentPolicy,
        },
        hotspot::{HotspotRuntime, HotspotStatus, Ipv4Cidr},
        redirector::RedirectorPreflightConfig,
    };

    #[derive(Default)]
    struct MockHotspot {
        starts: AtomicUsize,
        stops: AtomicUsize,
    }

    #[async_trait]
    impl HotspotController for MockHotspot {
        async fn start(&self, _config: &HotspotConfig) -> Result<()> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn stop(&self) -> Result<()> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn status(&self) -> Result<HotspotStatus> {
            Ok(HotspotStatus::Stopped)
        }

        async fn access_point(&self) -> Result<Option<crate::hotspot::HotspotAccessPoint>> {
            Ok(Some(crate::hotspot::HotspotAccessPoint {
                ssid: "VirtualProxyAP".to_string(),
            }))
        }
    }

    #[async_trait]
    impl InterfaceDiscovery for MockHotspot {
        async fn discover_hotspot(&self) -> Result<HotspotRuntime> {
            Ok(HotspotRuntime {
                interface_index: 23,
                gateway_ip: "192.168.137.1".parse().unwrap(),
                subnet: Ipv4Cidr {
                    address: "192.168.137.0".parse().unwrap(),
                    prefix_len: 24,
                },
            })
        }
    }

    #[derive(Default)]
    struct FailingPreflightRedirector {
        preflights: AtomicUsize,
        starts: AtomicUsize,
        stops: AtomicUsize,
    }

    #[async_trait]
    impl PacketRedirector for FailingPreflightRedirector {
        async fn preflight(&self, _config: RedirectorPreflightConfig) -> Result<()> {
            self.preflights.fetch_add(1, Ordering::SeqCst);
            bail!("preflight failed")
        }

        async fn start(&self, _config: RedirectorConfig, _flow_table: FlowTable) -> Result<()> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn stop(&self) -> Result<()> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn preflight_failure_happens_before_hotspot_mutation() {
        let hotspot = Arc::new(MockHotspot::default());
        let redirector = Arc::new(FailingPreflightRedirector::default());
        let app = HProxyApp {
            hotspot: hotspot.clone(),
            interfaces: hotspot.clone(),
            redirector: redirector.clone(),
        };

        let err = app.up(test_config()).await.unwrap_err();

        assert!(err.to_string().contains("preflight WinDivert redirector"));
        assert_eq!(redirector.preflights.load(Ordering::SeqCst), 1);
        assert_eq!(redirector.starts.load(Ordering::SeqCst), 0);
        assert_eq!(redirector.stops.load(Ordering::SeqCst), 0);
        assert_eq!(hotspot.starts.load(Ordering::SeqCst), 0);
        assert_eq!(hotspot.stops.load(Ordering::SeqCst), 0);
    }

    fn test_config() -> AppConfig {
        AppConfig {
            hotspot: HotspotConfig {
                ssid: "VirtualProxyAP".to_string(),
                password: "11102017".to_string(),
                band: HotspotBand::Auto,
            },
            outbound_proxy: ProxyConfig::direct(),
            proxy_preflight: ProxyPreflightConfig {
                enabled: false,
                target: "1.1.1.1:443".parse().unwrap(),
                timeout_ms: 5_000,
            },
            dns: DnsConfig::default(),
            policy: TransparentPolicy::default(),
            ports: LocalPorts {
                transparent_tcp: free_tcp_port(),
                dns_proxy: free_udp_port(),
            },
        }
    }

    fn free_tcp_port() -> u16 {
        TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn free_udp_port() -> u16 {
        UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[tokio::test]
    async fn proxy_probe_failure_happens_before_hotspot_or_windivert_mutation() {
        let hotspot = Arc::new(MockHotspot::default());
        let redirector = Arc::new(FailingPreflightRedirector::default());
        let app = HProxyApp {
            hotspot: hotspot.clone(),
            interfaces: hotspot.clone(),
            redirector: redirector.clone(),
        };
        let mut config = test_config();
        let proxy_port = free_tcp_port();
        config.outbound_proxy = ProxyConfig {
            kind: ProxyKind::Socks5,
            endpoint: Some(HostEndpoint {
                host: "127.0.0.1".to_string(),
                port: proxy_port,
            }),
            username: None,
            password: None,
            tls_skip_verify: false,
        };
        config.proxy_preflight = ProxyPreflightConfig {
            enabled: true,
            target: "1.1.1.1:443".parse().unwrap(),
            timeout_ms: 100,
        };

        let err = app.up(config).await.unwrap_err();

        assert!(err.to_string().contains("preflight outbound proxy"));
        assert_eq!(redirector.preflights.load(Ordering::SeqCst), 0);
        assert_eq!(redirector.starts.load(Ordering::SeqCst), 0);
        assert_eq!(redirector.stops.load(Ordering::SeqCst), 0);
        assert_eq!(hotspot.starts.load(Ordering::SeqCst), 0);
        assert_eq!(hotspot.stops.load(Ordering::SeqCst), 0);
    }
}
