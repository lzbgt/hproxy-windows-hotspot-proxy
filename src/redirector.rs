#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tracing::{debug, info, warn};

use crate::{
    config::{DnsPolicy, LocalPorts, TcpPolicy, TransparentPolicy, UdpPolicy},
    flow::{FlowKey, FlowTable, FlowValue, TransportProtocol},
    hotspot::{HotspotRuntime, Ipv4Cidr},
};

#[derive(Debug, Clone)]
pub struct RedirectorConfig {
    pub hotspot: HotspotRuntime,
    pub ports: LocalPorts,
    pub policy: TransparentPolicy,
}

#[derive(Debug, Clone, Copy)]
pub struct RedirectorPreflightConfig {
    pub dns_proxy_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMeta {
    pub protocol: TransportProtocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectDecision {
    Bypass(BypassReason),
    RedirectTcp { local_ip: IpAddr, local_port: u16 },
    RedirectDns { local_ip: IpAddr, local_port: u16 },
    Drop(DropReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassReason {
    NotHotspotClient,
    GatewayTraffic,
    UpstreamProxy,
    PrivateLan,
    MulticastOrBroadcast,
    TcpPolicyDirect,
    DnsPolicyDirect,
    UdpNtpDirect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    TcpPolicyDrop,
    DnsPolicyDrop,
    QuicBlocked,
    UdpPolicyDrop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketAction {
    Send,
    Drop,
}

static FORWARD_DIAG_LINES: AtomicUsize = AtomicUsize::new(0);
static NETWORK_DIAG_LINES: AtomicUsize = AtomicUsize::new(0);
const DATAPATH_DIAG_LIMIT: usize = 4096;

pub fn classify_packet(config: &RedirectorConfig, packet: &PacketMeta) -> RedirectDecision {
    if !is_hotspot_client(config.hotspot.subnet, packet.src_ip) {
        return RedirectDecision::Bypass(BypassReason::NotHotspotClient);
    }

    if packet.dst_port == 53 {
        return classify_dns(config);
    }

    if packet.dst_ip == config.hotspot.gateway_ip {
        return RedirectDecision::Bypass(BypassReason::GatewayTraffic);
    }

    if is_multicast_or_broadcast(packet.dst_ip) {
        return RedirectDecision::Bypass(BypassReason::MulticastOrBroadcast);
    }

    if config.policy.upstream_proxy_ip == Some(packet.dst_ip) {
        return RedirectDecision::Bypass(BypassReason::UpstreamProxy);
    }

    if config.policy.bypass_private_lan && is_private_lan(packet.dst_ip) {
        return RedirectDecision::Bypass(BypassReason::PrivateLan);
    }

    match packet.protocol {
        TransportProtocol::Tcp => classify_tcp(config),
        TransportProtocol::Udp => classify_udp(config, packet),
    }
}

fn classify_tcp(config: &RedirectorConfig) -> RedirectDecision {
    match config.policy.tcp {
        TcpPolicy::Proxy => RedirectDecision::RedirectTcp {
            local_ip: config.hotspot.gateway_ip,
            local_port: config.ports.transparent_tcp,
        },
        TcpPolicy::Direct => RedirectDecision::Bypass(BypassReason::TcpPolicyDirect),
        TcpPolicy::Drop => RedirectDecision::Drop(DropReason::TcpPolicyDrop),
    }
}

fn classify_dns(config: &RedirectorConfig) -> RedirectDecision {
    match config.policy.dns {
        DnsPolicy::Proxy => RedirectDecision::RedirectDns {
            local_ip: config.hotspot.gateway_ip,
            local_port: config.ports.dns_proxy,
        },
        DnsPolicy::Direct => RedirectDecision::Bypass(BypassReason::DnsPolicyDirect),
        DnsPolicy::Drop => RedirectDecision::Drop(DropReason::DnsPolicyDrop),
    }
}

fn classify_udp(config: &RedirectorConfig, packet: &PacketMeta) -> RedirectDecision {
    if config.policy.block_quic_udp_443 && packet.dst_port == 443 {
        return RedirectDecision::Drop(DropReason::QuicBlocked);
    }

    match config.policy.udp {
        UdpPolicy::DnsNtpDirectElseDrop if packet.dst_port == 123 => {
            RedirectDecision::Bypass(BypassReason::UdpNtpDirect)
        }
        UdpPolicy::DnsNtpDirectElseDrop | UdpPolicy::Drop => {
            RedirectDecision::Drop(DropReason::UdpPolicyDrop)
        }
    }
}

fn is_hotspot_client(subnet: Ipv4Cidr, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => subnet.contains(ip),
        IpAddr::V6(_) => false,
    }
}

fn is_multicast_or_broadcast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_multicast() || ip == Ipv4Addr::BROADCAST,
        IpAddr::V6(ip) => ip.is_multicast(),
    }
}

fn is_private_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip == Ipv4Addr::BROADCAST
                || ip.octets()[0] == 0
        }
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unicast_link_local(),
    }
}

#[async_trait]
pub trait PacketRedirector: Send + Sync {
    async fn preflight(&self, config: RedirectorPreflightConfig) -> Result<()>;
    async fn start(&self, config: RedirectorConfig, flow_table: FlowTable) -> Result<()>;
    async fn stop(&self) -> Result<()>;
}

#[derive(Default)]
pub struct WinDivertRedirector {
    state: Mutex<RedirectorState>,
}

#[derive(Default)]
struct RedirectorState {
    #[cfg(windows)]
    running: Option<windows_windivert::RunningRedirector>,
}

#[async_trait]
impl PacketRedirector for WinDivertRedirector {
    async fn preflight(&self, config: RedirectorPreflightConfig) -> Result<()> {
        #[cfg(windows)]
        {
            windows_windivert::preflight(config).context("preflight WinDivert packet handles")
        }

        #[cfg(not(windows))]
        {
            let _ = config;
            bail!("WinDivert redirector must run as a Windows binary, not inside WSL/Linux")
        }
    }

    async fn start(&self, config: RedirectorConfig, flow_table: FlowTable) -> Result<()> {
        #[cfg(windows)]
        {
            let running = windows_windivert::start(config, flow_table)
                .context("start WinDivert packet rewrite loop")?;
            let mut state = self.state.lock().expect("redirector state lock poisoned");
            if state.running.is_some() {
                running.stop();
                bail!("WinDivert redirector is already running");
            }
            state.running = Some(running);
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = (config, flow_table);
            bail!("WinDivert redirector must run as a Windows binary, not inside WSL/Linux")
        }
    }

    async fn stop(&self) -> Result<()> {
        #[cfg(windows)]
        {
            if let Some(running) = self
                .state
                .lock()
                .expect("redirector state lock poisoned")
                .running
                .take()
            {
                running.stop();
            }
        }
        Ok(())
    }
}

fn process_forward_packet(
    config: &RedirectorConfig,
    flow_table: &FlowTable,
    packet: &mut [u8],
) -> PacketAction {
    let Some(meta) = parse_ipv4_packet_meta(packet) else {
        return PacketAction::Send;
    };

    let decision = classify_packet(config, &meta);
    log_forward_decision(&meta, &decision);

    match decision {
        RedirectDecision::Bypass(reason) => {
            debug!("bypass packet: {reason:?}");
            PacketAction::Send
        }
        RedirectDecision::Drop(reason) => {
            debug!("drop packet: {reason:?}");
            PacketAction::Drop
        }
        RedirectDecision::RedirectTcp {
            local_ip,
            local_port,
        }
        | RedirectDecision::RedirectDns {
            local_ip,
            local_port,
        } => {
            flow_table.insert(
                FlowKey {
                    protocol: meta.protocol,
                    client_ip: meta.src_ip,
                    client_port: meta.src_port,
                },
                FlowValue::new(meta.dst_ip, meta.dst_port, local_ip, local_port),
            );
            if rewrite_destination(packet, local_ip, local_port).is_some() {
                PacketAction::Send
            } else {
                warn!("failed to rewrite redirected packet");
                PacketAction::Drop
            }
        }
    }
}

fn process_network_packet(
    config: &RedirectorConfig,
    flow_table: &FlowTable,
    packet: &mut [u8],
) -> PacketAction {
    let Some(meta) = parse_ipv4_packet_meta(packet) else {
        return PacketAction::Send;
    };

    log_network_packet(&meta);

    if meta.protocol != TransportProtocol::Udp {
        return PacketAction::Send;
    }
    if meta.src_ip != config.hotspot.gateway_ip || meta.src_port != config.ports.dns_proxy {
        return PacketAction::Send;
    }
    let IpAddr::V4(dst_ip) = meta.dst_ip else {
        return PacketAction::Send;
    };
    if !config.hotspot.subnet.contains(dst_ip) {
        return PacketAction::Send;
    }

    let Some(flow) = flow_table.get(&FlowKey {
        protocol: TransportProtocol::Udp,
        client_ip: meta.dst_ip,
        client_port: meta.dst_port,
    }) else {
        warn!(
            "missing original DNS destination for response to {}",
            meta.dst_ip
        );
        return PacketAction::Send;
    };

    if rewrite_source(packet, flow.original_dst_ip, flow.original_dst_port).is_some() {
        PacketAction::Send
    } else {
        warn!("failed to rewrite DNS response source");
        PacketAction::Drop
    }
}

fn log_forward_decision(meta: &PacketMeta, decision: &RedirectDecision) {
    let line = FORWARD_DIAG_LINES.fetch_add(1, Ordering::Relaxed);
    if line >= DATAPATH_DIAG_LIMIT {
        return;
    }

    info!(
        "hproxy datapath forward: {:?} {}:{} -> {}:{} => {}",
        meta.protocol,
        meta.src_ip,
        meta.src_port,
        meta.dst_ip,
        meta.dst_port,
        format_decision(decision)
    );
}

fn log_network_packet(meta: &PacketMeta) {
    let line = NETWORK_DIAG_LINES.fetch_add(1, Ordering::Relaxed);
    if line >= DATAPATH_DIAG_LIMIT {
        return;
    }

    info!(
        "hproxy datapath network: {:?} {}:{} -> {}:{}",
        meta.protocol, meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port
    );
}

fn format_decision(decision: &RedirectDecision) -> String {
    match decision {
        RedirectDecision::Bypass(reason) => format!("bypass {reason:?}"),
        RedirectDecision::Drop(reason) => format!("drop {reason:?}"),
        RedirectDecision::RedirectTcp {
            local_ip,
            local_port,
        } => {
            format!("redirect tcp to {local_ip}:{local_port}")
        }
        RedirectDecision::RedirectDns {
            local_ip,
            local_port,
        } => {
            format!("redirect dns to {local_ip}:{local_port}")
        }
    }
}

fn parse_ipv4_packet_meta(packet: &[u8]) -> Option<PacketMeta> {
    let header = Ipv4PacketHeader::parse(packet)?;
    let protocol = match header.protocol {
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        _ => return None,
    };
    let transport = TransportHeader::parse(packet, header.header_len, protocol)?;

    Some(PacketMeta {
        protocol,
        src_ip: IpAddr::V4(header.src_ip),
        src_port: transport.src_port,
        dst_ip: IpAddr::V4(header.dst_ip),
        dst_port: transport.dst_port,
    })
}

#[derive(Debug, Clone, Copy)]
struct Ipv4PacketHeader {
    header_len: usize,
    total_len: usize,
    protocol: u8,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
}

impl Ipv4PacketHeader {
    fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }
        let version = packet[0] >> 4;
        if version != 4 {
            return None;
        }
        let header_len = ((packet[0] & 0x0f) as usize) * 4;
        if header_len < 20 || packet.len() < header_len {
            return None;
        }
        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if total_len < header_len || packet.len() < total_len {
            return None;
        }
        let frag = u16::from_be_bytes([packet[6], packet[7]]);
        if frag & 0x1fff != 0 {
            return None;
        }

        Some(Self {
            header_len,
            total_len,
            protocol: packet[9],
            src_ip: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            dst_ip: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct TransportHeader {
    offset: usize,
    src_port: u16,
    dst_port: u16,
}

impl TransportHeader {
    fn parse(packet: &[u8], offset: usize, protocol: TransportProtocol) -> Option<Self> {
        let min_len = match protocol {
            TransportProtocol::Tcp => 20,
            TransportProtocol::Udp => 8,
        };
        if packet.len() < offset + min_len {
            return None;
        }
        Some(Self {
            offset,
            src_port: u16::from_be_bytes([packet[offset], packet[offset + 1]]),
            dst_port: u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]),
        })
    }
}

fn rewrite_destination(packet: &mut [u8], dst_ip: IpAddr, dst_port: u16) -> Option<()> {
    let IpAddr::V4(dst_ip) = dst_ip else {
        return None;
    };
    let header = Ipv4PacketHeader::parse(packet)?;
    let transport = TransportHeader::parse(
        packet,
        header.header_len,
        match header.protocol {
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            _ => return None,
        },
    )?;
    packet[16..20].copy_from_slice(&dst_ip.octets());
    packet[transport.offset + 2..transport.offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    recalculate_ipv4_checksums(packet)
}

fn rewrite_source(packet: &mut [u8], src_ip: IpAddr, src_port: u16) -> Option<()> {
    let IpAddr::V4(src_ip) = src_ip else {
        return None;
    };
    let header = Ipv4PacketHeader::parse(packet)?;
    let transport = TransportHeader::parse(
        packet,
        header.header_len,
        match header.protocol {
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            _ => return None,
        },
    )?;
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[transport.offset..transport.offset + 2].copy_from_slice(&src_port.to_be_bytes());
    recalculate_ipv4_checksums(packet)
}

fn recalculate_ipv4_checksums(packet: &mut [u8]) -> Option<()> {
    let header = Ipv4PacketHeader::parse(packet)?;
    let total_len = header.total_len;
    packet[10..12].fill(0);
    let ip_checksum = checksum(&packet[..header.header_len]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let checksum_offset = match header.protocol {
        6 => header.header_len + 16,
        17 => header.header_len + 6,
        _ => return Some(()),
    };
    if packet.len() < checksum_offset + 2 {
        return None;
    }
    packet[checksum_offset..checksum_offset + 2].fill(0);

    let transport_checksum = transport_checksum(
        &packet[12..16],
        &packet[16..20],
        header.protocol,
        &packet[header.header_len..total_len],
    );
    let transport_checksum = if header.protocol == 17 && transport_checksum == 0 {
        0xffff
    } else {
        transport_checksum
    };
    packet[checksum_offset..checksum_offset + 2].copy_from_slice(&transport_checksum.to_be_bytes());
    Some(())
}

fn transport_checksum(src_ip: &[u8], dst_ip: &[u8], protocol: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len() + 1);
    pseudo.extend_from_slice(src_ip);
    pseudo.extend_from_slice(dst_ip);
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    checksum(&pseudo)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u16::from_be_bytes([byte, 0]) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(windows)]
mod windows_windivert {
    use std::{
        ffi::{CString, c_char, c_void},
        sync::Arc,
        thread::{self, JoinHandle},
    };

    use anyhow::{Context, Result, anyhow, bail};
    use libloading::Library;
    use tracing::{info, warn};

    use super::{
        FlowTable, Ipv4Cidr, PacketAction, RedirectorConfig, RedirectorPreflightConfig,
        process_forward_packet, process_network_packet,
    };
    use crate::doctor::run_windivert_probe;

    const WINDIVERT_LAYER_NETWORK: u32 = 0;
    const WINDIVERT_SHUTDOWN_BOTH: u32 = 0x3;
    const WINDIVERT_MTU_MAX: usize = 40 + 0xffff;

    type Handle = *mut c_void;
    type WinDivertOpen = unsafe extern "system" fn(*const c_char, u32, i16, u64) -> Handle;
    type WinDivertRecv =
        unsafe extern "system" fn(Handle, *mut c_void, u32, *mut u32, *mut WinDivertAddress) -> i32;
    type WinDivertSend = unsafe extern "system" fn(
        Handle,
        *const c_void,
        u32,
        *mut u32,
        *const WinDivertAddress,
    ) -> i32;
    type WinDivertShutdown = unsafe extern "system" fn(Handle, u32) -> i32;
    type WinDivertClose = unsafe extern "system" fn(Handle) -> i32;

    #[derive(Clone)]
    struct WinDivertApi {
        _library: Arc<Library>,
        open: WinDivertOpen,
        recv: WinDivertRecv,
        send: WinDivertSend,
        shutdown: WinDivertShutdown,
        close: WinDivertClose,
    }

    impl WinDivertApi {
        fn load() -> Result<Self> {
            let dll_path = run_windivert_probe().dll_path.ok_or_else(|| {
                anyhow!("WinDivert.dll is missing; run scripts/install-windivert.ps1")
            })?;
            let library = unsafe { Library::new(&dll_path) }
                .with_context(|| format!("load {}", dll_path.display()))?;
            let library = Arc::new(library);
            let open = unsafe { *library.get::<WinDivertOpen>(b"WinDivertOpen\0")? };
            let recv = unsafe { *library.get::<WinDivertRecv>(b"WinDivertRecv\0")? };
            let send = unsafe { *library.get::<WinDivertSend>(b"WinDivertSend\0")? };
            let shutdown = unsafe { *library.get::<WinDivertShutdown>(b"WinDivertShutdown\0")? };
            let close = unsafe { *library.get::<WinDivertClose>(b"WinDivertClose\0")? };
            Ok(Self {
                _library: library,
                open,
                recv,
                send,
                shutdown,
                close,
            })
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct WinDivertAddress {
        timestamp: i64,
        flags: u32,
        reserved2: u32,
        reserved3: [u8; 64],
    }

    impl Default for WinDivertAddress {
        fn default() -> Self {
            Self {
                timestamp: 0,
                flags: 0,
                reserved2: 0,
                reserved3: [0; 64],
            }
        }
    }

    struct WinDivertHandle {
        api: WinDivertApi,
        raw: usize,
    }

    impl WinDivertHandle {
        fn open(api: WinDivertApi, filter: &str, layer: u32) -> Result<Arc<Self>> {
            let filter = CString::new(filter).context("build WinDivert filter string")?;
            let raw = unsafe { (api.open)(filter.as_ptr(), layer, 0, 0) };
            if raw as isize == -1 {
                bail!(
                    "WinDivertOpen failed for filter '{}': {}",
                    filter.to_string_lossy(),
                    std::io::Error::last_os_error()
                );
            }
            Ok(Arc::new(Self {
                api,
                raw: raw as usize,
            }))
        }

        fn raw(&self) -> Handle {
            self.raw as Handle
        }

        fn shutdown(&self) {
            let _ = unsafe { (self.api.shutdown)(self.raw(), WINDIVERT_SHUTDOWN_BOTH) };
        }
    }

    impl Drop for WinDivertHandle {
        fn drop(&mut self) {
            let _ = unsafe { (self.api.close)(self.raw()) };
        }
    }

    pub struct RunningRedirector {
        handles: Vec<Arc<WinDivertHandle>>,
        workers: Vec<JoinHandle<()>>,
    }

    impl RunningRedirector {
        pub fn stop(self) {
            for handle in &self.handles {
                handle.shutdown();
            }
            for worker in self.workers {
                if let Err(err) = worker.join() {
                    warn!("WinDivert worker join failed: {err:?}");
                }
            }
        }
    }

    pub fn start(config: RedirectorConfig, flow_table: FlowTable) -> Result<RunningRedirector> {
        let api = WinDivertApi::load()?;
        let filters = WinDivertFilters::for_hotspot(config.ports.dns_proxy, config.hotspot.subnet);

        let inbound_handle = WinDivertHandle::open(
            api.clone(),
            filters.inbound.as_str(),
            WINDIVERT_LAYER_NETWORK,
        )?;
        let network_handle =
            WinDivertHandle::open(api, filters.network.as_str(), WINDIVERT_LAYER_NETWORK)?;

        let inbound_worker = spawn_worker(
            "network-inbound",
            Arc::clone(&inbound_handle),
            config.clone(),
            flow_table.clone(),
            process_forward_packet,
        );
        let network_worker = spawn_worker(
            "network",
            Arc::clone(&network_handle),
            config,
            flow_table,
            process_network_packet,
        );

        info!("WinDivert redirector started");
        Ok(RunningRedirector {
            handles: vec![inbound_handle, network_handle],
            workers: vec![inbound_worker, network_worker],
        })
    }

    pub fn preflight(config: RedirectorPreflightConfig) -> Result<()> {
        let api = WinDivertApi::load()?;
        let filters = WinDivertFilters::preflight(config.dns_proxy_port);
        let inbound_handle = WinDivertHandle::open(
            api.clone(),
            filters.inbound.as_str(),
            WINDIVERT_LAYER_NETWORK,
        )?;
        let network_handle =
            WinDivertHandle::open(api, filters.network.as_str(), WINDIVERT_LAYER_NETWORK)?;
        inbound_handle.shutdown();
        network_handle.shutdown();
        drop(inbound_handle);
        drop(network_handle);
        Ok(())
    }

    struct WinDivertFilters {
        inbound: String,
        network: String,
    }

    impl WinDivertFilters {
        fn preflight(dns_proxy_port: u16) -> Self {
            Self {
                inbound: "inbound and ip and (tcp or udp)".to_string(),
                network: format!(
                    "outbound and ip and udp and udp.SrcPort == {}",
                    dns_proxy_port
                ),
            }
        }

        fn for_hotspot(dns_proxy_port: u16, subnet: Ipv4Cidr) -> Self {
            let (low, high) = cidr_bounds(subnet);
            Self {
                inbound: format!(
                    "inbound and ip and (tcp or udp) and ip.SrcAddr >= {} and ip.SrcAddr <= {}",
                    low, high
                ),
                network: format!(
                    "outbound and ip and udp and udp.SrcPort == {}",
                    dns_proxy_port
                ),
            }
        }
    }

    fn cidr_bounds(subnet: Ipv4Cidr) -> (std::net::Ipv4Addr, std::net::Ipv4Addr) {
        let prefix_len = subnet.prefix_len.min(32);
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let low = u32::from(subnet.address) & mask;
        let high = low | !mask;
        (low.into(), high.into())
    }

    fn spawn_worker(
        name: &'static str,
        handle: Arc<WinDivertHandle>,
        config: RedirectorConfig,
        flow_table: FlowTable,
        processor: fn(&RedirectorConfig, &FlowTable, &mut [u8]) -> PacketAction,
    ) -> JoinHandle<()> {
        thread::spawn(move || run_worker(name, handle, config, flow_table, processor))
    }

    fn run_worker(
        name: &str,
        handle: Arc<WinDivertHandle>,
        config: RedirectorConfig,
        flow_table: FlowTable,
        processor: fn(&RedirectorConfig, &FlowTable, &mut [u8]) -> PacketAction,
    ) {
        let mut packet = vec![0_u8; WINDIVERT_MTU_MAX];
        loop {
            let mut addr = WinDivertAddress::default();
            let mut recv_len = 0_u32;
            let ok = unsafe {
                (handle.api.recv)(
                    handle.raw(),
                    packet.as_mut_ptr().cast(),
                    packet.len() as u32,
                    &mut recv_len,
                    &mut addr,
                )
            };
            if ok == 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(232) {
                    break;
                }
                warn!("WinDivert {name} recv failed: {err}");
                continue;
            }

            let packet_len = recv_len as usize;
            let action = processor(&config, &flow_table, &mut packet[..packet_len]);
            if action == PacketAction::Drop {
                continue;
            }

            let mut send_len = 0_u32;
            let ok = unsafe {
                (handle.api.send)(
                    handle.raw(),
                    packet.as_ptr().cast(),
                    recv_len,
                    &mut send_len,
                    &addr,
                )
            };
            if ok == 0 {
                warn!(
                    "WinDivert {name} send failed after {} bytes: {}",
                    recv_len,
                    std::io::Error::last_os_error()
                );
            }
        }
        info!("WinDivert {name} worker stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{LocalPorts, TransparentPolicy},
        hotspot::HotspotRuntime,
    };

    fn config() -> RedirectorConfig {
        RedirectorConfig {
            hotspot: HotspotRuntime {
                interface_index: 23,
                gateway_ip: "192.168.137.1".parse().unwrap(),
                subnet: Ipv4Cidr {
                    address: "192.168.137.0".parse().unwrap(),
                    prefix_len: 24,
                },
            },
            ports: LocalPorts {
                transparent_tcp: 16000,
                dns_proxy: 1053,
            },
            policy: TransparentPolicy::default(),
        }
    }

    fn packet(protocol: TransportProtocol, dst: &str, port: u16) -> PacketMeta {
        PacketMeta {
            protocol,
            src_ip: "192.168.137.20".parse().unwrap(),
            src_port: 51000,
            dst_ip: dst.parse().unwrap(),
            dst_port: port,
        }
    }

    fn ipv4_packet(
        protocol: TransportProtocol,
        src: &str,
        src_port: u16,
        dst: &str,
        dst_port: u16,
    ) -> Vec<u8> {
        let protocol_number = match protocol {
            TransportProtocol::Tcp => 6,
            TransportProtocol::Udp => 17,
        };
        let transport_len = match protocol {
            TransportProtocol::Tcp => 20,
            TransportProtocol::Udp => 8,
        };
        let total_len = 20 + transport_len;
        let mut packet = vec![0_u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol_number;
        packet[12..16].copy_from_slice(&src.parse::<Ipv4Addr>().unwrap().octets());
        packet[16..20].copy_from_slice(&dst.parse::<Ipv4Addr>().unwrap().octets());
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        if protocol == TransportProtocol::Tcp {
            packet[32] = 0x50;
        } else {
            packet[24..26].copy_from_slice(&(transport_len as u16).to_be_bytes());
        }
        recalculate_ipv4_checksums(&mut packet).unwrap();
        packet
    }

    #[test]
    fn redirects_hotspot_tcp_to_transparent_proxy() {
        let decision = classify_packet(
            &config(),
            &packet(TransportProtocol::Tcp, "93.184.216.34", 443),
        );

        assert_eq!(
            decision,
            RedirectDecision::RedirectTcp {
                local_ip: "192.168.137.1".parse().unwrap(),
                local_port: 16000,
            }
        );
    }

    #[test]
    fn redirects_dns_even_when_client_targets_public_resolver() {
        let decision = classify_packet(&config(), &packet(TransportProtocol::Udp, "8.8.8.8", 53));

        assert_eq!(
            decision,
            RedirectDecision::RedirectDns {
                local_ip: "192.168.137.1".parse().unwrap(),
                local_port: 1053,
            }
        );
    }

    #[test]
    fn drops_quic_udp_443_by_default() {
        let decision = classify_packet(
            &config(),
            &packet(TransportProtocol::Udp, "93.184.216.34", 443),
        );

        assert_eq!(decision, RedirectDecision::Drop(DropReason::QuicBlocked));
    }

    #[test]
    fn bypasses_private_lan_destinations() {
        let decision = classify_packet(
            &config(),
            &packet(TransportProtocol::Tcp, "192.168.1.10", 443),
        );

        assert_eq!(decision, RedirectDecision::Bypass(BypassReason::PrivateLan));
    }

    #[test]
    fn bypasses_traffic_outside_hotspot_subnet() {
        let mut meta = packet(TransportProtocol::Tcp, "93.184.216.34", 443);
        meta.src_ip = "10.0.0.10".parse().unwrap();

        let decision = classify_packet(&config(), &meta);

        assert_eq!(
            decision,
            RedirectDecision::Bypass(BypassReason::NotHotspotClient)
        );
    }

    #[test]
    fn rewrites_tcp_packet_to_local_proxy_and_records_original_destination() {
        let config = config();
        let flow_table = FlowTable::new(16);
        let mut packet = ipv4_packet(
            TransportProtocol::Tcp,
            "192.168.137.20",
            51000,
            "93.184.216.34",
            443,
        );

        let action = process_forward_packet(&config, &flow_table, &mut packet);
        let rewritten = parse_ipv4_packet_meta(&packet).unwrap();
        let flow = flow_table
            .get(&FlowKey {
                protocol: TransportProtocol::Tcp,
                client_ip: "192.168.137.20".parse().unwrap(),
                client_port: 51000,
            })
            .unwrap();

        assert_eq!(action, PacketAction::Send);
        assert_eq!(rewritten.dst_ip, "192.168.137.1".parse::<IpAddr>().unwrap());
        assert_eq!(rewritten.dst_port, 16000);
        assert_eq!(
            flow.original_dst_ip,
            "93.184.216.34".parse::<IpAddr>().unwrap()
        );
        assert_eq!(flow.original_dst_port, 443);
    }

    #[test]
    fn rewrites_dns_response_source_to_original_resolver() {
        let config = config();
        let flow_table = FlowTable::new(16);
        flow_table.insert(
            FlowKey {
                protocol: TransportProtocol::Udp,
                client_ip: "192.168.137.20".parse().unwrap(),
                client_port: 53000,
            },
            FlowValue::new(
                "8.8.8.8".parse().unwrap(),
                53,
                "192.168.137.1".parse().unwrap(),
                1053,
            ),
        );
        let mut packet = ipv4_packet(
            TransportProtocol::Udp,
            "192.168.137.1",
            1053,
            "192.168.137.20",
            53000,
        );

        let action = process_network_packet(&config, &flow_table, &mut packet);
        let rewritten = parse_ipv4_packet_meta(&packet).unwrap();

        assert_eq!(action, PacketAction::Send);
        assert_eq!(rewritten.src_ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(rewritten.src_port, 53);
    }

    #[test]
    fn drops_quic_packet_without_recording_flow() {
        let config = config();
        let flow_table = FlowTable::new(16);
        let mut packet = ipv4_packet(
            TransportProtocol::Udp,
            "192.168.137.20",
            53000,
            "93.184.216.34",
            443,
        );

        let action = process_forward_packet(&config, &flow_table, &mut packet);

        assert_eq!(action, PacketAction::Drop);
        assert!(flow_table.is_empty());
    }
}
