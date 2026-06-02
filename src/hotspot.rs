#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;

use crate::{
    config::{HotspotBand, HotspotConfig},
    hostcmd::{powershell, powershell_available, powershell_named, powershell_with_env_named},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotspotRuntime {
    pub interface_index: u32,
    pub gateway_ip: IpAddr,
    pub subnet: Ipv4Cidr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4Cidr {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let prefix_len = self.prefix_len.min(32);
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let network = u32::from(self.address) & mask;
        let candidate = u32::from(ip) & mask;
        network == candidate
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotspotStatus {
    Stopped,
    Running,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotspotAccessPoint {
    pub ssid: String,
}

#[async_trait]
pub trait HotspotController: Send + Sync {
    async fn start(&self, config: &HotspotConfig) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn status(&self) -> Result<HotspotStatus>;
    async fn access_point(&self) -> Result<Option<HotspotAccessPoint>>;
}

#[async_trait]
pub trait InterfaceDiscovery: Send + Sync {
    async fn discover_hotspot(&self) -> Result<HotspotRuntime>;
}

#[derive(Default)]
pub struct WindowsHotspot;

#[async_trait]
impl HotspotController for WindowsHotspot {
    async fn start(&self, config: &HotspotConfig) -> Result<()> {
        let native_config = config.clone();
        let native_error =
            match tokio::task::spawn_blocking(move || native_hotspot_start(native_config))
                .await
                .context("join native hotspot start task")?
            {
                Ok(()) => return Ok(()),
                Err(err) if !powershell_available() => return Err(err),
                Err(err) => err,
            };

        if !powershell_available() {
            bail!("hotspot control requires powershell.exe and Windows WinRT tethering APIs")
        }

        let ssid = config.ssid.clone();
        let password = config.password.clone();
        let band = tethering_band_name(config.band).to_string();
        tokio::task::spawn_blocking(move || {
            powershell_with_env_named(
                "hotspot start",
                HOTSPOT_START_SCRIPT,
                &[
                    ("HPROXY_HOTSPOT_SSID", &ssid),
                    ("HPROXY_HOTSPOT_PASSWORD", &password),
                    ("HPROXY_HOTSPOT_BAND", &band),
                ],
            )
        })
        .await
        .context("join hotspot start task")?
        .with_context(|| {
            format!(
                "native WinRT hotspot start failed before PowerShell fallback: {native_error:#}"
            )
        })?;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        let native_error = match tokio::task::spawn_blocking(native_hotspot_stop)
            .await
            .context("join native hotspot stop task")?
        {
            Ok(()) => return Ok(()),
            Err(err) if !powershell_available() => return Err(err),
            Err(err) => err,
        };

        if !powershell_available() {
            bail!("hotspot control requires powershell.exe and Windows WinRT tethering APIs")
        }

        tokio::task::spawn_blocking(|| powershell_named("hotspot stop", HOTSPOT_STOP_SCRIPT))
            .await
            .context("join hotspot stop task")?
            .with_context(|| {
                format!(
                    "native WinRT hotspot stop failed before PowerShell fallback: {native_error:#}"
                )
            })?;
        Ok(())
    }

    async fn status(&self) -> Result<HotspotStatus> {
        match tokio::task::spawn_blocking(native_hotspot_status)
            .await
            .context("join native hotspot status task")?
        {
            Ok(status) => return Ok(status),
            Err(_) if !powershell_available() => return Ok(HotspotStatus::Unknown),
            Err(_) => {}
        }

        if !powershell_available() {
            return Ok(HotspotStatus::Unknown);
        }

        let output = tokio::task::spawn_blocking(|| {
            powershell_named("hotspot status", HOTSPOT_STATUS_SCRIPT)
        })
        .await
        .context("join hotspot status task")??;
        Ok(parse_hotspot_status(&output))
    }

    async fn access_point(&self) -> Result<Option<HotspotAccessPoint>> {
        match tokio::task::spawn_blocking(native_hotspot_access_point)
            .await
            .context("join native hotspot access point task")?
        {
            Ok(access_point) => return Ok(access_point),
            Err(_) if !powershell_available() => return Ok(None),
            Err(_) => {}
        }

        if !powershell_available() {
            return Ok(None);
        }

        let output = tokio::task::spawn_blocking(|| {
            powershell_named("hotspot access point", HOTSPOT_ACCESS_POINT_SCRIPT)
        })
        .await
        .context("join hotspot access point task")??;
        Ok(parse_hotspot_access_point(&output))
    }
}

#[async_trait]
impl InterfaceDiscovery for WindowsHotspot {
    async fn discover_hotspot(&self) -> Result<HotspotRuntime> {
        discover_hotspot_private_interface().await
    }
}

async fn discover_hotspot_private_interface() -> Result<HotspotRuntime> {
    match discover_hotspot_private_interface_native() {
        Ok(runtime) => return Ok(runtime),
        Err(native_error) if !powershell_available() => return Err(native_error),
        Err(_) => {}
    }

    let output = tokio::task::spawn_blocking(|| powershell(HOTSPOT_INTERFACE_DISCOVERY_SCRIPT))
        .await
        .context("join hotspot interface discovery task")??;
    parse_hotspot_runtime(&output)
}

#[cfg(windows)]
fn discover_hotspot_private_interface_native() -> Result<HotspotRuntime> {
    use std::{ffi::c_void, ptr};

    use windows_sys::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
        NetworkManagement::{
            IpHelper::{
                GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
                GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IF_TYPE_IEEE80211,
                IP_ADAPTER_ADDRESSES_LH,
            },
            Ndis::IfOperStatusUp,
        },
        Networking::WinSock::AF_INET,
    };

    let flags = GAA_FLAG_INCLUDE_ALL_INTERFACES
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 15_000_u32;

    for _ in 0..3 {
        let units = (size as usize).div_ceil(std::mem::size_of::<u64>());
        let mut buffer = vec![0_u64; units.max(1)];
        let result = unsafe {
            GetAdaptersAddresses(
                AF_INET as u32,
                flags,
                ptr::null::<c_void>(),
                buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };

        if result == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if result != ERROR_SUCCESS {
            bail!("GetAdaptersAddresses failed with Windows error {result}");
        }

        let mut candidates = Vec::new();
        let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !adapter.is_null() {
            let adapter_ref = unsafe { &*adapter };
            let description = wide_ptr_to_string(adapter_ref.Description);
            let friendly_name = wide_ptr_to_string(adapter_ref.FriendlyName);
            let is_wifi_direct = description.contains("Wi-Fi Direct")
                || description.contains("WiFi Direct")
                || friendly_name.contains("Wi-Fi Direct")
                || friendly_name.contains("WiFi Direct");
            if adapter_ref.IfType == IF_TYPE_IEEE80211
                && adapter_ref.OperStatus == IfOperStatusUp
                && is_wifi_direct
            {
                let interface_index = unsafe { adapter_ref.Anonymous1.Anonymous.IfIndex };
                let mut unicast = adapter_ref.FirstUnicastAddress;
                while !unicast.is_null() {
                    let unicast_ref = unsafe { &*unicast };
                    if let Some(gateway_ip) = ipv4_from_sockaddr(unicast_ref.Address.lpSockaddr) {
                        let prefix_len = unicast_ref.OnLinkPrefixLength;
                        if is_usable_hotspot_gateway(gateway_ip, prefix_len) {
                            candidates.push((interface_index, prefix_len, gateway_ip));
                        }
                    }
                    unicast = unicast_ref.Next;
                }
            }
            adapter = adapter_ref.Next;
        }

        candidates.sort_by_key(|(interface_index, prefix_len, _)| (*interface_index, *prefix_len));
        if let Some((interface_index, prefix_len, gateway_ip)) = candidates.into_iter().next() {
            return Ok(HotspotRuntime {
                interface_index,
                gateway_ip: IpAddr::V4(gateway_ip),
                subnet: Ipv4Cidr {
                    address: network_address(gateway_ip, prefix_len),
                    prefix_len,
                },
            });
        }

        bail!("no active native Wi-Fi Direct hotspot interface with IPv4 address found");
    }

    Err(anyhow!(
        "GetAdaptersAddresses repeatedly reported buffer overflow during hotspot discovery"
    ))
}

#[cfg(not(windows))]
fn discover_hotspot_private_interface_native() -> Result<HotspotRuntime> {
    bail!("native hotspot interface discovery requires a Windows binary")
}

#[cfg(windows)]
fn wide_ptr_to_string(value: windows_sys::core::PWSTR) -> String {
    if value.is_null() {
        return String::new();
    }

    let mut len = 0;
    unsafe {
        while *value.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, len))
    }
}

#[cfg(windows)]
fn ipv4_from_sockaddr(
    sockaddr: *mut windows_sys::Win32::Networking::WinSock::SOCKADDR,
) -> Option<Ipv4Addr> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    if sockaddr.is_null() {
        return None;
    }

    let sockaddr_ref = unsafe { &*sockaddr };
    if sockaddr_ref.sa_family != AF_INET {
        return None;
    }

    let sockaddr_in = unsafe { &*(sockaddr as *const SOCKADDR_IN) };
    let octets = unsafe { sockaddr_in.sin_addr.S_un.S_un_b };
    Some(Ipv4Addr::new(
        octets.s_b1,
        octets.s_b2,
        octets.s_b3,
        octets.s_b4,
    ))
}

#[cfg(windows)]
fn is_usable_hotspot_gateway(ip: Ipv4Addr, prefix_len: u8) -> bool {
    prefix_len <= 32 && !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified()
}

const HOTSPOT_INTERFACE_DISCOVERY_SCRIPT: &str = r#"
$adapter = Get-NetAdapter -IncludeHidden |
  Where-Object {
    $_.InterfaceDescription -match 'Wi-Fi Direct' -and
    ($_.Status -eq 'Up' -or $_.Status -eq 'Connected')
  } |
  Sort-Object ifIndex |
  Select-Object -First 1

if ($null -eq $adapter) { exit 0 }

$addr = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex |
  Where-Object {
    $_.IPAddress -notlike '169.254.*' -and
    $_.IPAddress -ne '127.0.0.1'
  } |
  Sort-Object PrefixLength |
  Select-Object -First 1

if ($null -eq $addr) { exit 0 }

'{0}|{1}|{2}' -f $adapter.ifIndex, $addr.IPAddress, $addr.PrefixLength
"#;

const HOTSPOT_STATUS_SCRIPT: &str = r#"
[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null

$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if ($null -eq $profile) {
  'Unknown'
  exit 0
}

$manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
$manager.TetheringOperationalState.ToString()
"#;

const HOTSPOT_ACCESS_POINT_SCRIPT: &str = r#"
[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null

$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if ($null -eq $profile) {
  exit 0
}

$manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
$config = $manager.GetCurrentAccessPointConfiguration()
$config.Ssid
"#;

const HOTSPOT_START_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.TetheringWiFiBand,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.TetheringWiFiAuthenticationKind,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null

function Start-WinRtOperation($operation, $name) {
  if ($null -eq $operation) {
    throw "$name returned a null WinRT operation"
  }
}

function Wait-HotspotState($manager, $expected, $name) {
  $timeoutAt = [DateTimeOffset]::UtcNow.AddSeconds(30)
  while ($manager.TetheringOperationalState.ToString() -ne $expected) {
    if ([DateTimeOffset]::UtcNow -gt $timeoutAt) {
      throw "$name did not reach $expected within 30 seconds; current state is $($manager.TetheringOperationalState)"
    }
    Start-Sleep -Milliseconds 250
  }
}

function Wait-HotspotSsid($manager, $expected) {
  $timeoutAt = [DateTimeOffset]::UtcNow.AddSeconds(30)
  while ($manager.GetCurrentAccessPointConfiguration().Ssid -ne $expected) {
    if ([DateTimeOffset]::UtcNow -gt $timeoutAt) {
      $current = $manager.GetCurrentAccessPointConfiguration().Ssid
      throw "ConfigureAccessPointAsync did not apply SSID '$expected' within 30 seconds; current SSID is '$current'"
    }
    Start-Sleep -Milliseconds 250
  }
}

$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if ($null -eq $profile) {
  throw 'No internet connection profile is available for tethering'
}

$capability = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::GetTetheringCapabilityFromConnectionProfile($profile)
if ($capability.ToString() -ne 'Enabled') {
  throw "Tethering capability is $capability"
}

$manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
$config = $manager.GetCurrentAccessPointConfiguration()
$config.Ssid = $env:HPROXY_HOTSPOT_SSID
$config.Passphrase = $env:HPROXY_HOTSPOT_PASSWORD
$config.AuthenticationKind = [Windows.Networking.NetworkOperators.TetheringWiFiAuthenticationKind]::Wpa2

switch ($env:HPROXY_HOTSPOT_BAND) {
  'Auto' { $config.Band = [Windows.Networking.NetworkOperators.TetheringWiFiBand]::Auto }
  'TwoPointFourGigahertz' { $config.Band = [Windows.Networking.NetworkOperators.TetheringWiFiBand]::TwoPointFourGigahertz }
  'FiveGigahertz' { $config.Band = [Windows.Networking.NetworkOperators.TetheringWiFiBand]::FiveGigahertz }
  default { throw "Unsupported hotspot band $env:HPROXY_HOTSPOT_BAND" }
}

Start-WinRtOperation ($manager.ConfigureAccessPointAsync($config)) 'ConfigureAccessPointAsync'
Wait-HotspotSsid $manager $env:HPROXY_HOTSPOT_SSID

if ($manager.TetheringOperationalState.ToString() -ne 'On') {
  Start-WinRtOperation ($manager.StartTetheringAsync()) 'StartTetheringAsync'
  Wait-HotspotState $manager 'On' 'StartTetheringAsync'
}

$manager.TetheringOperationalState.ToString()
"#;

const HOTSPOT_STOP_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null

function Start-WinRtOperation($operation, $name) {
  if ($null -eq $operation) {
    throw "$name returned a null WinRT operation"
  }
}

function Wait-HotspotState($manager, $expected, $name) {
  $timeoutAt = [DateTimeOffset]::UtcNow.AddSeconds(30)
  while ($manager.TetheringOperationalState.ToString() -ne $expected) {
    if ([DateTimeOffset]::UtcNow -gt $timeoutAt) {
      throw "$name did not reach $expected within 30 seconds; current state is $($manager.TetheringOperationalState)"
    }
    Start-Sleep -Milliseconds 250
  }
}

$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if ($null -eq $profile) {
  'Unknown'
  exit 0
}

$manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
if ($manager.TetheringOperationalState.ToString() -ne 'Off') {
  Start-WinRtOperation ($manager.StopTetheringAsync()) 'StopTetheringAsync'
  Wait-HotspotState $manager 'Off' 'StopTetheringAsync'
}

$manager.TetheringOperationalState.ToString()
"#;

fn parse_hotspot_runtime(output: &str) -> Result<HotspotRuntime> {
    let line = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("no active Wi-Fi Direct hotspot interface with IPv4 address found")
        })?;

    let mut parts = line.split('|');
    let interface_index = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing hotspot interface index"))?
        .parse::<u32>()
        .context("parse hotspot interface index")?;
    let gateway_ip = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing hotspot gateway IP"))?
        .parse::<Ipv4Addr>()
        .context("parse hotspot gateway IP")?;
    let prefix_len = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing hotspot prefix length"))?
        .parse::<u8>()
        .context("parse hotspot prefix length")?;

    if parts.next().is_some() {
        bail!("unexpected extra fields in hotspot interface discovery output");
    }

    Ok(HotspotRuntime {
        interface_index,
        gateway_ip: IpAddr::V4(gateway_ip),
        subnet: Ipv4Cidr {
            address: network_address(gateway_ip, prefix_len),
            prefix_len,
        },
    })
}

fn parse_hotspot_status(output: &str) -> HotspotStatus {
    let state = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("Unknown");

    match state {
        "On" => HotspotStatus::Running,
        "Off" => HotspotStatus::Stopped,
        _ => HotspotStatus::Unknown,
    }
}

fn parse_hotspot_access_point(output: &str) -> Option<HotspotAccessPoint> {
    let ssid = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    Some(HotspotAccessPoint {
        ssid: ssid.to_string(),
    })
}

#[cfg(windows)]
fn native_tethering_manager()
-> Result<windows::Networking::NetworkOperators::NetworkOperatorTetheringManager> {
    use windows::Networking::{
        Connectivity::NetworkInformation, NetworkOperators::NetworkOperatorTetheringManager,
    };

    let profile = NetworkInformation::GetInternetConnectionProfile()
        .context("get internet connection profile")?;
    NetworkOperatorTetheringManager::CreateFromConnectionProfile(&profile)
        .context("create native WinRT tethering manager")
}

#[cfg(not(windows))]
fn native_tethering_manager() -> Result<()> {
    bail!("native WinRT tethering manager requires a Windows binary")
}

#[cfg(windows)]
fn native_hotspot_start(config: HotspotConfig) -> Result<()> {
    use windows::{
        Networking::{
            Connectivity::NetworkInformation,
            NetworkOperators::{
                NetworkOperatorTetheringManager, TetheringCapability, TetheringOperationalState,
                TetheringWiFiAuthenticationKind,
            },
        },
        core::HSTRING,
    };

    let profile = NetworkInformation::GetInternetConnectionProfile()
        .context("get internet connection profile")?;
    let capability =
        NetworkOperatorTetheringManager::GetTetheringCapabilityFromConnectionProfile(&profile)
            .context("query native WinRT tethering capability")?;
    if capability != TetheringCapability::Enabled {
        bail!("Tethering capability is {capability:?}");
    }

    let manager = NetworkOperatorTetheringManager::CreateFromConnectionProfile(&profile)
        .context("create native WinRT tethering manager")?;
    let access_point = manager
        .GetCurrentAccessPointConfiguration()
        .context("query native WinRT hotspot access point configuration")?;
    access_point
        .SetSsid(&HSTRING::from(config.ssid.as_str()))
        .context("set native WinRT hotspot SSID")?;
    access_point
        .SetPassphrase(&HSTRING::from(config.password.as_str()))
        .context("set native WinRT hotspot passphrase")?;
    access_point
        .SetAuthenticationKind(TetheringWiFiAuthenticationKind::Wpa2)
        .context("set native WinRT hotspot WPA2 authentication")?;
    access_point
        .SetBand(native_tethering_band(config.band))
        .context("set native WinRT hotspot band")?;

    manager
        .ConfigureAccessPointAsync(&access_point)
        .context("start native ConfigureAccessPointAsync")?
        .join()
        .context("wait for native ConfigureAccessPointAsync")?;
    wait_native_hotspot_ssid(&manager, &config.ssid)
        .context("wait for native hotspot SSID configuration")?;

    if manager
        .TetheringOperationalState()
        .context("query native WinRT tethering state")?
        != TetheringOperationalState::On
    {
        let result = manager
            .StartTetheringAsync()
            .context("start native StartTetheringAsync")?
            .join()
            .context("wait for native StartTetheringAsync")?;
        ensure_tethering_operation_success("StartTetheringAsync", &result)?;
        wait_native_hotspot_state(
            &manager,
            TetheringOperationalState::On,
            "StartTetheringAsync",
        )?;
    }

    Ok(())
}

#[cfg(not(windows))]
fn native_hotspot_start(_config: HotspotConfig) -> Result<()> {
    bail!("native WinRT hotspot start requires a Windows binary")
}

#[cfg(windows)]
fn native_hotspot_stop() -> Result<()> {
    use windows::Networking::NetworkOperators::TetheringOperationalState;

    let manager = native_tethering_manager()?;
    if manager
        .TetheringOperationalState()
        .context("query native WinRT tethering state")?
        != TetheringOperationalState::Off
    {
        let result = manager
            .StopTetheringAsync()
            .context("start native StopTetheringAsync")?
            .join()
            .context("wait for native StopTetheringAsync")?;
        ensure_tethering_operation_success("StopTetheringAsync", &result)?;
        wait_native_hotspot_state(
            &manager,
            TetheringOperationalState::Off,
            "StopTetheringAsync",
        )?;
    }

    Ok(())
}

#[cfg(not(windows))]
fn native_hotspot_stop() -> Result<()> {
    bail!("native WinRT hotspot stop requires a Windows binary")
}

#[cfg(windows)]
fn native_hotspot_status() -> Result<HotspotStatus> {
    use windows::Networking::NetworkOperators::TetheringOperationalState;

    let state = native_tethering_manager()?
        .TetheringOperationalState()
        .context("query native WinRT tethering state")?;
    Ok(match state {
        TetheringOperationalState::On => HotspotStatus::Running,
        TetheringOperationalState::Off => HotspotStatus::Stopped,
        _ => HotspotStatus::Unknown,
    })
}

#[cfg(not(windows))]
fn native_hotspot_status() -> Result<HotspotStatus> {
    bail!("native WinRT hotspot status requires a Windows binary")
}

#[cfg(windows)]
fn native_hotspot_access_point() -> Result<Option<HotspotAccessPoint>> {
    let config = native_tethering_manager()?
        .GetCurrentAccessPointConfiguration()
        .context("query native WinRT hotspot access point configuration")?;
    let ssid = config.Ssid().context("query native WinRT hotspot SSID")?;
    let ssid = ssid.to_string();
    if ssid.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(HotspotAccessPoint { ssid }))
}

#[cfg(not(windows))]
fn native_hotspot_access_point() -> Result<Option<HotspotAccessPoint>> {
    bail!("native WinRT hotspot access point requires a Windows binary")
}

#[cfg(windows)]
fn native_tethering_band(
    band: HotspotBand,
) -> windows::Networking::NetworkOperators::TetheringWiFiBand {
    use windows::Networking::NetworkOperators::TetheringWiFiBand;

    match band {
        HotspotBand::Auto => TetheringWiFiBand::Auto,
        HotspotBand::TwoGhz => TetheringWiFiBand::TwoPointFourGigahertz,
        HotspotBand::FiveGhz => TetheringWiFiBand::FiveGigahertz,
    }
}

#[cfg(windows)]
fn wait_native_hotspot_state(
    manager: &windows::Networking::NetworkOperators::NetworkOperatorTetheringManager,
    expected: windows::Networking::NetworkOperators::TetheringOperationalState,
    operation_name: &str,
) -> Result<()> {
    let timeout_at = Instant::now() + Duration::from_secs(30);
    loop {
        let current = manager
            .TetheringOperationalState()
            .context("query native WinRT tethering state")?;
        if current == expected {
            return Ok(());
        }
        if Instant::now() >= timeout_at {
            bail!(
                "{operation_name} did not reach {expected:?} within 30 seconds; current state is {current:?}"
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(windows)]
fn wait_native_hotspot_ssid(
    manager: &windows::Networking::NetworkOperators::NetworkOperatorTetheringManager,
    expected: &str,
) -> Result<()> {
    let timeout_at = Instant::now() + Duration::from_secs(30);
    loop {
        let current = manager
            .GetCurrentAccessPointConfiguration()
            .context("query native WinRT hotspot access point configuration")?
            .Ssid()
            .context("query native WinRT hotspot SSID")?
            .to_string();
        if current == expected {
            return Ok(());
        }
        if Instant::now() >= timeout_at {
            bail!(
                "ConfigureAccessPointAsync did not apply SSID '{expected}' within 30 seconds; current SSID is '{current}'"
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(windows)]
fn ensure_tethering_operation_success(
    operation_name: &str,
    result: &windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult,
) -> Result<()> {
    use windows::Networking::NetworkOperators::TetheringOperationStatus;

    let status = result
        .Status()
        .with_context(|| format!("query native {operation_name} result status"))?;
    if status == TetheringOperationStatus::Success {
        return Ok(());
    }

    let message = result
        .AdditionalErrorMessage()
        .map(|value| value.to_string())
        .unwrap_or_default();
    if message.trim().is_empty() {
        bail!("{operation_name} failed with status {status:?}");
    }
    bail!("{operation_name} failed with status {status:?}: {message}");
}

fn network_address(ip: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let prefix_len = prefix_len.min(32);
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn tethering_band_name(band: HotspotBand) -> &'static str {
    match band {
        HotspotBand::Auto => "Auto",
        HotspotBand::TwoGhz => "TwoPointFourGigahertz",
        HotspotBand::FiveGhz => "FiveGigahertz",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hotspot_runtime_output() {
        let runtime = parse_hotspot_runtime("23|192.168.137.1|24\r\n").unwrap();

        assert_eq!(runtime.interface_index, 23);
        assert_eq!(
            runtime.gateway_ip,
            "192.168.137.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            runtime.subnet.address,
            "192.168.137.0".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(runtime.subnet.prefix_len, 24);
    }

    #[test]
    fn rejects_empty_hotspot_runtime_output() {
        assert!(parse_hotspot_runtime("").is_err());
    }

    #[test]
    fn computes_non_24_network_address() {
        assert_eq!(
            network_address("10.42.9.17".parse().unwrap(), 20),
            "10.42.0.0".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn parses_hotspot_status_output() {
        assert_eq!(parse_hotspot_status("On\r\n"), HotspotStatus::Running);
        assert_eq!(parse_hotspot_status("Off\r\n"), HotspotStatus::Stopped);
        assert_eq!(
            parse_hotspot_status("InTransition\r\n"),
            HotspotStatus::Unknown
        );
    }

    #[test]
    fn parses_hotspot_access_point_output() {
        assert_eq!(
            parse_hotspot_access_point("VirtualProxyAP\r\n"),
            Some(HotspotAccessPoint {
                ssid: "VirtualProxyAP".to_string()
            })
        );
        assert_eq!(parse_hotspot_access_point("\r\n"), None);
    }

    #[test]
    fn maps_hotspot_band_to_winrt_name() {
        assert_eq!(tethering_band_name(HotspotBand::Auto), "Auto");
        assert_eq!(
            tethering_band_name(HotspotBand::TwoGhz),
            "TwoPointFourGigahertz"
        );
        assert_eq!(tethering_band_name(HotspotBand::FiveGhz), "FiveGigahertz");
    }

    #[test]
    fn winrt_start_stop_scripts_have_state_timeouts() {
        assert!(HOTSPOT_START_SCRIPT.contains("Wait-HotspotState $manager 'On'"));
        assert!(HOTSPOT_STOP_SCRIPT.contains("Wait-HotspotState $manager 'Off'"));
        assert!(HOTSPOT_START_SCRIPT.contains("within 30 seconds"));
        assert!(HOTSPOT_STOP_SCRIPT.contains("within 30 seconds"));
    }
}
