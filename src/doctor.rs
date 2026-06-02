use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::hostcmd::{powershell, powershell_available};

const BUILD_TOOL_PROBE_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'

function Write-Field($Name, $Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        Write-Output "${Name}: "
    } else {
        Write-Output "${Name}: $Value"
    }
}

function Command-Version($Command, [string[]]$CommandArgs) {
    $cmd = Get-Command $Command -ErrorAction SilentlyContinue
    if (-not $cmd) {
        return ''
    }

    $output = & $cmd.Source @CommandArgs 2>$null | Select-Object -First 1
    if ($output) {
        return $output.ToString().Trim()
    }

    return ''
}

function Latest-ChildName($Path) {
    if (-not (Test-Path $Path)) {
        return ''
    }

    $item = Get-ChildItem $Path -Directory |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if ($item) {
        return $item.Name
    }

    return ''
}

$rustc = Command-Version 'rustc' @('--version')
$cargo = Command-Version 'cargo' @('--version')
$dotnet = Command-Version 'dotnet' @('--version')

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsPath = ''
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vsPath) {
        $vsPath = $vsPath.Trim()
    }
}

$msvcVersion = ''
$clPath = ''
$msbuildPath = ''
if ($vsPath) {
    $msvcRoot = Join-Path $vsPath 'VC\Tools\MSVC'
    $msvcVersion = Latest-ChildName $msvcRoot
    if ($msvcVersion) {
        $candidateCl = Join-Path $msvcRoot "$msvcVersion\bin\Hostx64\x64\cl.exe"
        if (Test-Path $candidateCl) {
            $clPath = $candidateCl
        }
    }

    $candidateMsbuild = Join-Path $vsPath 'MSBuild\Current\Bin\amd64\MSBuild.exe'
    if (Test-Path $candidateMsbuild) {
        $msbuildPath = $candidateMsbuild
    }
}

$sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$sdkVersion = ''
$wfpHeader = ''
$signtool = ''
$includeRoot = Join-Path $sdkRoot 'Include'
if (Test-Path $includeRoot) {
    $sdkVersion = Latest-ChildName $includeRoot
    if ($sdkVersion) {
        $candidateHeader = Join-Path $includeRoot "$sdkVersion\um\fwpmu.h"
        if (Test-Path $candidateHeader) {
            $wfpHeader = $candidateHeader
        }

        $candidateSigntool = Join-Path $sdkRoot "bin\$sdkVersion\x64\signtool.exe"
        if (Test-Path $candidateSigntool) {
            $signtool = $candidateSigntool
        }
    }
}

Write-Field 'rustc' $rustc
Write-Field 'cargo' $cargo
Write-Field 'dotnet sdk' $dotnet
Write-Field 'visual studio' $vsPath
Write-Field 'msvc' $msvcVersion
Write-Field 'cl path' $clPath
Write-Field 'msbuild path' $msbuildPath
Write-Field 'windows sdk' $sdkVersion
Write-Field 'signtool path' $signtool
Write-Field 'wfp header' $wfpHeader
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProbe {
    pub probe_available: bool,
    pub wifi_driver: Option<String>,
    pub hosted_network_supported: Option<bool>,
    pub station_supported: Option<bool>,
    pub soft_ap_supported: Option<bool>,
    pub wifi_direct_go_supported: Option<bool>,
    pub p2p_max_mobile_ap_clients: Option<u16>,
    pub wifi_direct_virtual_adapters: usize,
    pub mobile_hotspot_service_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildToolProbe {
    pub probe_available: bool,
    pub rustc_version: Option<String>,
    pub cargo_version: Option<String>,
    pub dotnet_sdk_version: Option<String>,
    pub visual_studio_path: Option<String>,
    pub msvc_version: Option<String>,
    pub cl_path: Option<String>,
    pub msbuild_path: Option<String>,
    pub windows_sdk_version: Option<String>,
    pub signtool_path: Option<String>,
    pub wfp_header_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinDivertProbe {
    pub dll_path: Option<PathBuf>,
    pub driver_path: Option<PathBuf>,
}

impl WinDivertProbe {
    pub fn files_present(&self) -> bool {
        self.dll_path.is_some() && self.driver_path.is_some()
    }

    pub fn usable_on_this_host(&self) -> bool {
        cfg!(windows) && self.files_present()
    }
}

impl BuildToolProbe {
    pub fn native_windows_toolchain_ready(&self) -> Option<bool> {
        if !self.probe_available {
            return None;
        }

        Some(
            self.rustc_version.is_some()
                && self.cargo_version.is_some()
                && self.visual_studio_path.is_some()
                && self.msvc_version.is_some()
                && self.cl_path.is_some()
                && self.msbuild_path.is_some()
                && self.windows_sdk_version.is_some(),
        )
    }

    pub fn wfp_driver_sdk_ready(&self) -> Option<bool> {
        if !self.probe_available {
            return None;
        }

        Some(
            self.cl_path.is_some()
                && self.msbuild_path.is_some()
                && self.windows_sdk_version.is_some()
                && self.signtool_path.is_some()
                && self.wfp_header_path.is_some(),
        )
    }
}

impl HostProbe {
    pub fn mobile_hotspot_likely_supported(&self) -> Option<bool> {
        match (
            self.station_supported,
            self.wifi_direct_go_supported,
            self.wifi_direct_virtual_adapters > 0,
        ) {
            (Some(true), Some(true), true) => Some(true),
            (Some(false), _, _) | (_, Some(false), _) => Some(false),
            _ => None,
        }
    }
}

pub fn run_windivert_probe() -> WinDivertProbe {
    let mut candidate_dirs = Vec::new();

    if let Some(dir) = std::env::var_os("HPROXY_WINDIVERT_DIR") {
        candidate_dirs.push(PathBuf::from(dir));
    }

    if let Ok(current_dir) = std::env::current_dir() {
        candidate_dirs.push(current_dir.join("third_party/windivert/win-x64"));
    }

    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        candidate_dirs.push(exe_dir.to_path_buf());
        candidate_dirs.push(exe_dir.join("windivert/win-x64"));
    }

    if let Some(system_root) = std::env::var_os("SystemRoot") {
        let system_root = PathBuf::from(system_root);
        candidate_dirs.push(system_root.join("System32"));
        candidate_dirs.push(system_root.join("System32/drivers"));
    }

    let dll_path = candidate_dirs
        .iter()
        .map(|dir| dir.join("WinDivert.dll"))
        .find(|path| path.is_file());
    let driver_path = candidate_dirs
        .iter()
        .map(|dir| dir.join("WinDivert64.sys"))
        .find(|path| path.is_file());

    WinDivertProbe {
        dll_path,
        driver_path,
    }
}

pub fn run_build_tool_probe() -> Result<BuildToolProbe> {
    if !powershell_available() {
        return Ok(BuildToolProbe {
            probe_available: false,
            rustc_version: None,
            cargo_version: None,
            dotnet_sdk_version: None,
            visual_studio_path: None,
            msvc_version: None,
            cl_path: None,
            msbuild_path: None,
            windows_sdk_version: None,
            signtool_path: None,
            wfp_header_path: None,
        });
    }

    let output = powershell(BUILD_TOOL_PROBE_SCRIPT).context("query Windows build toolchain")?;
    Ok(parse_build_tool_probe(&output))
}

pub fn run_host_probe() -> Result<HostProbe> {
    if !powershell_available() {
        return Ok(HostProbe {
            probe_available: false,
            wifi_driver: None,
            hosted_network_supported: None,
            station_supported: None,
            soft_ap_supported: None,
            wifi_direct_go_supported: None,
            p2p_max_mobile_ap_clients: None,
            wifi_direct_virtual_adapters: 0,
            mobile_hotspot_service_status: None,
        });
    }

    let drivers =
        powershell("netsh wlan show drivers").context("query Wi-Fi driver capabilities")?;
    let wireless_capabilities = powershell("netsh wlan show wirelesscapabilities")
        .context("query wireless device capabilities")?;
    let adapters = powershell(
        "Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -match 'Wi-Fi Direct|WiFi Direct|Wireless|WLAN|AX211' -or $_.Name -match 'Wi-Fi Direct|WiFi Direct|Wireless|WLAN' } | Format-List Name,InterfaceDescription,Status,ifIndex",
    )
    .context("query Wi-Fi adapter inventory")?;
    let hotspot_service =
        powershell("Get-Service icssvc | Format-List Name,DisplayName,Status,StartType")
            .context("query Windows Mobile Hotspot service")?;

    Ok(HostProbe {
        probe_available: true,
        wifi_driver: parse_string_field(&drivers, "Driver"),
        hosted_network_supported: parse_bool_field(&drivers, "Hosted network supported"),
        station_supported: parse_bool_field(&wireless_capabilities, "Station"),
        soft_ap_supported: parse_bool_field(&wireless_capabilities, "Soft AP"),
        wifi_direct_go_supported: parse_bool_field(&wireless_capabilities, "Wi-Fi Direct GO"),
        p2p_max_mobile_ap_clients: parse_u16_field(
            &wireless_capabilities,
            "P2P Max Mobile AP Clients",
        ),
        wifi_direct_virtual_adapters: adapters
            .matches("Microsoft Wi-Fi Direct Virtual Adapter")
            .count(),
        mobile_hotspot_service_status: parse_string_field(&hotspot_service, "Status"),
    })
}

fn parse_build_tool_probe(text: &str) -> BuildToolProbe {
    BuildToolProbe {
        probe_available: true,
        rustc_version: parse_non_empty_field(text, "rustc"),
        cargo_version: parse_non_empty_field(text, "cargo"),
        dotnet_sdk_version: parse_non_empty_field(text, "dotnet sdk"),
        visual_studio_path: parse_non_empty_field(text, "visual studio"),
        msvc_version: parse_non_empty_field(text, "msvc"),
        cl_path: parse_non_empty_field(text, "cl path"),
        msbuild_path: parse_non_empty_field(text, "msbuild path"),
        windows_sdk_version: parse_non_empty_field(text, "windows sdk"),
        signtool_path: parse_non_empty_field(text, "signtool path"),
        wfp_header_path: parse_non_empty_field(text, "wfp header"),
    }
}

fn parse_non_empty_field(text: &str, field: &str) -> Option<String> {
    parse_string_field(text, field).filter(|value| !value.is_empty())
}

fn parse_string_field(text: &str, field: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == field).then(|| value.trim().to_string())
    })
}

fn parse_bool_field(text: &str, field: &str) -> Option<bool> {
    let value = parse_string_field(text, field)?;
    let normalized = value.to_ascii_lowercase();
    if normalized.starts_with("yes") || normalized == "supported" {
        Some(true)
    } else if normalized.starts_with("no") || normalized == "not supported" {
        Some(false)
    } else {
        None
    }
}

fn parse_u16_field(text: &str, field: &str) -> Option<u16> {
    parse_string_field(text, field)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_wifi_capability_fields() {
        let text = r#"
    Station                                     : Supported
    Soft AP                                     : Not supported
    Wi-Fi Direct GO                             : Supported
    P2P Max Mobile AP Clients                   : 8
"#;

        assert_eq!(parse_bool_field(text, "Station"), Some(true));
        assert_eq!(parse_bool_field(text, "Soft AP"), Some(false));
        assert_eq!(parse_bool_field(text, "Wi-Fi Direct GO"), Some(true));
        assert_eq!(parse_u16_field(text, "P2P Max Mobile AP Clients"), Some(8));
    }

    #[test]
    fn parses_hosted_network_field() {
        let text = "    Hosted network supported  : No\n";
        assert_eq!(
            parse_bool_field(text, "Hosted network supported"),
            Some(false)
        );
    }

    #[test]
    fn parses_build_tool_probe_fields() {
        let text = r#"
rustc: rustc 1.95.0
cargo: cargo 1.95.0
dotnet sdk: 9.0.314
visual studio: C:\Program Files\Microsoft Visual Studio\2022\Community
msvc: 14.44.35207
cl path: C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe
msbuild path: C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe
windows sdk: 10.0.26100.0
signtool path: C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe
wfp header: C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\fwpmu.h
"#;

        let probe = parse_build_tool_probe(text);
        assert_eq!(probe.rustc_version.as_deref(), Some("rustc 1.95.0"));
        assert_eq!(probe.dotnet_sdk_version.as_deref(), Some("9.0.314"));
        assert_eq!(probe.msvc_version.as_deref(), Some("14.44.35207"));
        assert_eq!(probe.windows_sdk_version.as_deref(), Some("10.0.26100.0"));
        assert_eq!(probe.native_windows_toolchain_ready(), Some(true));
        assert_eq!(probe.wfp_driver_sdk_ready(), Some(true));
    }

    #[test]
    fn treats_empty_build_tool_fields_as_missing() {
        let text = r#"
rustc:
cargo: cargo 1.95.0
visual studio:
msvc:
cl path:
msbuild path:
windows sdk:
signtool path:
wfp header:
"#;

        let probe = parse_build_tool_probe(text);
        assert_eq!(probe.rustc_version, None);
        assert_eq!(probe.cargo_version.as_deref(), Some("cargo 1.95.0"));
        assert_eq!(probe.native_windows_toolchain_ready(), Some(false));
        assert_eq!(probe.wfp_driver_sdk_ready(), Some(false));
    }

    #[test]
    fn windivert_usability_requires_both_files() {
        let missing_driver = WinDivertProbe {
            dll_path: Some(PathBuf::from("WinDivert.dll")),
            driver_path: None,
        };
        assert!(!missing_driver.files_present());
        assert!(!missing_driver.usable_on_this_host());

        let complete = WinDivertProbe {
            dll_path: Some(PathBuf::from("WinDivert.dll")),
            driver_path: Some(PathBuf::from("WinDivert64.sys")),
        };
        assert!(complete.files_present());
        assert_eq!(complete.usable_on_this_host(), cfg!(windows));
    }
}
