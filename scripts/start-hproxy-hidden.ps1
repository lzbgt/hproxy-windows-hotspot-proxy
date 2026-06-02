param(
    [string]$Outbound = "socks5://192.168.0.104:8120",
    [string]$DnsUpstream = "223.5.5.5:53",
    [string]$Exe = "",
    [string]$LogFile = "",
    [switch]$FiveGhz,
    [switch]$SkipProxyProbe
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Exe) {
    $Exe = Join-Path $repoRoot "target\live-run-virtual\debug\hproxy.exe"
}

if (-not (Test-Path $Exe)) {
    throw "hproxy.exe not found at $Exe. Build it first with: cargo build --target-dir target\live-run-virtual"
}

$band = if ($FiveGhz) { "five-ghz" } else { "two-ghz" }
$arguments = @(
    "up",
    "--band", $band,
    "--outbound", $Outbound,
    "--proxy-probe-target", "1.1.1.1:443",
    "--dns-upstream", $DnsUpstream,
    "--dns-mode", "gateway"
)

if ($SkipProxyProbe) {
    $arguments += "--skip-proxy-probe"
}

if ($LogFile) {
    $arguments += @("--log-file", $LogFile)
}

$process = Start-Process `
    -FilePath $Exe `
    -ArgumentList $arguments `
    -WorkingDirectory $repoRoot `
    -WindowStyle Hidden `
    -PassThru

$pidFile = Join-Path $repoRoot "target\hproxy-gateway.pid"
Set-Content -Path $pidFile -Value $process.Id
Write-Output "hproxy started hidden as PID $($process.Id)"
Write-Output "SSID: VirtualProxyAP"
Write-Output "Password: 11102017"
Write-Output "PID file: $pidFile"
