# Environment Notes

These notes capture the development and test environment for session continuity.

## Host

The project is being developed from Arch Linux WSL on Windows 11:

```text
workspace: /mnt/c/work/windows-wifi-hotspot-with-proxy
WSL kernel: 6.6.114.1-microsoft-standard-WSL2
WSL shell: zsh
timezone in session: Asia/Shanghai
```

Rust is available in WSL:

```text
rustc 1.95.0
cargo 1.95.0
```

Rust is also available on the Windows host:

```text
rustc 1.95.0
cargo 1.95.0
rustc path: C:\Users\lzbgt\.cargo\bin\rustc.exe
cargo path: C:\Users\lzbgt\.cargo\bin\cargo.exe
```

Go is also available:

```text
go1.26.3
```

.NET is not available as `dotnet` inside WSL, but Windows has `dotnet.exe`:

```text
.NET SDK 9.0.314
Windows runtime OS version: 10.0.26200
```

The project has been switched to Rust, so .NET is not required for the current implementation.

Visual Studio native tooling is installed and detected by `hproxy doctor`:

```text
Visual Studio: C:\Program Files\Microsoft Visual Studio\2022\Community
MSVC: 14.44.35207
cl.exe: Microsoft C/C++ Optimizing Compiler 19.44.35227 for x64
MSBuild: C:\Program Files\Microsoft Visual Studio\2022\Community\Msbuild\Current\Bin\amd64\MSBuild.exe
```

Windows SDK / driver-adjacent tooling:

```text
Windows SDK: 10.0.26100.0
signtool.exe: C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe
WFP header: C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\fwpmu.h
```

WinDivert runtime files are vendored locally for the transparent packet datapath:

```text
third_party/windivert/win-x64/WinDivert.dll
third_party/windivert/win-x64/WinDivert64.sys
source package: Native.WinDivert 2.2.2 from NuGet
```

Refresh them with:

```powershell
.\scripts\install-windivert.ps1
```

Current readiness summary from `hproxy doctor`:

```text
windows native toolchain ready: yes
wfp driver sdk ready: yes
WinDivert files present: yes
WinDivert usable on this host: yes
WinDivert open probe: ok
```

To enter the native x64 build environment:

```powershell
cmd /c "`"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat`" -arch=x64 -host_arch=x64 && where cl && where msbuild"
```

## Windows Requirement

The final runnable hotspot gateway must be a Windows binary. WSL/Linux can build and test platform-neutral code, but it cannot:

```text
start Windows Mobile Hotspot
use WinRT NetworkOperatorTetheringManager directly
load/use WinDivert as the Windows packet datapath
validate packet interception against the real Windows hotspot interface
```

Use WSL for:

```text
code editing
documentation
optional quick smoke tests while editing
```

Use Windows for:

```text
canonical cargo test verification
administrator/elevated execution
Windows-target Rust build/test
hotspot control testing
WinDivert driver testing
future C++/WFP/driver SDK experiments
real MCU/client integration tests
verifying wiFiControl capability/package manifest behavior
```

Current Windows command policy for this repo:

```text
run git through cmd.exe /c git
run cargo/rust through cmd.exe /c cargo
```

## Hotspot Control Constraint

Windows Mobile Hotspot control is not a normal cross-platform network operation. `hproxy` must call Windows tethering APIs from a Windows binary, and the final app needs the Windows `wiFiControl` device capability declared in its manifest.

The runtime model is:

```text
Windows Wi-Fi STA:
    upstream internet connection profile

Windows Mobile Hotspot:
    private Wi-Fi tethering network created by Windows

hproxy:
    controls the tethering session and transparent packet path
```

See:

```text
docs/hotspot-control.md
```

## Current Host Wi-Fi Capability Check

Observed from Windows host commands:

```text
netsh wlan show drivers
```

```text
Interface name: WLAN
Driver: Intel(R) Wi-Fi 6E AX211 160MHz
Driver version: 24.30.1.1
Hosted network supported: No
Wireless Display Supported: Yes (Graphics Driver: Yes, Wi-Fi Driver: Yes)
```

```text
netsh wlan show wirelesscapabilities
```

```text
Station: Supported
Soft AP: Not supported
Wi-Fi Direct Device: Supported
Wi-Fi Direct GO: Supported
Wi-Fi Direct Client: Supported
P2P GO ports count: 1
P2P Clients Port Count: 1
P2P Max Mobile AP Clients: 8
```

Hidden adapter inventory also shows:

```text
Microsoft Wi-Fi Direct Virtual Adapter
Microsoft Wi-Fi Direct Virtual Adapter #2
Intel(R) Wi-Fi 6E AX211 160MHz
```

Interpretation:

```text
legacy netsh hostednetwork:
    not supported

classic Soft AP capability:
    not supported

modern Windows Mobile Hotspot path:
    likely supported through Wi-Fi Direct GO/tethering
```

Therefore `hproxy` should not use legacy hostednetwork APIs. It should use `NetworkOperatorTetheringManager` and fail clearly if Windows Mobile Hotspot runtime capability still rejects startup.

## Test Proxy Endpoint

For integration testing, the Windows host provides proxy access on its Wi-Fi IP at port `8120`.

Use one of these forms depending on what protocol the proxy server is actually serving:

```powershell
hproxy up --outbound socks5://<windows-wifi-ip>:8120
```

Before starting hotspot mode, verify the proxy protocol with:

```powershell
hproxy doctor --outbound socks5://<windows-wifi-ip>:8120 --proxy-probe-target 1.1.1.1:443
```

or:

```powershell
hproxy up --outbound https-proxy://<windows-wifi-ip>:8120
```

For HTTPS proxy mode:

```powershell
hproxy doctor --outbound https-proxy://<windows-wifi-ip>:8120 --proxy-probe-target 1.1.1.1:443
```

DNS defaults to `1.1.1.1:53`. For tests that need another resolver:

```powershell
hproxy up --outbound socks5://<windows-wifi-ip>:8120 --dns-upstream 8.8.8.8:53 --dns-mode gateway
```

The hotspot band defaults to 2.4 GHz for MCU compatibility. Use an explicit 5 GHz band only for clients known to support it:

```powershell
hproxy up --band five-ghz --outbound socks5://<windows-wifi-ip>:8120 --dns-mode gateway
```

If the local HTTPS proxy on `8120` uses a self-signed certificate or a certificate that does not match the Wi-Fi IP address, use one of these test-only forms:

```powershell
hproxy up --outbound https-proxy://<windows-wifi-ip>:8120 --proxy-tls-insecure
```

or:

```powershell
hproxy up --outbound "https-proxy://<windows-wifi-ip>:8120?tls_skip_verify=true"
```

Do not use insecure TLS verification for production proxy endpoints.

Important: SOCKS5 and HTTPS proxy are different protocols. They can share port `8120` only if the proxy server on Windows auto-detects both protocols. Otherwise test one mode at a time with the matching scheme.

## Current Build Command

From Windows through WSL:

```bash
cmd.exe /c "cd /d C:\work\windows-wifi-hotspot-with-proxy && cargo test"
```

Current Windows-side result:

```text
current Windows host tests pass
```

Windows-side doctor smoke test:

```bash
cmd.exe /c "cd /d C:\work\windows-wifi-hotspot-with-proxy && cargo run -- doctor --outbound socks5://127.0.0.1:8120"
```

Observed result:

```text
host OS: windows
windows hotspot control: true
WinDivert datapath: true
WinDivert files present: yes
WinDivert usable on this host: yes
WinDivert open probe: ok
windows native toolchain ready: yes
wfp driver sdk ready: yes
mobile hotspot path likely supported: yes
```

Live Windows/iPhone observation:

```text
SSID: VirtualProxyAP
hotspot gateway: 192.168.137.1/24
iPhone client observed: 192.168.137.252
DNS redirect observed: yes, client DNS to 192.168.137.1:53 redirected to local 1053
WinDivert transparent TCP relay observed: no
gateway-mode TCP relay observed: yes, gateway http/tls relay lines seen
current working upstream: socks5://192.168.0.104:8120
current working mode: --dns-mode gateway
```

Default hotspot credentials:

```text
SSID: VirtualProxyAP
password: 11102017
band: 2.4 GHz
```

`hproxy` emits no debug log unless logging is explicitly requested. For a hidden Windows experiment process:

```powershell
.\scripts\start-hproxy-hidden.ps1 -Outbound socks5://192.168.0.104:8120
```

To keep diagnostics without a popup console, pass a log file:

```powershell
.\scripts\start-hproxy-hidden.ps1 -Outbound socks5://192.168.0.104:8120 -LogFile target\hproxy-gateway.log
```

For foreground debugging:

```powershell
hproxy --log-stderr up --outbound socks5://192.168.0.104:8120 --dns-mode gateway
```

The current `doctor` output also reports:

```text
windows rustc: rustc 1.95.0 (59807616e 2026-04-14)
windows cargo: cargo 1.95.0 (f2d3ce0bd 2026-03-21)
windows dotnet sdk: 9.0.314
visual studio: C:\Program Files\Microsoft Visual Studio\2022\Community
msvc toolset: 14.44.35207
windows sdk: 10.0.26100.0
```

## Next Engineering TODOs

Concrete next tasks after the working gateway-mode proof:

```text
native WinRT status/access-point query is implemented and live-validated
native WinRT configure/start/stop is implemented; validate during a restart window before removing fallback
keep native IP Helper adapter/IP discovery as the primary path and PowerShell as fallback
validate gateway DNS/HTTP relay performance under joined-client load
add sustained Windows host throughput/latency checks with a joined Wi-Fi client
evaluate WFP redirect/callout only if gateway mode cannot cover required clients
```
