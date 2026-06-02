# Testing Plan

## Unit Tests

Run on the Windows host:

```cmd
cd /d C:\work\windows-wifi-hotspot-with-proxy
cargo test
```

From the current WSL editing session, invoke the Windows host toolchain with:

```bash
cmd.exe /c "cd /d C:\work\windows-wifi-hotspot-with-proxy && cargo test"
```

WSL `cargo test` is useful as a quick edit-time smoke check, but it is not a release gate. Windows host testing is the canonical path because hotspot control and WinDivert are Windows-only.

Current covered areas:

```text
proxy URI parsing
hotspot config validation
flow table capacity behavior
redirector TCP/DNS/UDP policy classification
host capability output parsing
Windows native toolchain output parsing
hotspot private-interface discovery output parsing
hotspot native WinRT status/access-point query
hotspot native WinRT configure/start/stop compile coverage
hotspot band mapping for WinRT start/configure
DNS upstream socket selection
DNS gateway response mode
HTTP Host and TLS SNI gateway parsing
HTTP gateway header-boundary parsing
WinDivert IPv4 TCP destination rewrite
WinDivert DNS response source rewrite
WinDivert UDP drop behavior
live hotspot SSID reporting
```

Current verification status:

```text
Windows cargo test: 37 passed
```

## Doctor Command

Use this before a real `up` attempt:

```powershell
hproxy doctor --outbound socks5://<windows-wifi-ip>:8120
```

or:

```powershell
hproxy doctor --outbound https-proxy://<windows-wifi-ip>:8120
```

To verify that the configured proxy protocol can actually open a TCP tunnel, add a target:

```powershell
hproxy doctor `
  --outbound socks5://<windows-wifi-ip>:8120 `
  --proxy-probe-target 1.1.1.1:443
```

For HTTPS proxy mode:

```powershell
hproxy doctor `
  --outbound https-proxy://<windows-wifi-ip>:8120 `
  --proxy-probe-target 1.1.1.1:443
```

For a local HTTPS proxy with a self-signed or IP-mismatched certificate:

```powershell
hproxy doctor --outbound https-proxy://<windows-wifi-ip>:8120 --proxy-tls-insecure
```

The probe timeout defaults to 5000 ms and can be changed:

```powershell
--proxy-probe-timeout-ms 10000
```

To verify that WinDivert can actually open packet handles in the current Windows process before a real `up` attempt:

```powershell
hproxy doctor `
  --outbound socks5://<windows-wifi-ip>:8120 `
  --windivert-open-probe
```

This checks driver/admin readiness without starting Mobile Hotspot. `hproxy up` runs the same WinDivert preflight after binding local listeners and before mutating hotspot state.

For `up`, proxy modes probe `1.1.1.1:443` through the configured SOCKS5/HTTP(S) CONNECT proxy before starting Mobile Hotspot. Change the probe target or timeout with:

```powershell
--proxy-probe-target 1.1.1.1:443
--proxy-probe-timeout-ms 5000
```

Use `--skip-proxy-probe` only when the configured upstream proxy intentionally blocks the probe target.

The current doctor command validates config shape, reports whether the binary is running on Windows, and probes the Windows host Wi-Fi capability through `powershell.exe` when available. This works from Arch WSL because `powershell.exe` can query the Windows host.

Current host probe coverage:

```text
Wi-Fi adapter exists
station mode support
legacy hostednetwork support
classic Soft AP support
Wi-Fi Direct GO support
Microsoft Wi-Fi Direct Virtual Adapter presence
P2P mobile AP client limit
Windows Mobile Hotspot service status
Windows Rust/Cargo availability
.NET SDK availability
Visual Studio/MSVC/MSBuild availability
Windows SDK, signtool, and WFP header availability
local WinDivert DLL/driver availability
```

Current readiness result:

```text
windows native toolchain ready: yes
wfp driver sdk ready: yes
WinDivert files present: yes
WinDivert usable on this host: yes
WinDivert open probe: ok
outbound proxy probe to 1.1.1.1:443: ok
```

Live Mobile Hotspot probe result on the current Windows host:

```text
hotspot live probe status: Running
hotspot live probe SSID: VirtualProxyAP
hotspot live probe private interface index: 23
hotspot live probe gateway: 192.168.137.1
hotspot live probe subnet: 192.168.137.0/24
```

Live iPhone datapath result:

```text
iPhone client observed: 192.168.137.252
DNS packets captured: yes
DNS redirect to local 1053: yes
DNS responses from local 1053: yes
TCP packets redirected to local relay: no
TCP relay accepts on local 16000: no
```

This means the current WinDivert transparent TCP rewrite path is not a working proxy path for Mobile Hotspot clients. The SOCKS5/HTTPS proxy connector preflight works, but web TCP from the phone does not reach the transparent connector because the local relay is never accepted.

Gateway mode is the current working client proxy path. It makes DNS A records resolve to the hotspot gateway, accepts client TCP on local ports 80/443, extracts HTTP Host or TLS SNI, then opens the configured SOCKS5/HTTPS upstream proxy.

Still pending for the Windows implementation:

```text
upstream STA connection profile selection
wiFiControl capability/package requirement check
target private hotspot adapter selection when specified
live restart-window validation of native WinRT configure/start/stop
working WinDivert TCP interception for joined Wi-Fi clients, only if gateway mode cannot cover required clients
```

## Integration Test Goal

The first real integration test should prove:

```text
1. hproxy starts Windows Mobile Hotspot.
2. A dumb Wi-Fi client joins with only SSID/password.
3. Client receives DHCP IP from Windows hotspot.
4. Client DNS to hardcoded 8.8.8.8 is intercepted.
5. Client TCP HTTPS traffic is transparently redirected.
6. hproxy opens SOCKS5 or HTTPS proxy CONNECT to <windows-wifi-ip>:8120.
7. Client traffic succeeds without configuring proxy settings on the client.
8. hproxy down/recover restores normal host networking.
```

## Manual Test Commands

After `doctor` reports host, proxy, and WinDivert readiness:

```powershell
hproxy doctor --outbound socks5://<windows-wifi-ip>:8120

hproxy up `
  --band two-ghz `
  --outbound socks5://<windows-wifi-ip>:8120 `
  --dns-upstream 1.1.1.1:53 `
  --dns-timeout-ms 5000

hproxy status

hproxy down
```

The default band is 2.4 GHz even when `--band` is omitted. That is the right default for most MCU devices. Use 5 GHz only for clients known to support it:

```powershell
--band five-ghz
```

Important: do not start the hotspot directly through PowerShell for proxy testing. Direct PowerShell proves Windows SoftAP support only. Proxying requires the full `hproxy up` process to stay running because that process owns the WinDivert packet handles, the flow table, the DNS proxy, and the transparent TCP proxy.

The phone should still show its Wi-Fi proxy setting as disabled or off. That is expected. `hproxy` is not configuring a client-side HTTP proxy; it transparently redirects hotspot-client TCP/DNS packets on the Windows host and then opens SOCKS5 or HTTPS CONNECT upstream from Windows.

By default `hproxy` emits no debug log. For a visible foreground test, start with `--log-stderr`. For a hidden process with diagnostics, use `--log-file target\hproxy-gateway.log`.

With `--log-stderr` or `--log-file`, the first captured packets include diagnostics such as:

```text
hproxy datapath forward: Tcp 192.168.137.x:port -> public.ip:443 => redirect tcp to 192.168.137.1:16000
hproxy tcp relay: accepted tcp/192.168.137.x:port; connecting upstream public.ip:443
```

If there are no `hproxy datapath forward` lines while the phone is browsing, WinDivert is not seeing the client traffic. If packets show `bypass NotHotspotClient`, the source address is not in the discovered hotspot subnet. If relay lines say `missing flow`, packets reached the local proxy without a matching redirect record.

Current working gateway-mode command:

```powershell
hproxy up `
  --band two-ghz `
  --outbound socks5://192.168.0.104:8120 `
  --proxy-probe-target 1.1.1.1:443 `
  --dns-upstream 223.5.5.5:53 `
  --dns-mode gateway
```

Expected startup lines:

```text
DNS gateway mode: A records answer 192.168.137.1
gateway HTTP proxy port: 80
gateway HTTPS proxy port: 443
```

Expected traffic lines while the phone or MCU browses:

```text
hproxy tcp relay: gateway http; connecting upstream example.com:80
hproxy tcp relay: gateway tls; connecting upstream example.com:443
```

The phone should still show its Wi-Fi proxy setting as disabled or off. That is expected. The proof that proxying is active is the `gateway http` or `gateway tls` relay lines and a successful outbound proxy probe.

For HTTPS proxy mode:

```powershell
hproxy up `
  --band two-ghz `
  --outbound https-proxy://<windows-wifi-ip>:8120 `
  --dns-upstream 1.1.1.1:53 `
  --dns-mode gateway
```

For local/self-signed HTTPS proxy testing:

```powershell
hproxy up `
  --band two-ghz `
  --outbound https-proxy://<windows-wifi-ip>:8120 `
  --proxy-tls-insecure `
  --dns-upstream 1.1.1.1:53 `
  --dns-mode gateway
```

The DNS proxy forwards UDP DNS packets to the configured upstream and returns raw responses. The WinDivert network-layer worker rewrites those responses so clients see replies as coming from their originally requested DNS server.

If `doctor` reports missing WinDivert files, install the local runtime dependency before any `up` test:

```powershell
.\scripts\install-windivert.ps1
```

## Must-Pass Cases

```text
No admin rights:
    fail WinDivert preflight before mutating hotspot state

Proxy unreachable:
    fail outbound proxy preflight before mutating hotspot state

Hotspot startup failure:
    rollback to previous state

Redirector failure:
    disable capture first, then stop listeners/hotspot

Startup local listener bind failure:
    fail before hotspot mutation

DNS proxy failure:
    stop or block client traffic clearly

Stop/recover:
    disable redirector before stopping proxy listeners
```
