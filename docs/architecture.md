# HProxy Architecture

`hproxy` is a single monolithic Rust app for Windows 11. It has multiple internal modules, but only one binary for users to run.

The product goal is a transparent proxy gateway for Wi-Fi clients that cannot be configured with proxy settings:

```text
MCU/vendor device
  normal Wi-Fi, DHCP, no proxy config
      |
Windows Mobile Hotspot
      |
hproxy packet redirector
      |
local transparent TCP/DNS proxy
      |
SOCKS5 or HTTP(S) CONNECT upstream proxy
      |
Windows upstream Wi-Fi internet
```

## Design Choice

The app is intentionally not split into multiple services or packages. It is one command:

```powershell
hproxy up ...
hproxy down
hproxy status
hproxy recover
hproxy doctor
```

Internally, modules stay separated so the code remains maintainable:

```text
src/main.rs       CLI entrypoint
src/app.rs        app orchestration and startup/recovery order
src/config.rs     config parsing and validation
src/doctor.rs     host capability probe for doctor command
src/flow.rs       original-destination flow table
src/hostcmd.rs    PowerShell command helper for WinRT and fallback probes
src/proxy.rs      transparent TCP relay and upstream connectors
src/dns.rs        DNS interception listener and UDP forwarder
src/hotspot.rs    Windows Mobile Hotspot adapter boundary
src/redirector.rs WinDivert adapter boundary
third_party/windivert/win-x64 local WinDivert runtime files
```

This keeps usage simple while preserving SOLID-style boundaries inside the code.

## How STA + SoftAP Works

`hproxy` does not directly switch the Wi-Fi adapter into SoftAP mode with low-level driver commands. It asks Windows Mobile Hotspot/tethering to create the hotspot.

The Windows API model is:

```text
NetworkOperatorTetheringManager
    public interface  = upstream connection profile, for example current Wi-Fi STA
    private interface = Wi-Fi tethering/mobile hotspot created by Windows
```

If the Wi-Fi adapter and driver support concurrent STA + hotspot mode, Windows keeps the upstream Wi-Fi connection alive and creates the private hotspot network for clients. If the adapter cannot do that, `hproxy` cannot force it; startup must fail clearly during `doctor` or `up`.

The detailed control-plane notes are in:

```text
docs/hotspot-control.md
```

## SOLID Boundaries

`app.rs` coordinates startup and shutdown. It should not parse packets, implement SOCKS5, resolve DNS, or call Windows APIs directly.

Startup is transaction-style:

```text
1. Validate config.
2. Build outbound connector.
3. Probe the configured upstream proxy before mutating Windows hotspot state.
4. Bind local transparent TCP and DNS listeners before mutating Windows hotspot state.
5. Preflight WinDivert handle opening before mutating Windows hotspot state.
6. Start Windows hotspot.
7. Discover hotspot interface/subnet.
8. Spawn local listener tasks.
9. Start redirector.
10. On any failure after mutation, abort listeners, stop redirector if started, then stop hotspot if started.
```

This order catches upstream proxy failures before clients are affected, prevents redirecting clients into dead local ports, catches WinDivert/admin failures before hotspot startup, and avoids leaving a hotspot running after partial startup failure.

`config.rs` owns config parsing and validation only.

`doctor.rs` owns host capability probing only. It can run from WSL by calling `powershell.exe`, but it does not mutate Windows network state. It reports both hotspot capability and Windows native build-tool readiness so future WinDivert or WFP work starts from verified host prerequisites.

`flow.rs` owns the mapping from redirected client connections to their original destinations.

`hostcmd.rs` owns shelling out to `powershell.exe` for host probes and adapter discovery that can run from either WSL or a Windows binary.

`proxy.rs` owns outbound TCP connection strategies:

```text
DirectConnector
Socks5Connector
HttpConnectConnector
HttpsConnectConnector
```

`dns.rs` owns local DNS interception. The current implementation forwards UDP DNS queries to a configured upstream resolver and returns the raw response to the client.

`hotspot.rs` owns the Windows hotspot boundary. Status, access-point SSID, configure, start, and stop use native typed WinRT APIs first. PowerShell remains as fallback for WinRT failures and diagnostics. Hotspot private-interface discovery tries native Windows IP Helper `GetAdaptersAddresses` first, then falls back to PowerShell if native discovery fails. Live probing on this host confirms Windows Mobile Hotspot can advertise `VirtualProxyAP` over Wi-Fi Direct with gateway `192.168.137.1/24`. The default band is 2.4 GHz because many MCU and embedded Wi-Fi clients cannot see or reliably join 5 GHz hotspot networks.

`redirector.rs` owns the redirector decision model and the WinDivert packet capture/rewrite boundary. The Windows packet loop now captures hotspot-client IPv4 traffic at `NETWORK inbound`, scoped to the discovered hotspot subnet, and rewrites DNS to the local DNS proxy. Live iPhone validation has confirmed DNS interception and DNS response forwarding.

The current client proxy design is DNS/SNI gateway mode:

```text
client DNS A query -> hproxy DNS gateway answer: 192.168.137.1
client TCP :80/:443 -> hotspot gateway local listener
hproxy extracts HTTP Host or TLS SNI
hproxy opens SOCKS5 / HTTP CONNECT / HTTPS CONNECT upstream to that host
hproxy relays bytes without TLS MITM
```

No TLS interception is required or desired. HProxy uses the clear routing metadata already present in normal HTTP/TLS handshakes, then tunnels bytes through the configured upstream proxy.

The original WinDivert transparent TCP rewrite path remains a foundation for direct-IP/no-SNI routing, but it is not the primary live path for Windows Mobile Hotspot NAT. Gateway DNS/SNI mode is the current product path for dumb Wi-Fi clients.

The concrete Windows datapath dependency is vendored from NuGet package `Native.WinDivert`:

```text
third_party/windivert/win-x64/WinDivert.dll
third_party/windivert/win-x64/WinDivert64.sys
```

`hproxy doctor` checks these files. If they are missing, run:

```powershell
.\scripts\install-windivert.ps1
```

## Data Plane

The intended transparent TCP path:

```text
1. Client sends TCP SYN:
   client_ip:client_port -> real_server_ip:real_server_port

2. WinDivert captures hotspot-client traffic at the inbound network layer before Windows Mobile Hotspot NAT.

3. Redirector stores:
   protocol + client_ip + client_port -> original destination

4. Redirector rewrites destination to:
   hotspot_gateway_ip:transparent_tcp_port

5. Transparent TCP proxy accepts the connection.

6. Proxy looks up the original destination in FlowTable.

7. Proxy opens upstream tunnel:
   SOCKS5 CONNECT or HTTP CONNECT or HTTPS proxy CONNECT

8. Proxy relays bytes without TLS MITM.
```

Current live state: this TCP path is designed and partly implemented, but gateway DNS/SNI is the working product path for Windows Mobile Hotspot clients. Keep the lower-layer TCP path scoped to the traffic classes that gateway mode cannot infer from Host/SNI metadata:

```text
primary current path: DNS/SNI gateway mode that returns the hotspot gateway from DNS and routes accepted 80/443 TCP by Host/SNI
future extension: WinDivert or WFP original-destination capture for direct-IP/no-SNI flows
```

DNS must also be intercepted because dumb clients may use hardcoded DNS servers such as `8.8.8.8`.

Current DNS behavior in normal forwarding mode:

```text
client DNS packet -> WinDivert redirect to local DNS proxy port
local DNS proxy -> configured upstream resolver
DNS response -> WinDivert source rewrite to original resolver IP:port -> client
```

Current DNS behavior in gateway mode:

```text
client A query -> synthetic A response for hotspot gateway
client non-A query -> empty successful response
```

This keeps MCU/client traffic on the local gateway path and avoids accidental IPv6 or HTTPS/SVCB bypasses. It also preserves end-to-end TLS because the gateway only reads SNI and relays encrypted bytes.

The default upstream is:

```text
1.1.1.1:53
```

This can be changed with:

```powershell
--dns-upstream 8.8.8.8:53
--dns-timeout-ms 5000
```

UDP policy should stay conservative:

```text
UDP/53 DNS: intercept
UDP/123 NTP: allow direct or SOCKS5 UDP when implemented
UDP/443 QUIC: drop by default
other UDP: drop by default
```

Current redirector classifier behavior:

```text
outside hotspot subnet:
    bypass

gateway, broadcast, multicast:
    bypass

upstream proxy IP:
    bypass to avoid proxy loops

private LAN destination:
    bypass when policy enables private LAN bypass

TCP from hotspot clients:
    redirect to transparent TCP proxy by default

DNS UDP/TCP port 53 from hotspot clients:
    redirect to local DNS proxy by default

UDP/443:
    drop by default to block QUIC and encourage TCP/TLS fallback

UDP/123:
    bypass direct under the default UDP policy

other UDP:
    drop by default
```

## Current Implementation State

Implemented:

```text
single Rust binary package
CLI command shape
config parsing and validation
SOCKS5 TCP CONNECT connector
HTTP CONNECT connector
HTTPS proxy CONNECT connector over TLS
direct TCP connector
transparent TCP proxy accept/relay loop
gateway TCP proxy for HTTP Host and TLS SNI routing
buffered HTTP Host capture for gateway proxy
bounded flow table
DNS UDP forwarding proxy
DNS gateway response mode
inline DNS gateway responses without per-query task spawn
Windows hotspot adapter boundary
Windows Mobile Hotspot WinRT status/access-point query through native Rust Windows APIs
Windows Mobile Hotspot WinRT configure/start/stop through native Rust Windows APIs
PowerShell fallback for Windows Mobile Hotspot WinRT configure/start/stop
Wi-Fi Direct private hotspot interface discovery through native Windows IP Helper API
PowerShell fallback for Wi-Fi Direct private hotspot interface discovery
vendored WinDivert runtime dependency from NuGet Native.WinDivert
WinDivert redirector adapter boundary
WinDivert IPv4 packet capture/rewrite/reinject loop for TCP and DNS
redirector classification policy for TCP/DNS/UDP/bypass/drop
DNS response source rewrite through WinDivert
unit tests for config and flow table
doctor host capability probe through powershell.exe/netsh
doctor Windows Rust/.NET/MSVC/SDK/WFP readiness probe
doctor WinDivert open-handle probe
doctor outbound proxy CONNECT probe
transaction-style startup rollback
```

Pending:

```text
remove or downgrade PowerShell interface-discovery fallback once native discovery has enough live coverage
live restart-window validation of native WinRT configure/start/stop
gateway performance validation under joined-client load
privilege/capability hardening for Windows Mobile Hotspot start/stop
live Windows hotspot/client validation of gateway mode across MCU devices
IPv6 packet redirection
full TCP return-path NAT for non-local proxy modes if needed
DNS-over-proxy or DoH/DoT resolver policy
state persistence for status/recover
integration test on Windows host
packaging/manifest support for Windows wiFiControl capability
```
