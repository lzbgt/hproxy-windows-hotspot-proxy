# Reference Notes

This file is historical reference material. The active design and environment notes are now in:

```text
docs/architecture.md
docs/environment.md
docs/testing.md
```

The active product design treats no-MITM TLS tunnelling as a feature. HProxy should route normal HTTPS by DNS plus TLS SNI and relay encrypted bytes. Lower-layer WinDivert/WFP work is only needed for traffic that does not expose routable metadata, such as direct-IP/no-SNI flows.

Correct — the core product should **not** rely on client-side proxy settings at all.

For MCU/vendor devices, the Windows software must be a **transparent proxy gateway**:

```text
Vendor MCU / device
    │ normal Wi-Fi, DHCP, no proxy config
    ▼
Windows Mobile Hotspot
    │ packet interception before normal internet forwarding
    ▼
Transparent redirector
    │ TCP/DNS/UDP policy
    ▼
Local proxy engine
    │ SOCKS5 / HTTP CONNECT / HTTPS proxy outbound
    ▼
Windows upstream Wi-Fi STA → Internet
```

The Windows hotspot control can still use `NetworkOperatorTetheringManager`; Microsoft’s API starts tethering, supports per-session hotspot config, and recommends stopping tethering before starting it again. It also requires the `wiFiControl` capability. ([Microsoft Learn][1]) For the transparent datapath, the realistic MVP is **WinDivert-based packet capture/modify/reinject**, because WinDivert supports packet capture, modification, dropping, reinjection, and has a `NETWORK_FORWARD` layer for packets passing through the machine. ([ReQrypt][2]) A production-grade version can use a signed WFP callout driver; Microsoft documents WFP callouts as capable of deep inspection, packet modification, stream modification, and logging, and Microsoft’s WFP sample already separates service, callout driver, and proxy service components. ([Microsoft Learn][3])

## Revised architecture

```text
+------------------------------------------------------------+
|                         UI / CLI                           |
|  Start hotspot proxy / stop / recover / status / logs      |
+-----------------------------+------------------------------+
                              |
                              v
+------------------------------------------------------------+
|              Elevated Windows Controller Service           |
|                                                            |
|  +---------------------+  +------------------------------+ |
|  | Hotspot Controller  |  | Upstream STA Monitor         | |
|  +---------------------+  +------------------------------+ |
|                                                            |
|  +---------------------+  +------------------------------+ |
|  | Interface Discovery |  | Policy / Config Manager      | |
|  +---------------------+  +------------------------------+ |
|                                                            |
|  +---------------------+  +------------------------------+ |
|  | Recovery Manager    |  | Firewall / Safety Manager    | |
|  +---------------------+  +------------------------------+ |
+-----------------------------+------------------------------+
                              |
                              v
+------------------------------------------------------------+
|                 Transparent Data Plane                     |
|                                                            |
|  +---------------------+  +------------------------------+ |
|  | Packet Redirector   |  | Flow Table                   | |
|  | WinDivert MVP       |  | client:port → original dst   | |
|  | WFP production      |  +------------------------------+ |
|  +---------------------+                                  |
|                                                            |
|  +---------------------+  +------------------------------+ |
|  | DNS Proxy           |  | Transparent TCP Proxy        | |
|  +---------------------+  +------------------------------+ |
|                                                            |
|  +--------------------------------------------------------+ |
|  | Outbound Connector                                     | |
|  | direct / SOCKS5 / HTTP CONNECT / HTTPS proxy CONNECT   | |
|  +--------------------------------------------------------+ |
+------------------------------------------------------------+
```

## Correct requirement model

The user configures only the Windows tool:

```json
{
  "hotspot": {
    "ssid": "VendorProxyAP",
    "password": "ChangeMe123",
    "band": "auto"
  },
  "upstream": {
    "type": "wifi_sta",
    "profile": "OfficeWiFi"
  },
  "outbound_proxy": {
    "type": "socks5",
    "server": "1.2.3.4",
    "port": 1080,
    "username": null,
    "password_secret_ref": null
  },
  "transparent_policy": {
    "tcp": "proxy",
    "dns": "proxy",
    "udp": "dns_ntp_direct_else_drop",
    "block_quic_udp_443": true,
    "bypass_private_lan": true
  }
}
```

Meaning:

```text
MCU/device side:
    only joins SSID/password

Windows side:
    starts hotspot
    captures traffic from hotspot subnet
    proxies traffic according to policy
```

Windows WinINET/WinHTTP proxy settings are **not the datapath**. They may be exposed as an optional host setting, but they do not solve proxying for hotspot clients. WinHTTP is independent from WinINet browser proxy settings. ([Microsoft Learn][4])

---

# Data plane design

## 1. Hotspot startup

Use `NetworkOperatorTetheringManager`.

Startup sequence:

```text
1. Acquire global service lock.
2. Snapshot current system state.
3. Verify upstream Wi-Fi STA is connected.
4. Verify upstream internet/proxy reachability.
5. Stop existing hotspot session if active.
6. Start hotspot with configured SSID/password/band.
7. Discover hotspot private interface:
   - interface index
   - gateway IP
   - subnet
   - DNS behavior
8. Start transparent data plane.
9. Mark state RUNNING.
```

Do **not** hardcode `192.168.137.1`. Windows often uses it, but the software should discover the real hotspot gateway/subnet after tethering starts.

---

## 2. Packet classification

The redirector must capture only hotspot-client traffic:

```text
capture if:
    packet source is inside hotspot client subnet
    OR packet arrives from hotspot private interface

bypass if:
    DHCP
    ARP / NDP
    local gateway traffic
    upstream proxy server IP itself
    multicast / broadcast
    mDNS / SSDP / local discovery
    private LAN destinations if policy says bypass
```

Conceptual rule:

```text
if src_ip in HOTSPOT_SUBNET
   and dst_ip not in BYPASS_SET
   and protocol in {TCP, UDP, DNS}:
       handle_by_transparent_policy()
else:
       reinject_original()
```

---

## 3. TCP transparent proxy algorithm

This is the key part.

Client thinks it is connecting to:

```text
client_ip:client_port → real_server_ip:real_server_port
```

The Windows redirector rewrites it internally to:

```text
client_ip:client_port → hotspot_gateway_ip:transparent_tcp_port
```

The local transparent proxy accepts the connection, looks up the original destination, then opens an outbound proxy tunnel.

### Flow table

```c
struct FlowKey {
    IpAddr client_ip;
    uint16_t client_port;
    uint8_t protocol; // TCP
};

struct FlowValue {
    IpAddr original_dst_ip;
    uint16_t original_dst_port;
    IpAddr rewritten_dst_ip;      // hotspot gateway
    uint16_t rewritten_dst_port;  // local transparent proxy port
    uint64_t created_at_ms;
    uint64_t last_seen_ms;
};
```

### TCP path

```text
1. Device sends SYN:
       192.168.137.20:51000 → 93.184.216.34:443

2. Redirector captures it.

3. Redirector stores:
       key   = 192.168.137.20:51000/TCP
       value = 93.184.216.34:443

4. Redirector rewrites destination:
       192.168.137.20:51000 → 192.168.137.1:16000

5. Local transparent proxy accepts connection.

6. Proxy asks FlowTable:
       peer 192.168.137.20:51000 originally wanted 93.184.216.34:443

7. Proxy opens outbound:
       SOCKS5 CONNECT 93.184.216.34:443
       or HTTP CONNECT 93.184.216.34:443
       or HTTPS-proxy CONNECT 93.184.216.34:443

8. Proxy relays raw bytes.

9. Redirector rewrites return packets:
       192.168.137.1:16000 → 192.168.137.20:51000

   into:

       93.184.216.34:443 → 192.168.137.20:51000
```

No TLS MITM is required. The proxy is just tunneling bytes.

That is important for vendor devices because certificate pinning usually still works.

---

## 4. DNS handling

You must intercept DNS. Many MCU/vendor devices use hardcoded DNS servers like `8.8.8.8`, and Windows hotspot DHCP may not give you enough control.

DNS policy:

```text
UDP/TCP dst port 53 from hotspot subnet
    → redirect to local DNS proxy
```

DNS proxy responsibilities:

```text
1. Receive DNS query from device.
2. Resolve using configured policy:
   - direct system resolver
   - DoH/DoT
   - remote DNS through SOCKS5/HTTP proxy if supported
3. Return response to client.
4. Store qname → answer IP mapping for logs/routing policy.
```

Example:

```text
Device query:
    192.168.137.20:40000 → 8.8.8.8:53

Internally redirected to:
    192.168.137.20:40000 → 192.168.137.1:1053

Returned to client as if from:
    8.8.8.8:53 → 192.168.137.20:40000
```

This avoids requiring any DNS setting on the MCU.

---

## 5. UDP handling

This is where the design must be honest.

TCP can be proxied through SOCKS5, HTTP CONNECT, or HTTPS proxy.

Generic UDP cannot be proxied through a normal HTTP/HTTPS proxy.

Recommended UDP policy:

```text
DNS UDP/53:
    intercept and handle locally

NTP UDP/123:
    allow direct or proxy if SOCKS5 UDP is supported

QUIC UDP/443:
    block by default, forcing most clients to retry TCP/TLS

mDNS/SSDP/broadcast:
    bypass local only

other UDP:
    drop by default, or SOCKS5 UDP ASSOCIATE if upstream supports it
```

Config:

```json
{
  "udp_policy": {
    "dns": "intercept",
    "ntp": "direct",
    "quic_udp_443": "drop",
    "generic_udp": "drop",
    "generic_udp_when_socks5_supports_udp": "proxy"
  }
}
```

For MCU/vendor IoT devices, this is usually acceptable if the protocols are HTTPS, MQTT/TCP, TCP socket, HTTP, or WebSocket. It may fail for devices that require UDP-only cloud protocols.

---

# Why WinDivert is the practical MVP

Use WinDivert first because it avoids writing your own kernel driver. It can capture, modify, drop, and reinject packets, and it supports forwarded packets through `WINDIVERT_LAYER_NETWORK_FORWARD`. ([ReQrypt][2])

Recommended handles:

```text
Handle A: NETWORK_FORWARD
    capture client → internet forwarded packets

Handle B: NETWORK
    capture local proxy → client packets for reverse source rewrite

Handle C: NETWORK_FORWARD or NETWORK
    capture DNS UDP/TCP 53 from hotspot clients
```

Implementation language:

```text
Controller service: C# / .NET
Redirector engine:  Rust or C++
Proxy engine:       Rust / Go / C++
UI:                 WPF / WinUI 3
```

C# can P/Invoke WinDivert, but the high-throughput packet loop is better in Rust or C++.

---

# Production option: WFP callout driver

For commercial/robust production, build a signed WFP callout driver.

WFP is the native Windows framework for packet filtering and modification. Microsoft’s docs explicitly mention packet modification, stream modification, deep inspection, and logging as callout-driver use cases. ([Microsoft Learn][3]) Microsoft’s WFP sample has the same rough shape you need: service, callout driver, and proxy service. ([Microsoft Learn][5])

However, WFP is much more expensive:

```text
Pros:
    robust
    native Windows networking architecture
    suitable for production security/networking product

Cons:
    kernel driver
    signing
    installer complexity
    harder debugging
    more crash risk
```

Recommended roadmap:

```text
V1: WinDivert transparent gateway
V2: hardened WinDivert + better diagnostics
V3: WFP signed driver if product needs enterprise reliability
```

---

# Why not generic TUN as the first design

A TUN-based proxy engine can transparently capture host traffic, but it is awkward for this exact product because you only want **hotspot-client traffic**, not all host traffic.

Some proxy engines’ interface routing controls are platform-limited; for example, sing-box documents `include_interface` as Linux-only. ([Sing Box][6]) That makes generic TUN less clean on Windows when the target is “only packets from the hotspot private interface.”

So:

```text
Good for full-host proxy:
    TUN

Good for hotspot-client-only proxy:
    WinDivert or WFP packet redirector
```

---

# Revised state machine

```text
STA_ONLY_IDLE
    |
    v
PRECHECK
    - admin/elevated service
    - Wi-Fi STA connected
    - upstream proxy reachable
    - capture driver available
    |
    v
SNAPSHOT_STATE
    - current hotspot state
    - STA profile
    - routes
    - firewall rules
    - previous transaction
    |
    v
START_HOTSPOT
    - stop existing tethering
    - configure SSID/passphrase
    - start tethering
    |
    v
DISCOVER_HOTSPOT_INTERFACE
    - private adapter index
    - gateway IP
    - subnet
    - client DHCP range if discoverable
    |
    v
START_PROXY_ENGINE
    - transparent TCP proxy
    - DNS proxy
    - outbound connector
    |
    v
INSTALL_CAPTURE_RULES
    - WinDivert/WFP filters
    - only hotspot subnet/interface
    |
    v
RUNNING_TRANSPARENT_GATEWAY
    |
    v
RECOVERING
    - remove capture first
    - stop proxy engine
    - stop hotspot
    - restore STA-only
    |
    v
STA_ONLY_IDLE
```

Important recovery order:

```text
1. Disable packet capture first.
2. Stop transparent proxy.
3. Stop DNS proxy.
4. Remove firewall rules.
5. Stop hotspot.
6. Restore previous hotspot config if changed.
7. Verify upstream STA still works.
```

Do not stop the proxy before disabling capture, otherwise packets may be redirected into a dead local port.

---

# CLI design

```powershell
hproxy status

hproxy up `
  --mode transparent `
  --ssid "VendorProxyAP" `
  --password "ChangeMe123" `
  --outbound socks5://1.2.3.4:1080 `
  --tcp proxy `
  --dns proxy `
  --udp dns-ntp-direct-else-drop `
  --block-quic true

hproxy up `
  --mode transparent `
  --ssid "VendorProxyAP" `
  --password "ChangeMe123" `
  --outbound https-proxy://proxy.example.com:443 `
  --tcp proxy `
  --dns proxy `
  --udp drop

hproxy down --recover-sta-only

hproxy recover
```

For `https_proxy`, define it precisely:

```text
https-proxy://proxy.example.com:443
```

Meaning:

```text
Windows transparent proxy opens TLS to proxy.example.com:443,
then sends HTTP CONNECT original_dst_ip:original_dst_port inside that TLS tunnel.
```

Do not confuse it with “proxy HTTPS traffic.” It is “the upstream proxy connection itself uses TLS.”

---

# Minimal implementation interfaces

## Controller → redirector

```json
{
  "command": "start",
  "hotspot_if_index": 23,
  "hotspot_gateway_ip": "192.168.137.1",
  "hotspot_subnet": "192.168.137.0/24",
  "transparent_tcp_port": 16000,
  "dns_proxy_port": 1053,
  "bypass": {
    "private_ipv4": true,
    "multicast": true,
    "broadcast": true,
    "upstream_proxy_ip": "1.2.3.4"
  }
}
```

## Redirector → proxy engine lookup

```json
{
  "client_ip": "192.168.137.20",
  "client_port": 51000,
  "protocol": "tcp"
}
```

Response:

```json
{
  "original_dst_ip": "93.184.216.34",
  "original_dst_port": 443
}
```

## Proxy engine outbound connector

```csharp
public interface IOutboundConnector
{
    Task<Stream> ConnectTcpAsync(
        IPAddress originalDstIp,
        int originalDstPort,
        string? domainHint,
        CancellationToken ct);
}
```

Implementations:

```text
DirectConnector
Socks5Connector
HttpConnectConnector
HttpsProxyConnectConnector
```

---

# SOLID implementation design

The codebase should be organized around small services with explicit contracts. The controller coordinates lifecycle; it should not contain packet parsing, proxy protocol handshakes, DNS resolution, UI logic, or Windows API details.

## Project layout

Recommended MVP layout:

```text
windows-wifi-hotspot-with-proxy/
  src/
    HProxy.Cli/                 # hproxy command line entrypoint
    HProxy.Service/             # elevated Windows service and lifecycle orchestration
    HProxy.Core/                # domain models, policies, state machine, contracts
    HProxy.Windows/             # Windows hotspot, interface, firewall, service APIs
    HProxy.Proxy/               # transparent TCP proxy and outbound connectors
    HProxy.Dns/                 # DNS proxy, resolvers, cache, query logging
    HProxy.Redirector.WinDivert/# packet capture, rewrite, reinject engine
    HProxy.Diagnostics/         # structured logs, metrics, health snapshots
  tests/
    HProxy.Core.Tests/
    HProxy.Proxy.Tests/
    HProxy.Dns.Tests/
    HProxy.Integration.Tests/
  tools/
    scripts/
  docs/
    architecture.md
    troubleshooting.md
```

If Rust is chosen for the packet loop, keep the same boundaries:

```text
src/
  controller-dotnet/
  cli-dotnet/
  redirector-rust/
  shared-contracts/
```

The key rule is that WinDivert-specific code stays isolated. Replacing WinDivert with a WFP driver later should not force rewrites in the proxy engine, DNS proxy, CLI, config parser, or lifecycle state machine.

## SOLID boundaries

### Single responsibility

Each module owns one reason to change:

```text
HotspotController:
    starts/stops/configures Windows Mobile Hotspot only

InterfaceDiscovery:
    discovers hotspot gateway, subnet, interface index, upstream interface

Redirector:
    captures, classifies, rewrites, drops, and reinjects packets only

FlowTable:
    records original destinations and flow lifetime only

TransparentTcpProxy:
    accepts redirected TCP connections and relays bytes only

DnsProxy:
    handles intercepted DNS queries only

OutboundConnector:
    opens upstream direct/SOCKS5/HTTP CONNECT/HTTPS proxy tunnels only

RecoveryManager:
    owns rollback order and transaction cleanup only
```

Avoid "manager" classes that do real work across many domains. The service orchestrator may coordinate components, but it should delegate every concrete operation.

### Open/closed

Use strategy interfaces for behavior that will change:

```csharp
public interface IOutboundConnector
{
    Task<Stream> ConnectTcpAsync(Endpoint destination, DomainHint? hint, CancellationToken ct);
}

public interface IDnsResolver
{
    Task<DnsMessage> ResolveAsync(DnsMessage query, CancellationToken ct);
}

public interface IPacketRedirector
{
    Task StartAsync(RedirectorConfig config, CancellationToken ct);
    Task StopAsync(CancellationToken ct);
}

public interface IUdpPolicyHandler
{
    UdpDecision Decide(UdpFlow flow);
}
```

Adding `ShadowsocksConnector`, `TrojanConnector`, `DoHResolver`, or `WfpRedirector` should mean adding a class and wiring config, not editing the core state machine.

### Liskov substitution

Interfaces must have narrow, honest contracts. For example, `HttpConnectConnector` cannot support generic UDP, so UDP support must not be implied by `IOutboundConnector`.

Use separate interfaces:

```csharp
public interface ITcpConnector
{
    Task<Stream> ConnectTcpAsync(Endpoint destination, DomainHint? hint, CancellationToken ct);
}

public interface IUdpAssociateConnector
{
    Task<IUdpRelaySession> OpenUdpAsync(CancellationToken ct);
}
```

Then SOCKS5 can implement both when UDP ASSOCIATE is available, while HTTP CONNECT implements only TCP.

### Interface segregation

Keep controller dependencies small:

```csharp
public interface IHotspotController
{
    Task StartAsync(HotspotConfig config, CancellationToken ct);
    Task StopAsync(CancellationToken ct);
    Task<HotspotStatus> GetStatusAsync(CancellationToken ct);
}

public interface IStateSnapshotStore
{
    Task<StateSnapshot> CaptureAsync(CancellationToken ct);
    Task SaveAsync(StateSnapshot snapshot, CancellationToken ct);
    Task<StateSnapshot?> LoadLastAsync(CancellationToken ct);
    Task ClearAsync(CancellationToken ct);
}
```

Do not pass a large `IWindowsSystem` dependency into every service. Split Windows operations by purpose: hotspot, interfaces, firewall, privilege checks, service control.

### Dependency inversion

High-level lifecycle code depends on interfaces from `HProxy.Core`, not on WinDivert, WinRT, sockets, or registry code directly.

```text
HProxy.Service
    depends on HProxy.Core contracts

HProxy.Windows
    implements hotspot/interface/firewall contracts

HProxy.Redirector.WinDivert
    implements packet redirector contracts

HProxy.Proxy
    implements TCP proxy and connector contracts
```

Concrete implementations are selected at composition root only:

```text
CLI command → loads config → sends command to service
Windows service startup → builds DI container → wires concrete services
```

---

# Efficient implementation approach

## Runtime model

Use a small number of long-running loops:

```text
controller service:
    lifecycle orchestration and health monitoring

redirector loop:
    WinDivert receive batch → classify → rewrite/drop/reinject batch

tcp accept loop:
    accept redirected TCP connection → lookup flow → connect upstream → relay

dns loop:
    receive DNS query → resolve → reply with original source rewrite
```

Do not spawn an unbounded thread per packet. TCP connections may use async tasks, but all packet capture should be batch-oriented and allocation-conscious.

## Flow table design

The flow table is shared between redirector and transparent proxy. It must be fast, bounded, and self-cleaning.

```text
key:
    protocol + client_ip + client_port

value:
    original_dst_ip
    original_dst_port
    redirected_dst_ip
    redirected_dst_port
    created_at
    last_seen
    state
```

Requirements:

```text
1. O(1) lookup for proxy accept path.
2. TTL cleanup for half-open flows.
3. Explicit cleanup on TCP FIN/RST when visible.
4. Bounded capacity with metrics when evicting.
5. No DNS-name dependency for routing correctness.
```

If the redirector is native and the proxy is .NET, expose flow lookup through shared memory, a local named pipe, or keep redirector and proxy in the same native engine. For MVP simplicity, prefer one process for redirector plus proxy if language choice allows it.

## Packet rewrite rules

Keep rewrite logic data-driven:

```text
Classifier:
    packet metadata → PacketDecision

Rewriter:
    PacketDecision + packet → modified packet

WinDivertAdapter:
    receive/send only
```

This separation makes packet policy testable without a live WinDivert driver.

## Configuration model

Use one normalized internal config regardless of CLI syntax:

```csharp
public sealed record AppConfig(
    HotspotConfig Hotspot,
    UpstreamConfig Upstream,
    ProxyConfig OutboundProxy,
    TransparentPolicy Policy,
    DiagnosticsConfig Diagnostics);
```

Validate config before changing the system:

```text
1. Parse CLI/file/env.
2. Normalize proxy URI.
3. Validate SSID/password.
4. Resolve upstream proxy host.
5. Probe TCP connectivity to upstream proxy.
6. Verify admin/service capability.
7. Only then mutate hotspot/capture state.
```

## Error handling

Use transaction-style startup:

```text
StartTransaction
    capture previous state
    start hotspot
    discover interface
    start proxy and DNS listeners
    install redirector
    commit

Rollback
    disable redirector
    stop listeners
    remove firewall changes
    stop hotspot if this tool started it
    restore previous config where possible
```

Failures should be typed, not stringly handled:

```csharp
public enum FailureCategory
{
    Privilege,
    Hotspot,
    InterfaceDiscovery,
    ProxyReachability,
    RedirectorDriver,
    Dns,
    Recovery
}
```

## Logging and diagnostics

Diagnostics must be useful without leaking secrets:

```text
log:
    state transitions
    hotspot interface/subnet
    upstream proxy endpoint without password
    flow counts
    DNS qname and response IP when enabled
    dropped UDP policy decisions
    driver errors

never log:
    hotspot password
    proxy password
    raw payload bytes by default
```

Expose:

```powershell
hproxy status
hproxy logs --tail
hproxy flows --active
hproxy doctor
```

## Performance targets

MVP targets:

```text
TCP throughput:
    enough for MCU/vendor devices and normal setup workflows, not full router replacement

Packet loop:
    batch receive/reinject
    avoid per-packet heap allocations where practical
    recompute checksums only after mutation

DNS:
    cache positive and negative responses according to TTL
    cap cache size

Relay:
    use pooled buffers
    full-duplex copy with cancellation and idle timeout
```

---

# MVP implementation sequence

Build in this order:

```text
1. Config parser and validation.
2. Outbound TCP connectors: direct, SOCKS5, HTTP CONNECT, HTTPS proxy CONNECT.
3. Transparent TCP proxy with fake/manual flow table for unit tests.
4. DNS proxy with hardcoded redirect tests.
5. WinDivert redirector for TCP SYN destination rewrite and return rewrite.
6. Hotspot/interface discovery.
7. Service lifecycle and transaction recovery.
8. CLI commands: up, down, status, recover, doctor.
9. Integration test with one real client on Windows 11.
```

This order keeps the riskiest driver and hotspot work behind testable proxy/connectivity components.

---

# Testing matrix

## Must-pass tests

```text
1. Device joins hotspot and gets DHCP IP.
2. Device with no proxy config can access HTTPS endpoint through SOCKS5 upstream.
3. Device using hardcoded 8.8.8.8 DNS still resolves through DNS proxy.
4. Device HTTP/MQTT/TCP traffic goes through upstream proxy.
5. UDP/443 QUIC is blocked and TCP fallback works.
6. Private LAN/mDNS/broadcast traffic is not sent to upstream proxy.
7. Stopping tool restores normal STA-only host behavior.
8. Killing the tool process and running recover restores STA-only.
9. Upstream proxy IP is bypassed to avoid proxy loop.
10. Host’s own traffic is not captured unless explicitly enabled.
```

## Failure cases

```text
No admin rights:
    fail before mutation

No upstream Wi-Fi:
    fail before hotspot start

Hotspot start fails:
    restore previous state

Proxy unreachable:
    do not start capture

Capture engine crashes:
    disable hotspot or fall back according to policy

DNS proxy crashes:
    stop capture or block client traffic clearly

WinDivert driver blocked by security software:
    report unsupported environment
```

---

# Strong recommendation

Build the first real version like this:

```text
Windows service
    + NetworkOperatorTetheringManager hotspot control
    + interface/subnet discovery
    + WinDivert transparent TCP/DNS redirector
    + local transparent TCP proxy
    + local DNS proxy
    + SOCKS5 / HTTP CONNECT / HTTPS proxy outbound connector
    + transaction-based recovery
```

That is the correct product architecture for devices that cannot be configured.
