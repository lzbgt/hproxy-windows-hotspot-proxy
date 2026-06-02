# HProxy Windows Hotspot Gateway

HProxy is a single Rust command-line app for Windows 11 that turns Windows Mobile Hotspot into a proxy gateway for Wi-Fi clients that cannot be configured with proxy settings.

It is aimed at vendor devices, MCUs, phones, and other "dumb" Wi-Fi clients that can join an SSID but cannot set SOCKS5 or HTTPS proxy options.

## What It Does

HProxy starts or controls Windows Mobile Hotspot, keeps a local gateway running on the hotspot side, and forwards client web traffic through a configured upstream proxy.

Current working mode:

```text
Wi-Fi client
  joins Windows Mobile Hotspot
      |
DNS gateway answer: hotspot gateway IP
      |
client connects to gateway port 80 or 443
      |
HProxy extracts HTTP Host or TLS SNI
      |
SOCKS5, HTTP CONNECT, or HTTPS CONNECT upstream proxy
```

HProxy does not require clients to configure their own proxy settings. The client Wi-Fi proxy setting should stay disabled.

## Defaults

```text
SSID: VirtualProxyAP
Password: 11102017
Band: 2.4 GHz
DNS mode: forward unless --dns-mode gateway is selected
Logging: disabled unless --log-file or --log-stderr is provided
```

2.4 GHz is the default because many MCU and embedded Wi-Fi devices cannot see or reliably join 5 GHz hotspot networks. Use `--band five-ghz` only for clients known to support it.

## Requirements

- Windows 11 host
- Rust installed on the Windows host
- Windows Mobile Hotspot support
- Wi-Fi adapter that supports Windows tethering through Wi-Fi Direct
- Administrator rights for WinDivert packet capture
- Upstream proxy, for example `socks5://192.168.0.104:8120`
- Vendored WinDivert runtime files under `third_party/windivert/win-x64`

The current validated host has:

```text
Windows Mobile Hotspot path: supported
Legacy hostednetwork SoftAP: not supported
Wi-Fi Direct GO: supported
WinDivert: usable
Windows Rust: available
Visual Studio / Windows SDK: installed
```

## Quick Start

Build and test with the Windows host toolchain:

```cmd
cd /d C:\work\windows-wifi-hotspot-with-proxy
cargo test
cargo build
```

Check host readiness:

```cmd
cargo run -- doctor --outbound socks5://192.168.0.104:8120 --proxy-probe-target 1.1.1.1:443 --windivert-open-probe
```

Start foreground for debugging:

```cmd
cargo run -- --log-stderr up --outbound socks5://192.168.0.104:8120 --dns-upstream 223.5.5.5:53 --dns-mode gateway
```

Start hidden for normal experimentation:

```powershell
.\scripts\start-hproxy-hidden.ps1 -Outbound socks5://192.168.0.104:8120 -LogFile target\hproxy-gateway.log
```

The hidden launcher uses:

```text
SSID: VirtualProxyAP
Password: 11102017
Band: 2.4 GHz
DNS mode: gateway
```

Connect the client device to `VirtualProxyAP`, leave the client proxy setting disabled, and browse normally.

## Commands

```cmd
hproxy up
hproxy down
hproxy status
hproxy recover
hproxy doctor
```

Useful options:

```cmd
--outbound socks5://192.168.0.104:8120
--outbound https-proxy://192.168.0.104:8120
--dns-mode gateway
--dns-upstream 223.5.5.5:53
--band five-ghz
--ssid CustomName
--password CustomPassword
--log-file target\hproxy-gateway.log
--log-stderr
```

For HTTPS proxy testing with a local self-signed certificate:

```cmd
hproxy up --outbound https-proxy://192.168.0.104:8120 --proxy-tls-insecure --dns-mode gateway
```

Do not use `--proxy-tls-insecure` for production proxy endpoints.

## Logging

HProxy does not emit debug logs by default.

Use file logging when running hidden:

```cmd
hproxy --log-file target\hproxy-gateway.log up --outbound socks5://192.168.0.104:8120 --dns-mode gateway
```

Use stderr logging for an interactive console:

```cmd
hproxy --log-stderr up --outbound socks5://192.168.0.104:8120 --dns-mode gateway
```

Expected gateway-mode log lines:

```text
gateway TCP proxy listening on 0.0.0.0:80
gateway TCP proxy listening on 0.0.0.0:443
WinDivert redirector started
hproxy tcp relay: gateway tls; connecting upstream example.com:443
```

## Current Live Host State

The tool is currently running on the Windows host for experimentation:

```text
PID: target\hproxy-gateway.pid
SSID: VirtualProxyAP
Hotspot: Running
Gateway TCP: 80, 443
DNS proxy: UDP 1053
Transparent TCP relay port: 16000
Log file: target\hproxy-gateway.log
Upstream proxy: socks5://192.168.0.104:8120
```

## Security And Compatibility Model

HProxy is designed as a tunnel gateway, not a TLS interception proxy.

Intentional properties:

- HTTPS is not decrypted, modified, or re-signed.
- No custom certificate authority is installed on clients.
- No TLS MITM is required for normal HTTPS traffic.
- Routing uses DNS plus HTTP Host or TLS SNI, then relays bytes through the configured upstream proxy.
- QUIC UDP/443 is dropped by policy so clients fall back to TCP/TLS, where Host/SNI routing is observable without decrypting payloads.

Current compatibility boundary:

- Normal browser, phone, MCU, and vendor-device HTTP/HTTPS traffic works when it uses DNS and sends HTTP Host or TLS SNI.
- A client that deliberately connects to a raw public IP without DNS and without SNI does not provide a hostname for gateway-mode routing.
- Generic UDP is not tunnelled through HTTP(S) CONNECT. DNS is handled locally; other UDP remains conservative by design.

The direct-IP/no-SNI case is the remaining routing extension. The design path for that is to combine gateway mode with a lower-layer original-destination capture path, such as a corrected WinDivert interception point or WFP callout. That extension should preserve the same no-MITM TLS property.

## Repository Layout

```text
src/main.rs        CLI entrypoint
src/app.rs         startup, shutdown, rollback orchestration
src/config.rs      typed config and validation
src/hotspot.rs     Windows Mobile Hotspot control
src/redirector.rs  WinDivert policy and packet boundary
src/proxy.rs       gateway relay and upstream connectors
src/dns.rs         DNS forwarding and gateway responses
docs/              architecture, environment, and testing notes
scripts/           WinDivert install and hidden-start helpers
third_party/       vendored WinDivert runtime files
```

## Documentation

- `docs/architecture.md`
- `docs/environment.md`
- `docs/hotspot-control.md`
- `docs/testing.md`
