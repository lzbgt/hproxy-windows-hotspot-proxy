# Windows Hotspot Control

This document clarifies how `hproxy` makes the Windows Wi-Fi adapter act as upstream STA plus hotspot SoftAP.

## Short Answer

`hproxy` does not manually reprogram the Wi-Fi card into SoftAP mode.

Instead, it calls the Windows Mobile Hotspot/tethering API:

```text
Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager
```

Windows owns the actual STA + SoftAP operation:

```text
same Windows host

upstream side:
    Wi-Fi STA remains connected to the normal internet Wi-Fi network

private side:
    Windows creates/runs a mobile hotspot Wi-Fi network for dumb clients

hproxy:
    controls hotspot lifecycle
    discovers the created private hotspot interface
    intercepts hotspot-client packets
    forwards them through SOCKS5 / HTTP CONNECT / HTTPS proxy
```

If the Wi-Fi adapter or driver cannot run STA and hotspot concurrently, `hproxy` cannot force it. The Windows API will report disabled capability or fail to start tethering.

On modern Windows 10/11 systems this may not appear as classic SoftAP support. For example, the current host reports:

```text
Hosted network supported: No
Soft AP: Not supported
Wi-Fi Direct GO: Supported
P2P Max Mobile AP Clients: 8
Microsoft Wi-Fi Direct Virtual Adapter devices present
```

That is still compatible with the intended Mobile Hotspot path. It means `hproxy` must use Windows tethering/Wi-Fi Direct based hotspot control, not legacy `netsh hostednetwork`.

## API Model

Microsoft's tethering API has this shape:

```text
CreateFromConnectionProfile(profile)
```

Meaning:

```text
public interface:
    the upstream connection profile, such as the current Wi-Fi STA internet connection

private interface:
    Wi-Fi tethering/mobile hotspot created by Windows
```

There is also an overload:

```text
CreateFromConnectionProfile(profile, adapter)
```

Meaning:

```text
public interface:
    the upstream connection profile

private interface:
    the selected network adapter where Windows should create the shared hotspot
```

So `hproxy` startup does:

```text
1. Validate configuration.
2. Probe the configured upstream proxy before changing hotspot state.
3. Bind local DNS/TCP proxy listeners.
4. Preflight WinDivert handle opening before changing hotspot state.
5. Find the current upstream internet ConnectionProfile.
6. Check tethering capability for that profile.
7. Create NetworkOperatorTetheringManager from the profile.
8. Configure SSID, passphrase, band, and authentication.
9. Start tethering.
10. Discover the Windows-created hotspot private interface, gateway IP, and subnet.
11. Start DNS/TCP proxy tasks.
12. Start WinDivert packet redirection scoped to that private interface/subnet.
```

The private hotspot interface discovery step is implemented first with the native Windows IP Helper API:

```text
GetAdaptersAddresses(AF_INET, ...)
```

`hproxy` scans active IEEE 802.11 adapters whose description or friendly name identifies them as Wi-Fi Direct, then records the first usable IPv4 unicast address as the hotspot gateway.

PowerShell remains as a fallback discovery path using:

```text
Get-NetAdapter -IncludeHidden
Get-NetIPAddress -AddressFamily IPv4
```

`hproxy` looks for the active Microsoft Wi-Fi Direct adapter with an IPv4 address, then records:

```text
interface index
gateway IPv4 address
prefix length
computed hotspot subnet
```

Hotspot status and access-point SSID queries are implemented with native typed WinRT APIs:

```text
NetworkInformation.GetInternetConnectionProfile()
NetworkOperatorTetheringManager.CreateFromConnectionProfile(profile)
manager.TetheringOperationalState
manager.GetCurrentAccessPointConfiguration().Ssid
```

`Off` maps to `Stopped`, `On` maps to `Running`, and transitional or unavailable states map to `Unknown`.

Hotspot configure/start/stop is implemented through the same WinRT manager using native typed WinRT APIs first:

```text
GetCurrentAccessPointConfiguration()
ConfigureAccessPointAsync(config)
StartTetheringAsync()
StopTetheringAsync()
```

The native path waits for SSID configuration and for the requested `On` or `Off` operational state. PowerShell remains as a fallback path for diagnostics and unexpected native WinRT failures.

The Rust app passes SSID, passphrase, and band through process environment variables to avoid command-line escaping problems. The current implementation uses WPA2 authentication and maps bands as:

```text
auto -> Auto
2.4 GHz -> TwoPointFourGigahertz
5 GHz -> FiveGigahertz
```

The CLI defaults are SSID `VirtualProxyAP`, password `11102017`, and 2.4 GHz:

```powershell
hproxy up ...
```

That default is intentional because many MCU and embedded Wi-Fi clients only support 2.4 GHz. Use an explicit 5 GHz hotspot only when the target clients support it:

```powershell
hproxy up --band five-ghz ...
```

`--band auto` is still available when Windows should choose the band.
`--ssid` is still available when a different hotspot name is needed.
`--password` is still available when a different hotspot password is needed.

## Capability And Packaging Constraint

The API requires the `wiFiControl` device capability in the app manifest. If that capability is missing, `CreateFromConnectionProfile` fails.

That matters for implementation:

```text
development binary:
    can build from Rust, but hotspot control may not work until packaged/manifested correctly

production binary:
    should be packaged or installed with the required Windows app capability

fallback:
    hproxy doctor must detect missing capability and report it before changing network state
```

This is why `hotspot.rs` is currently an adapter boundary. It needs a Windows-specific implementation plus a packaging story, not just normal cross-platform Rust socket code.

## Why Not netsh Hosted Network

Do not build the main product around legacy `netsh wlan set hostednetwork`.

The intended control plane is Windows Mobile Hotspot/tethering:

```text
NetworkOperatorTetheringManager
NetworkOperatorTetheringAccessPointConfiguration
NetworkOperatorTetheringSessionAccessPointConfiguration
```

That matches Windows 10/11 Mobile Hotspot behavior and lets Windows decide whether the adapter can support the required STA + private hotspot mode.

## What hproxy Owns After Hotspot Starts

Once Windows starts the hotspot, `hproxy` owns the transparent gateway behavior:

```text
Windows Mobile Hotspot:
    SSID/password
    Wi-Fi beaconing/authentication
    DHCP/private network
    NAT/tethering baseline

hproxy:
    identify hotspot private interface/subnet
    intercept hotspot-client TCP and DNS
    block/drop policy for UDP such as QUIC
    map redirected TCP flows to original destinations
    tunnel TCP through SOCKS5 / HTTP CONNECT / HTTPS proxy
    recover by disabling capture before stopping proxy listeners/hotspot
```

The two pieces are separate:

```text
Hotspot control:
    make dumb clients able to join Wi-Fi

Transparent datapath:
    make those clients' traffic use an upstream proxy without client settings
```
