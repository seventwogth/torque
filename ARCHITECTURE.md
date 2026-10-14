# Architecture

## Why a bundled C-tor and not Arti

Arti is a complete Tor client today, bridges and pluggable transports
included. Torque still drives the C implementation, for two reasons.

**The control protocol is already the API this UI needs.** Everything the
interface shows or changes maps onto it directly: `BW` events for the
bandwidth graph, `CIRC`/`STREAM` events plus `GETINFO circuit-status` for the
circuit list, `SETCONF Bridge/UseBridges/ClientTransportPlugin` to switch
bridges and transports without a restart, `SIGNAL NEWNYM` for a new identity.
Arti exposes far less introspection as public API, so the same screens would
mean reaching into internals.

**Embedding would not remove the process supervisor anyway.** Pluggable
transports — `lyrebird`, `snowflake-client`, `conjure-client` — are separate
executables regardless of which Tor implementation dials through them. A
bundled-binary layout and a supervisor are required either way, so
"in-process" buys less than it appears to.

`torque-core` keeps the engine behind its own API, so an Arti backend can be
added later without the UI noticing. Note that Arti's onion-service support is
still documented as less hardened than C-tor's.

## Crates

```
torque-control   Tor control protocol: cookie auth, SETCONF/SETEVENTS,
                 reply parser, BW/CIRC/STREAM/STATUS_CLIENT events
torque-bridges   bridge-line parsing and validation; which transports a
                 bridge set requires
torque-core      torrc generation, tor process supervision, state model
torque-router    trait TrafficRouter + per-platform backends
torque-ipc       newline-delimited JSON protocol, GUI <-> service
torque-service   the privileged half: owns tor, routes and firewall filters
torque-gui       eframe/egui UI, unprivileged
torque-cli       headless engine, for development and debugging
```

Dependencies point one way: `gui` and `service` depend on `core` and `ipc`;
`core` depends on `control`, `bridges` and `router`; those three depend on
nothing of ours. `ipc` carries plain data types rather than re-exporting
`core`'s, so the two halves can be upgraded independently.

## Privilege split

Transparent routing needs a TUN adapter, route changes and firewall filters.
The GUI must not run elevated to get them, so the layout follows
`wireguard-windows`: `torque-service` runs elevated (Windows service, systemd
unit, launchd daemon) and owns tor plus the routing backend; `torque-gui` runs
as the user and talks to it over a named pipe with an ACL, or a Unix socket
with peer credentials checked. Tor surviving a closed window falls out of this
for free.

## How traffic reaches Tor

| OS | Interception | Handed to | Privilege |
|---|---|---|---|
| Windows | Wintun adapter + userspace TCP/IP stack | `SocksPort` | admin |
| Linux | nftables redirect, tor's uid excluded | `TransPort` | `CAP_NET_ADMIN` |
| macOS | `utun` + `pf rdr-to` via a root helper | `TransPort` | root |

Windows is the outlier and the expensive case: tor's `TransPort` is not
supported there, so packets have to be terminated in a userspace TCP/IP stack
(`ipstack` / `netstack-smoltcp`, or `tun2proxy` wholesale) and handed to SOCKS.
Linux and macOS use tor's native transparent proxying — the Whonix/Tails
recipe — and need no TUN device at all.

Two deliberate non-choices:

- **Not WinDivert** on Windows. It is GPL/commercial, which does not fit an
  MIT project, and WFP covers the same ground. WFP filters at
  `FWPM_LAYER_ALE_AUTH_CONNECT_V4` can be installed from user mode via
  `fwpuclnt`, so the kill switch needs no kernel driver and no driver signing.
- **Not NetworkExtension** on macOS. A `PacketTunnelProvider` requires Apple
  Developer Program membership and a provisioning profile with the
  network-extension entitlement. `pf` plus a root helper ships without either.

## What transparent mode must get right

Tor carries **TCP only**. Everything below follows from that, and skipping any
of it produces a client that looks like it works and leaks.

- **DNS** must terminate at tor's `DNSPort`. UDP 53 cannot pass.
- **UDP must be blocked, not dropped silently** — explicitly including UDP 443,
  or browsers sit on QUIC instead of falling back to TCP.
- **IPv6** is blocked outright for 1.0.
- **`.onion` needs `AutomapHostsOnResolve 1`** with
  `VirtualAddrNetworkIPv4 10.192.0.0/10`. Without it onion names simply do not
  resolve in transparent mode.
- **The kill switch matches on the process, not the address.** Tor's own
  traffic must bypass the tunnel, and guard addresses rotate, so filtering by
  guard IP cannot hold. Permit `tor` and its transports; deny everything else.

Until all of it is in place, the UI marks transparent mode experimental. A
partial kill switch is worse than none, because it implies protection that
is not there.

## The async/UI seam

egui is immediate-mode and synchronous; the engine is tokio. The UI never
awaits: a background thread owns the service connection, pushes snapshots over
a channel and calls `ctx.request_repaint()`, and `update` only reads the newest
snapshot. This is load-bearing and should not be worked around.

## Roadmap

Stage numbers are referenced from `torque_router::Error::NotImplemented`.

1. **Engine** — control-protocol client, supervisor, torrc generation.
   `torque-cli` starts tor and reports bootstrap. *Done.*
2. **UI** — bootstrap, circuit list, bandwidth graph, new identity, SOCKS mode.
   *Bridge validation done; panels render a disconnected state.*
3. **Bridges and transports** — editor, obfs4/snowflake/webtunnel, live
   `SETCONF`, `moat`/BridgeDB fetch.
4. **Service** — IPC listener with an ACL, platform service registration,
   supervision moves out of the GUI.
5. **Windows transparent routing** — Wintun, userspace stack, `DNSPort`,
   `AutomapHostsOnResolve`.
6. **Kill switch** — WFP filters, UDP and IPv6 blocked. Transparent mode may
   only be called safe once this ships.
7. **Platforms and packaging** — nftables and `pf` backends, MSI installer,
   code signing, signature-verified updates for the bundled tor binaries.

## Known risks

- Antivirus false positives on an executable that bundles Tor and transports.
- Windows SmartScreen: needs code signing, and reputation takes time to build.
- Reproducible builds and signature verification of downloaded tor binaries —
  a censorship-circumvention tool that updates unverified binaries is a
  liability.
