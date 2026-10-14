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
torque-policy    per-app and per-host routing rules: the model and the
                 evaluation, no I/O
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

One mechanism on all three platforms: a TUN device takes the default route,
and every flow is terminated in a **userspace TCP/IP stack** (`ipstack` /
`netstack-smoltcp`, or `tun2proxy` wholesale) which decides per flow where it
goes. `torque-policy` makes that decision; see the next section.

| OS | TUN device | Privilege | Firewall |
|---|---|---|---|
| Windows | Wintun (`wintun.dll`, signed build) | admin | WFP filters |
| Linux | `/dev/net/tun` | `CAP_NET_ADMIN` | nftables |
| macOS | `utun` via a root helper | root | `pf` |

Tor's native `TransPort` would be cheaper on Linux and macOS — the
Whonix/Tails recipe, no TUN device, no userspace stack. It is kept only as an
optional fast path for the case where no per-app rules exist, and is not the
primary design, because a kernel redirect cannot attribute a flow to the
program that opened it. See below.

Two deliberate non-choices:

- **Not WinDivert** on Windows. It is GPL/commercial, which does not fit an
  MIT project, and WFP covers the same ground. WFP filters at
  `FWPM_LAYER_ALE_AUTH_CONNECT_V4` can be installed from user mode via
  `fwpuclnt`, so the kill switch needs no kernel driver and no driver signing.
- **Not NetworkExtension** on macOS. A `PacketTunnelProvider` requires Apple
  Developer Program membership and a provisioning profile with the
  network-extension entitlement. `pf` plus a root helper ships without either.

## Per-app and per-host rules (ProxyBridge)

Routing rules per application, and per destination host, with three outcomes:
through Tor, direct, or blocked.

### Why this is not a firewall feature

On Windows, deciding per program at the firewall means one of two things, and
both are out of reach for this project:

- a WFP **callout driver** at `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4`, which is a
  callout-only layer — user-mode filters cannot redirect a connection;
- a **split-tunnel kernel driver**, the way Mullvad does it: their driver
  checks each new socket's process binary path and redirects binds away from
  the tunnel.

Either needs a kernel driver, so EV code signing plus Microsoft attestation
signing. The user-mode WFP filters that give us the kill switch cannot do it.

### Where it goes instead

Into the userspace flow engine we already need for Windows. The TUN device
holds the default route, so **every flow arrives at us before it goes
anywhere**, and the decision is an ordinary function call rather than a
kernel hook. No driver, same code on all three platforms.

For each new flow the engine needs two facts:

**Which program opened it.** The local port is in the flow; the port-to-PID
mapping comes from `GetExtendedTcpTable`/`GetExtendedUdpTable` on Windows,
`/proc/net/*` plus socket inodes on Linux, `libproc` on macOS. Cache it and
refresh on a miss. A short-lived flow can vanish from the table before we
look, so **attribution failure must fall through to Tor, never to direct** —
otherwise the one case we cannot identify is the one that leaks.

**Where it is going.** We own DNS (`DNSPort` plus `AutomapHostsOnResolve`), so
the name is known before the flow exists and rules can key on it. Two limits
follow: a connection to a raw IP matches only IP/CIDR rules, and an app with
its own DoH/DoT resolver is invisible to us by name — either its endpoints get
blocked, or it only ever matches on IP.

### The rule model

`torque-policy`: pure logic, no I/O, tested like `torque-bridges`.

```
Policy  { rules: Vec<Rule>, default: Action }
Rule    { enabled: bool, label: Option<String>, matcher: Matcher, action: Action }
Matcher = Always | Process(path | file name) | Domain(exact | suffix)
        | Ip(cidr) | Port(range) | Protocol(tcp | udp)
        | All(..) | Any(..) | Not(..)
Action  = Tor { isolation: Option<String> } | Direct | Block

Policy::decide(&Flow) -> Outcome { decision, rule: Option<usize> }
Decision = Tor { isolation } | Direct | Blocked { reason }
```

First match wins, and `Outcome` carries which rule it was, so "why did this
app go that way" is answerable rather than guessed at. `default` is `Tor`, and
anything else is an explicit choice by the user.

Two decisions worth keeping:

- **`Blocked` carries a reason**, distinguishing a rule's `Block` from
  `TorCarriesNoUdp`. An app that silently goes quiet is the hardest thing
  about this mode to debug, so the engine should be able to say which it was.
- **`Policy::lints()`** returns advisory warnings for the editor: a default
  that leaves Tor, a rule shadowed by an earlier catch-all, UDP routed into
  Tor, an onion address routed out of it. It is deliberately conservative and
  does not descend into `Not`, since a noisy warning list gets ignored and
  then the real warning goes unread.

The `isolation` tag is close to free and worth having: tor isolates circuits
by SOCKS credentials, with `IsolateSOCKSAuth` on by default, so passing a
per-rule tag as the SOCKS username gives each app or group its own circuits
and its own exit. "This browser and that client never share an exit" becomes
one field in a rule.

### What it costs

Stated plainly, because these are the parts that can mislead a user:

- **The kill switch weakens.** It stops being "only tor may egress": a
  `Direct` rule means our service egresses on the physical interface on an
  app's behalf, so WFP is no longer the sole guarantee and a bug in rule
  evaluation becomes a leak. Everything else is still blocked and the engine
  fails closed, but transparent-with-rules is a weaker promise than
  transparent-everything and the UI must not show them as the same thing.
- **A `Tor` rule silently kills that app's UDP.** Tor carries TCP only. This
  needs saying per rule, not once in a settings page.
- **Per-host rules cannot bind a flow whose destination we never resolved.**

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
2. **UI** — bootstrap, circuit list, bandwidth graph, new identity, SOCKS mode,
   over the async seam described above. *Done.*
3. **Bridges and transports** — editor, obfs4/snowflake/webtunnel, live
   `SETCONF` with no restart. *Done.*
4. **Service** — IPC listener with an ACL, platform service registration,
   supervision moves out of the GUI.
5. **Flow engine and ProxyBridge** — Wintun, userspace TCP/IP stack, `DNSPort`
   and `AutomapHostsOnResolve`, flow-to-process attribution, `torque-policy`
   evaluation, per-rule stream isolation, rules editor in the UI. Windows
   first. `torque-policy` itself has landed ahead of the engine that calls it,
   so the IPC protocol in stage 4 can carry rules from the start rather than
   versioning them in later.
6. **Kill switch** — WFP filters, UDP and IPv6 blocked. Transparent mode may
   only be called safe once this ships, and transparent-with-rules is labelled
   separately from transparent-everything.
7. **Platform backends** — the flow engine on Linux and macOS, plus the
   optional native `TransPort` fast path for the no-rules case.
8. **Packaging** — MSI installer, code signing, signature-verified updates for
   the bundled tor binaries.
9. **Bridge acquisition** — `moat`, the domain-fronted BridgeDB API that Tor
   Browser uses, plus the circumvention-settings endpoint. Numbered last
   because it is independent, not because it is unimportant: a censored user
   cannot reach BridgeDB in a browser either. It is a different kind of work
   from stage 3 — an HTTPS client behind a CDN front and a CAPTCHA the user
   has to solve — and it buys nothing until the bridges it returns can be
   applied, which is what stage 3 delivered. Can land whenever.

Stages 5 and 7 are referenced from `torque_router::Error::NotImplemented`, so
new work gets appended rather than inserted.

## Known risks

- Antivirus false positives on an executable that bundles Tor and transports.
- Windows SmartScreen: needs code signing, and reputation takes time to build.
- Reproducible builds and signature verification of downloaded tor binaries —
  a censorship-circumvention tool that updates unverified binaries is a
  liability.
