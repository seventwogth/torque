# Torque

A desktop client for Tor that makes bridges, pluggable transports and traffic
routing legible — the things that matter when the network is being filtered,
in a window instead of a torrc file.

Windows first, cross-platform by design. Rust, with an egui interface and a
bundled C-tor driven over its control protocol.

> **Status: early.** Usable as a SOCKS proxy client: it starts and stops tor,
> shows bootstrap, circuits and bandwidth live, and switches bridges and
> transports without a restart. Transparent routing and per-app rules are not
> implemented — see the roadmap in [ARCHITECTURE.md](ARCHITECTURE.md). Do not
> rely on this for anything that matters yet.

## What it is meant to do

- Start, stop and watch Tor without a terminal: live bootstrap progress,
  circuit list with relays and streams, bandwidth graph, new identity.
- Make bridges manageable: paste lines from BridgeDB, see *why* a line is
  rejected, switch between obfs4, snowflake and webtunnel without editing
  config or restarting tor.
- Offer two honest traffic modes — Tor as a SOCKS proxy that apps opt into,
  or everything on the machine forced through Tor with a kill switch.

## Why not Arti

Arti is a complete Tor client, but the C implementation's control protocol is
already the API this UI needs — `BW` events for the graph, `CIRC`/`STREAM` for
the circuit list, `SETCONF` for live bridge changes. Embedding would also not
remove the process supervisor, since pluggable transports are separate
executables either way. The reasoning, and the seam that keeps an Arti backend
possible, are in [ARCHITECTURE.md](ARCHITECTURE.md).

## Building

Requires Rust 1.92 or newer.

```sh
cargo test --workspace     # the engine is covered by unit tests
cargo run -p torque-gui    # the UI
cargo run -p torque-cli    # headless: start tor, print bootstrap progress
```

Running tor needs the Tor Expert Bundle unpacked into `vendor/` — see
[vendor/README.md](vendor/README.md). No binaries are committed to this
repository.

## Layout

| Crate | Role |
|---|---|
| `torque-control` | Tor control protocol client |
| `torque-bridges` | bridge-line parsing and validation |
| `torque-policy` | per-app and per-host routing rules |
| `torque-core` | torrc generation, process supervision, state model |
| `torque-router` | per-platform traffic routing backends |
| `torque-ipc` | GUI ↔ service protocol |
| `torque-service` | the privileged half: tor, routes, firewall filters |
| `torque-gui` | the interface |
| `torque-cli` | headless engine, for development |

## Licence

MIT. Tor and its pluggable transports are BSD-3-Clause and are not
redistributed here.
