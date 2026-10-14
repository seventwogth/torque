# vendor/

Torque drives a bundled C-tor rather than embedding Arti, and tor's pluggable
transports are separate executables. Those binaries live here. **None of them
are committed** — see `.gitignore`.

## What goes here

Download the **Tor Expert Bundle** for your platform from
<https://www.torproject.org/download/tor/> — the same artifact Tor Browser
ships — and unpack it so this directory contains:

| File | Provides |
|------|----------|
| `tor` / `tor.exe` | the Tor client itself |
| `lyrebird` / `lyrebird.exe` | obfs4, meek_lite, webtunnel |
| `snowflake-client` / `snowflake-client.exe` | snowflake |
| `conjure-client` / `conjure-client.exe` | conjure |
| `geoip`, `geoip6` | country lookup for the circuit list |

On Windows the bundle also carries its own runtime DLLs; keep them alongside
`tor.exe`.

Transparent routing on Windows additionally needs `wintun.dll`:

- Download it from <https://www.wintun.net/> and place it next to the
  executable.
- **Use the signed prebuilt DLL as distributed.** Wintun's sources are GPLv2,
  which does not fit this project's MIT licence; the prebuilt signed binaries
  ship under a separate, more permissive licence, and only the signed build is
  supported. Do not rebuild it.

## Verify before you trust

Tor's downloads are signed. Check the `.asc` signature against the Tor
Browser Developers key before unpacking — a bridge client that silently runs a
tampered `tor.exe` is worse than no bridge client. Automating this check is
roadmap stage 7.

## Licences

Tor and the transports are BSD-3-Clause, compatible with Torque's MIT licence.
Ship their licence texts with any binary distribution.
