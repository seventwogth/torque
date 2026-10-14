//! Transparent routing on Windows — the expensive platform.
//!
//! Tor's `TransPort` is not supported on Windows, so there is no kernel-side
//! redirect to lean on. The plan:
//!
//! 1. Create a **Wintun** adapter and become the default route. Ship
//!    `wintun.dll` as downloaded from wintun.net, next to the executable: the
//!    sources are GPLv2, but the signed prebuilt DLL ships under a permissive
//!    licence, and only the signed build is supported. Never rebuild it.
//! 2. Read IP packets off the adapter and terminate them in a **userspace
//!    TCP/IP stack** (`ipstack` / `netstack-smoltcp`, or `tun2proxy` whole),
//!    turning each flow into a TCP connection to Tor's `SocksPort`.
//! 3. Force DNS to Tor's `DNSPort`, since Tor carries no UDP. `.onion` works
//!    only because tor's `AutomapHostsOnResolve` hands back a virtual address
//!    from `VirtualAddrNetworkIPv4`.
//! 4. Install **WFP** filters as the kill switch: at
//!    `FWPM_LAYER_ALE_AUTH_CONNECT_V4`, permit egress on the physical adapter
//!    only for tor and its transports, block everything else, and block UDP
//!    (443 included, or browsers hang on QUIC) and all IPv6. These filters are
//!    added from user mode via `fwpuclnt`, so no kernel driver and no driver
//!    signing — the privileged service is enough.
//!
//! Deliberately not WinDivert: it is GPL/commercial, which does not fit this
//! crate's MIT licence, and WFP covers the same ground.

use crate::{Capabilities, Error, RoutePlan, Result, TrafficRouter};

#[derive(Debug, Default)]
pub struct WintunRouter {
    _private: (),
}

impl TrafficRouter for WintunRouter {
    fn name(&self) -> &'static str {
        "wintun"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            transparent: true,
            kill_switch: true,
            needs_elevation: true,
        }
    }

    fn apply(&mut self, _plan: &RoutePlan) -> Result<()> {
        Err(Error::NotImplemented {
            what: "Wintun adapter plus userspace TCP/IP stack",
            stage: 5,
        })
    }

    fn teardown(&mut self) -> Result<()> {
        Ok(())
    }
}
