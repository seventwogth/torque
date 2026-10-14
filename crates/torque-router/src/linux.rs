//! Transparent routing on Linux — the cheap platform.
//!
//! No TUN device and no userspace TCP/IP stack are needed: tor's own
//! `TransPort` does transparent proxying natively. This is the Whonix/Tails
//! recipe:
//!
//! 1. Run tor under its own uid.
//! 2. nftables in the `nat` table: redirect outbound TCP to `TransPort` and
//!    outbound port 53 to `DNSPort`, with `meta skuid != <tor uid>` so tor's
//!    own traffic is excluded — that, not a list of guard addresses, is what
//!    prevents the routing loop.
//! 3. In the `filter` table: drop all other UDP and all IPv6, so nothing
//!    escapes while Tor is up.
//!
//! Needs `CAP_NET_ADMIN`, which is why it lives in the privileged service.

use crate::{Capabilities, Error, RoutePlan, Result, TrafficRouter};

#[derive(Debug, Default)]
pub struct NftablesRouter {
    _private: (),
}

impl TrafficRouter for NftablesRouter {
    fn name(&self) -> &'static str {
        "nftables"
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
            what: "nftables redirect to TransPort",
            stage: 7,
        })
    }

    fn teardown(&mut self) -> Result<()> {
        Ok(())
    }
}
