//! Transparent routing on Linux.
//!
//! Primary path, same as every other platform: a TUN device on the default
//! route, flows terminated in the userspace stack and dispatched by
//! `torque-policy`. nftables provides the kill switch — drop all UDP except
//! what reaches `DNSPort`, drop all IPv6, and permit egress on the physical
//! interface only for tor, its transports and the service.
//!
//! The cheap path, kept as an option for when no per-app rules exist: tor's
//! own `TransPort` does transparent proxying natively, so nftables can
//! redirect in the `nat` table — outbound TCP to `TransPort`, port 53 to
//! `DNSPort` — with `meta skuid != <tor uid>` excluding tor's own traffic.
//! That uid match, not a list of guard addresses, is what prevents the routing
//! loop. This is the Whonix/Tails recipe, and it cannot support rules keyed on
//! a program: `skuid` and cgroup matches are as far as it goes.
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
