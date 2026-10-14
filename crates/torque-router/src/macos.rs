//! Transparent routing on macOS.
//!
//! `pf` can redirect to tor's `TransPort` the same way nftables does, so this
//! is closer to the Linux backend than to the Windows one:
//!
//! 1. A small root helper (installed via `SMJobBless` or a launchd daemon)
//!    owns the privileged work; the GUI stays unprivileged.
//! 2. `pf` anchor with `rdr-to` for outbound TCP to `TransPort` and port 53 to
//!    `DNSPort`, with tor's own user excluded.
//! 3. Block remaining UDP and all IPv6.
//!
//! Deliberately not NetworkExtension: a `PacketTunnelProvider` requires
//! membership in the Apple Developer Program and a provisioning profile
//! carrying the network-extension entitlement. The `pf` + root-helper route
//! ships without either.

use crate::{Capabilities, Error, RoutePlan, Result, TrafficRouter};

#[derive(Debug, Default)]
pub struct PacketFilterRouter {
    _private: (),
}

impl TrafficRouter for PacketFilterRouter {
    fn name(&self) -> &'static str {
        "pf"
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
            what: "pf redirect to TransPort via a root helper",
            stage: 7,
        })
    }

    fn teardown(&mut self) -> Result<()> {
        Ok(())
    }
}
