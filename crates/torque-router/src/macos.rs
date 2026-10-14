//! Transparent routing on macOS.
//!
//! 1. A small root helper (installed via `SMJobBless` or a launchd daemon)
//!    owns the privileged work; the GUI stays unprivileged.
//! 2. A `utun` device on the default route, with flows terminated in the
//!    userspace stack and dispatched by `torque-policy`.
//! 3. A `pf` anchor as the kill switch: block remaining UDP and all IPv6,
//!    permit egress only for tor, its transports and the service.
//!
//! `pf` can also `rdr-to` tor's `TransPort` directly, which is cheaper and is
//! kept as a fast path for the no-rules case. It cannot back per-app rules at
//! all: unlike nftables, `pf` has no notion of the process behind a flow.
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
