//! How traffic reaches Tor.
//!
//! This is the seam between "Tor is a proxy you point apps at" and "everything
//! on this machine goes through Tor, subject to rules".
//!
//! Every backend puts a TUN device on the default route and terminates flows
//! in a userspace TCP/IP stack, because per-app routing rules need to know
//! which program opened a flow — something a kernel redirect cannot tell us
//! without a signed driver. Tor's native `TransPort` stays available as a fast
//! path only where no rules are configured.
//!
//! | OS      | TUN device                      | firewall |
//! |---------|---------------------------------|----------|
//! | Windows | Wintun (`wintun.dll`, signed)   | WFP      |
//! | Linux   | `/dev/net/tun`                  | nftables |
//! | macOS   | `utun` via a root helper        | `pf`     |

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A backend exists but is not finished yet; `stage` points at the
    /// roadmap step in ARCHITECTURE.md that delivers it.
    #[error("{what} is not implemented yet (roadmap stage {stage})")]
    NotImplemented { what: &'static str, stage: u8 },

    #[error("transparent routing needs elevated privileges")]
    PrivilegesRequired,

    #[error("routing backend failed: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RoutingMode {
    /// Tor listens on SOCKS; apps opt in. No privileges, no leak risk beyond
    /// whatever the user misconfigures.
    #[default]
    ProxyOnly,
    /// Everything is forced through Tor, with a kill switch. Needs elevation.
    Transparent,
}

impl fmt::Display for RoutingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProxyOnly => f.write_str("proxy only"),
            Self::Transparent => f.write_str("transparent"),
        }
    }
}

/// What a backend should enforce once Tor is up.
#[derive(Debug, Clone)]
pub struct RoutePlan {
    pub socks: SocketAddr,
    /// Tor's `DNSPort`. Mandatory in transparent mode: Tor carries no UDP, so
    /// resolution has to be funnelled here or it leaks.
    pub dns: SocketAddr,
    /// Tor's `TransPort`, where the platform supports it.
    pub transparent: Option<SocketAddr>,
    /// Block UDP outright. Tor cannot carry it, and QUIC on 443 must be
    /// blocked explicitly or browsers hang instead of falling back to TCP.
    pub block_udp: bool,
    /// Block IPv6 outright; transparent IPv6 is out of scope for 1.0.
    pub block_ipv6: bool,
    /// Executables allowed to bypass the tunnel — tor itself and its
    /// transports. Matching on the process, not on the guard's IP, is what
    /// makes the kill switch hold when guards rotate.
    ///
    /// Once `torque-policy` lands (stage 5) the service joins this list, since
    /// a `Direct` rule makes it egress on an app's behalf. That is also when
    /// the kill switch stops being a firewall-only guarantee.
    pub bypass: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub transparent: bool,
    pub kill_switch: bool,
    pub needs_elevation: bool,
}

pub trait TrafficRouter: Send {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;
    /// Installs the plan. Must be idempotent: the UI re-applies on reconnect.
    fn apply(&mut self, plan: &RoutePlan) -> Result<()>;
    /// Removes everything `apply` installed. Called on shutdown *and* on a
    /// failed `apply`, so it must tolerate partial state.
    fn teardown(&mut self) -> Result<()>;
}

/// The mode that needs no privileges: Tor listens, apps opt in, we touch
/// nothing. This is the only backend complete today.
#[derive(Debug, Default)]
pub struct ProxyOnlyRouter {
    plan: Option<RoutePlan>,
}

impl TrafficRouter for ProxyOnlyRouter {
    fn name(&self) -> &'static str {
        "proxy-only"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            transparent: false,
            kill_switch: false,
            needs_elevation: false,
        }
    }

    fn apply(&mut self, plan: &RoutePlan) -> Result<()> {
        tracing::info!(socks = %plan.socks, "proxy-only routing: tor is listening, nothing to install");
        self.plan = Some(plan.clone());
        Ok(())
    }

    fn teardown(&mut self) -> Result<()> {
        self.plan = None;
        Ok(())
    }
}

/// The transparent backend for this platform.
///
/// Every one of these is a stub today; see ARCHITECTURE.md stages 5 and 6.
pub fn transparent_router() -> Box<dyn TrafficRouter> {
    #[cfg(target_os = "windows")]
    return Box::new(windows::WintunRouter::default());
    #[cfg(target_os = "linux")]
    return Box::new(linux::NftablesRouter::default());
    #[cfg(target_os = "macos")]
    return Box::new(macos::PacketFilterRouter::default());
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    return Box::new(ProxyOnlyRouter::default());
}

pub fn router_for(mode: RoutingMode) -> Box<dyn TrafficRouter> {
    match mode {
        RoutingMode::ProxyOnly => Box::new(ProxyOnlyRouter::default()),
        RoutingMode::Transparent => transparent_router(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> RoutePlan {
        RoutePlan {
            socks: "127.0.0.1:9050".parse().unwrap(),
            dns: "127.0.0.1:9053".parse().unwrap(),
            transparent: None,
            block_udp: true,
            block_ipv6: true,
            bypass: Vec::new(),
        }
    }

    #[test]
    fn proxy_only_router_is_a_noop() {
        let mut router = ProxyOnlyRouter::default();
        assert!(!router.capabilities().needs_elevation);
        router.apply(&plan()).expect("proxy-only always applies");
        router.teardown().expect("teardown always succeeds");
    }

    #[test]
    fn transparent_router_reports_its_gap_rather_than_pretending() {
        let mut router = transparent_router();
        let error = router.apply(&plan()).expect_err("not implemented yet");
        assert!(matches!(error, Error::NotImplemented { .. }));
        // Teardown must stay safe to call after a failed apply.
        router.teardown().expect("teardown tolerates partial state");
    }
}
