//! The protocol between the GUI and the privileged service.
//!
//! Transparent routing needs a TUN device, routes and firewall filters, so
//! something must run elevated — but it must not be the GUI. The split mirrors
//! `wireguard-windows`: a service owns the privileged work, the UI runs as the
//! user and talks to it over a local transport.
//!
//! Transport is newline-delimited JSON over a Windows named pipe (with an ACL
//! restricting it to the installing user) or a Unix socket (with peer
//! credentials checked). Framing lives here so both ends agree on it.
//!
//! Deliberately plain data: no types from `torque-core` cross this boundary,
//! so the service can be upgraded without the GUI's types following along.

use serde::{Deserialize, Serialize};

/// Bumped whenever the message shapes change; both ends refuse a mismatch
/// rather than guessing.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    #[default]
    ProxyOnly,
    Transparent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// Protocol handshake; must be the first message.
    Hello { version: u32 },
    Status,
    Start(StartRequest),
    Stop,
    NewIdentity,
    /// Bridge lines as the user typed them; the service parses and validates.
    SetBridges { lines: Vec<String> },
    SetRoutingMode { mode: RoutingMode },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StartRequest {
    pub routing: RoutingMode,
    pub bridges: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    Hello {
        version: u32,
        service_version: String,
    },
    Ok,
    Status(Status),
    /// A rejected bridge line, reported with the index the GUI should mark.
    InvalidBridges {
        errors: Vec<BridgeError>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeError {
    pub index: usize,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Status {
    pub running: bool,
    pub bootstrap_progress: u8,
    pub bootstrap_summary: String,
    pub routing: RoutingMode,
    /// False while transparent mode is requested but its kill switch is not
    /// actually installed — the UI must not claim protection it lacks.
    pub kill_switch_active: bool,
    pub bandwidth: Bandwidth,
    pub circuits: Vec<Circuit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Bandwidth {
    pub read: u64,
    pub written: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Circuit {
    pub id: String,
    pub status: String,
    pub path: Vec<String>,
    pub streams: Vec<String>,
}

/// Encodes one message as a newline-terminated JSON frame.
pub fn encode<T: Serialize>(message: &T) -> serde_json::Result<String> {
    let mut frame = serde_json::to_string(message)?;
    frame.push('\n');
    Ok(frame)
}

pub fn decode<T: for<'de> Deserialize<'de>>(frame: &str) -> serde_json::Result<T> {
    serde_json::from_str(frame.trim_end())
}

/// Where the service listens. The name is fixed so the GUI can find it, and
/// access control is done with an ACL on the endpoint, not by obscurity.
pub fn endpoint() -> String {
    if cfg!(windows) {
        r"\\.\pipe\torque".to_owned()
    } else {
        "/run/torque/torque.sock".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let request = Request::SetBridges {
            lines: vec!["obfs4 192.0.2.1:443 ABCD".to_owned()],
        };
        let frame = encode(&request).expect("serializable");
        assert!(frame.ends_with('\n'));
        assert_eq!(decode::<Request>(&frame).expect("decodable"), request);
    }

    #[test]
    fn requests_are_externally_tagged_for_forward_compatibility() {
        let frame = encode(&Request::Status).expect("serializable");
        assert!(frame.contains(r#""request":"status""#));
    }

    #[test]
    fn status_defaults_to_unprotected() {
        let status = Status::default();
        assert!(!status.running);
        assert!(!status.kill_switch_active);
        assert_eq!(status.routing, RoutingMode::ProxyOnly);
    }
}
