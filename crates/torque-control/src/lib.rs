//! An async client for the Tor control protocol.
//!
//! This crate is the reason Torque drives a bundled C-tor rather than
//! embedding Arti: the control protocol already exposes, as a stable API,
//! everything the UI wants to show or change —
//!
//! - `BW` events for the bandwidth graph,
//! - `CIRC` / `STREAM` events plus `GETINFO circuit-status` for the circuit list,
//! - `SETCONF Bridge/UseBridges/ClientTransportPlugin` to switch bridges and
//!   transports without restarting tor,
//! - `SIGNAL NEWNYM` for a new identity.
//!
//! Reference: tor's `control-spec.txt`.

mod auth;
mod client;
mod error;
mod event;
mod reply;

pub use auth::AuthMethod;
pub use client::{ControlClient, EventStream};
pub use error::{Error, Result};
pub use event::{CircuitEvent, Event, LogLevel, StreamEvent};
pub use reply::{Reply, ReplyLine, quote};

/// Events Torque subscribes to on connect.
pub const DEFAULT_EVENTS: &[&str] = &["BW", "CIRC", "STREAM", "STATUS_CLIENT", "NOTICE", "WARN", "ERR"];
