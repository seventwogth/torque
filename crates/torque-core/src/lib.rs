//! The engine behind the UI: configuration, process supervision and the state
//! model, with no dependency on how any of it is displayed.
//!
//! Nothing here is privileged. Installing a kill switch or a TUN device is the
//! job of `torque-router` backends running inside `torque-service`.

mod engine;
mod error;
pub mod paths;
pub mod state;
pub mod torrc;

pub use engine::Engine;
pub use error::{Error, Result};
pub use paths::Layout;
pub use state::TorState;
pub use torrc::{TorConfig, TransportPlugin};

pub use torque_bridges as bridges;
pub use torque_control as control;
pub use torque_router as router;
