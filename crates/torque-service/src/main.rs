//! The privileged half of Torque.
//!
//! It owns everything that needs elevation — the TUN adapter, routes, firewall
//! filters — plus the tor process itself, so the GUI can run as a normal user
//! and survive being closed without taking Tor down.
//!
//! Today it runs in the foreground and keeps the shared state the GUI will
//! read. Still to come:
//!   - stage 4: listen on `torque_ipc::endpoint()`, ACL the endpoint, and
//!     serve `Request`/`Response`; register as a Windows service, a systemd
//!     unit and a launchd daemon.
//!   - stage 5/6: drive `torque_router` backends and refuse to report a kill
//!     switch as active unless the backend actually installed one.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use torque_core::router::RoutingMode;
use torque_core::{Engine, Layout, TorConfig, TorState, TransportPlugin};

/// The snapshot the IPC layer will serve. Written by one task, read by many.
type SharedState = Arc<RwLock<TorState>>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        protocol = torque_ipc::PROTOCOL_VERSION,
        endpoint = %torque_ipc::endpoint(),
        "torque service starting"
    );

    let layout = Layout::discover().context("locating data and vendor directories")?;
    let mut config = TorConfig::new(RoutingMode::ProxyOnly);
    config.plugins = TransportPlugin::expert_bundle(&layout);

    let mut engine = Engine::start(&layout, &config)
        .await
        .context("starting tor")?;
    let mut events = engine.take_events().expect("first caller takes the events");

    let state: SharedState = Arc::new(RwLock::new(TorState::default()));
    let writer = Arc::clone(&state);
    let pump = tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            writer.write().await.apply(&event);
        }
        tracing::warn!("control event stream ended");
    });

    tokio::signal::ctrl_c().await.context("waiting for ctrl-c")?;
    tracing::info!("shutting down");

    pump.abort();
    engine.shutdown().await.context("stopping tor")?;
    Ok(())
}
