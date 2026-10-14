//! The privileged half of Torque.
//!
//! It owns tor and, from stage 5, everything that needs elevation: the TUN
//! device, routes, firewall filters. Keeping it separate is what lets the UI
//! run as a normal user and lets Tor survive the window being closed.
//!
//! Today it runs in the foreground and unelevated, which is enough for
//! proxy-only mode — nothing it does yet requires privileges. Still to come:
//!   - stage 5/6: drive `torque_router` backends, and with elevation, the
//!     explicit endpoint ACL that an elevated service needs (see
//!     `torque_ipc::transport`).
//!   - stage 8: registration as a Windows service, a systemd unit and a
//!     launchd daemon, so it starts without a terminal.

mod actor;
mod session;

use anyhow::{Context, Result};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut listener = torque_ipc::Listener::bind()
        .await
        .with_context(|| format!("binding {}", torque_ipc::endpoint()))?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        protocol = torque_ipc::PROTOCOL_VERSION,
        endpoint = %torque_ipc::endpoint(),
        // Stated rather than assumed: this is the access boundary in force.
        access = "the user running this service",
        "torque service listening"
    );

    let jobs = actor::spawn();

    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(connection) => {
                    tracing::debug!("client connected");
                    tokio::spawn(session::serve(connection, jobs.clone()));
                }
                Err(error) => tracing::warn!(%error, "rejecting a connection"),
            },

            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    stop_tor(&jobs).await;
    // Dropping the mailbox ends the actor once the sessions holding clones
    // are gone. Tor would exit anyway when this process does — TAKEOWNERSHIP
    // ties its life to the control connection — but asking first means a
    // clean exit rather than relying on that backstop.
    drop(jobs);
    Ok(())
}

async fn stop_tor(jobs: &actor::Mailbox) {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    if jobs
        .send(actor::Job::Request(torque_ipc::Request::Stop, reply_tx))
        .is_err()
    {
        return;
    }
    match tokio::time::timeout(std::time::Duration::from_secs(10), reply_rx).await {
        Ok(Ok(_)) => tracing::info!("tor stopped"),
        Ok(Err(_)) => {}
        Err(_) => tracing::warn!("tor did not stop within 10s; exiting anyway"),
    }
}
