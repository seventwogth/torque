//! Headless Torque.
//!
//! This is roadmap stage 1: it exercises the whole engine — torrc generation,
//! process supervision, cookie auth, the event stream and the state model —
//! without any UI in the way. When something breaks, check here first.
//!
//! Usage:
//!   torque-cli                       proxy-only, no bridges
//!   torque-cli bridges.txt           one bridge line per line, `#` comments
//!
//! Requires the Tor Expert Bundle unpacked into `vendor/`.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use torque_core::bridges::parse_many;
use torque_core::control::Event;
use torque_core::router::RoutingMode;
use torque_core::{Engine, Layout, TorConfig, TorState, TransportPlugin};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let layout = Layout::discover().context("locating data and vendor directories")?;
    let mut config = TorConfig::new(RoutingMode::ProxyOnly);
    config.plugins = TransportPlugin::expert_bundle(&layout);

    if let Some(path) = std::env::args().nth(1).map(PathBuf::from) {
        let text = tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("reading bridge lines from {}", path.display()))?;
        let (bridges, errors) = parse_many(&text);
        for (index, error) in &errors {
            tracing::warn!("line {}: {error}", index + 1);
        }
        if bridges.is_empty() {
            bail!("no usable bridge lines in {}", path.display());
        }
        tracing::info!("using {} bridge(s)", bridges.len());
        config.bridges = bridges;
    }

    println!("data:   {}", layout.data_dir.display());
    println!("vendor: {}", layout.vendor_dir.display());

    let mut engine = Engine::start(&layout, &config)
        .await
        .context("starting tor")?;
    let control = engine.control();
    let mut events = engine.take_events().expect("first caller takes the events");

    let mut state = TorState::default();
    let mut bootstrapped = false;

    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else {
                    bail!("tor closed the control connection");
                };
                state.apply(&event);

                match &event {
                    Event::Bootstrap { progress, summary, .. } if !bootstrapped => {
                        println!("[{progress:>3}%] {summary}");
                        if state.bootstrap.is_done() {
                            bootstrapped = true;
                            let version = control.get_info("version").await.unwrap_or_default();
                            println!("\nconnected; tor {version}");
                            println!("socks: 127.0.0.1:{}\n", config.socks_port);
                        }
                    }
                    Event::Bandwidth { read, written } if bootstrapped => {
                        println!(
                            "down {:>8} up {:>8}   circuits {}",
                            human_bytes(*read),
                            human_bytes(*written),
                            state.built_circuits().count(),
                        );
                    }
                    Event::Log { level, message } => {
                        tracing::debug!(?level, "{message}");
                    }
                    _ => {}
                }
            }

            _ = tokio::signal::ctrl_c() => {
                println!("\nstopping tor");
                break;
            }
        }
    }

    engine.shutdown().await.context("stopping tor")?;
    Ok(())
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B/s", "KiB/s", "MiB/s", "GiB/s"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
