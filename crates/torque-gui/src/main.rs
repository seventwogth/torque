//! Torque's desktop UI.
//!
//! egui is immediate-mode and synchronous, while the engine is async. The seam
//! is deliberate and must stay: the UI never awaits anything. Once the service
//! exists (stage 4) a background thread owns the connection and pushes
//! snapshots over a channel, calling `ctx.request_repaint()`; `update` only
//! ever reads the newest snapshot.
//!
//! Today nothing is connected, so the panels render an explicitly disconnected
//! state — except the bridge editor, whose validation is real and local.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod panels;

use egui::ViewportBuilder;

use crate::panels::TorqueApp;

fn main() -> eframe::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_inner_size([1000.0, 660.0])
            .with_min_inner_size([760.0, 480.0])
            .with_title("Torque"),
        ..Default::default()
    };

    eframe::run_native(
        "Torque",
        options,
        Box::new(|_cc| Ok(Box::new(TorqueApp::default()))),
    )
}
