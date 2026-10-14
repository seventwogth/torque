use egui::{Color32, RichText, Ui};
use torque_core::TorState;
use torque_core::bridges::{BridgeLine, ParseError, parse_many, required_transports};
use torque_ipc::RoutingMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Status,
    Circuits,
    Bridges,
    Routing,
    Log,
}

impl Tab {
    const ALL: [Self; 5] = [
        Self::Status,
        Self::Circuits,
        Self::Bridges,
        Self::Routing,
        Self::Log,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Status => "Status",
            Self::Circuits => "Circuits",
            Self::Bridges => "Bridges",
            Self::Routing => "Routing",
            Self::Log => "Log",
        }
    }
}

pub struct TorqueApp {
    tab: Tab,
    /// Last snapshot from the service. Default until stage 4 wires the IPC.
    state: TorState,
    connected: bool,
    routing: RoutingMode,
    bridge_input: String,
    bridge_result: Option<BridgeValidation>,
}

impl Default for TorqueApp {
    fn default() -> Self {
        Self {
            tab: Tab::Status,
            state: TorState::default(),
            connected: false,
            routing: RoutingMode::ProxyOnly,
            bridge_input: String::new(),
            bridge_result: None,
        }
    }
}

struct BridgeValidation {
    bridges: Vec<BridgeLine>,
    errors: Vec<(usize, ParseError)>,
    transports: Vec<String>,
}

impl eframe::App for TorqueApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        egui::Panel::left("nav")
            .exact_size(150.0)
            .resizable(false)
            .show(ui, |ui| {
                ui.add_space(12.0);
                ui.heading("Torque");
                ui.add_space(12.0);
                for tab in Tab::ALL {
                    ui.selectable_value(&mut self.tab, tab, tab.label());
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                            .small()
                            .weak(),
                    );
                });
            });

        egui::Panel::bottom("status-bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                let (color, text) = if self.connected {
                    (Color32::from_rgb(0x3f, 0xb9, 0x50), "service connected")
                } else {
                    (Color32::from_rgb(0xc0, 0x6b, 0x2a), "service not connected")
                };
                ui.colored_label(color, "\u{25cf}");
                ui.label(text);
                ui.separator();
                ui.label(match self.routing {
                    RoutingMode::ProxyOnly => "proxy only",
                    RoutingMode::Transparent => "transparent (not active)",
                });
            });
        });

        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Status => self.status_panel(ui),
            Tab::Circuits => self.circuits_panel(ui),
            Tab::Bridges => self.bridges_panel(ui),
            Tab::Routing => self.routing_panel(ui),
            Tab::Log => self.log_panel(ui),
        });
    }
}

impl TorqueApp {
    fn status_panel(&mut self, ui: &mut Ui) {
        ui.heading("Status");
        ui.add_space(8.0);

        let bootstrap = &self.state.bootstrap;
        let fraction = f32::from(bootstrap.progress) / 100.0;
        ui.add(
            egui::ProgressBar::new(fraction)
                .show_percentage()
                .desired_height(18.0),
        );
        ui.label(if bootstrap.summary.is_empty() {
            "not started".to_owned()
        } else {
            bootstrap.summary.clone()
        });

        ui.add_space(16.0);
        ui.horizontal(|ui| {
            // Not wired until the service exists; shown disabled rather than
            // hidden so the eventual shape of the UI is visible.
            ui.add_enabled_ui(self.connected, |ui| {
                let _ = ui.button("Connect");
                let _ = ui.button("New identity");
            });
        });

        ui.add_space(16.0);
        let sample = self.state.latest_bandwidth();
        ui.label(format!(
            "down {}   up {}",
            human_bytes(sample.read),
            human_bytes(sample.written)
        ));
        ui.add_space(4.0);
        self.bandwidth_graph(ui);
    }

    /// Hand-drawn so the initial build carries no plotting dependency; swap in
    /// `egui_plot` once there is real data worth zooming into.
    fn bandwidth_graph(&self, ui: &mut Ui) {
        let (rect, _) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), 96.0),
            egui::Sense::hover(),
        );
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 4.0, ui.visuals().extreme_bg_color);

        let samples = &self.state.bandwidth;
        if samples.is_empty() {
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "no traffic yet",
                egui::FontId::proportional(12.0),
                ui.visuals().weak_text_color(),
            );
            return;
        }

        let peak = samples
            .iter()
            .map(|sample| sample.read.max(sample.written))
            .max()
            .unwrap_or(1)
            .max(1) as f32;
        let step = rect.width() / torque_core::state::BANDWIDTH_HISTORY as f32;

        let draw = |pick: fn(&torque_core::state::BandwidthSample) -> u64, color: Color32| {
            let stroke = egui::Stroke::new(1.5, color);
            for (index, pair) in samples.iter().collect::<Vec<_>>().windows(2).enumerate() {
                let y = |value: u64| rect.bottom() - (value as f32 / peak) * rect.height() * 0.92;
                let from = egui::pos2(rect.left() + index as f32 * step, y(pick(pair[0])));
                let to = egui::pos2(rect.left() + (index + 1) as f32 * step, y(pick(pair[1])));
                painter.line_segment([from, to], stroke);
            }
        };

        draw(|sample| sample.read, Color32::from_rgb(0x4c, 0x9b, 0xe8));
        draw(|sample| sample.written, Color32::from_rgb(0xd1, 0x8c, 0x3c));
    }

    fn circuits_panel(&mut self, ui: &mut Ui) {
        ui.heading("Circuits");
        ui.add_space(8.0);

        if self.state.circuits.is_empty() {
            ui.label(RichText::new("No circuits. Tor is not running.").weak());
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("circuits")
                .striped(true)
                .num_columns(4)
                .show(ui, |ui| {
                    ui.label(RichText::new("ID").strong());
                    ui.label(RichText::new("Status").strong());
                    ui.label(RichText::new("Path").strong());
                    ui.label(RichText::new("Streams").strong());
                    ui.end_row();

                    for circuit in self.state.circuits.values() {
                        ui.label(&circuit.id);
                        ui.label(&circuit.status);
                        ui.label(circuit.path.join(" \u{2192} "));
                        ui.label(circuit.streams.len().to_string());
                        ui.end_row();
                    }
                });
        });
    }

    fn bridges_panel(&mut self, ui: &mut Ui) {
        ui.heading("Bridges");
        ui.label(
            RichText::new("One bridge line per line, as given by BridgeDB. `#` starts a comment.")
                .weak(),
        );
        ui.add_space(8.0);

        ui.add(
            egui::TextEdit::multiline(&mut self.bridge_input)
                .desired_rows(8)
                .desired_width(f32::INFINITY)
                .code_editor()
                .hint_text("obfs4 192.0.2.1:443 <fingerprint> cert=... iat-mode=0"),
        );

        ui.add_space(8.0);
        if ui.button("Validate").clicked() {
            let (bridges, errors) = parse_many(&self.bridge_input);
            let transports = required_transports(&bridges);
            self.bridge_result = Some(BridgeValidation {
                bridges,
                errors,
                transports,
            });
        }

        if let Some(result) = &self.bridge_result {
            ui.add_space(8.0);
            ui.label(format!(
                "{} valid, {} rejected",
                result.bridges.len(),
                result.errors.len()
            ));

            for (index, error) in &result.errors {
                ui.colored_label(
                    Color32::from_rgb(0xd6, 0x4a, 0x4a),
                    format!("line {}: {error}", index + 1),
                );
            }

            let unauthenticated = result
                .bridges
                .iter()
                .filter(|bridge| bridge.is_unauthenticated())
                .count();
            if unauthenticated > 0 {
                ui.colored_label(
                    Color32::from_rgb(0xc0, 0x6b, 0x2a),
                    format!(
                        "{unauthenticated} bridge(s) carry no fingerprint, so the relay's \
                         identity cannot be verified"
                    ),
                );
            }

            if !result.transports.is_empty() {
                ui.label(format!(
                    "transports required: {}",
                    result.transports.join(", ")
                ));
            }
        }
    }

    fn routing_panel(&mut self, ui: &mut Ui) {
        ui.heading("Routing");
        ui.add_space(8.0);

        ui.radio_value(
            &mut self.routing,
            RoutingMode::ProxyOnly,
            "Proxy only \u{2014} apps opt in via SOCKS",
        );
        ui.radio_value(
            &mut self.routing,
            RoutingMode::Transparent,
            "Transparent \u{2014} route everything through Tor",
        );

        if self.routing == RoutingMode::Transparent {
            ui.add_space(12.0);
            ui.colored_label(
                Color32::from_rgb(0xc0, 0x6b, 0x2a),
                "Experimental: the kill switch is not implemented yet, so traffic can still \
                 leave outside Tor. Do not rely on this mode.",
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Transparent mode needs the privileged service, a TUN adapter and firewall \
                     filters. Until those land, this setting only changes the generated torrc.",
                )
                .weak(),
            );
        }
    }

    fn log_panel(&mut self, ui: &mut Ui) {
        ui.heading("Log");
        ui.add_space(8.0);

        if self.state.log.is_empty() {
            ui.label(RichText::new("Nothing logged yet.").weak());
            return;
        }

        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for entry in &self.state.log {
                    ui.label(format!("{:?}  {}", entry.level, entry.message));
                }
            });
    }
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
        format!("{bytes} B/s")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
