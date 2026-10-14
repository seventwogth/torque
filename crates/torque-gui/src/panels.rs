use egui::{Color32, RichText, Ui};
use torque_core::bridges::{BridgeLine, ParseError, parse_many, required_transports};
use torque_core::format::{human_rate, relay_nickname};
use torque_ipc::RoutingMode;

use crate::link::{Command, EngineLink, Mode, Snapshot, Status};

const WARN: Color32 = Color32::from_rgb(0xc0, 0x6b, 0x2a);
const BAD: Color32 = Color32::from_rgb(0xd6, 0x4a, 0x4a);
const GOOD: Color32 = Color32::from_rgb(0x3f, 0xb9, 0x50);
const READ: Color32 = Color32::from_rgb(0x4c, 0x9b, 0xe8);
const WRITTEN: Color32 = Color32::from_rgb(0xd1, 0x8c, 0x3c);

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
    link: EngineLink,
    tab: Tab,
    routing: RoutingMode,
    bridge_input: String,
    bridge_result: Option<BridgeValidation>,
}

impl TorqueApp {
    pub fn new(ctx: &egui::Context) -> Self {
        Self {
            link: EngineLink::spawn(ctx.clone()),
            tab: Tab::Status,
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
        let snapshot = self.link.snapshot();

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
                let (color, text) = match &snapshot.status {
                    Status::Running => (GOOD, "running".to_owned()),
                    Status::Starting => (WARN, "starting".to_owned()),
                    Status::Disconnected => (ui.visuals().weak_text_color(), "stopped".to_owned()),
                    Status::Failed(_) => (BAD, "failed".to_owned()),
                };
                ui.colored_label(color, "\u{25cf}");
                ui.label(text);
                ui.separator();
                ui.label(match &snapshot.mode {
                    Mode::Service { version } => format!("service {version}"),
                    Mode::Unprivileged => "unprivileged".to_owned(),
                });
                ui.separator();
                ui.label(match self.routing {
                    RoutingMode::ProxyOnly => "proxy only",
                    RoutingMode::Transparent => "transparent (not active)",
                });
                if let Some(socks) = snapshot.socks {
                    ui.separator();
                    ui.label(format!("socks {socks}"));
                }
            });
        });

        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Status => self.status_panel(ui, &snapshot),
            Tab::Circuits => self.circuits_panel(ui, &snapshot),
            Tab::Bridges => self.bridges_panel(ui, &snapshot),
            Tab::Routing => self.routing_panel(ui, &snapshot),
            Tab::Log => self.log_panel(ui, &snapshot),
        });
    }
}

impl TorqueApp {
    fn status_panel(&mut self, ui: &mut Ui, snapshot: &Snapshot) {
        ui.heading("Status");
        ui.add_space(8.0);

        let summary = &snapshot.view.bootstrap_summary;
        ui.add(
            egui::ProgressBar::new(f32::from(snapshot.view.bootstrap_progress) / 100.0)
                .show_percentage()
                .desired_height(18.0),
        );

        ui.horizontal(|ui| {
            if snapshot.status.is_busy() {
                ui.spinner();
            }
            ui.label(match &snapshot.status {
                Status::Disconnected => "not started".to_owned(),
                Status::Starting if summary.is_empty() => "launching tor".to_owned(),
                _ if !summary.is_empty() => summary.clone(),
                Status::Running => "connected".to_owned(),
                Status::Starting => "launching tor".to_owned(),
                Status::Failed(_) => String::new(),
            });
        });

        if let Status::Failed(message) = &snapshot.status {
            ui.add_space(8.0);
            ui.colored_label(BAD, message);
            if message.contains("vendor") || message.contains("Expert Bundle") {
                ui.label(
                    RichText::new(
                        "Unpack the Tor Expert Bundle into vendor/, or point \
                         TORQUE_VENDOR_DIR at it.",
                    )
                    .weak(),
                );
            }
        }

        ui.add_space(16.0);
        ui.horizontal(|ui| {
            let running = snapshot.status.is_running();
            ui.add_enabled_ui(!running && !snapshot.status.is_busy(), |ui| {
                if ui.button("Start").clicked() {
                    self.link.send(Command::Start);
                }
            });
            ui.add_enabled_ui(running, |ui| {
                if ui.button("Stop").clicked() {
                    self.link.send(Command::Stop);
                }
                if ui.button("New identity").clicked() {
                    self.link.send(Command::NewIdentity);
                }
            });
        });

        notice(ui, snapshot);

        if !snapshot.tor_version.is_empty() {
            ui.add_space(8.0);
            ui.label(RichText::new(format!("tor {}", snapshot.tor_version)).weak());
        }

        if !snapshot.bridges.is_empty() {
            ui.label(
                RichText::new(format!("via {} bridge(s)", snapshot.bridges.len()))
                    .weak(),
            );
        }

        ui.add_space(16.0);
        let sample = snapshot.view.latest_bandwidth();
        ui.horizontal(|ui| {
            ui.colored_label(READ, "\u{25bc}");
            ui.label(human_rate(sample.read));
            ui.add_space(12.0);
            ui.colored_label(WRITTEN, "\u{25b2}");
            ui.label(human_rate(sample.written));
        });
        ui.add_space(4.0);
        bandwidth_graph(ui, snapshot);
    }

    fn circuits_panel(&mut self, ui: &mut Ui, snapshot: &Snapshot) {
        ui.heading("Circuits");
        ui.add_space(8.0);

        if snapshot.view.circuits.is_empty() {
            ui.label(
                RichText::new(if snapshot.status.is_running() {
                    "No circuits yet."
                } else {
                    "No circuits. Tor is not running."
                })
                .weak(),
            );
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

                    for circuit in &snapshot.view.circuits {
                        ui.label(&circuit.id);
                        ui.label(&circuit.status);
                        ui.label(
                            circuit
                                .path
                                .iter()
                                .map(|hop| relay_nickname(hop))
                                .collect::<Vec<_>>()
                                .join(" \u{2192} "),
                        );
                        // The targets are what makes a circuit legible: which
                        // of them is carrying what.
                        ui.label(if circuit.streams.is_empty() {
                            "\u{2014}".to_owned()
                        } else {
                            circuit.streams.join(", ")
                        });
                        ui.end_row();
                    }
                });
        });
    }

    fn bridges_panel(&mut self, ui: &mut Ui, snapshot: &Snapshot) {
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
        ui.horizontal(|ui| {
            if ui.button("Validate").clicked() {
                self.validate_bridges();
            }

            let usable = self
                .bridge_result
                .as_ref()
                .is_some_and(|result| !result.bridges.is_empty());
            ui.add_enabled_ui(usable, |ui| {
                let label = if snapshot.status.is_running() {
                    "Apply now"
                } else {
                    "Use on next start"
                };
                if ui.button(label).clicked()
                    && let Some(result) = &self.bridge_result
                {
                    self.link.send(Command::SetBridges {
                        lines: result
                            .bridges
                            .iter()
                            .map(BridgeLine::to_bridge_value)
                            .collect(),
                    });
                }
            });

            ui.add_enabled_ui(!snapshot.bridges.is_empty(), |ui| {
                if ui.button("Clear").clicked() {
                    self.link.send(Command::SetBridges { lines: Vec::new() });
                }
            });
        });

        if snapshot.status.is_running() {
            ui.label(
                RichText::new("Applying switches the running tor over; no restart needed.")
                    .small()
                    .weak(),
            );
        }

        notice(ui, snapshot);

        if !snapshot.bridges.is_empty() {
            ui.add_space(8.0);
            ui.label(format!("In use: {} bridge(s)", snapshot.bridges.len()));
            egui::ScrollArea::vertical()
                .max_height(90.0)
                .show(ui, |ui| {
                    for line in &snapshot.bridges {
                        ui.label(RichText::new(line).monospace().small().weak());
                    }
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
                ui.colored_label(BAD, format!("line {}: {error}", index + 1));
            }

            let unauthenticated = result
                .bridges
                .iter()
                .filter(|bridge| bridge.is_unauthenticated())
                .count();
            if unauthenticated > 0 {
                ui.colored_label(
                    WARN,
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

    fn validate_bridges(&mut self) {
        let (bridges, errors) = parse_many(&self.bridge_input);
        let transports = required_transports(&bridges);
        self.bridge_result = Some(BridgeValidation {
            bridges,
            errors,
            transports,
        });
    }

    fn routing_panel(&mut self, ui: &mut Ui, snapshot: &Snapshot) {
        ui.heading("Routing");
        ui.add_space(8.0);

        ui.radio_value(
            &mut self.routing,
            RoutingMode::ProxyOnly,
            "Proxy only \u{2014} apps opt in via SOCKS",
        );

        let service = matches!(snapshot.mode, Mode::Service { .. });
        ui.add_enabled_ui(service, |ui| {
            ui.radio_value(
                &mut self.routing,
                RoutingMode::Transparent,
                "Transparent \u{2014} route everything through Tor",
            );
        });

        if !service {
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Transparent routing needs the privileged service. This session is driving \
                     tor directly, which needs no privileges and can only act as a proxy. Start \
                     torque-service and reopen Torque to use it.",
                )
                .weak(),
            );
            return;
        }

        if self.routing == RoutingMode::Transparent {
            ui.add_space(12.0);
            ui.colored_label(
                WARN,
                "Experimental: the kill switch is not implemented yet, so traffic can still \
                 leave outside Tor. Do not rely on this mode.",
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Transparent mode needs a TUN adapter and firewall filters. Until those \
                     land, the service will refuse this mode rather than half-apply it.",
                )
                .weak(),
            );
        }

        ui.add_space(16.0);
        ui.label(RichText::new("Routing rules").strong());
        ui.label(
            RichText::new(if snapshot.policy_enforced {
                "Rules are being enforced."
            } else {
                "No flow engine is reading routing rules yet, so none are enforced. The editor \
                 arrives with the engine that can act on it."
            })
            .weak(),
        );
    }

    fn log_panel(&mut self, ui: &mut Ui, snapshot: &Snapshot) {
        ui.heading("Log");
        ui.add_space(8.0);

        if snapshot.view.log.is_empty() {
            ui.label(
                RichText::new(match snapshot.mode {
                    // Worth saying which it is: an empty log that cannot fill
                    // looks identical to a quiet one.
                    Mode::Service { .. } => {
                        "The service does not forward tor's log over IPC yet."
                    }
                    Mode::Unprivileged => "Nothing logged yet.",
                })
                .weak(),
            );
            return;
        }

        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for entry in &snapshot.view.log {
                    ui.label(format!("{:?}  {}", entry.level, entry.message));
                }
            });
    }
}

/// The outcome of the last command, where the user just clicked.
fn notice(ui: &mut Ui, snapshot: &Snapshot) {
    let Some(notice) = &snapshot.notice else {
        return;
    };
    ui.add_space(8.0);
    if notice.error {
        ui.colored_label(BAD, &notice.text);
    } else {
        ui.label(RichText::new(&notice.text).weak());
    }
}

/// Hand-drawn so the initial build carries no plotting dependency; swap in
/// `egui_plot` once there is real data worth zooming into.
fn bandwidth_graph(ui: &mut Ui, snapshot: &Snapshot) {
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 96.0), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, ui.visuals().extreme_bg_color);

    let samples = &snapshot.view.bandwidth;
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
    let points: Vec<_> = samples.iter().collect();

    let draw = |pick: fn(&torque_core::state::BandwidthSample) -> u64, color: Color32| {
        let stroke = egui::Stroke::new(1.5, color);
        for (index, pair) in points.windows(2).enumerate() {
            let y = |value: u64| rect.bottom() - (value as f32 / peak) * rect.height() * 0.92;
            let from = egui::pos2(rect.left() + index as f32 * step, y(pick(pair[0])));
            let to = egui::pos2(rect.left() + (index + 1) as f32 * step, y(pick(pair[1])));
            painter.line_segment([from, to], stroke);
        }
    };

    draw(|sample| sample.read, READ);
    draw(|sample| sample.written, WRITTEN);
}
