//! The snapshot the UI renders, rebuilt from control-protocol events.

use std::collections::{BTreeMap, VecDeque};

use torque_control::{Event, LogLevel};

/// Samples kept for the bandwidth graph: two minutes at one `BW` per second.
pub const BANDWIDTH_HISTORY: usize = 120;
/// Log lines kept in memory for the log pane.
pub const LOG_HISTORY: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bootstrap {
    pub progress: u8,
    pub tag: String,
    pub summary: String,
}

impl Bootstrap {
    pub fn is_done(&self) -> bool {
        self.progress >= 100
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BandwidthSample {
    pub read: u64,
    pub written: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Circuit {
    pub id: String,
    pub status: String,
    pub path: Vec<String>,
    pub purpose: Option<String>,
    /// Targets of the streams currently attached, for "what is using this
    /// circuit" in the UI.
    pub streams: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct TorState {
    pub bootstrap: Bootstrap,
    pub circuits: BTreeMap<String, Circuit>,
    pub bandwidth: VecDeque<BandwidthSample>,
    pub log: VecDeque<LogEntry>,
}

impl TorState {
    pub fn apply(&mut self, event: &Event) {
        match event {
            Event::Bootstrap {
                progress,
                tag,
                summary,
            } => {
                self.bootstrap = Bootstrap {
                    progress: *progress,
                    tag: tag.clone(),
                    summary: summary.clone(),
                };
            }

            Event::Bandwidth { read, written } => {
                if self.bandwidth.len() == BANDWIDTH_HISTORY {
                    self.bandwidth.pop_front();
                }
                self.bandwidth.push_back(BandwidthSample {
                    read: *read,
                    written: *written,
                });
            }

            Event::Circuit(circuit) => {
                if matches!(circuit.status.as_str(), "CLOSED" | "FAILED") {
                    self.circuits.remove(&circuit.id);
                    return;
                }
                let entry = self
                    .circuits
                    .entry(circuit.id.clone())
                    .or_insert_with(|| Circuit {
                        id: circuit.id.clone(),
                        status: circuit.status.clone(),
                        path: Vec::new(),
                        purpose: None,
                        streams: BTreeMap::new(),
                    });
                entry.status = circuit.status.clone();
                // A LAUNCHED event carries no path; keep what we had.
                if !circuit.path.is_empty() {
                    entry.path = circuit.path.clone();
                }
                if circuit.purpose.is_some() {
                    entry.purpose = circuit.purpose.clone();
                }
            }

            Event::Stream(stream) => {
                let closed = matches!(stream.status.as_str(), "CLOSED" | "FAILED");
                for circuit in self.circuits.values_mut() {
                    circuit.streams.remove(&stream.id);
                }
                if !closed {
                    if let Some(circuit) = self.circuits.get_mut(&stream.circuit_id) {
                        circuit
                            .streams
                            .insert(stream.id.clone(), stream.target.clone());
                    }
                }
            }

            Event::Log { level, message } => {
                if self.log.len() == LOG_HISTORY {
                    self.log.pop_front();
                }
                self.log.push_back(LogEntry {
                    level: *level,
                    message: message.clone(),
                });
            }

            Event::Other { .. } => {}
        }
    }

    pub fn latest_bandwidth(&self) -> BandwidthSample {
        self.bandwidth.back().copied().unwrap_or_default()
    }

    /// Circuits that carry user traffic, newest id last.
    pub fn built_circuits(&self) -> impl Iterator<Item = &Circuit> {
        self.circuits
            .values()
            .filter(|circuit| circuit.status == "BUILT")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use torque_control::{CircuitEvent, StreamEvent};

    fn circuit_event(id: &str, status: &str, path: &[&str]) -> Event {
        Event::Circuit(CircuitEvent {
            id: id.to_owned(),
            status: status.to_owned(),
            path: path.iter().map(|hop| (*hop).to_owned()).collect(),
            purpose: Some("GENERAL".to_owned()),
            reason: None,
        })
    }

    #[test]
    fn tracks_bootstrap_progress() {
        let mut state = TorState::default();
        state.apply(&Event::Bootstrap {
            progress: 100,
            tag: "done".to_owned(),
            summary: "Done".to_owned(),
        });
        assert!(state.bootstrap.is_done());
    }

    #[test]
    fn bandwidth_history_is_bounded() {
        let mut state = TorState::default();
        for index in 0..(BANDWIDTH_HISTORY + 10) {
            state.apply(&Event::Bandwidth {
                read: index as u64,
                written: 0,
            });
        }
        assert_eq!(state.bandwidth.len(), BANDWIDTH_HISTORY);
        assert_eq!(state.latest_bandwidth().read, (BANDWIDTH_HISTORY + 9) as u64);
    }

    #[test]
    fn keeps_path_across_updates_that_omit_it() {
        let mut state = TorState::default();
        state.apply(&circuit_event("1", "EXTENDED", &["$A~guard", "$B~middle"]));
        state.apply(&circuit_event("1", "BUILT", &[]));

        let circuit = &state.circuits["1"];
        assert_eq!(circuit.status, "BUILT");
        assert_eq!(circuit.path.len(), 2);
        assert_eq!(state.built_circuits().count(), 1);
    }

    #[test]
    fn drops_closed_circuits() {
        let mut state = TorState::default();
        state.apply(&circuit_event("1", "BUILT", &["$A~guard"]));
        state.apply(&circuit_event("1", "CLOSED", &[]));
        assert!(state.circuits.is_empty());
    }

    #[test]
    fn moves_streams_between_circuits_and_removes_closed_ones() {
        let mut state = TorState::default();
        state.apply(&circuit_event("1", "BUILT", &["$A~guard"]));
        state.apply(&circuit_event("2", "BUILT", &["$B~guard"]));

        let attach = |circuit: &str, status: &str| {
            Event::Stream(StreamEvent {
                id: "7".to_owned(),
                status: status.to_owned(),
                circuit_id: circuit.to_owned(),
                target: "example.com:443".to_owned(),
            })
        };

        state.apply(&attach("1", "SUCCEEDED"));
        assert_eq!(state.circuits["1"].streams.len(), 1);

        state.apply(&attach("2", "SUCCEEDED"));
        assert!(state.circuits["1"].streams.is_empty());
        assert_eq!(state.circuits["2"].streams.len(), 1);

        state.apply(&attach("2", "CLOSED"));
        assert!(state.circuits["2"].streams.is_empty());
    }

    #[test]
    fn log_history_is_bounded() {
        let mut state = TorState::default();
        for index in 0..(LOG_HISTORY + 5) {
            state.apply(&Event::Log {
                level: LogLevel::Notice,
                message: index.to_string(),
            });
        }
        assert_eq!(state.log.len(), LOG_HISTORY);
    }
}
