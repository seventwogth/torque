//! The single owner of tor and of the routing configuration.
//!
//! Several clients may be connected at once, so the engine lives in one task
//! and everything reaches it as a [`Job`]. Requests carry a `oneshot` for the
//! reply, which keeps request/response pairing out of the sessions and makes
//! concurrent clients harmless.
//!
//! Control events are forwarded into the same mailbox, for the same reasons
//! as in the UI's worker: a plain loop over one receiver, and no borrow of
//! the event stream held across a branch that replaces it.

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use torque_core::bridges::parse_many;
use torque_core::control::Event;
use torque_core::router::{self, RoutingMode};
use torque_core::{Engine, Layout, TorConfig, TorState, TransportPlugin};
use torque_ipc::{
    Bandwidth, BridgeError, Circuit, Request, Response, RoutingMode as WireRoutingMode,
    StartRequest, Status,
};
use torque_policy::Policy;

pub enum Job {
    Request(Request, oneshot::Sender<Response>),
    Event { generation: u64, event: Event },
    StreamEnded { generation: u64 },
}

pub type Mailbox = mpsc::UnboundedSender<Job>;

/// Starts the actor and returns the mailbox sessions post to.
pub fn spawn() -> Mailbox {
    let (jobs, inbox) = mpsc::unbounded_channel();
    let actor = Actor {
        jobs: jobs.clone(),
        state: TorState::default(),
        bridges: Vec::new(),
        policy: Policy::default(),
        routing: RoutingMode::ProxyOnly,
        engine: None,
        forwarder: None,
        generation: 0,
    };
    tokio::spawn(actor.run(inbox));
    jobs
}

struct Actor {
    jobs: Mailbox,
    state: TorState,
    bridges: Vec<String>,
    policy: Policy,
    routing: RoutingMode,
    engine: Option<Engine>,
    forwarder: Option<JoinHandle<()>>,
    generation: u64,
}

impl Actor {
    async fn run(mut self, mut inbox: mpsc::UnboundedReceiver<Job>) {
        while let Some(job) = inbox.recv().await {
            match job {
                Job::Request(request, reply) => {
                    let response = self.handle(request).await;
                    // A client that hung up mid-request is normal.
                    let _ = reply.send(response);
                }
                Job::Event { generation, event } if generation == self.generation => {
                    self.state.apply(&event);
                }
                Job::StreamEnded { generation } if generation == self.generation => {
                    tracing::warn!("tor closed the control connection");
                    self.teardown().await;
                }
                // Leftovers from a previous run.
                Job::Event { .. } | Job::StreamEnded { .. } => {}
            }
        }

        self.teardown().await;
    }

    async fn handle(&mut self, request: Request) -> Response {
        match request {
            // Answered by the session before the actor ever sees it.
            Request::Hello { .. } => Response::Error {
                message: "handshake already completed".to_owned(),
            },

            Request::Status => Response::Status(self.status()),

            Request::Start(StartRequest { routing, bridges }) => {
                if let Err(message) = self.set_routing(routing) {
                    return Response::Error { message };
                }
                if !bridges.is_empty() {
                    if let Some(response) = self.store_bridges(bridges) {
                        return response;
                    }
                }
                self.start().await
            }

            Request::Stop => {
                self.teardown().await;
                Response::Ok
            }

            Request::NewIdentity => match self.engine.as_ref() {
                Some(engine) => match engine.control().new_identity().await {
                    Ok(()) => Response::Ok,
                    Err(error) => Response::Error {
                        message: error.to_string(),
                    },
                },
                None => Response::Error {
                    message: "tor is not running".to_owned(),
                },
            },

            Request::SetBridges { lines } => {
                if let Some(response) = self.store_bridges(lines) {
                    return response;
                }
                self.apply_bridges().await
            }

            Request::SetRoutingMode { mode } => match self.set_routing(mode) {
                Ok(()) => Response::Ok,
                Err(message) => Response::Error { message },
            },

            Request::GetPolicy => self.policy_response(),

            Request::SetPolicy { policy } => {
                // Stored, not enforced: nothing reads these rules until the
                // flow engine exists. `Status::policy_enforced` is what says
                // so, rather than this call pretending to have done more.
                self.policy = policy;
                tracing::info!(
                    rules = self.policy.rules.len(),
                    "routing rules stored; no flow engine is enforcing them yet"
                );
                self.policy_response()
            }
        }
    }

    fn policy_response(&self) -> Response {
        Response::Policy {
            lints: self.policy.lints(),
            policy: self.policy.clone(),
        }
    }

    /// Rejects a mode the platform backend cannot actually deliver, using the
    /// backend's own error rather than a message invented here.
    fn set_routing(&mut self, mode: WireRoutingMode) -> Result<(), String> {
        let mode = from_wire(mode);
        if mode == RoutingMode::Transparent {
            let router = router::transparent_router();
            if !router.capabilities().transparent {
                return Err(format!("{} cannot route transparently", router.name()));
            }
            // The backend exists but is a stub; ask it, and report what it says.
            let plan = router::RoutePlan {
                socks: ([127, 0, 0, 1], 9050).into(),
                dns: ([127, 0, 0, 1], 9053).into(),
                transparent: None,
                block_udp: true,
                block_ipv6: true,
                bypass: Vec::new(),
            };
            let mut router = router;
            if let Err(error) = router.apply(&plan) {
                return Err(error.to_string());
            }
        }
        self.routing = mode;
        Ok(())
    }

    /// `Some(response)` when a line was rejected, so the caller stops.
    fn store_bridges(&mut self, lines: Vec<String>) -> Option<Response> {
        let (_, errors) = parse_many(&lines.join("\n"));
        if !errors.is_empty() {
            return Some(Response::InvalidBridges {
                errors: errors
                    .into_iter()
                    .map(|(index, error)| BridgeError {
                        index,
                        message: error.to_string(),
                    })
                    .collect(),
            });
        }
        self.bridges = lines;
        None
    }

    async fn start(&mut self) -> Response {
        if self.engine.is_some() {
            return Response::Ok;
        }

        let layout = match Layout::discover() {
            Ok(layout) => layout,
            Err(error) => {
                return Response::Error {
                    message: error.to_string(),
                };
            }
        };
        let config = self.config(&layout);

        let mut engine = match Engine::start(&layout, &config).await {
            Ok(engine) => engine,
            Err(error) => {
                return Response::Error {
                    message: error.to_string(),
                };
            }
        };

        self.generation += 1;
        let generation = self.generation;
        if let Some(mut events) = engine.take_events() {
            let jobs = self.jobs.clone();
            self.forwarder = Some(tokio::spawn(async move {
                while let Some(event) = events.recv().await {
                    if jobs.send(Job::Event { generation, event }).is_err() {
                        return;
                    }
                }
                let _ = jobs.send(Job::StreamEnded { generation });
            }));
        }

        self.engine = Some(engine);
        tracing::info!("tor started");
        Response::Ok
    }

    async fn apply_bridges(&mut self) -> Response {
        let Some(engine) = self.engine.as_ref() else {
            return Response::Ok;
        };
        let layout = match Layout::discover() {
            Ok(layout) => layout,
            Err(error) => {
                return Response::Error {
                    message: error.to_string(),
                };
            }
        };
        match engine.apply_bridges(&self.config(&layout)).await {
            Ok(()) => Response::Ok,
            Err(error) => Response::Error {
                message: error.to_string(),
            },
        }
    }

    fn config(&self, layout: &Layout) -> TorConfig {
        let mut config = TorConfig::new(self.routing);
        config.plugins = TransportPlugin::expert_bundle(layout);
        let (bridges, errors) = parse_many(&self.bridges.join("\n"));
        for (index, error) in &errors {
            tracing::warn!("bridge line {}: {error}", index + 1);
        }
        config.bridges = bridges;
        config
    }

    async fn teardown(&mut self) {
        if let Some(forwarder) = self.forwarder.take() {
            forwarder.abort();
        }
        if let Some(engine) = self.engine.take()
            && let Err(error) = engine.shutdown().await
        {
            tracing::warn!(%error, "stopping tor failed");
        }
        self.state = TorState::default();
    }

    fn status(&self) -> Status {
        let bandwidth = self.state.latest_bandwidth();
        Status {
            running: self.engine.is_some(),
            bootstrap_progress: self.state.bootstrap.progress,
            bootstrap_summary: self.state.bootstrap.summary.clone(),
            routing: to_wire(self.routing),
            // Both stay false until something actually enforces them. The
            // wire is where that honesty has to live, because every front end
            // reads it from here.
            kill_switch_active: false,
            policy_enforced: false,
            bandwidth: Bandwidth {
                read: bandwidth.read,
                written: bandwidth.written,
            },
            circuits: self
                .state
                .circuits
                .values()
                .map(|circuit| Circuit {
                    id: circuit.id.clone(),
                    status: circuit.status.clone(),
                    path: circuit.path.clone(),
                    streams: circuit.streams.values().cloned().collect(),
                })
                .collect(),
        }
    }
}

/// The wire enum is kept separate from the router's so the protocol stays
/// plain data; these two functions are the whole cost of that.
fn to_wire(mode: RoutingMode) -> WireRoutingMode {
    match mode {
        RoutingMode::ProxyOnly => WireRoutingMode::ProxyOnly,
        RoutingMode::Transparent => WireRoutingMode::Transparent,
    }
}

fn from_wire(mode: WireRoutingMode) -> RoutingMode {
    match mode {
        WireRoutingMode::ProxyOnly => RoutingMode::ProxyOnly,
        WireRoutingMode::Transparent => RoutingMode::Transparent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_modes_survive_the_round_trip() {
        for mode in [RoutingMode::ProxyOnly, RoutingMode::Transparent] {
            assert_eq!(from_wire(to_wire(mode)), mode);
        }
    }
}
