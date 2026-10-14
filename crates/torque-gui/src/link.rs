//! The seam between the synchronous UI and the asynchronous engine.
//!
//! A dedicated thread owns a tokio runtime and the [`Engine`]; the UI owns
//! neither and never awaits. Communication is one channel each way: commands
//! in, and a `watch` carrying the newest [`Snapshot`] out. After publishing,
//! the worker calls `request_repaint` so the UI wakes up on its own.
//!
//! There is deliberately no `select!` here. Control events are forwarded into
//! the same mailbox the commands arrive on, which keeps the worker a plain
//! loop over one receiver — and avoids holding a borrow of the event stream
//! across a branch that needs to replace it.
//!
//! Until the privileged service lands (stage 4) the UI drives the engine
//! directly. When it does, only this module changes: the worker will hold an
//! IPC connection instead of an `Engine`, and the UI will not notice.

use std::net::SocketAddr;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use torque_core::bridges::parse_many;
use torque_core::control::Event;
use torque_core::router::RoutingMode;
use torque_core::{Engine, Layout, TorConfig, TorState, TransportPlugin};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    Disconnected,
    /// Tor is launching: the window between `Start` and the control
    /// connection being authenticated, which can take seconds.
    Starting,
    Running,
    /// Startup or the connection failed. Carries what to show the user —
    /// usually a missing binary or a torrc tor rejected.
    Failed(String),
}

impl Status {
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Starting)
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }
}

/// The outcome of the last command, for things that are worth telling the
/// user but do not change whether tor is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub error: bool,
    pub text: String,
}

/// Everything the UI renders, as of the last change.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub status: Status,
    pub state: TorState,
    pub tor_version: String,
    pub socks: Option<SocketAddr>,
    /// The bridge set in effect, or the one the next start will use. The
    /// worker owns this, so the UI has one source of truth rather than its
    /// own copy that can drift.
    pub bridges: Vec<String>,
    pub notice: Option<Notice>,
}

#[derive(Debug, Clone)]
pub enum Command {
    Start,
    Stop,
    NewIdentity,
    /// Replace the bridge set: applied to a running tor without restarting
    /// it, or remembered for the next start. Invalid lines are dropped with a
    /// log line, since the UI validates before sending.
    SetBridges { lines: Vec<String> },
}

/// Commands and forwarded control events share one mailbox.
enum Message {
    Command(Command),
    /// `generation` identifies the engine run this event came from, so events
    /// still in flight from a stopped tor cannot pollute the next run.
    Event { generation: u64, event: Event },
    StreamEnded { generation: u64 },
}

/// The UI's handle on the worker.
pub struct EngineLink {
    mailbox: mpsc::UnboundedSender<Message>,
    snapshot: watch::Receiver<Snapshot>,
}

impl EngineLink {
    pub fn spawn(ctx: egui::Context) -> Self {
        let (mailbox_tx, mailbox_rx) = mpsc::unbounded_channel();
        let (snapshot_tx, snapshot_rx) = watch::channel(Snapshot::default());

        let mailbox_for_worker = mailbox_tx.clone();
        std::thread::Builder::new()
            .name("torque-engine".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        // Without a runtime there is no engine; say so in the
                        // UI rather than leaving it stuck on "disconnected".
                        let _ = snapshot_tx.send(Snapshot {
                            status: Status::Failed(format!("cannot start runtime: {error}")),
                            ..Snapshot::default()
                        });
                        ctx.request_repaint();
                        return;
                    }
                };
                runtime.block_on(
                    Worker::new(ctx, snapshot_tx, mailbox_for_worker).run(mailbox_rx),
                );
            })
            .expect("spawning the engine thread");

        Self {
            mailbox: mailbox_tx,
            snapshot: snapshot_rx,
        }
    }

    pub fn send(&self, command: Command) {
        if self.mailbox.send(Message::Command(command)).is_err() {
            tracing::error!("engine thread is gone; command dropped");
        }
    }

    /// The newest snapshot. Cheap enough to call once per frame.
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot.borrow().clone()
    }
}

struct Worker {
    ctx: egui::Context,
    snapshot: watch::Sender<Snapshot>,
    mailbox: mpsc::UnboundedSender<Message>,
    status: Status,
    state: TorState,
    tor_version: String,
    socks: Option<SocketAddr>,
    bridges: Vec<String>,
    notice: Option<Notice>,
    engine: Option<Engine>,
    forwarder: Option<JoinHandle<()>>,
    generation: u64,
}

impl Worker {
    fn new(
        ctx: egui::Context,
        snapshot: watch::Sender<Snapshot>,
        mailbox: mpsc::UnboundedSender<Message>,
    ) -> Self {
        Self {
            ctx,
            snapshot,
            mailbox,
            status: Status::Disconnected,
            state: TorState::default(),
            tor_version: String::new(),
            socks: None,
            bridges: Vec::new(),
            notice: None,
            engine: None,
            forwarder: None,
            generation: 0,
        }
    }

    async fn run(mut self, mut mailbox: mpsc::UnboundedReceiver<Message>) {
        while let Some(message) = mailbox.recv().await {
            match message {
                Message::Command(command) => self.handle(command).await,

                Message::Event { generation, event } if generation == self.generation => {
                    self.state.apply(&event);
                    self.publish();
                }

                Message::StreamEnded { generation } if generation == self.generation => {
                    if self.status.is_running() {
                        self.status =
                            Status::Failed("tor closed the control connection".to_owned());
                        self.publish();
                    }
                }

                // Leftovers from a previous run.
                Message::Event { .. } | Message::StreamEnded { .. } => {}
            }
        }

        if let Some(engine) = self.engine.take()
            && let Err(error) = engine.shutdown().await
        {
            tracing::warn!(%error, "stopping tor on exit failed");
        }
    }

    async fn handle(&mut self, command: Command) {
        match command {
            Command::Start => self.start().await,
            Command::Stop => self.stop().await,
            Command::SetBridges { lines } => self.set_bridges(lines).await,
            Command::NewIdentity => {
                let Some(engine) = self.engine.as_ref() else {
                    return;
                };
                match engine.control().new_identity().await {
                    Ok(()) => self.notify(false, "New identity requested."),
                    Err(error) => self.notify(true, format!("NEWNYM failed: {error}")),
                }
            }
        }
    }

    /// Replaces the bridge set. Live when tor is running, so the user does not
    /// have to restart to try a different transport.
    async fn set_bridges(&mut self, lines: Vec<String>) {
        self.bridges = lines;

        let Some(engine) = self.engine.as_ref() else {
            let message = if self.bridges.is_empty() {
                "Bridges cleared; the next start will connect directly.".to_owned()
            } else {
                format!(
                    "{} bridge(s) stored for the next start.",
                    self.bridges.len()
                )
            };
            return self.notify(false, message);
        };

        let layout = match Layout::discover() {
            Ok(layout) => layout,
            Err(error) => return self.notify(true, error.to_string()),
        };
        let config = self.config(&layout);

        match engine.apply_bridges(&config).await {
            // Deliberately not resetting the local bootstrap state: tor does
            // not necessarily re-emit a bootstrap event here, and a progress
            // bar reset to zero that never moves again is worse than one that
            // keeps the last known value.
            Ok(()) if config.bridges.is_empty() => {
                self.notify(false, "Bridges disabled on the running tor.")
            }
            Ok(()) => self.notify(
                false,
                format!(
                    "{} bridge(s) applied; tor is rebuilding circuits.",
                    config.bridges.len()
                ),
            ),
            Err(error) => self.notify(true, format!("could not apply bridges: {error}")),
        }
    }

    /// The configuration implied by the worker's current bridge set.
    fn config(&self, layout: &Layout) -> TorConfig {
        let mut config = TorConfig::new(RoutingMode::ProxyOnly);
        config.plugins = TransportPlugin::expert_bundle(layout);

        let (bridges, errors) = parse_many(&self.bridges.join("\n"));
        for (index, error) in &errors {
            tracing::warn!("bridge line {}: {error}", index + 1);
        }
        config.bridges = bridges;
        config
    }

    async fn start(&mut self) {
        if self.engine.is_some() || self.status.is_busy() {
            return;
        }

        self.status = Status::Starting;
        self.state = TorState::default();
        self.notice = None;
        self.publish();

        let layout = match Layout::discover() {
            Ok(layout) => layout,
            Err(error) => return self.fail(error.to_string()),
        };
        let config = self.config(&layout);

        let mut engine = match Engine::start(&layout, &config).await {
            Ok(engine) => engine,
            Err(error) => return self.fail(error.to_string()),
        };

        self.generation += 1;
        let generation = self.generation;
        if let Some(events) = engine.take_events() {
            let mailbox = self.mailbox.clone();
            self.forwarder = Some(tokio::spawn(async move {
                let mut events = events;
                while let Some(event) = events.recv().await {
                    if mailbox.send(Message::Event { generation, event }).is_err() {
                        return;
                    }
                }
                let _ = mailbox.send(Message::StreamEnded { generation });
            }));
        }

        self.tor_version = engine
            .control()
            .get_info("version")
            .await
            .unwrap_or_default();
        self.socks = Some(SocketAddr::from(([127, 0, 0, 1], config.socks_port)));
        self.engine = Some(engine);
        self.status = Status::Running;
        self.publish();
    }

    async fn stop(&mut self) {
        if let Some(forwarder) = self.forwarder.take() {
            forwarder.abort();
        }
        if let Some(engine) = self.engine.take()
            && let Err(error) = engine.shutdown().await
        {
            tracing::warn!(%error, "stopping tor failed");
        }
        self.status = Status::Disconnected;
        self.state = TorState::default();
        self.tor_version.clear();
        self.socks = None;
        // The bridge set survives a stop — it is the user's configuration,
        // not part of the session.
        self.notice = None;
        self.publish();
    }

    fn fail(&mut self, message: String) {
        tracing::error!("{message}");
        self.status = Status::Failed(message);
        self.publish();
    }

    fn notify(&mut self, error: bool, text: impl Into<String>) {
        let text = text.into();
        if error {
            tracing::warn!("{text}");
        }
        self.notice = Some(Notice { error, text });
        self.publish();
    }

    fn publish(&self) {
        let _ = self.snapshot.send(Snapshot {
            status: self.status.clone(),
            state: self.state.clone(),
            tor_version: self.tor_version.clone(),
            socks: self.socks,
            bridges: self.bridges.clone(),
            notice: self.notice.clone(),
        });
        self.ctx.request_repaint();
    }
}
