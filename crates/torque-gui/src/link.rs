//! The seam between the synchronous UI and everything asynchronous.
//!
//! A dedicated thread owns a tokio runtime; the UI owns neither it nor
//! anything it holds, and never awaits. Commands go in on one channel, the
//! newest [`Snapshot`] comes out on a `watch`, and the worker calls
//! `request_repaint` after publishing so the UI wakes on its own.
//!
//! There is deliberately no `select!`. Control events, status polls and
//! commands all arrive on the same mailbox, which keeps the worker a plain
//! loop over one receiver and avoids holding a borrow across a branch that
//! replaces what it borrowed.
//!
//! # Two backends
//!
//! The worker talks to the privileged service when one is running, and
//! otherwise drives tor itself. Running without the service is a legitimate
//! mode, not a degraded one: proxy-only needs no privileges at all, and the
//! service is required only for transparent routing. Without the fallback the
//! app would be unusable until there is an installer.
//!
//! The choice is made once at startup and not revisited. Migrating a live
//! session between backends would mean orphaning or killing a running tor,
//! which is a worse surprise than asking for a restart.
//!
//! The service reports an instantaneous rate rather than a history, so the
//! bandwidth history is accumulated here in both modes.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use torque_core::bridges::parse_many;
use torque_core::control::Event;
use torque_core::router::RoutingMode;
use torque_core::state::{BANDWIDTH_HISTORY, BandwidthSample, LogEntry};
use torque_core::{Engine, Layout, TorConfig, TorState, TransportPlugin};
use torque_ipc::{PROTOCOL_VERSION, Request, Response, StartRequest};

/// How often the service is asked for its status. Matches tor's one-per-second
/// bandwidth event, so the graph advances at the same rate in both modes.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    Disconnected,
    /// Tor is launching: the window between `Start` and the control
    /// connection being authenticated, which can take seconds.
    Starting,
    Running,
    /// Carries what to show the user — usually a missing binary, a torrc tor
    /// rejected, or a lost service connection.
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

/// Which backend this session is using. Shown to the user, because it
/// determines what the app is allowed to do.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Mode {
    /// Driving tor directly. No privileges, and no transparent routing.
    #[default]
    Unprivileged,
    Service { version: String },
}

/// The outcome of the last command: worth telling the user, but not a change
/// in whether tor is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub error: bool,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct CircuitView {
    pub id: String,
    pub status: String,
    pub path: Vec<String>,
    pub streams: Vec<String>,
}

/// What the panels render, filled identically by either backend.
#[derive(Debug, Clone, Default)]
pub struct View {
    pub bootstrap_progress: u8,
    pub bootstrap_summary: String,
    pub circuits: Vec<CircuitView>,
    /// Newest last.
    pub bandwidth: VecDeque<BandwidthSample>,
    /// Empty in service mode: the protocol does not carry tor's log yet.
    pub log: VecDeque<LogEntry>,
}

impl View {
    pub fn latest_bandwidth(&self) -> BandwidthSample {
        self.bandwidth.back().copied().unwrap_or_default()
    }

    fn push_bandwidth(&mut self, sample: BandwidthSample) {
        if self.bandwidth.len() == BANDWIDTH_HISTORY {
            self.bandwidth.pop_front();
        }
        self.bandwidth.push_back(sample);
    }
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub mode: Mode,
    pub status: Status,
    pub view: View,
    pub tor_version: String,
    pub socks: Option<SocketAddr>,
    /// The bridge set in effect, or the one the next start will use. Owned by
    /// the worker, so the UI has one source of truth.
    pub bridges: Vec<String>,
    pub notice: Option<Notice>,
    /// Whether anything is actually enforcing routing rules. Reported, never
    /// assumed, so the UI cannot imply protection that is absent.
    pub policy_enforced: bool,
}

#[derive(Debug, Clone)]
pub enum Command {
    Start,
    Stop,
    NewIdentity,
    /// Replace the bridge set: applied to a running tor without restarting
    /// it, or remembered for the next start.
    SetBridges { lines: Vec<String> },
}

enum Message {
    Command(Command),
    /// `generation` identifies the engine run an event came from, so events
    /// still in flight from a stopped tor cannot pollute the next run.
    Event { generation: u64, event: Event },
    StreamEnded { generation: u64 },
    /// Service mode only: time to ask for status.
    Poll,
}

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
                        // Without a runtime there is no backend at all; say so
                        // rather than leaving the UI stuck on "disconnected".
                        let _ = snapshot_tx.send(Snapshot {
                            status: Status::Failed(format!("cannot start runtime: {error}")),
                            ..Snapshot::default()
                        });
                        ctx.request_repaint();
                        return;
                    }
                };
                runtime.block_on(async move {
                    Worker::connect(ctx, snapshot_tx, mailbox_for_worker)
                        .await
                        .run(mailbox_rx)
                        .await;
                });
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

/// Driving tor ourselves.
#[derive(Default)]
struct Direct {
    engine: Option<Engine>,
    state: TorState,
    forwarder: Option<JoinHandle<()>>,
    generation: u64,
}

enum Backend {
    Service {
        /// `None` once the connection broke; the next poll tries to restore it.
        connection: Option<torque_ipc::Connection>,
        version: String,
    },
    Direct(Direct),
}

struct Worker {
    ctx: egui::Context,
    snapshot: watch::Sender<Snapshot>,
    mailbox: mpsc::UnboundedSender<Message>,
    backend: Backend,
    status: Status,
    view: View,
    tor_version: String,
    socks: Option<SocketAddr>,
    bridges: Vec<String>,
    notice: Option<Notice>,
    policy_enforced: bool,
}

impl Worker {
    /// Picks the backend: the service if one answers, otherwise direct.
    async fn connect(
        ctx: egui::Context,
        snapshot: watch::Sender<Snapshot>,
        mailbox: mpsc::UnboundedSender<Message>,
    ) -> Self {
        let backend = match handshake().await {
            Ok((connection, version)) => {
                tracing::info!(%version, "using the torque service");
                let ticker = mailbox.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(POLL_INTERVAL);
                    while ticker.send(Message::Poll).is_ok() {
                        interval.tick().await;
                    }
                });
                Backend::Service {
                    connection: Some(connection),
                    version,
                }
            }
            Err(error) => {
                tracing::info!(%error, "no service; driving tor directly (proxy only)");
                Backend::Direct(Direct::default())
            }
        };

        let worker = Self {
            ctx,
            snapshot,
            mailbox,
            backend,
            status: Status::Disconnected,
            view: View::default(),
            tor_version: String::new(),
            socks: None,
            bridges: Vec::new(),
            notice: None,
            policy_enforced: false,
        };
        worker.publish();
        worker
    }

    async fn run(mut self, mut mailbox: mpsc::UnboundedReceiver<Message>) {
        while let Some(message) = mailbox.recv().await {
            match message {
                Message::Command(command) => self.handle(command).await,
                Message::Poll => self.poll().await,

                Message::Event { generation, event } => {
                    if let Backend::Direct(direct) = &mut self.backend
                        && generation == direct.generation
                    {
                        direct.state.apply(&event);
                        self.view = view_of(&direct.state);
                        self.publish();
                    }
                }

                Message::StreamEnded { generation } => {
                    if let Backend::Direct(direct) = &self.backend
                        && generation == direct.generation
                        && self.status.is_running()
                    {
                        self.status =
                            Status::Failed("tor closed the control connection".to_owned());
                        self.publish();
                    }
                }
            }
        }

        if let Backend::Direct(direct) = &mut self.backend
            && let Some(engine) = direct.engine.take()
            && let Err(error) = engine.shutdown().await
        {
            tracing::warn!(%error, "stopping tor on exit failed");
        }
    }

    async fn handle(&mut self, command: Command) {
        match &mut self.backend {
            Backend::Service { .. } => self.handle_via_service(command).await,
            Backend::Direct(_) => self.handle_directly(command).await,
        }
    }

    // --- service backend ---------------------------------------------------

    async fn handle_via_service(&mut self, command: Command) {
        let request = match &command {
            Command::Start => {
                self.status = Status::Starting;
                self.notice = None;
                self.publish();
                Request::Start(StartRequest {
                    routing: torque_ipc::RoutingMode::ProxyOnly,
                    bridges: self.bridges.clone(),
                })
            }
            Command::Stop => Request::Stop,
            Command::NewIdentity => Request::NewIdentity,
            Command::SetBridges { lines } => Request::SetBridges {
                lines: lines.clone(),
            },
        };

        let Some(response) = self.request(request).await else {
            return;
        };

        match response {
            Response::Ok => match &command {
                Command::Start => {}
                Command::Stop => {
                    self.status = Status::Disconnected;
                    self.view = View::default();
                    self.tor_version.clear();
                    self.notice = None;
                    self.publish();
                }
                Command::NewIdentity => self.notify(false, "New identity requested."),
                Command::SetBridges { lines } => {
                    self.bridges = lines.clone();
                    self.notify(false, bridges_applied(lines.len(), self.status.is_running()));
                }
            },

            Response::InvalidBridges { errors } => {
                let detail = errors
                    .iter()
                    .map(|error| format!("line {}: {}", error.index + 1, error.message))
                    .collect::<Vec<_>>()
                    .join("; ");
                self.notify(true, format!("the service rejected bridges: {detail}"));
            }

            Response::Error { message } => {
                if matches!(command, Command::Start) {
                    self.status = Status::Failed(message);
                    self.publish();
                } else {
                    self.notify(true, message);
                }
            }

            other => self.notify(true, format!("unexpected reply: {other:?}")),
        }

        // Pick up the new state without waiting for the next tick.
        self.poll().await;
    }

    async fn poll(&mut self) {
        let Backend::Service { connection, .. } = &mut self.backend else {
            return;
        };

        if connection.is_none() {
            match handshake().await {
                Ok((restored, version)) => {
                    self.backend = Backend::Service {
                        connection: Some(restored),
                        version,
                    };
                    self.notify(false, "Reconnected to the service.");
                }
                // Stay quiet: the status already says the connection is gone,
                // and a failing reconnect every second must not spam the user.
                Err(_) => return,
            }
        }

        let Some(Response::Status(status)) = self.request(Request::Status).await else {
            return;
        };

        self.status = match (&self.status, status.running) {
            (Status::Starting, false) => Status::Starting,
            (_, true) => Status::Running,
            (Status::Failed(message), false) => Status::Failed(message.clone()),
            (_, false) => Status::Disconnected,
        };

        self.view.bootstrap_progress = status.bootstrap_progress;
        self.view.bootstrap_summary = status.bootstrap_summary;
        self.view.circuits = status
            .circuits
            .into_iter()
            .map(|circuit| CircuitView {
                id: circuit.id,
                status: circuit.status,
                path: circuit.path,
                streams: circuit.streams,
            })
            .collect();
        if status.running {
            self.view.push_bandwidth(BandwidthSample {
                read: status.bandwidth.read,
                written: status.bandwidth.written,
            });
        }
        self.policy_enforced = status.policy_enforced;
        self.publish();
    }

    /// Sends one request, taking the connection out of the backend so the
    /// borrow does not outlive the await.
    async fn request(&mut self, request: Request) -> Option<Response> {
        let Backend::Service { connection, .. } = &mut self.backend else {
            return None;
        };
        let mut taken = connection.take()?;

        match taken.request::<_, Response>(&request).await {
            Ok(response) => {
                if let Backend::Service { connection, .. } = &mut self.backend {
                    *connection = Some(taken);
                }
                Some(response)
            }
            Err(error) => {
                self.status = Status::Failed(format!("lost the service connection: {error}"));
                self.publish();
                None
            }
        }
    }

    // --- direct backend ----------------------------------------------------

    async fn handle_directly(&mut self, command: Command) {
        match command {
            Command::Start => self.start_directly().await,
            Command::Stop => self.stop_directly().await,
            Command::SetBridges { lines } => self.set_bridges_directly(lines).await,
            Command::NewIdentity => {
                let Backend::Direct(direct) = &self.backend else {
                    return;
                };
                let Some(engine) = direct.engine.as_ref() else {
                    return;
                };
                match engine.control().new_identity().await {
                    Ok(()) => self.notify(false, "New identity requested."),
                    Err(error) => self.notify(true, format!("NEWNYM failed: {error}")),
                }
            }
        }
    }

    async fn start_directly(&mut self) {
        let Backend::Direct(direct) = &self.backend else {
            return;
        };
        if direct.engine.is_some() || self.status.is_busy() {
            return;
        }

        self.status = Status::Starting;
        self.view = View::default();
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

        let Backend::Direct(direct) = &mut self.backend else {
            return;
        };
        direct.generation += 1;
        let generation = direct.generation;
        direct.state = TorState::default();

        if let Some(mut events) = engine.take_events() {
            let mailbox = self.mailbox.clone();
            direct.forwarder = Some(tokio::spawn(async move {
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

        if let Backend::Direct(direct) = &mut self.backend {
            direct.engine = Some(engine);
        }
        self.status = Status::Running;
        self.publish();
    }

    async fn stop_directly(&mut self) {
        let Backend::Direct(direct) = &mut self.backend else {
            return;
        };
        if let Some(forwarder) = direct.forwarder.take() {
            forwarder.abort();
        }
        let engine = direct.engine.take();
        direct.state = TorState::default();

        if let Some(engine) = engine
            && let Err(error) = engine.shutdown().await
        {
            tracing::warn!(%error, "stopping tor failed");
        }

        self.status = Status::Disconnected;
        self.view = View::default();
        self.tor_version.clear();
        self.socks = None;
        // The bridge set survives a stop: it is configuration, not session.
        self.notice = None;
        self.publish();
    }

    async fn set_bridges_directly(&mut self, lines: Vec<String>) {
        self.bridges = lines;

        let Backend::Direct(direct) = &self.backend else {
            return;
        };
        let Some(engine) = direct.engine.as_ref() else {
            let count = self.bridges.len();
            return self.notify(false, bridges_applied(count, false));
        };

        let layout = match Layout::discover() {
            Ok(layout) => layout,
            Err(error) => return self.notify(true, error.to_string()),
        };
        let config = self.config(&layout);

        // Deliberately not resetting the local bootstrap state: tor does not
        // always re-emit a bootstrap event here, and a progress bar reset to
        // zero that never moves again is worse than one holding its last
        // known value.
        match engine.apply_bridges(&config).await {
            Ok(()) => {
                let count = config.bridges.len();
                self.notify(false, bridges_applied(count, true));
            }
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

    // --- shared ------------------------------------------------------------

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
        let mode = match &self.backend {
            Backend::Service { version, .. } => Mode::Service {
                version: version.clone(),
            },
            Backend::Direct(_) => Mode::Unprivileged,
        };
        let _ = self.snapshot.send(Snapshot {
            mode,
            status: self.status.clone(),
            view: self.view.clone(),
            tor_version: self.tor_version.clone(),
            socks: self.socks,
            bridges: self.bridges.clone(),
            notice: self.notice.clone(),
            policy_enforced: self.policy_enforced,
        });
        self.ctx.request_repaint();
    }
}

async fn handshake() -> std::io::Result<(torque_ipc::Connection, String)> {
    let mut connection = torque_ipc::connect().await?;
    match connection
        .request::<_, Response>(&Request::Hello {
            version: PROTOCOL_VERSION,
        })
        .await?
    {
        Response::Hello {
            service_version, ..
        } => Ok((connection, service_version)),
        Response::Error { message } => Err(std::io::Error::other(message)),
        other => Err(std::io::Error::other(format!(
            "unexpected handshake reply: {other:?}"
        ))),
    }
}

fn view_of(state: &TorState) -> View {
    View {
        bootstrap_progress: state.bootstrap.progress,
        bootstrap_summary: state.bootstrap.summary.clone(),
        circuits: state
            .circuits
            .values()
            .map(|circuit| CircuitView {
                id: circuit.id.clone(),
                status: circuit.status.clone(),
                path: circuit.path.clone(),
                streams: circuit.streams.values().cloned().collect(),
            })
            .collect(),
        bandwidth: state.bandwidth.clone(),
        log: state.log.clone(),
    }
}

fn bridges_applied(count: usize, running: bool) -> String {
    match (count, running) {
        (0, true) => "Bridges disabled on the running tor.".to_owned(),
        (0, false) => "Bridges cleared; the next start will connect directly.".to_owned(),
        (count, true) => format!("{count} bridge(s) applied; tor is rebuilding circuits."),
        (count, false) => format!("{count} bridge(s) stored for the next start."),
    }
}
