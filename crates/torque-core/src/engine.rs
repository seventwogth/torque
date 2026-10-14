//! Supervision of the bundled tor process and the control connection to it.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep};
use torque_control::{AuthMethod, ControlClient, DEFAULT_EVENTS, EventStream};

use crate::error::{Error, Result};
use crate::paths::Layout;
use crate::torrc::TorConfig;

/// How long to wait for tor to publish its control port before giving up.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_POLL: Duration = Duration::from_millis(100);
/// Lines of tor's stdout retained to explain a failed startup.
const STARTUP_LOG_LINES: usize = 20;

/// A running tor plus an authenticated control connection.
///
/// Dropping the engine kills tor: the child is spawned with `kill_on_drop`,
/// and `TAKEOWNERSHIP` makes tor exit if the control connection dies first.
/// Between them, a crashed Torque does not leave an orphaned tor behind.
pub struct Engine {
    control: Arc<ControlClient>,
    events: Option<EventStream>,
    child: Child,
    control_address: SocketAddr,
}

impl Engine {
    pub async fn start(layout: &Layout, config: &TorConfig) -> Result<Self> {
        let tor = layout.tor_binary();
        if !tor.exists() {
            return Err(Error::MissingBinary(tor));
        }
        for plugin in config.needed_plugins() {
            if !plugin.executable.exists() {
                return Err(Error::MissingBinary(plugin.executable.clone()));
            }
        }

        layout.ensure_data_dir().await?;
        tokio::fs::write(layout.torrc(), config.render(layout)).await?;

        // A stale port file from a previous run would be read as this run's.
        let port_file = layout.control_port_file();
        if tokio::fs::try_exists(&port_file).await.unwrap_or(false) {
            tokio::fs::remove_file(&port_file).await?;
        }

        let mut child = Command::new(&tor)
            .arg("-f")
            .arg(layout.torrc())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let recent = Arc::new(Mutex::new(VecDeque::with_capacity(STARTUP_LOG_LINES)));
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(forward_output(stdout, Arc::clone(&recent)));
        }

        let control_address = match wait_for_control_port(layout, &mut child).await {
            Ok(address) => address,
            Err(error) => {
                // Tor's own complaint is far more useful than our timeout.
                let tail = recent.lock().map(|lines| lines_to_text(&lines)).unwrap_or_default();
                if tail.is_empty() {
                    return Err(error);
                }
                return Err(Error::TorExited(format!("{error}: {tail}")));
            }
        };

        let (control, events) = ControlClient::connect(control_address).await?;
        control
            .authenticate(&AuthMethod::Cookie(layout.cookie()))
            .await?;
        control.take_ownership().await?;
        control.set_events(DEFAULT_EVENTS).await?;

        tracing::info!(%control_address, "tor is up and the control connection is authenticated");

        Ok(Self {
            control: Arc::new(control),
            events: Some(events),
            child,
            control_address,
        })
    }

    pub fn control(&self) -> Arc<ControlClient> {
        Arc::clone(&self.control)
    }

    pub fn control_address(&self) -> SocketAddr {
        self.control_address
    }

    /// Takes the event stream. Only the first caller gets it; later callers
    /// get `None`, since events are consumed, not broadcast.
    pub fn take_events(&mut self) -> Option<EventStream> {
        self.events.take()
    }

    /// Asks tor to exit, then waits for it.
    pub async fn shutdown(mut self) -> Result<()> {
        if let Err(error) = self.control.signal("HALT").await {
            tracing::warn!(%error, "SIGNAL HALT failed; killing tor instead");
            self.child.kill().await?;
        }
        let status = self.child.wait().await?;
        tracing::info!(?status, "tor exited");
        Ok(())
    }
}

async fn wait_for_control_port(layout: &Layout, child: &mut Child) -> Result<SocketAddr> {
    let port_file = layout.control_port_file();
    let cookie = layout.cookie();
    let deadline = Instant::now() + STARTUP_TIMEOUT;

    loop {
        if let Some(status) = child.try_wait()? {
            return Err(Error::TorExited(format!("exit status {status}")));
        }

        // The cookie has to exist too, or authentication races the write.
        if tokio::fs::try_exists(&port_file).await.unwrap_or(false)
            && tokio::fs::try_exists(&cookie).await.unwrap_or(false)
        {
            let contents = tokio::fs::read_to_string(&port_file).await?;
            if let Some(address) = parse_control_port_file(&contents) {
                return Ok(address);
            }
            // Tor may have written a partial line; try again next tick.
        }

        if Instant::now() >= deadline {
            return Err(Error::StartupTimeout(STARTUP_TIMEOUT));
        }
        sleep(STARTUP_POLL).await;
    }
}

/// Parses the `PORT=127.0.0.1:9051` line tor writes for `ControlPort auto`.
fn parse_control_port_file(contents: &str) -> Option<SocketAddr> {
    contents
        .lines()
        .filter_map(|line| line.trim().strip_prefix("PORT="))
        .find_map(|address| address.parse().ok())
}

async fn forward_output(
    stdout: tokio::process::ChildStdout,
    recent: Arc<Mutex<VecDeque<String>>>,
) {
    let mut lines = BufReader::new(stdout).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::debug!(target: "tor", "{line}");
        if let Ok(mut recent) = recent.lock() {
            if recent.len() == STARTUP_LOG_LINES {
                recent.pop_front();
            }
            recent.push_back(line);
        }
    }
}

fn lines_to_text(lines: &VecDeque<String>) -> String {
    lines
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_control_port_file() {
        assert_eq!(
            parse_control_port_file("PORT=127.0.0.1:49512\n"),
            Some("127.0.0.1:49512".parse().unwrap())
        );
    }

    #[test]
    fn ignores_partial_or_unexpected_content() {
        assert_eq!(parse_control_port_file(""), None);
        assert_eq!(parse_control_port_file("PORT=127.0.0.1"), None);
        // Unix sockets are a valid thing for tor to write, and not something
        // this version knows how to dial.
        assert_eq!(parse_control_port_file("UNIX_PORT=/run/tor/control"), None);
    }
}
