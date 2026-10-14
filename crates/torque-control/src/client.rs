use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, mpsc};

use crate::auth::AuthMethod;
use crate::error::{Error, Result};
use crate::event::Event;
use crate::reply::{Reply, ReplyBuilder, quote};

/// Asynchronous events pushed by tor after `SETEVENTS`.
pub type EventStream = mpsc::UnboundedReceiver<Event>;

/// A connection to tor's control port.
///
/// A background task owns the read half and demultiplexes it: `650` replies go
/// to the [`EventStream`], everything else to whoever is awaiting a command.
/// Commands are serialized, so replies cannot be mismatched.
pub struct ControlClient {
    writer: Mutex<OwnedWriteHalf>,
    replies: Mutex<mpsc::UnboundedReceiver<Result<Reply>>>,
}

impl ControlClient {
    pub async fn connect(address: SocketAddr) -> Result<(Self, EventStream)> {
        let stream = TcpStream::connect(address).await?;
        stream.set_nodelay(true)?;
        let (read, write) = stream.into_split();

        let (reply_tx, reply_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        tokio::spawn(demultiplex(read, reply_tx, event_tx));

        Ok((
            Self {
                writer: Mutex::new(write),
                replies: Mutex::new(reply_rx),
            },
            event_rx,
        ))
    }

    /// Sends one command and awaits its reply. Does not check the status code.
    pub async fn send(&self, command: &str) -> Result<Reply> {
        // Both locks are held for the whole exchange: that is what keeps
        // concurrent callers from stealing each other's replies.
        let mut writer = self.writer.lock().await;
        let mut replies = self.replies.lock().await;

        writer.write_all(command.as_bytes()).await?;
        writer.write_all(b"\r\n").await?;
        writer.flush().await?;

        replies
            .recv()
            .await
            .ok_or_else(|| Error::Protocol("control connection closed".to_owned()))?
    }

    /// Sends one command and rejects a non-success status code.
    pub async fn command(&self, command: &str) -> Result<Reply> {
        self.send(command).await?.into_ok()
    }

    pub async fn authenticate(&self, method: &AuthMethod) -> Result<()> {
        let reply = self.send(&method.command().await?).await?;
        if reply.is_ok() {
            Ok(())
        } else {
            Err(Error::Auth(reply.first_text().to_owned()))
        }
    }

    /// `PROTOCOLINFO` — the one command allowed before authenticating; it
    /// reports which auth methods this tor accepts and where its cookie lives.
    pub async fn protocol_info(&self) -> Result<Reply> {
        self.command("PROTOCOLINFO 1").await
    }

    /// Ties tor's lifetime to this connection: when it drops, tor exits. This
    /// is what stops orphaned tor processes from piling up after a crash.
    pub async fn take_ownership(&self) -> Result<()> {
        self.command("TAKEOWNERSHIP").await.map(drop)
    }

    pub async fn get_info(&self, key: &str) -> Result<String> {
        let reply = self.command(&format!("GETINFO {key}")).await?;
        reply
            .value(key)
            .or_else(|| reply.data(key))
            .map(str::to_owned)
            .ok_or_else(|| Error::Protocol(format!("GETINFO {key} returned no value")))
    }

    /// Applies configuration without restarting tor — how bridges and
    /// transports get switched live.
    pub async fn set_conf(&self, settings: &[(&str, &str)]) -> Result<()> {
        if settings.is_empty() {
            return Ok(());
        }
        let mut command = String::from("SETCONF");
        for (key, value) in settings {
            command.push(' ');
            command.push_str(key);
            command.push('=');
            command.push_str(&quote(value));
        }
        self.command(&command).await.map(drop)
    }

    /// Returns the listed options to their compiled-in defaults.
    pub async fn reset_conf(&self, keys: &[&str]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        self.command(&format!("RESETCONF {}", keys.join(" ")))
            .await
            .map(drop)
    }

    pub async fn set_events(&self, events: &[&str]) -> Result<()> {
        self.command(&format!("SETEVENTS {}", events.join(" ")))
            .await
            .map(drop)
    }

    pub async fn signal(&self, signal: &str) -> Result<()> {
        self.command(&format!("SIGNAL {signal}")).await.map(drop)
    }

    /// New identity: drops existing circuits so later streams use fresh ones.
    pub async fn new_identity(&self) -> Result<()> {
        self.signal("NEWNYM").await
    }
}

async fn demultiplex(
    read: OwnedReadHalf,
    replies: mpsc::UnboundedSender<Result<Reply>>,
    events: mpsc::UnboundedSender<Event>,
) {
    let mut lines = BufReader::new(read).lines();
    let mut builder = ReplyBuilder::default();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                let _ = replies.send(Err(error.into()));
                break;
            }
        };

        match builder.push(&line) {
            Ok(None) => {}
            Ok(Some(reply)) if reply.code == 650 => {
                for line in &reply.lines {
                    if events.send(Event::parse(&line.text)).is_err() {
                        tracing::debug!("event receiver dropped; stopping event delivery");
                        break;
                    }
                }
            }
            Ok(Some(reply)) => {
                if replies.send(Ok(reply)).is_err() {
                    break;
                }
            }
            Err(error) => {
                let _ = replies.send(Err(error));
                break;
            }
        }
    }

    tracing::debug!("control connection reader finished");
}
