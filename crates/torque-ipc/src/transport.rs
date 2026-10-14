//! The transport under the protocol: a Windows named pipe or a Unix socket,
//! carrying newline-delimited JSON.
//!
//! # Access control
//!
//! The endpoint controls tor and, later, routing, so who may open it matters.
//!
//! On Unix the socket is created mode `0600` inside a `0700` directory, which
//! is the whole story.
//!
//! On Windows the pipe is created with the process's default security, which
//! grants the creating user and `SYSTEM`. That is the correct boundary while
//! the service runs unelevated as the same user as the UI — the same boundary
//! as the user's own config file. It stops being sufficient the moment the
//! service runs elevated, because the pipe must then grant a specific
//! non-`SYSTEM` user, and that is an explicit SDDL the installer has to
//! record the user for. The two land together; see ARCHITECTURE.md stage 6.
//! Until then the service logs which boundary is in force rather than letting
//! it be assumed.

use std::io;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf, split};

use crate::{decode, encode};

/// Anything the transport can be built on.
pub trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}

/// One end of a connection, framing messages as newline-delimited JSON.
pub struct Connection {
    reader: BufReader<ReadHalf<Box<dyn Stream>>>,
    writer: WriteHalf<Box<dyn Stream>>,
}

impl Connection {
    fn new(stream: Box<dyn Stream>) -> Self {
        let (reader, writer) = split(stream);
        Self {
            reader: BufReader::new(reader),
            writer,
        }
    }

    pub async fn send<T: Serialize>(&mut self, message: &T) -> io::Result<()> {
        let frame = encode(message).map_err(io::Error::other)?;
        self.writer.write_all(frame.as_bytes()).await?;
        self.writer.flush().await
    }

    /// `Ok(None)` when the peer closed the connection cleanly.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> io::Result<Option<T>> {
        let mut line = String::new();
        if self.reader.read_line(&mut line).await? == 0 {
            return Ok(None);
        }
        decode(&line).map(Some).map_err(io::Error::other)
    }

    /// Sends a request and waits for the one reply to it.
    pub async fn request<Q: Serialize, R: DeserializeOwned>(
        &mut self,
        request: &Q,
    ) -> io::Result<R> {
        self.send(request).await?;
        self.recv()
            .await?
            .ok_or_else(|| io::Error::other("the service closed the connection"))
    }
}

/// Accepts connections on the service endpoint.
pub struct Listener {
    inner: platform::Listener,
}

impl Listener {
    /// Binds the endpoint. Fails if another service already holds it, rather
    /// than quietly taking over a name clients may already trust.
    pub async fn bind() -> io::Result<Self> {
        Ok(Self {
            inner: platform::Listener::bind().await?,
        })
    }

    pub async fn accept(&mut self) -> io::Result<Connection> {
        Ok(Connection::new(self.inner.accept().await?))
    }
}

/// Connects to a running service.
pub async fn connect() -> io::Result<Connection> {
    Ok(Connection::new(platform::connect().await?))
}

#[cfg(windows)]
mod platform {
    use std::io;
    use std::time::Duration;

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

    use super::Stream;
    use crate::endpoint;

    /// `ERROR_PIPE_BUSY`: every server instance is occupied, so wait for the
    /// service to create the next one.
    const ERROR_PIPE_BUSY: i32 = 231;
    const CONNECT_ATTEMPTS: u32 = 20;
    const CONNECT_RETRY: Duration = Duration::from_millis(50);

    pub(super) struct Listener {
        name: String,
        /// The instance waiting for the next client. A named pipe serves one
        /// client per instance, so accepting means handing this one over and
        /// creating its replacement.
        idle: Option<NamedPipeServer>,
    }

    impl Listener {
        pub(super) async fn bind() -> io::Result<Self> {
            let name = endpoint();
            let idle = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&name)?;
            Ok(Self {
                name,
                idle: Some(idle),
            })
        }

        pub(super) async fn accept(&mut self) -> io::Result<Box<dyn Stream>> {
            let server = self
                .idle
                .take()
                .ok_or_else(|| io::Error::other("the listener has no idle pipe instance"))?;
            server.connect().await?;
            self.idle = Some(ServerOptions::new().create(&self.name)?);
            Ok(Box::new(server))
        }
    }

    pub(super) async fn connect() -> io::Result<Box<dyn Stream>> {
        let name = endpoint();
        for _ in 0..CONNECT_ATTEMPTS {
            match ClientOptions::new().open(&name) {
                Ok(client) => return Ok(Box::new(client)),
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(CONNECT_RETRY).await;
                }
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other(
            "every pipe instance stayed busy; the service may be overloaded",
        ))
    }
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use tokio::net::{UnixListener, UnixStream};

    use super::Stream;
    use crate::endpoint;

    pub(super) struct Listener {
        inner: UnixListener,
        path: PathBuf,
    }

    impl Listener {
        pub(super) async fn bind() -> io::Result<Self> {
            let path = PathBuf::from(endpoint());
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
                tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
            }

            // A socket left behind by a crash would block the bind. Removing
            // it is safe because a live service holds the name through its own
            // bind, which would then fail below.
            if tokio::fs::try_exists(&path).await.unwrap_or(false)
                && UnixStream::connect(&path).await.is_err()
            {
                tokio::fs::remove_file(&path).await?;
            }

            let inner = UnixListener::bind(&path)?;
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
            Ok(Self { inner, path })
        }

        pub(super) async fn accept(&mut self) -> io::Result<Box<dyn Stream>> {
            let (stream, _) = self.inner.accept().await?;
            Ok(Box::new(stream))
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    pub(super) async fn connect() -> io::Result<Box<dyn Stream>> {
        Ok(Box::new(UnixStream::connect(endpoint()).await?))
    }
}
