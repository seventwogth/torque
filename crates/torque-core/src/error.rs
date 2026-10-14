use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    #[error("control protocol error: {0}")]
    Control(#[from] torque_control::Error),

    #[error("routing error: {0}")]
    Routing(#[from] torque_router::Error),

    #[error("cannot determine where to put files: {0}")]
    Layout(String),

    #[error("missing bundled binary {0}; install the Tor Expert Bundle into vendor/")]
    MissingBinary(PathBuf),

    /// Tor neither published its control port nor exited — usually a torrc it
    /// rejected, so its stdout is the thing worth reading.
    #[error("tor did not open its control port within {0:?}")]
    StartupTimeout(std::time::Duration),

    #[error("tor exited during startup: {0}")]
    TorExited(String),

    #[error("could not parse tor's control port file: {0}")]
    ControlPortFile(String),
}

pub type Result<T> = std::result::Result<T, Error>;
