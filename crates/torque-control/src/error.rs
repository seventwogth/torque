use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("control connection I/O failed: {0}")]
    Io(#[from] io::Error),

    /// The peer sent something that is not a valid control-protocol reply.
    #[error("control protocol violation: {0}")]
    Protocol(String),

    /// A well-formed reply carrying a non-success status code.
    #[error("tor replied {code}: {text}")]
    Status { code: u16, text: String },

    #[error("authentication rejected: {0}")]
    Auth(String),
}

pub type Result<T> = std::result::Result<T, Error>;
