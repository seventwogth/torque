use std::path::PathBuf;

use crate::error::Result;
use crate::reply::quote;

/// How to authenticate to the control port.
///
/// Torque spawns its own tor with `CookieAuthentication 1`, so [`Self::Cookie`]
/// is the normal path; the others exist for attaching to a tor the user already
/// runs (a system service, or Tor Browser).
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// `AUTHENTICATE` with no credentials — only when tor was built with
    /// `CookieAuthentication 0` and no password set.
    Null,
    /// Plaintext password matching tor's `HashedControlPassword`.
    Password(String),
    /// Contents of tor's `ControlAuthCookie` file, sent as hex.
    Cookie(PathBuf),
    // TODO(stage 2): SAFECOOKIE, which proves cookie knowledge via HMAC-SHA256
    // instead of sending it. Needed when attaching to a tor we did not spawn,
    // because the cookie then crosses a trust boundary.
}

impl AuthMethod {
    pub(crate) async fn command(&self) -> Result<String> {
        Ok(match self {
            Self::Null => "AUTHENTICATE".to_owned(),
            Self::Password(password) => format!("AUTHENTICATE {}", quote(password)),
            Self::Cookie(path) => {
                let cookie = tokio::fs::read(path).await?;
                format!("AUTHENTICATE {}", hex::encode(cookie))
            }
        })
    }
}
