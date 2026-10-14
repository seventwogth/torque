//! One client connection.

use tokio::sync::oneshot;
use torque_ipc::{Connection, PROTOCOL_VERSION, Request, Response};

use crate::actor::{Job, Mailbox};

/// Serves one client until it disconnects.
///
/// The handshake is answered here rather than in the actor: a connection that
/// has not agreed on a protocol version must not be able to reach the engine
/// at all.
pub async fn serve(mut connection: Connection, jobs: Mailbox) {
    if !handshake(&mut connection).await {
        return;
    }

    loop {
        let request = match connection.recv::<Request>().await {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(error) => {
                tracing::debug!(%error, "client connection failed");
                break;
            }
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        if jobs.send(Job::Request(request, reply_tx)).is_err() {
            let _ = connection
                .send(&Response::Error {
                    message: "the service is shutting down".to_owned(),
                })
                .await;
            break;
        }

        let response = match reply_rx.await {
            Ok(response) => response,
            Err(_) => Response::Error {
                message: "the service dropped the request".to_owned(),
            },
        };

        if let Err(error) = connection.send(&response).await {
            tracing::debug!(%error, "could not answer client");
            break;
        }
    }

    tracing::debug!("client disconnected");
}

/// `true` when the client agreed on the protocol version.
async fn handshake(connection: &mut Connection) -> bool {
    let first = match connection.recv::<Request>().await {
        Ok(Some(request)) => request,
        Ok(None) => return false,
        Err(error) => {
            tracing::debug!(%error, "handshake failed");
            return false;
        }
    };

    let response = match first {
        Request::Hello { version } if version == PROTOCOL_VERSION => Response::Hello {
            version: PROTOCOL_VERSION,
            service_version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        Request::Hello { version } => Response::Error {
            message: format!(
                "protocol version {version} is not supported; this service speaks \
                 {PROTOCOL_VERSION}"
            ),
        },
        _ => Response::Error {
            message: "the first message must be hello".to_owned(),
        },
    };

    let accepted = matches!(response, Response::Hello { .. });
    if let Err(error) = connection.send(&response).await {
        tracing::debug!(%error, "could not answer handshake");
        return false;
    }
    accepted
}
