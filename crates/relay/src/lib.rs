//! vouch-relay: dumb websocket message bus for FROST ceremonies.
//!
//! The relay sees session ids, participant ids, payload sizes, and
//! timing. It cannot interpret payloads. It does not authenticate
//! participants — knowledge of the session id is treated as a bearer
//! credential for v0.

pub mod protocol;
mod session;

pub use session::Registry;

use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use protocol::{ClientMessage, ErrorCode, ServerMessage};
use session::{ForwardError, JoinError};
use std::sync::Arc;
use tokio::sync::mpsc;

pub fn router() -> Router {
    Router::new()
        .route("/ws", get(ws_upgrade))
        .with_state(Registry::new())
}

async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(registry): State<Arc<Registry>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, registry))
}

async fn handle_socket(mut socket: WebSocket, registry: Arc<Registry>) {
    let (session, participant) = match recv_join(&mut socket).await {
        Ok(j) => j,
        Err(reason) => {
            let _ = send_direct(
                &mut socket,
                &ServerMessage::Error {
                    code: ErrorCode::NotJoined,
                    detail: reason.into(),
                },
            )
            .await;
            return;
        }
    };

    let (outbound_tx, mut outbound_rx) = mpsc::channel(Registry::outbound_buffer());
    let self_tx = outbound_tx.clone();

    match registry.join(&session, participant, outbound_tx).await {
        Ok(peers) => {
            let _ = self_tx.try_send(ServerMessage::Joined { peers });
        }
        Err(JoinError::ParticipantTaken) => {
            let _ = send_direct(
                &mut socket,
                &ServerMessage::Error {
                    code: ErrorCode::ParticipantTaken,
                    detail: "participant id already in session".into(),
                },
            )
            .await;
            return;
        }
    }

    tracing::debug!(%session, participant, "joined");

    let (mut ws_tx, mut ws_rx) = socket.split();

    let pump_out = tokio::spawn(async move {
        while let Some(msg) = outbound_rx.recv().await {
            let Ok(json) = serde_json::to_string(&msg) else {
                continue;
            };
            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    while let Some(frame) = ws_rx.next().await {
        let Ok(frame) = frame else {
            break;
        };
        let text = match frame {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue,
        };
        let parsed = match serde_json::from_str::<ClientMessage>(&text) {
            Ok(p) => p,
            Err(e) => {
                let _ = self_tx.try_send(ServerMessage::Error {
                    code: ErrorCode::ProtocolViolation,
                    detail: format!("invalid client message: {e}"),
                });
                continue;
            }
        };
        match parsed {
            ClientMessage::Join { .. } => {
                let _ = self_tx.try_send(ServerMessage::Error {
                    code: ErrorCode::ProtocolViolation,
                    detail: "duplicate join".into(),
                });
            }
            ClientMessage::Forward { to, payload } => {
                if let Err(e) =
                    registry.forward(&session, participant, to, payload).await
                {
                    let (code, detail) = match e {
                        ForwardError::PeerNotFound => {
                            (ErrorCode::PeerNotFound, "peer not in session".to_string())
                        }
                        ForwardError::PeerBackpressure => (
                            ErrorCode::PeerBackpressure,
                            "peer outbound queue full".to_string(),
                        ),
                    };
                    let _ = self_tx.try_send(ServerMessage::Error { code, detail });
                }
            }
        }
    }

    drop(self_tx);
    pump_out.abort();
    registry.leave(&session, participant).await;
    tracing::debug!(%session, participant, "left");
}

async fn recv_join(socket: &mut WebSocket) -> Result<(String, u16), &'static str> {
    let frame = socket.recv().await.ok_or("connection closed before join")?;
    let frame = frame.map_err(|_| "websocket error")?;
    let text = match frame {
        Message::Text(t) => t,
        _ => return Err("first frame must be text Join"),
    };
    match serde_json::from_str::<ClientMessage>(&text) {
        Ok(ClientMessage::Join { session, participant }) => Ok((session, participant)),
        Ok(_) => Err("first message must be Join"),
        Err(_) => Err("first message must be valid Join json"),
    }
}

async fn send_direct(socket: &mut WebSocket, msg: &ServerMessage) -> Result<(), ()> {
    let Ok(json) = serde_json::to_string(msg) else {
        return Err(());
    };
    socket.send(Message::Text(json.into())).await.map_err(|_| ())
}
