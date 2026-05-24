//! Boot the relay against a real TCP listener and drive it with two
//! WebSocket clients. Covers Join → PeerJoined → Forward → Message and
//! cleanup on disconnect.

use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{WebSocketStream, connect_async};
use vouch_relay::protocol::{ClientMessage, ServerMessage};

type Client = WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn boot_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, vouch_relay::router()).await.unwrap();
    });
    format!("ws://{}/ws", addr)
}

async fn connect(url: &str) -> Client {
    let (stream, _) = connect_async(url).await.unwrap();
    stream
}

async fn send(client: &mut Client, msg: &ClientMessage) {
    let json = serde_json::to_string(msg).unwrap();
    client.send(WsMessage::Text(json.into())).await.unwrap();
}

async fn recv(client: &mut Client) -> ServerMessage {
    let raw = tokio::time::timeout(Duration::from_secs(2), client.next())
        .await
        .expect("timeout waiting for server message")
        .expect("stream ended")
        .expect("ws error");
    let text = match raw {
        WsMessage::Text(t) => t,
        other => panic!("expected text frame, got {other:?}"),
    };
    serde_json::from_str(&text).expect("server message must parse")
}

#[tokio::test]
async fn two_party_join_and_forward() {
    let url = boot_relay().await;

    let mut alice = connect(&url).await;
    send(
        &mut alice,
        &ClientMessage::Join {
            session: "s1".into(),
            participant: 1,
        },
    )
    .await;
    let m = recv(&mut alice).await;
    assert!(matches!(m, ServerMessage::Joined { ref peers } if peers.is_empty()));

    let mut bob = connect(&url).await;
    send(
        &mut bob,
        &ClientMessage::Join {
            session: "s1".into(),
            participant: 2,
        },
    )
    .await;
    let m = recv(&mut bob).await;
    assert!(matches!(m, ServerMessage::Joined { ref peers } if peers == &[1]));

    // Alice gets notified Bob joined.
    let m = recv(&mut alice).await;
    assert!(matches!(m, ServerMessage::PeerJoined { participant: 2 }));

    // Alice → Bob.
    send(
        &mut alice,
        &ClientMessage::Forward {
            to: 2,
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        },
    )
    .await;
    match recv(&mut bob).await {
        ServerMessage::Message { from, payload } => {
            assert_eq!(from, 1);
            assert_eq!(payload, vec![0xde, 0xad, 0xbe, 0xef]);
        }
        other => panic!("expected Message, got {other:?}"),
    }

    // Bob → Alice.
    send(
        &mut bob,
        &ClientMessage::Forward {
            to: 1,
            payload: vec![0xca, 0xfe],
        },
    )
    .await;
    match recv(&mut alice).await {
        ServerMessage::Message { from, payload } => {
            assert_eq!(from, 2);
            assert_eq!(payload, vec![0xca, 0xfe]);
        }
        other => panic!("expected Message, got {other:?}"),
    }

    // Alice drops; Bob sees PeerLeft.
    drop(alice);
    let m = recv(&mut bob).await;
    assert!(matches!(m, ServerMessage::PeerLeft { participant: 1 }));
}

#[tokio::test]
async fn rejects_duplicate_participant() {
    let url = boot_relay().await;

    let mut a1 = connect(&url).await;
    send(
        &mut a1,
        &ClientMessage::Join {
            session: "s2".into(),
            participant: 1,
        },
    )
    .await;
    let _ = recv(&mut a1).await; // Joined

    let mut a2 = connect(&url).await;
    send(
        &mut a2,
        &ClientMessage::Join {
            session: "s2".into(),
            participant: 1,
        },
    )
    .await;
    match recv(&mut a2).await {
        ServerMessage::Error { code, .. } => {
            assert_eq!(code, vouch_relay::protocol::ErrorCode::ParticipantTaken)
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[tokio::test]
async fn forward_to_unknown_peer_returns_error() {
    let url = boot_relay().await;

    let mut alice = connect(&url).await;
    send(
        &mut alice,
        &ClientMessage::Join {
            session: "s3".into(),
            participant: 1,
        },
    )
    .await;
    let _ = recv(&mut alice).await;

    send(
        &mut alice,
        &ClientMessage::Forward {
            to: 99,
            payload: vec![1, 2, 3],
        },
    )
    .await;
    match recv(&mut alice).await {
        ServerMessage::Error { code, .. } => {
            assert_eq!(code, vouch_relay::protocol::ErrorCode::PeerNotFound)
        }
        other => panic!("expected Error, got {other:?}"),
    }
}
