//! Two-party FROST ceremony orchestration over the relay.
//!
//! [`run_dkg`] is symmetric — both client and signer call it with the
//! roles flipped. The function joins the named relay session, waits for
//! the other participant to be present, then walks through the FROST
//! DKG rounds, exchanging packages via relay `Forward`s.

use anyhow::Context;
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use vouch_frost::{KeyPackage, PublicKeyPackage, dkg, identifier};
use vouch_relay::protocol::{ClientMessage, ServerMessage};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn run_dkg(
    relay_url: &str,
    session: &str,
    my_id: u16,
    other_id: u16,
) -> anyhow::Result<(KeyPackage, PublicKeyPackage)> {
    let (mut ws, _resp) =
        connect_async(relay_url).await.context("connecting to relay")?;

    send(
        &mut ws,
        &ClientMessage::Join {
            session: session.to_string(),
            participant: my_id,
        },
    )
    .await?;
    wait_for_peer_present(&mut ws, other_id).await?;

    let mut rng = OsRng;
    let my_ident = identifier(my_id);
    let other_ident = identifier(other_id);

    // Round 1 — broadcast our package to the other party.
    let r1 = dkg::round1(my_ident, &mut rng)?;
    let r1_bytes = postcard::to_stdvec(&r1.package).context("encode round1 pkg")?;
    forward(&mut ws, other_id, r1_bytes).await?;
    let other_r1_bytes = recv_message_from(&mut ws, other_id).await?;
    let other_r1: dkg::Round1Package =
        postcard::from_bytes(&other_r1_bytes).context("decode round1 pkg")?;
    let received_r1: BTreeMap<_, _> = [(other_ident, other_r1)].into();

    // Round 2 — unicast our addressed package to the other party.
    let r2 = dkg::round2(r1.secret, &received_r1)?;
    let to_other = r2
        .packages
        .get(&other_ident)
        .context("missing round2 package for other party")?
        .clone();
    let r2_bytes = postcard::to_stdvec(&to_other).context("encode round2 pkg")?;
    forward(&mut ws, other_id, r2_bytes).await?;
    let other_r2_bytes = recv_message_from(&mut ws, other_id).await?;
    let other_r2: dkg::Round2Package =
        postcard::from_bytes(&other_r2_bytes).context("decode round2 pkg")?;
    let received_r2: BTreeMap<_, _> = [(other_ident, other_r2)].into();

    // Finalize.
    let (key_pkg, pub_pkg) =
        dkg::finalize(&r2.secret, &received_r1, &received_r2)?;

    Ok((key_pkg, pub_pkg))
}

async fn send(ws: &mut Ws, msg: &ClientMessage) -> anyhow::Result<()> {
    let json = serde_json::to_string(msg)?;
    ws.send(WsMessage::Text(json.into())).await?;
    Ok(())
}

async fn forward(ws: &mut Ws, to: u16, payload: Vec<u8>) -> anyhow::Result<()> {
    send(ws, &ClientMessage::Forward { to, payload }).await
}

async fn recv(ws: &mut Ws) -> anyhow::Result<ServerMessage> {
    let raw = ws
        .next()
        .await
        .context("ws stream ended")?
        .context("ws error")?;
    let text = match raw {
        WsMessage::Text(t) => t,
        other => anyhow::bail!("expected text frame, got {other:?}"),
    };
    serde_json::from_str(text.as_str()).context("decode server message")
}

async fn wait_for_peer_present(ws: &mut Ws, other_id: u16) -> anyhow::Result<()> {
    loop {
        match recv(ws).await? {
            ServerMessage::Joined { peers } => {
                if peers.contains(&other_id) {
                    return Ok(());
                }
            }
            ServerMessage::PeerJoined { participant } if participant == other_id => {
                return Ok(());
            }
            ServerMessage::Error { code, detail } => {
                anyhow::bail!("relay error before peer present: {code:?}: {detail}");
            }
            _ => {}
        }
    }
}

async fn recv_message_from(ws: &mut Ws, from: u16) -> anyhow::Result<Vec<u8>> {
    loop {
        match recv(ws).await? {
            ServerMessage::Message { from: f, payload } if f == from => {
                return Ok(payload);
            }
            ServerMessage::Message { from: f, .. } => {
                anyhow::bail!("unexpected message from participant {f} (expected {from})");
            }
            ServerMessage::PeerLeft { participant } if participant == from => {
                anyhow::bail!("peer {from} left before sending message");
            }
            ServerMessage::Error { code, detail } => {
                anyhow::bail!("relay error: {code:?}: {detail}");
            }
            _ => {}
        }
    }
}
