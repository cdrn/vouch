//! Wire protocol for the relay.
//!
//! v0 envelope: JSON over WebSocket text frames. Payloads are opaque
//! `Vec<u8>` — the relay never interprets them. FROST messages travel
//! inside `Forward`/`Message` payloads, serialized by the participants.
//!
//! No end-to-end encryption between participants yet; payloads are
//! currently plaintext. Wire format does not change when E2E lands —
//! payloads just become ciphertexts.

use serde::{Deserialize, Serialize};

pub type ParticipantId = u16;
pub type SessionId = String;

/// Client → relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// First message on a new connection. Joins (or creates) a session.
    Join {
        session: SessionId,
        participant: ParticipantId,
    },
    /// Unicast a payload to one peer in the current session.
    Forward {
        to: ParticipantId,
        #[serde(with = "serde_bytes_compat")]
        payload: Vec<u8>,
    },
}

/// Relay → client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Sent once after a successful Join. `peers` lists participants
    /// already in the session at the moment of join.
    Joined { peers: Vec<ParticipantId> },
    /// A new peer just joined this session.
    PeerJoined { participant: ParticipantId },
    /// A peer's connection closed.
    PeerLeft { participant: ParticipantId },
    /// Payload from another peer.
    Message {
        from: ParticipantId,
        #[serde(with = "serde_bytes_compat")]
        payload: Vec<u8>,
    },
    /// Operation failed. Connection may or may not stay open depending
    /// on severity (see `code`).
    Error { code: ErrorCode, detail: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Bad message ordering, malformed JSON, etc. Fatal.
    ProtocolViolation,
    /// Another connection already claimed this participant id in this
    /// session. Fatal.
    ParticipantTaken,
    /// Forward target is not in the session right now. Non-fatal.
    PeerNotFound,
    /// Sent a non-Join message as the first message. Fatal.
    NotJoined,
    /// Peer's outbound queue is full; relay closing their connection.
    /// Fatal for the disconnected peer.
    PeerBackpressure,
}

/// Workaround for `Vec<u8>` serializing as a JSON array by default with
/// `serde_json`. We keep it as a JSON array for now (debuggable, no
/// extra deps); switching to base64 or a binary codec later only
/// touches this module.
mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        bytes.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}
