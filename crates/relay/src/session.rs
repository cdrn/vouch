//! In-memory session registry.
//!
//! A session is a group of WebSocket connections identified by an
//! opaque `SessionId`. Each connection registers itself under a
//! `ParticipantId` unique within the session. The registry forwards
//! unicast messages between members and tears sessions down when their
//! last member leaves.

use crate::protocol::{ParticipantId, ServerMessage, SessionId};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc};

const OUTBOUND_BUFFER: usize = 64;

#[derive(Default)]
pub struct Registry {
    sessions: Mutex<HashMap<SessionId, Session>>,
}

#[derive(Default)]
struct Session {
    members: HashMap<ParticipantId, mpsc::Sender<ServerMessage>>,
}

#[derive(Debug, Error)]
pub enum JoinError {
    #[error("participant id already in session")]
    ParticipantTaken,
}

#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("target peer not in session")]
    PeerNotFound,
    #[error("target peer outbound queue full")]
    PeerBackpressure,
}

impl Registry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn outbound_buffer() -> usize {
        OUTBOUND_BUFFER
    }

    /// Add a participant to a session. Returns the list of existing
    /// peers (if any), and notifies them that a new peer joined.
    pub async fn join(
        &self,
        session: &SessionId,
        participant: ParticipantId,
        outbound: mpsc::Sender<ServerMessage>,
    ) -> Result<Vec<ParticipantId>, JoinError> {
        let mut sessions = self.sessions.lock().await;
        let sess = sessions.entry(session.clone()).or_default();
        if sess.members.contains_key(&participant) {
            return Err(JoinError::ParticipantTaken);
        }
        let existing: Vec<_> = sess.members.keys().copied().collect();
        for peer_tx in sess.members.values() {
            let _ = peer_tx.try_send(ServerMessage::PeerJoined { participant });
        }
        sess.members.insert(participant, outbound);
        Ok(existing)
    }

    /// Deliver `payload` to one peer in the session.
    pub async fn forward(
        &self,
        session: &SessionId,
        from: ParticipantId,
        to: ParticipantId,
        payload: Vec<u8>,
    ) -> Result<(), ForwardError> {
        let sessions = self.sessions.lock().await;
        let sess = sessions.get(session).ok_or(ForwardError::PeerNotFound)?;
        let target = sess.members.get(&to).ok_or(ForwardError::PeerNotFound)?;
        target
            .try_send(ServerMessage::Message { from, payload })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => ForwardError::PeerBackpressure,
                mpsc::error::TrySendError::Closed(_) => ForwardError::PeerNotFound,
            })
    }

    /// Remove a participant. Notifies remaining peers. Cleans up empty
    /// sessions.
    pub async fn leave(&self, session: &SessionId, participant: ParticipantId) {
        let mut sessions = self.sessions.lock().await;
        let Some(sess) = sessions.get_mut(session) else {
            return;
        };
        if sess.members.remove(&participant).is_none() {
            return;
        }
        for peer_tx in sess.members.values() {
            let _ = peer_tx.try_send(ServerMessage::PeerLeft { participant });
        }
        if sess.members.is_empty() {
            sessions.remove(session);
        }
    }
}
