//! vouch-signer: ceremony participant exposed as an HTTP service.
//!
//! `POST /v0/dkg` runs a DKG with a peer over a relay session and
//! stores the resulting key package under the joint pubkey. v0 holds
//! the key package in-process; later it lives in a TEE.

pub mod api;
pub mod ceremony;

use crate::api::{DkgRequest, DkgResponse};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use vouch_frost::KeyPackage;

pub struct AppState {
    /// account id (postcard-serialized joint VerifyingKey) → key package.
    pub accounts: Mutex<HashMap<Vec<u8>, KeyPackage>>,
}

impl AppState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            accounts: Mutex::new(HashMap::new()),
        })
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/v0/dkg", post(handle_dkg))
        .with_state(AppState::new())
}

async fn handle_dkg(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DkgRequest>,
) -> Result<Json<DkgResponse>, AppError> {
    let (key_pkg, pub_pkg) = ceremony::run_dkg(
        &req.relay_url,
        &req.session,
        req.signer_participant,
        req.client_participant,
    )
    .await?;

    let vkey_bytes = postcard::to_stdvec(pub_pkg.verifying_key())
        .map_err(|e| anyhow::anyhow!("encode joint vkey: {e}"))?;

    state.accounts.lock().await.insert(vkey_bytes.clone(), key_pkg);

    tracing::info!(
        account = %hex::encode(&vkey_bytes),
        "stored key package after DKG"
    );

    Ok(Json(DkgResponse {
        joint_pubkey_hex: hex::encode(&vkey_bytes),
    }))
}

pub struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("handler error: {:#}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("{:#}", self.0)).into_response()
    }
}
