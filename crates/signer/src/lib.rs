//! vouch-signer: ceremony participant exposed as an HTTP service.
//!
//! `POST /v0/dkg` runs a DKG and stores the resulting key package
//! under the joint pubkey. `POST /v0/sign` looks up that key package
//! and runs a sign ceremony, returning the aggregated signature.
//!
//! v0 holds the key package in-process; later it lives in a TEE.

pub mod api;
pub mod ceremony;

use crate::api::{DkgRequest, DkgResponse, SignRequest, SignResponse};
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
use vouch_frost::{KeyPackage, PublicKeyPackage};

#[derive(Clone)]
pub struct AccountState {
    pub key_package: KeyPackage,
    pub pubkey_package: PublicKeyPackage,
}

pub struct AppState {
    pub accounts: Mutex<HashMap<Vec<u8>, AccountState>>,
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
        .route("/v0/sign", post(handle_sign))
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

    state.accounts.lock().await.insert(
        vkey_bytes.clone(),
        AccountState {
            key_package: key_pkg,
            pubkey_package: pub_pkg,
        },
    );

    tracing::info!(
        account = %hex::encode(&vkey_bytes),
        "stored key package after DKG"
    );

    Ok(Json(DkgResponse {
        joint_pubkey_hex: hex::encode(&vkey_bytes),
    }))
}

async fn handle_sign(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, AppError> {
    let account_id = hex::decode(&req.account_pubkey_hex)
        .map_err(|e| anyhow::anyhow!("invalid account_pubkey_hex: {e}"))?;

    let account = state
        .accounts
        .lock()
        .await
        .get(&account_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("unknown account"))?;

    let sig = ceremony::run_sign(
        &req.relay_url,
        &req.session,
        req.signer_participant,
        req.client_participant,
        &account.key_package,
        &account.pubkey_package,
        &req.message,
    )
    .await?;

    let sig_bytes = postcard::to_stdvec(&sig)
        .map_err(|e| anyhow::anyhow!("encode signature: {e}"))?;

    tracing::info!(
        account = %req.account_pubkey_hex,
        msg_len = req.message.len(),
        "signed"
    );

    Ok(Json(SignResponse {
        signature_hex: hex::encode(&sig_bytes),
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
