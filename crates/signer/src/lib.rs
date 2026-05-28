//! vouch-signer: ceremony participant exposed as an HTTP service.
//!
//! Endpoints:
//!   POST /v0/dkg     run DKG, store key package, optionally bind to H_passport
//!   POST /v0/sign    sign a message via FROST
//!   POST /v0/recover look up an account by H_passport
//!
//! v0 holds the key package in-process; later it lives in a TEE.

pub mod api;
pub mod ceremony;

use crate::api::{
    DkgRequest, DkgResponse, RecoverRequest, RecoverResponse, SignRequest, SignResponse,
};
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
    /// account id (postcard-serialized joint VerifyingKey, hex'd) → account state.
    pub accounts: Mutex<HashMap<Vec<u8>, AccountState>>,
    /// H_passport (32-byte commitment) → account id (postcard-serialized
    /// joint VerifyingKey). Set at DKG time when the client passes
    /// h_passport_hex; read at /v0/recover time.
    pub passport_index: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl AppState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            accounts: Mutex::new(HashMap::new()),
            passport_index: Mutex::new(HashMap::new()),
        })
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/v0/dkg", post(handle_dkg))
        .route("/v0/sign", post(handle_sign))
        .route("/v0/recover", post(handle_recover))
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

    if let Some(h_passport_hex) = req.h_passport_hex.as_deref() {
        let h_bytes = hex::decode(h_passport_hex)
            .map_err(|e| anyhow::anyhow!("invalid h_passport_hex: {e}"))?;
        if h_bytes.len() != 32 {
            return Err(AppError(anyhow::anyhow!(
                "h_passport must be 32 bytes, got {}",
                h_bytes.len()
            )));
        }
        state
            .passport_index
            .lock()
            .await
            .insert(h_bytes, vkey_bytes.clone());
        tracing::info!(
            account = %hex::encode(&vkey_bytes),
            h_passport = %h_passport_hex,
            "registered H_passport commitment for account"
        );
    }

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

async fn handle_recover(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>, AppError> {
    let h_bytes = hex::decode(&req.h_passport_hex)
        .map_err(|e| anyhow::anyhow!("invalid h_passport_hex: {e}"))?;
    if h_bytes.len() != 32 {
        return Err(AppError(anyhow::anyhow!(
            "h_passport must be 32 bytes, got {}",
            h_bytes.len()
        )));
    }

    let account_id = state.passport_index.lock().await.get(&h_bytes).cloned();
    match account_id {
        Some(id) => {
            tracing::info!(
                h_passport = %req.h_passport_hex,
                account = %hex::encode(&id),
                "recover: H_passport matched"
            );
            Ok(Json(RecoverResponse {
                account_pubkey_hex: hex::encode(&id),
                matched: true,
            }))
        }
        None => {
            tracing::info!(h_passport = %req.h_passport_hex, "recover: no match");
            Ok(Json(RecoverResponse {
                account_pubkey_hex: String::new(),
                matched: false,
            }))
        }
    }
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
