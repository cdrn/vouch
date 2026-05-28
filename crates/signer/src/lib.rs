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
pub mod evm;

use crate::api::{
    DkgRequest, DkgResponse, RecoverRequest, RecoverResponse, SignRequest, SignResponse,
    WalletCreateRequest, WalletCreateResponse, WalletRecoverRequest, WalletRecoverResponse,
    WalletSignExecuteRequest, WalletSignExecuteResponse,
};
use crate::evm::{EvmConfig, EvmWallet};
use axum::{
    Json, Router,
    extract::State,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};
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
    /// v0 demo wallets indexed by their onchain address (lowercased hex).
    /// Holds the BIP340 keypair the signer uses to sign opHashes
    /// server-side. v1 replaces with the real FROST share-on-device.
    pub demo_wallets: Mutex<HashMap<String, EvmWallet>>,
    /// H_passport → demo wallet account address.
    pub demo_passport_index: Mutex<HashMap<Vec<u8>, String>>,
    /// EVM config — RPC, deployer key, recovery authority key, contracts dir.
    pub evm: EvmConfig,
}

impl AppState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            accounts: Mutex::new(HashMap::new()),
            passport_index: Mutex::new(HashMap::new()),
            demo_wallets: Mutex::new(HashMap::new()),
            demo_passport_index: Mutex::new(HashMap::new()),
            evm: EvmConfig::default(),
        })
    }
}

pub fn router() -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    Router::new()
        .route("/v0/dkg", post(handle_dkg))
        .route("/v0/sign", post(handle_sign))
        .route("/v0/recover", post(handle_recover))
        .route("/v0/wallet/create", post(handle_wallet_create))
        .route("/v0/wallet/sign-and-execute", post(handle_wallet_sign_execute))
        .route("/v0/wallet/recover", post(handle_wallet_recover))
        .with_state(AppState::new())
        .layer(cors)
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

// ───── v0 demo wallet handlers (server-held keys) ─────

async fn handle_wallet_create(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WalletCreateRequest>,
) -> Result<Json<WalletCreateResponse>, AppError> {
    let h_bytes = hex::decode(&req.h_passport_hex)
        .map_err(|e| anyhow::anyhow!("invalid h_passport_hex: {e}"))?;
    if h_bytes.len() != 32 {
        return Err(AppError(anyhow::anyhow!(
            "h_passport must be 32 bytes, got {}",
            h_bytes.len()
        )));
    }

    // Generate fresh 2-of-2 FROST keypair, deploy SCA with the joint pubX.
    let wallet = EvmWallet::fresh()?;
    let pub_x_hex = wallet.pub_x_hex();
    let evm = state.evm.clone();
    let pub_x_for_deploy = pub_x_hex.clone();
    let account_address = tokio::task::spawn_blocking(move || {
        evm.deploy_vouch_account(&pub_x_for_deploy)
    })
    .await
    .map_err(|e| anyhow::anyhow!("deploy task join: {e}"))??;

    let key = account_address.to_lowercase();
    state
        .demo_passport_index
        .lock()
        .await
        .insert(h_bytes, key.clone());
    state.demo_wallets.lock().await.insert(key.clone(), wallet);

    tracing::info!(account = %account_address, pub_x = %pub_x_hex, "demo wallet created");

    Ok(Json(WalletCreateResponse {
        account_address,
        pub_x_hex,
        deploy_tx_hash: None,
    }))
}

async fn handle_wallet_sign_execute(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WalletSignExecuteRequest>,
) -> Result<Json<WalletSignExecuteResponse>, AppError> {
    let key = req.account_address.to_lowercase();

    let evm = state.evm.clone();
    let account = req.account_address.clone();
    let nonce_account = account.clone();
    let nonce = tokio::task::spawn_blocking(move || evm.read_nonce(&nonce_account))
        .await
        .map_err(|e| anyhow::anyhow!("nonce task join: {e}"))??;

    let evm = state.evm.clone();
    let target = req.target.clone();
    let value = req.value.clone();
    let data = req.data.clone();
    let account_for_hash = account.clone();
    let op_hash = tokio::task::spawn_blocking(move || {
        evm.compute_op_hash(&account_for_hash, &target, &value, &data, nonce)
    })
    .await
    .map_err(|e| anyhow::anyhow!("opHash task join: {e}"))??;

    let sig = {
        let wallets = state.demo_wallets.lock().await;
        let wallet = wallets
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("unknown demo wallet {}", req.account_address))?;
        wallet.sign_op_hash(&op_hash)?
    };
    let sig_hex = hex::encode(sig);

    let evm = state.evm.clone();
    let tx_hash = tokio::task::spawn_blocking(move || {
        evm.execute(&account, &req.target, &req.value, &req.data, &sig_hex)
    })
    .await
    .map_err(|e| anyhow::anyhow!("execute task join: {e}"))??;

    tracing::info!(account = %req.account_address, tx_hash = %tx_hash, "demo execute");

    Ok(Json(WalletSignExecuteResponse {
        tx_hash,
        op_hash_hex: hex::encode(op_hash),
        signature_hex: hex::encode(sig),
    }))
}

async fn handle_wallet_recover(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WalletRecoverRequest>,
) -> Result<Json<WalletRecoverResponse>, AppError> {
    let h_bytes = hex::decode(&req.h_passport_hex)
        .map_err(|e| anyhow::anyhow!("invalid h_passport_hex: {e}"))?;
    if h_bytes.len() != 32 {
        return Err(AppError(anyhow::anyhow!(
            "h_passport must be 32 bytes, got {}",
            h_bytes.len()
        )));
    }

    let account = state
        .demo_passport_index
        .lock()
        .await
        .get(&h_bytes)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no demo wallet registered for this H_passport"))?;

    // Generate fresh FROST keypair, sign rotation, submit.
    let new_wallet = EvmWallet::fresh()?;
    let new_pub_x_hex = new_wallet.pub_x_hex();

    let old_pub_x_hex = {
        let wallets = state.demo_wallets.lock().await;
        wallets
            .get(&account)
            .map(|w| w.pub_x_hex())
            .unwrap_or_default()
    };

    let evm = state.evm.clone();
    let account_for_digest = account.clone();
    let new_pub_x_for_digest = new_pub_x_hex.clone();
    let digest = tokio::task::spawn_blocking(move || {
        evm.rotation_digest(&account_for_digest, &new_pub_x_for_digest)
    })
    .await
    .map_err(|e| anyhow::anyhow!("rotation digest task join: {e}"))??;

    let evm = state.evm.clone();
    let digest_for_sign = digest.clone();
    let rot_sig =
        tokio::task::spawn_blocking(move || evm.sign_rotation(&digest_for_sign))
            .await
            .map_err(|e| anyhow::anyhow!("sign rotation task join: {e}"))??;

    let evm = state.evm.clone();
    let account_for_send = account.clone();
    let new_pub_x_for_send = new_pub_x_hex.clone();
    let rot_sig_for_send = rot_sig.clone();
    let rotation_tx_hash = tokio::task::spawn_blocking(move || {
        evm.rotate_pub_key(&account_for_send, &new_pub_x_for_send, &rot_sig_for_send)
    })
    .await
    .map_err(|e| anyhow::anyhow!("rotate task join: {e}"))??;

    state
        .demo_wallets
        .lock()
        .await
        .insert(account.clone(), new_wallet);

    tracing::info!(
        account = %account,
        old_pub_x = %old_pub_x_hex,
        new_pub_x = %new_pub_x_hex,
        tx_hash = %rotation_tx_hash,
        "demo recovery complete"
    );

    Ok(Json(WalletRecoverResponse {
        account_address: account,
        old_pub_x_hex,
        new_pub_x_hex,
        rotation_tx_hash,
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
