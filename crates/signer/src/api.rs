//! HTTP request / response types for the signer service.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRequest {
    pub session: String,
    pub relay_url: String,
    pub signer_participant: u16,
    pub client_participant: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgResponse {
    /// Hex-encoded postcard serialization of the joint `VerifyingKey`.
    /// Doubles as the account id within the signer's key-package map.
    pub joint_pubkey_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// Account id, as returned by `DkgResponse::joint_pubkey_hex`.
    pub account_pubkey_hex: String,
    pub session: String,
    pub relay_url: String,
    pub signer_participant: u16,
    pub client_participant: u16,
    /// Opaque bytes to sign. For real userops this is the userop hash;
    /// the signer does not interpret it.
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    /// Hex-encoded postcard-serialized FROST `Signature`. Switch to
    /// canonical 64-byte BIP340 bytes when we need to ship it onchain.
    pub signature_hex: String,
}
