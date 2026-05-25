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
