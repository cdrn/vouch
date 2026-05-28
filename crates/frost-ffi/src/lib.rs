//! vouch-frost-ffi: opaque-blob facade over vouch-frost for the FFI
//! boundary.
//!
//! React Native (and any other non-Rust caller) consumes vouch-frost
//! via this crate. Every type that crosses the FFI boundary is either
//! a primitive, a `Vec<u8>` (postcard-serialized FROST type), a
//! `String` (hex-encoded for human-readable IDs), or a simple record
//! of those.
//!
//! Why a separate crate: `vouch-frost`'s native API uses BTreeMap and
//! generic FROST types that don't survive the C ABI cleanly. Keeping
//! the wrapper here means the cryptographic core stays clean and the
//! FFI noise is isolated.

use rand::rngs::OsRng;
use std::collections::BTreeMap;
use thiserror::Error;
use vouch_frost::{dkg, identifier, sign};

uniffi::setup_scaffolding!();

// ───── Errors ────────────────────────────────────────────────────────────

#[derive(Debug, Error, uniffi::Error)]
pub enum FrostFfiError {
    #[error("invalid input: {msg}")]
    Invalid { msg: String },
    #[error("frost: {msg}")]
    Frost { msg: String },
    #[error("postcard: {msg}")]
    Postcard { msg: String },
}

impl From<vouch_frost::Error> for FrostFfiError {
    fn from(e: vouch_frost::Error) -> Self {
        FrostFfiError::Frost { msg: e.to_string() }
    }
}

impl From<postcard::Error> for FrostFfiError {
    fn from(e: postcard::Error) -> Self {
        FrostFfiError::Postcard { msg: e.to_string() }
    }
}

fn invalid(msg: impl Into<String>) -> FrostFfiError {
    FrostFfiError::Invalid { msg: msg.into() }
}

fn frost_err(msg: impl Into<String>) -> FrostFfiError {
    FrostFfiError::Frost { msg: msg.into() }
}

// ───── DKG ───────────────────────────────────────────────────────────────

/// Output of DKG round 1. `secret` is held privately by the caller and
/// passed to `dkg_round2`; `package` is sent over the wire to the
/// other party.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DkgRound1Output {
    pub secret: Vec<u8>,
    pub package: Vec<u8>,
}

/// Output of DKG round 2. `secret` is held privately; `package_for_other`
/// is sent point-to-point to the other party (2-of-2: exactly one peer).
#[derive(Debug, Clone, uniffi::Record)]
pub struct DkgRound2Output {
    pub secret: Vec<u8>,
    pub package_for_other: Vec<u8>,
}

/// Output of DKG finalize. `key_package` is the device's share (store
/// encrypted on-device); `pubkey_package` is the joint pubkey package
/// (use to verify signatures or as the account id).
#[derive(Debug, Clone, uniffi::Record)]
pub struct DkgFinalizeOutput {
    pub key_package: Vec<u8>,
    pub pubkey_package: Vec<u8>,
    /// 32-byte x-only BIP340 joint verifying key (drops the 0x02/0x03
    /// SEC prefix — what the SCA's `pubX` stores).
    pub joint_pubkey_x: Vec<u8>,
}

#[uniffi::export]
pub fn dkg_round1(my_participant_id: u16) -> Result<DkgRound1Output, FrostFfiError> {
    let mut rng = OsRng;
    let out = dkg::round1(identifier(my_participant_id), &mut rng)?;
    Ok(DkgRound1Output {
        secret: postcard::to_stdvec(&out.secret)?,
        package: postcard::to_stdvec(&out.package)?,
    })
}

#[uniffi::export]
pub fn dkg_round2(
    round1_secret: Vec<u8>,
    other_participant_id: u16,
    other_round1_package: Vec<u8>,
) -> Result<DkgRound2Output, FrostFfiError> {
    let secret: dkg::Round1Secret = postcard::from_bytes(&round1_secret)?;
    let other_pkg: dkg::Round1Package = postcard::from_bytes(&other_round1_package)?;
    let other_id = identifier(other_participant_id);
    let received: BTreeMap<_, _> = [(other_id, other_pkg)].into();
    let out = dkg::round2(secret, &received)?;
    let pkg_for_other = out
        .packages
        .get(&other_id)
        .ok_or_else(|| invalid("round2 missing package for other party"))?;
    Ok(DkgRound2Output {
        secret: postcard::to_stdvec(&out.secret)?,
        package_for_other: postcard::to_stdvec(pkg_for_other)?,
    })
}

#[uniffi::export]
pub fn dkg_finalize(
    round2_secret: Vec<u8>,
    other_participant_id: u16,
    other_round1_package: Vec<u8>,
    other_round2_package: Vec<u8>,
) -> Result<DkgFinalizeOutput, FrostFfiError> {
    let secret: dkg::Round2Secret = postcard::from_bytes(&round2_secret)?;
    let other_r1: dkg::Round1Package = postcard::from_bytes(&other_round1_package)?;
    let other_r2: dkg::Round2Package = postcard::from_bytes(&other_round2_package)?;
    let other_id = identifier(other_participant_id);
    let received_r1: BTreeMap<_, _> = [(other_id, other_r1)].into();
    let received_r2: BTreeMap<_, _> = [(other_id, other_r2)].into();
    let (key_pkg, pub_pkg) = dkg::finalize(&secret, &received_r1, &received_r2)?;

    // SEC-compressed pubkey is 33 bytes (0x02/0x03 prefix + 32 x-coord);
    // drop the prefix for BIP340 x-only.
    let vk_bytes = pub_pkg
        .verifying_key()
        .serialize()
        .map_err(|e| frost_err(format!("serialize vkey: {e}")))?;
    if vk_bytes.len() != 33 {
        return Err(invalid(format!(
            "expected 33-byte SEC pubkey, got {}",
            vk_bytes.len()
        )));
    }
    let joint_pubkey_x = vk_bytes[1..].to_vec();

    Ok(DkgFinalizeOutput {
        key_package: postcard::to_stdvec(&key_pkg)?,
        pubkey_package: postcard::to_stdvec(&pub_pkg)?,
        joint_pubkey_x,
    })
}

// ───── Signing ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, uniffi::Record)]
pub struct SignCommitOutput {
    pub nonces: Vec<u8>,
    pub commitments: Vec<u8>,
}

#[uniffi::export]
pub fn sign_commit(key_package: Vec<u8>) -> Result<SignCommitOutput, FrostFfiError> {
    let key: vouch_frost::KeyPackage = postcard::from_bytes(&key_package)?;
    let mut rng = OsRng;
    let (nonces, commits) = sign::commit(&key, &mut rng);
    Ok(SignCommitOutput {
        nonces: postcard::to_stdvec(&nonces)?,
        commitments: postcard::to_stdvec(&commits)?,
    })
}

#[uniffi::export]
pub fn sign_sign_share(
    signing_package: Vec<u8>,
    nonces: Vec<u8>,
    key_package: Vec<u8>,
) -> Result<Vec<u8>, FrostFfiError> {
    let pkg: vouch_frost::SigningPackage = postcard::from_bytes(&signing_package)?;
    let nonces: vouch_frost::SigningNonces = postcard::from_bytes(&nonces)?;
    let key: vouch_frost::KeyPackage = postcard::from_bytes(&key_package)?;
    let share = sign::sign_share(&pkg, &nonces, &key)?;
    Ok(postcard::to_stdvec(&share)?)
}

#[uniffi::export]
pub fn sign_make_signing_package(
    my_participant_id: u16,
    my_commitments: Vec<u8>,
    other_participant_id: u16,
    other_commitments: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>, FrostFfiError> {
    let mine: vouch_frost::SigningCommitments = postcard::from_bytes(&my_commitments)?;
    let theirs: vouch_frost::SigningCommitments = postcard::from_bytes(&other_commitments)?;
    let map: BTreeMap<_, _> = [
        (identifier(my_participant_id), mine),
        (identifier(other_participant_id), theirs),
    ]
    .into();
    let pkg = sign::make_signing_package(map, &message)?;
    Ok(postcard::to_stdvec(&pkg)?)
}

#[uniffi::export]
pub fn sign_aggregate(
    signing_package: Vec<u8>,
    my_participant_id: u16,
    my_share: Vec<u8>,
    other_participant_id: u16,
    other_share: Vec<u8>,
    pubkey_package: Vec<u8>,
) -> Result<Vec<u8>, FrostFfiError> {
    let pkg: vouch_frost::SigningPackage = postcard::from_bytes(&signing_package)?;
    let pubkey: vouch_frost::PublicKeyPackage = postcard::from_bytes(&pubkey_package)?;
    let mine: vouch_frost::SignatureShare = postcard::from_bytes(&my_share)?;
    let theirs: vouch_frost::SignatureShare = postcard::from_bytes(&other_share)?;
    let shares: BTreeMap<_, _> = [
        (identifier(my_participant_id), mine),
        (identifier(other_participant_id), theirs),
    ]
    .into();
    let sig = sign::aggregate(&pkg, &shares, &pubkey)?;
    // Return canonical BIP340 64-byte signature (R_x || s) — this is
    // what the on-chain SchnorrVerifier expects.
    let sig_bytes = sig
        .serialize()
        .map_err(|e| frost_err(format!("serialize sig: {e}")))?;
    Ok(sig_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a full DKG + sign + aggregate through the FFI surface in
    /// process, with both parties running the same FFI functions. Asserts
    /// the joint pubkey is consistent across parties and that the
    /// 64-byte BIP340 sig verifies under it.
    #[test]
    fn ffi_dkg_sign_round_trip() {
        let id_a: u16 = 1;
        let id_b: u16 = 2;

        // DKG
        let a_r1 = dkg_round1(id_a).unwrap();
        let b_r1 = dkg_round1(id_b).unwrap();

        let a_r2 = dkg_round2(a_r1.secret.clone(), id_b, b_r1.package.clone()).unwrap();
        let b_r2 = dkg_round2(b_r1.secret.clone(), id_a, a_r1.package.clone()).unwrap();

        let a_final = dkg_finalize(
            a_r2.secret.clone(),
            id_b,
            b_r1.package.clone(),
            b_r2.package_for_other.clone(),
        )
        .unwrap();
        let b_final = dkg_finalize(
            b_r2.secret.clone(),
            id_a,
            a_r1.package.clone(),
            a_r2.package_for_other.clone(),
        )
        .unwrap();

        assert_eq!(
            a_final.joint_pubkey_x, b_final.joint_pubkey_x,
            "joint pubkey must match across parties"
        );

        // Sign
        let msg = b"vouch ffi round-trip test".to_vec();
        let a_commit = sign_commit(a_final.key_package.clone()).unwrap();
        let b_commit = sign_commit(b_final.key_package.clone()).unwrap();

        let pkg_a = sign_make_signing_package(
            id_a,
            a_commit.commitments.clone(),
            id_b,
            b_commit.commitments.clone(),
            msg.clone(),
        )
        .unwrap();

        let a_share = sign_sign_share(
            pkg_a.clone(),
            a_commit.nonces.clone(),
            a_final.key_package.clone(),
        )
        .unwrap();
        let b_share = sign_sign_share(
            pkg_a.clone(),
            b_commit.nonces.clone(),
            b_final.key_package.clone(),
        )
        .unwrap();

        let sig_bytes = sign_aggregate(
            pkg_a,
            id_a,
            a_share,
            id_b,
            b_share,
            a_final.pubkey_package.clone(),
        )
        .unwrap();
        assert_eq!(sig_bytes.len(), 64, "BIP340 sig must be 64 bytes");

        // Reach back through vouch-frost directly to confirm the sig
        // verifies under the joint pubkey package.
        let pubkey_pkg: vouch_frost::PublicKeyPackage =
            postcard::from_bytes(&a_final.pubkey_package).unwrap();
        let sig = vouch_frost::Signature::deserialize(&sig_bytes)
            .expect("deserialize sig");
        pubkey_pkg
            .verifying_key()
            .verify(&msg, &sig)
            .expect("aggregated sig must verify under joint pubkey");
    }
}
