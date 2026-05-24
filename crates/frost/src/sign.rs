//! Signing ceremony primitives.
//!
//! Both signers call [`commit`] and [`sign_share`]. The coordinator
//! (the client, in vouch) additionally calls [`make_signing_package`]
//! and [`aggregate`]. The signer service never aggregates.

use crate::{Error, Identifier, KeyPackage, MAX_SIGNERS, PublicKeyPackage};
use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};
use frost_secp256k1_tr::round2::{self, SignatureShare};
use frost_secp256k1_tr::{Signature, SigningPackage, aggregate as frost_aggregate};
use std::collections::BTreeMap;

const ALL_PARTIES: usize = MAX_SIGNERS as usize;

pub fn commit<R: rand_core::RngCore + rand_core::CryptoRng>(
    key: &KeyPackage,
    rng: &mut R,
) -> (SigningNonces, SigningCommitments) {
    frost_secp256k1_tr::round1::commit(key.signing_share(), rng)
}

pub fn make_signing_package(
    commitments: BTreeMap<Identifier, SigningCommitments>,
    message: &[u8],
) -> Result<SigningPackage, Error> {
    if commitments.len() != ALL_PARTIES {
        return Err(Error::Invariant(
            "signing: 2-of-2 expects exactly 2 nonce commitments",
        ));
    }
    Ok(SigningPackage::new(commitments, message))
}

pub fn sign_share(
    pkg: &SigningPackage,
    nonces: &SigningNonces,
    key: &KeyPackage,
) -> Result<SignatureShare, Error> {
    Ok(round2::sign(pkg, nonces, key)?)
}

pub fn aggregate(
    pkg: &SigningPackage,
    shares: &BTreeMap<Identifier, SignatureShare>,
    pubkey: &PublicKeyPackage,
) -> Result<Signature, Error> {
    if shares.len() != ALL_PARTIES {
        return Err(Error::Invariant(
            "signing: 2-of-2 expects exactly 2 signature shares",
        ));
    }
    Ok(frost_aggregate(pkg, shares, pubkey)?)
}
