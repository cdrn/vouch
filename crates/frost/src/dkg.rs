//! 2-of-2 distributed key generation.
//!
//! Both parties run all three stages symmetrically. Each function takes
//! only what arrives on the wire from the other party, plus state held
//! locally between rounds.

use crate::{Error, Identifier, KeyPackage, MAX_SIGNERS, MIN_SIGNERS, PublicKeyPackage};
use frost_secp256k1_tr::keys::dkg;
use std::collections::BTreeMap;

pub use dkg::round1::{Package as Round1Package, SecretPackage as Round1Secret};
pub use dkg::round2::{Package as Round2Package, SecretPackage as Round2Secret};

const OTHER_PARTIES: usize = (MAX_SIGNERS - 1) as usize;

pub struct Round1Output {
    pub secret: Round1Secret,
    pub package: Round1Package,
}

pub fn round1<R: rand_core::RngCore + rand_core::CryptoRng>(
    id: Identifier,
    rng: &mut R,
) -> Result<Round1Output, Error> {
    let (secret, package) = dkg::part1(id, MAX_SIGNERS, MIN_SIGNERS, rng)?;
    Ok(Round1Output { secret, package })
}

pub struct Round2Output {
    pub secret: Round2Secret,
    pub packages: BTreeMap<Identifier, Round2Package>,
}

pub fn round2(
    secret: Round1Secret,
    received: &BTreeMap<Identifier, Round1Package>,
) -> Result<Round2Output, Error> {
    if received.len() != OTHER_PARTIES {
        return Err(Error::Invariant(
            "dkg round2: 2-of-2 expects exactly 1 round1 package from the other party",
        ));
    }
    let (secret, packages) = dkg::part2(secret, received)?;
    Ok(Round2Output { secret, packages })
}

pub fn finalize(
    secret: &Round2Secret,
    received_round1: &BTreeMap<Identifier, Round1Package>,
    received_round2: &BTreeMap<Identifier, Round2Package>,
) -> Result<(KeyPackage, PublicKeyPackage), Error> {
    if received_round1.len() != OTHER_PARTIES || received_round2.len() != OTHER_PARTIES {
        return Err(Error::Invariant(
            "dkg finalize: 2-of-2 expects exactly 1 package from the other party in each round",
        ));
    }
    Ok(dkg::part3(secret, received_round1, received_round2)?)
}
