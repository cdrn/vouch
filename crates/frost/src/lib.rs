//! vouch-frost: 2-of-2 FROST (frost-secp256k1-tr) wrapper.
//!
//! Hardcodes 2-of-2. Curve and tweak (BIP340 taproot-compatible
//! schnorr) are fixed. Ceremony primitives live in [`dkg`] and [`sign`];
//! both parties call into the same functions — there is no built-in
//! coordinator/server asymmetry in this crate. The signer service and
//! the client just call different subsets.

mod error;
pub mod dkg;
pub mod sign;

pub use error::Error;
pub use frost_secp256k1_tr::keys::{KeyPackage, PublicKeyPackage};
pub use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};
pub use frost_secp256k1_tr::round2::SignatureShare;
pub use frost_secp256k1_tr::{Identifier, Signature, SigningPackage, VerifyingKey};

pub const MIN_SIGNERS: u16 = 2;
pub const MAX_SIGNERS: u16 = 2;

pub fn identifier(n: u16) -> Identifier {
    n.try_into().expect("FROST identifier must be nonzero")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    struct Party {
        id: Identifier,
        key: KeyPackage,
        pubkey: PublicKeyPackage,
    }

    fn run_dkg_2of2<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> (Party, Party) {
        let id_a = identifier(1);
        let id_b = identifier(2);

        let a_r1 = dkg::round1(id_a, rng).unwrap();
        let b_r1 = dkg::round1(id_b, rng).unwrap();

        let a_received_r1: BTreeMap<_, _> = [(id_b, b_r1.package)].into();
        let b_received_r1: BTreeMap<_, _> = [(id_a, a_r1.package)].into();

        let a_r2 = dkg::round2(a_r1.secret, &a_received_r1).unwrap();
        let b_r2 = dkg::round2(b_r1.secret, &b_received_r1).unwrap();

        let a_received_r2: BTreeMap<_, _> = [(id_b, b_r2.packages[&id_a].clone())].into();
        let b_received_r2: BTreeMap<_, _> = [(id_a, a_r2.packages[&id_b].clone())].into();

        let (a_key, a_pub) = dkg::finalize(&a_r2.secret, &a_received_r1, &a_received_r2).unwrap();
        let (b_key, b_pub) = dkg::finalize(&b_r2.secret, &b_received_r1, &b_received_r2).unwrap();

        (
            Party { id: id_a, key: a_key, pubkey: a_pub },
            Party { id: id_b, key: b_key, pubkey: b_pub },
        )
    }

    #[test]
    fn dkg_produces_consistent_joint_pubkey() {
        let mut rng = OsRng;
        let (a, b) = run_dkg_2of2(&mut rng);
        assert_eq!(a.pubkey.verifying_key(), b.pubkey.verifying_key());
    }

    #[test]
    fn full_dkg_sign_verify() {
        let mut rng = OsRng;
        let (a, b) = run_dkg_2of2(&mut rng);

        let msg = b"vouch test message";

        let (a_nonces, a_commits) = sign::commit(&a.key, &mut rng);
        let (b_nonces, b_commits) = sign::commit(&b.key, &mut rng);

        let commits: BTreeMap<_, _> = [(a.id, a_commits), (b.id, b_commits)].into();
        let pkg = sign::make_signing_package(commits, msg).unwrap();

        let a_share = sign::sign_share(&pkg, &a_nonces, &a.key).unwrap();
        let b_share = sign::sign_share(&pkg, &b_nonces, &b.key).unwrap();

        let shares: BTreeMap<_, _> = [(a.id, a_share), (b.id, b_share)].into();
        let sig = sign::aggregate(&pkg, &shares, &a.pubkey).unwrap();

        a.pubkey
            .verifying_key()
            .verify(msg, &sig)
            .expect("aggregated signature must verify under joint pubkey");
    }

    #[test]
    fn rejects_wrong_commitment_count() {
        let mut rng = OsRng;
        let (a, _b) = run_dkg_2of2(&mut rng);
        let (_nonces, commits) = sign::commit(&a.key, &mut rng);
        let only_one: BTreeMap<_, _> = [(a.id, commits)].into();
        let err = sign::make_signing_package(only_one, b"msg").unwrap_err();
        assert!(matches!(err, Error::Invariant(_)));
    }
}
