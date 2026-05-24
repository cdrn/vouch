//! vouch-frost: 2-of-2 FROST (frost-secp256k1-tr) wrapper.
//!
//! DKG, sign, and refresh ceremonies live here. v0 hardcodes 2-of-2;
//! curve and tweak (BIP340 taproot-compatible schnorr) are fixed.

use frost_secp256k1_tr as frost;

pub use frost::keys::{KeyPackage, PublicKeyPackage};
pub use frost::{Identifier, Signature, VerifyingKey};

pub const MIN_SIGNERS: u16 = 2;
pub const MAX_SIGNERS: u16 = 2;

pub fn identifier(n: u16) -> Identifier {
    n.try_into().expect("FROST identifier must be nonzero")
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1_tr::keys::dkg;
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    #[test]
    fn dkg_sign_verify_happy_path() {
        let mut rng = OsRng;

        let id_a = identifier(1);
        let id_b = identifier(2);

        // DKG round 1
        let (a_r1_secret, a_r1_pkg) =
            dkg::part1(id_a, MAX_SIGNERS, MIN_SIGNERS, &mut rng).unwrap();
        let (b_r1_secret, b_r1_pkg) =
            dkg::part1(id_b, MAX_SIGNERS, MIN_SIGNERS, &mut rng).unwrap();

        // each participant receives the OTHER's round1 package
        let a_received_r1: BTreeMap<_, _> = [(id_b, b_r1_pkg)].into();
        let b_received_r1: BTreeMap<_, _> = [(id_a, a_r1_pkg)].into();

        // DKG round 2
        let (a_r2_secret, a_r2_pkgs) =
            dkg::part2(a_r1_secret, &a_received_r1).unwrap();
        let (b_r2_secret, b_r2_pkgs) =
            dkg::part2(b_r1_secret, &b_received_r1).unwrap();

        // each participant sends the round2 package addressed to the other
        let a_received_r2: BTreeMap<_, _> =
            [(id_b, b_r2_pkgs[&id_a].clone())].into();
        let b_received_r2: BTreeMap<_, _> =
            [(id_a, a_r2_pkgs[&id_b].clone())].into();

        // DKG part 3 (finalize)
        let (a_key_pkg, a_pubkey_pkg) =
            dkg::part3(&a_r2_secret, &a_received_r1, &a_received_r2).unwrap();
        let (b_key_pkg, b_pubkey_pkg) =
            dkg::part3(&b_r2_secret, &b_received_r1, &b_received_r2).unwrap();

        // both parties agree on the joint pubkey
        assert_eq!(a_pubkey_pkg.verifying_key(), b_pubkey_pkg.verifying_key());

        // sign: round 1 (nonce commitments)
        let msg = b"vouch test message";

        let (a_nonces, a_commits) =
            frost::round1::commit(a_key_pkg.signing_share(), &mut rng);
        let (b_nonces, b_commits) =
            frost::round1::commit(b_key_pkg.signing_share(), &mut rng);

        let commitments: BTreeMap<_, _> =
            [(id_a, a_commits), (id_b, b_commits)].into();
        let signing_package = frost::SigningPackage::new(commitments, msg);

        // sign: round 2 (signature shares)
        let a_share =
            frost::round2::sign(&signing_package, &a_nonces, &a_key_pkg).unwrap();
        let b_share =
            frost::round2::sign(&signing_package, &b_nonces, &b_key_pkg).unwrap();

        let shares: BTreeMap<_, _> = [(id_a, a_share), (id_b, b_share)].into();

        // aggregate + verify
        let group_sig =
            frost::aggregate(&signing_package, &shares, &a_pubkey_pkg).unwrap();

        a_pubkey_pkg
            .verifying_key()
            .verify(msg, &group_sig)
            .expect("aggregated signature must verify under joint pubkey");
    }
}
