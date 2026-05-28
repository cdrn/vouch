//! EVM interactions for the demo wallet endpoints.
//!
//! v0 trust regression: the signer holds BOTH shares of a 2-of-2 FROST
//! key (trusted-dealer key generation) and runs the sign ceremony
//! server-side. The wire format the SCA verifies is the same canonical
//! 64-byte BIP340 signature either way — only the *custody* of the
//! shares is server-only in v0.
//!
//! Why frost-secp256k1-tr and not k256 directly: signatures produced
//! by frost-secp256k1-tr are known-good against `SchnorrVerifier.sol`
//! (gen_test_vector + the anvil-recover.sh script prove the wire
//! interop). Re-deriving that wire equivalence for a different signing
//! library is a debug rabbit hole we don't need.
//!
//! v1: replace EvmWallet::sign_op_hash with the run_sign ceremony
//! driven from the device side once UniFFI/WASM lands.

use anyhow::{Context, Result};
use frost_secp256k1_tr::keys::{
    IdentifierList, KeyPackage, PublicKeyPackage, generate_with_dealer,
};
use frost_secp256k1_tr::{Identifier, SigningPackage};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::process::Command;

/// Per-wallet 2-of-2 FROST keypair held server-side. Stored in memory;
/// lost on restart (demo).
pub struct EvmWallet {
    pub key_a: KeyPackage,
    pub key_b: KeyPackage,
    pub pubkey_package: PublicKeyPackage,
    pub id_a: Identifier,
    pub id_b: Identifier,
    /// 32-byte x-only joint BIP340 public key (matches VouchAccount.pubX).
    pub pub_x: [u8; 32],
}

impl EvmWallet {
    pub fn fresh() -> Result<Self> {
        let mut rng = OsRng;
        let (shares, pubkey_package) =
            generate_with_dealer(2, 2, IdentifierList::Default, &mut rng)
                .map_err(|e| anyhow::anyhow!("FROST trusted-dealer keygen: {e}"))?;

        // Identifier::try_from accepts u16, we use 1 and 2.
        let id_a = Identifier::try_from(1u16).unwrap();
        let id_b = Identifier::try_from(2u16).unwrap();

        let secret_a = shares
            .get(&id_a)
            .ok_or_else(|| anyhow::anyhow!("missing share for id 1"))?;
        let secret_b = shares
            .get(&id_b)
            .ok_or_else(|| anyhow::anyhow!("missing share for id 2"))?;

        let key_a = KeyPackage::try_from(secret_a.clone())
            .map_err(|e| anyhow::anyhow!("KeyPackage A: {e}"))?;
        let key_b = KeyPackage::try_from(secret_b.clone())
            .map_err(|e| anyhow::anyhow!("KeyPackage B: {e}"))?;

        // VerifyingKey::serialize gives 33-byte compressed SEC (prefix + x).
        let vk_bytes = pubkey_package
            .verifying_key()
            .serialize()
            .map_err(|e| anyhow::anyhow!("serialize joint vkey: {e}"))?;
        if vk_bytes.len() != 33 {
            anyhow::bail!("expected 33-byte SEC pubkey, got {}", vk_bytes.len());
        }
        let mut pub_x = [0u8; 32];
        pub_x.copy_from_slice(&vk_bytes[1..]);

        Ok(Self {
            key_a,
            key_b,
            pubkey_package,
            id_a,
            id_b,
            pub_x,
        })
    }

    pub fn pub_x_hex(&self) -> String {
        hex::encode(self.pub_x)
    }

    /// Run the full FROST sign ceremony with both shares in-process.
    /// Returns the canonical 64-byte BIP340 signature.
    pub fn sign_op_hash(&self, op_hash: &[u8]) -> Result<[u8; 64]> {
        use frost_secp256k1_tr::{aggregate, round1, round2};

        let mut rng = OsRng;
        let (nonces_a, commits_a) = round1::commit(self.key_a.signing_share(), &mut rng);
        let (nonces_b, commits_b) = round1::commit(self.key_b.signing_share(), &mut rng);

        let commitments: BTreeMap<_, _> =
            [(self.id_a, commits_a), (self.id_b, commits_b)].into();
        let signing_package = SigningPackage::new(commitments, op_hash);

        let share_a = round2::sign(&signing_package, &nonces_a, &self.key_a)
            .map_err(|e| anyhow::anyhow!("round2 sign a: {e}"))?;
        let share_b = round2::sign(&signing_package, &nonces_b, &self.key_b)
            .map_err(|e| anyhow::anyhow!("round2 sign b: {e}"))?;

        let shares: BTreeMap<_, _> = [(self.id_a, share_a), (self.id_b, share_b)].into();
        let sig = aggregate(&signing_package, &shares, &self.pubkey_package)
            .map_err(|e| anyhow::anyhow!("aggregate: {e}"))?;

        let sig_bytes = sig
            .serialize()
            .map_err(|e| anyhow::anyhow!("serialize sig: {e}"))?;
        if sig_bytes.len() != 64 {
            anyhow::bail!("expected 64-byte BIP340 sig, got {}", sig_bytes.len());
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig_bytes);
        Ok(out)
    }
}

/// Anvil + foundry CLI client. Uses `forge` to deploy and `cast` for
/// all read/write operations. Spawns subprocesses — slow but reliable
/// and zero rust EVM deps.
#[derive(Clone)]
pub struct EvmConfig {
    pub rpc_url: String,
    pub deployer_key: String, // hex-prefixed
    pub recovery_authority_key: String,
    pub contracts_dir: String,
    pub chain_id: u64,
}

impl Default for EvmConfig {
    fn default() -> Self {
        let root = std::env::var("VOUCH_REPO_ROOT")
            .unwrap_or_else(|_| "/Users/cdrn/Code/vouch".into());
        Self {
            rpc_url: std::env::var("VOUCH_RPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8545".into()),
            deployer_key: std::env::var("VOUCH_DEPLOYER_KEY").unwrap_or_else(|_| {
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into()
            }),
            recovery_authority_key: std::env::var("VOUCH_RECOVERY_KEY")
                .unwrap_or_else(|_| {
                    // For the demo, recovery authority == deployer.
                    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into()
                }),
            contracts_dir: format!("{root}/contracts"),
            chain_id: 31337,
        }
    }
}

impl EvmConfig {
    pub fn recovery_authority_address(&self) -> Result<String> {
        let out = run_cmd(Command::new("cast").args([
            "wallet",
            "address",
            "--private-key",
            &self.recovery_authority_key,
        ]))?;
        Ok(out.trim().to_string())
    }

    /// Deploy VouchAccount(pubX, recoveryAuthority) and return its address.
    pub fn deploy_vouch_account(&self, pub_x_hex: &str) -> Result<String> {
        let recovery_addr = self.recovery_authority_address()?;
        let pub_x = if pub_x_hex.starts_with("0x") {
            pub_x_hex.to_string()
        } else {
            format!("0x{pub_x_hex}")
        };

        let stdout = run_cmd(
            Command::new("forge")
                .current_dir(&self.contracts_dir)
                .args([
                    "create",
                    "src/VouchAccount.sol:VouchAccount",
                    "--rpc-url",
                    &self.rpc_url,
                    "--private-key",
                    &self.deployer_key,
                    "--broadcast",
                    "--json",
                    "--constructor-args",
                    &pub_x,
                    &recovery_addr,
                ])
                .env("FOUNDRY_DISABLE_NIGHTLY_WARNING", "1"),
        )?;

        let v = parse_json_object(&stdout)
            .with_context(|| format!("forge create JSON parse failed: {stdout}"))?;
        v.get("deployedTo")
            .and_then(|x| x.as_str())
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("forge create lacked deployedTo: {stdout}"))
    }

    /// Read VouchAccount.nonce().
    pub fn read_nonce(&self, account: &str) -> Result<u64> {
        let out = run_cmd(Command::new("cast").args([
            "call",
            account,
            "nonce()",
            "--rpc-url",
            &self.rpc_url,
        ]))?;
        let hex_val = out.trim().trim_start_matches("0x");
        Ok(u64::from_str_radix(hex_val, 16).unwrap_or(0))
    }

    /// Compute the SCA's op hash for a (target, value, data, nonce) tuple.
    pub fn compute_op_hash(
        &self,
        account: &str,
        target: &str,
        value: &str,
        data: &str,
        nonce: u64,
    ) -> Result<[u8; 32]> {
        let data_hash = run_cmd(Command::new("cast").args(["keccak", data]))?;
        let data_hash = data_hash.trim();

        let encoded = run_cmd(Command::new("cast").args([
            "abi-encode",
            "f(address,uint256,bytes32,uint256,uint256,address)",
            target,
            value,
            data_hash,
            &nonce.to_string(),
            &self.chain_id.to_string(),
            account,
        ]))?;

        let op_hash_hex = run_cmd(Command::new("cast").args(["keccak", encoded.trim()]))?;
        let op_hash_hex = op_hash_hex.trim().trim_start_matches("0x");
        let mut out = [0u8; 32];
        hex::decode_to_slice(op_hash_hex, &mut out)
            .with_context(|| format!("decode op hash hex {op_hash_hex}"))?;
        Ok(out)
    }

    /// Submit VouchAccount.execute(target, value, data, sig). Returns tx hash.
    pub fn execute(
        &self,
        account: &str,
        target: &str,
        value: &str,
        data: &str,
        sig_hex: &str,
    ) -> Result<String> {
        let sig = if sig_hex.starts_with("0x") {
            sig_hex.to_string()
        } else {
            format!("0x{sig_hex}")
        };
        let stdout = run_cmd(
            Command::new("cast")
                .args([
                    "send",
                    account,
                    "execute(address,uint256,bytes,bytes)",
                    target,
                    value,
                    data,
                    &sig,
                    "--rpc-url",
                    &self.rpc_url,
                    "--private-key",
                    &self.deployer_key,
                    "--json",
                ])
                .env("FOUNDRY_DISABLE_NIGHTLY_WARNING", "1"),
        )?;
        let v = parse_json_object(&stdout)
            .with_context(|| format!("cast send JSON parse failed: {stdout}"))?;
        v.get("transactionHash")
            .and_then(|x| x.as_str())
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("cast send lacked transactionHash: {stdout}"))
    }

    /// Read VouchAccount.rotationDigest(newPubX). Returns the 32-byte
    /// digest as hex.
    pub fn rotation_digest(&self, account: &str, new_pub_x: &str) -> Result<String> {
        let pub_x = if new_pub_x.starts_with("0x") {
            new_pub_x.to_string()
        } else {
            format!("0x{new_pub_x}")
        };
        let out = run_cmd(Command::new("cast").args([
            "call",
            account,
            "rotationDigest(uint256)(bytes32)",
            &pub_x,
            "--rpc-url",
            &self.rpc_url,
        ]))?;
        Ok(out.trim().to_string())
    }

    /// Have the recovery authority sign a rotation digest (EIP-191 prefix
    /// applied by `cast wallet sign`).
    pub fn sign_rotation(&self, digest_hex: &str) -> Result<String> {
        let out = run_cmd(Command::new("cast").args([
            "wallet",
            "sign",
            "--private-key",
            &self.recovery_authority_key,
            digest_hex,
        ]))?;
        Ok(out.trim().to_string())
    }

    /// Submit VouchAccount.rotatePubKey(newPubX, sig). Returns tx hash.
    pub fn rotate_pub_key(
        &self,
        account: &str,
        new_pub_x: &str,
        sig: &str,
    ) -> Result<String> {
        let pub_x = if new_pub_x.starts_with("0x") {
            new_pub_x.to_string()
        } else {
            format!("0x{new_pub_x}")
        };
        let stdout = run_cmd(
            Command::new("cast")
                .args([
                    "send",
                    account,
                    "rotatePubKey(uint256,bytes)",
                    &pub_x,
                    sig,
                    "--rpc-url",
                    &self.rpc_url,
                    "--private-key",
                    &self.deployer_key,
                    "--json",
                ])
                .env("FOUNDRY_DISABLE_NIGHTLY_WARNING", "1"),
        )?;
        let v = parse_json_object(&stdout)
            .with_context(|| format!("cast send JSON parse failed: {stdout}"))?;
        v.get("transactionHash")
            .and_then(|x| x.as_str())
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("cast send lacked transactionHash: {stdout}"))
    }
}

/// Extract the first JSON object from a string (skipping any leading
/// chatter), since some foundry commands print warnings before JSON.
fn parse_json_object(s: &str) -> Result<serde_json::Value> {
    let start = s
        .find('{')
        .ok_or_else(|| anyhow::anyhow!("no JSON object in: {s}"))?;
    let trailing = &s[start..];
    Ok(serde_json::from_str::<serde_json::Value>(trailing.trim_end())?)
}

fn run_cmd(cmd: &mut Command) -> Result<String> {
    let output = cmd
        .output()
        .with_context(|| format!("spawning {:?}", cmd.get_program()))?;
    if !output.status.success() {
        anyhow::bail!(
            "{:?} failed: stdout={}, stderr={}",
            cmd.get_program(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}
