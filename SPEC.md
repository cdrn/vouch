# spec: passport-recoverable 2/2 frost wallet

## primitives
- **curve**: secp256k1, BIP340 schnorr sigs (frost-secp256k1-tr)
- **threshold**: 2-of-2
- **participants**: user device (passkey-bound share) + co-signer service (server-held share)
- **main chain**: ethereum mainnet, EIP-7702-delegated EOA → ERC-4337-style SCA logic w/ onchain schnorr verifier
- **cross-chain**: same EOA address works as a plain EOA on other chains via session keys (see below)

## share custody
- **user share**: stored on-device, encrypted-at-rest w/ KEK derived from WebAuthn PRF extension over the user's passkey. passkey synced via platform (icloud keychain / google credential manager) for cross-device. share material itself stays local per device, KEK is what's portable.
- **co-signer share**: held in tee (nitro enclave). never extracted. all ceremony rounds executed inside.

## identity binding
- at setup, user scans passport via NFC. zk-passport circuit (self.xyz or rarimo fork) generates commitment over stable attributes (country, dob, name_hash, document_number_hash) → `H_passport`
- `H_passport` stored co-signer side, indexed by account
- account contract stores nothing about identity onchain (privacy preserved)

## DKG (setup)
1. user creates passkey on device, derives KEK via PRF
2. client generates a fresh single-party ECDSA keypair `K` on device — gives the wallet an address `A`
3. client + co-signer run frost DKG ceremony over websocket relay
4. both parties end with: their respective share, the joint pubkey `P`
5. client encrypts share w/ KEK, stores locally
6. user scans passport, generates zk-proof committing to attributes, sends to co-signer
7. co-signer verifies proof, stores `H_passport` against account
8. client signs an EIP-7702 authorization with `K`: "delegate `A` → vouch SCA contract, init with `P`"
9. submit the delegation tx (paymaster-sponsored or user-funded)
10. **client deletes `K`** — address `A` is now permanently bound to vouch SCA logic; no admin escape hatch. trade-off: if SCA has a bug, user bridges out via session keys, can never undelegate.

## sign (normal flow)
1. user constructs userop, computes hash
2. client decrypts local share (via passkey unlock → PRF → KEK), enters ceremony
3. ws session opened, co-signer joins
4. frost round 1: nonce commitments exchanged
5. frost round 2: partial sigs exchanged
6. client aggregates → 64-byte schnorr sig
7. userop submitted to bundler, account contract's `validateUserOp` runs onchain schnorr verifier against `P`

## recover (passkey lost)
1. user installs wallet on new device, creates new passkey
2. client signals "recovery mode" to co-signer w/ new device pubkey
3. user scans passport, generates fresh zk-proof
4. proof submitted to co-signer; co-signer verifies and checks commitment matches `H_passport` for this account
5. on match, co-signer initiates **share refresh ceremony**:
   - new DKG between new-device share-holder and co-signer
   - new shares generated, OLD shares invalidated (via verifiable proactive secret sharing — both parties commit to randomness that re-randomizes shares while preserving `P`)
   - joint pubkey `P` unchanged → account contract unchanged onchain
6. new client encrypts new share w/ new device's KEK, stores
7. signing resumes w/ new device + co-signer

## onchain (main chain, EIP-7702 + 4337-style SCA)
- user's wallet address `A` is a normal EOA address (derived from one-shot ECDSA key `K`, which was deleted after the 7702 delegation tx landed)
- after delegation, `A` executes the vouch SCA contract code for every tx sent to it
- SCA storage holds: aggregate pubkey `P`, session-key registry, replay nonces
- `validateUserOp(userop, sig)`:
  - if sig is a registered session-key ECDSA sig within policy → verify via ecrecover, ~3k gas
  - else, verify sig is a valid BIP340 schnorr sig under `P` → ~80-120k gas via ecrecover-trick verifier (chainflip keymanager port)
- no recovery logic onchain — `P` never changes across recoveries bc refresh ceremony preserves it. recovery is fully offchain
- session keys: short-lived ECDSA keypairs registered by a FROST-signed userop. each carries a policy (expiry, spending cap, allowed call targets). expected to be the hot path for ~95% of userops — Schnorr verifier runs once per session, not once per tx
- the SCA code is immutable from the user's perspective: there is no admin key, no proxy upgradeability, no way to redelegate `A` (because `K` is gone)

## session keys
- short-lived ECDSA keypairs registered in the main-chain SCA via a FROST-signed userop
- per-key policy stored onchain: expiry timestamp, spending cap (total ETH/value moved), allowlist of call targets (e.g., specific dexes / tokens)
- device holds the session-key private material; co-signer never sees it
- in-session userops: ECDSA sig (3k gas) + policy check (5-10k storage reads) — full sign cost ~15k vs ~150k for direct FROST
- revoke: any session key can be revoked early by a FROST-signed userop
- compromised device blast radius is bounded by the active session's policy

## cross-chain
- same EOA address `A` works on every EVM chain (ECDSA pubkey → address is chain-agnostic)
- on the main chain, `A` is 7702-delegated to vouch SCA — full threshold + recovery property
- on other chains, `A` is undelegated by default — it's just a plain EOA, controlled by whichever session key the user is currently using
- model: main chain is the **vault**, session keys are **spending wallets** that happen to act as plain EOAs cross-chain
- flow: FROST-sign a userop on main chain to bridge value to a session key's address on chain X → session key signs txs on chain X as a normal EOA → leftover funds bridge back to vault when session expires
- no onchain identity / recovery on non-main chains — those are intentionally low-trust spending environments. value at rest stays on main chain

## relay / coordination
- websocket relay server, dumb message bus
- relay sees: session ids, message ciphertexts (encrypted between participants), timing
- relay cannot: decrypt messages, forge participation, hold shares
- multiple relays acceptable, client tries in order

## state
- co-signer state per account: `H_passport`, account pubkey `P`, last_signed_userop_hash, share material in tee
- replay prevention: co-signer refuses to sign same userop hash twice
- no shared state needed (single co-signer v0)

## failure modes (acknowledged, unfixed v0)
- co-signer compromised: shares safe (in tee), but co-signer can refuse all signs. user cooked until ops restored.
- co-signer down: same as above.
- co-signer compelled (legal/regulatory): refuses target user, target user cooked.
- passport lost AND co-signer refuses: target user fully cooked. no slow-path backstop in v0.
- passport reissued: nullifier scheme on stable attributes means new passport produces same `H_passport`, recovery still works (this is the design dividend of attribute-based commitment).
- self.xyz / rarimo circuit bug: forgeable proofs. trust assumption.
- country signing key compromised: forgeable proofs for citizens of that country. trust assumption.

## components to build
1. **frost-core wrapper** (rust lib): DKG + sign + refresh ceremonies, 2-of-2 specialized
2. **co-signer service** (rust + axum): ws server, tee share storage, policy/replay logic, passport commitment registry
3. **wallet client** (rn + rust-via-uniffi or pure ts w/ wasm frost): DKG/sign/recover UI, passkey/PRF integration, NFC passport scanning via self.xyz sdk or native bridge
4. **schnorr verifier contract** (solidity): ecrecover-trick impl, port chainflip's keymanager
5. **4337 account contract** (solidity): minimal, validateUserOp → schnorr verifier
6. **relay server** (rust + axum): ws message bus, session management
7. **zk-passport integration**: self.xyz sdk preferred; fallback to rolling own with rarimo circuits

## what's out of scope v0
- federation (single co-signer)
- gas abstraction / paymaster (user holds eth on the main chain)
- slow-path contract-based recovery backstop
- zkemail factors
- card / fiat rails
- mobile-app-store distribution (testflight / web demo only)
- bridge integration — cross-chain works via plain-EOA semantics; user does their own bridging in v0

## the actual interesting property
recovery flow has zero personal-information disclosure to co-signer beyond the zk-proof. co-signer holds `H_passport` (an opaque commitment) and verifies proofs against it. they never learn the user's name, dob, passport number, or country directly. recovery is privacy-preserving by construction. afaict no existing recovery system has this property — kyc-based recoveries always reveal identity to the recovery provider.
