@AGENTS.md

# vouch wallet client (v0 demo)

Expo 56 / RN 0.85 / TypeScript. Three screens: Onboarding (create wallet), Wallet (sign + execute), Recover (passport tap → onchain pubkey rotation).

## v0 trust model — read this before touching crypto

The signer service holds *both* shares of the 2-of-2 FROST key in v0. It runs the sign ceremony in-process and signs userops server-side. The wire format of the resulting signature is *identical* to what a real 2-party FROST would produce — `SchnorrVerifier.sol` accepts it unchanged.

This is a trust regression vs the spec (the device should hold one share). It exists because UniFFI / native module integration is multi-session work and we needed to ship the visible flow first. The client's `src/lib/frost.ts` is intentionally still a stub; v1 replaces it with native-module calls and the signer's `/v0/wallet/*` endpoints get retired in favor of the `/v0/{dkg,sign,recover}` ones that already exist.

## Run

From the repo root:

```
scripts/run-demo.sh   # boots anvil + signer
```

then in another shell:

```
cd client
npx expo start --dev-client
```

NFC needs a real device. iOS simulator can run Onboarding + Wallet but not Recover.

## Endpoints the client calls

- `POST /v0/wallet/create { h_passport_hex }` — deploys a fresh VouchAccount, returns `{ account_address, pub_x_hex }`. Onboarding hashes the user-typed recovery phrase to make a demo H_passport.
- `POST /v0/wallet/sign-and-execute { account_address, target, value, data }` — signer reads the SCA's nonce, computes the opHash, signs it via in-process FROST, submits `execute()`. Returns `{ tx_hash }`.
- `POST /v0/wallet/recover { h_passport_hex }` — looks up the account by H_passport, generates a fresh joint key, signs the SCA's `rotationDigest` with the recovery authority key (EIP-191), submits `rotatePubKey()`. Returns `{ new_pub_x_hex, rotation_tx_hash }`.

## Passport NFC flow (Recover screen)

`src/lib/passport.ts`:
1. `acquireIsoDep()` from `react-native-nfc-manager` — shows the system NFC prompt
2. `bacMutualAuthenticate(mrz, transport, rng)` — full ICAO 9303 BAC handshake (`src/lib/bac.ts` + `bac-session.ts`)
3. `readDg1(transport, session)` — secure-messaged READ BINARY chunks
4. `parseDg1(bytes)` → `ParsedMrz`
5. `computeHPassport(parsed)` — SHA-256 over stable attributes only (country, nationality, DOB, sha256(name), sha256(doc#))
6. POST H_passport to `/v0/wallet/recover`

The BAC + DG1 code is exercised by 17 vitest tests (`npm test`). Live NFC validation only on a real device with a real passport.

## What v1 changes

- `src/lib/frost.ts` stubs get replaced with calls into a UniFFI-generated TurboModule wrapping `vouch-frost-ffi`. The device holds the device share; the signer's `/v0/dkg` + `/v0/sign` endpoints run their half over the WS relay.
- `/v0/wallet/*` endpoints retire.
- Recovery flow: device runs a fresh DKG with the signer (after H_passport verification); the signer signs the resulting joint pubkey's rotation digest with the recovery authority.

## Don't redo

- We considered pure-JS FROST in TS and rejected it (~300 LOC of hand-ported crypto we'd have to audit).
- We considered downgrading Expo to 52 to use `@selfxyz/mobile-sdk-alpha` for NFC + zk-passport and rejected it for v0 (the SDK's zk-proof isn't required for demo trust model; raw NFC + BAC + DG1 in TS gives us the visible flow).
