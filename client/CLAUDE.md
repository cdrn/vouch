@AGENTS.md

# Passport NFC + zk-proof integration

The blocker for finishing the recovery flow is the passport piece. Inspected `selfxyz/self` monorepo (2026-05-27); findings:

- **`@selfxyz/mobile-sdk-alpha`** — embeddable in-app SDK (NFC + zk-proof). **Pinned to RN 0.76–0.77 + React 18.3.1**. Unpublished; consumed from monorepo. We're on RN 0.85 + React 19 — incompatible.
- **`@selfxyz/rn-sdk`** — thin webview wrapper around Self's hosted JS app. RN >=0.72, React ^18. Less embeddable; loses the "tap → magic" UX since it's webview-mediated.
- Underlying NFC reader on iOS is **AndyQ/NFCPassportReader.swift**, on Android **JMRTD**. The xcframework ships inside mobile-sdk-alpha.

Three paths considered:
1. Downgrade Expo to 52 (RN 0.76, React 18) → use mobile-sdk-alpha directly. Best privacy story (zk-proof on-device); means redoing the scaffold.
2. Keep current Expo 56 stack, bridge to AndyQ/JMRTD ourselves via custom BAC in TS over `react-native-nfc-manager`. No zk-proof — device sends MRZ-derived `H_passport` directly to the signer over TLS. Honest trust model for alpha.
3. Commercial: `readid-react-native@4.127.0` (Signicat). BAC + PACE + Chip Auth, Expo-tagged. Pay-for-license. Fastest to a working tap-to-read.

Decision pending. Don't redo this research; ask the user before starting.

# Frost native bridge

`vouch-frost` (rust crate at `../crates/frost`) needs to run on-device so the client really holds a 2-of-2 share. Plan is `uniffi-bindgen-react-native` over an opaque-blob wrapper of the FROST API (encode KeyPackage/Round1Package/etc. via postcard at the FFI boundary, pass `Vec<u8>` across). Not started.

Until the bridge lands, `src/lib/frost.ts` functions throw at call time — by design, so the missing piece is loud, not silent.
