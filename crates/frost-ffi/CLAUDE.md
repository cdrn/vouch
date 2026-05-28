# vouch-frost-ffi

Opaque-blob FFI facade over `vouch-frost`. Built so iOS / Android (and React Native via TurboModule) can drive 2-of-2 FROST DKG + sign without seeing the FROST internals — everything across the boundary is primitives + `Vec<u8>` + simple Records.

## What's wired now

- `cargo test -p vouch-frost-ffi` → 1 test, full DKG + sign round-trip through the FFI surface, asserts the aggregated 64-byte BIP340 sig verifies under the joint pubkey.
- `cargo build -p vouch-frost-ffi --release` produces `target/release/libvouch_frost_ffi.{dylib,a,rlib}`.
- `cargo run -p vouch-frost-ffi --bin vouch-frost-uniffi-bindgen -- generate --library target/release/libvouch_frost_ffi.dylib --language swift|kotlin --out-dir <dir>` emits idiomatic Swift / Kotlin bindings that import via UniFFI's `RustBuffer` runtime.

## What's left for RN integration (task 9)

1. **Cross-compile to mobile targets**. We need:
   - iOS: `aarch64-apple-ios` (device), `aarch64-apple-ios-sim` (simulator on Apple Silicon), `x86_64-apple-ios` (simulator on Intel). Combined via `xcodebuild -create-xcframework` into a single `.xcframework`.
   - Android: `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android`. Needs the Android NDK, and either `cargo-ndk` or manual `CC_*` / `AR_*` env vars per target.
2. **`uniffi-bindgen-react-native`**. The published Swift / Kotlin bindings above target Foundation / Kotlin stdlib. For RN we use `jhugman/uniffi-bindgen-react-native`, which is the same generator with the addition of:
   - TurboModule C++ spec
   - Hermes-friendly type marshalling
   - A small JS shim
   It's alpha as of late 2025; pin to a known-good commit.
3. **Expo dev-client config**. Expo 56 / RN 0.85 use the New Architecture by default — TurboModules work. Native module gets wired via `expo prebuild` + an `expo-module.config.json` describing the iOS xcframework + Android AAR paths. The `client/app.json` plugins array needs an entry pointing at the local module.
4. **Replace `client/src/lib/frost.ts` stubs**. The TS surface is already shaped (DkgConfig / SignConfig / AccountInit) — they call into the generated TurboModule.

## Sharp edges

- `uniffi-bindgen-react-native` and stable `uniffi` may pin different versions. If they disagree the generated bindings won't load. Check `Cargo.lock` first.
- RN 0.76+ removed the bridge; only New Architecture modules work. We're on 0.85, fine.
- iOS bitcode is dead; xcframework should be assembled with `-create-xcframework` against the static `libvouch_frost_ffi.a`, not the dylib.
- BUSL / Apache-2.0 license — `vouch-frost` and downstream are Apache-2.0; `frost-secp256k1-tr` is also Apache-2.0. Clean to ship.

## Don't redo

We considered and rejected:

- Pure-JS FROST in TypeScript. The crypto would have to be hand-ported from frost-secp256k1-tr; ~300+ LOC of crypto code we'd have to audit ourselves. Native FROST stays.
- UDL-based UniFFI definitions. The proc-macro mode (`uniffi::setup_scaffolding!()` + `#[uniffi::export]`) generates the same bindings without a separate type file. Stick with proc-macros.
