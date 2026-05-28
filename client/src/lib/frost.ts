// vouch-frost client bridge.
//
// This module is the client-side face of the FROST ceremony. It will
// eventually call into a native module (uniffi-bindgen-react-native
// wrapping the vouch-frost rust crate) so the device runs real
// secp256k1 / BIP340 schnorr math locally and never ships its share
// off-device.
//
// For now the functions are unimplemented stubs. They throw at call
// time so wiring problems surface immediately rather than silently
// returning fake data.

export type AccountInit = {
  /// 32-byte hex (no 0x prefix) of the joint BIP340 x-only pubkey.
  pubX: string;
  /// Opaque hex blob holding the device's FROST KeyPackage; format
  /// matches what the rust crate emits via postcard.
  share: string;
};

export type DkgConfig = {
  relayUrl: string; // e.g. ws://192.168.x.x:8088/ws
  signerUrl: string; // e.g. http://192.168.x.x:8089
  sessionId: string;
  clientParticipant: number; // 1
  signerParticipant: number; // 2
};

export async function runClientDkg(_: DkgConfig): Promise<AccountInit> {
  throw new Error(
    "frost.runClientDkg: native module not linked yet. " +
      "Wire vouch-frost via uniffi-bindgen-react-native (see clients TODO)."
  );
}

export type SignConfig = DkgConfig & {
  share: string;
  pubX: string;
  /// 32-byte hex op-hash (no 0x prefix) to sign.
  opHash: string;
};

export async function runClientSign(_: SignConfig): Promise<string /* 64-byte sig hex */> {
  throw new Error("frost.runClientSign: native module not linked yet.");
}
