// Passport NFC + zk-proof bridge.
//
// Reads ICAO 9303 ePassport data over NFC and produces a zero-knowledge
// proof committing to stable attributes (country, dob, name_hash,
// document_number_hash). The proof is what the signer verifies to gate
// recovery.
//
// Implementation will use @selfxyz/mobile-sdk-alpha (which bundles
// native NFC reading + circuit proving) once it's linkable. For now
// the function shells through to that SDK at call time.

import NfcManager from "react-native-nfc-manager";

export type PassportProof = {
  /// Opaque proof bytes (circuit-specific). Sent to the signer's
  /// /v0/recover endpoint along with the new device pubkey.
  proofHex: string;
  /// The H_passport commitment that this proof attests to. Signer
  /// compares against its stored commitment for the account.
  commitmentHex: string;
};

export async function scanPassportAndProve(_: {
  /// MRZ-derived BAC keys (date of birth, doc number, expiry). For
  /// the demo we'll prompt the user to enter the MRZ once; PACE/CA
  /// support follows.
  mrz: { documentNumber: string; dateOfBirth: string; expiryDate: string };
  /// Bound into the proof so the signer can confirm the proof was
  /// generated for *this* recovery attempt, not replayed.
  challenge: string;
}): Promise<PassportProof> {
  throw new Error(
    "passport.scanPassportAndProve: @selfxyz/mobile-sdk-alpha not linked yet. " +
      "Until then this stub blocks recovery so we don't ship a fake."
  );
}

export async function nfcSupported(): Promise<boolean> {
  try {
    return await NfcManager.isSupported();
  } catch {
    return false;
  }
}
