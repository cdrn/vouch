// Passport NFC orchestration. Drives the full flow:
//   acquire IsoDep → BAC mutual auth → read DG1 → parse MRZ → derive
//   H_passport. v0 does not generate a zk-proof; the device sends
//   H_passport (and supporting MRZ-derived data) to the signer.

import * as Crypto from "expo-crypto";
import NfcManager from "react-native-nfc-manager";

import type { Mrz } from "./bac";
import { bacMutualAuthenticate } from "./bac-session";
import {
  ParsedMrz,
  bytesToHex,
  computeHPassport,
  parseDg1,
  readDg1,
} from "./passport-data";
import { acquireIsoDep } from "./passport-nfc";

export type PassportReadResult = {
  mrz: ParsedMrz;
  hPassportHex: string;
  dg1Hex: string;
};

/// Tap the passport, run BAC with the supplied MRZ, read DG1, parse it,
/// derive the H_passport commitment. Caller controls cleanup via
/// throwing if cancellation is needed.
export async function scanPassport(mrz: Mrz): Promise<PassportReadResult> {
  const rng = (n: number) => Crypto.getRandomBytes(n);

  const { transport, release } = await acquireIsoDep();
  try {
    const session = await bacMutualAuthenticate(mrz, transport, rng);
    const { dg1 } = await readDg1(transport, session);
    const parsed = parseDg1(dg1);
    const hPassport = computeHPassport(parsed);
    return {
      mrz: parsed,
      hPassportHex: bytesToHex(hPassport),
      dg1Hex: bytesToHex(dg1),
    };
  } finally {
    await release();
  }
}

export async function nfcSupported(): Promise<boolean> {
  try {
    return await NfcManager.isSupported();
  } catch {
    return false;
  }
}
