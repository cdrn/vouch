// React Native NFC transport: wraps react-native-nfc-manager's IsoDep
// channel as the ApduTransport our BAC code expects.

import NfcManager, { NfcTech } from "react-native-nfc-manager";

import type { ApduTransport } from "./bac-session";

function hexFromBytes(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function bytesFromHex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/// Acquire the NFC tag in IsoDep mode, returning a transport function
/// and a cleanup function the caller MUST invoke when done.
///
/// Usage:
///   const { transport, release } = await acquireIsoDep();
///   try {
///     const session = await bacMutualAuthenticate(mrz, transport, rng);
///     const { dg1 } = await readDg1(transport, session);
///   } finally {
///     await release();
///   }
export async function acquireIsoDep(): Promise<{
  transport: ApduTransport;
  release: () => Promise<void>;
}> {
  await NfcManager.start();
  await NfcManager.requestTechnology(NfcTech.IsoDep, {
    alertMessage: "Hold your passport flat against the back of your phone.",
  });

  const transport: ApduTransport = async (apdu) => {
    // The lib accepts a number[] or hex string depending on platform.
    // Passing a number[] works on both iOS and Android per its docs.
    const resp = (await NfcManager.isoDepHandler.transceive(Array.from(apdu))) as
      | number[]
      | string
      | Uint8Array;
    if (typeof resp === "string") return bytesFromHex(resp);
    if (resp instanceof Uint8Array) return resp;
    return new Uint8Array(resp);
  };

  const release = async () => {
    try {
      await NfcManager.cancelTechnologyRequest();
    } catch {
      /* swallow; tag may already be gone */
    }
  };

  return { transport, release };
}

export { hexFromBytes };
