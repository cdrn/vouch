// ICAO 9303 Basic Access Control session — mutual authentication and
// secure messaging.
//
// Layered on top of bac.ts (offline crypto primitives) and a transport
// abstraction so the same code drives a real passport over NFC in the
// app and a mocked passport in unit tests.

import {
  bacConcat,
  bacXor,
  bytesToHex,
  des3CbcDecrypt,
  des3CbcEncrypt,
  isoPad,
  kEnc,
  kMac,
  Mrz,
  retailMac,
} from "./bac";

/// A transport sends a single command APDU (CLA INS P1 P2 [Lc Data] [Le])
/// and returns the response (data + SW1 SW2). Per ISO 7816-4.
export type ApduTransport = (commandApdu: Uint8Array) => Promise<Uint8Array>;

export type RngFn = (n: number) => Uint8Array;

/// Status word 9000 = success. Other SWs are errors / warnings.
function statusOk(sw: number): boolean {
  return sw === 0x9000;
}

function splitResponse(apdu: Uint8Array): { data: Uint8Array; sw: number } {
  if (apdu.length < 2) throw new Error("APDU response too short");
  const data = apdu.slice(0, apdu.length - 2);
  const sw = (apdu[apdu.length - 2] << 8) | apdu[apdu.length - 1];
  return { data, sw };
}

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  return out;
}

/// Bump a fixed-size 8-byte counter, big-endian. Used for the Send
/// Sequence Counter (SSC) in BAC secure messaging.
function incrementSsc(ssc: Uint8Array): Uint8Array {
  const out = new Uint8Array(ssc);
  for (let i = out.length - 1; i >= 0; i--) {
    out[i] = (out[i] + 1) & 0xff;
    if (out[i] !== 0) break;
  }
  return out;
}

/// Result of a successful BAC handshake: session keys + initial SSC.
/// Hold this in memory only for the lifetime of the passport tap.
export type BacSession = {
  ksEnc: Uint8Array; // 16 bytes
  ksMac: Uint8Array; // 16 bytes
  ssc: Uint8Array; // 8 bytes, mutates with each APDU exchange
};

/// Run BAC mutual auth and derive session keys.
///
/// Sequence per ICAO 9303 Part 11 §4.3.4:
///   1. GET CHALLENGE        → rnd_ic
///   2. Build S = rnd_ifd || rnd_ic || K_ifd
///   3. E_ifd = 3DES_CBC(S, K_ENC, IV=0)
///   4. M_ifd = retailMac(K_MAC, isoPad(E_ifd))
///   5. MUTUAL AUTHENTICATE [E_ifd || M_ifd]  → [E_ic || M_ic]
///   6. Verify M_ic, decrypt E_ic
///   7. Check rnd_ifd echoed, extract K_ic
///   8. Derive session keys from K_ifd XOR K_ic, SSC from random halves.
export async function bacMutualAuthenticate(
  mrz: Mrz,
  transport: ApduTransport,
  rng: RngFn
): Promise<BacSession> {
  const ke = kEnc(mrz);
  const km = kMac(mrz);

  // 1. GET CHALLENGE
  const challengeResp = await transport(new Uint8Array([0x00, 0x84, 0x00, 0x00, 0x08]));
  const { data: rndIc, sw: sw1 } = splitResponse(challengeResp);
  if (!statusOk(sw1) || rndIc.length !== 8) {
    throw new Error(`GET CHALLENGE failed: SW=${sw1.toString(16)}`);
  }

  // 2. Build S
  const rndIfd = rng(8);
  const kIfd = rng(16);
  const S = bacConcat(rndIfd, rndIc, kIfd);

  // 3. Encrypt S
  const eIfd = des3CbcEncrypt(S, ke);

  // 4. MAC over padded E_ifd
  const mIfd = retailMac(km, isoPad(eIfd));

  // 5. MUTUAL AUTHENTICATE
  const cmdData = bacConcat(eIfd, mIfd); // 40 bytes
  const maCmd = bacConcat(
    new Uint8Array([0x00, 0x82, 0x00, 0x00, cmdData.length]),
    cmdData,
    new Uint8Array([0x28]) // Le = 40 expected response data
  );
  const maResp = await transport(maCmd);
  const { data: maData, sw: sw2 } = splitResponse(maResp);
  if (!statusOk(sw2)) {
    throw new Error(`MUTUAL AUTHENTICATE failed: SW=${sw2.toString(16)}`);
  }
  if (maData.length !== 40) {
    throw new Error(`MUTUAL AUTHENTICATE response wrong length: ${maData.length}`);
  }

  // 6. Verify M_ic
  const eIc = maData.slice(0, 32);
  const mIc = maData.slice(32, 40);
  const mIcExpected = retailMac(km, isoPad(eIc));
  if (bytesToHex(mIc) !== bytesToHex(mIcExpected)) {
    throw new Error("MUTUAL AUTHENTICATE: M_ic verification failed");
  }

  // 7. Decrypt E_ic
  const R = des3CbcDecrypt(eIc, ke); // 32 bytes
  const rndIcRecv = R.slice(0, 8);
  const rndIfdRecv = R.slice(8, 16);
  const kIc = R.slice(16, 32);
  if (bytesToHex(rndIcRecv) !== bytesToHex(rndIc)) {
    throw new Error("MUTUAL AUTHENTICATE: rnd_ic mismatch");
  }
  if (bytesToHex(rndIfdRecv) !== bytesToHex(rndIfd)) {
    throw new Error("MUTUAL AUTHENTICATE: rnd_ifd mismatch");
  }

  // 8. Session keys from K_ifd XOR K_ic; SSC from random halves.
  const kSeedSession = bacXor(kIfd, kIc);
  const ksEnc = deriveSessionKey(kSeedSession, 1);
  const ksMac = deriveSessionKey(kSeedSession, 2);
  const ssc = bacConcat(rndIc.slice(4, 8), rndIfd.slice(4, 8));

  return { ksEnc, ksMac, ssc };
}

/// Session-key KDF — same as the boot-time KDF but operating on the
/// XOR'd seed. Pulled out to keep the dependency on bac.ts narrow.
function deriveSessionKey(seed: Uint8Array, counter: number): Uint8Array {
  // SHA-1(seed || u32be(counter))[0..16], parity-adjusted.
  // Reuse forge here so we don't double the SHA-1 implementations.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const forge = require("node-forge");
  const input = bacConcat(seed, u32be(counter));
  const md = forge.md.sha1.create();
  md.update(forge.util.binary.raw.encode(input));
  const out = forge.util.binary.raw.decode(md.digest().bytes()) as Uint8Array;
  const km = out.slice(0, 16);
  return adjustParity(km);
}

function adjustParity(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b);
  for (let i = 0; i < out.length; i++) {
    const v = out[i];
    let parity = 0;
    for (let j = 1; j < 8; j++) parity ^= (v >> j) & 1;
    out[i] = (v & 0xfe) | (parity ^ 1);
  }
  return out;
}

// ───── Secure messaging ──────────────────────────────────────────────────
//
// Each command APDU gets wrapped:
//   - Header: CLA | 0x0c (secure messaging indicator)
//   - Data: TLVs of [encrypted payload, expected length, MAC]
//   - MAC computed over (SSC++ || padded(header) || TLVs[before MAC])
//
// Each response gets unwrapped after verifying its MAC.

/// Wrap a plain APDU into a secure-messaging APDU using the session
/// state. The SSC is bumped TWICE during one exchange: once for the
/// command MAC, once for the response MAC.
export function wrapApdu(
  session: BacSession,
  cla: number,
  ins: number,
  p1: number,
  p2: number,
  data?: Uint8Array,
  le?: number
): { wrapped: Uint8Array; session: BacSession } {
  // SSC++ (for command).
  const sscCmd = incrementSsc(session.ssc);

  // Mask CLA to indicate secure messaging.
  const header = new Uint8Array([cla | 0x0c, ins, p1, p2]);
  const paddedHeader = isoPad(header);

  let do87 = new Uint8Array();
  if (data && data.length > 0) {
    // DO'87' = 87 | len | 01 | encrypted(padded(data))
    const padded = isoPad(data);
    const ct = des3CbcEncrypt(padded, session.ksEnc);
    const body = bacConcat(new Uint8Array([0x01]), ct); // 01 || cipher
    do87 = bacConcat(new Uint8Array([0x87]), tlvLen(body.length), body);
  }

  let do97 = new Uint8Array();
  if (le !== undefined) {
    // DO'97' = 97 | 01 | le
    do97 = new Uint8Array([0x97, 0x01, le & 0xff]);
  }

  // MAC input = padded(SSC++ || header) || do87 || do97 then padded.
  // ICAO 9303 §D.4: M = MAC(KS_MAC, padded(SSC || CmdHeader || DO87 || DO97)).
  const macInput = isoPad(bacConcat(sscCmd, paddedHeader, do87, do97));
  const mac = retailMac(session.ksMac, macInput);
  // DO'8E' = 8E | 08 | mac
  const do8e = bacConcat(new Uint8Array([0x8e, 0x08]), mac);

  const body = bacConcat(do87, do97, do8e);
  const wrapped = bacConcat(
    new Uint8Array([cla | 0x0c, ins, p1, p2, body.length]),
    body,
    new Uint8Array([0x00]) // Le = 256 (extended)
  );

  return { wrapped, session: { ...session, ssc: sscCmd } };
}

/// Unwrap a secure-messaging response APDU. Verifies the MAC over
/// (SSC++ || DO87/DO99) then decrypts DO87 if present.
export function unwrapResponse(
  session: BacSession,
  response: Uint8Array
): { data: Uint8Array; sw: number; session: BacSession } {
  const { data: body, sw } = splitResponse(response);

  // SSC++ (for response).
  const sscResp = incrementSsc(session.ssc);

  // Parse TLVs.
  let i = 0;
  let do87Body: Uint8Array | null = null;
  let do99Body: Uint8Array | null = null;
  let do8eBody: Uint8Array | null = null;
  let macedRegionEnd = 0;
  while (i < body.length) {
    const tag = body[i];
    const [len, lenSize] = readTlvLen(body, i + 1);
    const valStart = i + 1 + lenSize;
    const val = body.slice(valStart, valStart + len);
    if (tag === 0x87) do87Body = val;
    else if (tag === 0x99) do99Body = val;
    else if (tag === 0x8e) {
      do8eBody = val;
      macedRegionEnd = i;
      break;
    }
    i = valStart + len;
  }
  if (!do8eBody) throw new Error("response missing DO'8E' (MAC)");

  const macInput = isoPad(bacConcat(sscResp, body.slice(0, macedRegionEnd)));
  const expectedMac = retailMac(session.ksMac, macInput);
  if (bytesToHex(do8eBody) !== bytesToHex(expectedMac)) {
    throw new Error("secure-messaging MAC verification failed");
  }

  // Decrypt DO'87' if present.
  let data = new Uint8Array();
  if (do87Body) {
    if (do87Body[0] !== 0x01) throw new Error("DO'87' missing padding indicator");
    const ct = do87Body.slice(1);
    const pt = des3CbcDecrypt(ct, session.ksEnc);
    data = unisoPad(pt);
  }

  // DO'99' carries the status word.
  let respSw = sw;
  if (do99Body && do99Body.length === 2) {
    respSw = (do99Body[0] << 8) | do99Body[1];
  }

  return { data, sw: respSw, session: { ...session, ssc: sscResp } };
}

function tlvLen(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  if (n < 0x100) return new Uint8Array([0x81, n]);
  return new Uint8Array([0x82, (n >>> 8) & 0xff, n & 0xff]);
}

function readTlvLen(buf: Uint8Array, off: number): [number, number] {
  const first = buf[off];
  if (first < 0x80) return [first, 1];
  if (first === 0x81) return [buf[off + 1], 2];
  if (first === 0x82) return [(buf[off + 1] << 8) | buf[off + 2], 3];
  throw new Error(`unsupported TLV length form: ${first.toString(16)}`);
}

function unisoPad(data: Uint8Array): Uint8Array {
  // Strip ISO 9797-1 padding method 2: find the last 0x80 and trim.
  for (let i = data.length - 1; i >= 0; i--) {
    if (data[i] === 0x80) return data.slice(0, i);
    if (data[i] !== 0x00) throw new Error("invalid ISO 9797-1 padding");
  }
  throw new Error("no padding marker found");
}
