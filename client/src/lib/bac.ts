// ICAO 9303 Basic Access Control (BAC) primitives.
//
// References:
//   Doc 9303 Part 11, §4.3 (Basic Access Control)
//   Doc 9303 Part 11 Appendix D.3 (BAC worked example)
//
// This module covers the *offline* parts of BAC — deriving keys from
// the MRZ, computing MACs, building/parsing the MUTUAL AUTHENTICATE
// command/response, and the 3DES wrapping. The NFC transport and the
// stateful secure-messaging session live in bac-session.ts.

import forge from "node-forge";

// ───── byte helpers ───────────────────────────────────────────────────────

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "").replace(/\s+/g, "");
  if (clean.length % 2) throw new Error("hex length must be even");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function bytesToForge(b: Uint8Array): string {
  return forge.util.binary.raw.encode(b);
}

function forgeToBytes(s: string): Uint8Array {
  // Forge's raw decode returns a Uint8Array with an implementation-defined
  // backing buffer; copy into a fresh one so TS 6's stricter Uint8Array
  // generic doesn't reject downstream operations.
  return new Uint8Array(forge.util.binary.raw.decode(s));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new Error("xor length mismatch");
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

// ───── MRZ check digit ────────────────────────────────────────────────────

/// ICAO 9303 check digit: weights 7,3,1 cycling over the input chars,
/// where A-Z map to 10-35 and digits to their value.
export function mrzCheckDigit(input: string): number {
  const weights = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    let v: number;
    if (c >= 0x30 && c <= 0x39) v = c - 0x30;
    else if (c >= 0x41 && c <= 0x5a) v = c - 0x41 + 10;
    else if (c === 0x3c) v = 0; // '<' filler
    else throw new Error(`mrzCheckDigit: invalid char ${input[i]}`);
    sum += v * weights[i % 3];
  }
  return sum % 10;
}

// ───── BAC key derivation ─────────────────────────────────────────────────

export type Mrz = {
  documentNumber: string; // up to 9 chars, pad to 9 with '<'
  dateOfBirth: string; // YYMMDD
  dateOfExpiry: string; // YYMMDD
};

/// Compose the "MRZ information" string from the three MRZ fields,
/// each followed by its check digit. Per ICAO 9303 Part 11 §4.3.2.
function mrzInfo(mrz: Mrz): string {
  let doc = mrz.documentNumber;
  if (doc.length > 9) throw new Error("document number too long");
  doc = doc.padEnd(9, "<");
  const docCd = mrzCheckDigit(doc);
  const dobCd = mrzCheckDigit(mrz.dateOfBirth);
  const expCd = mrzCheckDigit(mrz.dateOfExpiry);
  return `${doc}${docCd}${mrz.dateOfBirth}${dobCd}${mrz.dateOfExpiry}${expCd}`;
}

/// K_seed = SHA-1(MRZ_info)[0..16]
export function kSeed(mrz: Mrz): Uint8Array {
  const md = forge.md.sha1.create();
  md.update(mrzInfo(mrz));
  const digest = forgeToBytes(md.digest().bytes());
  return digest.slice(0, 16);
}

/// ICAO 9303 §4.3.3 key derivation:
///   H = SHA-1(K_seed || c) where c is a 4-byte big-endian integer
///   key_material = H[0..16]
///   K1, K2 = key_material[0..8], key_material[8..16] (parity-adjusted DES keys)
function kdf(seed: Uint8Array, c: number): Uint8Array {
  const cBytes = new Uint8Array([0, 0, 0, c]);
  const md = forge.md.sha1.create();
  md.update(bytesToForge(concat(seed, cBytes)));
  const digest = forgeToBytes(md.digest().bytes());
  const km = digest.slice(0, 16);
  return adjustParity(km);
}

/// Force odd parity on each byte. DES key bytes use the LSB as a parity
/// bit; flipping it does not change the effective key.
function adjustParity(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b);
  for (let i = 0; i < out.length; i++) {
    let v = out[i];
    let parity = 0;
    for (let j = 1; j < 8; j++) parity ^= (v >> j) & 1;
    // we want odd parity, so set bit 0 to complement of XOR-of-other-bits
    out[i] = (v & 0xfe) | (parity ^ 1);
  }
  return out;
}

/// 3DES (CBC) encryption key, derived from MRZ.
export function kEnc(mrz: Mrz): Uint8Array {
  return kdf(kSeed(mrz), 1);
}

/// MAC key (used with Retail-MAC / ISO 9797-1 alg 3), derived from MRZ.
export function kMac(mrz: Mrz): Uint8Array {
  return kdf(kSeed(mrz), 2);
}

// ───── 3DES (CBC, two-key, EDE) ───────────────────────────────────────────

/// Two-key 3DES expressed as a 24-byte key (K1||K2||K1). node-forge
/// accepts a 24-byte key and does EDE internally.
function expand3Key(k16: Uint8Array): Uint8Array {
  return concat(k16, k16.slice(0, 8));
}

export function des3CbcEncrypt(plaintext: Uint8Array, key16: Uint8Array): Uint8Array {
  const cipher = forge.cipher.createCipher("3DES-CBC", bytesToForge(expand3Key(key16)));
  cipher.start({ iv: bytesToForge(new Uint8Array(8)) });
  cipher.update(forge.util.createBuffer(bytesToForge(plaintext)));
  if (!cipher.finish()) throw new Error("3DES-CBC encrypt failed");
  // forge pads by default; BAC uses no padding (we pre-pad), so the
  // output length should be exactly plaintext.length. Trim any pad.
  return forgeToBytes(cipher.output.bytes()).slice(0, plaintext.length);
}

export function des3CbcDecrypt(ciphertext: Uint8Array, key16: Uint8Array): Uint8Array {
  const decipher = forge.cipher.createDecipher("3DES-CBC", bytesToForge(expand3Key(key16)));
  decipher.start({ iv: bytesToForge(new Uint8Array(8)) });
  decipher.update(forge.util.createBuffer(bytesToForge(ciphertext)));
  // Forge accepts a callback to override its padding check; the older
  // @types/node-forge declares finish() with no args, so cast through.
  if (!(decipher as unknown as { finish: (pad: () => boolean) => boolean }).finish(() => true)) {
    throw new Error("3DES-CBC decrypt failed");
  }
  return forgeToBytes(decipher.output.bytes()).slice(0, ciphertext.length);
}

// ───── ISO 9797-1 algorithm 3 (Retail-MAC) ────────────────────────────────

/// 8-byte Retail-MAC over `data` using a 16-byte key (K1||K2).
/// Input is ISO/IEC 9797-1 padding method 2 already applied by the caller
/// when BAC requires it; this function does no padding.
///
/// Algorithm:
///   block_n = ... = single-DES-CBC(data, K1)[last 8 bytes]
///   MAC = DES-decrypt(block_n, K2) → DES-encrypt(result, K1)
export function retailMac(key16: Uint8Array, data: Uint8Array): Uint8Array {
  if (data.length % 8 !== 0) throw new Error("retail-mac input must be 8-byte aligned");
  const k1 = key16.slice(0, 8);
  const k2 = key16.slice(8, 16);

  // CBC over data with K1, IV=0 → last block.
  const cipher = forge.cipher.createCipher("DES-CBC", bytesToForge(k1));
  cipher.start({ iv: bytesToForge(new Uint8Array(8)) });
  cipher.update(forge.util.createBuffer(bytesToForge(data)));
  if (!cipher.finish()) throw new Error("DES-CBC failed");
  const allBlocks = forgeToBytes(cipher.output.bytes()).slice(0, data.length);
  const last = allBlocks.slice(allBlocks.length - 8);

  // Decrypt with K2 then encrypt with K1 (ECB single-block).
  const dec = forge.cipher.createDecipher("DES-ECB", bytesToForge(k2));
  dec.start({});
  dec.update(forge.util.createBuffer(bytesToForge(last)));
  if (!(dec as unknown as { finish: (pad: () => boolean) => boolean }).finish(() => true)) {
    throw new Error("DES-ECB decrypt failed");
  }
  const mid = forgeToBytes(dec.output.bytes()).slice(0, 8);

  const enc = forge.cipher.createCipher("DES-ECB", bytesToForge(k1));
  enc.start({});
  enc.update(forge.util.createBuffer(bytesToForge(mid)));
  if (!enc.finish()) throw new Error("DES-ECB encrypt failed");
  return forgeToBytes(enc.output.bytes()).slice(0, 8);
}

/// ISO/IEC 9797-1 padding method 2: append 0x80 then 0x00 bytes to fill
/// to a multiple of `blockSize`.
export function isoPad(data: Uint8Array, blockSize = 8): Uint8Array {
  const padLen = blockSize - (data.length % blockSize);
  const pad = new Uint8Array(padLen);
  pad[0] = 0x80;
  return concat(data, pad);
}

export { concat as bacConcat, xor as bacXor };
