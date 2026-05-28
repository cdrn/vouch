// ICAO 9303 EF.DG1 reader + MRZ parser + H_passport commitment.
//
// After BAC mutual auth, the chip exposes DG1 via secure messaging.
// We SELECT EF.DG1 (FID 0x0101 under the eMRTD application), READ
// BINARY in chunks until the TLV's declared length is satisfied, then
// parse the MRZ payload.

import forge from "node-forge";

import { bacConcat, bytesToHex } from "./bac";
import { ApduTransport, BacSession, unwrapResponse, wrapApdu } from "./bac-session";

const MAX_LE_PER_READ = 0xe0; // safe chunk size for short-form READ BINARY

// AID for the ICAO eMRTD application (LDS).
const EMRTD_AID = new Uint8Array([0xa0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]);

/// SELECT the eMRTD application by AID, then SELECT EF.DG1, then READ
/// BINARY until the chip returns the full DG1 file. Returns the raw
/// TLV bytes — call `parseMrz` to extract attributes.
export async function readDg1(
  transport: ApduTransport,
  session: BacSession
): Promise<{ dg1: Uint8Array; session: BacSession }> {
  // SELECT BY AID (eMRTD application).
  let s = await selectByAid(transport, session, EMRTD_AID);

  // SELECT EF.DG1 (FID 0x0101).
  s = await selectByFid(transport, s, new Uint8Array([0x01, 0x01]));

  // READ BINARY: first read 4 bytes to learn the TLV length, then
  // pull the rest in chunks.
  const header = await readBinary(transport, s, 0, 4);
  s = header.session;
  const totalLen = parseTlvLength(header.bytes);

  let collected = header.bytes;
  while (collected.length < totalLen) {
    const remaining = totalLen - collected.length;
    const chunk = Math.min(remaining, MAX_LE_PER_READ);
    const r = await readBinary(transport, s, collected.length, chunk);
    s = r.session;
    collected = bacConcat(collected, r.bytes);
  }

  return { dg1: collected.slice(0, totalLen), session: s };
}

async function selectByAid(
  transport: ApduTransport,
  session: BacSession,
  aid: Uint8Array
): Promise<BacSession> {
  const { wrapped, session: s1 } = wrapApdu(session, 0x00, 0xa4, 0x04, 0x0c, aid);
  const resp = await transport(wrapped);
  const r = unwrapResponse(s1, resp);
  if (r.sw !== 0x9000) throw new Error(`SELECT by AID failed: SW=${r.sw.toString(16)}`);
  return r.session;
}

async function selectByFid(
  transport: ApduTransport,
  session: BacSession,
  fid: Uint8Array
): Promise<BacSession> {
  const { wrapped, session: s1 } = wrapApdu(session, 0x00, 0xa4, 0x02, 0x0c, fid);
  const resp = await transport(wrapped);
  const r = unwrapResponse(s1, resp);
  if (r.sw !== 0x9000) throw new Error(`SELECT EF failed: SW=${r.sw.toString(16)}`);
  return r.session;
}

async function readBinary(
  transport: ApduTransport,
  session: BacSession,
  offset: number,
  length: number
): Promise<{ bytes: Uint8Array; session: BacSession }> {
  if (offset > 0x7fff) throw new Error("READ BINARY offset > 0x7fff not supported");
  const p1 = (offset >> 8) & 0xff;
  const p2 = offset & 0xff;
  const { wrapped, session: s1 } = wrapApdu(session, 0x00, 0xb0, p1, p2, undefined, length);
  const resp = await transport(wrapped);
  const r = unwrapResponse(s1, resp);
  if (r.sw !== 0x9000 && r.sw !== 0x9100) {
    throw new Error(`READ BINARY @ ${offset} failed: SW=${r.sw.toString(16)}`);
  }
  return { bytes: r.data, session: r.session };
}

/// Parse a BER-TLV header at the start of buf and return total tag+len+value length.
function parseTlvLength(buf: Uint8Array): number {
  if (buf.length < 2) throw new Error("TLV too short");
  // Tag: 1 or 2 bytes. For DG1 the tag is 0x61.
  let off = 1;
  if ((buf[0] & 0x1f) === 0x1f) {
    while (off < buf.length && (buf[off] & 0x80) !== 0) off++;
    off++;
  }
  if (off >= buf.length) throw new Error("TLV length missing");
  const first = buf[off];
  if (first < 0x80) return off + 1 + first;
  const lenSize = first & 0x7f;
  if (off + 1 + lenSize > buf.length) {
    throw new Error("TLV length too short to compute total");
  }
  let len = 0;
  for (let i = 0; i < lenSize; i++) len = (len << 8) | buf[off + 1 + i];
  return off + 1 + lenSize + len;
}

// ───── MRZ parsing ────────────────────────────────────────────────────────

export type ParsedMrz = {
  format: "TD1" | "TD2" | "TD3";
  documentType: string;
  issuingCountry: string; // 3-letter code
  documentNumber: string;
  nationality: string; // 3-letter code
  dateOfBirth: string; // YYMMDD
  sex: "M" | "F" | "X";
  dateOfExpiry: string; // YYMMDD
  primaryIdentifier: string;
  secondaryIdentifier: string;
  raw: string;
};

export function parseDg1(dg1: Uint8Array): ParsedMrz {
  // DG1 = 0x61 LL 5F1F LL <mrz ASCII>
  if (dg1[0] !== 0x61) throw new Error("DG1 missing 0x61 tag");
  // Skip to the inner 5F1F tag.
  let i = 1;
  const [outerLen, outerLenSize] = readBerLen(dg1, i);
  i += outerLenSize;
  const inner = dg1.slice(i, i + outerLen);

  // Inner: 5F1F LL <mrz>
  if (!(inner[0] === 0x5f && inner[1] === 0x1f)) {
    throw new Error("DG1 inner tag is not 5F1F");
  }
  const [innerLen, innerLenSize] = readBerLen(inner, 2);
  const mrzBytes = inner.slice(2 + innerLenSize, 2 + innerLenSize + innerLen);
  const mrz = new TextDecoder("ascii").decode(mrzBytes);

  return parseMrzString(mrz);
}

function readBerLen(buf: Uint8Array, off: number): [number, number] {
  const first = buf[off];
  if (first < 0x80) return [first, 1];
  const n = first & 0x7f;
  let len = 0;
  for (let i = 0; i < n; i++) len = (len << 8) | buf[off + 1 + i];
  return [len, 1 + n];
}

export function parseMrzString(mrz: string): ParsedMrz {
  // TD3 = 2 lines × 44 chars = 88
  // TD2 = 2 lines × 36 chars = 72
  // TD1 = 3 lines × 30 chars = 90
  if (mrz.length === 88) return parseTd3(mrz);
  if (mrz.length === 90) return parseTd1(mrz);
  if (mrz.length === 72) return parseTd2(mrz);
  throw new Error(`unrecognized MRZ length: ${mrz.length}`);
}

function parseTd3(mrz: string): ParsedMrz {
  const line1 = mrz.slice(0, 44);
  const line2 = mrz.slice(44, 88);
  const documentType = line1.slice(0, 2).replace(/</g, "");
  const issuingCountry = line1.slice(2, 5);
  const names = line1.slice(5, 44);
  const namesSplit = names.indexOf("<<");
  const primary = (namesSplit >= 0 ? names.slice(0, namesSplit) : names).replace(/</g, " ").trim();
  const secondary =
    namesSplit >= 0
      ? names
          .slice(namesSplit + 2)
          .replace(/</g, " ")
          .trim()
      : "";

  const documentNumber = line2.slice(0, 9).replace(/</g, "");
  // line2[9] = doc# check digit
  const nationality = line2.slice(10, 13);
  const dateOfBirth = line2.slice(13, 19);
  // line2[19] = dob check
  const sex = line2[20] as "M" | "F" | "X";
  const dateOfExpiry = line2.slice(21, 27);
  // line2[27] = expiry check
  // remaining: personal number + optional check digits

  return {
    format: "TD3",
    documentType,
    issuingCountry,
    documentNumber,
    nationality,
    dateOfBirth,
    sex,
    dateOfExpiry,
    primaryIdentifier: primary,
    secondaryIdentifier: secondary,
    raw: mrz,
  };
}

function parseTd2(mrz: string): ParsedMrz {
  const line1 = mrz.slice(0, 36);
  const line2 = mrz.slice(36, 72);
  const documentType = line1.slice(0, 2).replace(/</g, "");
  const issuingCountry = line1.slice(2, 5);
  const names = line1.slice(5, 36);
  const namesSplit = names.indexOf("<<");
  const primary = (namesSplit >= 0 ? names.slice(0, namesSplit) : names).replace(/</g, " ").trim();
  const secondary =
    namesSplit >= 0 ? names.slice(namesSplit + 2).replace(/</g, " ").trim() : "";

  const documentNumber = line2.slice(0, 9).replace(/</g, "");
  const nationality = line2.slice(10, 13);
  const dateOfBirth = line2.slice(13, 19);
  const sex = line2[20] as "M" | "F" | "X";
  const dateOfExpiry = line2.slice(21, 27);

  return {
    format: "TD2",
    documentType,
    issuingCountry,
    documentNumber,
    nationality,
    dateOfBirth,
    sex,
    dateOfExpiry,
    primaryIdentifier: primary,
    secondaryIdentifier: secondary,
    raw: mrz,
  };
}

function parseTd1(mrz: string): ParsedMrz {
  const line1 = mrz.slice(0, 30);
  const line2 = mrz.slice(30, 60);
  const line3 = mrz.slice(60, 90);

  const documentType = line1.slice(0, 2).replace(/</g, "");
  const issuingCountry = line1.slice(2, 5);
  const documentNumber = line1.slice(5, 14).replace(/</g, "");

  const dateOfBirth = line2.slice(0, 6);
  const sex = line2[7] as "M" | "F" | "X";
  const dateOfExpiry = line2.slice(8, 14);
  const nationality = line2.slice(15, 18);

  const names = line3.replace(/<+$/, "");
  const namesSplit = names.indexOf("<<");
  const primary = (namesSplit >= 0 ? names.slice(0, namesSplit) : names).replace(/</g, " ").trim();
  const secondary =
    namesSplit >= 0 ? names.slice(namesSplit + 2).replace(/</g, " ").trim() : "";

  return {
    format: "TD1",
    documentType,
    issuingCountry,
    documentNumber,
    nationality,
    dateOfBirth,
    sex,
    dateOfExpiry,
    primaryIdentifier: primary,
    secondaryIdentifier: secondary,
    raw: mrz,
  };
}

// ───── H_passport commitment ──────────────────────────────────────────────

/// 32-byte commitment over stable passport attributes. Used as the
/// account-linked recovery key on the signer side.
///
/// Stable attributes (per the vouch spec): country, dob, name_hash,
/// document_number_hash. NOT document number or expiry directly —
/// those rotate when a passport is reissued.
///
/// We use the issuing country (3-letter), date of birth, and hashes of
/// the name and document number. SHA-256 over the concatenation.
export function computeHPassport(p: ParsedMrz): Uint8Array {
  const md = forge.md.sha256.create();
  md.update("vouch/H_passport/v1");
  md.update("\0");
  md.update(p.issuingCountry);
  md.update("\0");
  md.update(p.nationality);
  md.update("\0");
  md.update(p.dateOfBirth);
  md.update("\0");
  md.update(sha256Hex(p.primaryIdentifier + "<<" + p.secondaryIdentifier));
  md.update("\0");
  md.update(sha256Hex(p.documentNumber));
  const digestBytes = forge.util.binary.raw.decode(md.digest().bytes());
  return digestBytes;
}

function sha256Hex(s: string): string {
  const md = forge.md.sha256.create();
  md.update(s);
  return md.digest().toHex();
}

export { bytesToHex };
