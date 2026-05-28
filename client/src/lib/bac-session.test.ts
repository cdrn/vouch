import { describe, expect, test } from "vitest";
import { randomBytes } from "node:crypto";

import {
  bacConcat,
  bytesToHex,
  des3CbcDecrypt,
  des3CbcEncrypt,
  hexToBytes,
  isoPad,
  kEnc,
  kMac,
  Mrz,
  retailMac,
} from "./bac";
import {
  ApduTransport,
  bacMutualAuthenticate,
  unwrapResponse,
  wrapApdu,
} from "./bac-session";

const SPEC_MRZ: Mrz = {
  documentNumber: "L898902C",
  dateOfBirth: "690806",
  dateOfExpiry: "940623",
};

/// Mock passport chip that participates in the BAC handshake. Holds
/// the same MRZ-derived keys as the reader and supplies a (mock) chip
/// nonce + key. Lets us drive the full handshake in vitest.
function makeMockPassport(mrz: Mrz, chipRng: () => Uint8Array) {
  const ke = kEnc(mrz);
  const km = kMac(mrz);
  let pendingRndIc: Uint8Array | null = null;
  let mutuallyAuthenticated = false;
  let sessionKsEnc: Uint8Array | null = null;
  let sessionKsMac: Uint8Array | null = null;
  let sessionSsc: Uint8Array | null = null;

  const transport: ApduTransport = async (apdu) => {
    // GET CHALLENGE
    if (apdu[0] === 0x00 && apdu[1] === 0x84) {
      pendingRndIc = chipRng().slice(0, 8);
      return new Uint8Array([...pendingRndIc, 0x90, 0x00]);
    }
    // MUTUAL AUTHENTICATE
    if (apdu[0] === 0x00 && apdu[1] === 0x82) {
      if (!pendingRndIc) return new Uint8Array([0x6f, 0x00]);
      const lc = apdu[4];
      const cmdData = apdu.slice(5, 5 + lc);
      if (cmdData.length !== 40) return new Uint8Array([0x67, 0x00]);
      const eIfd = cmdData.slice(0, 32);
      const mIfd = cmdData.slice(32, 40);
      const mIfdExpected = retailMac(km, isoPad(eIfd));
      if (bytesToHex(mIfd) !== bytesToHex(mIfdExpected)) {
        return new Uint8Array([0x69, 0x88]);
      }
      const S = des3CbcDecrypt(eIfd, ke);
      const rndIfd = S.slice(0, 8);
      const rndIcRecv = S.slice(8, 16);
      const kIfd = S.slice(16, 32);
      if (bytesToHex(rndIcRecv) !== bytesToHex(pendingRndIc)) {
        return new Uint8Array([0x69, 0x88]);
      }
      const kIc = chipRng().slice(0, 16);
      const R = bacConcat(pendingRndIc, rndIfd, kIc);
      const eIc = des3CbcEncrypt(R, ke);
      const mIc = retailMac(km, isoPad(eIc));
      // Derive session state for subsequent secure-messaging APDUs.
      const seed = new Uint8Array(16);
      for (let i = 0; i < 16; i++) seed[i] = kIfd[i] ^ kIc[i];
      sessionKsEnc = deriveSpecKey(seed, 1);
      sessionKsMac = deriveSpecKey(seed, 2);
      sessionSsc = bacConcat(pendingRndIc.slice(4, 8), rndIfd.slice(4, 8));
      mutuallyAuthenticated = true;
      return new Uint8Array([...eIc, ...mIc, 0x90, 0x00]);
    }
    return new Uint8Array([0x6d, 0x00]); // INS not supported
  };

  return {
    transport,
    isMutuallyAuthenticated: () => mutuallyAuthenticated,
    getSessionKsEnc: () => sessionKsEnc,
    getSessionKsMac: () => sessionKsMac,
    getSessionSsc: () => sessionSsc,
  };
}

function deriveSpecKey(seed: Uint8Array, c: number): Uint8Array {
  // Mirror of bac-session.ts's session-key KDF, for the mock passport.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const forge = require("node-forge");
  const cBytes = new Uint8Array([0, 0, 0, c]);
  const md = forge.md.sha1.create();
  md.update(forge.util.binary.raw.encode(bacConcat(seed, cBytes)));
  const out = forge.util.binary.raw.decode(md.digest().bytes()) as Uint8Array;
  return out.slice(0, 16);
}

describe("BAC mutual authentication (mock passport)", () => {
  test("session keys converge between reader and chip", async () => {
    // Use Node's crypto for reader RNG; passport gets its own counter
    // so the test is deterministic but the inputs are non-trivial.
    let chipCounter = 0;
    const chipRng = () => {
      const out = new Uint8Array(32);
      for (let i = 0; i < 32; i++) out[i] = (chipCounter * 31 + i + 1) & 0xff;
      chipCounter++;
      return out;
    };
    const chip = makeMockPassport(SPEC_MRZ, chipRng);

    const readerRng = (n: number) => new Uint8Array(randomBytes(n));

    const session = await bacMutualAuthenticate(SPEC_MRZ, chip.transport, readerRng);

    expect(chip.isMutuallyAuthenticated()).toBe(true);
    // Reader-derived keys must match the chip's (modulo the parity bit
    // adjustment the reader applies — the chip mock uses unadjusted keys).
    const chipKsEnc = chip.getSessionKsEnc()!;
    const chipKsMac = chip.getSessionKsMac()!;
    // Parity bit is LSB of each byte; compare upper 7 bits.
    expect(maskParity(session.ksEnc)).toEqual(maskParity(chipKsEnc));
    expect(maskParity(session.ksMac)).toEqual(maskParity(chipKsMac));
    // SSC must be identical.
    expect(bytesToHex(session.ssc)).toBe(bytesToHex(chip.getSessionSsc()!));
  });

  test("rejects mutual auth with wrong MRZ", async () => {
    const chipRng = () => new Uint8Array(32).fill(0x55);
    const chip = makeMockPassport(SPEC_MRZ, chipRng);
    const wrongMrz: Mrz = { ...SPEC_MRZ, dateOfBirth: "990101" };
    await expect(
      bacMutualAuthenticate(wrongMrz, chip.transport, (n) => new Uint8Array(n))
    ).rejects.toThrow(/MUTUAL AUTHENTICATE/);
  });
});

function maskParity(b: Uint8Array): Uint8Array {
  return Uint8Array.from(b, (x) => x & 0xfe);
}

describe("secure-messaging APDU wrap / unwrap", () => {
  test("wrapped APDU has correct shape", () => {
    const session = {
      ksEnc: hexToBytes("979ec13b1cbfe9dcd01ab0fed307eae5"),
      ksMac: hexToBytes("f1cb1f1fb5adf208806b89dc579dc1f8"),
      ssc: hexToBytes("887022120c06c226"),
    };
    // SELECT EF.COM (5F.01 not used; this just exercises the wrap path).
    const { wrapped } = wrapApdu(session, 0x00, 0xa4, 0x02, 0x0c, hexToBytes("011e"));
    // First byte CLA must have the SM bit set (0x00 | 0x0c = 0x0c).
    expect(wrapped[0]).toBe(0x0c);
    expect(wrapped[1]).toBe(0xa4);
    // Must contain the DO'8E' tag (0x8e) at some offset.
    expect(Array.from(wrapped).indexOf(0x8e)).toBeGreaterThan(0);
  });

  test("round-trip: chip's response to our wrapped command unwraps cleanly", () => {
    // Use deterministic session state for reproducibility.
    const session = {
      ksEnc: hexToBytes("979ec13b1cbfe9dcd01ab0fed307eae5"),
      ksMac: hexToBytes("f1cb1f1fb5adf208806b89dc579dc1f8"),
      ssc: hexToBytes("887022120c06c226"),
    };

    // Simulate a chip response that's a wrapped APDU: it has DO'87'
    // (encrypted data) + DO'99' (status word) + DO'8E' (MAC). We build
    // one ourselves using the same session keys, then unwrap.
    const payload = hexToBytes("deadbeef"); // pretend chip returned 4 bytes
    const padded = isoPad(payload);
    const ct = des3CbcEncrypt(padded, session.ksEnc);
    const do87 = bacConcat(
      new Uint8Array([0x87, ct.length + 1, 0x01]),
      ct
    );
    const do99 = new Uint8Array([0x99, 0x02, 0x90, 0x00]);

    // Reader will bump SSC before MACing the response.
    const sscResp = incrementSscLocal(session.ssc);
    const macInput = isoPad(bacConcat(sscResp, do87, do99));
    const mac = retailMac(session.ksMac, macInput);
    const do8e = bacConcat(new Uint8Array([0x8e, 0x08]), mac);

    const body = bacConcat(do87, do99, do8e);
    const respApdu = bacConcat(body, new Uint8Array([0x90, 0x00]));

    const { data, sw } = unwrapResponse(session, respApdu);
    expect(sw).toBe(0x9000);
    expect(bytesToHex(data)).toBe("deadbeef");
  });
});

function incrementSscLocal(ssc: Uint8Array): Uint8Array {
  const out = new Uint8Array(ssc);
  for (let i = out.length - 1; i >= 0; i--) {
    out[i] = (out[i] + 1) & 0xff;
    if (out[i] !== 0) break;
  }
  return out;
}
