import { describe, expect, test } from "vitest";

import { computeHPassport, parseDg1, parseMrzString } from "./passport-data";
import { bytesToHex, hexToBytes } from "./bac";

// ICAO 9303 Doc Part 4, Appendix B example MRZ for a TD3 passport
// (machine-readable travel document, two 44-char lines):
//
// Line 1: P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<
// Line 2: L898902C36UTO7408122F1204159ZE184226B<<<<<10
//
// Primary: ERIKSSON, Secondary: ANNA MARIA, country UTO,
// DOB 740812, expiry 120415, sex F, doc# L898902C3, nationality UTO.

const SAMPLE_TD3 =
  "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" +
  "L898902C36UTO7408122F1204159ZE184226B<<<<<10";

describe("MRZ parsing", () => {
  test("parses ICAO 9303 sample TD3", () => {
    const p = parseMrzString(SAMPLE_TD3);
    expect(p.format).toBe("TD3");
    expect(p.documentType).toBe("P");
    expect(p.issuingCountry).toBe("UTO");
    expect(p.documentNumber).toBe("L898902C3");
    expect(p.nationality).toBe("UTO");
    expect(p.dateOfBirth).toBe("740812");
    expect(p.sex).toBe("F");
    expect(p.dateOfExpiry).toBe("120415");
    expect(p.primaryIdentifier).toBe("ERIKSSON");
    expect(p.secondaryIdentifier).toBe("ANNA MARIA");
  });
});

describe("DG1 BER-TLV parsing", () => {
  test("unwraps 0x61 / 0x5F1F nested TLV", () => {
    const mrz = SAMPLE_TD3;
    const mrzBytes = new TextEncoder().encode(mrz);
    // 5F1F LL <mrz>
    const inner = new Uint8Array([0x5f, 0x1f, mrz.length, ...mrzBytes]);
    // 61 LL <inner>
    const dg1 = new Uint8Array([0x61, inner.length, ...inner]);
    const parsed = parseDg1(dg1);
    expect(parsed.documentNumber).toBe("L898902C3");
  });
});

describe("H_passport commitment", () => {
  test("32 bytes, deterministic", () => {
    const p = parseMrzString(SAMPLE_TD3);
    const a = computeHPassport(p);
    const b = computeHPassport(p);
    expect(a.length).toBe(32);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  test("changes when stable attributes change", () => {
    const p = parseMrzString(SAMPLE_TD3);
    const base = computeHPassport(p);

    // Different doc number → different H_passport.
    const swappedDoc = { ...p, documentNumber: "M123456789" };
    expect(bytesToHex(computeHPassport(swappedDoc))).not.toBe(bytesToHex(base));

    // Different DOB → different H_passport.
    const swappedDob = { ...p, dateOfBirth: "650101" };
    expect(bytesToHex(computeHPassport(swappedDob))).not.toBe(bytesToHex(base));

    // Different country → different H_passport.
    const swappedCountry = { ...p, issuingCountry: "USA" };
    expect(bytesToHex(computeHPassport(swappedCountry))).not.toBe(bytesToHex(base));
  });
});
