// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Smoke tests for the ELF parser.
// Uses hand-crafted minimal ELF byte sequences (no real binary files needed).

import { describe, it, expect } from "vitest";
import { parseELF, ParseError } from "./elf";
import { ELFClass, ELFData, ELFType, ELFMachine } from "./types";

// ─── Minimal ELF builders ─────────────────────────────────────────────────────

/** Builds a 64-byte ELF64 LSB header with no sections and no program headers. */
function minimalELF64(overrides: { type?: number; machine?: number } = {}): Uint8Array {
  const buf = new Uint8Array(64);
  const dv = new DataView(buf.buffer);

  // e_ident
  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46; // magic
  buf[4] = ELFClass.ELF64; // EI_CLASS
  buf[5] = ELFData.LSB; // EI_DATA
  buf[6] = 1; // EI_VERSION

  dv.setUint16(16, overrides.type ?? ELFType.Exec, true); // e_type
  dv.setUint16(18, overrides.machine ?? ELFMachine.X86_64, true); // e_machine
  dv.setUint32(20, 1, true); // e_version
  dv.setUint16(52, 64, true); // e_ehsize
  dv.setUint16(54, 56, true); // e_phentsize
  dv.setUint16(58, 64, true); // e_shentsize

  return buf;
}

/** Builds a 64-byte ELF32 LSB header with no sections and no program headers. */
function minimalELF32(overrides: { type?: number; machine?: number } = {}): Uint8Array {
  const buf = new Uint8Array(64);
  const dv = new DataView(buf.buffer);

  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46;
  buf[4] = ELFClass.ELF32;
  buf[5] = ELFData.LSB;
  buf[6] = 1;

  dv.setUint16(16, overrides.type ?? ELFType.Exec, true);
  dv.setUint16(18, overrides.machine ?? ELFMachine.X86, true);
  dv.setUint32(20, 1, true);
  dv.setUint16(40, 52, true); // e_ehsize (ELF32 header is 52 bytes)
  dv.setUint16(42, 32, true); // e_phentsize
  dv.setUint16(46, 40, true); // e_shentsize

  return buf;
}

/** Same as minimalELF64 but big-endian (MSB). */
function minimalELF64BE(): Uint8Array {
  const buf = new Uint8Array(64);
  const dv = new DataView(buf.buffer);
  const be = false; // setUint16 littleEndian=false → big-endian

  buf[0] = 0x7f;
  buf[1] = 0x45;
  buf[2] = 0x4c;
  buf[3] = 0x46;
  buf[4] = ELFClass.ELF64;
  buf[5] = ELFData.MSB;
  buf[6] = 1;

  dv.setUint16(16, ELFType.Dyn, be);
  dv.setUint16(18, ELFMachine.AArch64, be);
  dv.setUint32(20, 1, be);
  dv.setUint16(52, 64, be);
  dv.setUint16(54, 56, be);
  dv.setUint16(58, 64, be);

  return buf;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("parseELF – ELF64 LSB", () => {
  it("parses header fields correctly", () => {
    const elf = parseELF(minimalELF64());
    expect(elf.header.class).toBe(ELFClass.ELF64);
    expect(elf.header.data).toBe(ELFData.LSB);
    expect(elf.header.type).toBe(ELFType.Exec);
    expect(elf.header.machine).toBe(ELFMachine.X86_64);
    expect(elf.header.entryPoint).toBe(0n);
    expect(elf.header.phNum).toBe(0);
    expect(elf.header.shNum).toBe(0);
  });

  it("returns empty tables when phNum/shNum are 0", () => {
    const elf = parseELF(minimalELF64());
    expect(elf.programHeaders).toHaveLength(0);
    expect(elf.sectionHeaders).toHaveLength(0);
    expect(elf.symbols).toHaveLength(0);
    expect(elf.dynSymbols).toHaveLength(0);
    expect(elf.relocations).toHaveLength(0);
    expect(elf.dynamicEntries).toHaveLength(0);
    expect(elf.notes).toHaveLength(0);
    expect(elf.versionInfo).toBeNull();
  });

  it("keeps the raw bytes on the result", () => {
    const raw = minimalELF64();
    const elf = parseELF(raw);
    expect(elf.raw).toBe(raw);
  });

  it("accepts ET_DYN (shared object)", () => {
    const elf = parseELF(minimalELF64({ type: ELFType.Dyn }));
    expect(elf.header.type).toBe(ELFType.Dyn);
  });
});

describe("parseELF – ELF32 LSB", () => {
  it("parses header fields correctly", () => {
    const elf = parseELF(minimalELF32());
    expect(elf.header.class).toBe(ELFClass.ELF32);
    expect(elf.header.data).toBe(ELFData.LSB);
    expect(elf.header.type).toBe(ELFType.Exec);
    expect(elf.header.machine).toBe(ELFMachine.X86);
    expect(elf.header.entryPoint).toBe(0n); // bigint, even in ELF32
  });

  it("returns empty tables when phNum/shNum are 0", () => {
    const elf = parseELF(minimalELF32());
    expect(elf.programHeaders).toHaveLength(0);
    expect(elf.sectionHeaders).toHaveLength(0);
  });
});

describe("parseELF – ELF64 MSB (big-endian)", () => {
  it("parses header fields with correct byte order", () => {
    const elf = parseELF(minimalELF64BE());
    expect(elf.header.class).toBe(ELFClass.ELF64);
    expect(elf.header.data).toBe(ELFData.MSB);
    expect(elf.header.type).toBe(ELFType.Dyn);
    expect(elf.header.machine).toBe(ELFMachine.AArch64);
  });
});

describe("parseELF – error handling", () => {
  it("throws ParseError when the buffer is too small", () => {
    expect(() => parseELF(new Uint8Array(16))).toThrow(ParseError);
  });

  it("throws ParseError on invalid magic number", () => {
    const buf = new Uint8Array(64); // all zeros – magic is wrong
    expect(() => parseELF(buf)).toThrow(ParseError);
  });

  it("throws ParseError with a descriptive message for bad magic", () => {
    const buf = new Uint8Array(64);
    expect(() => parseELF(buf)).toThrow("Not an ELF file");
  });

  it("throws ParseError for unsupported ELF class (EI_CLASS=3)", () => {
    const buf = minimalELF64();
    buf[4] = 3; // invalid class
    expect(() => parseELF(buf)).toThrow(ParseError);
  });

  it("throws ParseError for unsupported data encoding (EI_DATA=3)", () => {
    const buf = minimalELF64();
    buf[5] = 3; // invalid encoding
    expect(() => parseELF(buf)).toThrow(ParseError);
  });

  it("is an instance of Error as well as ParseError", () => {
    try {
      parseELF(new Uint8Array(16));
    } catch (e) {
      expect(e).toBeInstanceOf(Error);
      expect(e).toBeInstanceOf(ParseError);
    }
  });
});
