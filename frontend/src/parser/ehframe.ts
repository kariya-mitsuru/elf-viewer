// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// .eh_frame and .eh_frame_hdr parser.
// References: DWARF 5 §6.4, LSB Core §10.6, System V ABI AMD64 §3.7

import { Reader } from "./reader.ts";
import {
  type EhFrameCIE,
  type EhFrameFDE,
  type EhFrameHdr,
  type EhFrameHdrEntry,
  type EhFrameData,
  type SectionHeader,
  type ProgramHeader,
  type ELFFile,
  ELFMachine,
  PHType,
} from "./types.ts";

// ─── LEB128 encoding ─────────────────────────────────────────────────────────

function readULEB128(view: DataView, off: number): [number, number] {
  let result = 0;
  let shift = 0;
  let byte: number;
  let pos = off;
  do {
    byte = view.getUint8(pos++);
    result |= (byte & 0x7f) << shift;
    shift += 7;
  } while (byte & 0x80);
  // Treat as unsigned 32-bit
  return [result >>> 0, pos - off];
}

function readSLEB128(view: DataView, off: number): [number, number] {
  let result = 0;
  let shift = 0;
  let byte: number;
  let pos = off;
  do {
    byte = view.getUint8(pos++);
    result |= (byte & 0x7f) << shift;
    shift += 7;
  } while (byte & 0x80);
  // Sign extend
  if (shift < 32 && byte & 0x40) result |= -(1 << shift);
  return [result | 0, pos - off];
}

// ─── DW_EH_PE pointer encoding ───────────────────────────────────────────────

const DW_EH_PE_omit = 0xff;
// Format (low nibble)
const DW_EH_PE_absptr = 0x00;
const DW_EH_PE_uleb128 = 0x01;
const DW_EH_PE_udata2 = 0x02;
const DW_EH_PE_udata4 = 0x03;
const DW_EH_PE_udata8 = 0x04;
const DW_EH_PE_sleb128 = 0x09;
const DW_EH_PE_sdata2 = 0x0a;
const DW_EH_PE_sdata4 = 0x0b;
const DW_EH_PE_sdata8 = 0x0c;
// Application (high nibble)
const DW_EH_PE_pcrel = 0x10;
const DW_EH_PE_datarel = 0x30;

/** Human-readable name for a DW_EH_PE encoding byte. */
function ehPeEncName(enc: number): string {
  if (enc === DW_EH_PE_omit) return "omit";
  const fmt = enc & 0x0f;
  const app = enc & 0x70;
  const fmtNames: Record<number, string> = {
    [DW_EH_PE_absptr]: "absptr",
    [DW_EH_PE_uleb128]: "uleb128",
    [DW_EH_PE_udata2]: "udata2",
    [DW_EH_PE_udata4]: "udata4",
    [DW_EH_PE_udata8]: "udata8",
    [DW_EH_PE_sleb128]: "sleb128",
    [DW_EH_PE_sdata2]: "sdata2",
    [DW_EH_PE_sdata4]: "sdata4",
    [DW_EH_PE_sdata8]: "sdata8",
  };
  const appNames: Record<number, string> = {
    0x00: "absptr",
    [DW_EH_PE_pcrel]: "pcrel",
    0x20: "textrel",
    [DW_EH_PE_datarel]: "datarel",
    0x40: "funcrel",
    0x50: "aligned",
  };
  const parts: string[] = [];
  if (app !== 0x00) parts.push(appNames[app] ?? `app(${app.toString(16)})`);
  parts.push(fmtNames[fmt] ?? `fmt(${fmt.toString(16)})`);
  if (enc & 0x80) parts.push("indirect");
  return parts.join("+");
}

/**
 * Read an encoded pointer value. Returns [decodedValue, bytesConsumed].
 * `pcAddr` is the virtual address of the field being read (for pcrel).
 * `dataAddr` is the base address for datarel encoding.
 */
function readEncodedValue(
  view: DataView,
  off: number,
  le: boolean,
  is64: boolean,
  enc: number,
  pcAddr: bigint,
  dataAddr: bigint
): [bigint, number] {
  if (enc === DW_EH_PE_omit) return [0n, 0];

  const fmt = enc & 0x0f;
  let val: bigint;
  let size: number;

  switch (fmt) {
    case DW_EH_PE_absptr:
      if (is64) {
        val = view.getBigInt64(off, le);
        size = 8;
      } else {
        val = BigInt(view.getInt32(off, le));
        size = 4;
      }
      break;
    case DW_EH_PE_uleb128: {
      const [v, n] = readULEB128(view, off);
      val = BigInt(v);
      size = n;
      break;
    }
    case DW_EH_PE_udata2:
      val = BigInt(view.getUint16(off, le));
      size = 2;
      break;
    case DW_EH_PE_udata4:
      val = BigInt(view.getUint32(off, le));
      size = 4;
      break;
    case DW_EH_PE_udata8:
      val = view.getBigUint64(off, le);
      size = 8;
      break;
    case DW_EH_PE_sleb128: {
      const [v, n] = readSLEB128(view, off);
      val = BigInt(v);
      size = n;
      break;
    }
    case DW_EH_PE_sdata2:
      val = BigInt(view.getInt16(off, le));
      size = 2;
      break;
    case DW_EH_PE_sdata4:
      val = BigInt(view.getInt32(off, le));
      size = 4;
      break;
    case DW_EH_PE_sdata8:
      val = view.getBigInt64(off, le);
      size = 8;
      break;
    default:
      return [0n, 0];
  }

  // Apply application modifier
  const app = enc & 0x70;
  if (app === DW_EH_PE_pcrel) val += pcAddr;
  else if (app === DW_EH_PE_datarel) val += dataAddr;
  // absptr (0x00), textrel, funcrel, aligned: val unchanged or unsupported

  return [val, size];
}

/** Byte size of an encoded value (for fixed-size formats only). Returns 0 for variable-size. */
function encodedValueSize(enc: number, is64: boolean): number {
  const fmt = enc & 0x0f;
  switch (fmt) {
    case DW_EH_PE_absptr:
      return is64 ? 8 : 4;
    case DW_EH_PE_udata2:
    case DW_EH_PE_sdata2:
      return 2;
    case DW_EH_PE_udata4:
    case DW_EH_PE_sdata4:
      return 4;
    case DW_EH_PE_udata8:
    case DW_EH_PE_sdata8:
      return 8;
    default:
      return 0; // variable-size (uleb128, sleb128)
  }
}

// ─── Register names ──────────────────────────────────────────────────────────

const X86_64_REGS: Record<number, string> = {
  0: "rax",
  1: "rdx",
  2: "rcx",
  3: "rbx",
  4: "rsi",
  5: "rdi",
  6: "rbp",
  7: "rsp",
  8: "r8",
  9: "r9",
  10: "r10",
  11: "r11",
  12: "r12",
  13: "r13",
  14: "r14",
  15: "r15",
  16: "rip",
  17: "xmm0",
  18: "xmm1",
  19: "xmm2",
  20: "xmm3",
  21: "xmm4",
  22: "xmm5",
  23: "xmm6",
  24: "xmm7",
  25: "xmm8",
  26: "xmm9",
  27: "xmm10",
  28: "xmm11",
  29: "xmm12",
  30: "xmm13",
  31: "xmm14",
  32: "xmm15",
  49: "rFLAGS",
  50: "es",
  51: "cs",
  52: "ss",
  53: "ds",
  54: "fs",
  55: "gs",
  62: "tr",
  63: "ldtr",
  64: "mxcsr",
  65: "fcw",
  66: "fsw",
};

function aarch64RegName(n: number): string {
  if (n <= 30) return `x${n}`;
  if (n === 31) return "sp";
  if (n >= 64 && n <= 95) return `v${n - 64}`;
  return `r${n}`;
}

function regName(n: number, machine: ELFMachine): string {
  if (machine === ELFMachine.AArch64) return aarch64RegName(n);
  if (machine === ELFMachine.X86_64) return X86_64_REGS[n] ?? `r${n}`;
  return `r${n}`;
}

// ─── CFI instruction decoder ─────────────────────────────────────────────────

function decodeCFI(
  view: DataView,
  start: number,
  end: number,
  le: boolean,
  codeAlign: number,
  dataAlign: number,
  machine: ELFMachine
): string[] {
  const instrs: string[] = [];
  let off = start;
  const rn = (n: number) => `r${n} (${regName(n, machine)})`;

  while (off < end) {
    const byte = view.getUint8(off++);
    const high2 = byte & 0xc0;

    if (high2 === 0x40) {
      // DW_CFA_advance_loc
      const delta = byte & 0x3f;
      instrs.push(`DW_CFA_advance_loc: ${delta * codeAlign}`);
    } else if (high2 === 0x80) {
      // DW_CFA_offset
      const reg = byte & 0x3f;
      const [uoff, n] = readULEB128(view, off);
      off += n;
      instrs.push(`DW_CFA_offset: ${rn(reg)} at cfa${fmtOff(uoff * dataAlign)}`);
    } else if (high2 === 0xc0) {
      // DW_CFA_restore
      const reg = byte & 0x3f;
      instrs.push(`DW_CFA_restore: ${rn(reg)}`);
    } else {
      // Extended opcodes
      switch (byte) {
        case 0x00:
          instrs.push("DW_CFA_nop");
          break;
        case 0x01: {
          // DW_CFA_set_loc — skip address (pointer-sized)
          const sz = view.byteLength - off >= 8 ? 8 : 4;
          off += sz;
          instrs.push("DW_CFA_set_loc");
          break;
        }
        case 0x02: {
          // DW_CFA_advance_loc1
          const delta = view.getUint8(off++);
          instrs.push(`DW_CFA_advance_loc1: ${delta * codeAlign}`);
          break;
        }
        case 0x03: {
          // DW_CFA_advance_loc2
          const delta = view.getUint16(off, le);
          off += 2;
          instrs.push(`DW_CFA_advance_loc2: ${delta * codeAlign}`);
          break;
        }
        case 0x04: {
          // DW_CFA_advance_loc4
          const delta = view.getUint32(off, le);
          off += 4;
          instrs.push(`DW_CFA_advance_loc4: ${delta * codeAlign}`);
          break;
        }
        case 0x05: {
          // DW_CFA_offset_extended
          const [reg, n1] = readULEB128(view, off);
          off += n1;
          const [uoff, n2] = readULEB128(view, off);
          off += n2;
          instrs.push(`DW_CFA_offset_extended: ${rn(reg)} at cfa${fmtOff(uoff * dataAlign)}`);
          break;
        }
        case 0x06: {
          // DW_CFA_restore_extended
          const [reg, n] = readULEB128(view, off);
          off += n;
          instrs.push(`DW_CFA_restore_extended: ${rn(reg)}`);
          break;
        }
        case 0x07: {
          // DW_CFA_undefined
          const [reg, n] = readULEB128(view, off);
          off += n;
          instrs.push(`DW_CFA_undefined: ${rn(reg)}`);
          break;
        }
        case 0x08: {
          // DW_CFA_same_value
          const [reg, n] = readULEB128(view, off);
          off += n;
          instrs.push(`DW_CFA_same_value: ${rn(reg)}`);
          break;
        }
        case 0x09: {
          // DW_CFA_register
          const [reg1, n1] = readULEB128(view, off);
          off += n1;
          const [reg2, n2] = readULEB128(view, off);
          off += n2;
          instrs.push(`DW_CFA_register: ${rn(reg1)} in ${rn(reg2)}`);
          break;
        }
        case 0x0a:
          instrs.push("DW_CFA_remember_state");
          break;
        case 0x0b:
          instrs.push("DW_CFA_restore_state");
          break;
        case 0x0c: {
          // DW_CFA_def_cfa
          const [reg, n1] = readULEB128(view, off);
          off += n1;
          const [uoff, n2] = readULEB128(view, off);
          off += n2;
          instrs.push(`DW_CFA_def_cfa: ${rn(reg)} ofs ${uoff}`);
          break;
        }
        case 0x0d: {
          // DW_CFA_def_cfa_register
          const [reg, n] = readULEB128(view, off);
          off += n;
          instrs.push(`DW_CFA_def_cfa_register: ${rn(reg)}`);
          break;
        }
        case 0x0e: {
          // DW_CFA_def_cfa_offset
          const [uoff, n] = readULEB128(view, off);
          off += n;
          instrs.push(`DW_CFA_def_cfa_offset: ${uoff}`);
          break;
        }
        case 0x0f: {
          // DW_CFA_def_cfa_expression
          const [len, n] = readULEB128(view, off);
          off += n + len;
          instrs.push(`DW_CFA_def_cfa_expression (${len} bytes)`);
          break;
        }
        case 0x10: {
          // DW_CFA_expression
          const [reg, n1] = readULEB128(view, off);
          off += n1;
          const [len, n2] = readULEB128(view, off);
          off += n2 + len;
          instrs.push(`DW_CFA_expression: ${rn(reg)} (${len} bytes)`);
          break;
        }
        case 0x11: {
          // DW_CFA_offset_extended_sf
          const [reg, n1] = readULEB128(view, off);
          off += n1;
          const [soff, n2] = readSLEB128(view, off);
          off += n2;
          instrs.push(`DW_CFA_offset_extended_sf: ${rn(reg)} at cfa${fmtOff(soff * dataAlign)}`);
          break;
        }
        case 0x12: {
          // DW_CFA_def_cfa_sf
          const [reg, n1] = readULEB128(view, off);
          off += n1;
          const [soff, n2] = readSLEB128(view, off);
          off += n2;
          instrs.push(`DW_CFA_def_cfa_sf: ${rn(reg)} ofs ${soff * dataAlign}`);
          break;
        }
        case 0x13: {
          // DW_CFA_def_cfa_offset_sf
          const [soff, n] = readSLEB128(view, off);
          off += n;
          instrs.push(`DW_CFA_def_cfa_offset_sf: ${soff * dataAlign}`);
          break;
        }
        case 0x14: {
          // DW_CFA_val_offset
          const [reg, n1] = readULEB128(view, off);
          off += n1;
          const [uoff, n2] = readULEB128(view, off);
          off += n2;
          instrs.push(`DW_CFA_val_offset: ${rn(reg)} is cfa${fmtOff(uoff * dataAlign)}`);
          break;
        }
        case 0x15: {
          // DW_CFA_val_offset_sf
          const [reg, n1] = readULEB128(view, off);
          off += n1;
          const [soff, n2] = readSLEB128(view, off);
          off += n2;
          instrs.push(`DW_CFA_val_offset_sf: ${rn(reg)} is cfa${fmtOff(soff * dataAlign)}`);
          break;
        }
        case 0x16: {
          // DW_CFA_val_expression
          const [reg, n1] = readULEB128(view, off);
          off += n1;
          const [len, n2] = readULEB128(view, off);
          off += n2 + len;
          instrs.push(`DW_CFA_val_expression: ${rn(reg)} (${len} bytes)`);
          break;
        }
        case 0x2e: {
          // DW_CFA_GNU_args_size
          const [sz, n] = readULEB128(view, off);
          off += n;
          instrs.push(`DW_CFA_GNU_args_size: ${sz}`);
          break;
        }
        case 0x2f: {
          // DW_CFA_GNU_negative_offset_extended
          const [reg, n1] = readULEB128(view, off);
          off += n1;
          const [uoff, n2] = readULEB128(view, off);
          off += n2;
          instrs.push(
            `DW_CFA_GNU_negative_offset_extended: ${rn(reg)} at cfa${fmtOff(-(uoff * dataAlign))}`
          );
          break;
        }
        default:
          instrs.push(`DW_CFA_unknown(0x${byte.toString(16)})`);
          break;
      }
    }
  }
  return instrs;
}

function fmtOff(v: number): string {
  if (v >= 0) return `+${v}`;
  return `${v}`;
}

// ─── CIE/FDE string reader ───────────────────────────────────────────────────

function readCString(view: DataView, off: number): [string, number] {
  let end = off;
  while (end < view.byteLength && view.getUint8(end) !== 0) end++;
  const bytes = new Uint8Array(view.buffer, view.byteOffset + off, end - off);
  return [new TextDecoder().decode(bytes), end + 1 - off]; // +1 for NUL
}

// ─── .eh_frame parser ────────────────────────────────────────────────────────

function parseEhFrameSection(
  r: Reader,
  sectionFileOffset: number,
  sectionSize: number,
  sectionVaddr: bigint,
  machine: ELFMachine
): { cies: EhFrameCIE[]; fdes: EhFrameFDE[] } {
  const cies: EhFrameCIE[] = [];
  const fdes: EhFrameFDE[] = [];
  const cieMap = new Map<number, EhFrameCIE>(); // section offset → CIE

  const view = r.subView(sectionFileOffset, sectionSize);
  const le = r.le;
  const is64 = r.is64;
  let pos = 0;

  while (pos + 4 <= sectionSize) {
    const recordStart = pos;
    let length = new DataView(view.buffer, view.byteOffset + pos, 4).getUint32(0, le);
    pos += 4;

    if (length === 0) break; // terminator

    let extendedLength = false;
    if (length === 0xffffffff) {
      // 64-bit DWARF length
      if (pos + 8 > sectionSize) break;
      const dv = new DataView(view.buffer, view.byteOffset + pos, 8);
      length = Number(dv.getBigUint64(0, le));
      pos += 8;
      extendedLength = true;
    }

    const contentStart = pos;
    const recordEnd = contentStart + length;
    if (recordEnd > sectionSize) break;

    // CIE_id / CIE_pointer (4 bytes in .eh_frame, 8 bytes if extended)
    const idSize = extendedLength ? 8 : 4;
    if (pos + idSize > recordEnd) {
      pos = recordEnd;
      continue;
    }
    const idField = extendedLength
      ? Number(new DataView(view.buffer, view.byteOffset + pos, 8).getBigUint64(0, le))
      : new DataView(view.buffer, view.byteOffset + pos, 4).getUint32(0, le);
    pos += idSize;

    const totalRecordSize = recordEnd - recordStart;

    if (idField === 0) {
      // CIE
      const cie = parseCIE(view, pos, recordEnd, recordStart, totalRecordSize, le, is64, machine);
      cies.push(cie);
      cieMap.set(recordStart, cie);
    } else {
      // FDE — CIE pointer is relative backward offset from the CIE_pointer field
      const ciePointerFieldOff = contentStart;
      const cieOff = ciePointerFieldOff - idField;
      const cie = cieMap.get(cieOff);

      const fde = parseFDE(
        view,
        pos,
        recordEnd,
        recordStart,
        totalRecordSize,
        le,
        is64,
        machine,
        cie ?? null,
        sectionVaddr,
        cieOff
      );
      fdes.push(fde);
    }

    pos = recordEnd;
  }

  return { cies, fdes };
}

function parseCIE(
  view: DataView,
  pos: number,
  end: number,
  recordStart: number,
  totalSize: number,
  le: boolean,
  is64: boolean,
  machine: ELFMachine
): EhFrameCIE {
  const version = view.getUint8(pos++);
  const [augmentation, augLen] = readCString(view, pos);
  pos += augLen;

  const [codeAlignFactor, n1] = readULEB128(view, pos);
  pos += n1;
  const [dataAlignFactor, n2] = readSLEB128(view, pos);
  pos += n2;

  // Return address register: u8 in version 1, ULEB128 in version 3+
  let returnAddressReg: number;
  if (version === 1) {
    returnAddressReg = view.getUint8(pos++);
  } else {
    const [reg, n3] = readULEB128(view, pos);
    pos += n3;
    returnAddressReg = reg;
  }

  let fdeEncoding = DW_EH_PE_absptr;
  let lsdaEncoding = DW_EH_PE_omit;
  let personalityEncoding = DW_EH_PE_omit;
  let personalityRoutine = 0n;
  let isSignalFrame = false;

  // Parse augmentation data if augmentation starts with 'z'
  if (augmentation.startsWith("z")) {
    const [augDataLen, n4] = readULEB128(view, pos);
    pos += n4;
    const augEnd = pos + augDataLen;

    for (let i = 1; i < augmentation.length && pos < augEnd; i++) {
      const ch = augmentation[i];
      if (ch === "R") {
        fdeEncoding = view.getUint8(pos++);
      } else if (ch === "P") {
        personalityEncoding = view.getUint8(pos++);
        const [val, sz] = readEncodedValue(view, pos, le, is64, personalityEncoding, 0n, 0n);
        personalityRoutine = val;
        pos += sz;
      } else if (ch === "L") {
        lsdaEncoding = view.getUint8(pos++);
      } else if (ch === "S") {
        isSignalFrame = true;
      }
    }
    pos = augEnd; // skip any remaining augmentation data
  }

  const instructions = decodeCFI(
    view,
    pos,
    end,
    le,
    codeAlignFactor,
    dataAlignFactor,
    machine
  );

  return {
    offset: recordStart,
    length: totalSize,
    version,
    augmentation,
    codeAlignFactor,
    dataAlignFactor,
    returnAddressReg,
    fdeEncoding,
    lsdaEncoding,
    personalityEncoding,
    personalityRoutine,
    isSignalFrame,
    initialInstructions: instructions,
  };
}

function parseFDE(
  view: DataView,
  pos: number,
  end: number,
  recordStart: number,
  totalSize: number,
  le: boolean,
  is64: boolean,
  machine: ELFMachine,
  cie: EhFrameCIE | null,
  sectionVaddr: bigint,
  cieOff: number
): EhFrameFDE {
  const fdeEncoding = cie?.fdeEncoding ?? DW_EH_PE_absptr;
  const codeAlign = cie?.codeAlignFactor ?? 1;
  const dataAlign = cie?.dataAlignFactor ?? 1;
  const lsdaEncoding = cie?.lsdaEncoding ?? DW_EH_PE_omit;

  // initial_location
  const pcRelAddr = sectionVaddr + BigInt(pos);
  const [pcBegin, sz1] = readEncodedValue(view, pos, le, is64, fdeEncoding, pcRelAddr, 0n);
  pos += sz1;

  // address_range (same format bits as fdeEncoding, but without application — always absolute)
  const rangeFmt = fdeEncoding & 0x0f;
  const [pcRange, sz2] = readEncodedValue(view, pos, le, is64, rangeFmt, 0n, 0n);
  pos += sz2;

  let lsda = 0n;
  // Augmentation data (if CIE has 'z')
  if (cie?.augmentation.startsWith("z")) {
    const [augDataLen, n] = readULEB128(view, pos);
    pos += n;
    const augEnd = pos + augDataLen;
    if (lsdaEncoding !== DW_EH_PE_omit && augDataLen > 0) {
      const lsdaPcAddr = sectionVaddr + BigInt(pos);
      const [val] = readEncodedValue(view, pos, le, is64, lsdaEncoding, lsdaPcAddr, 0n);
      lsda = val;
    }
    pos = augEnd;
  }

  const instructions = decodeCFI(view, pos, end, le, codeAlign, dataAlign, machine);

  return {
    offset: recordStart,
    length: totalSize,
    cieOffset: cieOff,
    pcBegin,
    pcRange,
    lsda,
    instructions,
  };
}

// ─── .eh_frame_hdr parser ────────────────────────────────────────────────────

function parseEhFrameHdrSection(
  r: Reader,
  sectionFileOffset: number,
  sectionSize: number,
  sectionVaddr: bigint
): EhFrameHdr | null {
  if (sectionSize < 4) return null;
  const view = r.subView(sectionFileOffset, sectionSize);
  const le = r.le;
  const is64 = r.is64;

  const version = view.getUint8(0);
  if (version !== 1) return null;

  const ehFramePtrEnc = view.getUint8(1);
  const fdeCountEnc = view.getUint8(2);
  const tableEnc = view.getUint8(3);

  let pos = 4;

  // eh_frame_ptr
  const ptrPcAddr = sectionVaddr + BigInt(pos);
  const [ehFramePtr, sz1] = readEncodedValue(
    view,
    pos,
    le,
    is64,
    ehFramePtrEnc,
    ptrPcAddr,
    sectionVaddr
  );
  pos += sz1;

  // fde_count
  let fdeCount = 0;
  if (fdeCountEnc !== DW_EH_PE_omit) {
    const countPcAddr = sectionVaddr + BigInt(pos);
    const [count, sz2] = readEncodedValue(
      view,
      pos,
      le,
      is64,
      fdeCountEnc,
      countPcAddr,
      sectionVaddr
    );
    fdeCount = Number(count);
    pos += sz2;
  }

  // Binary search table
  const table: EhFrameHdrEntry[] = [];
  const entrySize = encodedValueSize(tableEnc, is64);
  for (let i = 0; i < fdeCount && pos + entrySize * 2 <= sectionSize; i++) {
    const locPcAddr = sectionVaddr + BigInt(pos);
    const [initialLocation, sz3] = readEncodedValue(
      view,
      pos,
      le,
      is64,
      tableEnc,
      locPcAddr,
      sectionVaddr
    );
    pos += sz3;
    const fdePcAddr = sectionVaddr + BigInt(pos);
    const [fdeOffset, sz4] = readEncodedValue(
      view,
      pos,
      le,
      is64,
      tableEnc,
      fdePcAddr,
      sectionVaddr
    );
    pos += sz4;
    table.push({ initialLocation, fdeOffset });
  }

  return { version, ehFramePtrEnc, fdeCountEnc, tableEnc, ehFramePtr, fdeCount, table };
}

// ─── Public entry point ──────────────────────────────────────────────────────

export function parseEhFrame(elf: ELFFile, r: Reader): EhFrameData | null {
  const shs = elf.sectionHeaders;
  const phs = elf.programHeaders;
  const machine = elf.header.machine;

  // Find .eh_frame section
  const ehFrameSh = shs.find((s) => s.name === ".eh_frame");
  if (!ehFrameSh || ehFrameSh.size === 0) return null;

  // Find .eh_frame_hdr section (or PT_GNU_EH_FRAME segment)
  const ehFrameHdrSh: SectionHeader | undefined = shs.find((s) => s.name === ".eh_frame_hdr");
  let hdrFileOffset: number | null = null;
  let hdrVaddr = 0n;
  let hdrSize = 0;

  if (ehFrameHdrSh && ehFrameHdrSh.size > 0) {
    hdrFileOffset = ehFrameHdrSh.offset;
    hdrVaddr = ehFrameHdrSh.addr;
    hdrSize = ehFrameHdrSh.size;
  } else {
    // Fall back to PT_GNU_EH_FRAME program header
    const ehFrameHdrPh: ProgramHeader | undefined = phs.find(
      (p) => p.type === PHType.GnuEhFrame
    );
    if (ehFrameHdrPh && ehFrameHdrPh.filesz > 0) {
      hdrFileOffset = ehFrameHdrPh.offset;
      hdrVaddr = ehFrameHdrPh.vaddr;
      hdrSize = ehFrameHdrPh.filesz;
    }
  }

  const { cies, fdes } = parseEhFrameSection(
    r,
    ehFrameSh.offset,
    ehFrameSh.size,
    ehFrameSh.addr,
    machine
  );

  let hdr: EhFrameHdr | null = null;
  if (hdrFileOffset !== null) {
    hdr = parseEhFrameHdrSection(r, hdrFileOffset, hdrSize, hdrVaddr);
  }

  return {
    cies,
    fdes,
    hdr,
    sectionFileOffset: ehFrameSh.offset,
    sectionVaddr: ehFrameSh.addr,
    hdrSectionFileOffset: hdrFileOffset,
  };
}

export { ehPeEncName };
