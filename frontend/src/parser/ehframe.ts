// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// .eh_frame, .eh_frame_hdr, and .debug_frame parser.
// References: DWARF 5 §6.4, LSB Core §10.6, System V ABI AMD64 §3.7

import { Cursor } from "./reader.ts";
import {
  type EhFrameCIE,
  type EhFrameFDE,
  type EhFrameHdr,
  type EhFrameHdrEntry,
  type EhFrameData,
  type ProgramHeader,
  type ELFFile,
  ELFMachine,
  PHType,
} from "./types.ts";
import { vaddrToFileOffset } from "./elf.ts";

// ─── DW_EH_PE pointer encoding ───────────────────────────────────────────────

const DW_EH_PE_omit = 0xff;
const DW_EH_PE_absptr = 0x00;
const DW_EH_PE_uleb128 = 0x01;
const DW_EH_PE_udata2 = 0x02;
const DW_EH_PE_udata4 = 0x03;
const DW_EH_PE_udata8 = 0x04;
const DW_EH_PE_sleb128 = 0x09;
const DW_EH_PE_sdata2 = 0x0a;
const DW_EH_PE_sdata4 = 0x0b;
const DW_EH_PE_sdata8 = 0x0c;
const DW_EH_PE_pcrel = 0x10;
const DW_EH_PE_datarel = 0x30;

/** Human-readable name for a DW_EH_PE encoding byte. */
function ehPeEncName(enc: number): string {
  if (enc === DW_EH_PE_omit) {
    return "omit";
  }
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
  if (app !== 0x00) {
    parts.push(appNames[app] ?? `app(${app.toString(16)})`);
  }
  parts.push(fmtNames[fmt] ?? `fmt(${fmt.toString(16)})`);
  if (enc & 0x80) {
    parts.push("indirect");
  }
  return parts.join("+");
}

/**
 * Read an encoded pointer value from `c` (advances cursor).
 * `pcAddr` is the virtual address of the field being read (for pcrel).
 * `dataAddr` is the base address for datarel encoding.
 */
function readEncodedValue(c: Cursor, enc: number, pcAddr: bigint, dataAddr: bigint): bigint {
  if (enc === DW_EH_PE_omit) {
    return 0n;
  }

  const fmt = enc & 0x0f;
  let val: bigint;

  switch (fmt) {
    case DW_EH_PE_absptr:
      val = c.is64 ? c.i64() : BigInt(c.i32());
      break;
    case DW_EH_PE_uleb128:
      val = BigInt(c.uleb128());
      break;
    case DW_EH_PE_udata2:
      val = BigInt(c.u16());
      break;
    case DW_EH_PE_udata4:
      val = BigInt(c.u32());
      break;
    case DW_EH_PE_udata8:
      val = c.u64();
      break;
    case DW_EH_PE_sleb128:
      val = BigInt(c.sleb128());
      break;
    case DW_EH_PE_sdata2:
      val = BigInt(c.i16());
      break;
    case DW_EH_PE_sdata4:
      val = BigInt(c.i32());
      break;
    case DW_EH_PE_sdata8:
      val = c.i64();
      break;
    default:
      return 0n;
  }

  const app = enc & 0x70;
  if (app === DW_EH_PE_pcrel) {
    val += pcAddr;
  } else if (app === DW_EH_PE_datarel) {
    val += dataAddr;
  }

  return val;
}

/** Byte size of a fixed-size encoded value. Returns 0 for variable-size formats. */
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
      return 0;
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
  if (n <= 30) {
    return `x${n}`;
  }
  if (n === 31) {
    return "sp";
  }
  if (n >= 64 && n <= 95) {
    return `v${n - 64}`;
  }
  return `r${n}`;
}

function regName(n: number, machine: ELFMachine): string {
  if (machine === ELFMachine.AArch64) {
    return aarch64RegName(n);
  }
  if (machine === ELFMachine.X86_64) {
    return X86_64_REGS[n] ?? `r${n}`;
  }
  return `r${n}`;
}

// ─── DWARF expression decoder ────────────────────────────────────────────────

function decodeDwarfExpr(c: Cursor, len: number, machine: ELFMachine): string[] {
  const ops: string[] = [];
  const end = c.pos + len;
  const rn = (n: number) => `r${n} (${regName(n, machine)})`;

  while (c.pos < end) {
    const op = c.u8();

    if (op >= 0x30 && op <= 0x4f) {
      ops.push(`DW_OP_lit${op - 0x30}`);
      continue;
    }
    if (op >= 0x50 && op <= 0x6f) {
      const reg = op - 0x50;
      ops.push(`DW_OP_reg${reg} (${regName(reg, machine)})`);
      continue;
    }
    if (op >= 0x70 && op <= 0x8f) {
      const reg = op - 0x70;
      ops.push(`DW_OP_breg${reg} (${regName(reg, machine)}): ${c.sleb128()}`);
      continue;
    }

    switch (op) {
      case 0x03:
        ops.push(`DW_OP_addr: 0x${c.addr().toString(16)}`);
        break;
      case 0x06:
        ops.push("DW_OP_deref");
        break;
      case 0x08:
        ops.push(`DW_OP_const1u: ${c.u8()}`);
        break;
      case 0x09:
        ops.push(`DW_OP_const1s: ${c.i8()}`);
        break;
      case 0x0a:
        ops.push(`DW_OP_const2u: ${c.u16()}`);
        break;
      case 0x0b:
        ops.push(`DW_OP_const2s: ${c.i16()}`);
        break;
      case 0x0c:
        ops.push(`DW_OP_const4u: ${c.u32()}`);
        break;
      case 0x0d:
        ops.push(`DW_OP_const4s: ${c.i32()}`);
        break;
      case 0x0e:
        ops.push(`DW_OP_const8u: ${c.u64()}`);
        break;
      case 0x0f:
        ops.push(`DW_OP_const8s: ${c.i64()}`);
        break;
      case 0x10:
        ops.push(`DW_OP_constu: ${c.uleb128()}`);
        break;
      case 0x11:
        ops.push(`DW_OP_consts: ${c.sleb128()}`);
        break;
      case 0x12:
        ops.push("DW_OP_dup");
        break;
      case 0x13:
        ops.push("DW_OP_drop");
        break;
      case 0x14:
        ops.push("DW_OP_over");
        break;
      case 0x15:
        ops.push(`DW_OP_pick: ${c.u8()}`);
        break;
      case 0x16:
        ops.push("DW_OP_swap");
        break;
      case 0x17:
        ops.push("DW_OP_rot");
        break;
      case 0x19:
        ops.push("DW_OP_abs");
        break;
      case 0x1a:
        ops.push("DW_OP_and");
        break;
      case 0x1b:
        ops.push("DW_OP_div");
        break;
      case 0x1c:
        ops.push("DW_OP_minus");
        break;
      case 0x1d:
        ops.push("DW_OP_mod");
        break;
      case 0x1e:
        ops.push("DW_OP_mul");
        break;
      case 0x1f:
        ops.push("DW_OP_neg");
        break;
      case 0x20:
        ops.push("DW_OP_not");
        break;
      case 0x21:
        ops.push("DW_OP_or");
        break;
      case 0x22:
        ops.push("DW_OP_plus");
        break;
      case 0x23:
        ops.push(`DW_OP_plus_uconst: ${c.uleb128()}`);
        break;
      case 0x24:
        ops.push("DW_OP_shl");
        break;
      case 0x25:
        ops.push("DW_OP_shr");
        break;
      case 0x26:
        ops.push("DW_OP_shra");
        break;
      case 0x27:
        ops.push("DW_OP_xor");
        break;
      case 0x28:
        ops.push(`DW_OP_bra: ${c.i16()}`);
        break;
      case 0x29:
        ops.push("DW_OP_eq");
        break;
      case 0x2a:
        ops.push("DW_OP_ge");
        break;
      case 0x2b:
        ops.push("DW_OP_gt");
        break;
      case 0x2c:
        ops.push("DW_OP_le");
        break;
      case 0x2d:
        ops.push("DW_OP_lt");
        break;
      case 0x2e:
        ops.push("DW_OP_ne");
        break;
      case 0x2f:
        ops.push(`DW_OP_skip: ${c.i16()}`);
        break;
      case 0x90:
        ops.push(`DW_OP_regx: ${rn(c.uleb128())}`);
        break;
      case 0x91:
        ops.push(`DW_OP_fbreg: ${c.sleb128()}`);
        break;
      case 0x92: {
        const reg = c.uleb128();
        ops.push(`DW_OP_bregx: ${rn(reg)} ${c.sleb128()}`);
        break;
      }
      case 0x93:
        ops.push(`DW_OP_piece: ${c.uleb128()}`);
        break;
      case 0x94:
        ops.push(`DW_OP_deref_size: ${c.u8()}`);
        break;
      case 0x96:
        ops.push("DW_OP_nop");
        break;
      case 0x9c:
        ops.push("DW_OP_call_frame_cfa");
        break;
      case 0x9d: {
        const sz = c.uleb128();
        ops.push(`DW_OP_bit_piece: ${sz} offset ${c.uleb128()}`);
        break;
      }
      case 0x9f:
        ops.push("DW_OP_stack_value");
        break;
      default:
        ops.push(`DW_OP_unknown(0x${op.toString(16)})`);
        c.pos = end; // bail out
        break;
    }
  }
  return ops;
}

function fmtDwarfExpr(c: Cursor, len: number, machine: ELFMachine): string {
  return decodeDwarfExpr(c, len, machine).join("; ");
}

// ─── CFI instruction decoder ─────────────────────────────────────────────────

function decodeCFI(
  c: Cursor,
  end: number,
  codeAlign: number,
  dataAlign: number,
  machine: ELFMachine
): string[] {
  const instrs: string[] = [];
  const rn = (n: number) => `r${n} (${regName(n, machine)})`;

  while (c.pos < end) {
    const byte = c.u8();
    const high2 = byte & 0xc0;

    if (high2 === 0x40) {
      instrs.push(`DW_CFA_advance_loc: ${(byte & 0x3f) * codeAlign}`);
    } else if (high2 === 0x80) {
      instrs.push(`DW_CFA_offset: ${rn(byte & 0x3f)} at cfa${fmtOff(c.uleb128() * dataAlign)}`);
    } else if (high2 === 0xc0) {
      instrs.push(`DW_CFA_restore: ${rn(byte & 0x3f)}`);
    } else {
      switch (byte) {
        case 0x00:
          instrs.push("DW_CFA_nop");
          break;
        case 0x01:
          c.skip(c.is64 ? 8 : 4);
          instrs.push("DW_CFA_set_loc");
          break;
        case 0x02:
          instrs.push(`DW_CFA_advance_loc1: ${c.u8() * codeAlign}`);
          break;
        case 0x03:
          instrs.push(`DW_CFA_advance_loc2: ${c.u16() * codeAlign}`);
          break;
        case 0x04:
          instrs.push(`DW_CFA_advance_loc4: ${c.u32() * codeAlign}`);
          break;
        case 0x05: {
          const reg = c.uleb128();
          instrs.push(
            `DW_CFA_offset_extended: ${rn(reg)} at cfa${fmtOff(c.uleb128() * dataAlign)}`
          );
          break;
        }
        case 0x06:
          instrs.push(`DW_CFA_restore_extended: ${rn(c.uleb128())}`);
          break;
        case 0x07:
          instrs.push(`DW_CFA_undefined: ${rn(c.uleb128())}`);
          break;
        case 0x08:
          instrs.push(`DW_CFA_same_value: ${rn(c.uleb128())}`);
          break;
        case 0x09: {
          const reg1 = c.uleb128();
          instrs.push(`DW_CFA_register: ${rn(reg1)} in ${rn(c.uleb128())}`);
          break;
        }
        case 0x0a:
          instrs.push("DW_CFA_remember_state");
          break;
        case 0x0b:
          instrs.push("DW_CFA_restore_state");
          break;
        case 0x0c: {
          const reg = c.uleb128();
          instrs.push(`DW_CFA_def_cfa: ${rn(reg)} ofs ${c.uleb128()}`);
          break;
        }
        case 0x0d:
          instrs.push(`DW_CFA_def_cfa_register: ${rn(c.uleb128())}`);
          break;
        case 0x0e:
          instrs.push(`DW_CFA_def_cfa_offset: ${c.uleb128()}`);
          break;
        case 0x0f: {
          const len = c.uleb128();
          instrs.push(`DW_CFA_def_cfa_expression (${fmtDwarfExpr(c, len, machine)})`);
          break;
        }
        case 0x10: {
          const reg = c.uleb128();
          const len = c.uleb128();
          instrs.push(`DW_CFA_expression: ${rn(reg)} (${fmtDwarfExpr(c, len, machine)})`);
          break;
        }
        case 0x11: {
          const reg = c.uleb128();
          instrs.push(
            `DW_CFA_offset_extended_sf: ${rn(reg)} at cfa${fmtOff(c.sleb128() * dataAlign)}`
          );
          break;
        }
        case 0x12: {
          const reg = c.uleb128();
          instrs.push(`DW_CFA_def_cfa_sf: ${rn(reg)} ofs ${c.sleb128() * dataAlign}`);
          break;
        }
        case 0x13:
          instrs.push(`DW_CFA_def_cfa_offset_sf: ${c.sleb128() * dataAlign}`);
          break;
        case 0x14: {
          const reg = c.uleb128();
          instrs.push(`DW_CFA_val_offset: ${rn(reg)} is cfa${fmtOff(c.uleb128() * dataAlign)}`);
          break;
        }
        case 0x15: {
          const reg = c.uleb128();
          instrs.push(`DW_CFA_val_offset_sf: ${rn(reg)} is cfa${fmtOff(c.sleb128() * dataAlign)}`);
          break;
        }
        case 0x16: {
          const reg = c.uleb128();
          const len = c.uleb128();
          instrs.push(`DW_CFA_val_expression: ${rn(reg)} (${fmtDwarfExpr(c, len, machine)})`);
          break;
        }
        case 0x2e:
          instrs.push(`DW_CFA_GNU_args_size: ${c.uleb128()}`);
          break;
        case 0x2f: {
          const reg = c.uleb128();
          instrs.push(
            `DW_CFA_GNU_negative_offset_extended: ${rn(reg)} at cfa${fmtOff(-(c.uleb128() * dataAlign))}`
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
  return v >= 0 ? `+${v}` : `${v}`;
}

// ─── .eh_frame / .debug_frame parser ─────────────────────────────────────────

/**
 * Parse CIE/FDE records from an .eh_frame or .debug_frame section.
 *
 * Key differences between the two formats:
 *  - CIE sentinel: .eh_frame uses 0, .debug_frame uses 0xFFFFFFFF (or all-ones for 64-bit)
 *  - FDE CIE pointer: .eh_frame is a relative backward offset from the field,
 *    .debug_frame is an absolute offset from the section start
 *  - .debug_frame has no 'z' augmentation data (pointers are always absptr)
 */
function parseCfiSection(
  fc: Cursor,
  sectionFileOffset: number,
  sectionSize: number,
  sectionVaddr: bigint,
  machine: ELFMachine,
  isDebugFrame: boolean
): { cies: EhFrameCIE[]; fdes: EhFrameFDE[] } {
  const cies: EhFrameCIE[] = [];
  const fdes: EhFrameFDE[] = [];
  const cieMap = new Map<number, EhFrameCIE>();

  const c = fc.cursor(sectionFileOffset, sectionSize, isDebugFrame ? ".debug_frame" : ".eh_frame");

  while (c.remaining >= 4) {
    const recordStart = c.pos;
    let length = c.u32();

    if (length === 0) {
      break;
    } // terminator

    let extendedLength = false;
    if (length === 0xffffffff) {
      if (c.remaining < 8) {
        break;
      }
      length = Number(c.u64());
      extendedLength = true;
    }

    const contentStart = c.pos;
    const recordEnd = contentStart + length;
    if (recordEnd > c.length) {
      break;
    }

    const idSize = extendedLength ? 8 : 4;
    if (c.pos + idSize > recordEnd) {
      c.pos = recordEnd;
      continue;
    }
    const idField = extendedLength ? Number(c.u64()) : c.u32();

    const totalRecordSize = recordEnd - recordStart;
    const cieSentinel = isDebugFrame ? (extendedLength ? 0xffffffffffffffff : 0xffffffff) : 0;

    if (idField === cieSentinel) {
      const cie = parseCIE(c, recordEnd, recordStart, totalRecordSize, machine);
      cies.push(cie);
      cieMap.set(recordStart, cie);
    } else {
      const cieOff = isDebugFrame ? idField : contentStart - idField;
      const cie = cieMap.get(cieOff);
      const fde = parseFDE(
        c,
        recordEnd,
        recordStart,
        totalRecordSize,
        machine,
        cie ?? null,
        sectionVaddr,
        cieOff
      );
      fdes.push(fde);
    }

    c.pos = recordEnd;
  }

  return { cies, fdes };
}

function parseCIE(
  c: Cursor,
  end: number,
  recordStart: number,
  totalSize: number,
  machine: ELFMachine
): EhFrameCIE {
  const version = c.u8();
  const augmentation = c.cstring();
  const codeAlignFactor = c.uleb128();
  const dataAlignFactor = c.sleb128();
  const returnAddressReg = version === 1 ? c.u8() : c.uleb128();

  let fdeEncoding = DW_EH_PE_absptr;
  let lsdaEncoding = DW_EH_PE_omit;
  let personalityEncoding = DW_EH_PE_omit;
  let personalityRoutine = 0n;
  let isSignalFrame = false;

  if (augmentation.startsWith("z")) {
    const augDataLen = c.uleb128();
    const augEnd = c.pos + augDataLen;

    for (let i = 1; i < augmentation.length && c.pos < augEnd; i++) {
      const ch = augmentation[i];
      if (ch === "R") {
        fdeEncoding = c.u8();
      } else if (ch === "P") {
        personalityEncoding = c.u8();
        personalityRoutine = readEncodedValue(c, personalityEncoding, 0n, 0n);
      } else if (ch === "L") {
        lsdaEncoding = c.u8();
      } else if (ch === "S") {
        isSignalFrame = true;
      }
    }
    c.pos = augEnd;
  }

  const instructions = decodeCFI(c, end, codeAlignFactor, dataAlignFactor, machine);

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
  c: Cursor,
  end: number,
  recordStart: number,
  totalSize: number,
  machine: ELFMachine,
  cie: EhFrameCIE | null,
  sectionVaddr: bigint,
  cieOff: number
): EhFrameFDE {
  const fdeEncoding = cie?.fdeEncoding ?? DW_EH_PE_absptr;
  const codeAlign = cie?.codeAlignFactor ?? 1;
  const dataAlign = cie?.dataAlignFactor ?? 1;
  const lsdaEncoding = cie?.lsdaEncoding ?? DW_EH_PE_omit;

  const pcRelAddr = sectionVaddr + BigInt(c.pos);
  const pcBegin = readEncodedValue(c, fdeEncoding, pcRelAddr, 0n);

  // address_range uses same format bits but without application (always absolute)
  const pcRange = readEncodedValue(c, fdeEncoding & 0x0f, 0n, 0n);

  let lsda = 0n;
  if (cie?.augmentation.startsWith("z")) {
    const augDataLen = c.uleb128();
    const augEnd = c.pos + augDataLen;
    if (lsdaEncoding !== DW_EH_PE_omit && augDataLen > 0) {
      const lsdaPcAddr = sectionVaddr + BigInt(c.pos);
      lsda = readEncodedValue(c, lsdaEncoding, lsdaPcAddr, 0n);
    }
    c.pos = augEnd;
  }

  const instructions = decodeCFI(c, end, codeAlign, dataAlign, machine);

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
  fc: Cursor,
  sectionFileOffset: number,
  sectionSize: number,
  sectionVaddr: bigint
): EhFrameHdr | null {
  if (sectionSize < 4) {
    return null;
  }

  const c = fc.cursor(sectionFileOffset, sectionSize, ".eh_frame_hdr");

  const version = c.u8();
  if (version !== 1) {
    return null;
  }

  const ehFramePtrEnc = c.u8();
  const fdeCountEnc = c.u8();
  const tableEnc = c.u8();

  const ptrPcAddr = sectionVaddr + BigInt(c.pos);
  const ehFramePtr = readEncodedValue(c, ehFramePtrEnc, ptrPcAddr, sectionVaddr);

  let fdeCount = 0;
  if (fdeCountEnc !== DW_EH_PE_omit) {
    const countPcAddr = sectionVaddr + BigInt(c.pos);
    fdeCount = Number(readEncodedValue(c, fdeCountEnc, countPcAddr, sectionVaddr));
  }

  const table: EhFrameHdrEntry[] = [];
  const entrySize = encodedValueSize(tableEnc, c.is64);
  for (let i = 0; i < fdeCount && c.remaining >= entrySize * 2; i++) {
    const locPcAddr = sectionVaddr + BigInt(c.pos);
    const initialLocation = readEncodedValue(c, tableEnc, locPcAddr, sectionVaddr);
    const fdePcAddr = sectionVaddr + BigInt(c.pos);
    const fdeOffset = readEncodedValue(c, tableEnc, fdePcAddr, sectionVaddr);
    table.push({ initialLocation, fdeOffset });
  }

  return { version, ehFramePtrEnc, fdeCountEnc, tableEnc, ehFramePtr, fdeCount, table };
}

function estimateEhFrameSize(fileOffset: number, phs: ProgramHeader[], fileSize: number): number {
  for (const ph of phs) {
    if (ph.type !== PHType.Load) {
      continue;
    }
    const segEnd = ph.offset + ph.filesz;
    if (fileOffset >= ph.offset && fileOffset < segEnd) {
      return segEnd - fileOffset;
    }
  }
  return fileSize - fileOffset;
}

// ─── Public entry points ─────────────────────────────────────────────────────

export function parseEhFrame(elf: ELFFile, fc: Cursor): EhFrameData | null {
  const shs = elf.sectionHeaders;
  const phs = elf.programHeaders;
  const machine = elf.header.machine;
  const fileSize = fc.length;

  // Locate .eh_frame_hdr
  let hdrFileOffset: number | null = null;
  let hdrVaddr = 0n;
  let hdrSize = 0;

  const ehFrameHdrSh = shs.find((s) => s.name === ".eh_frame_hdr");
  if (ehFrameHdrSh && ehFrameHdrSh.size > 0) {
    hdrFileOffset = ehFrameHdrSh.offset;
    hdrVaddr = ehFrameHdrSh.addr;
    hdrSize = ehFrameHdrSh.size;
  } else {
    const ehFrameHdrPh = phs.find((p) => p.type === PHType.GnuEhFrame);
    if (ehFrameHdrPh && ehFrameHdrPh.filesz > 0) {
      hdrFileOffset = ehFrameHdrPh.offset;
      hdrVaddr = ehFrameHdrPh.vaddr;
      hdrSize = ehFrameHdrPh.filesz;
    }
  }

  // Locate .eh_frame
  let ehFrameFileOffset: number;
  let ehFrameVaddr: bigint;
  let ehFrameSize: number;

  const ehFrameSh = shs.find((s) => s.name === ".eh_frame");
  if (ehFrameSh && ehFrameSh.size > 0) {
    ehFrameFileOffset = ehFrameSh.offset;
    ehFrameVaddr = ehFrameSh.addr;
    ehFrameSize = ehFrameSh.size;
  } else if (hdrFileOffset !== null) {
    const hdr = parseEhFrameHdrSection(fc, hdrFileOffset, hdrSize, hdrVaddr);
    if (!hdr) {
      return null;
    }
    const fo = vaddrToFileOffset(hdr.ehFramePtr, phs);
    if (fo === null) {
      return null;
    }
    ehFrameFileOffset = fo;
    ehFrameVaddr = hdr.ehFramePtr;
    ehFrameSize = estimateEhFrameSize(fo, phs, fileSize);
  } else {
    return null;
  }

  const { cies, fdes } = parseCfiSection(
    fc,
    ehFrameFileOffset,
    ehFrameSize,
    ehFrameVaddr,
    machine,
    false
  );

  let hdr: EhFrameHdr | null = null;
  if (hdrFileOffset !== null) {
    hdr = parseEhFrameHdrSection(fc, hdrFileOffset, hdrSize, hdrVaddr);
  }

  return {
    cies,
    fdes,
    hdr,
    sectionFileOffset: ehFrameFileOffset,
    sectionVaddr: ehFrameVaddr,
    hdrSectionFileOffset: hdrFileOffset,
  };
}

export function parseDebugFrame(elf: ELFFile, fc: Cursor): EhFrameData | null {
  const shs = elf.sectionHeaders;
  const machine = elf.header.machine;

  const debugFrameSh = shs.find((s) => s.name === ".debug_frame");
  if (!debugFrameSh || debugFrameSh.size === 0) {
    return null;
  }

  const { cies, fdes } = parseCfiSection(
    fc,
    debugFrameSh.offset,
    debugFrameSh.size,
    debugFrameSh.addr,
    machine,
    true
  );

  return {
    cies,
    fdes,
    hdr: null,
    sectionFileOffset: debugFrameSh.offset,
    sectionVaddr: debugFrameSh.addr,
    hdrSectionFileOffset: null,
  };
}

export { ehPeEncName };
