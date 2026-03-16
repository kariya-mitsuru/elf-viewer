// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Core ELF parser.
// Parses an ELF binary from a Uint8Array using DataView for binary access.
// Supports ELF32/ELF64, LSB/MSB.
//
// BigInt convention
// -----------------
// Virtual/physical addresses (Elf_Addr) and flag/version Xword fields are
// stored as `bigint` because they may exceed Number.MAX_SAFE_INTEGER.
//
// File offsets (Elf_Off), file sizes, memory sizes, and alignment values are
// stored as `number`. For ELF64, if any such value exceeds
// Number.MAX_SAFE_INTEGER (2^53 − 1), ParseError is thrown – no real file
// would ever be that large.
//
// Fixed-width 32-bit-or-smaller fields (Elf_Word, Elf_Half, etc.) are
// always `number`.

import {
  ELFClass,
  ELFData,
  ELFType,
  ELFOSABI,
  ELFMachine,
  SHType,
  PHType,
  DynTag,
  STBind,
  STType,
  STVisibility,
  SHN_UNDEF,
  SHN_ABS,
  SHN_COMMON,
  type ELFFile,
  type ELFHeader,
  type ProgramHeader,
  type SectionHeader,
  type Symbol,
  type RelocationEntry,
  type RelocationSection,
  type DynamicEntry,
  type Note,
  type VersionInfo,
  type VersionNeed,
  type VersionNeedAux,
  type VersionDef,
  type HashTable,
  type GnuHashTable,
} from "./types.ts";
import { Reader } from "./reader.ts";
import { parseEhFrame, parseDebugFrame } from "./ehframe.ts";

const decoder = new TextDecoder();

type StrTabFn = (idx: number) => string;
const emptyStrTab: StrTabFn = () => "";

function strTab(dv: DataView | null): StrTabFn {
  if (!dv) return emptyStrTab;
  // ELF spec: empty string table only permits idx=0
  if (dv.byteLength === 0) {
    return (idx: number) => {
      if (idx !== 0) throw new ParseError(`String table index ${idx} in empty string table`);
      return "";
    };
  }
  // ELF spec: first and last bytes of a non-empty string table must be null
  if (dv.getUint8(0) !== 0) throw new ParseError("String table does not begin with a null byte");
  if (dv.getUint8(dv.byteLength - 1) !== 0)
    throw new ParseError("String table does not end with a null byte");
  return (idx: number) => {
    if (idx < 0 || idx >= dv.byteLength)
      throw new ParseError(`String table index ${idx} out of range (size ${dv.byteLength})`);
    let end = idx;
    while (dv.getUint8(end) !== 0) end++;
    return decoder.decode(new Uint8Array(dv.buffer, dv.byteOffset + idx, end - idx));
  };
}

// ─── ELF structure sizes ──────────────────────────────────────────────────────
// Byte sizes of key ELF structures. Values correspond to sizeof(Elf{32,64}_*)
// defined in elf.h. Centralised here to avoid scattering the same ternary
// expression across the file.

/** sizeof(Elf32_Sym) = 16, sizeof(Elf64_Sym) = 24 */
function symEntSize(is64: boolean): number {
  return is64 ? 24 : 16;
}

/** sizeof(Elf{32,64}_Rel/Rela): Elf64_Rel=16, Elf64_Rela=24, Elf32_Rel=8, Elf32_Rela=12 */
function relEntSize(is64: boolean, isRela: boolean): number {
  return is64 ? (isRela ? 24 : 16) : isRela ? 12 : 8;
}

/** sizeof(Elf32_Dyn) = 8, sizeof(Elf64_Dyn) = 16 */
function dynEntSize(is64: boolean): number {
  return is64 ? 16 : 8;
}

/** Native pointer/address size in bytes: 4 (ELF32) or 8 (ELF64) */
function addrSize(is64: boolean): number {
  return is64 ? 8 : 4;
}

// ─── ELF header ──────────────────────────────────────────────────────────────

const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46]; // \x7fELF

/** Thrown when the input is not a valid or supported ELF binary. */
export class ParseError extends Error {}

/**
 * Safely converts a bigint ELF64 field to number.
 * Throws ParseError if the value exceeds Number.MAX_SAFE_INTEGER, which would
 * indicate a file/offset too large to be practically loaded.
 */
function safeNum(v: bigint, field: string): number {
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ParseError(`${field} value 0x${v.toString(16)} exceeds safe integer range`);
  }
  return Number(v);
}

/**
 * Parses the ELF identification block and file header (e_ident … e_shstrndx).
 * Validates magic number, ELF class (32/64), and data encoding (LSB/MSB).
 * @throws {ParseError} if the file is too small, magic is wrong, or class/encoding is unsupported
 */
function parseHeader(raw: Uint8Array): [ELFHeader, Reader] {
  if (raw.length < 64) throw new ParseError("File too small to be an ELF");

  for (let i = 0; i < 4; i++) {
    if (raw[i] !== ELF_MAGIC[i]) throw new ParseError("Not an ELF file (invalid magic)");
  }

  const cls = raw[4] as ELFClass;
  const data = raw[5] as ELFData;

  if (cls !== ELFClass.ELF32 && cls !== ELFClass.ELF64) {
    throw new ParseError(`Unsupported ELF class: ${cls}`);
  }
  if (data !== ELFData.LSB && data !== ELFData.MSB) {
    throw new ParseError(`Unsupported ELF data encoding: ${data}`);
  }

  const le = data === ELFData.LSB;
  const is64 = cls === ELFClass.ELF64;
  const r = new Reader(new DataView(raw.buffer, raw.byteOffset, raw.byteLength), le, is64);

  return [
    {
      class: cls,
      data: data,
      version: r.u8(6),
      osabi: r.u8(7) as ELFOSABI,
      abiVersion: r.u8(8),
      type: r.half(16) as ELFType,
      machine: r.half(18) as ELFMachine,
      entryPoint: r.addr(24),
      phOffset: is64 ? safeNum(r.u64(32), "e_phoff") : r.u32(28),
      shOffset: is64 ? safeNum(r.u64(40), "e_shoff") : r.u32(32),
      flags: r.word(is64 ? 48 : 36),
      ehSize: r.half(is64 ? 52 : 40),
      phEntSize: r.half(is64 ? 54 : 42),
      phNum: r.half(is64 ? 56 : 44),
      shEntSize: r.half(is64 ? 58 : 46),
      shNum: r.half(is64 ? 60 : 48),
      shStrNdx: r.half(is64 ? 62 : 50),
    },
    r,
  ];
}

// ─── Program headers ──────────────────────────────────────────────────────────

/**
 * Parses the program header table (PT_* segments).
 * Returns an empty array when phNum is 0 or phOffset is 0 (no PT table).
 * Note: ELF32 and ELF64 have different field layouts (flags position differs).
 */
function parseProgramHeaders(r: Reader, h: ELFHeader): ProgramHeader[] {
  if (h.phNum === 0 || h.phOffset === 0) return [];
  const expectedPhEntSize = r.is64 ? 56 : 32;
  if (h.phEntSize !== expectedPhEntSize)
    throw new ParseError(`Invalid e_phentsize: expected ${expectedPhEntSize}, got ${h.phEntSize}`);
  const phs: ProgramHeader[] = [];
  const base = h.phOffset;

  if (base + h.phNum * h.phEntSize > r.view.byteLength)
    throw new ParseError("Program header table extends beyond end of file");

  for (let i = 0; i < h.phNum; i++) {
    const off = base + i * h.phEntSize;
    if (r.is64) {
      phs.push({
        index: i,
        type: r.word(off) as PHType,
        flags: r.word(off + 4),
        offset: safeNum(r.u64(off + 8), "p_offset"),
        vaddr: r.u64(off + 16),
        paddr: r.u64(off + 24),
        filesz: safeNum(r.u64(off + 32), "p_filesz"),
        memsz: safeNum(r.u64(off + 40), "p_memsz"),
        align: safeNum(r.u64(off + 48), "p_align"),
      });
    } else {
      phs.push({
        index: i,
        type: r.word(off) as PHType,
        offset: r.u32(off + 4),
        vaddr: BigInt(r.u32(off + 8)),
        paddr: BigInt(r.u32(off + 12)),
        filesz: r.u32(off + 16),
        memsz: r.u32(off + 20),
        flags: r.word(off + 24),
        align: r.u32(off + 28),
      });
    }
  }
  for (const ph of phs) {
    if (ph.offset + ph.filesz > r.view.byteLength)
      throw new ParseError(`Program header [${ph.index}] extends beyond end of file`);
  }
  return phs;
}

// ─── Section headers ──────────────────────────────────────────────────────────

// nameOff holds the sh_name field (byte offset into .shstrtab), resolved in the second pass
type RawSectionEntry = Omit<SectionHeader, "name"> & { nameOff: number };

/**
 * Parses the section header table and resolves section names from .shstrtab.
 * Two-pass: first reads raw entries, then resolves names using the string table
 * identified by `h.shStrNdx`. If .shstrtab is absent, names fall back to
 * `[<nameOff>]`.
 */
function parseSectionHeaders(r: Reader, h: ELFHeader): SectionHeader[] {
  if (h.shNum === 0 || h.shOffset === 0) return [];
  const expectedShEntSize = r.is64 ? 64 : 40;
  if (h.shEntSize !== expectedShEntSize)
    throw new ParseError(`Invalid e_shentsize: expected ${expectedShEntSize}, got ${h.shEntSize}`);

  const base = h.shOffset;

  // First pass: read raw entries without names
  const entries: RawSectionEntry[] = [];
  if (base + h.shNum * h.shEntSize > r.view.byteLength)
    throw new ParseError("Section header table extends beyond end of file");

  for (let i = 0; i < h.shNum; i++) {
    const off = base + i * h.shEntSize;
    if (r.is64) {
      entries.push({
        index: i,
        nameOff: r.word(off),
        type: r.word(off + 4) as SHType,
        flags: r.u64(off + 8),
        addr: r.u64(off + 16),
        offset: safeNum(r.u64(off + 24), "sh_offset"),
        size: safeNum(r.u64(off + 32), "sh_size"),
        link: r.word(off + 40),
        info: r.word(off + 44),
        addralign: safeNum(r.u64(off + 48), "sh_addralign"),
        entsize: safeNum(r.u64(off + 56), "sh_entsize"),
      });
    } else {
      entries.push({
        index: i,
        nameOff: r.word(off),
        type: r.word(off + 4) as SHType,
        flags: BigInt(r.u32(off + 8)),
        addr: BigInt(r.u32(off + 12)),
        offset: r.u32(off + 16),
        size: r.u32(off + 20),
        link: r.word(off + 24),
        info: r.word(off + 28),
        addralign: r.u32(off + 32),
        entsize: r.u32(off + 36),
      });
    }
  }

  // Validate section file regions: no section extends beyond EOF, no two sections overlap
  const fileRegions = entries
    .filter((e) => e.type !== SHType.NoBits && e.size > 0)
    .sort((a, b) => a.offset - b.offset);
  for (const e of fileRegions) {
    if (e.offset + e.size > r.view.byteLength)
      throw new ParseError(`Section [${e.index}] extends beyond end of file`);
  }
  for (let i = 0; i + 1 < fileRegions.length; i++) {
    const a = fileRegions[i],
      b = fileRegions[i + 1];
    if (a.offset + a.size > b.offset)
      throw new ParseError(`Section [${a.index}] and section [${b.index}] overlap in file`);
  }

  // Resolve section name reader from e_shstrndx
  const strNdx = h.shStrNdx;
  let readName: StrTabFn;
  if (strNdx === SHN_UNDEF) {
    readName = (nameOff) => `[${nameOff}]`;
  } else if (strNdx < entries.length) {
    const { offset: off, size: sz } = entries[strNdx];
    readName = strTab(r.subView(off, sz));
  } else {
    throw new ParseError(`e_shstrndx ${strNdx} out of range (shNum is ${entries.length})`);
  }

  return entries.map((e) => ({
    index: e.index,
    name: readName(e.nameOff),
    type: e.type,
    flags: e.flags,
    addr: e.addr,
    offset: e.offset,
    size: e.size,
    link: e.link,
    info: e.info,
    addralign: e.addralign,
    entsize: e.entsize,
  }));
}

/**
 * Returns a Reader over a section's file data, or null if the section has
 * no data (size === 0). Callers are responsible for skipping SHT_NOBITS
 * sections, which have sh_size > 0 (memory size) but no file bytes.
 */
function sectionData(sh: SectionHeader, r: Reader): Reader | null {
  if (sh.size === 0) return null;
  return r.slice(sh.offset, sh.size);
}

/**
 * Maps a virtual address to a file offset by walking PT_LOAD segments.
 * Used as a fallback for stripped binaries that lack section headers.
 * Returns null if no PT_LOAD segment covers the address.
 */
function vaddrToFileOffset(
  va: bigint | null,
  phs: ProgramHeader[],
  context: string
): number | null {
  if (va === null) return null;
  for (const ph of phs) {
    if (ph.type !== PHType.Load) continue;
    if (va >= ph.vaddr && va < ph.vaddr + BigInt(ph.filesz)) {
      return ph.offset + Number(va - ph.vaddr);
    }
  }
  throw new ParseError(`${context}: vaddr ${va} not found in any PT_LOAD segment`);
}

// ─── Symbol table ─────────────────────────────────────────────────────────────

function parseSymbolEntries(
  r: Reader,
  count: number,
  entSize: number,
  strtab: StrTabFn,
  shs: SectionHeader[]
): Symbol[] {
  const syms: Symbol[] = [];

  for (let i = 0; i < count; i++) {
    const off = i * entSize;
    let name = "",
      value = 0n,
      size = 0,
      info = 0,
      other = 0,
      shndx = 0;

    if (r.is64) {
      const nameIdx = r.u32(off);
      info = r.u8(off + 4);
      other = r.u8(off + 5);
      shndx = r.u16(off + 6);
      value = r.u64(off + 8);
      size = safeNum(r.u64(off + 16), "st_size");
      name = strtab(nameIdx);
    } else {
      const nameIdx = r.u32(off);
      value = BigInt(r.u32(off + 4));
      size = r.u32(off + 8);
      info = r.u8(off + 12);
      other = r.u8(off + 13);
      shndx = r.u16(off + 14);
      name = strtab(nameIdx);
    }

    const bind: STBind = (info >> 4) as STBind;
    const type: STType = (info & 0xf) as STType;
    const vis: STVisibility = (other & 0x3) as STVisibility;

    let sectionName: string | null = null;
    if (shndx === SHN_UNDEF || shndx === SHN_ABS || shndx === SHN_COMMON) {
      // null — view handles these via shndx
    } else if (shndx < shs.length) {
      sectionName = shs[shndx].name;
    } else if (shs.length === 0) {
      sectionName = `[${shndx}]`;
    } else {
      throw new ParseError(`Symbol shndx ${shndx} out of range (shNum is ${shs.length})`);
    }

    syms.push({ index: i, name, value, size, bind, type, visibility: vis, shndx, sectionName });
  }
  return syms;
}

/**
 * Parses a symbol table section (SHT_SYMTAB or SHT_DYNSYM).
 * Resolves symbol names from the linked string table (sh_link).
 * Returns empty array if the target section doesn't exist or has no data.
 */
function parseSymbols(
  shs: SectionHeader[],
  r: Reader,
  type: SHType.SymTab | SHType.DynSym
): Symbol[] {
  const sh = shs.find((s) => s.type === type);
  if (!sh) return [];
  const data = sectionData(sh, r);
  if (!data) return [];
  if (sh.link >= shs.length)
    throw new ParseError(`Symbol table sh_link ${sh.link} out of range (shNum is ${shs.length})`);
  const strSh = shs[sh.link];
  if (strSh.type !== SHType.StrTab)
    throw new ParseError(`Symbol table sh_link [${sh.link}] is not SHT_STRTAB (got ${strSh.type})`);
  const strtabData = strTab(sectionData(strSh, r)?.view ?? null);
  const entSize = symEntSize(r.is64);
  if (sh.entsize !== entSize)
    throw new ParseError(
      `Symbol table sh_entsize ${sh.entsize} does not match expected ${entSize}`
    );
  if (data.view.byteLength % entSize !== 0)
    throw new ParseError(
      `Symbol table size ${data.view.byteLength} is not a multiple of sh_entsize ${entSize}`
    );
  const count = data.view.byteLength / entSize;
  return parseSymbolEntries(data, count, entSize, strtabData, shs);
}

// ─── Relocations ─────────────────────────────────────────────────────────────

function parseRelTable(
  r: Reader,
  count: number,
  entSize: number,
  isRela: boolean,
  syms: Symbol[]
): RelocationEntry[] {
  const entries: RelocationEntry[] = [];

  for (let i = 0; i < count; i++) {
    const off = i * entSize;
    let offset: bigint,
      symIdx: number,
      type: number,
      addend: bigint | null = null;

    if (r.is64) {
      offset = r.u64(off);
      const info = r.u64(off + 8);
      if (isRela) addend = r.i64(off + 16);
      // ELF64: sym=info[63:32], type=info[31:0]
      symIdx = Number(info >> 32n);
      type = Number(info & 0xffffffffn);
    } else {
      offset = BigInt(r.u32(off));
      const info = r.u32(off + 4);
      if (isRela) addend = BigInt(r.i32(off + 8));
      // ELF32: sym=info[31:8], type=info[7:0]
      symIdx = info >>> 8;
      type = info & 0xff;
    }
    const sym = symIdx < syms.length ? syms[symIdx] : null;

    entries.push({
      offset,
      symIndex: symIdx,
      symName: sym?.name ?? "",
      symValue: sym?.value ?? 0n,
      type,
      addend,
    });
  }
  return entries;
}

function parseRelrTable(r: Reader, count: number, entSize: number): RelocationEntry[] {
  const wordBits = entSize * 8;
  let offset = 0n;
  const entries: RelocationEntry[] = [];

  for (let i = 0; i < count; i++) {
    const w = r.is64 ? r.u64(i * entSize) : BigInt(r.u32(i * entSize));

    if ((w & 1n) === 0n) {
      offset = w;
      entries.push({ offset, symIndex: 0, symName: "", symValue: 0n, type: 8, addend: null });
    } else {
      for (let bit = 1; bit < wordBits; bit++) {
        offset += BigInt(entSize);
        if ((w >> BigInt(bit)) & 1n) {
          entries.push({ offset, symIndex: 0, symName: "", symValue: 0n, type: 8, addend: null });
        }
      }
    }
  }
  return entries;
}

/**
 * Parses all relocation sections (SHT_REL, SHT_RELA, SHT_RELR).
 * For each section, whether to look up symbols in .dynsym or .symtab is
 * determined by `sh_link` – if it points to an SHT_DYNSYM section, dynSyms
 * is used (and `usesDynSym` is set true on each entry, enabling version-info
 * lookup).
 */
function parseRelocations(
  shs: SectionHeader[],
  r: Reader,
  dynSyms: Symbol[],
  allSyms: Symbol[]
): RelocationSection[] {
  const sections: RelocationSection[] = [];

  for (const sh of shs) {
    if (sh.type !== SHType.Rela && sh.type !== SHType.Rel && sh.type !== SHType.Relr) continue;
    const data = sectionData(sh, r);
    if (!data) continue;

    if (sh.type === SHType.Relr) {
      const wordSize = addrSize(r.is64);
      if (sh.entsize !== wordSize)
        throw new ParseError(
          `${sh.name}: sh_entsize ${sh.entsize} does not match expected ${wordSize}`
        );
      if (data.view.byteLength % wordSize !== 0)
        throw new ParseError(
          `${sh.name}: size ${data.view.byteLength} is not a multiple of sh_entsize ${wordSize}`
        );
      const count = data.view.byteLength / wordSize;
      sections.push({
        name: sh.name,
        usesDynSym: false,
        entries: parseRelrTable(data, count, wordSize),
        fileOffset: sh.offset,
        byteSize: sh.size,
      });
    } else {
      const isRela = sh.type === SHType.Rela;
      const entSize = relEntSize(r.is64, isRela);
      if (sh.entsize !== entSize)
        throw new ParseError(
          `${sh.name}: sh_entsize ${sh.entsize} does not match expected ${entSize}`
        );
      if (data.view.byteLength % entSize !== 0)
        throw new ParseError(
          `${sh.name}: size ${data.view.byteLength} is not a multiple of sh_entsize ${entSize}`
        );
      const count = data.view.byteLength / entSize;
      const usesDynSym = sh.link < shs.length && shs[sh.link].type === SHType.DynSym;
      const syms = usesDynSym ? dynSyms : allSyms;
      sections.push({
        name: sh.name,
        usesDynSym,
        entries: parseRelTable(data, count, entSize, isRela, syms),
        fileOffset: sh.offset,
        byteSize: sh.size,
      });
    }
  }
  return sections;
}

// ─── Dynamic section ──────────────────────────────────────────────────────────

/**
 * Parses the dynamic section via PT_DYNAMIC.
 * Resolves string values (DT_NEEDED, DT_SONAME, etc.) from DT_STRTAB,
 * mapping the virtual address to a file offset via PT_LOAD.
 */
function parseDynamic(
  r: Reader,
  phs: ProgramHeader[]
): { entries: DynamicEntry[]; strtab: StrTabFn } {
  const dynPh = phs.find((p) => p.type === PHType.Dynamic);
  if (!dynPh) return { entries: [], strtab: emptyStrTab };
  const { offset: off, filesz: sz } = dynPh;
  if (off + sz > r.view.byteLength)
    throw new ParseError(`PT_DYNAMIC [${off}..+${sz}] exceeds file size (${r.view.byteLength})`);
  const entSize = dynEntSize(r.is64);
  if (sz % entSize !== 0)
    throw new ParseError(`PT_DYNAMIC size ${sz} is not a multiple of entsize ${entSize}`);
  const data = r.slice(off, sz);

  // First pass: collect entries, find DT_STRTAB address
  const entries: DynamicEntry[] = [];
  let strtabOff: number | null = null;
  let strtabSz: bigint | null = null;

  for (let off = 0; off < data.view.byteLength; off += entSize) {
    let tag: DynTag, value: bigint;
    if (r.is64) {
      tag = safeNum(data.i64(off), "DynTag") as DynTag;
      value = data.u64(off + 8);
    } else {
      tag = data.i32(off) as DynTag;
      value = BigInt(data.u32(off + 4));
    }
    entries.push({ tag, value, name: null });
    if (tag === DynTag.Null) break;
    if (tag === DynTag.StrTab) strtabOff = vaddrToFileOffset(value, phs, "DT_STRTAB");
    if (tag === DynTag.StrSz) strtabSz = value;
  }

  // Resolve string table via PT_LOAD
  if (strtabOff === null) throw new ParseError("DT_STRTAB is missing from dynamic section");
  if (strtabSz === null) throw new ParseError("DT_STRSZ is missing from dynamic section");
  if (BigInt(strtabOff) + strtabSz > BigInt(r.view.byteLength))
    throw new ParseError(
      `DT_STRTAB [${strtabOff}..+${strtabSz}] exceeds file size (${r.view.byteLength})`
    );
  const strtab = strTab(r.subView(strtabOff, Number(strtabSz)));

  // String-valued tags
  const strTags = new Set<number>([DynTag.Needed, DynTag.SoName, DynTag.RPath, DynTag.RunPath]);

  if (strtab !== emptyStrTab) {
    for (const entry of entries) {
      if (strTags.has(entry.tag)) entry.name = strtab(safeNum(entry.value, "DT strtab offset"));
    }
  }

  return { entries, strtab };
}

// ─── Dynamic symbol / reloc fallback (no section headers) ────────────────────

function parseDynSymbolsFromDynamic(
  get: (tag: DynTag) => bigint | null,
  phs: ProgramHeader[],
  r: Reader,
  count: number,
  strtab: StrTabFn
): Symbol[] {
  if (count === 0) return [];

  const symtabOff = vaddrToFileOffset(get(DynTag.SymTab), phs, "DT_SYMTAB");
  if (symtabOff === null) return [];

  // Parse symbol entries
  const entSize = symEntSize(r.is64);
  const totalSize = count * entSize;
  if (symtabOff + totalSize > r.view.byteLength)
    throw new ParseError(
      `Dynamic symbol table [${symtabOff}..+${totalSize}] exceeds file size (${r.view.byteLength})`
    );

  return parseSymbolEntries(r.slice(symtabOff, totalSize), count, entSize, strtab, []);
}

function parseRelocationsFromDynamic(
  get: (tag: DynTag) => bigint | null,
  dynSyms: Symbol[],
  phs: ProgramHeader[],
  r: Reader
): RelocationSection[] {
  const sections: RelocationSection[] = [];

  // Returns { data, count } after validating tags, entSz, and file bounds.
  // Returns null if all three tags are absent (section not present).
  function resolveSection(
    va: bigint | null,
    sz: bigint | null,
    entSz: bigint | null,
    expectedEntSz: number,
    sectionName: string
  ): { data: Reader; count: number; fileOff: number; byteSize: number } | null {
    if (va === null && sz === null && entSz === null) return null;
    if (va === null || sz === null || entSz === null)
      throw new ParseError(
        `${sectionName}: incomplete dynamic tags (va=${va}, sz=${sz}, entSz=${entSz})`
      );
    if (entSz !== BigInt(expectedEntSz))
      throw new ParseError(
        `${sectionName}: entsize ${entSz} does not match expected ${expectedEntSz}`
      );
    const fileOff = vaddrToFileOffset(va, phs, sectionName)!;
    if (BigInt(fileOff) + sz > BigInt(r.view.byteLength))
      throw new ParseError(
        `${sectionName}: [${fileOff}..+${sz}] exceeds file size (${r.view.byteLength})`
      );
    const byteSize = Number(sz);
    return { data: r.slice(fileOff, byteSize), count: byteSize / expectedEntSz, fileOff, byteSize };
  }

  function parseTable(
    va: bigint | null,
    sz: bigint | null,
    entSz: bigint | null,
    isRela: boolean,
    sectionName: string
  ): void {
    const entSize = relEntSize(r.is64, isRela);
    const resolved = resolveSection(va, sz, entSz, entSize, sectionName);
    if (resolved === null) return;
    const { data, count, fileOff, byteSize } = resolved;
    sections.push({
      name: sectionName,
      usesDynSym: true,
      entries: parseRelTable(data, count, entSize, isRela, dynSyms),
      fileOffset: fileOff,
      byteSize,
    });
  }

  const relaEnt = get(DynTag.RelaEnt);
  const relEnt = get(DynTag.RelEnt);

  // DT_RELA / DT_RELASZ / DT_RELAENT
  parseTable(get(DynTag.Rela), get(DynTag.RelaSz), relaEnt, true, ".rela.dyn");
  // DT_REL / DT_RELSZ / DT_RELENT
  parseTable(get(DynTag.Rel), get(DynTag.RelSz), relEnt, false, ".rel.dyn");

  // DT_JMPREL / DT_PLTRELSZ / DT_PLTREL
  const isRelaForPlt = get(DynTag.PltRel) === BigInt(DynTag.Rela);
  parseTable(
    get(DynTag.JmpRel),
    get(DynTag.PltRelSz),
    isRelaForPlt ? relaEnt : relEnt,
    isRelaForPlt,
    ".rela.plt"
  );

  // DT_RELR / DT_RELRSZ / DT_RELRENT
  const wordSize = addrSize(r.is64);
  const resolved = resolveSection(
    get(DynTag.Relr),
    get(DynTag.RelrSz),
    get(DynTag.RelrEnt),
    wordSize,
    ".relr.dyn"
  );
  if (resolved !== null) {
    const { data, count, fileOff, byteSize } = resolved;
    sections.push({
      name: ".relr.dyn",
      usesDynSym: false,
      entries: parseRelrTable(data, count, wordSize),
      fileOffset: fileOff,
      byteSize,
    });
  }

  return sections;
}

// ─── Notes ───────────────────────────────────────────────────────────────────

function align4(n: number): number {
  return (n + 3) & ~3;
}

/**
 * Parses ELF note entries from SHT_NOTE sections.
 * Falls back to PT_NOTE segments when there are no section headers
 * (e.g. core dumps or fully stripped executables).
 */
function parseNotes(shs: SectionHeader[], r: Reader, phs: ProgramHeader[]): Note[] {
  const notes: Note[] = [];

  function parseNoteData(nr: Reader, sectionName: string): void {
    let off = 0;
    while (off + 12 <= nr.view.byteLength) {
      const namesz = nr.u32(off);
      const descsz = nr.u32(off + 4);
      const type = nr.u32(off + 8);
      off += 12;
      if (off + namesz > nr.view.byteLength) break;
      const name =
        namesz > 0
          ? decoder.decode(new Uint8Array(nr.view.buffer, nr.view.byteOffset + off, namesz - 1)) // strip null
          : "";
      off += align4(namesz);
      if (off + descsz > nr.view.byteLength) break;
      const desc = nr.slice(off, descsz);
      off += align4(descsz);
      notes.push({ sectionName, name, type, desc });
    }
  }

  // From note sections
  for (const sh of shs) {
    if (sh.type !== SHType.Note) continue;
    const d = sectionData(sh, r);
    if (d) parseNoteData(d, sh.name);
  }

  // From PT_NOTE segments (for stripped binaries without section headers)
  if (shs.length === 0) {
    for (const ph of phs) {
      if (ph.type !== PHType.Note) continue;
      const off = ph.offset,
        sz = ph.filesz;
      if (off + sz <= r.view.byteLength) {
        parseNoteData(r.slice(off, sz), "PT_NOTE");
      }
    }
  }

  return notes;
}

// ─── Version info ─────────────────────────────────────────────────────────────

function parseVerSymTable(r: Reader, count: number): number[] {
  const versions: number[] = [];
  for (let i = 0; i < count; i++) {
    versions.push(r.u16(i * 2));
  }
  return versions;
}

function parseVerNeedTable(
  r: Reader,
  strtab: StrTabFn,
  count: number
): { needs: VersionNeed[]; byteSize: number } {
  const needs: VersionNeed[] = [];
  let off = 0;
  let maxOff = 0;
  for (let i = 0; i < count && off + 16 <= r.view.byteLength; i++) {
    maxOff = Math.max(maxOff, off + 16);
    const cnt = r.u16(off + 2);
    const fileIdx = r.u32(off + 4);
    const auxOff = r.u32(off + 8);
    const next = r.u32(off + 12);
    const file = strtab(fileIdx);
    const aux: VersionNeedAux[] = [];
    let aoff = off + auxOff;
    for (let j = 0; j < cnt && aoff + 16 <= r.view.byteLength; j++) {
      maxOff = Math.max(maxOff, aoff + 16);
      const hash = r.u32(aoff);
      const flags = r.u16(aoff + 4);
      const other = r.u16(aoff + 6);
      const nameIdx = r.u32(aoff + 8);
      const anext = r.u32(aoff + 12);
      aux.push({ hash, flags, other, name: strtab(nameIdx) });
      if (anext === 0) break;
      aoff += anext;
    }
    needs.push({ file, cnt, aux });
    if (next === 0) break;
    off += next;
  }
  return { needs, byteSize: maxOff };
}

function parseVerDefTable(
  r: Reader,
  strtab: StrTabFn,
  count: number
): { defs: VersionDef[]; byteSize: number } {
  const defs: VersionDef[] = [];
  let off = 0;
  let maxOff = 0;
  for (let i = 0; i < count && off + 20 <= r.view.byteLength; i++) {
    maxOff = Math.max(maxOff, off + 20);
    const flags = r.u16(off + 2);
    const ndx = r.u16(off + 4);
    const cnt = r.u16(off + 6);
    const hash = r.u32(off + 8);
    const auxOff = r.u32(off + 12);
    const next = r.u32(off + 16);
    const names: string[] = [];
    let aoff = off + auxOff;
    for (let j = 0; j < cnt && aoff + 8 <= r.view.byteLength; j++) {
      maxOff = Math.max(maxOff, aoff + 8);
      const nameIdx = r.u32(aoff);
      const anext = r.u32(aoff + 4);
      names.push(strtab(nameIdx));
      if (anext === 0) break;
      aoff += anext;
    }
    defs.push({ flags, ndx, hash, names });
    if (next === 0) break;
    off += next;
  }
  return { defs, byteSize: maxOff };
}

// ─── Version info ─────────────────────────────────────────────────────────────

/**
 * Parses GNU symbol versioning tables via dynamic entries:
 *   DT_VERSYM  – one uint16 per .dynsym entry
 *   DT_VERNEED – libraries and versions required
 *   DT_VERDEF  – versions defined by this DSO
 * Returns null when none of these tags are present.
 */
function parseVersionInfo(
  get: (tag: DynTag) => bigint | null,
  dynSymCount: number,
  phs: ProgramHeader[],
  r: Reader,
  strtab: StrTabFn
): VersionInfo | null {
  const verSymVA = get(DynTag.VerSym);
  const verNeedVA = get(DynTag.VerNeed);
  const verDefVA = get(DynTag.VerDef);

  if (verSymVA === null && verNeedVA === null && verDefVA === null) return null;

  // DT_VERSYM: one uint16 per dynamic symbol
  let symVersions: number[] = [];
  let verSymFileOffset: number | null = null;
  const verSymByteSize = dynSymCount * 2;
  if (dynSymCount > 0) {
    const fileOff = vaddrToFileOffset(verSymVA, phs, "DT_VERSYM");
    if (fileOff !== null && fileOff + verSymByteSize <= r.view.byteLength) {
      symVersions = parseVerSymTable(r.slice(fileOff, verSymByteSize), dynSymCount);
      verSymFileOffset = fileOff;
    }
  }

  // DT_VERNEED / DT_VERNEEDNUM: walk the verneed linked list
  let versionNeeds: VersionNeed[] = [];
  let verNeedByteSize = 0;
  let verNeedFileOffset: number | null = null;
  const verNeedNum = get(DynTag.VerNeedNum);
  const verNeedOff = vaddrToFileOffset(verNeedVA, phs, "DT_VERNEED");
  if (verNeedOff !== null) {
    const count = verNeedNum !== null ? Number(verNeedNum) : 0;
    const { needs, byteSize } = parseVerNeedTable(
      r.slice(verNeedOff, r.view.byteLength - verNeedOff),
      strtab,
      count
    );
    versionNeeds = needs;
    verNeedByteSize = byteSize;
    verNeedFileOffset = verNeedOff;
  }

  // DT_VERDEF / DT_VERDEFNUM: walk the verdef linked list
  let versionDefs: VersionDef[] = [];
  let verDefByteSize = 0;
  let verDefFileOffset: number | null = null;
  const verDefNum = get(DynTag.VerDefNum);
  const verDefOff = vaddrToFileOffset(verDefVA, phs, "DT_VERDEF");
  if (verDefOff !== null) {
    const count = verDefNum !== null ? Number(verDefNum) : 0;
    const { defs, byteSize } = parseVerDefTable(
      r.slice(verDefOff, r.view.byteLength - verDefOff),
      strtab,
      count
    );
    versionDefs = defs;
    verDefByteSize = byteSize;
    verDefFileOffset = verDefOff;
  }

  return {
    symVersions,
    versionNeeds,
    versionDefs,
    verNeedByteSize,
    verDefByteSize,
    verSymFileOffset,
    verSymByteSize,
    verNeedFileOffset,
    verDefFileOffset,
  };
}

// ─── SHT_HASH (SYSV hash table) ───────────────────────────────────────────────

/**
 * Parses all SHT_HASH sections and returns their bucket/chain data with
 * resolved symbol names from the linked symbol table (sh_link).
 *
 * Structure of a SYSV hash table:
 *   u32  nbucket
 *   u32  nchain        (== number of symbols in the linked symtab)
 *   u32  bucket[nbucket]   — head symbol index per hash bucket (0 = empty)
 *   u32  chain[nchain]     — chains[i] = next sym in chain for sym i (0 = end)
 */
function parseHashTables(
  get: (tag: DynTag) => bigint | null,
  phs: ProgramHeader[],
  r: Reader
): HashTable[] {
  const hashOff = vaddrToFileOffset(get(DynTag.Hash), phs, "DT_HASH");
  if (hashOff === null || hashOff + 8 > r.view.byteLength) return [];

  const nbucket = r.u32(hashOff);
  const nchain = r.u32(hashOff + 4);
  if (hashOff + 8 + (nbucket + nchain) * 4 > r.view.byteLength) return [];

  const buckets: number[] = [];
  for (let i = 0; i < nbucket; i++) buckets.push(r.u32(hashOff + 8 + i * 4));

  const chains: number[] = [];
  const chainsOff = hashOff + 8 + nbucket * 4;
  for (let i = 0; i < nchain; i++) chains.push(r.u32(chainsOff + i * 4));

  const byteSize = 8 + (nbucket + nchain) * 4;
  return [
    {
      sectionName: ".hash",
      shIndex: -1,
      nbucket,
      nchain,
      buckets,
      chains,
      symNames: [],
      fileOffset: hashOff,
      byteSize,
    },
  ];
}

// ─── GNU Hash table ───────────────────────────────────────────────────────────

function parseGnuHashTable(
  get: (tag: DynTag) => bigint | null,
  phs: ProgramHeader[],
  r: Reader
): GnuHashTable | null {
  const off = vaddrToFileOffset(get(DynTag.GnuHash), phs, "DT_GNU_HASH");
  if (off === null || off + 16 > r.view.byteLength) return null;

  const nbuckets = r.u32(off);
  const symoffset = r.u32(off + 4);
  const bloomSize = r.u32(off + 8);
  const bloomShift = r.u32(off + 12);
  const wordSize = addrSize(r.is64); // 4 or 8

  const bloomOff = off + 16;
  if (bloomOff + bloomSize * wordSize > r.view.byteLength) return null;

  const bloom: bigint[] = [];
  for (let i = 0; i < bloomSize; i++) {
    bloom.push(r.is64 ? r.u64(bloomOff + i * 8) : BigInt(r.u32(bloomOff + i * 4)));
  }

  const bucketsOff = bloomOff + bloomSize * wordSize;
  if (bucketsOff + nbuckets * 4 > r.view.byteLength) return null;

  const buckets: number[] = [];
  for (let i = 0; i < nbuckets; i++) {
    buckets.push(r.u32(bucketsOff + i * 4));
  }

  const chainOff = bucketsOff + nbuckets * 4;

  // Find the highest occupied bucket (start index of the last symbol chain).
  let maxBucket = 0;
  for (const b of buckets) {
    if (b > maxBucket) maxBucket = b;
  }

  // Follow the chain from maxBucket until the end-of-chain bit (bit 0) is set
  // to determine how many symbols are hashed.
  let numHashed = 0;
  if (maxBucket >= symoffset) {
    let idx = maxBucket;
    while (true) {
      const entOff = chainOff + (idx - symoffset) * 4;
      if (entOff + 4 > r.view.byteLength) break;
      const entry = r.u32(entOff);
      idx++;
      if (entry & 1) break;
    }
    numHashed = idx - symoffset;
  }

  const hashValues: number[] = [];
  for (let i = 0; i < numHashed; i++) {
    const entOff = chainOff + i * 4;
    if (entOff + 4 > r.view.byteLength) break;
    hashValues.push(r.u32(entOff));
  }

  const byteSize = 16 + bloomSize * wordSize + nbuckets * 4 + hashValues.length * 4;

  return {
    sectionName: ".gnu.hash",
    shIndex: -1,
    nbuckets,
    symoffset,
    bloomSize,
    bloomShift,
    bloom,
    bloomWordSize: wordSize,
    buckets,
    hashValues,
    symNames: [],
    fileOffset: off,
    byteSize,
  };
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/**
 * Main entry point. Parses a complete ELF binary and returns a structured
 * {@link ELFFile} with all headers, symbols, relocations, and metadata.
 *
 * Parsing strategy for stripped binaries (no section headers):
 *   - dynamic entries  → parsed from PT_DYNAMIC segment
 *   - dynamic symbols  → resolved via DT_SYMTAB + DT_HASH / DT_GNU_HASH
 *   - relocations      → resolved via DT_REL / DT_RELA / DT_JMPREL / DT_RELR
 *   - version info     → resolved via DT_VERSYM / DT_VERNEED / DT_VERDEF
 *
 * @throws {ParseError} if the magic number is wrong or the format is unsupported
 */
export function parseELF(bytes: Uint8Array): ELFFile {
  const [header, r] = parseHeader(bytes);

  const phs = parseProgramHeaders(r, header);
  const shs = parseSectionHeaders(r, header);

  // Parse dynamic section first — needed as fallback for symbols/relocations
  const { entries: dynamics, strtab: dynStrtab } = parseDynamic(r, phs);
  const getDyn = (tag: DynTag) => dynamics.find((e) => e.tag === tag)?.value ?? null;

  const symbols = parseSymbols(shs, r, SHType.SymTab);
  let dynSymbols = parseSymbols(shs, r, SHType.DynSym);

  // Step 1-2: Parse hash tables first (no dynSymbols needed)
  const hashTables = parseHashTables(getDyn, phs, r);
  const gnuHashTable = parseGnuHashTable(getDyn, phs, r);

  // Step 3: Fallback dynamic symbol parse — derive count from hash tables
  if (dynSymbols.length === 0 && dynamics.length > 0) {
    let count = 0;
    if (hashTables.length > 0) {
      count = hashTables[0].nchain;
    } else if (gnuHashTable !== null) {
      count = gnuHashTable.symoffset + gnuHashTable.hashValues.length;
    }
    dynSymbols = parseDynSymbolsFromDynamic(getDyn, phs, r, count, dynStrtab);
  }

  // Step 4: Populate symNames now that dynSymbols is ready
  for (const ht of hashTables) ht.symNames = dynSymbols.map((s) => s.name);
  if (gnuHashTable !== null) gnuHashTable.symNames = dynSymbols.map((s) => s.name);

  let relocs = parseRelocations(shs, r, dynSymbols, symbols);
  if (relocs.length === 0 && dynamics.length > 0) {
    relocs = parseRelocationsFromDynamic(getDyn, dynSymbols, phs, r);
  }
  const notes = parseNotes(shs, r, phs);
  const versionInfo = parseVersionInfo(getDyn, dynSymbols.length, phs, r, dynStrtab);

  // Resolve .dynsym file location: prefer section header, fall back to DT_SYMTAB
  let dynSymFileOffset: number | null = null;
  let dynSymByteSize = 0;
  const dynSymSh = shs.find((s) => s.type === SHType.DynSym);
  if (dynSymSh && dynSymSh.size > 0) {
    dynSymFileOffset = dynSymSh.offset;
    dynSymByteSize = dynSymSh.size;
  } else if (dynSymbols.length > 0) {
    const fo = vaddrToFileOffset(getDyn(DynTag.SymTab), phs, "DT_SYMTAB");
    if (fo !== null) {
      dynSymFileOffset = fo;
      dynSymByteSize = dynSymbols.length * symEntSize(r.is64);
    }
  }

  const elfFile: ELFFile = {
    header,
    programHeaders: phs,
    sectionHeaders: shs,
    symbols,
    dynSymbols,
    dynSymFileOffset,
    dynSymByteSize,
    relocations: relocs,
    dynamicEntries: dynamics,
    notes,
    versionInfo,
    hashTables,
    gnuHashTable,
    ehFrame: null,
    debugFrame: null,
    raw: bytes,
  };

  // Parse .eh_frame / .eh_frame_hdr and .debug_frame
  elfFile.ehFrame = parseEhFrame(elfFile, r);
  elfFile.debugFrame = parseDebugFrame(elfFile, r);

  return elfFile;
}
