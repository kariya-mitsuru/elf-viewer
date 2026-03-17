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
import { Reader, Cursor } from "./reader.ts"; // Reader kept for Note.desc interface
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
function parseHeader(raw: Uint8Array): [ELFHeader, Cursor] {
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
  const osabi = raw[7] as ELFOSABI;
  const abiVersion = raw[8];
  const c = new Cursor(new DataView(raw.buffer, raw.byteOffset, raw.byteLength), le, is64, 16);

  // File header (offset 16): type(2) machine(2) e_version(4) then pointer-sized fields
  const type = c.u16() as ELFType;
  const machine = c.u16() as ELFMachine;
  const version = c.u32();

  const entryPoint = c.addr();
  const phOffset = is64 ? safeNum(c.u64(), "e_phoff") : c.u32();
  const shOffset = is64 ? safeNum(c.u64(), "e_shoff") : c.u32();
  const flags = c.u32();
  const ehSize = c.u16();
  const phEntSize = c.u16();
  const phNum = c.u16();
  const shEntSize = c.u16();
  const shNum = c.u16();
  const shStrNdx = c.u16();

  // Reset cursor to start for downstream use as the file-level handle.
  c.pos = 0;

  return [
    {
      class: cls,
      data,
      version,
      osabi,
      abiVersion,
      type,
      machine,
      entryPoint,
      phOffset,
      shOffset,
      flags,
      ehSize,
      phEntSize,
      phNum,
      shEntSize,
      shNum,
      shStrNdx,
    },
    c,
  ];
}

// ─── Program headers ──────────────────────────────────────────────────────────

/**
 * Parses the program header table (PT_* segments).
 * Returns an empty array when phNum is 0 or phOffset is 0 (no PT table).
 * Note: ELF32 and ELF64 have different field layouts (flags position differs).
 */
function parseProgramHeaders(fc: Cursor, h: ELFHeader): ProgramHeader[] {
  if (h.phNum === 0 || h.phOffset === 0) return [];
  const expectedPhEntSize = fc.is64 ? 56 : 32;
  if (h.phEntSize !== expectedPhEntSize)
    throw new ParseError(`Invalid e_phentsize: expected ${expectedPhEntSize}, got ${h.phEntSize}`);
  const phs: ProgramHeader[] = [];
  const base = h.phOffset;

  if (base + h.phNum * h.phEntSize > fc.length)
    throw new ParseError("Program header table extends beyond end of file");

  const c = fc.cursor(base, h.phNum * h.phEntSize);
  for (let i = 0; i < h.phNum; i++) {
    if (c.is64) {
      phs.push({
        index: i,
        type: c.u32() as PHType,
        flags: c.u32(),
        offset: safeNum(c.u64(), "p_offset"),
        vaddr: c.u64(),
        paddr: c.u64(),
        filesz: safeNum(c.u64(), "p_filesz"),
        memsz: safeNum(c.u64(), "p_memsz"),
        align: safeNum(c.u64(), "p_align"),
      });
    } else {
      phs.push({
        index: i,
        type: c.u32() as PHType,
        offset: c.u32(),
        vaddr: BigInt(c.u32()),
        paddr: BigInt(c.u32()),
        filesz: c.u32(),
        memsz: c.u32(),
        flags: c.u32(),
        align: c.u32(),
      });
    }
  }
  for (const ph of phs) {
    if (ph.offset + ph.filesz > fc.length)
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
function parseSectionHeaders(fc: Cursor, h: ELFHeader): SectionHeader[] {
  if (h.shNum === 0 || h.shOffset === 0) return [];
  const expectedShEntSize = fc.is64 ? 64 : 40;
  if (h.shEntSize !== expectedShEntSize)
    throw new ParseError(`Invalid e_shentsize: expected ${expectedShEntSize}, got ${h.shEntSize}`);

  const base = h.shOffset;

  // First pass: read raw entries without names
  const entries: RawSectionEntry[] = [];
  if (base + h.shNum * h.shEntSize > fc.length)
    throw new ParseError("Section header table extends beyond end of file");

  const c = fc.cursor(base, h.shNum * h.shEntSize);
  for (let i = 0; i < h.shNum; i++) {
    if (c.is64) {
      entries.push({
        index: i,
        nameOff: c.u32(),
        type: c.u32() as SHType,
        flags: c.u64(),
        addr: c.u64(),
        offset: safeNum(c.u64(), "sh_offset"),
        size: safeNum(c.u64(), "sh_size"),
        link: c.u32(),
        info: c.u32(),
        addralign: safeNum(c.u64(), "sh_addralign"),
        entsize: safeNum(c.u64(), "sh_entsize"),
      });
    } else {
      entries.push({
        index: i,
        nameOff: c.u32(),
        type: c.u32() as SHType,
        flags: BigInt(c.u32()),
        addr: BigInt(c.u32()),
        offset: c.u32(),
        size: c.u32(),
        link: c.u32(),
        info: c.u32(),
        addralign: c.u32(),
        entsize: c.u32(),
      });
    }
  }

  // Validate section file regions: no section extends beyond EOF, no two sections overlap
  const fileRegions = entries
    .filter((e) => e.type !== SHType.NoBits && e.size > 0)
    .sort((a, b) => a.offset - b.offset);
  for (const e of fileRegions) {
    if (e.offset + e.size > fc.length)
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
    readName = strTab(fc.subView(off, sz));
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
 * Returns a Cursor over a section's file data, or null if the section has
 * no data (size === 0). Callers are responsible for skipping SHT_NOBITS
 * sections, which have sh_size > 0 (memory size) but no file bytes.
 */
function sectionData(sh: SectionHeader, fc: Cursor): Cursor | null {
  if (sh.size === 0) return null;
  return fc.cursor(sh.offset, sh.size);
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
  c: Cursor,
  count: number,
  strtab: StrTabFn,
  shs: SectionHeader[]
): Symbol[] {
  const syms: Symbol[] = [];

  for (let i = 0; i < count; i++) {
    let name = "",
      value = 0n,
      size = 0,
      info = 0,
      other = 0,
      shndx = 0;

    if (c.is64) {
      // Elf64_Sym: name(4), info(1), other(1), shndx(2), value(8), size(8)
      const nameIdx = c.u32();
      info = c.u8();
      other = c.u8();
      shndx = c.u16();
      value = c.u64();
      size = safeNum(c.u64(), "st_size");
      name = strtab(nameIdx);
    } else {
      // Elf32_Sym: name(4), value(4), size(4), info(1), other(1), shndx(2)
      const nameIdx = c.u32();
      value = BigInt(c.u32());
      size = c.u32();
      info = c.u8();
      other = c.u8();
      shndx = c.u16();
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
  fc: Cursor,
  type: SHType.SymTab | SHType.DynSym
): Symbol[] {
  const sh = shs.find((s) => s.type === type);
  if (!sh) return [];
  const data = sectionData(sh, fc);
  if (!data) return [];
  if (sh.link >= shs.length)
    throw new ParseError(`Symbol table sh_link ${sh.link} out of range (shNum is ${shs.length})`);
  const strSh = shs[sh.link];
  if (strSh.type !== SHType.StrTab)
    throw new ParseError(`Symbol table sh_link [${sh.link}] is not SHT_STRTAB (got ${strSh.type})`);
  const strtabData = strTab(sectionData(strSh, fc)?.view ?? null);
  const entSize = symEntSize(fc.is64);
  if (sh.entsize !== entSize)
    throw new ParseError(
      `Symbol table sh_entsize ${sh.entsize} does not match expected ${entSize}`
    );
  if (data.length % entSize !== 0)
    throw new ParseError(
      `Symbol table size ${data.length} is not a multiple of sh_entsize ${entSize}`
    );
  const count = data.length / entSize;
  return parseSymbolEntries(data, count, strtabData, shs);
}

// ─── Relocations ─────────────────────────────────────────────────────────────

function parseRelTable(
  c: Cursor,
  count: number,
  isRela: boolean,
  syms: Symbol[]
): RelocationEntry[] {
  const entries: RelocationEntry[] = [];

  for (let i = 0; i < count; i++) {
    let offset: bigint,
      symIdx: number,
      type: number,
      addend: bigint | null = null;

    if (c.is64) {
      offset = c.u64();
      const info = c.u64();
      if (isRela) addend = c.i64();
      symIdx = Number(info >> 32n);
      type = Number(info & 0xffffffffn);
    } else {
      offset = BigInt(c.u32());
      const info = c.u32();
      if (isRela) addend = BigInt(c.i32());
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

function parseRelrTable(c: Cursor, count: number, entSize: number): RelocationEntry[] {
  const wordBits = entSize * 8;
  let offset = 0n;
  const entries: RelocationEntry[] = [];

  for (let i = 0; i < count; i++) {
    const w = c.is64 ? c.u64() : BigInt(c.u32());

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
  fc: Cursor,
  dynSyms: Symbol[],
  allSyms: Symbol[]
): RelocationSection[] {
  const sections: RelocationSection[] = [];

  for (const sh of shs) {
    if (sh.type !== SHType.Rela && sh.type !== SHType.Rel && sh.type !== SHType.Relr) continue;
    const data = sectionData(sh, fc);
    if (!data) continue;

    if (sh.type === SHType.Relr) {
      const wordSize = addrSize(fc.is64);
      if (sh.entsize !== wordSize)
        throw new ParseError(
          `${sh.name}: sh_entsize ${sh.entsize} does not match expected ${wordSize}`
        );
      if (data.length % wordSize !== 0)
        throw new ParseError(
          `${sh.name}: size ${data.length} is not a multiple of sh_entsize ${wordSize}`
        );
      const count = data.length / wordSize;
      sections.push({
        name: sh.name,
        usesDynSym: false,
        entries: parseRelrTable(data.cursor(0), count, wordSize),
        fileOffset: sh.offset,
        byteSize: sh.size,
      });
    } else {
      const isRela = sh.type === SHType.Rela;
      const entSize = relEntSize(fc.is64, isRela);
      if (sh.entsize !== entSize)
        throw new ParseError(
          `${sh.name}: sh_entsize ${sh.entsize} does not match expected ${entSize}`
        );
      if (data.length % entSize !== 0)
        throw new ParseError(
          `${sh.name}: size ${data.length} is not a multiple of sh_entsize ${entSize}`
        );
      const count = data.length / entSize;
      const usesDynSym = sh.link < shs.length && shs[sh.link].type === SHType.DynSym;
      const syms = usesDynSym ? dynSyms : allSyms;
      sections.push({
        name: sh.name,
        usesDynSym,
        entries: parseRelTable(data.cursor(0), count, isRela, syms),
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
  fc: Cursor,
  phs: ProgramHeader[]
): { entries: DynamicEntry[]; strtab: StrTabFn } {
  const dynPh = phs.find((p) => p.type === PHType.Dynamic);
  if (!dynPh) return { entries: [], strtab: emptyStrTab };
  const { offset: off, filesz: sz } = dynPh;
  if (off + sz > fc.length)
    throw new ParseError(`PT_DYNAMIC [${off}..+${sz}] exceeds file size (${fc.length})`);
  const entSize = dynEntSize(fc.is64);
  if (sz % entSize !== 0)
    throw new ParseError(`PT_DYNAMIC size ${sz} is not a multiple of entsize ${entSize}`);
  // First pass: collect entries, find DT_STRTAB address
  const entries: DynamicEntry[] = [];
  let strtabOff: number | null = null;
  let strtabSz: bigint | null = null;

  const c = fc.cursor(off, sz);
  while (c.remaining >= entSize) {
    const tag = (c.is64 ? safeNum(c.i64(), "DynTag") : c.i32()) as DynTag;
    const value = c.is64 ? c.u64() : BigInt(c.u32());
    entries.push({ tag, value, name: null });
    if (tag === DynTag.Null) break;
    if (tag === DynTag.StrTab) strtabOff = vaddrToFileOffset(value, phs, "DT_STRTAB");
    if (tag === DynTag.StrSz) strtabSz = value;
  }

  // Resolve string table via PT_LOAD
  if (strtabOff === null) throw new ParseError("DT_STRTAB is missing from dynamic section");
  if (strtabSz === null) throw new ParseError("DT_STRSZ is missing from dynamic section");
  if (BigInt(strtabOff) + strtabSz > BigInt(fc.length))
    throw new ParseError(
      `DT_STRTAB [${strtabOff}..+${strtabSz}] exceeds file size (${fc.length})`
    );
  const strtab = strTab(fc.subView(strtabOff, Number(strtabSz)));

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
  fc: Cursor,
  count: number,
  strtab: StrTabFn
): Symbol[] {
  if (count === 0) return [];

  const symtabOff = vaddrToFileOffset(get(DynTag.SymTab), phs, "DT_SYMTAB");
  if (symtabOff === null) return [];

  const entSize = symEntSize(fc.is64);
  const totalSize = count * entSize;
  if (symtabOff + totalSize > fc.length)
    throw new ParseError(
      `Dynamic symbol table [${symtabOff}..+${totalSize}] exceeds file size (${fc.length})`
    );

  return parseSymbolEntries(fc.cursor(symtabOff, totalSize), count, strtab, []);
}

function parseRelocationsFromDynamic(
  get: (tag: DynTag) => bigint | null,
  dynSyms: Symbol[],
  phs: ProgramHeader[],
  fc: Cursor
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
  ): { data: Cursor; count: number; fileOff: number; byteSize: number } | null {
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
    if (BigInt(fileOff) + sz > BigInt(fc.length))
      throw new ParseError(
        `${sectionName}: [${fileOff}..+${sz}] exceeds file size (${fc.length})`
      );
    const byteSize = Number(sz);
    return { data: fc.cursor(fileOff, byteSize), count: byteSize / expectedEntSz, fileOff, byteSize };
  }

  function parseTable(
    va: bigint | null,
    sz: bigint | null,
    entSz: bigint | null,
    isRela: boolean,
    sectionName: string
  ): void {
    const entSize = relEntSize(fc.is64, isRela);
    const resolved = resolveSection(va, sz, entSz, entSize, sectionName);
    if (resolved === null) return;
    const { data, count, fileOff, byteSize } = resolved;
    sections.push({
      name: sectionName,
      usesDynSym: true,
      entries: parseRelTable(data, count, isRela, dynSyms),
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
  const wordSize = addrSize(fc.is64);
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
function parseNotes(shs: SectionHeader[], fc: Cursor, phs: ProgramHeader[]): Note[] {
  const notes: Note[] = [];

  function parseNoteData(c: Cursor, sectionName: string): void {
    while (c.remaining >= 12) {
      const namesz = c.u32();
      const descsz = c.u32();
      const type = c.u32();
      if (c.remaining < namesz) break;
      const name =
        namesz > 0
          ? decoder.decode(new Uint8Array(c.view.buffer, c.view.byteOffset + c.pos, namesz - 1))
          : "";
      c.skip(align4(namesz));
      if (c.remaining < descsz) break;
      const desc = new Reader(
        new DataView(c.view.buffer, c.view.byteOffset + c.pos, descsz),
        c.le,
        c.is64
      );
      c.skip(align4(descsz));
      notes.push({ sectionName, name, type, desc });
    }
  }

  // From note sections
  for (const sh of shs) {
    if (sh.type !== SHType.Note) continue;
    if (sh.size === 0) continue;
    parseNoteData(fc.cursor(sh.offset, sh.size), sh.name);
  }

  // From PT_NOTE segments (for stripped binaries without section headers)
  if (shs.length === 0) {
    for (const ph of phs) {
      if (ph.type !== PHType.Note) continue;
      if (ph.offset + ph.filesz <= fc.length) {
        parseNoteData(fc.cursor(ph.offset, ph.filesz), "PT_NOTE");
      }
    }
  }

  return notes;
}

// ─── Version info ─────────────────────────────────────────────────────────────

function parseVerSymTable(c: Cursor, count: number): number[] {
  const versions: number[] = [];
  for (let i = 0; i < count; i++) {
    versions.push(c.u16());
  }
  return versions;
}

// Verneed: version(2) cnt(2) file(4) aux(4) next(4) = 16 bytes
// Vernaux: hash(4) flags(2) other(2) name(4) next(4) = 16 bytes
const VERNEED_SIZE = 16;
const VERNAUX_SIZE = 16;

function parseVerNeedTable(
  c: Cursor,
  strtab: StrTabFn,
  count: number
): { needs: VersionNeed[]; byteSize: number } {
  const needs: VersionNeed[] = [];
  for (let i = 0; i < count && c.remaining >= VERNEED_SIZE; i++) {
    const version = c.u16();
    if (version !== 1)
      throw new ParseError(`VERNEED: unsupported version ${version} (expected 1)`);
    const cnt = c.u16();
    const fileIdx = c.u32();
    const auxOff = c.u32();
    const next = c.u32();
    if (auxOff !== VERNEED_SIZE)
      throw new ParseError(`VERNEED: unexpected vn_aux ${auxOff} (expected ${VERNEED_SIZE})`);
    const file = strtab(fileIdx);
    const aux: VersionNeedAux[] = [];
    for (let j = 0; j < cnt && c.remaining >= VERNAUX_SIZE; j++) {
      const hash = c.u32();
      const flags = c.u16();
      const other = c.u16();
      const nameIdx = c.u32();
      const anext = c.u32();
      aux.push({ hash, flags, other, name: strtab(nameIdx) });
      if (j < cnt - 1 && anext !== VERNAUX_SIZE)
        throw new ParseError(`VERNAUX: unexpected vna_next ${anext} (expected ${VERNAUX_SIZE})`);
    }
    needs.push({ file, cnt, aux });
    const expectedNext = VERNEED_SIZE + cnt * VERNAUX_SIZE;
    if (i < count - 1 && next !== expectedNext)
      throw new ParseError(`VERNEED: unexpected vn_next ${next} (expected ${expectedNext})`);
  }
  return { needs, byteSize: c.pos };
}

// Verdef: version(2) flags(2) ndx(2) cnt(2) hash(4) aux(4) next(4) = 20 bytes
// Verdaux: name(4) next(4) = 8 bytes
const VERDEF_SIZE = 20;
const VERDAUX_SIZE = 8;

function parseVerDefTable(
  c: Cursor,
  strtab: StrTabFn,
  count: number
): { defs: VersionDef[]; byteSize: number } {
  const defs: VersionDef[] = [];
  for (let i = 0; i < count && c.remaining >= VERDEF_SIZE; i++) {
    const version = c.u16();
    if (version !== 1)
      throw new ParseError(`VERDEF: unsupported version ${version} (expected 1)`);
    const flags = c.u16();
    const ndx = c.u16();
    const cnt = c.u16();
    const hash = c.u32();
    const auxOff = c.u32();
    const next = c.u32();
    if (auxOff !== VERDEF_SIZE)
      throw new ParseError(`VERDEF: unexpected vd_aux ${auxOff} (expected ${VERDEF_SIZE})`);
    const names: string[] = [];
    for (let j = 0; j < cnt && c.remaining >= VERDAUX_SIZE; j++) {
      const nameIdx = c.u32();
      const anext = c.u32();
      names.push(strtab(nameIdx));
      if (j < cnt - 1 && anext !== VERDAUX_SIZE)
        throw new ParseError(`VERDAUX: unexpected vda_next ${anext} (expected ${VERDAUX_SIZE})`);
    }
    defs.push({ flags, ndx, hash, names });
    const expectedNext = VERDEF_SIZE + cnt * VERDAUX_SIZE;
    if (i < count - 1 && next !== expectedNext)
      throw new ParseError(`VERDEF: unexpected vd_next ${next} (expected ${expectedNext})`);
  }
  return { defs, byteSize: c.pos };
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
  fc: Cursor,
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
    if (fileOff !== null && fileOff + verSymByteSize <= fc.length) {
      symVersions = parseVerSymTable(fc.cursor(fileOff, verSymByteSize), dynSymCount);
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
      fc.cursor(verNeedOff, fc.length - verNeedOff),
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
      fc.cursor(verDefOff, fc.length - verDefOff),
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
function parseHashTable(c: Cursor, fileOffset: number): HashTable {
  const nbucket = c.u32();
  const nchain = c.u32();

  const buckets: number[] = [];
  for (let i = 0; i < nbucket; i++) buckets.push(c.u32());

  const chains: number[] = [];
  for (let i = 0; i < nchain; i++) chains.push(c.u32());

  return {
    sectionName: ".hash",
    shIndex: -1,
    nbucket,
    nchain,
    buckets,
    chains,
    symNames: [],
    fileOffset,
    byteSize: c.pos,
  };
}

// ─── GNU Hash table ───────────────────────────────────────────────────────────

function parseGnuHashTable(c: Cursor, fileOffset: number): GnuHashTable {
  const nbuckets = c.u32();
  const symoffset = c.u32();
  const bloomSize = c.u32();
  const bloomShift = c.u32();
  const wordSize = c.is64 ? 8 : 4;

  const bloom: bigint[] = [];
  for (let i = 0; i < bloomSize; i++) {
    bloom.push(c.is64 ? c.u64() : BigInt(c.u32()));
  }

  const buckets: number[] = [];
  for (let i = 0; i < nbuckets; i++) {
    buckets.push(c.u32());
  }

  // Hash values are contiguous, ordered by bucket (symbols are sorted by
  // gnu_hash % nbuckets). Walk buckets in order, following each chain.
  const hashValues: number[] = [];
  for (const start of buckets) {
    if (start === 0) continue;
    while (c.remaining >= 4) {
      const v = c.u32();
      hashValues.push(v);
      if (v & 1) break; // end-of-chain
    }
  }

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
    fileOffset,
    byteSize: c.pos,
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
  const [header, fc] = parseHeader(bytes);

  const phs = parseProgramHeaders(fc, header);
  const shs = parseSectionHeaders(fc, header);

  // Parse dynamic section first — needed as fallback for symbols/relocations
  const { entries: dynamics, strtab: dynStrtab } = parseDynamic(fc, phs);
  const getDyn = (tag: DynTag) => dynamics.find((e) => e.tag === tag)?.value ?? null;

  const symbols = parseSymbols(shs, fc, SHType.SymTab);
  let dynSymbols = parseSymbols(shs, fc, SHType.DynSym);

  // Step 1-2: Parse hash tables first (no dynSymbols needed)
  const hashTables: HashTable[] = [];
  const hashOff = vaddrToFileOffset(getDyn(DynTag.Hash), phs, "DT_HASH");
  if (hashOff !== null) hashTables.push(parseHashTable(fc.cursor(hashOff), hashOff));

  const gnuHashOff = vaddrToFileOffset(getDyn(DynTag.GnuHash), phs, "DT_GNU_HASH");
  const gnuHashTable = gnuHashOff !== null ? parseGnuHashTable(fc.cursor(gnuHashOff), gnuHashOff) : null;

  // Step 3: Fallback dynamic symbol parse — derive count from hash tables
  if (dynSymbols.length === 0 && dynamics.length > 0) {
    let count = 0;
    if (hashTables.length > 0) {
      count = hashTables[0].nchain;
    } else if (gnuHashTable !== null) {
      count = gnuHashTable.symoffset + gnuHashTable.hashValues.length;
    }
    dynSymbols = parseDynSymbolsFromDynamic(getDyn, phs, fc, count, dynStrtab);
  }

  // Step 4: Populate symNames now that dynSymbols is ready
  for (const ht of hashTables) ht.symNames = dynSymbols.map((s) => s.name);
  if (gnuHashTable !== null) gnuHashTable.symNames = dynSymbols.map((s) => s.name);

  let relocs = parseRelocations(shs, fc, dynSymbols, symbols);
  if (relocs.length === 0 && dynamics.length > 0) {
    relocs = parseRelocationsFromDynamic(getDyn, dynSymbols, phs, fc);
  }
  const notes = parseNotes(shs, fc, phs);
  const versionInfo = parseVersionInfo(getDyn, dynSymbols.length, phs, fc, dynStrtab);

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
      dynSymByteSize = dynSymbols.length * symEntSize(fc.is64);
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
  elfFile.ehFrame = parseEhFrame(elfFile, fc);
  elfFile.debugFrame = parseDebugFrame(elfFile, fc);

  return elfFile;
}
