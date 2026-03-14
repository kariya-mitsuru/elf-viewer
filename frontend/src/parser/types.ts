// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// ELF data type definitions.
// References: ELF specification, System V ABI, Linux kernel elf.h

import { Reader } from "./reader.ts";

// ─── Enumerations ────────────────────────────────────────────────────────────

export enum ELFClass {
  ELF32 = 1,
  ELF64 = 2,
}

export enum ELFData {
  LSB = 1, // Little-endian
  MSB = 2, // Big-endian
}

export enum ELFType {
  None = 0,
  Rel = 1, // ET_REL – relocatable
  Exec = 2, // ET_EXEC – executable
  Dyn = 3, // ET_DYN – shared object
  Core = 4, // ET_CORE
}

export enum ELFOSABI {
  None = 0,
  HPUX = 1,
  NetBSD = 2,
  Linux = 3,
  Solaris = 6,
  AIX = 7,
  IRIX = 8,
  FreeBSD = 9,
  OpenBSD = 12,
  ARM = 97,
  Standalone = 255,
}

export enum ELFMachine {
  None = 0,
  SPARC = 2,
  X86 = 3,
  MIPS = 8,
  PPC = 20,
  PPC64 = 21,
  S390 = 22,
  ARM = 40,
  IA64 = 50,
  X86_64 = 62,
  AArch64 = 183,
  RISC_V = 243,
  LoongArch = 258,
}

// Section type (sh_type)
export enum SHType {
  Null = 0,
  ProgBits = 1,
  SymTab = 2,
  StrTab = 3,
  Rela = 4,
  Hash = 5,
  Dynamic = 6,
  Note = 7,
  NoBits = 8,
  Rel = 9,
  ShLib = 10,
  DynSym = 11,
  InitArray = 14,
  FiniArray = 15,
  PreInitArray = 16,
  Group = 17,
  SymTabShndx = 18,
  Relr = 19,
  GnuHash = 0x6ffffff6,
  GnuVerNeed = 0x6ffffffe,
  GnuVerDef = 0x6ffffffd,
  GnuVerSym = 0x6fffffff,
}

// Section flags (sh_flags)
export const SHF_WRITE = 0x1n;
export const SHF_ALLOC = 0x2n;
export const SHF_EXECINSTR = 0x4n;
export const SHF_MERGE = 0x10n;
export const SHF_STRINGS = 0x20n;
export const SHF_GROUP = 0x200n;
export const SHF_TLS = 0x400n;

// Program header type (p_type)
export enum PHType {
  Null = 0,
  Load = 1,
  Dynamic = 2,
  Interp = 3,
  Note = 4,
  ShLib = 5,
  Phdr = 6,
  Tls = 7,
  GnuEhFrame = 0x6474e550,
  GnuStack = 0x6474e551,
  GnuRelRo = 0x6474e552,
  GnuProperty = 0x6474e553,
}

// Program header flags (p_flags)
export const PF_X = 0x1;
export const PF_W = 0x2;
export const PF_R = 0x4;

// Dynamic tag (d_tag)
export enum DynTag {
  Null = 0,
  Needed = 1,
  PltRelSz = 2,
  PltGot = 3,
  Hash = 4,
  StrTab = 5,
  SymTab = 6,
  Rela = 7,
  RelaSz = 8,
  RelaEnt = 9,
  StrSz = 10,
  SymEnt = 11,
  Init = 12,
  Fini = 13,
  SoName = 14,
  RPath = 15,
  Symbolic = 16,
  Rel = 17,
  RelSz = 18,
  RelEnt = 19,
  PltRel = 20,
  Debug = 21,
  TextRel = 22,
  JmpRel = 23,
  BindNow = 24,
  InitArray = 25,
  FiniArray = 26,
  InitArraySz = 27,
  FiniArraySz = 28,
  RunPath = 29,
  Flags = 30,
  Encoding = 32,
  // eslint-disable-next-line @typescript-eslint/no-duplicate-enum-values
  PreInitArray = 32,
  PreInitArraySz = 33,
  SymTabShndx = 34,
  RelrSz = 35,
  Relr = 36,
  RelrEnt = 37,
  GnuHash = 0x6ffffef5,
  VerSym = 0x6ffffff0,
  RelaCount = 0x6ffffff9,
  RelCount = 0x6ffffffa,
  VerDef = 0x6ffffffc,
  VerDefNum = 0x6ffffffd,
  VerNeed = 0x6ffffffe,
  VerNeedNum = 0x6fffffff,
  Flags1 = 0x6ffffffb,
  // Architecture-specific (x86-64)
  X86_64Plt = 0x70000000,
  X86_64PltSz = 0x70000001,
  X86_64PltEnt = 0x70000003,
}

// Symbol binding (ELF32_ST_BIND / ELF64_ST_BIND)
export enum STBind {
  Local = 0,
  Global = 1,
  Weak = 2,
  GnuUnique = 10,
}

// Symbol type (ELF32_ST_TYPE / ELF64_ST_TYPE)
export enum STType {
  NoType = 0,
  Object = 1,
  Func = 2,
  Section = 3,
  File = 4,
  Common = 5,
  Tls = 6,
  GnuIfunc = 10,
}

// Symbol visibility (ELF32_ST_VISIBILITY / ELF64_ST_VISIBILITY)
export enum STVisibility {
  Default = 0,
  Internal = 1,
  Hidden = 2,
  Protected = 3,
}

// Special section indices
export const SHN_UNDEF = 0;
export const SHN_ABS = 0xfff1;
export const SHN_COMMON = 0xfff2;
export const SHN_XINDEX = 0xffff;

// DT_FLAGS bit masks (d_val field of DynTag.Flags)
export const DF_ORIGIN = 0x01; // Object may use $ORIGIN substitution
export const DF_SYMBOLIC = 0x02; // Symbol resolution starts from this object
export const DF_TEXTREL = 0x04; // Object contains text relocations
export const DF_BIND_NOW = 0x08; // No lazy binding for this object
export const DF_STATIC_TLS = 0x10; // Module uses the static TLS model

// DT_FLAGS_1 bit masks (d_val field of DynTag.Flags1)
export const DF_1_NOW = 0x00000001; // Set RTLD_NOW for this object
export const DF_1_GLOBAL = 0x00000002; // Set RTLD_GLOBAL for this object
export const DF_1_GROUP = 0x00000004; // Set RTLD_GROUP for this object
export const DF_1_NODELETE = 0x00000008; // Set RTLD_NODELETE for this object
export const DF_1_LOADFLTR = 0x00000010; // Trigger filtee loading at runtime
export const DF_1_INITFIRST = 0x00000020; // Set RTLD_INITFIRST for this object
export const DF_1_NOOPEN = 0x00000040; // Set RTLD_NOOPEN for this object
export const DF_1_ORIGIN = 0x00000080; // $ORIGIN must be handled
export const DF_1_DIRECT = 0x00000100; // Direct binding enabled
export const DF_1_TRANS = 0x00000200;
export const DF_1_INTERPOSE = 0x00000400; // Object is used to interpose
export const DF_1_NODEFLIB = 0x00000800; // Ignore default lib search path
export const DF_1_NODUMP = 0x00001000; // Object cannot be dldump'ed
export const DF_1_CONFALT = 0x00002000; // Configuration alternative created
export const DF_1_ENDFILTEE = 0x00004000; // Filtee terminates filters search
export const DF_1_DISPRELDNE = 0x00008000; // Disp reloc applied at build time
export const DF_1_DISPRELPND = 0x00010000; // Disp reloc applied at run time
export const DF_1_NODIRECT = 0x00020000; // Object has no-direct binding
export const DF_1_IGNMULDEF = 0x00040000;
export const DF_1_NOKSYMS = 0x00080000;
export const DF_1_NOHDR = 0x00100000;
export const DF_1_EDITED = 0x00200000; // Object is modified after built
export const DF_1_NORELOC = 0x00400000;
export const DF_1_SYMINTPOSE = 0x00800000; // Object has individual interposers
export const DF_1_GLOBAUDIT = 0x01000000; // Global auditing required
export const DF_1_SINGLETON = 0x02000000; // Singleton symbols are used
export const DF_1_STUB = 0x04000000;
export const DF_1_PIE = 0x08000000; // Position-independent executable
export const DF_1_KMOD = 0x10000000;
export const DF_1_WEAKFILTER = 0x20000000;
export const DF_1_NOCOMMON = 0x40000000;

// Relocation type helpers
export const R_SYM = (info: bigint): bigint => info >> 32n;
export const R_TYPE = (info: bigint): bigint => info & 0xffffffffn;

// ─── Parsed data structures ───────────────────────────────────────────────────
// Field type convention:
//   bigint  – virtual/physical addresses and other values that may exceed 2^53
//             (Elf_Addr, and Elf_Xword used for flags/version fields).
//   number  – file offsets, file sizes, and all 32-bit-or-smaller fields.
//             If a file offset/size read from ELF64 exceeds Number.MAX_SAFE_INTEGER,
//             ParseError is thrown during parsing.

export interface ELFHeader {
  class: ELFClass; // 32 or 64 bit
  data: ELFData; // endianness
  version: number; // EI_VERSION
  osabi: ELFOSABI;
  abiVersion: number;
  type: ELFType;
  machine: ELFMachine;
  entryPoint: bigint;
  phOffset: number; // program header table file offset
  shOffset: number; // section header table file offset
  flags: number;
  ehSize: number;
  phEntSize: number;
  phNum: number;
  shEntSize: number;
  shNum: number;
  shStrNdx: number;
}

export interface ProgramHeader {
  index: number;
  type: PHType;
  flags: number;
  offset: number;
  vaddr: bigint;
  paddr: bigint;
  filesz: number;
  memsz: number;
  align: number;
}

export interface SectionHeader {
  index: number;
  name: string;
  type: SHType;
  flags: bigint;
  addr: bigint;
  offset: number;
  size: number;
  link: number;
  info: number;
  addralign: number;
  entsize: number;
}

export interface Symbol {
  index: number;
  name: string;
  value: bigint;
  size: number;
  bind: STBind;
  type: STType;
  visibility: STVisibility;
  shndx: number; // section index (SHN_UNDEF, SHN_ABS, etc.)
  sectionName: string | null; // resolved section name, or null for special indices
}

export interface RelocationEntry {
  offset: bigint;
  symIndex: number;
  symName: string;
  symValue: bigint; // value of the referenced symbol (0 if none)
  type: number; // architecture-specific relocation type
  addend: bigint | null; // null for REL (no addend)
}

export interface RelocationSection {
  name: string; // relocation section name (e.g. ".rela.plt")
  usesDynSym: boolean; // true if symIndex refers to .dynsym (version info applies)
  entries: RelocationEntry[];
  fileOffset: number | null; // file offset of the raw relocation data (null if not resolvable)
  byteSize: number; // byte size of the raw relocation data
}

export interface DynamicEntry {
  tag: DynTag;
  value: bigint; // raw value (address or integer)
  name: string | null; // resolved string for DT_NEEDED, DT_SONAME, etc.
}

export interface Note {
  sectionName: string;
  name: string; // note name (e.g. "GNU", "CORE")
  type: number; // note type
  desc: Reader; // raw note descriptor bytes
}

export interface VersionNeed {
  file: string; // library name (from DT_NEEDED)
  cnt: number;
  aux: VersionNeedAux[];
}

export interface VersionNeedAux {
  hash: number;
  flags: number;
  other: number; // version index
  name: string; // version name
}

export interface VersionDef {
  flags: number;
  ndx: number; // version index
  hash: number;
  names: string[]; // first is the version name
}

export interface HashTable {
  sectionName: string;
  shIndex: number;
  nbucket: number;
  nchain: number;
  buckets: number[]; // length = nbucket; each entry is head symbol index (0 = empty)
  chains: number[]; // length = nchain;  chains[i] = next symbol in chain (0 = end)
  symNames: string[]; // symbol names, indexed by symbol index (length = nchain)
  fileOffset: number | null; // file offset of the structure start (null if not resolvable)
  byteSize: number; // total byte size: 8 + (nbucket + nchain) * 4
}

export interface GnuHashTable {
  sectionName: string;
  shIndex: number;
  nbuckets: number;
  symoffset: number; // index of first hashed symbol (symbols 0..symoffset-1 are unhashed)
  bloomSize: number; // number of bloom filter words
  bloomShift: number; // shift count used in second bloom hash
  bloom: bigint[]; // bloom filter words (u64 for ELF64, u32 → bigint for ELF32)
  bloomWordSize: number; // 4 (ELF32) or 8 (ELF64)
  buckets: number[]; // length = nbuckets; 0 = empty, else starting symbol index
  hashValues: number[]; // one u32 per hashed symbol; bit 0 = end-of-chain marker
  symNames: string[]; // dynamic symbol names indexed from 0
  fileOffset: number | null; // file offset of the structure start (null if not resolvable)
  byteSize: number; // total byte size: 16 + bloom*bloomWordSize + nbuckets*4 + hashValues*4
}

export interface VersionInfo {
  symVersions: number[]; // index i → version index of symbol i (from .gnu.version)
  versionNeeds: VersionNeed[];
  versionDefs: VersionDef[];
  verNeedByteSize: number; // byte size of the VERNEED structure (from linked-list traversal)
  verDefByteSize: number; // byte size of the VERDEF structure (from linked-list traversal)
  verSymFileOffset: number | null; // file offset of .gnu.version  (null if not resolvable)
  verSymByteSize: number; // byte size of .gnu.version
  verNeedFileOffset: number | null; // file offset of .gnu.version_r (null if not resolvable)
  verDefFileOffset: number | null; // file offset of .gnu.version_d (null if not resolvable)
}

// Top-level result returned by the ELF parser
export interface ELFFile {
  header: ELFHeader;
  programHeaders: ProgramHeader[];
  sectionHeaders: SectionHeader[];
  symbols: Symbol[]; // from .symtab
  dynSymbols: Symbol[]; // from .dynsym
  dynSymFileOffset: number | null; // file offset of .dynsym (null if not resolvable)
  dynSymByteSize: number; // byte size of .dynsym table
  relocations: RelocationSection[];
  dynamicEntries: DynamicEntry[];
  notes: Note[];
  versionInfo: VersionInfo | null;
  hashTables: HashTable[]; // from DT_HASH dynamic entry (.hash)
  gnuHashTable: GnuHashTable | null; // from DT_GNU_HASH (.gnu.hash)
  // Raw bytes (kept for future hex-dump use)
  raw: Uint8Array;
}
