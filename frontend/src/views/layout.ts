// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Maps a parsed ELFFile to the intermediate LayoutData structure used by MemoryMapView.
// This replicates the segment/section mapping logic that was previously in the Go backend.

import {
  type ELFFile,
  type ProgramHeader,
  PHType,
  SHType,
  DynTag,
  PF_R,
  PF_W,
  PF_X,
  SHF_WRITE,
  SHF_EXECINSTR,
  SHF_ALLOC,
  SHF_TLS,
} from "../parser/types.ts";
import { shTypeName as secTypeName, phTypeName, dynTagName, shFlagsStr } from "./viewUtils.ts";

// ─── Intermediate types used by MemoryMapView ─────────────────────────────────

export interface LayoutSection {
  shIndex: number;
  name: string;
  addr: bigint; // virtual address (bigint); in object-file mode, BigInt(fileOffset)
  size: number;
  offset: number;
  isNobits: boolean;
  typeName: string; // section type string (e.g. "PROGBITS")
  shType: SHType; // raw section type enum value
  flags: string; // section flags string (e.g. "R-X")
  addralign: number; // address alignment
  entsize: number; // entry size (0 if not fixed-size)
  link: number; // section link
  info: number; // section info
}

export interface LayoutSegment {
  index: number;
  vaddr: bigint; // virtual address (bigint); in object-file mode, BigInt(fileOffset)
  paddr: bigint; // physical address
  memsz: number;
  filesz: number;
  fileOff: number;
  align: number;
  flags: string; // "R-X" format
  colorClass: string; // rx | rw | ro | other
  typeName?: string; // object file mode: section type
  sections: LayoutSection[];
}

export interface LayoutNonLoad {
  index: number;
  typeName: string;
  phType: PHType; // raw PH type enum value
  vaddr: bigint;
  paddr: bigint; // physical address
  filesz: number;
  memsz: number;
  flags: string;
  fileOff: number; // file offset
  align: number;
}

export interface LayoutDynEntry {
  tag: number;
  tagName: string;
  addr: bigint;
  value: bigint;
  companions: Array<{ label: string; value: string }>;
  shIndex: number | null; // section starting at this address (if any)
  sectionName: string | null; // name of that section
  fileOffset: number | null; // file offset for hex dump
  byteSize: number | null; // byte size for hex dump
}

export interface LayoutHeaderInfo {
  ehSize: number;
  phOff: number;
  phEntSize: number;
  phNum: number;
  hasPHDR: boolean; // true when a PT_PHDR segment exists (shown in non-load column instead)
}

export interface LayoutData {
  filePath: string;
  isObjectFile: boolean;
  segments: LayoutSegment[];
  nonLoadSegments: LayoutNonLoad[];
  dynamicEntries: LayoutDynEntry[];
  headerInfo: LayoutHeaderInfo | null;
  warnings: string[];
}

// ─── Entry point ─────────────────────────────────────────────────────────────

export function buildLayout(elf: ELFFile, filePath: string): LayoutData {
  const loadSegs = elf.programHeaders.filter((p) => p.type === PHType.Load);
  if (loadSegs.length === 0) {
    return buildObjectLayout(elf, filePath);
  }
  return buildExecLayout(elf, filePath, loadSegs);
}

// ─── Executable/shared library layout ────────────────────────────────────────

function buildExecLayout(elf: ELFFile, filePath: string, loadSegs: ProgramHeader[]): LayoutData {
  const sorted = [...loadSegs].sort((a, b) => (a.vaddr < b.vaddr ? -1 : a.vaddr > b.vaddr ? 1 : 0));

  const segments: LayoutSegment[] = sorted.map((ph) => {
    const secs = elf.sectionHeaders
      .filter(
        (sh) =>
          sh.type !== SHType.Null &&
          !!(sh.flags & SHF_ALLOC) &&
          sh.size > 0 &&
          // NOBITS+TLS (.tbss) shares virtual addresses with regular data and has no
          // file content — exclude it from the memory map entirely.
          !(sh.type === SHType.NoBits && !!(sh.flags & SHF_TLS)) &&
          // Use file-offset containment (like readelf) to avoid double-counting when
          // LOAD segments overlap in virtual address space (e.g. RELRO in libc).
          // Other NOBITS sections (.bss) have no file content, fall back to vaddr range.
          (sh.type === SHType.NoBits
            ? sh.addr >= ph.vaddr && sh.addr < ph.vaddr + BigInt(ph.memsz)
            : sh.offset >= ph.offset && sh.offset + sh.size <= ph.offset + ph.filesz)
      )
      .sort((a, b) => (a.addr < b.addr ? -1 : 1));

    return {
      index: ph.index,
      vaddr: ph.vaddr,
      paddr: ph.paddr,
      memsz: ph.memsz,
      filesz: ph.filesz,
      fileOff: ph.offset,
      align: ph.align,
      flags: flagsString(ph.flags),
      colorClass: flagsToColorClass(ph.flags),
      sections: secs.map((sh) => ({
        shIndex: sh.index,
        name: sh.name,
        addr: sh.addr, // bigint virtual address
        size: sh.size,
        offset: sh.offset,
        isNobits: sh.type === SHType.NoBits,
        typeName: secTypeName(sh.type),
        shType: sh.type,
        flags: shFlagsStr(sh.flags),
        addralign: sh.addralign,
        entsize: sh.entsize,
        link: sh.link,
        info: sh.info,
      })),
    };
  });

  const nonLoadSegments: LayoutNonLoad[] = elf.programHeaders
    .filter((p) => p.type !== PHType.Load && p.type !== PHType.Null)
    .map((ph) => ({
      index: ph.index,
      typeName: phTypeName(ph.type),
      phType: ph.type,
      vaddr: ph.vaddr,
      paddr: ph.paddr,
      filesz: ph.filesz,
      memsz: ph.memsz,
      flags: flagsString(ph.flags),
      fileOff: ph.offset,
      align: ph.align,
    }));

  // Dynamic entries: address-type tags only (to mark addresses on the map)
  const dynByTag = new Map<number, bigint>();
  for (const de of elf.dynamicEntries) dynByTag.set(de.tag as number, de.value);

  // Build address → section map for "Go to Section" navigation and hex dump
  const addrToSection = new Map<
    bigint,
    { shIndex: number; name: string; offset: number; size: number }
  >();
  for (const seg of segments) {
    for (const sec of seg.sections)
      addrToSection.set(sec.addr, {
        shIndex: sec.shIndex,
        name: sec.name,
        offset: sec.offset,
        size: sec.size,
      });
  }

  const dynamicEntries: LayoutDynEntry[] = elf.dynamicEntries
    .filter((de) => de.name === null && isAddrTag(de.tag) && de.value > 0n)
    .map((de) => {
      const companionDefs = COMPANION_MAP[de.tag as number];
      const companions: Array<{ label: string; value: string }> = [];
      if (companionDefs) {
        for (const cd of companionDefs) {
          const v = dynByTag.get(cd.tag as number);
          if (v !== undefined) companions.push({ label: cd.label, value: fmtCompanion(v, cd.fmt) });
        }
      }
      const secInfo = addrToSection.get(de.value);

      // Compute fileOffset and byteSize for hex dump
      let fileOffset: number | null = null;
      let byteSize: number | null = null;
      if (secInfo) {
        fileOffset = secInfo.offset;
        byteSize = secInfo.size;
      } else if (companionDefs) {
        // First 'hex' companion is conventionally the size tag (RELASZ, RELSZ, STRSZ, etc.)
        const sizeDef = companionDefs.find((cd) => cd.fmt === "hex");
        if (sizeDef) {
          const sizeVal = dynByTag.get(sizeDef.tag as number);
          if (sizeVal !== undefined && sizeVal > 0n) {
            byteSize = Number(sizeVal);
            const seg = sorted.find(
              (s) => de.value >= s.vaddr && de.value < s.vaddr + BigInt(s.filesz)
            );
            if (seg) fileOffset = seg.offset + Number(de.value - seg.vaddr);
          }
        }
      }
      // DT_HASH has no size companion tag in the ELF spec; derive size from the
      // parsed hash table structure: header(2) + nbucket + nchain words of 4 bytes each.
      if (byteSize === null && de.tag === DynTag.Hash && elf.hashTables.length > 0) {
        const ht = elf.hashTables[0];
        byteSize = (2 + ht.nbucket + ht.nchain) * 4;
        if (fileOffset === null) {
          const seg = sorted.find(
            (s) => de.value >= s.vaddr && de.value < s.vaddr + BigInt(s.filesz)
          );
          if (seg) fileOffset = seg.offset + Number(de.value - seg.vaddr);
        }
      }
      // DT_GNU_HASH has no size companion tag; derive from the parsed structure.
      if (byteSize === null && de.tag === DynTag.GnuHash && elf.gnuHashTable) {
        byteSize = elf.gnuHashTable.byteSize;
        if (fileOffset === null) {
          if (elf.gnuHashTable.fileOffset !== null) {
            fileOffset = elf.gnuHashTable.fileOffset;
          } else {
            const seg = sorted.find(
              (s) => de.value >= s.vaddr && de.value < s.vaddr + BigInt(s.filesz)
            );
            if (seg) fileOffset = seg.offset + Number(de.value - seg.vaddr);
          }
        }
      }
      // DT_SYMTAB has no size companion tag; derive size from dynSymbols count and entry size.
      if (byteSize === null && de.tag === DynTag.SymTab && elf.dynSymByteSize > 0) {
        byteSize = elf.dynSymByteSize;
        if (fileOffset === null) {
          if (elf.dynSymFileOffset !== null) {
            fileOffset = elf.dynSymFileOffset;
          } else {
            const seg = sorted.find(
              (s) => de.value >= s.vaddr && de.value < s.vaddr + BigInt(s.filesz)
            );
            if (seg) fileOffset = seg.offset + Number(de.value - seg.vaddr);
          }
        }
      }
      // DT_VERSYM: one uint16 per dynamic symbol — no size tag in the ELF spec.
      if (byteSize === null && de.tag === DynTag.VerSym) {
        const sz = elf.dynSymbols.length * 2;
        if (sz > 0) {
          byteSize = sz;
          if (fileOffset === null) {
            const seg = sorted.find(
              (s) => de.value >= s.vaddr && de.value < s.vaddr + BigInt(s.filesz)
            );
            if (seg) fileOffset = seg.offset + Number(de.value - seg.vaddr);
          }
        }
      }
      // DT_VERNEED / DT_VERDEF: variable-length linked-list structures; sizes from parser traversal.
      if (byteSize === null && elf.versionInfo) {
        let sz = 0;
        if (de.tag === DynTag.VerNeed) sz = elf.versionInfo.verNeedByteSize;
        else if (de.tag === DynTag.VerDef) sz = elf.versionInfo.verDefByteSize;
        if (sz > 0) {
          byteSize = sz;
          if (fileOffset === null) {
            const seg = sorted.find(
              (s) => de.value >= s.vaddr && de.value < s.vaddr + BigInt(s.filesz)
            );
            if (seg) fileOffset = seg.offset + Number(de.value - seg.vaddr);
          }
        }
      }

      return {
        tag: de.tag as number,
        tagName: dynTagName(de.tag, elf.header.machine),
        addr: de.value,
        value: de.value,
        companions,
        shIndex: secInfo?.shIndex ?? null,
        sectionName: secInfo?.name ?? dynTagCanonicalName(de.tag, elf),
        fileOffset,
        byteSize,
      };
    });

  const h = elf.header;
  const phdrSeg = elf.programHeaders.find((p) => p.type === PHType.Phdr);
  const headerInfo: LayoutHeaderInfo = {
    ehSize: h.ehSize,
    phOff: h.phOffset,
    phEntSize: h.phEntSize,
    phNum: h.phNum,
    hasPHDR: !!phdrSeg,
  };

  // Warnings: check PHDR segment consistency
  const warnings: string[] = [];
  if (phdrSeg) {
    const expected = h.phEntSize * h.phNum;
    if (phdrSeg.offset !== h.phOffset) {
      warnings.push(
        `PT_PHDR offset (0x${phdrSeg.offset.toString(16)}) does not match e_phoff (0x${h.phOffset.toString(16)})`
      );
    }
    if (phdrSeg.filesz !== expected) {
      warnings.push(
        `PT_PHDR filesz (0x${phdrSeg.filesz.toString(16)}) does not match phentsize*phnum (0x${expected.toString(16)})`
      );
    }
  }

  return {
    filePath,
    isObjectFile: false,
    segments,
    nonLoadSegments,
    dynamicEntries,
    headerInfo,
    warnings,
  };
}

// ─── Object file layout (no PT_LOAD) ─────────────────────────────────────────

function buildObjectLayout(elf: ELFFile, filePath: string): LayoutData {
  const h = elf.header;
  const segments: LayoutSegment[] = [];

  // ELF header "segment" (synthetic, index -1)
  segments.push({
    index: -1,
    vaddr: 0n,
    paddr: 0n,
    memsz: h.ehSize,
    filesz: h.ehSize,
    fileOff: 0,
    align: 1,
    flags: "R--",
    colorClass: "ro",
    typeName: "ELF Header",
    sections: [],
  });

  // Each section as its own segment
  for (const sh of elf.sectionHeaders) {
    if (sh.type === SHType.Null || sh.size === 0) continue;
    if (sh.type === SHType.NoBits) continue;

    segments.push({
      index: sh.index,
      vaddr: BigInt(sh.offset), // object files: use file offset as "vaddr"
      paddr: 0n,
      memsz: sh.size,
      filesz: sh.size,
      fileOff: sh.offset,
      align: sh.addralign,
      flags: secFlagsString(sh.flags),
      colorClass: secFlagsToColorClass(sh.flags),
      typeName: secTypeName(sh.type),
      sections: [
        {
          shIndex: sh.index,
          name: sh.name,
          addr: BigInt(sh.offset), // use file offset as pseudo-vaddr
          size: sh.size,
          offset: sh.offset,
          isNobits: false,
          typeName: secTypeName(sh.type),
          shType: sh.type,
          flags: shFlagsStr(sh.flags),
          addralign: sh.addralign,
          entsize: sh.entsize,
          link: sh.link,
          info: sh.info,
        },
      ],
    });
  }

  // Section header table (synthetic, index -2)
  if (h.shOffset > 0 && h.shNum > 0) {
    const shTableSize = h.shEntSize * h.shNum;
    segments.push({
      index: -2,
      vaddr: BigInt(h.shOffset),
      paddr: 0n,
      memsz: shTableSize,
      filesz: shTableSize,
      fileOff: h.shOffset,
      align: 1,
      flags: "R--",
      colorClass: "ro",
      typeName: "Section Headers",
      sections: [],
    });
  }

  // Sort by file offset (= vaddr in object file mode)
  segments.sort((a, b) => (a.vaddr < b.vaddr ? -1 : a.vaddr > b.vaddr ? 1 : 0));

  return {
    filePath,
    isObjectFile: true,
    segments,
    nonLoadSegments: [],
    dynamicEntries: [],
    headerInfo: null,
    warnings: [],
  };
}

// ─── File layout (section-based, file-offset view) ───────────────────────────

export function buildFileLayout(elf: ELFFile, filePath: string): LayoutData {
  const h = elf.header;
  const segments: LayoutSegment[] = [];

  // ELF header (synthetic, index -1)
  segments.push({
    index: -1,
    vaddr: 0n,
    paddr: 0n,
    memsz: h.ehSize,
    filesz: h.ehSize,
    fileOff: 0,
    align: 1,
    flags: "R--",
    colorClass: "ro",
    typeName: "ELF Header",
    sections: [],
  });

  // Program header table (synthetic, index -3)
  if (h.phOffset > 0 && h.phNum > 0) {
    const phTableSize = h.phEntSize * h.phNum;
    segments.push({
      index: -3,
      vaddr: BigInt(h.phOffset),
      paddr: 0n,
      memsz: phTableSize,
      filesz: phTableSize,
      fileOff: h.phOffset,
      align: 1,
      flags: "R--",
      colorClass: "ro",
      typeName: "Program Headers",
      sections: [],
    });
  }

  // Each non-empty section as its own row (file offset as "address")
  for (const sh of elf.sectionHeaders) {
    if (sh.type === SHType.Null || sh.size === 0) continue;
    if (sh.type === SHType.NoBits) continue;
    segments.push({
      index: sh.index,
      vaddr: BigInt(sh.offset), // file offset used as address
      paddr: 0n,
      memsz: sh.size,
      filesz: sh.size,
      fileOff: sh.offset,
      align: sh.addralign,
      flags: secFlagsString(sh.flags),
      colorClass: secFlagsToColorClass(sh.flags),
      typeName: secTypeName(sh.type),
      sections: [
        {
          shIndex: sh.index,
          name: sh.name,
          addr: BigInt(sh.offset), // file offset used as address
          size: sh.size,
          offset: sh.offset,
          isNobits: false,
          typeName: secTypeName(sh.type),
          shType: sh.type,
          flags: shFlagsStr(sh.flags),
          addralign: sh.addralign,
          entsize: sh.entsize,
          link: sh.link,
          info: sh.info,
        },
      ],
    });
  }

  // Section header table (synthetic, index -2)
  if (h.shOffset > 0 && h.shNum > 0) {
    const shTableSize = h.shEntSize * h.shNum;
    segments.push({
      index: -2,
      vaddr: BigInt(h.shOffset),
      paddr: 0n,
      memsz: shTableSize,
      filesz: shTableSize,
      fileOff: h.shOffset,
      align: 1,
      flags: "R--",
      colorClass: "ro",
      typeName: "Section Headers",
      sections: [],
    });
  }

  // Sort by file offset
  segments.sort((a, b) => (a.vaddr < b.vaddr ? -1 : a.vaddr > b.vaddr ? 1 : 0));

  return {
    filePath,
    isObjectFile: true, // reuse object-file rendering (file-offset based)
    segments,
    nonLoadSegments: [],
    dynamicEntries: [],
    headerInfo: null,
    warnings: [],
  };
}

// ─── Helper functions ─────────────────────────────────────────────────────────

function flagsString(flags: number): string {
  return `${flags & PF_R ? "R" : "-"}${flags & PF_W ? "W" : "-"}${flags & PF_X ? "X" : "-"}`;
}

function flagsToColorClass(flags: number): string {
  const r = !!(flags & PF_R);
  const w = !!(flags & PF_W);
  const x = !!(flags & PF_X);
  if (r && x && !w) return "rx";
  if (r && w && !x) return "rw";
  if (r && !w && !x) return "ro";
  return "other";
}

function secFlagsString(flags: bigint): string {
  const r = true; // sections are always readable
  const w = !!(flags & SHF_WRITE);
  const x = !!(flags & SHF_EXECINSTR);
  return `${r ? "R" : "-"}${w ? "W" : "-"}${x ? "X" : "-"}`;
}

function secFlagsToColorClass(flags: bigint): string {
  const alloc = !!(flags & SHF_ALLOC);
  const write = !!(flags & SHF_WRITE);
  const exec = !!(flags & SHF_EXECINSTR);
  if (alloc && exec) return "rx";
  if (alloc && write) return "rw";
  if (alloc) return "ro";
  return "other";
}

// Tags that hold addresses (shown on the memory map as markers)
const ADDR_TAGS = new Set<number>([
  DynTag.PltGot,
  DynTag.Hash,
  DynTag.StrTab,
  DynTag.SymTab,
  DynTag.Rela,
  DynTag.Init,
  DynTag.Fini,
  DynTag.Rel,
  DynTag.JmpRel,
  DynTag.InitArray,
  DynTag.FiniArray,
  DynTag.PreInitArray,
  DynTag.VerNeed,
  DynTag.VerSym,
  DynTag.GnuHash,
  DynTag.Relr,
  DynTag.VerDef,
  DynTag.X86_64Plt,
]);

function isAddrTag(tag: DynTag): boolean {
  return ADDR_TAGS.has(tag);
}

// Canonical section name for a dynamic tag when no section header is present.
function dynTagCanonicalName(tag: DynTag, elf: ELFFile): string | null {
  switch (tag) {
    case DynTag.Hash:
      return elf.hashTables[0]?.sectionName ?? ".hash";
    case DynTag.GnuHash:
      return elf.gnuHashTable?.sectionName ?? ".gnu.hash";
    case DynTag.StrTab:
      return ".dynstr";
    case DynTag.SymTab:
      return ".dynsym";
    case DynTag.Rela:
      return ".rela.dyn";
    case DynTag.Rel:
      return ".rel.dyn";
    case DynTag.JmpRel:
      return elf.relocations.find((r) => r.name.endsWith(".plt"))?.name ?? ".rela.plt";
    case DynTag.Relr:
      return ".relr.dyn";
    case DynTag.InitArray:
      return ".init_array";
    case DynTag.FiniArray:
      return ".fini_array";
    case DynTag.PreInitArray:
      return ".preinit_array";
    case DynTag.VerSym:
      return ".gnu.version";
    case DynTag.VerNeed:
      return ".gnu.version_r";
    case DynTag.VerDef:
      return ".gnu.version_d";
    default:
      return null;
  }
}

// Companion tags: shown in the Memory Map tooltip alongside each address-type entry.
// fmt: 'hex' for size values, 'pltrel' for DT_PLTREL (shown as RELA/REL), 'dec' for counts/entry sizes.
type CompanionFmt = "hex" | "dec" | "pltrel";
const COMPANION_MAP: Partial<
  Record<number, Array<{ tag: DynTag; label: string; fmt: CompanionFmt }>>
> = {
  [DynTag.Rela]: [
    { tag: DynTag.RelaSz, label: "RELASZ", fmt: "hex" },
    { tag: DynTag.RelaEnt, label: "RELAENT", fmt: "dec" },
  ],
  [DynTag.Rel]: [
    { tag: DynTag.RelSz, label: "RELSZ", fmt: "hex" },
    { tag: DynTag.RelEnt, label: "RELENT", fmt: "dec" },
  ],
  [DynTag.JmpRel]: [
    { tag: DynTag.PltRelSz, label: "PLTRELSZ", fmt: "hex" },
    { tag: DynTag.PltRel, label: "PLTREL", fmt: "pltrel" },
  ],
  [DynTag.InitArray]: [{ tag: DynTag.InitArraySz, label: "INIT_ARRAYSZ", fmt: "hex" }],
  [DynTag.FiniArray]: [{ tag: DynTag.FiniArraySz, label: "FINI_ARRAYSZ", fmt: "hex" }],
  [DynTag.PreInitArray]: [{ tag: DynTag.PreInitArraySz, label: "PREINIT_ARRAYSZ", fmt: "hex" }],
  [DynTag.StrTab]: [{ tag: DynTag.StrSz, label: "STRSZ", fmt: "hex" }],
  [DynTag.Relr]: [
    { tag: DynTag.RelrSz, label: "RELRSZ", fmt: "hex" },
    { tag: DynTag.RelrEnt, label: "RELRENT", fmt: "dec" },
  ],
  [DynTag.VerDef]: [{ tag: DynTag.VerDefNum, label: "VERDEFNUM", fmt: "dec" }],
  [DynTag.VerNeed]: [{ tag: DynTag.VerNeedNum, label: "VERNEEDNUM", fmt: "dec" }],
  [DynTag.X86_64Plt]: [
    { tag: DynTag.X86_64PltSz, label: "X86_64_PLTSZ", fmt: "hex" },
    { tag: DynTag.X86_64PltEnt, label: "X86_64_PLTENT", fmt: "dec" },
  ],
};

/** Maps each companion tag (e.g. DT_RELASZ, DT_RELAENT) to its address-type main tag (e.g. DT_RELA). */
export const companionToMainTag: ReadonlyMap<number, number> = (() => {
  const m = new Map<number, number>();
  for (const [mainTagStr, companions] of Object.entries(COMPANION_MAP)) {
    const mainTag = Number(mainTagStr);
    for (const { tag } of companions!) m.set(tag as number, mainTag);
  }
  return m;
})();

function fmtCompanion(v: bigint, fmt: CompanionFmt): string {
  if (fmt === "hex") return `0x${v.toString(16).toUpperCase()}`;
  if (fmt === "pltrel")
    return v === BigInt(DynTag.Rela)
      ? "RELA"
      : v === BigInt(DynTag.Rel)
        ? "REL"
        : `0x${v.toString(16).toUpperCase()}`;
  return String(v);
}
