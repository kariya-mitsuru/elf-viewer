// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Shared view utilities.
// Functions and constants used across multiple view modules.

import {
  type ELFFile,
  type VersionInfo,
  ELFType,
  ELFMachine,
  SHType,
  PHType,
  DynTag,
  PF_R,
  PF_W,
  PF_X,
  SHF_WRITE,
  SHF_ALLOC,
  SHF_EXECINSTR,
  SHF_MERGE,
  SHF_STRINGS,
  SHF_GROUP,
  SHF_TLS,
  DF_1_PIE,
} from "../parser/types.ts";

// ─── Navigation target ────────────────────────────────────────────────────────

export type NavTarget =
  | "symbols"
  | "relocations"
  | "dynamic"
  | "notes"
  | "versions"
  | "hash"
  | "gnu-hash";

/** Maps a section type to the view tab that displays its content. */
export function sectionNavTarget(type: SHType): NavTarget | null {
  switch (type) {
    case SHType.DynSym:
    case SHType.SymTab:
    case SHType.GnuVerSym:
      return "symbols";
    case SHType.Rel:
    case SHType.Rela:
    case SHType.Relr:
      return "relocations";
    case SHType.Dynamic:
      return "dynamic";
    case SHType.Note:
      return "notes";
    case SHType.GnuVerNeed:
    case SHType.GnuVerDef:
      return "versions";
    case SHType.Hash:
      return "hash";
    case SHType.GnuHash:
      return "gnu-hash";
    default:
      return null;
  }
}

/** Human-readable label for a NavTarget (used in context menus). */
export function navTargetLabel(target: NavTarget): string {
  switch (target) {
    case "symbols":
      return "Symbols View";
    case "relocations":
      return "Relocations View";
    case "dynamic":
      return "Dynamic View";
    case "notes":
      return "Notes View";
    case "versions":
      return "Versions View";
    case "hash":
      return "Hash Table View";
    case "gnu-hash":
      return "GNU Hash Table View";
  }
}

/** Maps a DynTag to the view tab that best displays its content. */
export function dynNavTarget(tag: DynTag): NavTarget | null {
  switch (tag) {
    case DynTag.SymTab:
      return "symbols";
    case DynTag.Hash:
      return "hash";
    case DynTag.GnuHash:
      return "gnu-hash";
    case DynTag.Rela:
    case DynTag.Rel:
    case DynTag.JmpRel:
    case DynTag.Relr:
      return "relocations";
    case DynTag.VerSym:
    case DynTag.VerDef:
    case DynTag.VerNeed:
      return "versions";
    default:
      return null;
  }
}

// ─── Version info helpers ─────────────────────────────────────────────────────

/**
 * Returns [versionName, versionNumber, hidden] for a symbol by index.
 * Looks up the version in versionNeeds (for DT_VERNEED) and versionDefs (for DT_VERDEF).
 */
export function versionParts(
  symIndex: number,
  versionInfo: VersionInfo | null
): [string, string, boolean] {
  if (!versionInfo || symIndex >= versionInfo.symVersions.length) return ["", "", false];
  const raw = versionInfo.symVersions[symIndex];
  const hidden = (raw & 0x8000) !== 0;
  const vidx = raw & 0x7fff;
  if (vidx <= 1) return ["", "", false];
  for (const need of versionInfo.versionNeeds) {
    for (const aux of need.aux) {
      if (aux.other === vidx) return [`@${aux.name}`, String(vidx), hidden];
    }
  }
  for (const def of versionInfo.versionDefs) {
    if (def.ndx === vidx && def.names.length > 0) {
      return [`${hidden ? "@" : "@@"}${def.names[0]}`, String(vidx), hidden];
    }
  }
  return ["", String(vidx), hidden];
}

/**
 * Builds the HTML cell content for the version number column.
 * Returns an HTML string (safe — verNum is a numeric string, hidden is boolean).
 */
export function verNumCellHtml(verNum: string, hidden: boolean): string {
  if (!verNum) return "";
  return `<div class="ver-num-cell"><span class="ver-num-val">${verNum}</span><span class="ver-hidden-slot">${hidden ? `<span class="ver-hidden" title="hidden">h</span>` : ""}</span></div>`;
}

// ─── Virtual scroll threshold ─────────────────────────────────────────────────

/** Rows above this count use virtual scrolling instead of rendering all rows. */
export const VIRTUAL_THRESHOLD = 500;

// ─── Sub-tab panel switcher ───────────────────────────────────────────────────

export interface SubTab {
  label: string;
  render: (panel: HTMLElement) => void;
  onActivate?: () => void;
}

export interface SubTabHandle {
  /** Update the visible label text of tab i (e.g. to show a filtered count). */
  updateLabel(i: number, label: string): void;
}

/**
 * Creates a section-nav tab switcher inside `container`.
 * Appends a nav bar with one button per tab, followed by one panel div per tab.
 * Only renders a panel's content the first time it becomes active (lazy rendering).
 */
export function createSubTabs(container: HTMLElement, tabs: SubTab[]): SubTabHandle {
  container.classList.add("has-section-nav");
  const nav = document.createElement("nav");
  nav.className = "section-nav";
  container.appendChild(nav);

  const panels: HTMLElement[] = [];
  const btns: HTMLButtonElement[] = [];
  const rendered = new Set<number>();

  for (const tab of tabs) {
    const btn = document.createElement("button");
    btn.className = "section-nav-link";
    btn.textContent = tab.label;
    nav.appendChild(btn);
    btns.push(btn);

    const panel = document.createElement("div");
    panel.style.display = "none";
    panels.push(panel);
    container.appendChild(panel);
  }

  function activate(i: number): void {
    if (btns[i].classList.contains("active")) return;
    for (let j = 0; j < tabs.length; j++) {
      btns[j].classList.toggle("active", j === i);
      panels[j].style.display = j === i ? "" : "none";
    }
    const sc = container.closest(".tab-content") as HTMLElement | null;
    if (sc) sc.scrollTop = 0;
    if (!rendered.has(i)) {
      rendered.add(i);
      tabs[i].render(panels[i]);
    }
    tabs[i].onActivate?.();
  }

  for (let i = 0; i < tabs.length; i++) {
    btns[i].addEventListener("click", () => activate(i));
  }
  if (tabs.length > 0) activate(0);

  return {
    updateLabel(i: number, label: string): void {
      if (btns[i]) btns[i].textContent = label;
    },
  };
}

// ─── ELF name conversion functions ───────────────────────────────────────────

/** Section header type → display name. */
export function shTypeName(t: SHType): string {
  switch (t) {
    case SHType.Null:
      return "NULL";
    case SHType.ProgBits:
      return "PROGBITS";
    case SHType.SymTab:
      return "SYMTAB";
    case SHType.StrTab:
      return "STRTAB";
    case SHType.Rela:
      return "RELA";
    case SHType.Hash:
      return "HASH";
    case SHType.Dynamic:
      return "DYNAMIC";
    case SHType.Note:
      return "NOTE";
    case SHType.NoBits:
      return "NOBITS";
    case SHType.Rel:
      return "REL";
    case SHType.ShLib:
      return "SHLIB";
    case SHType.DynSym:
      return "DYNSYM";
    case SHType.Relr:
      return "RELR";
    case SHType.InitArray:
      return "INIT_ARRAY";
    case SHType.FiniArray:
      return "FINI_ARRAY";
    case SHType.PreInitArray:
      return "PREINIT_ARRAY";
    case SHType.Group:
      return "GROUP";
    case SHType.SymTabShndx:
      return "SYMTAB_SHNDX";
    case SHType.GnuHash:
      return "GNU_HASH";
    case SHType.GnuVerNeed:
      return "VERNEED";
    case SHType.GnuVerDef:
      return "VERDEF";
    case SHType.GnuVerSym:
      return "VERSYM";
    default:
      return `0x${(t as number).toString(16).toUpperCase()}`;
  }
}

/** Program header type → display name. */
export function phTypeName(t: PHType): string {
  switch (t) {
    case PHType.Null:
      return "NULL";
    case PHType.Load:
      return "LOAD";
    case PHType.Dynamic:
      return "DYNAMIC";
    case PHType.Interp:
      return "INTERP";
    case PHType.Note:
      return "NOTE";
    case PHType.ShLib:
      return "SHLIB";
    case PHType.Phdr:
      return "PHDR";
    case PHType.Tls:
      return "TLS";
    case PHType.GnuEhFrame:
      return "GNU_EH_FRAME";
    case PHType.GnuStack:
      return "GNU_STACK";
    case PHType.GnuRelRo:
      return "GNU_RELRO";
    case PHType.GnuProperty:
      return "GNU_PROPERTY";
    default:
      return `0x${(t as number).toString(16).toUpperCase()}`;
  }
}

// Architecture-specific dynamic tag names (0x70000000+ range)
const AARCH64_DYN_TAGS: Record<number, string> = {
  0x70000001: "AARCH64_BTI_PLT",
  0x70000003: "AARCH64_PAC_PLT",
  0x70000005: "AARCH64_VARIANT_PCS",
  0x70000009: "AARCH64_MEMTAG_MODE",
  0x7000000b: "AARCH64_MEMTAG_HEAP",
  0x7000000d: "AARCH64_MEMTAG_STACK",
  0x7000000f: "AARCH64_MEMTAG_GLOBALS",
  0x70000011: "AARCH64_MEMTAG_GLOBALSSZ",
};

const X86_64_DYN_TAGS: Record<number, string> = {
  0x70000000: "X86_64_PLT",
  0x70000001: "X86_64_PLTSZ",
  0x70000003: "X86_64_PLTENT",
};

/** Dynamic section tag → display name. */
export function dynTagName(tag: DynTag, machine?: ELFMachine): string {
  switch (tag) {
    case DynTag.Null:
      return "NULL";
    case DynTag.Needed:
      return "NEEDED";
    case DynTag.PltRelSz:
      return "PLTRELSZ";
    case DynTag.PltGot:
      return "PLTGOT";
    case DynTag.Hash:
      return "HASH";
    case DynTag.StrTab:
      return "STRTAB";
    case DynTag.SymTab:
      return "SYMTAB";
    case DynTag.Rela:
      return "RELA";
    case DynTag.RelaSz:
      return "RELASZ";
    case DynTag.RelaEnt:
      return "RELAENT";
    case DynTag.StrSz:
      return "STRSZ";
    case DynTag.SymEnt:
      return "SYMENT";
    case DynTag.Init:
      return "INIT";
    case DynTag.Fini:
      return "FINI";
    case DynTag.SoName:
      return "SONAME";
    case DynTag.RPath:
      return "RPATH";
    case DynTag.Symbolic:
      return "SYMBOLIC";
    case DynTag.Rel:
      return "REL";
    case DynTag.RelSz:
      return "RELSZ";
    case DynTag.RelEnt:
      return "RELENT";
    case DynTag.PltRel:
      return "PLTREL";
    case DynTag.Debug:
      return "DEBUG";
    case DynTag.TextRel:
      return "TEXTREL";
    case DynTag.JmpRel:
      return "JMPREL";
    case DynTag.BindNow:
      return "BIND_NOW";
    case DynTag.InitArray:
      return "INIT_ARRAY";
    case DynTag.FiniArray:
      return "FINI_ARRAY";
    case DynTag.InitArraySz:
      return "INIT_ARRAYSZ";
    case DynTag.FiniArraySz:
      return "FINI_ARRAYSZ";
    case DynTag.RunPath:
      return "RUNPATH";
    case DynTag.Flags:
      return "FLAGS";
    case DynTag.GnuHash:
      return "GNU_HASH";
    case DynTag.VerSym:
      return "VERSYM";
    case DynTag.RelCount:
      return "RELCOUNT";
    case DynTag.RelaCount:
      return "RELACOUNT";
    case DynTag.VerDef:
      return "VERDEF";
    case DynTag.VerDefNum:
      return "VERDEFNUM";
    case DynTag.VerNeed:
      return "VERNEED";
    case DynTag.VerNeedNum:
      return "VERNEEDNUM";
    case DynTag.Flags1:
      return "FLAGS_1";
    case DynTag.RelrSz:
      return "RELRSZ";
    case DynTag.Relr:
      return "RELR";
    case DynTag.RelrEnt:
      return "RELRENT";
    default: {
      // Architecture-specific range (0x70000000+)
      const tagNum = tag as number;
      if (tagNum >= 0x70000000 && tagNum <= 0x7fffffff) {
        const archTable = machine === ELFMachine.AArch64 ? AARCH64_DYN_TAGS : X86_64_DYN_TAGS;
        const name = archTable[tagNum];
        if (name) return name;
      }
      return `0x${tagNum.toString(16).toUpperCase()}`;
    }
  }
}

// ─── Flag string helpers ───────────────────────────────────────────────────────

/** Section header flags → compact string (e.g. "WAX", "WA", returns "-" if none). */
export function shFlagsStr(f: bigint): string {
  let s = "";
  if (f & SHF_WRITE) s += "W";
  if (f & SHF_ALLOC) s += "A";
  if (f & SHF_EXECINSTR) s += "X";
  if (f & SHF_MERGE) s += "M";
  if (f & SHF_STRINGS) s += "S";
  if (f & SHF_GROUP) s += "G";
  if (f & SHF_TLS) s += "T";
  return s || "-";
}

/** Program header flags → "RWX"-style string (spaces for missing bits). */
export function phFlagsStr(f: number): string {
  return `${f & PF_R ? "R" : " "}${f & PF_W ? "W" : " "}${f & PF_X ? "E" : " "}`;
}

// ─── Formatting helpers ────────────────────────────────────────────────────────

/** Zero-padded hex string: `0x001A2B`. */
export function hexPad(n: number | bigint, pad: number): string {
  return `0x${n.toString(16).toUpperCase().padStart(pad, "0")}`;
}

/** Appends `<p class="empty-msg">text</p>` to container. */
export function appendEmptyMessage(container: HTMLElement, text: string): void {
  const p = document.createElement("p");
  p.className = "empty-msg";
  p.textContent = text;
  container.appendChild(p);
}

// ─── Program header navigation ────────────────────────────────────────────────

/** Maps a program header type to the view tab that displays its content. */
export function phNavTarget(t: PHType): NavTarget | null {
  switch (t) {
    case PHType.Dynamic:
      return "dynamic";
    case PHType.Note:
    case PHType.GnuProperty:
      return "notes";
    default:
      return null;
  }
}

// ─── PIE detection ────────────────────────────────────────────────────────────

/** Returns true if the ELF is a PIE executable (ET_DYN with DF_1_PIE set). */
export function isPIE(elf: ELFFile): boolean {
  if (elf.header.type !== ELFType.Dyn) return false;
  return elf.dynamicEntries.some(
    (e) => e.tag === DynTag.Flags1 && (e.value & BigInt(DF_1_PIE)) !== 0n
  );
}
