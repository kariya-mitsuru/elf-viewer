// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Notes view: renders NOTE sections (readelf -n).

import { type ELFFile, type Note } from "../parser/types.ts";
import { type Cursor } from "../parser/reader.ts";
import { slugId, renderSectionNav } from "../ui/SectionNav.ts";
import { appendEmptyMessage } from "./viewUtils.ts";

// GNU note types
const GNU_NOTE_TYPE: Record<number, string> = {
  1: "NT_GNU_ABI_TAG",
  2: "NT_GNU_HWCAP",
  3: "NT_GNU_BUILD_ID",
  4: "NT_GNU_GOLD_VERSION",
  5: "NT_GNU_PROPERTY_TYPE_0",
};

// stapsdt note types
const STAPSDT_NOTE_TYPE: Record<number, string> = {
  3: "NT_STAPSDT",
};

// ── NT_GNU_PROPERTY_TYPE_0 parser ─────────────────────────────────────────

function fmtX86Isa1(bits: number): string {
  const levels = ["x86-64-baseline", "x86-64-v2", "x86-64-v3", "x86-64-v4"];
  const out: string[] = [];
  for (let i = 0; i < levels.length; i++) if (bits & (1 << i)) out.push(levels[i]);
  return out.length ? out.join(", ") : `0x${bits.toString(16)}`;
}

function fmtX86CompatIsa1(bits: number): string {
  const names = [
    "i486",
    "i586",
    "i686",
    "SSE",
    "SSE2",
    "SSE3",
    "SSSE3",
    "SSE4.1",
    "SSE4.2",
    "AVX",
    "AVX2",
    "AVX512F",
    "AVX512CD",
    "AVX512ER",
    "AVX512PF",
    "AVX512VL",
    "AVX512DQ",
    "AVX512BW",
  ];
  const out: string[] = [];
  for (let i = 0; i < names.length; i++) if (bits & (1 << i)) out.push(names[i]);
  return out.length ? out.join(", ") : `0x${bits.toString(16)}`;
}

function fmtX86Feature2(bits: number): string {
  const names = [
    "x86",
    "x87",
    "MMX",
    "XMM",
    "YMM",
    "ZMM",
    "FXSR",
    "XSAVE",
    "XSAVEOPT",
    "XSAVEC",
    "TMM",
    "MASK",
  ];
  const out: string[] = [];
  for (let i = 0; i < names.length; i++) if (bits & (1 << i)) out.push(names[i]);
  return out.length ? out.join(", ") : `0x${bits.toString(16)}`;
}

function formatOneGnuProperty(type: number, datasz: number, data: Cursor): string {
  const u32 = () => (datasz >= 4 ? data.u32() : 0);

  switch (type) {
    case 0x00000001: {
      // GNU_PROPERTY_STACK_SIZE
      const sz = datasz >= 8 ? data.u64() : BigInt(datasz >= 4 ? data.u32() : 0);
      return `stack size: 0x${sz.toString(16)}`;
    }
    case 0x00000002:
      return "no copy on protected";
    case 0x00000004:
      return "memory seal";

    case 0xc0000000: {
      // GNU_PROPERTY_AARCH64_FEATURE_1_AND
      const bits = u32();
      const flags: string[] = [];
      if (bits & 0x1) flags.push("BTI");
      if (bits & 0x2) flags.push("PAC");
      return `AArch64 feature: ${flags.length ? flags.join(", ") : `0x${bits.toString(16)}`}`;
    }
    case 0xc0000002: {
      // GNU_PROPERTY_X86_FEATURE_1_AND
      const bits = u32();
      const flags: string[] = [];
      if (bits & 0x1) flags.push("IBT");
      if (bits & 0x2) flags.push("SHSTK");
      if (bits & 0x4) flags.push("LAM_U48");
      if (bits & 0x8) flags.push("LAM_U57");
      return `x86 feature: ${flags.length ? flags.join(", ") : `0x${bits.toString(16)}`}`;
    }
    case 0xc0008000:
      return `x86 feature2 needed: ${fmtX86Feature2(u32())}`; // GNU_PROPERTY_X86_FEATURE_2_NEEDED
    case 0xc0008001:
      return `x86 ISA compat needed: ${fmtX86CompatIsa1(u32())}`; // GNU_PROPERTY_X86_COMPAT_ISA_1_NEEDED
    case 0xc0008002:
      return `x86 ISA needed: ${fmtX86Isa1(u32())}`; // GNU_PROPERTY_X86_ISA_1_NEEDED
    case 0xc0010000:
      return `x86 feature2 used: ${fmtX86Feature2(u32())}`; // GNU_PROPERTY_X86_FEATURE_2_USED
    case 0xc0010001:
      return `x86 ISA compat used: ${fmtX86CompatIsa1(u32())}`; // GNU_PROPERTY_X86_COMPAT_ISA_1_USED
    case 0xc0010002:
      return `x86 ISA used: ${fmtX86Isa1(u32())}`; // GNU_PROPERTY_X86_ISA_1_USED

    default: {
      const n = Math.min(data.length, 8);
      const hex = Array.from({ length: n }, () =>
        data.u8().toString(16).padStart(2, "0")
      ).join(" ");
      return `type 0x${type.toString(16)}: ${hex}${data.length > 8 ? " ..." : ""}`;
    }
  }
}

function formatGnuProperties(c: Cursor): string {
  const align = c.is64 ? 8 : 4;
  const lines: string[] = [];
  while (c.remaining >= 8) {
    const type = c.u32();
    const datasz = c.u32();
    const actualSz = Math.min(datasz, c.remaining);
    const data = c.sub(actualSz);
    c.skip((datasz + align - 1) & ~(align - 1));
    lines.push(formatOneGnuProperty(type, datasz, data));
  }
  return lines.join("<br>");
}

// ── NT_STAPSDT parser ─────────────────────────────────────────────────────

function formatStapsdtDesc(c: Cursor): string {
  const ptrSize = c.is64 ? 8 : 4;
  if (c.length < ptrSize * 3) return "(too short)";

  const pc = c.addr();
  const base = c.addr();
  const semaphore = c.addr();

  const provider = c.cstring();
  const probe = c.cstring();
  const args = c.cstring();

  const padW = c.is64 ? 16 : 8;
  const h = (v: bigint) => `0x${v.toString(16).padStart(padW, "0")}`;
  const lines: string[] = [
    `${provider}::${probe}`,
    `location: ${h(pc)}  base: ${h(base)}` +
      (semaphore !== 0n ? `  semaphore: ${h(semaphore)}` : ""),
  ];
  if (args) lines.push(`args: ${args}`);
  return lines.join("<br>");
}

// ── Generic note description ───────────────────────────────────────────────

function formatNoteDesc(note: Note, c: Cursor): string {
  const { name, type } = note;
  if (name === "GNU") {
    if (type === 3 && c.length > 0) {
      // Build ID
      return Array.from({ length: c.length }, () =>
        c.u8().toString(16).padStart(2, "0")
      ).join("");
    }
    if (type === 1 && c.length >= 16) {
      const os = c.u32();
      const major = c.u32();
      const minor = c.u32();
      const patch = c.u32();
      const osNames: Record<number, string> = { 0: "Linux", 1: "Hurd", 2: "Solaris", 3: "FreeBSD" };
      return `OS: ${osNames[os] ?? os}, ABI: ${major}.${minor}.${patch}`;
    }
  }
  // Hex dump for unknown
  if (c.length === 0) return "(empty)";
  const n = Math.min(c.length, 32);
  const hex = Array.from({ length: n }, () => c.u8().toString(16).padStart(2, "0")).join(" ");
  return c.length <= 32 ? hex : hex + ` ... (${c.length} bytes)`;
}

function noteTypeName(name: string, type: number): string {
  if (name === "GNU") return GNU_NOTE_TYPE[type] ?? `NT_UNKNOWN(${type})`;
  if (name === "stapsdt") return STAPSDT_NOTE_TYPE[type] ?? `type(${type})`;
  return `type(${type})`;
}

export function renderNotes(container: HTMLElement, elf: ELFFile): void {
  const notes = elf.notes;
  container.innerHTML = `<h2 class="view-title">Notes (${notes.length})</h2>`;

  if (notes.length === 0) {
    appendEmptyMessage(container, "No notes");
    return;
  }

  // Group by section
  const bySec = new Map<string, Note[]>();
  for (const n of notes) {
    if (!bySec.has(n.sectionName)) bySec.set(n.sectionName, []);
    bySec.get(n.sectionName)!.push(n);
  }

  renderSectionNav(
    container,
    Array.from(bySec.keys()).map((name) => ({
      id: slugId("note", name),
      label: `${name} (${bySec.get(name)!.length})`,
    }))
  );

  for (const [secName, secNotes] of bySec) {
    const h3 = document.createElement("h3");
    h3.id = slugId("note", secName);
    h3.className = "view-subtitle";
    h3.textContent = `Notes in section '${secName}':`;
    container.appendChild(h3);

    const table = document.createElement("table");
    table.className = "data-table";
    table.innerHTML = `<thead><tr><th>Owner</th><th>Data size</th><th>Type</th><th>Description</th></tr></thead>`;
    const tbody = document.createElement("tbody");
    for (const note of secNotes) {
      const isProperty = note.name === "GNU" && note.type === 5;
      const isStapsdt = note.name === "stapsdt" && note.type === 3;
      const descHtml = isProperty
        ? formatGnuProperties(note.desc)
        : isStapsdt
          ? formatStapsdtDesc(note.desc)
          : formatNoteDesc(note, note.desc);
      const descClass = isProperty || isStapsdt ? "mono note-property-desc" : "mono note-desc";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${note.name}</td>
        <td class="mono">0x${note.desc.length.toString(16).padStart(8, "0")}</td>
        <td class="mono">${noteTypeName(note.name, note.type)}</td>
        <td class="${descClass}">${descHtml}</td>
      `;
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    container.appendChild(table);
  }
}
