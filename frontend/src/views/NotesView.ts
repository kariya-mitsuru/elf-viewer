// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Notes view: renders NOTE sections (readelf -n).

import { type ELFFile, type Note } from "../parser/types.ts";
import { type Reader } from "../parser/reader.ts";
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

function formatOneGnuProperty(type: number, datasz: number, data: Reader): string {
  const u32 = () => (datasz >= 4 ? data.u32(0) : 0);

  switch (type) {
    case 0x00000001: {
      // GNU_PROPERTY_STACK_SIZE
      const sz = datasz >= 8 ? data.u64(0) : BigInt(datasz >= 4 ? data.u32(0) : 0);
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
      const n = Math.min(data.view.byteLength, 8);
      const hex = Array.from({ length: n }, (_, i) =>
        data.u8(i).toString(16).padStart(2, "0")
      ).join(" ");
      return `type 0x${type.toString(16)}: ${hex}${data.view.byteLength > 8 ? " ..." : ""}`;
    }
  }
}

function formatGnuProperties(r: Reader): string {
  const align = r.is64 ? 8 : 4;
  const lines: string[] = [];
  let off = 0;
  while (off + 8 <= r.view.byteLength) {
    const type = r.u32(off);
    const datasz = r.u32(off + 4);
    off += 8;
    const actualSz = Math.min(datasz, r.view.byteLength - off);
    const data = r.slice(off, actualSz);
    off += (datasz + align - 1) & ~(align - 1);
    lines.push(formatOneGnuProperty(type, datasz, data));
  }
  return lines.join("<br>");
}

// ── NT_STAPSDT parser ─────────────────────────────────────────────────────

const _td = new TextDecoder();

function formatStapsdtDesc(r: Reader): string {
  const ptrSize = r.is64 ? 8 : 4;
  if (r.view.byteLength < ptrSize * 3) return "(too short)";

  const pc = r.addr(0);
  const base = r.addr(ptrSize);
  const semaphore = r.addr(ptrSize * 2);

  // Read three consecutive NUL-terminated strings
  let off = ptrSize * 3;
  const readStr = (): string => {
    const start = off;
    while (off < r.view.byteLength && r.u8(off) !== 0) off++;
    const s = _td.decode(new Uint8Array(r.view.buffer, r.view.byteOffset + start, off - start));
    off++; // skip NUL
    return s;
  };
  const provider = readStr();
  const probe = readStr();
  const args = readStr();

  const padW = r.is64 ? 16 : 8;
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

function formatNoteDesc(note: Note, r: Reader): string {
  const { name, type } = note;
  if (name === "GNU") {
    if (type === 3 && r.view.byteLength > 0) {
      // Build ID
      return Array.from({ length: r.view.byteLength }, (_, i) =>
        r.u8(i).toString(16).padStart(2, "0")
      ).join("");
    }
    if (type === 1 && r.view.byteLength >= 16) {
      const os = r.u32(0);
      const major = r.u32(4);
      const minor = r.u32(8);
      const patch = r.u32(12);
      const osNames: Record<number, string> = { 0: "Linux", 1: "Hurd", 2: "Solaris", 3: "FreeBSD" };
      return `OS: ${osNames[os] ?? os}, ABI: ${major}.${minor}.${patch}`;
    }
  }
  // Hex dump for unknown
  if (r.view.byteLength === 0) return "(empty)";
  const n = Math.min(r.view.byteLength, 32);
  const hex = Array.from({ length: n }, (_, i) => r.u8(i).toString(16).padStart(2, "0")).join(" ");
  return r.view.byteLength <= 32 ? hex : hex + ` ... (${r.view.byteLength} bytes)`;
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
        <td class="mono">0x${note.desc.view.byteLength.toString(16).padStart(8, "0")}</td>
        <td class="mono">${noteTypeName(note.name, note.type)}</td>
        <td class="${descClass}">${descHtml}</td>
      `;
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    container.appendChild(table);
  }
}
