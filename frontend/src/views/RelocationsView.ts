// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Relocations view: renders relocation entries (readelf -r).

import {
  type ELFFile,
  type RelocationEntry,
  type RelocationSection,
  type VersionInfo,
} from "../parser/types.ts";
import {
  versionParts,
  verNumCellHtml,
  VIRTUAL_THRESHOLD,
  createSubTabs,
  appendEmptyMessage,
} from "./viewUtils.ts";
import { attachVirtualScroll } from "./virtualScroll.ts";

// Architecture-specific relocation type names (x86-64)
const R_X86_64: Record<number, string> = {
  0: "R_X86_64_NONE",
  1: "R_X86_64_64",
  2: "R_X86_64_PC32",
  3: "R_X86_64_GOT32",
  4: "R_X86_64_PLT32",
  5: "R_X86_64_COPY",
  6: "R_X86_64_GLOB_DAT",
  7: "R_X86_64_JUMP_SLOT",
  8: "R_X86_64_RELATIVE",
  9: "R_X86_64_GOTPCREL",
  10: "R_X86_64_32",
  11: "R_X86_64_32S",
  12: "R_X86_64_16",
  13: "R_X86_64_PC16",
  14: "R_X86_64_8",
  15: "R_X86_64_PC8",
  16: "R_X86_64_DTPMOD64",
  17: "R_X86_64_DTPOFF64",
  18: "R_X86_64_TPOFF64",
  19: "R_X86_64_TLSGD",
  20: "R_X86_64_TLSLD",
  21: "R_X86_64_DTPOFF32",
  22: "R_X86_64_GOTTPOFF",
  23: "R_X86_64_TPOFF32",
  24: "R_X86_64_PC64",
  25: "R_X86_64_GOTOFF64",
  26: "R_X86_64_GOTPC32",
  27: "R_X86_64_GOT64",
  28: "R_X86_64_GOTPCREL64",
  29: "R_X86_64_GOTPC64",
  30: "R_X86_64_GOTPLT64",
  31: "R_X86_64_PLTOFF64",
  32: "R_X86_64_SIZE32",
  33: "R_X86_64_SIZE64",
  34: "R_X86_64_GOTPC32_TLSDESC",
  35: "R_X86_64_TLSDESC_CALL",
  36: "R_X86_64_TLSDESC",
  37: "R_X86_64_IRELATIVE",
  38: "R_X86_64_RELATIVE64",
  41: "R_X86_64_GOTPCRELX",
  42: "R_X86_64_REX_GOTPCRELX",
};

function relocTypeName(type: number): string {
  return R_X86_64[type] ?? `type(${type})`;
}

// Virtual-scroll renderer for relocation entries.
function renderVirtualRelocationTable(
  container: HTMLElement,
  entries: RelocationEntry[],
  usesDynSym: boolean,
  versionInfo: VersionInfo | null,
  is64: boolean,
  hasAddend: boolean
): void {
  const padW = is64 ? 16 : 8;

  const table = document.createElement("table");
  table.className = "data-table reloc-virtual";
  table.innerHTML = `
    <thead><tr>
      <th>Offset</th><th>Info</th><th>Type</th><th>Sym. Value</th><th>Sym. Name</th>
      <th>Version</th><th>Ver#</th>
      ${hasAddend ? '<th class="sym-right">Addend</th>' : ""}
    </tr></thead>
    <tbody></tbody>
  `;
  container.appendChild(table);

  attachVirtualScroll(
    table,
    entries.length,
    (i) => {
      const r = entries[i];
      const [verName, verNum, hidden] = usesDynSym
        ? versionParts(r.symIndex, versionInfo)
        : ["", "", false];
      const verNumCell = verNumCellHtml(verNum, hidden);
      const addendStr =
        r.addend !== null && r.addend !== 0n
          ? r.addend > 0n
            ? `+0x${r.addend.toString(16)}`
            : `-0x${(-r.addend).toString(16)}`
          : "";
      const addendCell = hasAddend ? `<td class="mono sym-right">${addendStr}</td>` : "";
      const tr = document.createElement("tr");
      if (i % 2 === 0) tr.className = "vs-even";
      tr.innerHTML = `
        <td class="mono">0x${r.offset.toString(16).toUpperCase().padStart(padW, "0")}</td>
        <td class="mono">${r.symIndex.toString(16).padStart(8, "0")}${r.type.toString(16).padStart(8, "0")}</td>
        <td class="mono">${relocTypeName(r.type)}</td>
        <td class="mono">${r.symValue ? `0x${r.symValue.toString(16).toUpperCase().padStart(padW, "0")}` : ""}</td>
        <td class="mono">${r.symName}</td>
        <td class="mono sym-version">${verName}</td>
        <td class="mono">${verNumCell}</td>
        ${addendCell}
      `;
      return tr;
    },
    () => container.style.display !== "none"
  );
}

function renderRelocationSection(
  container: HTMLElement,
  section: RelocationSection,
  versionInfo: VersionInfo | null,
  is64: boolean,
  hasAddend: boolean
): void {
  if (section.entries.length === 0) {
    appendEmptyMessage(container, "No entries");
    return;
  }

  if (section.entries.length > VIRTUAL_THRESHOLD) {
    renderVirtualRelocationTable(
      container,
      section.entries,
      section.usesDynSym,
      versionInfo,
      is64,
      hasAddend
    );
    return;
  }

  const padW = is64 ? 16 : 8;
  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead><tr>
      <th>Offset</th><th>Info</th><th>Type</th><th>Sym. Value</th><th>Sym. Name</th>
      <th>Version</th><th>Ver#</th>
      ${hasAddend ? '<th class="sym-right">Addend</th>' : ""}
    </tr></thead>
  `;
  const tbody = document.createElement("tbody");
  for (const r of section.entries) {
    const [verName, verNum, hidden] = section.usesDynSym
      ? versionParts(r.symIndex, versionInfo)
      : ["", "", false];
    const verNumCell = verNumCellHtml(verNum, hidden);
    const addendStr =
      r.addend !== null && r.addend !== 0n
        ? r.addend > 0n
          ? `+0x${r.addend.toString(16)}`
          : `-0x${(-r.addend).toString(16)}`
        : "";
    const addendCell = hasAddend ? `<td class="mono sym-right">${addendStr}</td>` : "";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">0x${r.offset.toString(16).toUpperCase().padStart(padW, "0")}</td>
      <td class="mono">${r.symIndex.toString(16).padStart(8, "0")}${r.type.toString(16).padStart(8, "0")}</td>
      <td class="mono">${relocTypeName(r.type)}</td>
      <td class="mono">${r.symValue ? `0x${r.symValue.toString(16).toUpperCase().padStart(padW, "0")}` : ""}</td>
      <td class="mono">${r.symName}</td>
      <td class="mono sym-version">${verName}</td>
      <td class="mono">${verNumCell}</td>
      ${addendCell}
    `;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

export function renderRelocations(container: HTMLElement, elf: ELFFile): void {
  const sections = elf.relocations;
  const total = sections.reduce((n, s) => n + s.entries.length, 0);
  container.innerHTML = `<h2 class="view-title">Relocations (${total} total)</h2>`;

  if (sections.length === 0) {
    const p = document.createElement("p");
    p.className = "empty-msg";
    p.textContent = "No relocations";
    container.appendChild(p);
    return;
  }

  const is64 = sections.some((s) => s.entries.some((r) => r.offset > 0xffffffffn));
  const hasAddend = sections.some((s) => s.entries.some((r) => r.addend !== null));
  const versionInfo = elf.versionInfo;

  // Sub-tab switcher — one tab per relocation section
  createSubTabs(
    container,
    sections.map((s) => ({
      label: `${s.name} (${s.entries.length})`,
      render: (p: HTMLElement) => renderRelocationSection(p, s, versionInfo, is64, hasAddend),
    }))
  );
}
