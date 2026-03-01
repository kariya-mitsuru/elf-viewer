// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Symbols view: renders symbol tables (readelf -s / --extra-sym-info).

import {
  type ELFFile,
  type Symbol,
  type VersionInfo,
  STBind,
  STType,
  STVisibility,
  SHN_UNDEF,
  SHN_ABS,
  SHN_COMMON,
} from "../parser/types.ts";
import { versionParts, verNumCellHtml, VIRTUAL_THRESHOLD, createSubTabs } from "./viewUtils.ts";
import { attachVirtualScroll } from "./virtualScroll.ts";

function bindName(b: STBind): string {
  switch (b) {
    case STBind.Local:
      return "LOCAL";
    case STBind.Global:
      return "GLOBAL";
    case STBind.Weak:
      return "WEAK";
    case STBind.GnuUnique:
      return "UNIQUE";
    default:
      return `${b}`;
  }
}

function typeName(t: STType): string {
  switch (t) {
    case STType.NoType:
      return "NOTYPE";
    case STType.Object:
      return "OBJECT";
    case STType.Func:
      return "FUNC";
    case STType.Section:
      return "SECTION";
    case STType.File:
      return "FILE";
    case STType.Common:
      return "COMMON";
    case STType.Tls:
      return "TLS";
    case STType.GnuIfunc:
      return "IFUNC";
    default:
      return `${t}`;
  }
}

function visName(v: STVisibility): string {
  switch (v) {
    case STVisibility.Default:
      return "DEFAULT";
    case STVisibility.Internal:
      return "INTERNAL";
    case STVisibility.Hidden:
      return "HIDDEN";
    case STVisibility.Protected:
      return "PROTECTED";
    default:
      return `${v}`;
  }
}

// Ndx and section name as separate values.
function ndxParts(sym: Symbol): [string, string] {
  if (sym.shndx === SHN_UNDEF) return ["UND", ""];
  if (sym.shndx === SHN_ABS) return ["ABS", ""];
  if (sym.shndx === SHN_COMMON) return ["COM", ""];
  if (sym.sectionName) return [String(sym.shndx), sym.sectionName];
  return [String(sym.shndx), ""];
}

// Virtual-scroll renderer: only the visible rows (+ a buffer) are in the DOM.
// Scrolling is handled by the parent .tab-content element (no nested scrollbar).
function renderVirtualTable(
  container: HTMLElement,
  syms: Symbol[],
  versionInfo: VersionInfo | null,
  is64: boolean
): void {
  const padW = is64 ? 16 : 8;

  const table = document.createElement("table");
  table.className = "data-table symbol-table symbol-virtual";
  table.innerHTML = `
    <thead><tr>
      <th class="sym-right">Num</th><th>Value</th><th class="sym-right">Size</th><th>Type</th><th>Bind</th><th>Vis</th>
      <th>Ndx</th><th>Section</th><th>Name</th><th>Version</th><th>Ver#</th>
    </tr></thead>
    <tbody></tbody>
  `;
  container.appendChild(table);

  attachVirtualScroll(
    table,
    syms.length,
    (i) => {
      const sym = syms[i];
      const [ndx, section] = ndxParts(sym);
      const [verName, verNum, hidden] = versionParts(sym.index, versionInfo);
      const verNumCell = verNumCellHtml(verNum, hidden);
      const tr = document.createElement("tr");
      if (i % 2 === 0) tr.className = "vs-even";
      tr.innerHTML = `
        <td class="mono sym-right">${sym.index}</td>
        <td class="mono">0x${sym.value.toString(16).toUpperCase().padStart(padW, "0")}</td>
        <td class="mono sym-right">${sym.size}</td>
        <td class="mono">${typeName(sym.type)}</td>
        <td class="mono">${bindName(sym.bind)}</td>
        <td class="mono">${visName(sym.visibility)}</td>
        <td class="mono ndx-cell">${ndx}</td>
        <td class="mono">${section}</td>
        <td class="mono sym-name">${sym.name || ""}</td>
        <td class="mono sym-version">${verName}</td>
        <td class="mono">${verNumCell}</td>
      `;
      return tr;
    },
    () => container.style.display !== "none"
  );
}

function renderSymbolTable(
  container: HTMLElement,
  title: string,
  syms: Symbol[],
  versionInfo: VersionInfo | null,
  id: string,
  showTitle = true
): void {
  if (showTitle) {
    const h3 = document.createElement("h3");
    h3.id = id;
    h3.className = "view-subtitle";
    h3.textContent = `${title} (${syms.length} symbols)`;
    container.appendChild(h3);
  }

  if (syms.length === 0) {
    const p = document.createElement("p");
    p.className = "empty-msg";
    p.textContent = "No symbols";
    container.appendChild(p);
    return;
  }

  const is64 = syms.some((s) => s.value > 0xffffffffn);

  if (syms.length > VIRTUAL_THRESHOLD) {
    renderVirtualTable(container, syms, versionInfo, is64);
    return;
  }

  const table = document.createElement("table");
  table.className = "data-table symbol-table";
  table.innerHTML = `
    <thead><tr>
      <th class="sym-right">Num</th><th>Value</th><th class="sym-right">Size</th><th>Type</th><th>Bind</th><th>Vis</th>
      <th>Ndx</th><th>Section</th><th>Name</th><th>Version</th><th>Ver#</th>
    </tr></thead>
  `;
  const tbody = document.createElement("tbody");
  const padW = is64 ? 16 : 8;
  for (const sym of syms) {
    const [ndx, section] = ndxParts(sym);
    const [verName, verNum, hidden] = versionParts(sym.index, versionInfo);
    const verNumCell = verNumCellHtml(verNum, hidden);
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono sym-right">${sym.index}</td>
      <td class="mono">0x${sym.value.toString(16).toUpperCase().padStart(padW, "0")}</td>
      <td class="mono sym-right">${sym.size}</td>
      <td class="mono">${typeName(sym.type)}</td>
      <td class="mono">${bindName(sym.bind)}</td>
      <td class="mono">${visName(sym.visibility)}</td>
      <td class="mono ndx-cell">${ndx}</td>
      <td class="mono">${section}</td>
      <td class="mono sym-name">${sym.name || ""}</td>
      <td class="mono sym-version">${verName}</td>
      <td class="mono">${verNumCell}</td>
    `;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

export function renderSymbols(container: HTMLElement, elf: ELFFile): void {
  container.innerHTML = '<h2 class="view-title">Symbol Tables</h2>';

  const tables = [
    { name: ".symtab", id: "sym-symtab", syms: elf.symbols, versionInfo: null },
    { name: ".dynsym", id: "sym-dynsym", syms: elf.dynSymbols, versionInfo: elf.versionInfo },
  ].filter((t) => t.syms.length > 0);

  if (tables.length === 0) {
    const p = document.createElement("p");
    p.className = "empty-msg";
    p.textContent = "No symbol tables";
    container.appendChild(p);
    return;
  }

  // Sub-tab switcher (always, even for a single table — consistent appearance)
  createSubTabs(
    container,
    tables.map((t) => ({
      label: `${t.name} (${t.syms.length})`,
      render: (p: HTMLElement) => renderSymbolTable(p, t.name, t.syms, t.versionInfo, t.id, false),
    }))
  );
}
