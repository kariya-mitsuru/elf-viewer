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
import {
  versionParts,
  verNumCellHtml,
  VIRTUAL_THRESHOLD,
  createSubTabs,
  appendEmptyMessage,
  hexPad,
} from "./viewUtils.ts";
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
// Returns a setFilter function that replaces the displayed rows with a filtered subset.
function renderVirtualTable(
  container: HTMLElement,
  syms: Symbol[],
  versionInfo: VersionInfo | null,
  is64: boolean,
  initialFilter: string
): (term: string) => void {
  const padW = is64 ? 16 : 8;

  function buildRow(filtered: Symbol[], i: number): HTMLTableRowElement {
    const sym = filtered[i];
    const [ndx, section] = ndxParts(sym);
    const [verName, verNum, hidden] = versionParts(sym.index, versionInfo);
    const verNumCell = verNumCellHtml(verNum, hidden);
    const tr = document.createElement("tr");
    if (i % 2 === 0) tr.className = "vs-even";
    tr.innerHTML = `
      <td class="mono sym-right">${sym.index}</td>
      <td class="mono">${hexPad(sym.value, padW)}</td>
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
  }

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

  function applyFilter(term: string): Symbol[] {
    const lower = term.toLowerCase();
    return term ? syms.filter((s) => s.name.toLowerCase().includes(lower)) : syms;
  }

  let filtered = applyFilter(initialFilter);
  const handle = attachVirtualScroll(
    table,
    filtered.length,
    (i) => buildRow(filtered, i),
    () => container.style.display !== "none"
  );

  return (term: string) => {
    filtered = applyFilter(term);
    handle.update(filtered.length, (i) => buildRow(filtered, i));
  };
}

// Returns a setFilter function that updates the table when the search term changes.
function renderSymbolTable(
  container: HTMLElement,
  title: string,
  syms: Symbol[],
  versionInfo: VersionInfo | null,
  id: string,
  initialFilter: string
): (term: string) => void {
  const h3 = document.createElement("h3");
  h3.id = id;
  h3.className = "view-subtitle";
  h3.textContent = `${title} (${syms.length} symbols)`;
  container.appendChild(h3);

  if (syms.length === 0) {
    appendEmptyMessage(container, "No symbols");
    return () => {};
  }

  const is64 = syms.some((s) => s.value > 0xffffffffn);

  if (syms.length > VIRTUAL_THRESHOLD) {
    return renderVirtualTable(container, syms, versionInfo, is64, initialFilter);
  }

  // Static table path (small tables).
  const table = document.createElement("table");
  table.className = "data-table symbol-table";
  table.innerHTML = `
    <thead><tr>
      <th class="sym-right">Num</th><th>Value</th><th class="sym-right">Size</th><th>Type</th><th>Bind</th><th>Vis</th>
      <th>Ndx</th><th>Section</th><th>Name</th><th>Version</th><th>Ver#</th>
    </tr></thead>
  `;
  const tbody = document.createElement("tbody");
  table.appendChild(tbody);
  container.appendChild(table);

  const noResultMsg = document.createElement("p");
  noResultMsg.className = "empty-msg search-no-result";
  noResultMsg.textContent = "No matching symbols";
  noResultMsg.style.display = "none";
  container.appendChild(noResultMsg);

  const padW = is64 ? 16 : 8;

  function buildStaticRows(filtered: Symbol[]): void {
    tbody.innerHTML = "";
    for (const sym of filtered) {
      const [ndx, section] = ndxParts(sym);
      const [verName, verNum, hidden] = versionParts(sym.index, versionInfo);
      const verNumCell = verNumCellHtml(verNum, hidden);
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono sym-right">${sym.index}</td>
        <td class="mono">${hexPad(sym.value, padW)}</td>
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
    noResultMsg.style.display = filtered.length === 0 ? "" : "none";
  }

  buildStaticRows(
    initialFilter
      ? syms.filter((s) => s.name.toLowerCase().includes(initialFilter.toLowerCase()))
      : syms
  );

  return (term: string) => {
    const lower = term.toLowerCase();
    const filtered = term ? syms.filter((s) => s.name.toLowerCase().includes(lower)) : syms;
    buildStaticRows(filtered);
  };
}

export function renderSymbols(container: HTMLElement, elf: ELFFile): void {
  container.innerHTML = '<h2 class="view-title">Symbol Tables</h2>';

  const tables = [
    { name: ".symtab", id: "sym-symtab", syms: elf.symbols, versionInfo: null },
    { name: ".dynsym", id: "sym-dynsym", syms: elf.dynSymbols, versionInfo: elf.versionInfo },
  ].filter((t) => t.syms.length > 0);

  if (tables.length === 0) {
    appendEmptyMessage(container, "No symbol tables");
    return;
  }

  // Single search box shared across all sub-tabs.
  // Set up filter state before createSubTabs so the lazy render callbacks
  // can capture currentFilter from the closure.
  let currentFilter = "";
  const panelUpdaters: Array<((term: string) => void) | null> = tables.map(() => null);

  // Sub-tab switcher (always, even for a single table — consistent appearance).
  // createSubTabs immediately renders the first panel (activate(0)), so
  // currentFilter must already be set before this call.
  const subtabs = createSubTabs(
    container,
    tables.map((t, i) => ({
      label: `${t.name} (${t.syms.length})`,
      render: (p: HTMLElement) => {
        const setFilter = renderSymbolTable(p, t.name, t.syms, t.versionInfo, t.id, currentFilter);
        panelUpdaters[i] = setFilter;
      },
    }))
  );

  // Append search input to the section-nav so it lives in the same sticky bar.
  const nav = container.querySelector<HTMLElement>(".section-nav");
  if (nav) {
    const searchInput = document.createElement("input");
    searchInput.type = "search";
    searchInput.className = "search-input";
    searchInput.placeholder = "Filter by name…";
    searchInput.setAttribute("aria-label", "Filter symbols by name");
    searchInput.addEventListener("input", () => {
      currentFilter = searchInput.value;
      const lower = currentFilter.toLowerCase();
      for (let i = 0; i < tables.length; i++) {
        panelUpdaters[i]?.(currentFilter);
        const t = tables[i];
        if (currentFilter) {
          const n = t.syms.filter((s) => s.name.toLowerCase().includes(lower)).length;
          subtabs.updateLabel(i, `${t.name} (${n} / ${t.syms.length})`);
        } else {
          subtabs.updateLabel(i, `${t.name} (${t.syms.length})`);
        }
      }
    });
    nav.appendChild(searchInput);
  }
}
