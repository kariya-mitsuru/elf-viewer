// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Symbols view: renders symbol tables (readelf -s / --extra-sym-info).

import {
  type ELFFile,
  type Symbol,
  type VersionInfo,
  SHN_UNDEF,
  SHN_ABS,
  SHN_COMMON,
} from "../parser/types.ts";
import {
  versionParts,
  verNumCellHtml,
  VIRTUAL_THRESHOLD,
  createSubTabs,
  createSearchInput,
  appendEmptyMessage,
  hexPad,
  stBindName,
  stTypeName,
  stVisName,
} from "./viewUtils.ts";
import { attachVirtualScroll } from "./virtualScroll.ts";

// Ndx and section name as separate values.
function ndxParts(sym: Symbol): [string, string] {
  if (sym.shndx === SHN_UNDEF) {
    return ["UND", ""];
  }
  if (sym.shndx === SHN_ABS) {
    return ["ABS", ""];
  }
  if (sym.shndx === SHN_COMMON) {
    return ["COM", ""];
  }
  if (sym.sectionName) {
    return [String(sym.shndx), sym.sectionName];
  }
  return [String(sym.shndx), ""];
}

const symbolHeaderHtml = `
  <thead><tr>
    <th class="sym-right">Num</th><th>Value</th><th class="sym-right">Size</th><th>Type</th><th>Bind</th><th>Vis</th>
    <th>Ndx</th><th>Section</th><th>Name</th><th>Version</th><th>Ver#</th>
  </tr></thead>
`;

function createSymbolRow(
  sym: Symbol,
  versionInfo: VersionInfo | null,
  padW: number
): HTMLTableRowElement {
  const [ndx, section] = ndxParts(sym);
  const [verName, verNum, hidden] = versionParts(sym.index, versionInfo);
  const verNumCell = verNumCellHtml(verNum, hidden);
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td class="mono sym-right">${sym.index}</td>
    <td class="mono">${hexPad(sym.value, padW)}</td>
    <td class="mono sym-right">${sym.size}</td>
    <td class="mono">${stTypeName(sym.type)}</td>
    <td class="mono">${stBindName(sym.bind)}</td>
    <td class="mono">${stVisName(sym.visibility)}</td>
    <td class="mono ndx-cell">${ndx}</td>
    <td class="mono">${section}</td>
    <td class="mono sym-name">${sym.name || ""}</td>
    <td class="mono sym-version">${verName}</td>
    <td class="mono">${verNumCell}</td>
  `;
  return tr;
}

function applySymbolFilter(syms: Symbol[], term: string): Symbol[] {
  const lower = term.toLowerCase();
  return term ? syms.filter((s) => s.name.toLowerCase().includes(lower)) : syms;
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
  const padW = is64 ? 16 : 8;
  const table = document.createElement("table");

  if (syms.length > VIRTUAL_THRESHOLD) {
    table.className = "data-table symbol-table symbol-virtual";
    table.innerHTML = symbolHeaderHtml + "<tbody></tbody>";
    container.appendChild(table);

    let filtered = applySymbolFilter(syms, initialFilter);
    const handle = attachVirtualScroll(
      table,
      filtered.length,
      (i) => {
        const tr = createSymbolRow(filtered[i], versionInfo, padW);
        if (i % 2 === 0) {
          tr.className = "vs-even";
        }
        return tr;
      },
      () => container.style.display !== "none"
    );

    return (term: string) => {
      filtered = applySymbolFilter(syms, term);
      handle.update(filtered.length, (i) => {
        const tr = createSymbolRow(filtered[i], versionInfo, padW);
        if (i % 2 === 0) {
          tr.className = "vs-even";
        }
        return tr;
      });
    };
  }

  // Static table path (small tables).
  table.className = "data-table symbol-table";
  table.innerHTML = symbolHeaderHtml;
  const tbody = document.createElement("tbody");
  table.appendChild(tbody);
  container.appendChild(table);

  const noResultMsg = document.createElement("p");
  noResultMsg.className = "empty-msg search-no-result";
  noResultMsg.textContent = "No matching symbols";
  noResultMsg.style.display = "none";
  container.appendChild(noResultMsg);

  function buildStaticRows(filtered: Symbol[]): void {
    tbody.innerHTML = "";
    for (const sym of filtered) {
      tbody.appendChild(createSymbolRow(sym, versionInfo, padW));
    }
    noResultMsg.style.display = filtered.length === 0 ? "" : "none";
  }

  buildStaticRows(applySymbolFilter(syms, initialFilter));

  return (term: string) => {
    buildStaticRows(applySymbolFilter(syms, term));
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

  createSearchInput(container, (value) => {
    currentFilter = value;
    const lower = value.toLowerCase();
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
}
