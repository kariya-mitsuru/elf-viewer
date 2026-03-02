// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Hash Table view: renders SHT_HASH (SYSV hash) sections (readelf --hash-symbols).
//
// Structure:
//   - If multiple SHT_HASH sections exist, top-level sub-tabs select the section.
//   - Within each section: "Buckets" and "Chains" sub-tabs with a shared search box.
//
// Buckets tab: one row per bucket — shows the head symbol index and name.
//   When filtering: shows only non-empty buckets with a matching head symbol name.
// Chains tab:  one row per symbol — shows sym name and the chain[i] next pointer.
//   Uses virtual scrolling when nchain > VIRTUAL_THRESHOLD.

import { type ELFFile, type HashTable } from "../parser/types.ts";
import { VIRTUAL_THRESHOLD, createSubTabs } from "./viewUtils.ts";
import { attachVirtualScroll } from "./virtualScroll.ts";
const STN_UNDEF = 0;

// ─── Buckets tab ──────────────────────────────────────────────────────────────

// Returns a setFilter function that rebuilds the table when the search term changes.
// When filtering: empty buckets are hidden; only non-empty buckets with a matching
// head symbol name are shown.
function renderBuckets(
  container: HTMLElement,
  ht: HashTable,
  initialFilter: string
): (term: string) => void {
  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead><tr>
      <th class="sym-right">Bucket #</th>
      <th class="sym-right">Head Sym #</th>
      <th>Symbol Name</th>
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

  function buildRows(term: string): void {
    tbody.innerHTML = "";
    const lower = term.toLowerCase();
    let count = 0;
    for (let i = 0; i < ht.buckets.length; i++) {
      const head = ht.buckets[i];
      if (head === STN_UNDEF) {
        if (!term) {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td class="mono sym-right">${i}</td>
            <td class="mono sym-right empty-bucket">—</td>
            <td></td>
          `;
          tbody.appendChild(tr);
          count++;
        }
      } else {
        const name = ht.symNames[head] ?? "";
        if (term && !name.toLowerCase().includes(lower)) continue;
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="mono sym-right">${i}</td>
          <td class="mono sym-right">${head}</td>
          <td class="mono">${name}</td>
        `;
        tbody.appendChild(tr);
        count++;
      }
    }
    noResultMsg.style.display = count === 0 ? "" : "none";
  }

  buildRows(initialFilter);
  return buildRows;
}

// ─── Chains tab ───────────────────────────────────────────────────────────────

function buildChainRow(i: number, ht: HashTable): HTMLTableRowElement {
  const next = ht.chains[i];
  const symName = ht.symNames[i] ?? "";
  const nextName = next !== STN_UNDEF ? (ht.symNames[next] ?? "") : "";
  const nextCell =
    next !== STN_UNDEF
      ? `<td class="mono sym-right">${next}</td><td class="mono">${nextName}</td>`
      : `<td class="mono sym-right empty-bucket">—</td><td></td>`;
  const tr = document.createElement("tr");
  if (i % 2 === 0) tr.className = "vs-even";
  tr.innerHTML = `
    <td class="mono sym-right">${i}</td>
    <td class="mono">${symName}</td>
    ${nextCell}
  `;
  return tr;
}

// Returns a setFilter function. Uses virtual scroll when nchain > VIRTUAL_THRESHOLD.
function renderChains(
  container: HTMLElement,
  ht: HashTable,
  initialFilter: string
): (term: string) => void {
  if (ht.nchain === 0) {
    const p = document.createElement("p");
    p.className = "empty-msg";
    p.textContent = "No entries";
    container.appendChild(p);
    return () => {};
  }

  function getFilteredIndices(term: string): number[] {
    if (!term) return Array.from({ length: ht.nchain }, (_, i) => i);
    const lower = term.toLowerCase();
    return Array.from({ length: ht.nchain }, (_, i) => i).filter((i) =>
      (ht.symNames[i] ?? "").toLowerCase().includes(lower)
    );
  }

  const thead = `
    <thead><tr>
      <th class="sym-right">Sym #</th>
      <th>Symbol Name</th>
      <th class="sym-right">Next Sym #</th>
      <th>Next Symbol Name</th>
    </tr></thead>
  `;
  const noResultMsg = document.createElement("p");
  noResultMsg.className = "empty-msg search-no-result";
  noResultMsg.textContent = "No matching symbols";
  noResultMsg.style.display = "none";

  if (ht.nchain > VIRTUAL_THRESHOLD) {
    const table = document.createElement("table");
    table.className = "data-table chains-virtual";
    table.innerHTML = `${thead}<tbody></tbody>`;
    container.appendChild(table);
    container.appendChild(noResultMsg);

    let filteredIndices = getFilteredIndices(initialFilter);
    const handle = attachVirtualScroll(
      table,
      filteredIndices.length,
      (i) => buildChainRow(filteredIndices[i], ht),
      () => container.style.display !== "none"
    );

    return (term: string) => {
      filteredIndices = getFilteredIndices(term);
      handle.update(filteredIndices.length, (i) => buildChainRow(filteredIndices[i], ht));
      noResultMsg.style.display = filteredIndices.length === 0 ? "" : "none";
    };
  }

  // Static table path (small tables).
  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `${thead}`;
  const tbody = document.createElement("tbody");
  table.appendChild(tbody);
  container.appendChild(table);
  container.appendChild(noResultMsg);

  function buildStaticRows(term: string): void {
    tbody.innerHTML = "";
    const indices = getFilteredIndices(term);
    for (const i of indices) tbody.appendChild(buildChainRow(i, ht));
    noResultMsg.style.display = indices.length === 0 ? "" : "none";
  }

  buildStaticRows(initialFilter);
  return buildStaticRows;
}

// ─── Per-section panel ────────────────────────────────────────────────────────

function renderHashSection(container: HTMLElement, ht: HashTable): void {
  // Stats header
  const occupied = ht.buckets.filter((b) => b !== STN_UNDEF).length;
  const loadFactor = ht.nbucket > 0 ? (ht.nchain / ht.nbucket).toFixed(2) : "—";
  const stats = document.createElement("div");
  stats.className = "hash-stats";
  stats.innerHTML = `
    <table class="data-table hash-info-table">
      <tbody>
        <tr><td>Buckets</td><td class="mono">${ht.nbucket}</td></tr>
        <tr><td>Symbols (nchain)</td><td class="mono">${ht.nchain}</td></tr>
        <tr><td>Occupied buckets</td><td class="mono">${occupied} / ${ht.nbucket}</td></tr>
        <tr><td>Load factor</td><td class="mono">${loadFactor}</td></tr>
      </tbody>
    </table>
  `;
  container.appendChild(stats);

  // Shared filter state across Buckets / Chains sub-tabs.
  let currentFilter = "";
  let bucketsUpdater: ((term: string) => void) | null = null;
  let chainsUpdater: ((term: string) => void) | null = null;

  createSubTabs(container, [
    {
      label: `Buckets (${ht.nbucket})`,
      render: (p: HTMLElement) => {
        bucketsUpdater = renderBuckets(p, ht, currentFilter);
      },
    },
    {
      label: `Chains (${ht.nchain})`,
      render: (p: HTMLElement) => {
        chainsUpdater = renderChains(p, ht, currentFilter);
      },
    },
  ]);

  // Append search input to the Buckets/Chains section-nav.
  const nav = container.querySelector<HTMLElement>(".section-nav");
  if (nav) {
    const searchInput = document.createElement("input");
    searchInput.type = "search";
    searchInput.className = "search-input";
    searchInput.placeholder = "Filter by name…";
    searchInput.setAttribute("aria-label", "Filter symbols by name");
    searchInput.addEventListener("input", () => {
      currentFilter = searchInput.value;
      bucketsUpdater?.(currentFilter);
      chainsUpdater?.(currentFilter);
    });
    nav.appendChild(searchInput);
  }
}

// ─── Top-level export ─────────────────────────────────────────────────────────

export function renderHash(container: HTMLElement, elf: ELFFile): void {
  const tables = elf.hashTables;
  container.innerHTML = `<h2 class="view-title">Hash Table (SHT_HASH)</h2>`;

  if (tables.length === 0) {
    const p = document.createElement("p");
    p.className = "empty-msg";
    p.textContent = "No SHT_HASH sections found";
    container.appendChild(p);
    return;
  }

  if (tables.length === 1) {
    renderHashSection(container, tables[0]);
    return;
  }

  // Multiple hash sections — section selector sub-tabs at top level
  createSubTabs(
    container,
    tables.map((ht) => ({
      label: ht.sectionName,
      render: (p: HTMLElement) => renderHashSection(p, ht),
    }))
  );
}
