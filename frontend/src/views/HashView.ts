// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Hash Table view: renders SHT_HASH (SYSV hash) sections (readelf --hash-symbols).
//
// Structure:
//   - If multiple SHT_HASH sections exist, top-level sub-tabs select the section.
//   - Within each section: "Buckets" and "Chains" sub-tabs.
//
// Buckets tab: one row per bucket — shows the head symbol index and name.
// Chains tab:  one row per symbol — shows sym name and the chain[i] next pointer.
//              Uses virtual scrolling when nchain > VIRTUAL_THRESHOLD.

import { type ELFFile, type HashTable } from "../parser/types.ts";
import { VIRTUAL_THRESHOLD, createSubTabs } from "./viewUtils.ts";
import { attachVirtualScroll } from "./virtualScroll.ts";
const STN_UNDEF = 0;

// ─── Buckets tab ──────────────────────────────────────────────────────────────

function renderBuckets(container: HTMLElement, ht: HashTable): void {
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
  for (let i = 0; i < ht.buckets.length; i++) {
    const head = ht.buckets[i];
    const tr = document.createElement("tr");
    if (head === STN_UNDEF) {
      tr.innerHTML = `
        <td class="mono sym-right">${i}</td>
        <td class="mono sym-right empty-bucket">—</td>
        <td></td>
      `;
    } else {
      const name = ht.symNames[head] ?? "";
      tr.innerHTML = `
        <td class="mono sym-right">${i}</td>
        <td class="mono sym-right">${head}</td>
        <td class="mono">${name}</td>
      `;
    }
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
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

function renderVirtualChains(container: HTMLElement, ht: HashTable): void {
  const table = document.createElement("table");
  table.className = "data-table chains-virtual";
  table.innerHTML = `
    <thead><tr>
      <th class="sym-right">Sym #</th>
      <th>Symbol Name</th>
      <th class="sym-right">Next Sym #</th>
      <th>Next Symbol Name</th>
    </tr></thead>
    <tbody></tbody>
  `;
  container.appendChild(table);
  attachVirtualScroll(
    table,
    ht.nchain,
    (i) => buildChainRow(i, ht),
    () => container.style.display !== "none"
  );
}

function renderChains(container: HTMLElement, ht: HashTable): void {
  if (ht.nchain === 0) {
    const p = document.createElement("p");
    p.className = "empty-msg";
    p.textContent = "No entries";
    container.appendChild(p);
    return;
  }

  if (ht.nchain > VIRTUAL_THRESHOLD) {
    renderVirtualChains(container, ht);
    return;
  }

  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead><tr>
      <th class="sym-right">Sym #</th>
      <th>Symbol Name</th>
      <th class="sym-right">Next Sym #</th>
      <th>Next Symbol Name</th>
    </tr></thead>
  `;
  const tbody = document.createElement("tbody");
  for (let i = 0; i < ht.nchain; i++) {
    tbody.appendChild(buildChainRow(i, ht));
  }
  table.appendChild(tbody);
  container.appendChild(table);
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

  // Buckets / Chains sub-tabs
  createSubTabs(container, [
    { label: `Buckets (${ht.nbucket})`, render: (p: HTMLElement) => renderBuckets(p, ht) },
    { label: `Chains (${ht.nchain})`, render: (p: HTMLElement) => renderChains(p, ht) },
  ]);
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
