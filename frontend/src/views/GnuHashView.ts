// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// GNU Hash Table view: renders the DT_GNU_HASH structure (readelf --gnu-hash-symbols).
//
// GNU hash structure layout:
//   u32 nbuckets
//   u32 symoffset      — first symbol index covered by the hash
//   u32 bloom_size     — number of bloom filter words
//   u32 bloom_shift    — shift for second bloom hash
//   word[bloom_size]   — bloom filter (u32 for ELF32, u64 for ELF64)
//   u32[nbuckets]      — bucket array (0 = empty, else starting symbol index)
//   u32[nsyms]         — hash value chain (bit 0 = end-of-chain marker)
//
// Sub-tabs: Bloom Filter | Buckets | Hash Values

import { type ELFFile, type GnuHashTable } from "../parser/types.ts";
import { VIRTUAL_THRESHOLD, createSubTabs, appendEmptyMessage } from "./viewUtils.ts";
import { attachVirtualScroll } from "./virtualScroll.ts";

// ─── Bloom Filter tab ─────────────────────────────────────────────────────────

function renderBloomFilter(container: HTMLElement, ht: GnuHashTable): void {
  if (ht.bloom.length === 0) {
    appendEmptyMessage(container, "No bloom filter words");
    return;
  }

  const hexWidth = ht.bloomWordSize === 8 ? 16 : 8;
  const bitWidth = ht.bloomWordSize * 8;

  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead><tr>
      <th class="sym-right">Index</th>
      <th class="sym-right">Value (hex)</th>
      <th class="sym-right">Set bits</th>
      <th>Bit pattern</th>
    </tr></thead>
  `;
  const tbody = document.createElement("tbody");
  for (let i = 0; i < ht.bloom.length; i++) {
    const val = ht.bloom[i];
    const hex = val.toString(16).padStart(hexWidth, "0");
    // Count set bits
    let bits = val;
    let setBits = 0;
    while (bits > 0n) {
      if (bits & 1n) setBits++;
      bits >>= 1n;
    }
    // Visual bit pattern (64-bit groups of 8)
    const binStr = val.toString(2).padStart(bitWidth, "0");
    const groups: string[] = [];
    for (let j = 0; j < bitWidth; j += 8) groups.push(binStr.slice(j, j + 8));
    const bitPattern = groups.join(" ");
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono sym-right">${i}</td>
      <td class="mono sym-right">0x${hex}</td>
      <td class="mono sym-right">${setBits} / ${bitWidth}</td>
      <td class="mono bloom-bits">${bitPattern}</td>
    `;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

// ─── Buckets tab ─────────────────────────────────────────────────────────────

function renderBuckets(container: HTMLElement, ht: GnuHashTable): void {
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
    if (head === 0) {
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

// ─── Hash Values tab ─────────────────────────────────────────────────────────

/** Build a mapping: symbol index → bucket number. */
function buildSymToBucket(ht: GnuHashTable): Map<number, number> {
  const map = new Map<number, number>();
  for (let b = 0; b < ht.buckets.length; b++) {
    const head = ht.buckets[b];
    if (head === 0) continue;
    for (let symIdx = head; ; symIdx++) {
      map.set(symIdx, b);
      const hi = symIdx - ht.symoffset;
      if (hi < 0 || hi >= ht.hashValues.length) break;
      if ((ht.hashValues[hi] & 1) !== 0) break; // end-of-chain marker
    }
  }
  return map;
}

function buildHashValueRow(
  i: number,
  ht: GnuHashTable,
  symToBucket: Map<number, number>
): HTMLTableRowElement {
  const symIdx = ht.symoffset + i;
  const hashVal = ht.hashValues[i];
  const isEnd = (hashVal & 1) !== 0;
  const name = ht.symNames[symIdx] ?? "";
  const bucket = symToBucket.get(symIdx);
  const bucketStr = bucket !== undefined ? String(bucket) : "—";
  const tr = document.createElement("tr");
  if (i % 2 === 0) tr.className = "vs-even";
  tr.innerHTML = `
    <td class="mono sym-right">${symIdx}</td>
    <td class="mono">${name}</td>
    <td class="mono sym-right">0x${(hashVal >>> 0).toString(16).padStart(8, "0")}</td>
    <td class="mono sym-right">${bucketStr}</td>
    <td class="mono sym-right">${isEnd ? "✓" : ""}</td>
  `;
  return tr;
}

function renderVirtualHashValues(container: HTMLElement, ht: GnuHashTable): void {
  const symToBucket = buildSymToBucket(ht);
  const table = document.createElement("table");
  table.className = "data-table hashvals-virtual";
  table.innerHTML = `
    <thead><tr>
      <th class="sym-right">Sym #</th>
      <th>Symbol Name</th>
      <th class="sym-right">Hash Value</th>
      <th class="sym-right">Bucket #</th>
      <th class="sym-right">End of Chain</th>
    </tr></thead>
    <tbody></tbody>
  `;
  container.appendChild(table);
  attachVirtualScroll(
    table,
    ht.hashValues.length,
    (i) => buildHashValueRow(i, ht, symToBucket),
    () => container.style.display !== "none"
  );
}

function renderHashValues(container: HTMLElement, ht: GnuHashTable): void {
  if (ht.hashValues.length === 0) {
    appendEmptyMessage(container, "No hashed symbols");
    return;
  }

  if (ht.hashValues.length > VIRTUAL_THRESHOLD) {
    renderVirtualHashValues(container, ht);
    return;
  }

  const symToBucket = buildSymToBucket(ht);
  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead><tr>
      <th class="sym-right">Sym #</th>
      <th>Symbol Name</th>
      <th class="sym-right">Hash Value</th>
      <th class="sym-right">Bucket #</th>
      <th class="sym-right">End of Chain</th>
    </tr></thead>
  `;
  const tbody = document.createElement("tbody");
  for (let i = 0; i < ht.hashValues.length; i++) {
    tbody.appendChild(buildHashValueRow(i, ht, symToBucket));
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

// ─── Main panel ───────────────────────────────────────────────────────────────

function renderGnuHashSection(container: HTMLElement, ht: GnuHashTable): void {
  const occupied = ht.buckets.filter((b) => b !== 0).length;
  const loadFactor = ht.nbuckets > 0 ? (ht.hashValues.length / ht.nbuckets).toFixed(2) : "—";
  const totalSyms = ht.symoffset + ht.hashValues.length;

  const stats = document.createElement("div");
  stats.className = "hash-stats";
  stats.innerHTML = `
    <table class="data-table hash-info-table">
      <tbody>
        <tr><td>Buckets</td>          <td class="mono">${ht.nbuckets}</td></tr>
        <tr><td>Symbol offset</td>    <td class="mono">${ht.symoffset}</td></tr>
        <tr><td>Hashed symbols</td>   <td class="mono">${ht.hashValues.length}</td></tr>
        <tr><td>Total symbols</td>    <td class="mono">${totalSyms}</td></tr>
        <tr><td>Bloom words</td>      <td class="mono">${ht.bloomSize} × ${ht.bloomWordSize * 8}-bit (shift ${ht.bloomShift})</td></tr>
        <tr><td>Occupied buckets</td> <td class="mono">${occupied} / ${ht.nbuckets}</td></tr>
        <tr><td>Load factor</td>      <td class="mono">${loadFactor}</td></tr>
      </tbody>
    </table>
  `;
  container.appendChild(stats);

  createSubTabs(container, [
    {
      label: `Bloom Filter (${ht.bloomSize})`,
      render: (p: HTMLElement) => renderBloomFilter(p, ht),
    },
    { label: `Buckets (${ht.nbuckets})`, render: (p: HTMLElement) => renderBuckets(p, ht) },
    {
      label: `Hash Values (${ht.hashValues.length})`,
      render: (p: HTMLElement) => renderHashValues(p, ht),
    },
  ]);
}

// ─── Top-level export ─────────────────────────────────────────────────────────

export function renderGnuHash(container: HTMLElement, elf: ELFFile): void {
  container.innerHTML = `<h2 class="view-title">GNU Hash Table (DT_GNU_HASH)</h2>`;

  const ht = elf.gnuHashTable;
  if (!ht) {
    appendEmptyMessage(container, "No DT_GNU_HASH found");
    return;
  }

  renderGnuHashSection(container, ht);
}
