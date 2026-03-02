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
// A shared search box in the sub-nav:
//   - Bloom Filter: highlights the bloom word and the two check-bits for the search term
//   - Buckets / Hash Values: filter rows by symbol name

import { type ELFFile, type GnuHashTable } from "../parser/types.ts";
import { VIRTUAL_THRESHOLD, createSubTabs, appendEmptyMessage } from "./viewUtils.ts";
import { attachVirtualScroll } from "./virtualScroll.ts";

// ─── GNU hash helpers ─────────────────────────────────────────────────────────

/** elf_gnu_hash: the hash function used by DT_GNU_HASH sections. */
function elfGnuHash(name: string): number {
  let h = 5381;
  for (let i = 0; i < name.length; i++) h = (Math.imul(h, 33) + name.charCodeAt(i)) >>> 0;
  return h;
}

/**
 * Renders a bloom filter word as a grouped bit pattern (8 bits per group).
 * Bits in `hitBits` (positions counted from LSB = 0) are wrapped in a highlight span.
 */
function buildBitPatternHtml(val: bigint, bitWidth: number, hitBits: Set<number>): string {
  const binStr = val.toString(2).padStart(bitWidth, "0");
  // binStr[j] = bit at position (bitWidth - 1 - j) from LSB.
  let html = "";
  for (let j = 0; j < bitWidth; j++) {
    if (j > 0 && j % 8 === 0) html += " ";
    const bitPos = bitWidth - 1 - j;
    const char = binStr[j];
    html += hitBits.has(bitPos) ? `<span class="bloom-bit-hit">${char}</span>` : char;
  }
  return html;
}

// ─── Bloom Filter tab ─────────────────────────────────────────────────────────

function renderBloomFilter(
  container: HTMLElement,
  ht: GnuHashTable,
  initialTerm: string
): { update: (term: string) => void; scrollNow: () => void } {
  if (ht.bloom.length === 0) {
    appendEmptyMessage(container, "No bloom filter words");
    return { update: () => {}, scrollNow: () => {} };
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

  // Per-row references for efficient highlight updates.
  const rows: HTMLTableRowElement[] = [];
  const bitCells: HTMLTableCellElement[] = [];

  for (let i = 0; i < ht.bloom.length; i++) {
    const val = ht.bloom[i];
    const hex = val.toString(16).padStart(hexWidth, "0");
    let bits = val;
    let setBits = 0;
    while (bits > 0n) {
      if (bits & 1n) setBits++;
      bits >>= 1n;
    }
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono sym-right">${i}</td>
      <td class="mono sym-right">0x${hex}</td>
      <td class="mono sym-right">${setBits} / ${bitWidth}</td>
    `;
    const bitTd = document.createElement("td");
    bitTd.className = "mono bloom-bits";
    bitTd.innerHTML = buildBitPatternHtml(val, bitWidth, new Set());
    tr.appendChild(bitTd);
    tbody.appendChild(tr);
    rows.push(tr);
    bitCells.push(bitTd);
  }
  table.appendChild(tbody);
  container.appendChild(table);

  // Info line: appears when a search term is active.
  const bloomInfo = document.createElement("p");
  bloomInfo.className = "bloom-info view-note";
  bloomInfo.style.display = "none";
  container.appendChild(bloomInfo);

  let prevIdx = -1;
  let scrollTimer = 0;
  let pendingScrollIdx = -1;

  // Scrolls the highlighted row into view, accounting for sticky section-nav + th.
  // Only scrolls when the row is outside the visible area (up or down).
  // If the container is hidden (display:none via tab switching), stores the index
  // and returns false so the caller can retry on next tab activation.
  function performScroll(wordIdx: number): boolean {
    if (container.offsetParent === null) {
      pendingScrollIdx = wordIdx;
      return false;
    }
    pendingScrollIdx = -1;
    const row = rows[wordIdx];
    let sc: Element | null = row.parentElement;
    while (sc && sc !== document.body) {
      const ov = getComputedStyle(sc).overflowY;
      if (ov === "auto" || ov === "scroll") break;
      sc = sc.parentElement;
    }
    if (!sc) return true;
    const scRect = sc.getBoundingClientRect();
    const rowRect = row.getBoundingClientRect();
    // thead itself is not sticky; only th children are (position:sticky, top:37px).
    // Using th.getBoundingClientRect().bottom gives the true visible boundary.
    const firstTh = table.tHead?.querySelector<HTMLElement>("th");
    const stickyTop = firstTh ? firstTh.getBoundingClientRect().bottom : scRect.top;
    if (rowRect.top < stickyTop) {
      sc.scrollBy({ top: rowRect.top - stickyTop, behavior: "smooth" });
    } else if (rowRect.bottom > scRect.bottom) {
      sc.scrollBy({ top: rowRect.bottom - scRect.bottom, behavior: "smooth" });
    }
    return true;
  }

  // Called by the tab's onActivate hook to execute any deferred scroll.
  function scrollNow(): void {
    if (pendingScrollIdx >= 0) performScroll(pendingScrollIdx);
  }

  function applyHighlight(term: string): void {
    // Clear previous highlight.
    if (prevIdx >= 0) {
      rows[prevIdx].classList.remove("bloom-hit-row", "bloom-positive", "bloom-negative");
      bitCells[prevIdx].innerHTML = buildBitPatternHtml(ht.bloom[prevIdx], bitWidth, new Set());
      prevIdx = -1;
    }
    // Cancel pending scroll from previous keystroke.
    if (scrollTimer) {
      clearTimeout(scrollTimer);
      scrollTimer = 0;
    }
    pendingScrollIdx = -1;
    if (!term) {
      bloomInfo.style.display = "none";
      return;
    }

    const h = elfGnuHash(term);
    const wordIdx = Math.floor(h / bitWidth) % ht.bloomSize;
    const bit1 = h % bitWidth;
    const bit2 = (h >>> ht.bloomShift) % bitWidth;

    bloomInfo.style.display = "";
    bloomInfo.textContent = `"${term}" → hash 0x${h.toString(16)}, word ${wordIdx}, bits ${bit1} & ${bit2}`;

    if (!rows[wordIdx]) return;

    const word = ht.bloom[wordIdx];
    const bit1Set = (word >> BigInt(bit1)) & 1n;
    const bit2Set = (word >> BigInt(bit2)) & 1n;
    const isPositive = bit1Set === 1n && bit2Set === 1n;

    rows[wordIdx].classList.add("bloom-hit-row", isPositive ? "bloom-positive" : "bloom-negative");
    bitCells[wordIdx].innerHTML = buildBitPatternHtml(word, bitWidth, new Set([bit1, bit2]));
    bloomInfo.textContent += isPositive ? " → possibly present" : " → definitely absent";
    prevIdx = wordIdx;

    // Scroll 300 ms after typing stops (bi-directional: up or down as needed).
    // The timer is cancelled on each keystroke, so no scroll occurs while actively
    // typing. If the tab is hidden when the timer fires, performScroll() stores a
    // pending index; scrollNow() will execute it on the next tab activation.
    scrollTimer = window.setTimeout(() => {
      scrollTimer = 0;
      performScroll(wordIdx);
    }, 300);
  }

  applyHighlight(initialTerm);
  return { update: applyHighlight, scrollNow };
}

// ─── Buckets tab ─────────────────────────────────────────────────────────────

// Returns a setFilter function.
// When filtering: empty buckets are hidden; only non-empty buckets with a matching
// head symbol name are shown.
function renderBuckets(
  container: HTMLElement,
  ht: GnuHashTable,
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
      if (head === 0) {
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

// Returns a setFilter function. Uses virtual scroll when hashValues.length > VIRTUAL_THRESHOLD.
function renderHashValues(
  container: HTMLElement,
  ht: GnuHashTable,
  initialFilter: string
): (term: string) => void {
  if (ht.hashValues.length === 0) {
    appendEmptyMessage(container, "No hashed symbols");
    return () => {};
  }

  const symToBucket = buildSymToBucket(ht);

  function getFilteredIndices(term: string): number[] {
    if (!term) return Array.from({ length: ht.hashValues.length }, (_, i) => i);
    const lower = term.toLowerCase();
    return Array.from({ length: ht.hashValues.length }, (_, i) => i).filter((i) =>
      (ht.symNames[ht.symoffset + i] ?? "").toLowerCase().includes(lower)
    );
  }

  const thead = `
    <thead><tr>
      <th class="sym-right">Sym #</th>
      <th>Symbol Name</th>
      <th class="sym-right">Hash Value</th>
      <th class="sym-right">Bucket #</th>
      <th class="sym-right">End of Chain</th>
    </tr></thead>
  `;
  const noResultMsg = document.createElement("p");
  noResultMsg.className = "empty-msg search-no-result";
  noResultMsg.textContent = "No matching symbols";
  noResultMsg.style.display = "none";

  if (ht.hashValues.length > VIRTUAL_THRESHOLD) {
    const table = document.createElement("table");
    table.className = "data-table hashvals-virtual";
    table.innerHTML = `${thead}<tbody></tbody>`;
    container.appendChild(table);
    container.appendChild(noResultMsg);

    let filteredIndices = getFilteredIndices(initialFilter);
    const handle = attachVirtualScroll(
      table,
      filteredIndices.length,
      (i) => buildHashValueRow(filteredIndices[i], ht, symToBucket),
      () => container.style.display !== "none"
    );

    return (term: string) => {
      filteredIndices = getFilteredIndices(term);
      handle.update(filteredIndices.length, (i) =>
        buildHashValueRow(filteredIndices[i], ht, symToBucket)
      );
      noResultMsg.style.display = filteredIndices.length === 0 ? "" : "none";
    };
  }

  // Static table path (small tables).
  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = thead;
  const tbody = document.createElement("tbody");
  table.appendChild(tbody);
  container.appendChild(table);
  container.appendChild(noResultMsg);

  function buildStaticRows(term: string): void {
    tbody.innerHTML = "";
    const indices = getFilteredIndices(term);
    for (const i of indices) tbody.appendChild(buildHashValueRow(i, ht, symToBucket));
    noResultMsg.style.display = indices.length === 0 ? "" : "none";
  }

  buildStaticRows(initialFilter);
  return buildStaticRows;
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

  // Shared filter state across all sub-tabs.
  let currentFilter = "";
  let bloomFilterUpdater: ((term: string) => void) | null = null;
  let bloomScrollNow: (() => void) | null = null;
  let bucketsUpdater: ((term: string) => void) | null = null;
  let hashValuesUpdater: ((term: string) => void) | null = null;

  const subtabs = createSubTabs(container, [
    {
      label: `Bloom Filter (${ht.bloomSize})`,
      render: (p: HTMLElement) => {
        const handle = renderBloomFilter(p, ht, currentFilter);
        bloomFilterUpdater = handle.update;
        bloomScrollNow = handle.scrollNow;
      },
      onActivate: () => bloomScrollNow?.(),
    },
    {
      label: `Buckets (${ht.nbuckets})`,
      render: (p: HTMLElement) => {
        bucketsUpdater = renderBuckets(p, ht, currentFilter);
      },
    },
    {
      label: `Hash Values (${ht.hashValues.length})`,
      render: (p: HTMLElement) => {
        hashValuesUpdater = renderHashValues(p, ht, currentFilter);
      },
    },
  ]);

  // Append search input to the sub-tab section-nav.
  const nav = container.querySelector<HTMLElement>(".section-nav");
  if (nav) {
    const searchInput = document.createElement("input");
    searchInput.type = "search";
    searchInput.className = "search-input";
    searchInput.placeholder = "Filter by name…";
    searchInput.setAttribute("aria-label", "Filter symbols by name");
    searchInput.addEventListener("input", () => {
      currentFilter = searchInput.value;
      bloomFilterUpdater?.(currentFilter); // updates highlight + starts 300ms timer
      bucketsUpdater?.(currentFilter);
      hashValuesUpdater?.(currentFilter);
      if (currentFilter) {
        const lower = currentFilter.toLowerCase();
        const nBuckets = ht.buckets.filter(
          (h) => h !== 0 && (ht.symNames[h] ?? "").toLowerCase().includes(lower)
        ).length;
        const nHashVals = Array.from({ length: ht.hashValues.length }, (_, i) => i).filter((i) =>
          (ht.symNames[ht.symoffset + i] ?? "").toLowerCase().includes(lower)
        ).length;
        subtabs.updateLabel(1, `Buckets (${nBuckets} / ${ht.nbuckets})`);
        subtabs.updateLabel(2, `Hash Values (${nHashVals} / ${ht.hashValues.length})`);
      } else {
        subtabs.updateLabel(1, `Buckets (${ht.nbuckets})`);
        subtabs.updateLabel(2, `Hash Values (${ht.hashValues.length})`);
      }
    });
    nav.appendChild(searchInput);
  }
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
