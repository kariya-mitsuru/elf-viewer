// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Shared bucket rendering for HashView and GnuHashView.
// Both SHT_HASH and DT_GNU_HASH use the same bucket table layout:
//   Bucket # | Head Sym # | Symbol Name
// Empty buckets (head === 0) are shown as "—" when no filter is active.

interface BucketSource {
  buckets: Uint32Array | number[];
  symNames: string[];
}

/**
 * Renders a bucket table with optional filtering.
 * Returns a setFilter function that rebuilds the table when the search term changes.
 */
export function renderBuckets(
  container: HTMLElement,
  ht: BucketSource,
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
