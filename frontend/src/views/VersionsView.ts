// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Versions view: renders VERDEF and VERNEED sections (readelf -V).

import { type ELFFile, type VersionDef, type VersionNeed } from "../parser/types.ts";
import { slugId, renderSectionNav } from "../ui/SectionNav.ts";

const VER_FLG_BASE = 0x1;
const VER_FLG_WEAK = 0x2;

const ID_DEFS = "ver-defs";

function verDefFlagsStr(flags: number): string {
  const parts: string[] = [];
  if (flags & VER_FLG_BASE) parts.push("BASE");
  if (flags & VER_FLG_WEAK) parts.push("WEAK");
  return parts.join(" ") || "none";
}

function verNeedFlagsStr(flags: number): string {
  if (flags & VER_FLG_WEAK) return "WEAK";
  return "none";
}

function renderVerDef(container: HTMLElement, defs: VersionDef[]): void {
  const h3 = document.createElement("h3");
  h3.id = ID_DEFS;
  h3.className = "view-subtitle";
  h3.textContent = `Version Definitions (${defs.length})`;
  container.appendChild(h3);

  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead><tr>
      <th>Index</th><th>Flags</th><th>Version</th><th>Parent Versions</th>
    </tr></thead>
  `;
  const tbody = document.createElement("tbody");
  for (const def of defs) {
    const name = def.names[0] ?? "";
    const parents = def.names.slice(1).join(", ");
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${def.ndx}</td>
      <td class="mono flags">${verDefFlagsStr(def.flags)}</td>
      <td class="mono">${name}</td>
      <td class="mono">${parents}</td>
    `;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

function renderVerNeed(container: HTMLElement, needs: VersionNeed[]): void {
  const h3 = document.createElement("h3");
  h3.className = "view-subtitle";
  h3.textContent = `Version Requirements (${needs.length} ${needs.length === 1 ? "library" : "libraries"})`;
  container.appendChild(h3);

  for (const need of needs) {
    const id = slugId("ver-need", need.file);
    const header = document.createElement("div");
    header.id = id;
    header.className = "ver-group-header";
    header.textContent = `${need.file}  (${need.cnt} version${need.cnt !== 1 ? "s" : ""} needed)`;
    container.appendChild(header);

    const table = document.createElement("table");
    table.className = "data-table ver-group-table";
    table.innerHTML = `
      <thead><tr>
        <th>Version</th><th>Flags</th><th>Index</th>
      </tr></thead>
    `;
    const tbody = document.createElement("tbody");
    for (const aux of need.aux) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${aux.name}</td>
        <td class="mono flags">${verNeedFlagsStr(aux.flags)}</td>
        <td class="mono">${aux.other}</td>
      `;
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    container.appendChild(table);
  }
}

export function renderVersions(container: HTMLElement, elf: ELFFile): void {
  const info = elf.versionInfo;
  container.innerHTML = '<h2 class="view-title">Versions</h2>';

  if (!info || (info.versionDefs.length === 0 && info.versionNeeds.length === 0)) {
    const p = document.createElement("p");
    p.className = "empty-msg";
    p.textContent = "No version information";
    container.appendChild(p);
    return;
  }

  const navItems: { id: string; label: string }[] = [];
  if (info.versionDefs.length > 0) {
    navItems.push({ id: ID_DEFS, label: `Definitions (${info.versionDefs.length})` });
  }
  for (const need of info.versionNeeds) {
    navItems.push({ id: slugId("ver-need", need.file), label: `${need.file} (${need.cnt})` });
  }
  renderSectionNav(container, navItems);

  if (info.versionDefs.length > 0) renderVerDef(container, info.versionDefs);
  if (info.versionNeeds.length > 0) renderVerNeed(container, info.versionNeeds);
}
