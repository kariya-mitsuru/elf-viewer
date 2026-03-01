// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Section Headers view: renders all section headers (readelf -S).

import { type ELFFile, SHType } from "../parser/types.ts";
import { showContextMenu } from "../ui/ContextMenu.ts";
import {
  type NavTarget,
  sectionNavTarget,
  navTargetLabel,
  shTypeName,
  shFlagsStr,
  hexPad,
  appendEmptyMessage,
} from "./viewUtils.ts";

export function renderSectionHeaders(
  container: HTMLElement,
  elf: ELFFile,
  onHexDump?: (label: string, offset: number, size: number) => void,
  onNavigate?: (target: NavTarget) => void
): void {
  const shs = elf.sectionHeaders;
  const hexLen = (n: number | bigint) => n.toString(16).length;
  const dAddr = shs.reduce((m, sh) => Math.max(m, hexLen(sh.addr)), 1);
  const dOffset = shs.reduce((m, sh) => Math.max(m, hexLen(sh.offset)), 1);
  const dSize = shs.reduce((m, sh) => Math.max(m, hexLen(sh.size)), 1);

  container.innerHTML = `<h2 class="view-title">Section Headers (${shs.length})</h2>`;
  if (shs.length === 0) {
    appendEmptyMessage(container, "No section headers");
    return;
  }

  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead><tr>
      <th>[Nr]</th><th>Name</th><th>Type</th><th>Address</th><th>Offset</th>
      <th>Size</th><th>EntrySize</th><th>Flags</th><th>Link</th><th>Info</th><th>Align</th>
    </tr></thead>
  `;
  const tbody = document.createElement("tbody");
  for (const sh of shs) {
    const tr = document.createElement("tr");
    tr.id = `sh-row-${sh.index}`;
    const dimOffset = BigInt(sh.offset) === sh.addr ? " cell-dim" : "";
    const dimEntsize = sh.entsize === 0 ? " cell-dim" : "";
    const dimLink = sh.link === 0 ? " cell-dim" : "";
    const dimInfo = sh.info === 0 ? " cell-dim" : "";
    const dimAlign = sh.addralign === 0 ? " cell-dim" : "";
    tr.innerHTML = `
      <td class="mono">[${sh.index.toString().padStart(2, " ")}]</td>
      <td class="mono name-cell">${sh.name || "(null)"}</td>
      <td class="mono">${shTypeName(sh.type)}</td>
      <td class="mono">${hexPad(sh.addr, dAddr)}</td>
      <td class="mono${dimOffset}">${hexPad(sh.offset, dOffset)}</td>
      <td class="mono">${hexPad(sh.size, dSize)}</td>
      <td class="mono${dimEntsize}">${hexPad(sh.entsize, 2)}</td>
      <td class="mono flags">${shFlagsStr(sh.flags)}</td>
      <td class="mono${dimLink}">${sh.link}</td>
      <td class="mono${dimInfo}">${sh.info}</td>
      <td class="mono${dimAlign}">${sh.addralign}</td>
    `;
    const navTarget = onNavigate ? sectionNavTarget(sh.type) : null;
    if (navTarget !== null) {
      tr.classList.add("nav-row");
      tr.addEventListener("dblclick", () => onNavigate!(navTarget));
    }
    tr.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      const items = [];
      if (navTarget !== null) {
        items.push({
          label: `Open in ${navTargetLabel(navTarget)}`,
          action: () => onNavigate!(navTarget),
        });
      }
      if (onHexDump && sh.type !== SHType.NoBits && Number(sh.size) > 0) {
        const label = sh.name || `section ${sh.index}`;
        items.push({
          label: `Hex Dump: ${label}`,
          action: () => onHexDump(label, Number(sh.offset), Number(sh.size)),
        });
      }
      if (items.length > 0) showContextMenu(e.clientX, e.clientY, items);
    });
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);

  const legend = document.createElement("p");
  legend.className = "view-note";
  legend.textContent =
    "Flags: W (write), A (alloc), X (execute), M (merge), S (strings), G (group), T (TLS)";
  container.appendChild(legend);
}
