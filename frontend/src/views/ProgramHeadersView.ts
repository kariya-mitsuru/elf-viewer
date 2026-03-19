// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Program Headers view: renders all program headers (readelf -l).

import { type ELFFile, PHType, SHType, SHF_TLS } from "../parser/types.ts";
import { attachCtxMenu } from "../ui/ContextMenu.ts";
import {
  type NavTarget,
  phTypeName,
  phFlagsStr,
  hexPad,
  appendEmptyMessage,
  phNavTarget,
  navTargetLabel,
} from "./viewUtils.ts";

export function renderProgramHeaders(
  container: HTMLElement,
  elf: ELFFile,
  onHexDump?: (label: string, offset: number, size: number) => void,
  onNavigate?: (target: NavTarget) => void
): void {
  const phs = elf.programHeaders;
  const hexLen = (n: number | bigint) => n.toString(16).length;
  const dOffset = phs.reduce((m, ph) => Math.max(m, hexLen(ph.offset)), 1);
  const dVaddr = phs.reduce((m, ph) => Math.max(m, hexLen(ph.vaddr)), 1);
  const dPaddr = phs.reduce((m, ph) => Math.max(m, hexLen(ph.paddr)), 1);
  const dFilesz = phs.reduce((m, ph) => Math.max(m, hexLen(ph.filesz)), 1);
  const dMemsz = phs.reduce((m, ph) => Math.max(m, hexLen(ph.memsz)), 1);

  container.innerHTML = `<h2 class="view-title">Program Headers (${phs.length})</h2>`;

  if (phs.length === 0) {
    appendEmptyMessage(container, "No program headers");
    return;
  }

  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead><tr>
      <th>#</th><th>Type</th><th>Offset</th><th>VirtAddr</th><th>PhysAddr</th>
      <th>FileSize</th><th>MemSize</th><th>Flags</th><th>Align</th>
    </tr></thead>
  `;
  const tbody = document.createElement("tbody");
  for (const ph of phs) {
    const tr = document.createElement("tr");
    tr.id = `ph-row-${ph.index}`;
    const dimOffset = BigInt(ph.offset) === ph.vaddr ? " cell-dim" : "";
    const dimPaddr = ph.paddr === ph.vaddr ? " cell-dim" : "";
    const dimMemsz = ph.memsz === ph.filesz ? " cell-dim" : "";
    const dimAlign = ph.align === 0 ? " cell-dim" : "";
    tr.innerHTML = `
      <td class="mono">${ph.index}</td>
      <td class="mono">${phTypeName(ph.type)}</td>
      <td class="mono${dimOffset}">${hexPad(ph.offset, dOffset)}</td>
      <td class="mono">${hexPad(ph.vaddr, dVaddr)}</td>
      <td class="mono${dimPaddr}">${hexPad(ph.paddr, dPaddr)}</td>
      <td class="mono">${hexPad(ph.filesz, dFilesz)}</td>
      <td class="mono${dimMemsz}">${hexPad(ph.memsz, dMemsz)}</td>
      <td class="mono flags">${phFlagsStr(ph.flags)}</td>
      <td class="mono${dimAlign}">${ph.align > 0 ? `0x${ph.align.toString(16)}` : "0"}</td>
    `;
    const navTarget = onNavigate ? phNavTarget(ph.type) : null;
    if (navTarget !== null) {
      tr.classList.add("nav-row");
      tr.addEventListener("dblclick", () => onNavigate!(navTarget));
    }
    attachCtxMenu(tr, [
      navTarget !== null
        ? { label: `Open in ${navTargetLabel(navTarget)}`, action: () => onNavigate!(navTarget) }
        : null,
      onHexDump && ph.filesz > 0
        ? {
            label: `Hex Dump: ${phTypeName(ph.type)} PH #${ph.index}`,
            action: () =>
              onHexDump(
                `${phTypeName(ph.type)} PH #${ph.index}`,
                Number(ph.offset),
                Number(ph.filesz)
              ),
          }
        : null,
    ]);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);

  // Interp string
  const interpPh = phs.find((p) => p.type === PHType.Interp);
  if (interpPh) {
    const off = interpPh.offset;
    const sz = interpPh.filesz;
    if (off + sz <= elf.raw.length) {
      const interp = new TextDecoder().decode(elf.raw.slice(off, off + sz - 1));
      const note = document.createElement("p");
      note.className = "view-note";
      note.textContent = `      [Requesting program interpreter: ${interp}]`;
      container.appendChild(note);
    }
  }

  // Section-to-segment mapping
  if (elf.sectionHeaders.length > 0) {
    const h2 = document.createElement("h3");
    h2.className = "view-subtitle";
    h2.textContent = "Section to Segment mapping:";
    container.appendChild(h2);

    const mapTable = document.createElement("table");
    mapTable.className = "data-table";
    mapTable.innerHTML = "<thead><tr><th>Segment</th><th>Sections</th></tr></thead>";
    const mtbody = document.createElement("tbody");
    for (const ph of phs) {
      const secs = elf.sectionHeaders.filter((sh) => {
        if (!sh.name || sh.size === 0) return false;
        if (sh.type === SHType.NoBits) {
          // .tbss (TLS+NOBITS) only belongs to PT_TLS, not to LOAD/GNU_RELRO/etc.
          if ((sh.flags & SHF_TLS) !== 0n && ph.type !== PHType.Tls) return false;
          // Other NOBITS sections have no file content; check by virtual address
          return sh.addr >= ph.vaddr && sh.addr + BigInt(sh.size) <= ph.vaddr + BigInt(ph.memsz);
        }
        // Non-NOBITS: check by file offset to avoid false matches when addr == 0
        return sh.offset >= ph.offset && sh.offset + sh.size <= ph.offset + ph.filesz;
      });
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="mono">${ph.index.toString().padStart(2, " ")}</td><td class="mono">${secs.map((s) => s.name).join(" ")}</td>`;
      mtbody.appendChild(tr);
    }
    mapTable.appendChild(mtbody);
    container.appendChild(mapTable);
  }
}
