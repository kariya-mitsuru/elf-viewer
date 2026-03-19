// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Dynamic section view: renders all dynamic entries (readelf -d).

import {
  type ELFFile,
  DynTag,
  DF_ORIGIN,
  DF_SYMBOLIC,
  DF_TEXTREL,
  DF_BIND_NOW,
  DF_STATIC_TLS,
  DF_1_NOW,
  DF_1_GLOBAL,
  DF_1_GROUP,
  DF_1_NODELETE,
  DF_1_LOADFLTR,
  DF_1_INITFIRST,
  DF_1_NOOPEN,
  DF_1_ORIGIN,
  DF_1_DIRECT,
  DF_1_TRANS,
  DF_1_INTERPOSE,
  DF_1_NODEFLIB,
  DF_1_NODUMP,
  DF_1_CONFALT,
  DF_1_ENDFILTEE,
  DF_1_DISPRELDNE,
  DF_1_DISPRELPND,
  DF_1_NODIRECT,
  DF_1_IGNMULDEF,
  DF_1_NOKSYMS,
  DF_1_NOHDR,
  DF_1_EDITED,
  DF_1_NORELOC,
  DF_1_SYMINTPOSE,
  DF_1_GLOBAUDIT,
  DF_1_SINGLETON,
  DF_1_STUB,
  DF_1_PIE,
  DF_1_KMOD,
  DF_1_WEAKFILTER,
  DF_1_NOCOMMON,
} from "../parser/types.ts";
import { buildLayout, type LayoutDynEntry, companionToMainTag } from "./layout.ts";
import { attachCtxMenu, type CtxMenuItem } from "../ui/ContextMenu.ts";
import { showTooltip, hideTooltip, moveTooltip, escapeHtml, ttRow } from "../ui/Tooltip.ts";
import {
  dynTagName,
  navTargetLabel,
  dynNavTarget,
  appendEmptyMessage,
  hexPad,
  type NavTarget,
} from "./viewUtils.ts";

// Tags whose values are counts or entry sizes — displayed as decimal.
// Size tags (*SZ) fall through to the hex default, matching the Memory Map tooltip.
const DEC_TAGS = new Set<number>([
  DynTag.RelaEnt,
  DynTag.SymEnt,
  DynTag.RelEnt,
  DynTag.RelrEnt,
  DynTag.X86_64PltEnt,
  DynTag.VerDefNum,
  DynTag.VerNeedNum,
  DynTag.RelCount,
  DynTag.RelaCount,
]);

// DT_FLAGS bit names in order (LSB first)
const DF_BITS: [number, string][] = [
  [DF_ORIGIN, "ORIGIN"],
  [DF_SYMBOLIC, "SYMBOLIC"],
  [DF_TEXTREL, "TEXTREL"],
  [DF_BIND_NOW, "BIND_NOW"],
  [DF_STATIC_TLS, "STATIC_TLS"],
];

// DT_FLAGS_1 bit names in order (LSB first)
const DF_1_BITS: [number, string][] = [
  [DF_1_NOW, "NOW"],
  [DF_1_GLOBAL, "GLOBAL"],
  [DF_1_GROUP, "GROUP"],
  [DF_1_NODELETE, "NODELETE"],
  [DF_1_LOADFLTR, "LOADFLTR"],
  [DF_1_INITFIRST, "INITFIRST"],
  [DF_1_NOOPEN, "NOOPEN"],
  [DF_1_ORIGIN, "ORIGIN"],
  [DF_1_DIRECT, "DIRECT"],
  [DF_1_TRANS, "TRANS"],
  [DF_1_INTERPOSE, "INTERPOSE"],
  [DF_1_NODEFLIB, "NODEFLIB"],
  [DF_1_NODUMP, "NODUMP"],
  [DF_1_CONFALT, "CONFALT"],
  [DF_1_ENDFILTEE, "ENDFILTEE"],
  [DF_1_DISPRELDNE, "DISPRELDNE"],
  [DF_1_DISPRELPND, "DISPRELPND"],
  [DF_1_NODIRECT, "NODIRECT"],
  [DF_1_IGNMULDEF, "IGNMULDEF"],
  [DF_1_NOKSYMS, "NOKSYMS"],
  [DF_1_NOHDR, "NOHDR"],
  [DF_1_EDITED, "EDITED"],
  [DF_1_NORELOC, "NORELOC"],
  [DF_1_SYMINTPOSE, "SYMINTPOSE"],
  [DF_1_GLOBAUDIT, "GLOBAUDIT"],
  [DF_1_SINGLETON, "SINGLETON"],
  [DF_1_STUB, "STUB"],
  [DF_1_PIE, "PIE"],
  [DF_1_KMOD, "KMOD"],
  [DF_1_WEAKFILTER, "WEAKFILTER"],
  [DF_1_NOCOMMON, "NOCOMMON"],
];

function decodeBitFlags(val: bigint, bits: [number, string][]): string {
  const hex = `0x${val.toString(16).toUpperCase()}`;
  const names = bits.filter(([mask]) => val & BigInt(mask)).map(([, name]) => name);
  return names.length > 0 ? `${hex} (${names.join(" ")})` : hex;
}

// ─── Tooltip helpers ──────────────────────────────────────────────────────────

function dynEntryTooltipHtml(le: LayoutDynEntry): string {
  const fmtAddr = (v: bigint) => `0x${v.toString(16).toUpperCase()}`;
  const rows = [
    ttRow(le.tagName, fmtAddr(le.value)),
    ...le.companions.map((c) => ttRow(c.label, c.value)),
  ].join("");
  return `<div class="tt-title">${escapeHtml(le.tagName)}</div><table>${rows}</table>`;
}

// ─── Main render function ─────────────────────────────────────────────────────

export function renderDynamic(
  container: HTMLElement,
  elf: ELFFile,
  onNavigate?: (target: NavTarget) => void,
  onSectionClick?: (shIndex: number) => void,
  onHexDump?: (label: string, fileOffset: number, size: number) => void
): void {
  const entries = elf.dynamicEntries;
  container.innerHTML = `<h2 class="view-title">Dynamic Section (${entries.length} entries)</h2>`;

  if (entries.length === 0) {
    appendEmptyMessage(container, "No dynamic section");
    return;
  }

  const machine = elf.header.machine;

  // Build a tag → LayoutDynEntry map for navigation/tooltip metadata.
  // This is only populated for address-type tags (DT_RELA, DT_SYMTAB, etc.).
  const layout = buildLayout(elf, "");
  const dynByTag = new Map<number, LayoutDynEntry>(layout.dynamicEntries.map((e) => [e.tag, e]));

  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead><tr><th>Tag</th><th>Type</th><th>Value</th></tr></thead>
  `;
  const tbody = document.createElement("tbody");
  for (const de of entries) {
    const tr = document.createElement("tr");
    tr.id = `dyn-row-${de.tag}`;
    const tag = de.tag as number;
    let valueStr: string;

    if (de.name !== null) {
      // String-valued (DT_NEEDED etc.)
      const prefix =
        de.tag === DynTag.Needed
          ? "Shared library: "
          : de.tag === DynTag.SoName
            ? "Library soname: "
            : de.tag === DynTag.RPath
              ? "Library rpath: "
              : de.tag === DynTag.RunPath
                ? "Library runpath: "
                : "";
      valueStr = `${prefix}[${de.name}]`;
    } else if (de.tag === DynTag.Flags) {
      valueStr = decodeBitFlags(de.value, DF_BITS);
    } else if (de.tag === DynTag.Flags1) {
      valueStr = decodeBitFlags(de.value, DF_1_BITS);
    } else if (de.tag === DynTag.PltRel) {
      valueStr =
        de.value === BigInt(DynTag.Rela)
          ? "RELA"
          : de.value === BigInt(DynTag.Rel)
            ? "REL"
            : `0x${de.value.toString(16).toUpperCase()}`;
    } else if (DEC_TAGS.has(tag)) {
      valueStr = `${de.value}`;
    } else {
      valueStr = `0x${de.value.toString(16).toUpperCase()}`;
    }

    tr.innerHTML = `
      <td class="mono">${hexPad(de.tag, 16)}</td>
      <td class="mono">${dynTagName(de.tag, machine)}</td>
      <td class="mono">${valueStr}</td>
    `;

    // ── Tooltip ───────────────────────────────────────────────────────────────
    // Companion tags (e.g. RELASZ, RELAENT) inherit the LayoutDynEntry of their
    // address-type main tag (RELA), so they share the same tooltip and context menu.
    const le = dynByTag.get(tag) ?? dynByTag.get(companionToMainTag.get(tag) ?? -1);
    if (le) {
      tr.addEventListener("mouseenter", (e) =>
        showTooltip(dynEntryTooltipHtml(le), e.clientX, e.clientY)
      );
      tr.addEventListener("mousemove", (e) => moveTooltip(e.clientX, e.clientY));
      tr.addEventListener("mouseleave", () => hideTooltip());
    }

    // ── Context menu ──────────────────────────────────────────────────────────
    const navTarget = dynNavTarget(de.tag as DynTag);
    const menuItems: Array<CtxMenuItem | null> = [];

    if (navTarget && onNavigate)
      menuItems.push({
        label: `Open in ${navTargetLabel(navTarget)}`,
        action: () => onNavigate(navTarget),
      });

    if (le?.shIndex !== null && le?.shIndex !== undefined && onSectionClick)
      menuItems.push({
        label: `Go to Section Headers: ${le.sectionName ?? ""}`,
        action: () => onSectionClick(le.shIndex!),
      });

    if (
      le?.fileOffset !== null &&
      le?.fileOffset !== undefined &&
      le?.byteSize !== null &&
      le?.byteSize !== undefined &&
      le.byteSize > 0 &&
      onHexDump
    ) {
      const label = le.sectionName ?? dynTagName(de.tag, machine);
      const off = le.fileOffset,
        sz = le.byteSize;
      menuItems.push({ label: `Hex Dump: ${label}`, action: () => onHexDump(label, off, sz) });
    }

    const validItems = menuItems.filter(Boolean) as CtxMenuItem[];
    if (validItems.length > 0) {
      tr.classList.add("nav-row");
      // Double-click: open first available view
      if (navTarget && onNavigate) tr.addEventListener("dblclick", () => onNavigate(navTarget));
      attachCtxMenu(tr, validItems, hideTooltip);
    }

    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}
