// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Memory map visualization view.
// Renders a CSS-grid-based memory map of an ELF file.
// Ported from the original main.js rendering code.

import { type ELFFile, PHType } from "../parser/types.ts";
import {
  buildLayout,
  buildFileLayout,
  type LayoutData,
  type LayoutSegment,
  type LayoutSection,
  type LayoutNonLoad,
  type LayoutDynEntry,
  type LayoutHeaderInfo,
} from "./layout.ts";
import { attachCtxMenu as attachCtxMenuBase, type CtxMenuItem } from "../ui/ContextMenu.ts";
import { hideTooltip, addTooltipHandlers, escapeHtml, ttRow } from "../ui/Tooltip.ts";
import {
  type NavTarget,
  sectionNavTarget,
  navTargetLabel,
  dynNavTarget,
  phNavTarget,
} from "./viewUtils.ts";

// Wraps the shared context menu helper to always hide the tooltip before showing.
function attachCtxMenu(el: HTMLElement, items: Array<CtxMenuItem | null>): void {
  attachCtxMenuBase(el, items, hideTooltip);
}

// ─── Types for internal row representation ────────────────────────────────────

type RowType =
  | "gap"
  | "elf-header"
  | "program-headers"
  | "leading-gap"
  | "section-gap"
  | "section"
  | "no-section-segment";

interface BaseRow {
  type: RowType;
  bytes: bigint;
  isBss?: boolean;
}

interface GapRow extends BaseRow {
  type: "gap";
  gapStart: bigint;
  gapFlags?: string;
  gapColorClass?: string;
}

interface SegRow extends BaseRow {
  type: "elf-header" | "program-headers" | "leading-gap" | "section-gap" | "no-section-segment";
  seg: LayoutSegment;
  fileOffset?: number; // file offset (number); used for ELF header (0) and PH table
  rowAddr?: bigint;
  splitAddr?: bigint;
  splitSize?: bigint;
}

interface SectionRow extends BaseRow {
  type: "section";
  seg: LayoutSegment;
  sec: LayoutSection;
  secColorIdx: number;
  splitAddr?: bigint;
  splitSize?: bigint;
  splitOffset?: number; // file offset of this split within the section
  splitIndex?: number;
  splitTotal?: number;
}

type Row = GapRow | SegRow | SectionRow;

function rowSeg(row: Row): LayoutSegment | undefined {
  if (row.type === "gap") {
    return undefined;
  }
  return row.seg;
}

// ─── Column layout ────────────────────────────────────────────────────────────

interface ColLayout {
  offset: number | null;
  sections: number | null;
  dynamic: number | null;
  nlBase: number;
}

function computeCols(hasOffset: boolean, hasLabelsCol: boolean, hasDynEntries: boolean): ColLayout {
  let next = 2;
  const offset = hasOffset ? next++ : null;
  const sections = hasLabelsCol ? next++ : null;
  const dynamic = hasDynEntries ? next++ : null;
  const nlBase = next;
  return { offset, sections, dynamic, nlBase };
}

// ─── Color helpers ────────────────────────────────────────────────────────────

const colorMap: Record<string, [number, number, number]> = {
  rx: [40, 100, 190],
  rw: [40, 160, 70],
  ro: [190, 170, 30],
  other: [130, 130, 130],
};

function segmentColorCSS(cls: string, dim = false): string {
  const [r, g, b] = colorMap[cls] ?? colorMap.other;
  if (dim) {
    return `rgba(${Math.floor(r / 2 + 40)}, ${Math.floor(g / 2 + 40)}, ${Math.floor(b / 2 + 40)}, 0.55)`;
  }
  return `rgba(${r}, ${g}, ${b}, 0.86)`;
}

function sectionColor(cls: string, index: number, isBss: boolean): string {
  let [r, g, b] = colorMap[cls] ?? colorMap.other;
  if (isBss) {
    r = Math.floor(r / 2 + 40);
    g = Math.floor(g / 2 + 40);
    b = Math.floor(b / 2 + 40);
  }
  if (index % 2 === 0) {
    r = Math.min(r + 30, 255);
    g = Math.min(g + 30, 255);
    b = Math.min(b + 30, 255);
  } else {
    r = Math.max(r - 20, 0);
    g = Math.max(g - 20, 0);
    b = Math.max(b - 20, 0);
  }
  return `rgba(${r}, ${g}, ${b}, 0.86)`;
}

// ─── Formatters ───────────────────────────────────────────────────────────────

function makeFormatters(layout: LayoutData) {
  const segs = layout.segments;
  if (segs.length === 0) {
    return {
      fmtAddr: (v: bigint) => `0x${v.toString(16)}`,
      fmtOffset: null as null | ((v: number) => string),
    };
  }

  let maxAddr = 0n;
  for (const s of segs) {
    const end = s.vaddr + BigInt(s.memsz);
    if (end > maxAddr) {
      maxAddr = end;
    }
  }
  const hexDigits = maxAddr.toString(16).length;
  const fmtAddr = (val: bigint) => "0x" + val.toString(16).toUpperCase().padStart(hexDigits, "0");

  if (layout.isObjectFile) {
    return { fmtAddr, fmtOffset: null };
  }

  let maxOff = 0;
  for (const s of segs) {
    for (const sec of s.sections) {
      if (!sec.isNobits && sec.offset + sec.size > maxOff) {
        maxOff = sec.offset + sec.size;
      }
    }
    if (s.filesz > 0 && s.fileOff + s.filesz > maxOff) {
      maxOff = s.fileOff + s.filesz;
    }
  }
  if (maxOff === 0) {
    return { fmtAddr, fmtOffset: null };
  }
  const offDigits = maxOff.toString(16).length;
  const fmtOffset = (val: number) =>
    "(0x" + val.toString(16).toUpperCase().padStart(offDigits, "0") + ")";
  return { fmtAddr, fmtOffset };
}

// ─── Row building (ported from main.js buildRows) ────────────────────────────

function buildRows(
  segs: LayoutSegment[],
  hi: LayoutHeaderInfo | null,
  isObjectFile: boolean
): Row[] {
  const rows: Row[] = [];
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];

    // Gap before this segment
    if (i > 0) {
      const prev = segs[i - 1];
      const prevEnd = prev.vaddr + BigInt(prev.memsz);
      if (seg.vaddr > prevEnd) {
        const nextAlign = BigInt(seg.align > 0 ? seg.align : 1);
        const boundary = (seg.vaddr / nextAlign) * nextAlign;
        if (boundary > prevEnd && boundary < seg.vaddr) {
          rows.push({
            type: "gap",
            bytes: boundary - prevEnd,
            gapStart: prevEnd,
            gapFlags: prev.flags,
            gapColorClass: prev.colorClass,
          });
          rows.push({
            type: "gap",
            bytes: seg.vaddr - boundary,
            gapStart: boundary,
            gapFlags: seg.flags,
            gapColorClass: seg.colorClass,
          });
        } else {
          rows.push({
            type: "gap",
            bytes: seg.vaddr - prevEnd,
            gapStart: prevEnd,
            gapFlags: prev.flags,
            gapColorClass: prev.colorClass,
          });
        }
      }
    } else if (!isObjectFile) {
      // Gap before the very first segment if it doesn't start at its align boundary
      const align = BigInt(seg.align > 1 ? seg.align : 1);
      if (align > 1n) {
        const alignedStart = (seg.vaddr / align) * align;
        if (alignedStart < seg.vaddr) {
          rows.push({
            type: "gap",
            bytes: seg.vaddr - alignedStart,
            gapStart: alignedStart,
            gapFlags: seg.flags,
            gapColorClass: seg.colorClass,
          });
        }
      }
    }

    const hasSections = seg.sections.length > 0;
    const hasBss = seg.filesz > 0 && seg.filesz < seg.memsz;
    const fileEnd = hasBss ? seg.vaddr + BigInt(seg.filesz) : 0n;

    if (hasSections) {
      // Leading padding (ELF header / program headers / generic padding)
      const firstSecAddr = seg.sections[0].addr;
      if (firstSecAddr > seg.vaddr) {
        const gapBytes = firstSecAddr - seg.vaddr;

        const ehSize = hi ? hi.ehSize : 0;
        const phOff = hi ? hi.phOff : 0;
        const phTableSize = hi ? hi.phEntSize * hi.phNum : 0;

        if (hi && seg.fileOff === 0 && ehSize > 0) {
          const ehBytes = BigInt(ehSize) < gapBytes ? BigInt(ehSize) : gapBytes;
          rows.push({
            type: "elf-header",
            bytes: ehBytes,
            seg,
            isBss: false,
            fileOffset: 0,
          } as SegRow);
          let consumed = ehBytes;
          if (phTableSize > 0 && phOff === ehSize && consumed + BigInt(phTableSize) <= gapBytes) {
            rows.push({
              type: "program-headers",
              bytes: BigInt(phTableSize),
              seg,
              isBss: false,
              fileOffset: phOff,
            } as SegRow);
            consumed += BigInt(phTableSize);
          }
          if (consumed < gapBytes) {
            rows.push({
              type: "leading-gap",
              bytes: gapBytes - consumed,
              seg,
              isBss: false,
              rowAddr: seg.vaddr + consumed,
            } as SegRow);
          }
        } else {
          rows.push({
            type: "leading-gap",
            bytes: gapBytes,
            seg,
            isBss: false,
            rowAddr: seg.vaddr,
          } as SegRow);
        }
      }

      // Section rows
      let secColorIdx = 0;
      for (let si = 0; si < seg.sections.length; si++) {
        const sec = seg.sections[si];
        // Gap between consecutive sections
        if (si > 0) {
          const prevSec = seg.sections[si - 1];
          const prevSecEnd = prevSec.addr + BigInt(prevSec.size);
          if (sec.addr > prevSecEnd) {
            if (hasBss && prevSecEnd < fileEnd && sec.addr > fileEnd) {
              // Gap spans the file/BSS boundary: split into two rows
              rows.push({
                type: "section-gap",
                bytes: fileEnd - prevSecEnd,
                seg,
                isBss: false,
                rowAddr: prevSecEnd,
              } as SegRow);
              rows.push({
                type: "section-gap",
                bytes: sec.addr - fileEnd,
                seg,
                isBss: true,
                rowAddr: fileEnd,
              } as SegRow);
            } else {
              const gapIsBss = hasBss && prevSecEnd >= fileEnd;
              rows.push({
                type: "section-gap",
                bytes: sec.addr - prevSecEnd,
                seg,
                isBss: gapIsBss,
                rowAddr: prevSecEnd,
              } as SegRow);
            }
          }
        }
        const isBss = hasBss && sec.addr + BigInt(sec.size) > fileEnd;
        rows.push({
          type: "section",
          bytes: sec.size > 0 ? BigInt(sec.size) : 1n,
          seg,
          sec,
          isBss,
          secColorIdx,
        } as SectionRow);
        secColorIdx++;
      }
    } else {
      if (hi && seg.fileOff === 0 && seg.filesz > 0) {
        const ehSize = hi.ehSize;
        const phOff = hi.phOff;
        const phTableSize = hi.phEntSize * hi.phNum;
        let consumed = 0;
        if (ehSize > 0 && ehSize <= seg.filesz) {
          rows.push({
            type: "elf-header",
            bytes: BigInt(ehSize),
            seg,
            isBss: false,
            fileOffset: 0,
          } as SegRow);
          consumed = ehSize;
        }
        if (phTableSize > 0 && phOff === consumed && consumed + phTableSize <= seg.filesz) {
          rows.push({
            type: "program-headers",
            bytes: BigInt(phTableSize),
            seg,
            isBss: false,
            fileOffset: phOff,
          } as SegRow);
          consumed += phTableSize;
        }
        if (consumed < seg.memsz) {
          if (hasBss && consumed < seg.filesz) {
            rows.push({
              type: "no-section-segment",
              bytes: BigInt(seg.filesz - consumed),
              seg,
              isBss: false,
              splitAddr: seg.vaddr + BigInt(consumed),
              splitSize: BigInt(seg.filesz - consumed),
            } as SegRow);
            rows.push({
              type: "no-section-segment",
              bytes: BigInt(seg.memsz - seg.filesz),
              seg,
              isBss: true,
              splitAddr: seg.vaddr + BigInt(seg.filesz),
              splitSize: BigInt(seg.memsz - seg.filesz),
            } as SegRow);
          } else if (hasBss) {
            rows.push({
              type: "no-section-segment",
              bytes: BigInt(seg.memsz - consumed),
              seg,
              isBss: true,
              splitAddr: seg.vaddr + BigInt(consumed),
              splitSize: BigInt(seg.memsz - consumed),
            } as SegRow);
          } else {
            rows.push({
              type: "no-section-segment",
              bytes: BigInt(seg.memsz - consumed),
              seg,
              splitAddr: seg.vaddr + BigInt(consumed),
              splitSize: BigInt(seg.memsz - consumed),
            } as SegRow);
          }
        }
      } else {
        if (hasBss) {
          rows.push({
            type: "no-section-segment",
            bytes: seg.filesz > 0 ? BigInt(seg.filesz) : 1n,
            seg,
            isBss: false,
          } as SegRow);
          rows.push({
            type: "no-section-segment",
            bytes: BigInt(seg.memsz - seg.filesz),
            seg,
            isBss: true,
            splitAddr: seg.vaddr + BigInt(seg.filesz),
            splitSize: BigInt(seg.memsz - seg.filesz),
          } as SegRow);
        } else {
          rows.push({
            type: "no-section-segment",
            bytes: seg.memsz > 0 ? BigInt(seg.memsz) : 1n,
            seg,
          } as SegRow);
        }
      }
    }
  }

  // Gap after the very last segment if it doesn't end at its align boundary
  if (!isObjectFile && segs.length > 0) {
    const last = segs[segs.length - 1];
    const align = BigInt(last.align > 1 ? last.align : 1);
    if (align > 1n) {
      const lastEnd = last.vaddr + BigInt(last.memsz);
      const alignedEnd = ((lastEnd + align - 1n) / align) * align;
      if (alignedEnd > lastEnd) {
        rows.push({
          type: "gap",
          bytes: alignedEnd - lastEnd,
          gapStart: lastEnd,
          gapFlags: last.flags,
          gapColorClass: last.colorClass,
        });
      }
    }
  }

  return rows;
}

function splitAtNonLoad(rows: Row[], nonLoad: LayoutNonLoad[]): void {
  if (nonLoad.length === 0) {
    return;
  }
  const splitPoints = new Set<bigint>();
  for (const ns of nonLoad) {
    // Use filesz for the end boundary (not memsz), so BSS-like extensions (e.g.
    // PT_TLS .tbss) don't generate split points inside unrelated sections.
    const extent = ns.filesz > 0 ? ns.filesz : ns.memsz;
    if (extent > 0) {
      splitPoints.add(ns.vaddr);
      splitPoints.add(ns.vaddr + BigInt(extent));
    }
  }
  const sorted = [...splitPoints].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  for (let r = rows.length - 1; r >= 0; r--) {
    const row = rows[r];
    if (row.type !== "section" && row.type !== "no-section-segment") {
      continue;
    }
    const { start: rowStart, end: rowEnd } = getRowAddrRange(row)!;

    const points = sorted.filter((p) => p > rowStart && p < rowEnd);
    if (points.length === 0) {
      continue;
    }
    const boundaries = [rowStart, ...points, rowEnd];
    const newRows: Row[] = [];
    if (row.type === "no-section-segment") {
      for (let i = 0; i < boundaries.length - 1; i++) {
        const addr = boundaries[i];
        const size = boundaries[i + 1] - addr;
        newRows.push({
          type: "no-section-segment",
          bytes: size > 0n ? size : 1n,
          seg: row.seg,
          splitAddr: addr,
          splitSize: size,
          isBss: addr >= row.seg.vaddr + BigInt(row.seg.filesz),
        });
      }
    } else if (row.type === "section") {
      for (let i = 0; i < boundaries.length - 1; i++) {
        const addr = boundaries[i];
        const size = boundaries[i + 1] - addr;
        const origSplitAddr = row.splitAddr ?? row.sec.addr;
        newRows.push({
          type: "section",
          bytes: size > 0n ? size : 1n,
          seg: row.seg,
          sec: row.sec,
          isBss: row.isBss,
          secColorIdx: row.secColorIdx,
          splitAddr: addr,
          splitSize: size,
          splitOffset: row.sec.offset + Number(addr - origSplitAddr),
          splitIndex: i,
          splitTotal: boundaries.length - 1,
        });
      }
    }
    rows.splice(r, 1, ...newRows);
  }
}

function splitAtDynamicEntries(rows: Row[], dynEntries: LayoutDynEntry[]): void {
  if (dynEntries.length === 0) {
    return;
  }
  const splitPoints = new Set<bigint>();
  for (const de of dynEntries) {
    splitPoints.add(de.addr);
    if (de.byteSize !== null && de.byteSize > 0) {
      splitPoints.add(de.addr + BigInt(de.byteSize));
    }
  }
  const sorted = [...splitPoints].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  for (let r = rows.length - 1; r >= 0; r--) {
    const row = rows[r];
    if (row.type !== "no-section-segment") {
      continue;
    }
    const sr = row as SegRow;
    const rowStart = sr.splitAddr ?? sr.seg.vaddr;
    const rowEnd = rowStart + (sr.splitSize ?? BigInt(sr.seg.memsz));
    const points = sorted.filter((p) => p > rowStart && p < rowEnd);
    if (points.length === 0) {
      continue;
    }
    const boundaries = [rowStart, ...points, rowEnd];
    const newRows: Row[] = boundaries.slice(0, -1).map((addr, i) => {
      const size = boundaries[i + 1] - addr;
      return {
        type: "no-section-segment",
        bytes: size > 0n ? size : 1n,
        seg: sr.seg,
        splitAddr: addr,
        splitSize: size,
        isBss: addr >= sr.seg.vaddr + BigInt(sr.seg.filesz),
      } as SegRow;
    });
    rows.splice(r, 1, ...newRows);
  }
}

interface NLEntry {
  ns: LayoutNonLoad;
  firstRow: number;
  lastRow: number;
  lane: number;
}

function assignLanes(
  rows: Row[],
  nonLoad: LayoutNonLoad[]
): { nlEntries: NLEntry[]; nlLaneCount: number } {
  const nlEntries: NLEntry[] = [];
  for (const ns of nonLoad) {
    const nsStart = ns.vaddr;
    const nsEnd = ns.vaddr + BigInt(ns.filesz);
    let firstRow = -1,
      lastRow = -1;
    for (let r = 0; r < rows.length; r++) {
      const range = getRowAddrRange(rows[r]);
      if (range === null) {
        continue;
      }
      if (range.start < nsEnd && range.end > nsStart) {
        if (firstRow === -1) {
          firstRow = r;
        }
        lastRow = r;
      }
    }
    if (firstRow !== -1) {
      nlEntries.push({ ns, firstRow, lastRow, lane: -1 });
    }
  }

  for (const entry of nlEntries) {
    let lane = 0;
    while (
      nlEntries.some(
        (o) => o.lane === lane && o.firstRow <= entry.lastRow && o.lastRow >= entry.firstRow
      )
    ) {
      lane++;
    }
    entry.lane = lane;
  }
  const nlLaneCount = nlEntries.length > 0 ? Math.max(...nlEntries.map((e) => e.lane)) + 1 : 0;
  return { nlEntries, nlLaneCount };
}

function buildSegSpans(
  rows: Row[]
): Map<number, { startRow: number; endRow: number; fileRows: number; bssRows: number }> {
  const map = new Map<
    number,
    { startRow: number; endRow: number; fileRows: number; bssRows: number }
  >();
  for (let r = 0; r < rows.length; r++) {
    const seg = rowSeg(rows[r]);
    if (!seg) {
      continue;
    }
    const idx = seg.index;
    if (!map.has(idx)) {
      map.set(idx, { startRow: r, endRow: r, fileRows: 0, bssRows: 0 });
    }
    const span = map.get(idx)!;
    span.endRow = r;
    if (rows[r].isBss) {
      span.bssRows++;
    } else {
      span.fileRows++;
    }
  }
  return map;
}

// Returns the virtual address range [start, end) of a row, or null for gap rows.
function getRowAddrRange(row: Row): { start: bigint; end: bigint } | null {
  if (row.type === "section") {
    const start = row.splitAddr ?? row.sec.addr;
    return { start, end: start + (row.splitSize ?? BigInt(row.sec.size)) };
  }
  if (row.type === "leading-gap" || row.type === "section-gap") {
    const start = row.rowAddr ?? row.seg.vaddr;
    return { start, end: start + row.bytes };
  }
  if (row.type === "elf-header" || row.type === "program-headers") {
    const start = row.seg.vaddr + BigInt(row.fileOffset ?? 0);
    return { start, end: start + row.bytes };
  }
  if (row.type === "no-section-segment") {
    const start = row.splitAddr ?? row.seg.vaddr;
    return { start, end: start + (row.splitSize ?? BigInt(row.seg.memsz)) };
  }
  return null; // 'gap' rows have no segment address range
}

// ─── Tooltip HTML builders ────────────────────────────────────────────────────

function sectionTooltipHtml(
  sec: LayoutSection,
  fmtAddr: (v: bigint) => string,
  fmtOffset: ((v: number) => string) | null
): string {
  const showOffset = BigInt(sec.offset) !== sec.addr;
  const fmtOff = fmtOffset
    ? (v: number) => fmtOffset(v).slice(1, -1)
    : (v: number) => `0x${v.toString(16).toUpperCase()}`;
  const rows = [
    ttRow("Type", sec.typeName),
    ttRow("Flags", sec.flags),
    ttRow("Address", fmtAddr(sec.addr)),
    ...(showOffset ? [ttRow("Offset", fmtOff(sec.offset))] : []),
    ttRow("Size", `0x${sec.size.toString(16).toUpperCase()}`),
    ...(sec.entsize > 0 ? [ttRow("EntrySize", `0x${sec.entsize.toString(16).toUpperCase()}`)] : []),
    ...(sec.link > 0 ? [ttRow("Link", String(sec.link))] : []),
    ...(sec.info > 0 ? [ttRow("Info", String(sec.info))] : []),
    ttRow("Align", String(sec.addralign)),
  ].join("");
  return `<div class="tt-title">${escapeHtml(sec.name)}</div><table>${rows}</table>`;
}

function segmentTooltipHtml(
  seg: LayoutSegment,
  fmtAddr: (v: bigint) => string,
  fmtOffset: ((v: number) => string) | null
): string {
  const label = seg.typeName ?? "LOAD";
  const title =
    seg.index >= 0 ? `${label}  <span class="tt-index">PH #${seg.index}</span>` : escapeHtml(label);
  const showPaddr = seg.paddr !== seg.vaddr;
  const showOffset = BigInt(seg.fileOff) !== seg.vaddr;
  const showMemsz = seg.memsz !== seg.filesz;
  const fmtOff = fmtOffset
    ? (v: number) => fmtOffset(v).slice(1, -1)
    : (v: number) => `0x${v.toString(16).toUpperCase()}`;
  const rows = [
    ttRow("Flags", seg.flags),
    ttRow("VirtAddr", fmtAddr(seg.vaddr)),
    ...(showPaddr ? [ttRow("PhysAddr", fmtAddr(seg.paddr))] : []),
    ...(showOffset ? [ttRow("Offset", fmtOff(seg.fileOff))] : []),
    ttRow("FileSize", `0x${seg.filesz.toString(16).toUpperCase()}`),
    ...(showMemsz ? [ttRow("MemSize", `0x${seg.memsz.toString(16).toUpperCase()}`)] : []),
    ttRow("Align", `0x${seg.align.toString(16)}`),
  ].join("");
  return `<div class="tt-title">${title}</div><table>${rows}</table>`;
}

function nonLoadTooltipHtml(
  ns: LayoutNonLoad,
  fmtAddr: (v: bigint) => string,
  fmtOffset: ((v: number) => string) | null
): string {
  const showPaddr = ns.paddr !== ns.vaddr;
  const showOffset = BigInt(ns.fileOff) !== ns.vaddr;
  const showMemsz = ns.memsz !== ns.filesz;
  const fmtOff = fmtOffset
    ? (v: number) => fmtOffset(v).slice(1, -1)
    : (v: number) => `0x${v.toString(16).toUpperCase()}`;
  const rows = [
    ttRow("Flags", ns.flags),
    ttRow("VirtAddr", fmtAddr(ns.vaddr)),
    ...(showPaddr ? [ttRow("PhysAddr", fmtAddr(ns.paddr))] : []),
    ...(showOffset ? [ttRow("Offset", fmtOff(ns.fileOff))] : []),
    ttRow("FileSize", `0x${ns.filesz.toString(16).toUpperCase()}`),
    ...(showMemsz ? [ttRow("MemSize", `0x${ns.memsz.toString(16).toUpperCase()}`)] : []),
    ttRow("Align", `0x${ns.align.toString(16)}`),
  ].join("");
  return `<div class="tt-title">${escapeHtml(ns.typeName)}  <span class="tt-index">PH #${ns.index}</span></div><table>${rows}</table>`;
}

function makeCell(container: HTMLElement, className: string, text: string): HTMLElement {
  const el = document.createElement("div");
  el.className = className;
  el.textContent = text;
  container.appendChild(el);
  return el;
}

// ─── Grid setup ───────────────────────────────────────────────────────────────

function setupGrid(
  container: HTMLElement,
  rows: Row[],
  cols: ColLayout,
  nlLaneCount: number,
  isObjectFile: boolean
): void {
  const totalSpan = rows.reduce((s, r) => s + r.bytes, 0n) || 1n;
  const totalHeight = 500;
  const minRowH = 24;
  const rowHeights = rows.map((r) =>
    Math.max(Math.round((Number(r.bytes) / Number(totalSpan)) * totalHeight), minRowH)
  );
  container.style.gridTemplateRows = "auto " + rowHeights.map((h) => h + "px").join(" ");

  let colTemplate: string;
  if (isObjectFile) {
    colTemplate = cols.sections !== null ? "auto auto" : "auto";
  } else {
    const offsetCol = cols.offset !== null ? "auto" : "";
    const sectionsCol = cols.sections !== null ? "auto" : "";
    const dynCol = cols.dynamic !== null ? "auto" : "";
    const nlCols = Array(nlLaneCount).fill("auto").join(" ");
    colTemplate = `auto ${offsetCol} ${sectionsCol} ${dynCol} ${nlCols} auto auto`
      .replace(/\s+/g, " ")
      .trim();
  }
  container.style.gridTemplateColumns = colTemplate;
}

function renderHeaderRow(container: HTMLElement, cols: ColLayout, isObjectFile: boolean): void {
  const addH = (text: string, col: string) => {
    const h = document.createElement("div");
    h.className = "map-header";
    h.textContent = text;
    h.style.gridRow = "1";
    h.style.gridColumn = col;
    container.appendChild(h);
  };
  const addrLabel = isObjectFile ? "File Offset" : "Address";
  addH(addrLabel, "1");
  if (cols.offset !== null) {
    addH("File Offset", String(cols.offset));
  }
  if (cols.sections !== null) {
    addH("Sections", String(cols.sections));
  }
  if (!isObjectFile) {
    if (cols.dynamic !== null) {
      addH("Dynamic", String(cols.dynamic));
    }
    addH("Program Headers", `${cols.nlBase} / -2`);
    addH(addrLabel, "-2");
  }
}

// ─── Row rendering ────────────────────────────────────────────────────────────

function renderRows(
  container: HTMLElement,
  rows: Row[],
  fmtAddr: (v: bigint) => string,
  fmtOffset: ((v: number) => string) | null,
  cols: ColLayout,
  segSpans: ReturnType<typeof buildSegSpans>,
  emitted: Set<number>,
  isObjectFile: boolean,
  onSectionClick?: (shIndex: number | null, segIndex: number) => void,
  onElfHeaderClick?: () => void,
  onProgHeadersClick?: () => void,
  onSectionHeadersClick?: () => void,
  onHexDump?: (label: string, fileOffset: number, size: number) => void,
  onNavigate?: (target: NavTarget) => void
): void {
  let stripeIdx = 0;
  for (let r = 0; r < rows.length; r++) {
    const row = rows[r];
    const gridRow = r + 2;

    const dim = isObjectFile && row.type !== "gap" && stripeIdx % 2 === 1;
    if (isObjectFile && row.type !== "gap") {
      stripeIdx++;
    }

    if (row.type === "gap") {
      placeGapRow(container, gridRow, row, fmtAddr, cols, isObjectFile);
    } else if (row.type === "elf-header") {
      placeHeaderRow(
        container,
        gridRow,
        row,
        "ELF Header",
        fmtAddr,
        fmtOffset,
        cols,
        onElfHeaderClick,
        onHexDump,
        dim
      );
      maybeEmitSegInfo(
        container,
        row.seg,
        fmtAddr,
        fmtOffset,
        cols,
        segSpans,
        emitted,
        isObjectFile,
        onSectionClick,
        onHexDump
      );
    } else if (row.type === "program-headers") {
      placeHeaderRow(
        container,
        gridRow,
        row,
        "Program Headers",
        fmtAddr,
        fmtOffset,
        cols,
        onProgHeadersClick,
        onHexDump,
        dim
      );
      maybeEmitSegInfo(
        container,
        row.seg,
        fmtAddr,
        fmtOffset,
        cols,
        segSpans,
        emitted,
        isObjectFile,
        onSectionClick,
        onHexDump
      );
    } else if (row.type === "leading-gap") {
      placeLeadingGapRow(container, gridRow, row, fmtAddr, cols, dim);
      maybeEmitSegInfo(
        container,
        row.seg,
        fmtAddr,
        fmtOffset,
        cols,
        segSpans,
        emitted,
        isObjectFile,
        onSectionClick,
        onHexDump
      );
    } else if (row.type === "section-gap") {
      placeLeadingGapRow(container, gridRow, row, fmtAddr, cols, dim);
      maybeEmitSegInfo(
        container,
        row.seg,
        fmtAddr,
        fmtOffset,
        cols,
        segSpans,
        emitted,
        isObjectFile,
        onSectionClick,
        onHexDump
      );
    } else if (row.type === "section") {
      placeSectionRow(
        container,
        gridRow,
        row,
        fmtAddr,
        fmtOffset,
        cols,
        onSectionClick,
        onHexDump,
        onNavigate,
        dim
      );
      maybeEmitSegInfo(
        container,
        row.seg,
        fmtAddr,
        fmtOffset,
        cols,
        segSpans,
        emitted,
        isObjectFile,
        onSectionClick,
        onHexDump
      );
    } else if (row.type === "no-section-segment") {
      const segIdx = (row as SegRow).seg.index;
      const noSecClick =
        segIdx === -1
          ? onElfHeaderClick
          : segIdx === -3
            ? onProgHeadersClick
            : segIdx === -2
              ? onSectionHeadersClick
              : undefined;
      const noSecGoTo =
        segIdx === -1
          ? "ELF Header"
          : segIdx === -3
            ? "Program Headers"
            : segIdx === -2
              ? "Section Headers"
              : undefined;
      placeNoSectionRow(
        container,
        gridRow,
        row,
        fmtAddr,
        fmtOffset,
        cols,
        noSecClick,
        onHexDump,
        noSecGoTo,
        dim
      );
      maybeEmitSegInfo(
        container,
        row.seg,
        fmtAddr,
        fmtOffset,
        cols,
        segSpans,
        emitted,
        isObjectFile,
        onSectionClick,
        onHexDump
      );
    }
  }
}

function placeGapRow(
  container: HTMLElement,
  gridRow: number,
  row: GapRow,
  fmtAddr: (v: bigint) => string,
  cols: ColLayout,
  isObjectFile: boolean
): void {
  const addr = makeCell(container, "addr-cell", fmtAddr(row.gapStart));
  addr.style.gridRow = String(gridRow);
  addr.style.gridColumn = "1";

  if (isObjectFile && cols.sections !== null) {
    const item = document.createElement("div");
    item.className = "sec-item leading-gap";
    item.style.gridRow = String(gridRow);
    item.style.gridColumn = String(cols.sections);
    item.innerHTML = `<span>(padding)</span><span style="margin-left:auto;font-size:10px;opacity:0.7">0x${row.bytes.toString(16).toUpperCase()}</span>`;
    container.appendChild(item);
    return;
  }

  const gap = document.createElement("div");
  gap.className = "gap-cell";
  gap.style.gridRow = String(gridRow);
  const gapStartCol = cols.sections ?? cols.dynamic ?? cols.nlBase;
  gap.style.gridColumn = `${gapStartCol} / -2`;
  if (row.gapColorClass) {
    const [r, g, b] = colorMap[row.gapColorClass] ?? colorMap.other;
    gap.style.background = `rgba(${r}, ${g}, ${b}, 0.12)`;
    gap.style.borderLeft = `3px solid rgba(${r}, ${g}, ${b}, 0.5)`;
  }
  gap.textContent = `gap  0x${row.bytes.toString(16).toUpperCase()}${row.gapFlags ? ` [${row.gapFlags}]` : ""}`;
  container.appendChild(gap);

  const rAddr = document.createElement("div");
  rAddr.className = "addr-cell";
  rAddr.style.gridRow = String(gridRow);
  rAddr.style.gridColumn = "-2";
  rAddr.style.flexDirection = "column";
  rAddr.style.alignItems = "center";
  rAddr.style.justifyContent = "space-between";
  rAddr.innerHTML = `<span>${fmtAddr(row.gapStart)}</span><span>${fmtAddr(row.gapStart + row.bytes - 1n)}</span>`;
  container.appendChild(rAddr);
}

function placeHeaderRow(
  container: HTMLElement,
  gridRow: number,
  row: SegRow,
  label: string,
  fmtAddr: (v: bigint) => string,
  fmtOffset: ((v: number) => string) | null,
  cols: ColLayout,
  onClick?: () => void,
  onHexDump?: (label: string, fileOffset: number, size: number) => void,
  dim = false
): void {
  const fo = row.fileOffset ?? 0;
  const vaddr = row.seg.vaddr + BigInt(fo);
  const addr = makeCell(container, "addr-cell", fmtAddr(vaddr));
  addr.style.gridRow = String(gridRow);
  addr.style.gridColumn = "1";

  if (fmtOffset && cols.offset !== null) {
    const off = makeCell(container, "offset-cell", fmtOffset(fo));
    off.style.gridRow = String(gridRow);
    off.style.gridColumn = String(cols.offset);
  }

  if (cols.sections !== null) {
    const item = document.createElement("div");
    item.className = "sec-item leading-gap";
    item.style.gridRow = String(gridRow);
    item.style.gridColumn = String(cols.sections);
    const hdrBase = "rgba(180, 150, 220, 0.25)";
    item.style.background = dim
      ? `linear-gradient(rgba(49,50,68,0.4),rgba(49,50,68,0.4)),${hdrBase}`
      : hdrBase;
    item.style.color = "#cba6f7";
    item.innerHTML = `<span>${label}</span><span style="margin-left:auto;font-size:10px;opacity:0.7">0x${row.bytes.toString(16).toUpperCase()}</span>`;
    const rowSize = Number(row.bytes);
    const hasHex = !!onHexDump && rowSize > 0;
    if (onClick || hasHex) {
      item.style.cursor = "pointer";
      if (onClick) {
        item.addEventListener("click", onClick);
      }
      attachCtxMenu(item, [
        onClick ? { label: `Go to ${label}`, action: onClick } : null,
        hasHex
          ? { label: `Hex Dump: ${label}`, action: () => onHexDump!(label, fo, rowSize) }
          : null,
      ]);
    }
    container.appendChild(item);
  }
}

function placeLeadingGapRow(
  container: HTMLElement,
  gridRow: number,
  row: SegRow,
  fmtAddr: (v: bigint) => string,
  cols: ColLayout,
  dim = false
): void {
  const padAddr = row.rowAddr ?? row.seg.vaddr;
  const addr = makeCell(container, "addr-cell", fmtAddr(padAddr));
  addr.style.gridRow = String(gridRow);
  addr.style.gridColumn = "1";

  if (cols.sections !== null) {
    const item = document.createElement("div");
    item.className = "sec-item leading-gap";
    item.style.gridRow = String(gridRow);
    item.style.gridColumn = String(cols.sections);
    if (dim) {
      item.style.setProperty(
        "background",
        "linear-gradient(rgba(49,50,68,0.4),rgba(49,50,68,0.4)),rgba(120,120,120,0.2)",
        "important"
      );
    }
    item.innerHTML = `<span>(padding)</span><span style="margin-left:auto;font-size:10px;opacity:0.7">0x${row.bytes.toString(16).toUpperCase()}</span>`;
    container.appendChild(item);
  }
}

function placeSectionRow(
  container: HTMLElement,
  gridRow: number,
  row: SectionRow,
  fmtAddr: (v: bigint) => string,
  fmtOffset: ((v: number) => string) | null,
  cols: ColLayout,
  onSectionClick?: (shIndex: number | null, segIndex: number) => void,
  onHexDump?: (label: string, fileOffset: number, size: number) => void,
  onNavigate?: (target: NavTarget) => void,
  dim = false
): void {
  const sec = row.sec;
  const secAddr = row.splitAddr ?? sec.addr;
  const secSize = row.splitSize ?? BigInt(sec.size);
  const secOffset = row.splitOffset ?? sec.offset;

  const addr = makeCell(container, "addr-cell", fmtAddr(secAddr));
  addr.style.gridRow = String(gridRow);
  addr.style.gridColumn = "1";

  if (fmtOffset && cols.offset !== null && !sec.isNobits) {
    const off = makeCell(container, "offset-cell", fmtOffset(secOffset));
    off.style.gridRow = String(gridRow);
    off.style.gridColumn = String(cols.offset);
  }

  let splitLabel = "";
  if (row.splitTotal !== undefined) {
    if (row.splitTotal === 2) {
      splitLabel =
        row.splitIndex === 0
          ? ' <span style="font-size:10px;opacity:0.7">(first half)</span>'
          : ' <span style="font-size:10px;opacity:0.7">(second half)</span>';
    } else {
      splitLabel = ` <span style="font-size:10px;opacity:0.7">(part ${(row.splitIndex ?? 0) + 1}/${row.splitTotal})</span>`;
    }
  }

  if (cols.sections !== null) {
    const item = document.createElement("div");
    item.className = "sec-item" + (row.isBss ? " bss" : "");
    const secBase = sectionColor(row.seg.colorClass, row.secColorIdx, row.isBss ?? false);
    item.style.background = dim
      ? `linear-gradient(rgba(49,50,68,0.4),rgba(49,50,68,0.4)),${secBase}`
      : secBase;
    item.style.gridRow = String(gridRow);
    item.style.gridColumn = String(cols.sections);
    item.innerHTML = `<span>${escapeHtml(sec.name)}${splitLabel}</span><span style="margin-left:auto;font-size:10px;opacity:0.7">0x${secSize.toString(16).toUpperCase()}</span>`;
    addTooltipHandlers(item, () => sectionTooltipHtml(sec, fmtAddr, fmtOffset));
    const hasHex = !!onHexDump && !sec.isNobits && sec.size > 0;
    const navTarget = onNavigate ? sectionNavTarget(sec.shType) : null;
    if (onSectionClick || hasHex || navTarget !== null) {
      item.style.cursor = "pointer";
      if (onSectionClick) {
        item.addEventListener("click", () => onSectionClick(sec.shIndex, row.seg.index));
      }
      attachCtxMenu(item, [
        onSectionClick
          ? {
              label: "Go to Section Headers",
              action: () => onSectionClick(sec.shIndex, row.seg.index),
            }
          : null,
        navTarget
          ? { label: `Open in ${navTargetLabel(navTarget)}`, action: () => onNavigate!(navTarget) }
          : null,
        hasHex
          ? {
              label: `Hex Dump: ${sec.name}`,
              action: () => onHexDump!(sec.name, sec.offset, sec.size),
            }
          : null,
      ]);
    }
    container.appendChild(item);
  }
}

function placeNoSectionRow(
  container: HTMLElement,
  gridRow: number,
  row: SegRow,
  fmtAddr: (v: bigint) => string,
  fmtOffset: ((v: number) => string) | null,
  cols: ColLayout,
  onClick?: () => void,
  onHexDump?: (label: string, fileOffset: number, size: number) => void,
  goToLabel?: string,
  dim = false
): void {
  const seg = row.seg;
  const rowAddr = row.splitAddr ?? seg.vaddr;
  const addr = makeCell(container, "addr-cell", fmtAddr(rowAddr));
  addr.style.gridRow = String(gridRow);
  addr.style.gridColumn = "1";

  if (fmtOffset && cols.offset !== null && seg.filesz > 0 && !row.isBss) {
    const rowFileOff = seg.fileOff + Number(rowAddr - seg.vaddr);
    const off = makeCell(container, "offset-cell", fmtOffset(rowFileOff));
    off.style.gridRow = String(gridRow);
    off.style.gridColumn = String(cols.offset);
  }

  if (cols.sections !== null && seg.typeName) {
    const rowSize = row.splitSize ?? BigInt(seg.memsz);
    const item = document.createElement("div");
    if (row.isBss) {
      item.className = "sec-item bss";
      const bssBase = sectionColor(seg.colorClass, 0, true);
      item.style.background = dim
        ? `linear-gradient(rgba(49,50,68,0.4),rgba(49,50,68,0.4)),${bssBase}`
        : bssBase;
    } else {
      item.className = "sec-item leading-gap";
      if (dim) {
        item.style.setProperty(
          "background",
          "linear-gradient(rgba(49,50,68,0.4),rgba(49,50,68,0.4)),rgba(120,120,120,0.2)",
          "important"
        );
      }
    }
    item.style.gridRow = String(gridRow);
    item.style.gridColumn = String(cols.sections);
    if (seg.index < 0) {
      item.style.color = "#cba6f7";
    }
    item.innerHTML = `<span>${escapeHtml(seg.typeName)}</span><span style="margin-left:auto;font-size:10px;opacity:0.7">0x${rowSize.toString(16).toUpperCase()}</span>`;
    const hasHex = !!onHexDump && seg.filesz > 0 && !row.isBss;
    const hexLabel = seg.typeName ?? `Segment #${seg.index}`;
    if (onClick || hasHex) {
      item.style.cursor = "pointer";
      if (onClick) {
        item.addEventListener("click", onClick);
      }
      attachCtxMenu(item, [
        onClick && goToLabel ? { label: `Go to ${goToLabel}`, action: onClick } : null,
        hasHex
          ? {
              label: `Hex Dump: ${hexLabel}`,
              action: () => onHexDump!(hexLabel, seg.fileOff, seg.filesz),
            }
          : null,
      ]);
    }
    container.appendChild(item);
  }
}

// Canonical section name for a non-load segment type.
function nonLoadHexLabel(ns: LayoutNonLoad): string {
  switch (ns.phType) {
    case PHType.Dynamic:
      return ".dynamic";
    case PHType.Interp:
      return ".interp";
    case PHType.GnuEhFrame:
      return ".eh_frame_hdr";
    case PHType.GnuProperty:
      return ".note.gnu.property";
    default:
      return `${ns.typeName} PH #${ns.index}`;
  }
}

function renderNonLoadOverlays(
  container: HTMLElement,
  nlEntries: NLEntry[],
  cols: ColLayout,
  fmtAddr: (v: bigint) => string,
  fmtOffset: ((v: number) => string) | null,
  onSectionClick?: (shIndex: number | null, segIndex: number) => void,
  onHexDump?: (label: string, fileOffset: number, size: number) => void,
  onNavigate?: (target: NavTarget) => void
): void {
  for (const { ns, firstRow, lastRow, lane } of nlEntries) {
    const block = document.createElement("div");
    block.className = "non-load-seg";
    block.style.gridRow = `${firstRow + 2} / span ${lastRow - firstRow + 1}`;
    block.style.gridColumn = String(cols.nlBase + lane);
    block.innerHTML = `<span class="nl-type">${ns.typeName}</span><span>PH #${ns.index} ${ns.flags}</span>`;
    addTooltipHandlers(block, () => nonLoadTooltipHtml(ns, fmtAddr, fmtOffset));
    const hasHex = !!onHexDump && ns.filesz > 0;
    const navTarget = onNavigate ? phNavTarget(ns.phType) : null;
    if (onSectionClick || hasHex || navTarget !== null) {
      block.style.cursor = "pointer";
      if (onSectionClick) {
        block.addEventListener("click", () => onSectionClick(null, ns.index));
      }
      attachCtxMenu(block, [
        onSectionClick
          ? { label: "Go to Program Headers", action: () => onSectionClick(null, ns.index) }
          : null,
        navTarget
          ? { label: `Open in ${navTargetLabel(navTarget)}`, action: () => onNavigate!(navTarget) }
          : null,
        hasHex
          ? {
              label: `Hex Dump: ${nonLoadHexLabel(ns)}`,
              action: () => onHexDump!(nonLoadHexLabel(ns), ns.fileOff, ns.filesz),
            }
          : null,
      ]);
    }
    container.appendChild(block);
  }
}

function dynEntryTooltipHtml(entries: LayoutDynEntry[], fmtAddr: (v: bigint) => string): string {
  return entries
    .map((de) => {
      const rows = [
        ttRow(de.tagName, fmtAddr(de.value)),
        ...de.companions.map((c) => ttRow(c.label, c.value)),
      ].join("");
      return `<div class="tt-title">${escapeHtml(de.tagName)}</div><table>${rows}</table>`;
    })
    .join('<div class="tt-sep"></div>');
}

function renderDynamicEntries(
  container: HTMLElement,
  rows: Row[],
  dynEntries: LayoutDynEntry[],
  cols: ColLayout,
  fmtAddr: (v: bigint) => string,
  onDynamicClick?: (tag: number) => void,
  onSectionClick?: (shIndex: number | null, segIndex: number) => void,
  onNavigate?: (target: NavTarget) => void,
  onHexDump?: (label: string, fileOffset: number, size: number) => void
): void {
  const dynByRow = new Map<number, LayoutDynEntry[]>();
  for (const de of dynEntries) {
    for (let r = 0; r < rows.length; r++) {
      const range = getRowAddrRange(rows[r]);
      if (range === null) {
        continue;
      }
      if (de.addr >= range.start && de.addr < range.end) {
        if (!dynByRow.has(r)) {
          dynByRow.set(r, []);
        }
        dynByRow.get(r)!.push(de);
        break;
      }
    }
  }
  for (const [r, entries] of dynByRow) {
    const cell = document.createElement("div");
    cell.className = "dyn-entry";
    cell.style.gridRow = String(r + 2);
    cell.style.gridColumn = String(cols.dynamic);
    cell.textContent = entries.map((e) => e.tagName).join(", ");
    addTooltipHandlers(cell, () => dynEntryTooltipHtml(entries, fmtAddr));

    // Collect unique nav targets across all entries in this cell
    const seenTargets = new Set<NavTarget>();
    const navItems: Array<CtxMenuItem | null> = [];
    for (const e of entries) {
      if (onDynamicClick) {
        navItems.push({
          label: `Go to Dynamic: ${e.tagName}`,
          action: () => onDynamicClick(e.tag),
        });
      }
    }
    for (const e of entries) {
      if (e.shIndex !== null && onSectionClick) {
        navItems.push({
          label: `Go to Section: ${e.sectionName}`,
          action: () => onSectionClick(e.shIndex!, -1),
        });
      }
    }
    for (const e of entries) {
      const t = dynNavTarget(e.tag);
      if (t && !seenTargets.has(t) && onNavigate) {
        seenTargets.add(t);
        navItems.push({ label: `Open in ${navTargetLabel(t)}`, action: () => onNavigate(t) });
      }
    }
    for (const e of entries) {
      if (onHexDump && e.fileOffset !== null && e.byteSize !== null && e.byteSize > 0) {
        const label = e.sectionName ?? e.tagName;
        const off = e.fileOffset,
          sz = e.byteSize;
        navItems.push({ label: `Hex Dump: ${label}`, action: () => onHexDump(label, off, sz) });
      }
    }

    if (navItems.length > 0) {
      cell.style.cursor = "pointer";
      if (onDynamicClick) {
        cell.addEventListener("click", () => onDynamicClick(entries[0].tag));
      }
      attachCtxMenu(cell, navItems);
    }
    container.appendChild(cell);
  }
}

function maybeEmitSegInfo(
  container: HTMLElement,
  seg: LayoutSegment,
  fmtAddr: (v: bigint) => string,
  fmtOffset: ((v: number) => string) | null,
  cols: ColLayout,
  segSpans: ReturnType<typeof buildSegSpans>,
  emitted: Set<number>,
  isObjectFile: boolean,
  onSectionClick?: (shIndex: number | null, segIndex: number) => void,
  onHexDump?: (label: string, fileOffset: number, size: number) => void
): void {
  if (isObjectFile) {
    return;
  }
  if (emitted.has(seg.index)) {
    return;
  }
  emitted.add(seg.index);

  const span = segSpans.get(seg.index);
  if (!span) {
    return;
  }

  const totalRows = span.endRow - span.startRow + 1;
  const startGridRow = span.startRow + 2;
  const hasBss = seg.filesz > 0 && seg.filesz < seg.memsz;
  const isNoFileData = seg.filesz === 0 && seg.memsz > 0;
  const bgStartCol = cols.dynamic !== null ? cols.dynamic : cols.nlBase;

  const emitBg = (bgColor: string, gridRowVal: string, rad: "top" | "bottom" | "full"): void => {
    const L = 6,
      R = 6;
    const [tl, tr, br, bl] =
      rad === "top" ? [L, R, 0, 0] : rad === "bottom" ? [0, 0, R, L] : [L, R, R, L];
    if (cols.dynamic !== null) {
      const db = document.createElement("div");
      db.className = "seg-bg";
      db.style.background = bgColor;
      db.style.gridRow = gridRowVal;
      db.style.gridColumn = String(cols.dynamic);
      db.style.borderRadius = `${tl}px 0 0 ${bl}px`;
      container.appendChild(db);
      const ph = document.createElement("div");
      ph.className = "seg-bg";
      ph.style.background = bgColor;
      ph.style.gridRow = gridRowVal;
      ph.style.gridColumn = `${cols.nlBase} / -2`;
      ph.style.borderRadius = `0 ${rad !== "bottom" ? R : 0}px ${rad !== "top" ? R : 0}px 0`;
      container.appendChild(ph);
    } else {
      const bg = document.createElement("div");
      bg.className = "seg-bg";
      bg.style.background = bgColor;
      bg.style.gridRow = gridRowVal;
      bg.style.gridColumn = `${bgStartCol} / -2`;
      bg.style.borderRadius = `${tl}px ${tr}px ${br}px ${bl}px`;
      container.appendChild(bg);
    }
  };

  if (hasBss && span.bssRows > 0) {
    const fc = span.fileRows || 1,
      bc = span.bssRows || 1;
    emitBg(segmentColorCSS(seg.colorClass), `${startGridRow} / span ${fc}`, "top");
    emitBg(segmentColorCSS(seg.colorClass, true), `${startGridRow + fc} / span ${bc}`, "bottom");

    const fp = document.createElement("div");
    fp.className = "seg-file-part";
    fp.style.background = segmentColorCSS(seg.colorClass);
    fp.style.gridRow = `${startGridRow} / span ${fc}`;
    fp.style.gridColumn = "-3";
    fp.innerHTML = `<span class="ph-label">LOAD</span><span class="detail">PH #${seg.index} ${seg.flags}</span><span class="detail">Filesz: 0x${seg.filesz.toString(16).toUpperCase()}</span>`;
    addTooltipHandlers(fp, () => segmentTooltipHtml(seg, fmtAddr, fmtOffset));
    const fpHasHex = !!onHexDump && seg.filesz > 0;
    if (onSectionClick || fpHasHex) {
      fp.style.cursor = "pointer";
      if (onSectionClick) {
        fp.addEventListener("click", () => onSectionClick(null, seg.index));
      }
      attachCtxMenu(fp, [
        onSectionClick
          ? { label: "Go to Program Headers", action: () => onSectionClick(null, seg.index) }
          : null,
        fpHasHex
          ? {
              label: `Hex Dump: LOAD PH #${seg.index}`,
              action: () => onHexDump!(`LOAD PH #${seg.index}`, seg.fileOff, seg.filesz),
            }
          : null,
      ]);
    }
    container.appendChild(fp);

    const bp = document.createElement("div");
    bp.className = "seg-bss-part";
    bp.style.background = segmentColorCSS(seg.colorClass, true);
    bp.style.gridRow = `${startGridRow + fc} / span ${bc}`;
    bp.style.gridColumn = "-3";
    const bssSize = seg.memsz - seg.filesz; // both number
    bp.innerHTML = `<span>no file data</span><span>(0x${bssSize.toString(16).toUpperCase()})</span>`;
    addTooltipHandlers(bp, () => segmentTooltipHtml(seg, fmtAddr, fmtOffset));
    container.appendChild(bp);
  } else {
    const bgColor = isNoFileData
      ? segmentColorCSS(seg.colorClass, true)
      : segmentColorCSS(seg.colorClass);
    emitBg(bgColor, `${startGridRow} / span ${totalRows}`, "full");

    const info = document.createElement("div");
    info.className = "seg-info";
    info.style.background = bgColor;
    info.style.gridRow = `${startGridRow} / span ${totalRows}`;
    info.style.gridColumn = "-3";
    info.innerHTML = `<span class="ph-label">LOAD</span><span class="detail">PH #${seg.index} ${seg.flags}</span><span class="detail">Filesz: 0x${seg.filesz.toString(16).toUpperCase()}</span>${isNoFileData ? '<span class="detail">no file data</span>' : ""}`;
    addTooltipHandlers(info, () => segmentTooltipHtml(seg, fmtAddr, fmtOffset));
    const infoHasHex = !!onHexDump && seg.filesz > 0;
    if (onSectionClick || infoHasHex) {
      info.style.cursor = "pointer";
      if (onSectionClick) {
        info.addEventListener("click", () => onSectionClick(null, seg.index));
      }
      attachCtxMenu(info, [
        onSectionClick
          ? { label: "Go to Program Headers", action: () => onSectionClick(null, seg.index) }
          : null,
        infoHasHex
          ? {
              label: `Hex Dump: LOAD PH #${seg.index}`,
              action: () => onHexDump!(`LOAD PH #${seg.index}`, seg.fileOff, seg.filesz),
            }
          : null,
      ]);
    }
    container.appendChild(info);
  }

  const rAddr = document.createElement("div");
  rAddr.className = "addr-cell";
  rAddr.style.gridRow = `${startGridRow} / span ${totalRows}`;
  rAddr.style.gridColumn = "-2";
  rAddr.style.flexDirection = "column";
  rAddr.style.alignItems = "center";
  rAddr.style.justifyContent = "space-between";
  rAddr.innerHTML = `<span>${fmtAddr(seg.vaddr)}</span><span>${fmtAddr(seg.vaddr + BigInt(seg.memsz) - 1n)}</span>`;
  container.appendChild(rAddr);
}

// ─── Public class ─────────────────────────────────────────────────────────────

export class MemoryMapView {
  private container: HTMLElement;
  private elf: ELFFile;
  private filePath: string;
  private mode: "memory" | "file";
  onSectionClick?: (shIndex: number | null, segIndex: number) => void;
  onDynamicClick?: (tag: number) => void;
  onElfHeaderClick?: () => void;
  onProgHeadersClick?: () => void;
  onSectionHeadersClick?: () => void;
  onHexDump?: (label: string, fileOffset: number, size: number) => void;
  onNavigate?: (target: NavTarget) => void;

  constructor(
    container: HTMLElement,
    elf: ELFFile,
    filePath: string,
    mode: "memory" | "file" = "memory"
  ) {
    this.container = container;
    this.elf = elf;
    this.filePath = filePath;
    this.mode = mode;
  }

  render(): void {
    this.container.innerHTML = "";
    this.container.className = ""; // remove tab-content padding; we manage layout directly

    const layout =
      this.mode === "file"
        ? buildFileLayout(this.elf, this.filePath)
        : buildLayout(this.elf, this.filePath);

    if (layout.warnings.length > 0) {
      const warnDiv = document.createElement("div");
      warnDiv.style.background = "rgba(243, 139, 168, 0.15)";
      warnDiv.style.color = "#f38ba8";
      warnDiv.style.padding = "8px 12px";
      warnDiv.style.borderRadius = "4px";
      warnDiv.style.fontSize = "12px";
      warnDiv.style.margin = "8px 0";
      warnDiv.innerHTML = layout.warnings.map((w) => `⚠ ${w}`).join("<br>");
      this.container.appendChild(warnDiv);
    }

    const mapGrid = document.createElement("div");
    mapGrid.className = "memory-map";
    this.container.appendChild(mapGrid);

    this._renderIntoGrid(mapGrid, layout);
  }

  private _renderIntoGrid(mapGrid: HTMLElement, layout: LayoutData): void {
    const { fmtAddr, fmtOffset } = makeFormatters(layout);

    if (layout.segments.length === 0) {
      mapGrid.textContent = "No segments to display";
      return;
    }

    const rows = buildRows(layout.segments, layout.headerInfo, layout.isObjectFile);
    if (!layout.isObjectFile) {
      splitAtNonLoad(rows, layout.nonLoadSegments);
      splitAtDynamicEntries(rows, layout.dynamicEntries);
    }

    const hasLabelsCol = rows.some((r) => r.type === "section");
    const { nlEntries, nlLaneCount } = assignLanes(rows, layout.nonLoadSegments);
    const hasDynEntries = layout.dynamicEntries.length > 0;

    const cols = computeCols(fmtOffset !== null, hasLabelsCol, hasDynEntries);

    // ELF Header and Program Headers overlays in nl-lanes (always shown in the Program Headers
    // column, regardless of whether a sections column exists).
    let elfHdrFirstRow = -1,
      elfHdrLastRow = -1;
    let phHdrFirstRow = -1,
      phHdrLastRow = -1;
    if (!layout.isObjectFile) {
      for (let r = 0; r < rows.length; r++) {
        if (rows[r].type === "elf-header") {
          if (elfHdrFirstRow === -1) {
            elfHdrFirstRow = r;
          }
          elfHdrLastRow = r;
        } else if (rows[r].type === "program-headers") {
          if (phHdrFirstRow === -1) {
            phHdrFirstRow = r;
          }
          phHdrLastRow = r;
        }
      }
    }
    const hasElfHdrOverlay = elfHdrFirstRow !== -1;
    const hasPhHdrOverlay = phHdrFirstRow !== -1;
    // Assign lanes using the same overlap logic as assignLanes.
    let elfHdrLane = 0;
    if (hasElfHdrOverlay) {
      while (
        nlEntries.some(
          (e) => e.lane === elfHdrLane && e.firstRow <= elfHdrLastRow && e.lastRow >= elfHdrFirstRow
        )
      ) {
        elfHdrLane++;
      }
    }
    let phHdrLane = 0;
    if (hasPhHdrOverlay) {
      while (
        nlEntries.some(
          (e) => e.lane === phHdrLane && e.firstRow <= phHdrLastRow && e.lastRow >= phHdrFirstRow
        ) ||
        (hasElfHdrOverlay &&
          elfHdrLane === phHdrLane &&
          elfHdrFirstRow <= phHdrLastRow &&
          elfHdrLastRow >= phHdrFirstRow)
      ) {
        phHdrLane++;
      }
    }
    const totalNlLanes = Math.max(
      nlLaneCount,
      hasElfHdrOverlay ? elfHdrLane + 1 : 0,
      hasPhHdrOverlay ? phHdrLane + 1 : 0
    );

    setupGrid(mapGrid, rows, cols, totalNlLanes, layout.isObjectFile);
    renderHeaderRow(mapGrid, cols, layout.isObjectFile);

    const segSpans = buildSegSpans(rows);
    const emitted = new Set<number>();
    renderRows(
      mapGrid,
      rows,
      fmtAddr,
      fmtOffset,
      cols,
      segSpans,
      emitted,
      layout.isObjectFile,
      this.onSectionClick,
      this.onElfHeaderClick,
      this.onProgHeadersClick,
      this.onSectionHeadersClick,
      this.onHexDump,
      this.onNavigate
    );

    if (!layout.isObjectFile) {
      renderNonLoadOverlays(
        mapGrid,
        nlEntries,
        cols,
        fmtAddr,
        fmtOffset,
        this.onSectionClick,
        this.onHexDump,
        this.onNavigate
      );
      if (hasDynEntries) {
        renderDynamicEntries(
          mapGrid,
          rows,
          layout.dynamicEntries,
          cols,
          fmtAddr,
          this.onDynamicClick,
          this.onSectionClick,
          this.onNavigate,
          this.onHexDump
        );
      }
      if (hasElfHdrOverlay) {
        const box = document.createElement("div");
        box.className = "non-load-seg";
        box.style.gridRow = `${elfHdrFirstRow + 2} / span ${elfHdrLastRow - elfHdrFirstRow + 1}`;
        box.style.gridColumn = String(cols.nlBase + elfHdrLane);
        box.innerHTML = `<span class="nl-type">ELF Header</span>`;
        const ehHasHex = !!this.onHexDump && !!layout.headerInfo && layout.headerInfo.ehSize > 0;
        if (this.onElfHeaderClick || ehHasHex) {
          box.style.cursor = "pointer";
          if (this.onElfHeaderClick) {
            box.addEventListener("click", this.onElfHeaderClick);
          }
          attachCtxMenu(box, [
            this.onElfHeaderClick
              ? { label: "Go to ELF Header", action: this.onElfHeaderClick }
              : null,
            ehHasHex
              ? {
                  label: "Hex Dump: ELF Header",
                  action: () => this.onHexDump!("ELF Header", 0, layout.headerInfo!.ehSize),
                }
              : null,
          ]);
        }
        mapGrid.appendChild(box);
      }
      if (hasPhHdrOverlay && layout.headerInfo && !layout.headerInfo.hasPHDR) {
        const hi = layout.headerInfo;
        const box = document.createElement("div");
        box.className = "non-load-seg";
        box.style.gridRow = `${phHdrFirstRow + 2} / span ${phHdrLastRow - phHdrFirstRow + 1}`;
        box.style.gridColumn = String(cols.nlBase + phHdrLane);
        box.innerHTML = `<span class="nl-type">Program Headers</span>`;
        const phTableSize = hi.phEntSize * hi.phNum;
        const phHasHex = !!this.onHexDump && phTableSize > 0;
        if (this.onProgHeadersClick || phHasHex) {
          box.style.cursor = "pointer";
          if (this.onProgHeadersClick) {
            box.addEventListener("click", this.onProgHeadersClick);
          }
          attachCtxMenu(box, [
            this.onProgHeadersClick
              ? { label: "Go to Program Headers", action: this.onProgHeadersClick }
              : null,
            phHasHex
              ? {
                  label: "Hex Dump: Program Headers",
                  action: () => this.onHexDump!("Program Headers", hi.phOff, phTableSize),
                }
              : null,
          ]);
        }
        mapGrid.appendChild(box);
      }
    }
  }
}
