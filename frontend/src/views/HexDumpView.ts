// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Hex dump view — renders a region of the ELF file as a hex+ASCII dump,
// similar to the `hd` (hexdump) command. Uses virtual scrolling so that
// large sections open and close quickly regardless of their size.

import { type ELFFile } from "../parser/types.ts";

const COLS = 16;
const PAD_TOP = 8; // px — spacing above first data row (matches original padding-top)
const PAD_BOTTOM = 16; // px — spacing below last data row (matches original padding-bottom)
const BUFFER = 3; // extra rows rendered above/below the visible area

// Column header: "+RelOff" (9+2=11 chars) + "FileOff" (8+2=10 chars) + hex columns + ASCII
const COL_HEADER = `${"+RelOff".padEnd(11)}${"FileOff".padEnd(10)}00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  |0123456789abcdef|`;

function buildRows(bytes: Uint8Array, fileOffset: number, first: number, last: number): string {
  const lines: string[] = [];
  for (let i = first; i < last; i++) {
    const byteIdx = i * COLS;
    const rowBytes = bytes.subarray(byteIdx, Math.min(byteIdx + COLS, bytes.length));
    const count = rowBytes.length;

    const relStr = "+" + byteIdx.toString(16).padStart(8, "0");
    const fileStr = (fileOffset + byteIdx).toString(16).padStart(8, "0");

    const g1: string[] = [];
    const g2: string[] = [];
    for (let j = 0; j < 8; j++)
      g1.push(j < count ? rowBytes[j].toString(16).padStart(2, "0") : "  ");
    for (let j = 8; j < COLS; j++)
      g2.push(j < count ? rowBytes[j].toString(16).padStart(2, "0") : "  ");
    const hexStr = `${g1.join(" ")}  ${g2.join(" ")}`;

    const ascii = Array.from(rowBytes)
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
      .join("")
      .padEnd(COLS, " ");

    lines.push(`${relStr}  ${fileStr}  ${hexStr}  |${ascii}|`);
  }
  return lines.join("\n");
}

export function renderHexDump(
  container: HTMLElement,
  elf: ELFFile,
  label: string,
  fileOffset: number,
  size: number
): void {
  container.innerHTML = "";
  container.style.padding = "0"; // manage padding ourselves for sticky to work

  // ── Sticky header ──────────────────────────────────────────────────────────
  const sticky = document.createElement("div");
  sticky.className = "hex-dump-sticky";
  container.appendChild(sticky);

  const heading = document.createElement("h2");
  heading.className = "hex-dump-heading";
  heading.textContent = label;
  sticky.appendChild(heading);

  const meta = document.createElement("div");
  meta.className = "hex-dump-meta";
  meta.textContent =
    `File offset: 0x${fileOffset.toString(16).padStart(8, "0").toUpperCase()}` +
    `   Size: 0x${size.toString(16).toUpperCase()} (${size} bytes)`;
  sticky.appendChild(meta);

  if (size === 0) {
    const msg = document.createElement("p");
    msg.className = "hex-dump-empty";
    msg.textContent = "Empty (size = 0)";
    sticky.appendChild(msg);
    return;
  }

  const end = Math.min(fileOffset + size, elf.raw.length);
  if (end <= fileOffset) {
    const msg = document.createElement("p");
    msg.className = "hex-dump-empty";
    msg.textContent = "No file data available (offset beyond file end)";
    sticky.appendChild(msg);
    return;
  }

  // Column header — lives in the sticky area
  const colHead = document.createElement("pre");
  colHead.className = "hex-dump-colheader";
  colHead.textContent = COL_HEADER;
  sticky.appendChild(colHead);

  // ── Virtual scroll ──────────────────────────────────────────────────────────
  const bytes = elf.raw.subarray(fileOffset, end);
  const totalRows = Math.ceil(bytes.length / COLS);

  // Measure the rendered height of one row using a hidden probe element.
  // This accounts for the actual font metrics in the current environment.
  const probe = document.createElement("pre");
  probe.className = "hex-dump-pre";
  probe.style.cssText = "position:absolute;visibility:hidden;padding:0;margin:0";
  probe.textContent = COL_HEADER;
  container.appendChild(probe);
  const rowHeight = probe.getBoundingClientRect().height || 21;
  probe.remove();

  // The virtual scroll area is a tall placeholder div whose height represents
  // all rows. Only the visible subset of rows is actually in the DOM.
  const vscroll = document.createElement("div");
  vscroll.style.position = "relative";
  vscroll.style.height = `${PAD_TOP + totalRows * rowHeight + PAD_BOTTOM}px`;
  container.appendChild(vscroll);

  // The single <pre> that shows only the currently visible rows, repositioned on scroll.
  const pre = document.createElement("pre");
  pre.className = "hex-dump-pre";
  pre.style.position = "absolute";
  pre.style.left = "0";
  pre.style.padding = `0 16px`;
  pre.style.margin = "0";
  vscroll.appendChild(pre);

  const renderVisible = () => {
    const scrollTop = container.scrollTop;
    const first = Math.max(0, Math.floor((scrollTop - PAD_TOP) / rowHeight) - BUFFER);
    const last = Math.min(
      totalRows,
      Math.ceil((scrollTop + container.clientHeight) / rowHeight) + BUFFER
    );
    pre.style.top = `${PAD_TOP + first * rowHeight}px`;
    pre.textContent = buildRows(bytes, fileOffset, first, last);
  };

  // Use rAF to coalesce rapid scroll events into one DOM update per frame.
  let rafId = 0;
  container.addEventListener("scroll", () => {
    if (rafId) return;
    rafId = requestAnimationFrame(() => {
      rafId = 0;
      renderVisible();
    });
  });

  renderVisible();
}
