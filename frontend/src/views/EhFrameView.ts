// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// .eh_frame / .eh_frame_hdr view: renders exception handling frame information.

import {
  type ELFFile,
  type EhFrameData,
  type EhFrameCIE,
  type EhFrameFDE,
  type EhFrameHdr,
} from "../parser/types.ts";
import { ehPeEncName } from "../parser/ehframe.ts";
import { appendEmptyMessage, hexPad, createSubTabs } from "./viewUtils.ts";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtHex(n: number | bigint, pad: number): string {
  return `0x${n.toString(16).padStart(pad, "0")}`;
}

function regNameStr(n: number, machine: number): string {
  // Imported from parser; simple fallback for display
  if (machine === 183 /* AArch64 */) {
    if (n <= 30) {
      return `r${n} (x${n})`;
    }
    if (n === 31) {
      return "r31 (sp)";
    }
    if (n >= 64 && n <= 95) {
      return `r${n} (v${n - 64})`;
    }
    return `r${n}`;
  }
  if (machine === 62 /* X86_64 */) {
    const names: Record<number, string> = {
      0: "rax",
      1: "rdx",
      2: "rcx",
      3: "rbx",
      4: "rsi",
      5: "rdi",
      6: "rbp",
      7: "rsp",
      8: "r8",
      9: "r9",
      10: "r10",
      11: "r11",
      12: "r12",
      13: "r13",
      14: "r14",
      15: "r15",
      16: "rip",
    };
    return names[n] ? `r${n} (${names[n]})` : `r${n}`;
  }
  return `r${n}`;
}

// ─── .eh_frame_hdr panel ─────────────────────────────────────────────────────

function renderHdr(
  container: HTMLElement,
  hdr: EhFrameHdr,
  is64: boolean,
  ehFrameVaddr: bigint
): void {
  const padW = is64 ? 16 : 8;

  // Header info table
  const info = document.createElement("table");
  info.className = "info-table";
  const rows: [string, string][] = [
    ["Version", `${hdr.version}`],
    [
      "eh_frame_ptr_enc",
      `0x${hdr.ehFramePtrEnc.toString(16).padStart(2, "0")} (${ehPeEncName(hdr.ehFramePtrEnc)})`,
    ],
    [
      "fde_count_enc",
      `0x${hdr.fdeCountEnc.toString(16).padStart(2, "0")} (${ehPeEncName(hdr.fdeCountEnc)})`,
    ],
    ["table_enc", `0x${hdr.tableEnc.toString(16).padStart(2, "0")} (${ehPeEncName(hdr.tableEnc)})`],
    ["eh_frame_ptr", fmtHex(hdr.ehFramePtr, padW)],
    ["FDE count", `${hdr.fdeCount}`],
  ];
  for (const [label, value] of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="info-label">${label}</td><td class="info-value mono">${value}</td>`;
    info.appendChild(tr);
  }
  container.appendChild(info);

  if (hdr.table.length === 0) {
    return;
  }

  // Binary search table
  const h3 = document.createElement("h3");
  h3.className = "view-subtitle";
  h3.textContent = "Binary Search Table";
  container.appendChild(h3);

  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `<thead><tr><th>#</th><th>Initial Location</th><th>FDE Address</th><th>FDE Offset</th></tr></thead>`;
  const tbody = document.createElement("tbody");
  for (let i = 0; i < hdr.table.length; i++) {
    const e = hdr.table[i];
    const fdeSectionOff = Number(e.fdeOffset - ehFrameVaddr);
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${i}</td>
      <td class="mono">${hexPad(e.initialLocation, padW)}</td>
      <td class="mono">${hexPad(e.fdeOffset, padW)}</td>
      <td class="mono">${hexPad(fdeSectionOff, 8)}</td>
    `;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

// ─── .eh_frame CIE/FDE panel ────────────────────────────────────────────────

function renderCIE(cie: EhFrameCIE, machine: number, padW: number): HTMLElement {
  const div = document.createElement("div");
  div.className = "eh-record";

  const header = document.createElement("div");
  header.className = "eh-record-header";
  header.innerHTML = `
    <span class="eh-offset mono">${fmtHex(cie.offset, 8)}</span>
    <span class="eh-length mono">${fmtHex(cie.length, 8)}</span>
    <span class="eh-tag eh-tag-cie">CIE</span>
    <span class="eh-detail">Version: ${cie.version}  Augmentation: "${cie.augmentation}"</span>
  `;
  div.appendChild(header);

  const info = document.createElement("table");
  info.className = "info-table eh-info";
  const rows: [string, string][] = [];
  if (cie.addressSize > 0) {
    rows.push(["Address size", `${cie.addressSize}`]);
  }
  if (cie.segmentSelectorSize > 0) {
    rows.push(["Segment selector size", `${cie.segmentSelectorSize}`]);
  }
  rows.push(
    ["Code alignment factor", `${cie.codeAlignFactor}`],
    ["Data alignment factor", `${cie.dataAlignFactor}`],
    ["Return address column", regNameStr(cie.returnAddressReg, machine)]
  );
  if (cie.augmentation.includes("R")) {
    rows.push([
      "FDE encoding",
      `0x${cie.fdeEncoding.toString(16).padStart(2, "0")} (${ehPeEncName(cie.fdeEncoding)})`,
    ]);
  }
  if (cie.augmentation.includes("P")) {
    rows.push([
      "Personality",
      `enc=0x${cie.personalityEncoding.toString(16).padStart(2, "0")} addr=${hexPad(cie.personalityRoutine, padW)}`,
    ]);
  }
  if (cie.augmentation.includes("L")) {
    rows.push([
      "LSDA encoding",
      `0x${cie.lsdaEncoding.toString(16).padStart(2, "0")} (${ehPeEncName(cie.lsdaEncoding)})`,
    ]);
  }
  if (cie.isSignalFrame) {
    rows.push(["Signal frame", "yes"]);
  }
  for (const [label, value] of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="info-label">${label}</td><td class="info-value mono">${value}</td>`;
    info.appendChild(tr);
  }
  div.appendChild(info);

  if (cie.initialInstructions.length > 0) {
    const instrDiv = document.createElement("div");
    instrDiv.className = "eh-instructions";
    instrDiv.innerHTML = cie.initialInstructions
      .map((s) => `<div class="eh-instr mono">${s}</div>`)
      .join("");
    div.appendChild(instrDiv);
  }

  return div;
}

function renderFDE(fde: EhFrameFDE, cieMap: Map<number, EhFrameCIE>, padW: number): HTMLElement {
  const div = document.createElement("div");
  div.className = "eh-record";

  const cie = cieMap.get(fde.cieOffset);
  const cieLabel = cie ? fmtHex(cie.offset, 8) : "?";

  const pcEnd = fde.pcBegin + fde.pcRange;
  const header = document.createElement("div");
  header.className = "eh-record-header";
  header.innerHTML = `
    <span class="eh-offset mono">${fmtHex(fde.offset, 8)}</span>
    <span class="eh-length mono">${fmtHex(fde.length, 8)}</span>
    <span class="eh-tag eh-tag-fde">FDE</span>
    <span class="eh-detail">cie=${cieLabel}  pc=${hexPad(fde.pcBegin, padW)}..${hexPad(pcEnd, padW)}</span>
  `;
  div.appendChild(header);

  if (fde.lsda !== 0n) {
    const lsdaDiv = document.createElement("div");
    lsdaDiv.className = "eh-lsda mono";
    lsdaDiv.textContent = `LSDA: ${hexPad(fde.lsda, padW)}`;
    div.appendChild(lsdaDiv);
  }

  if (fde.instructions.length > 0) {
    const instrDiv = document.createElement("div");
    instrDiv.className = "eh-instructions";
    instrDiv.innerHTML = fde.instructions
      .map((s) => `<div class="eh-instr mono">${s}</div>`)
      .join("");
    div.appendChild(instrDiv);
  }

  return div;
}

function renderRecords(
  container: HTMLElement,
  data: EhFrameData,
  machine: number,
  is64: boolean
): void {
  const padW = is64 ? 16 : 8;

  if (data.cies.length === 0 && data.fdes.length === 0) {
    appendEmptyMessage(container, "No CIE/FDE records");
    return;
  }

  // Build CIE map for FDE→CIE lookup
  const cieMap = new Map<number, EhFrameCIE>();
  for (const cie of data.cies) {
    cieMap.set(cie.offset, cie);
  }

  // Merge CIEs and FDEs in offset order
  type Record = { type: "cie"; cie: EhFrameCIE } | { type: "fde"; fde: EhFrameFDE };
  const records: Record[] = [
    ...data.cies.map((cie) => ({ type: "cie" as const, cie })),
    ...data.fdes.map((fde) => ({ type: "fde" as const, fde })),
  ].sort((a, b) => {
    const offA = a.type === "cie" ? a.cie.offset : a.fde.offset;
    const offB = b.type === "cie" ? b.cie.offset : b.fde.offset;
    return offA - offB;
  });

  for (const rec of records) {
    if (rec.type === "cie") {
      container.appendChild(renderCIE(rec.cie, machine, padW));
    } else {
      container.appendChild(renderFDE(rec.fde, cieMap, padW));
    }
  }
}

// ─── Main export ─────────────────────────────────────────────────────────────

export function renderEhFrame(container: HTMLElement, elf: ELFFile): void {
  const data = elf.ehFrame;
  container.innerHTML = "";

  if (!data) {
    container.innerHTML = '<h2 class="view-title">.eh_frame</h2>';
    appendEmptyMessage(container, "No .eh_frame section found");
    return;
  }

  const totalRecords = data.cies.length + data.fdes.length;
  container.innerHTML = `<h2 class="view-title">.eh_frame (${data.cies.length} CIE, ${data.fdes.length} FDE)</h2>`;

  const is64 = elf.header.class === 2; // ELFClass.ELF64
  const machine = elf.header.machine as number;

  const tabs = [];

  if (data.hdr) {
    tabs.push({
      label: `.eh_frame_hdr (${data.hdr.fdeCount} entries)`,
      render: (panel: HTMLElement) => renderHdr(panel, data.hdr!, is64, data.sectionVaddr),
    });
  }

  tabs.push({
    label: `.eh_frame (${totalRecords} records)`,
    render: (panel: HTMLElement) => renderRecords(panel, data, machine, is64),
  });

  if (tabs.length === 1) {
    tabs[0].render(container);
  } else {
    createSubTabs(container, tabs);
  }
}

export function renderDebugFrame(container: HTMLElement, elf: ELFFile): void {
  const data = elf.debugFrame;
  container.innerHTML = "";

  if (!data) {
    container.innerHTML = '<h2 class="view-title">.debug_frame</h2>';
    appendEmptyMessage(container, "No .debug_frame section found");
    return;
  }

  container.innerHTML = `<h2 class="view-title">.debug_frame (${data.cies.length} CIE, ${data.fdes.length} FDE)</h2>`;

  const is64 = elf.header.class === 2;
  const machine = elf.header.machine as number;
  renderRecords(container, data, machine, is64);
}
