// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Relocations view: renders relocation entries (readelf -r).

import {
  type ELFFile,
  type RelocationEntry,
  type RelocationSection,
  type VersionInfo,
  ELFMachine,
} from "../parser/types.ts";
import {
  versionParts,
  verNumCellHtml,
  VIRTUAL_THRESHOLD,
  createSubTabs,
  appendEmptyMessage,
  hexPad,
} from "./viewUtils.ts";
import { attachVirtualScroll } from "./virtualScroll.ts";

// Architecture-specific relocation type names (x86-64)
const R_X86_64: Record<number, string> = {
  0: "R_X86_64_NONE",
  1: "R_X86_64_64",
  2: "R_X86_64_PC32",
  3: "R_X86_64_GOT32",
  4: "R_X86_64_PLT32",
  5: "R_X86_64_COPY",
  6: "R_X86_64_GLOB_DAT",
  7: "R_X86_64_JUMP_SLOT",
  8: "R_X86_64_RELATIVE",
  9: "R_X86_64_GOTPCREL",
  10: "R_X86_64_32",
  11: "R_X86_64_32S",
  12: "R_X86_64_16",
  13: "R_X86_64_PC16",
  14: "R_X86_64_8",
  15: "R_X86_64_PC8",
  16: "R_X86_64_DTPMOD64",
  17: "R_X86_64_DTPOFF64",
  18: "R_X86_64_TPOFF64",
  19: "R_X86_64_TLSGD",
  20: "R_X86_64_TLSLD",
  21: "R_X86_64_DTPOFF32",
  22: "R_X86_64_GOTTPOFF",
  23: "R_X86_64_TPOFF32",
  24: "R_X86_64_PC64",
  25: "R_X86_64_GOTOFF64",
  26: "R_X86_64_GOTPC32",
  27: "R_X86_64_GOT64",
  28: "R_X86_64_GOTPCREL64",
  29: "R_X86_64_GOTPC64",
  30: "R_X86_64_GOTPLT64",
  31: "R_X86_64_PLTOFF64",
  32: "R_X86_64_SIZE32",
  33: "R_X86_64_SIZE64",
  34: "R_X86_64_GOTPC32_TLSDESC",
  35: "R_X86_64_TLSDESC_CALL",
  36: "R_X86_64_TLSDESC",
  37: "R_X86_64_IRELATIVE",
  38: "R_X86_64_RELATIVE64",
  41: "R_X86_64_GOTPCRELX",
  42: "R_X86_64_REX_GOTPCRELX",
  43: "R_X86_64_CODE_4_GOTPCRELX",
  44: "R_X86_64_CODE_4_GOTTPOFF",
  45: "R_X86_64_CODE_4_GOTPC32_TLSDESC",
  46: "R_X86_64_CODE_5_GOTPCRELX",
  47: "R_X86_64_CODE_5_GOTTPOFF",
  48: "R_X86_64_CODE_5_GOTPC32_TLSDESC",
  49: "R_X86_64_CODE_6_GOTPCRELX",
  50: "R_X86_64_CODE_6_GOTTPOFF",
  51: "R_X86_64_CODE_6_GOTPC32_TLSDESC",
};

// Architecture-specific relocation type names (AArch64)
const R_AARCH64: Record<number, string> = {
  // Null
  0: "R_AARCH64_NONE",
  // Data relocations
  257: "R_AARCH64_ABS64",
  258: "R_AARCH64_ABS32",
  259: "R_AARCH64_ABS16",
  260: "R_AARCH64_PREL64",
  261: "R_AARCH64_PREL32",
  262: "R_AARCH64_PREL16",
  // Group 5: Instructions — MOVW
  263: "R_AARCH64_MOVW_UABS_G0",
  264: "R_AARCH64_MOVW_UABS_G0_NC",
  265: "R_AARCH64_MOVW_UABS_G1",
  266: "R_AARCH64_MOVW_UABS_G1_NC",
  267: "R_AARCH64_MOVW_UABS_G2",
  268: "R_AARCH64_MOVW_UABS_G2_NC",
  269: "R_AARCH64_MOVW_UABS_G3",
  270: "R_AARCH64_MOVW_SABS_G0",
  271: "R_AARCH64_MOVW_SABS_G1",
  272: "R_AARCH64_MOVW_SABS_G2",
  // Group 6: Instructions — PC-relative
  274: "R_AARCH64_LD_PREL_LO19",
  275: "R_AARCH64_ADR_PREL_LO21",
  276: "R_AARCH64_ADR_PREL_PG_HI21",
  277: "R_AARCH64_ADR_PREL_PG_HI21_NC",
  278: "R_AARCH64_ADD_ABS_LO12_NC",
  279: "R_AARCH64_LDST8_ABS_LO12_NC",
  280: "R_AARCH64_TSTBR14",
  281: "R_AARCH64_CONDBR19",
  283: "R_AARCH64_JUMP26",
  284: "R_AARCH64_CALL26",
  285: "R_AARCH64_LDST16_ABS_LO12_NC",
  286: "R_AARCH64_LDST32_ABS_LO12_NC",
  287: "R_AARCH64_LDST64_ABS_LO12_NC",
  // Group 7: Instructions — PC-relative MOVW
  288: "R_AARCH64_MOVW_PREL_G0",
  289: "R_AARCH64_MOVW_PREL_G0_NC",
  290: "R_AARCH64_MOVW_PREL_G1",
  291: "R_AARCH64_MOVW_PREL_G1_NC",
  292: "R_AARCH64_MOVW_PREL_G2",
  293: "R_AARCH64_MOVW_PREL_G2_NC",
  294: "R_AARCH64_MOVW_PREL_G3",
  // Load literal (128-bit)
  299: "R_AARCH64_LDST128_ABS_LO12_NC",
  // GOT-relative
  300: "R_AARCH64_MOVW_GOTOFF_G0",
  301: "R_AARCH64_MOVW_GOTOFF_G0_NC",
  302: "R_AARCH64_MOVW_GOTOFF_G1",
  303: "R_AARCH64_MOVW_GOTOFF_G1_NC",
  304: "R_AARCH64_MOVW_GOTOFF_G2",
  305: "R_AARCH64_MOVW_GOTOFF_G2_NC",
  306: "R_AARCH64_MOVW_GOTOFF_G3",
  307: "R_AARCH64_GOTREL64",
  308: "R_AARCH64_GOTREL32",
  309: "R_AARCH64_GOT_LD_PREL19",
  310: "R_AARCH64_LD64_GOTOFF_LO15",
  311: "R_AARCH64_ADR_GOT_PAGE",
  312: "R_AARCH64_LD64_GOT_LO12_NC",
  313: "R_AARCH64_LD64_GOTPAGE_LO15",
  // TLS General-Dynamic
  512: "R_AARCH64_TLSGD_ADR_PREL21",
  513: "R_AARCH64_TLSGD_ADR_PAGE21",
  514: "R_AARCH64_TLSGD_ADD_LO12_NC",
  515: "R_AARCH64_TLSGD_MOVW_G1",
  516: "R_AARCH64_TLSGD_MOVW_G0_NC",
  // TLS Local-Dynamic
  517: "R_AARCH64_TLSLD_ADR_PREL21",
  518: "R_AARCH64_TLSLD_ADR_PAGE21",
  519: "R_AARCH64_TLSLD_ADD_LO12_NC",
  520: "R_AARCH64_TLSLD_MOVW_G1",
  521: "R_AARCH64_TLSLD_MOVW_G0_NC",
  522: "R_AARCH64_TLSLD_LD_PREL19",
  523: "R_AARCH64_TLSLD_MOVW_DTPREL_G2",
  524: "R_AARCH64_TLSLD_MOVW_DTPREL_G1",
  525: "R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC",
  526: "R_AARCH64_TLSLD_MOVW_DTPREL_G0",
  527: "R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC",
  528: "R_AARCH64_TLSLD_ADD_DTPREL_HI12",
  529: "R_AARCH64_TLSLD_ADD_DTPREL_LO12",
  530: "R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC",
  531: "R_AARCH64_TLSLD_LDST8_DTPREL_LO12",
  532: "R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC",
  533: "R_AARCH64_TLSLD_LDST16_DTPREL_LO12",
  534: "R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC",
  535: "R_AARCH64_TLSLD_LDST32_DTPREL_LO12",
  536: "R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC",
  537: "R_AARCH64_TLSLD_LDST64_DTPREL_LO12",
  538: "R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC",
  539: "R_AARCH64_TLSLD_LDST128_DTPREL_LO12",
  540: "R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC",
  // TLS Initial-Exec
  544: "R_AARCH64_TLSIE_MOVW_GOTTPREL_G1",
  545: "R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC",
  546: "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21",
  547: "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC",
  548: "R_AARCH64_TLSIE_LD_GOTTPREL_PREL19",
  // TLS Local-Exec
  549: "R_AARCH64_TLSLE_MOVW_TPREL_G2",
  550: "R_AARCH64_TLSLE_MOVW_TPREL_G1",
  551: "R_AARCH64_TLSLE_MOVW_TPREL_G1_NC",
  552: "R_AARCH64_TLSLE_MOVW_TPREL_G0",
  553: "R_AARCH64_TLSLE_MOVW_TPREL_G0_NC",
  554: "R_AARCH64_TLSLE_ADD_TPREL_HI12",
  555: "R_AARCH64_TLSLE_ADD_TPREL_LO12",
  556: "R_AARCH64_TLSLE_ADD_TPREL_LO12_NC",
  557: "R_AARCH64_TLSLE_LDST8_TPREL_LO12",
  558: "R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC",
  559: "R_AARCH64_TLSLE_LDST16_TPREL_LO12",
  560: "R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC",
  561: "R_AARCH64_TLSLE_LDST32_TPREL_LO12",
  562: "R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC",
  563: "R_AARCH64_TLSLE_LDST64_TPREL_LO12",
  564: "R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC",
  565: "R_AARCH64_TLSLE_LDST128_TPREL_LO12",
  566: "R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC",
  // TLS descriptor
  569: "R_AARCH64_TLSDESC_LD_PREL19",
  570: "R_AARCH64_TLSDESC_ADR_PREL21",
  571: "R_AARCH64_TLSDESC_ADR_PAGE21",
  572: "R_AARCH64_TLSDESC_LD64_LO12",
  573: "R_AARCH64_TLSDESC_ADD_LO12",
  574: "R_AARCH64_TLSDESC_OFF_G1",
  575: "R_AARCH64_TLSDESC_OFF_G0_NC",
  576: "R_AARCH64_TLSDESC_LDR",
  577: "R_AARCH64_TLSDESC_ADD",
  578: "R_AARCH64_TLSDESC_CALL",
  // Dynamic relocations
  1024: "R_AARCH64_COPY",
  1025: "R_AARCH64_GLOB_DAT",
  1026: "R_AARCH64_JUMP_SLOT",
  1027: "R_AARCH64_RELATIVE",
  1028: "R_AARCH64_TLS_DTPMOD64",
  1029: "R_AARCH64_TLS_DTPREL64",
  1030: "R_AARCH64_TLS_TPREL64",
  1031: "R_AARCH64_TLSDESC",
  1032: "R_AARCH64_IRELATIVE",
};

// Architecture-specific relocation type names (ARM 32-bit)
const R_ARM: Record<number, string> = {
  0: "R_ARM_NONE",
  1: "R_ARM_PC24",
  2: "R_ARM_ABS32",
  3: "R_ARM_REL32",
  4: "R_ARM_LDR_PC_G0",
  5: "R_ARM_ABS16",
  6: "R_ARM_ABS12",
  7: "R_ARM_THM_ABS5",
  8: "R_ARM_ABS8",
  9: "R_ARM_SBREL32",
  10: "R_ARM_THM_CALL",
  11: "R_ARM_THM_PC8",
  20: "R_ARM_COPY",
  21: "R_ARM_GLOB_DAT",
  22: "R_ARM_JUMP_SLOT",
  23: "R_ARM_RELATIVE",
  24: "R_ARM_GOTOFF32",
  25: "R_ARM_BASE_PREL",
  26: "R_ARM_GOT_BREL",
  27: "R_ARM_PLT32",
  28: "R_ARM_CALL",
  29: "R_ARM_JUMP24",
  30: "R_ARM_THM_JUMP24",
  38: "R_ARM_ALU_PC_G0_NC",
  39: "R_ARM_ALU_PC_G0",
  40: "R_ARM_ALU_PC_G1_NC",
  41: "R_ARM_ALU_PC_G1",
  42: "R_ARM_ALU_PC_G2",
  43: "R_ARM_LDR_PC_G1",
  44: "R_ARM_LDR_PC_G2",
  45: "R_ARM_LDRS_PC_G0",
  46: "R_ARM_LDRS_PC_G1",
  47: "R_ARM_LDRS_PC_G2",
  48: "R_ARM_LDC_PC_G0",
  49: "R_ARM_LDC_PC_G1",
  50: "R_ARM_LDC_PC_G2",
  100: "R_ARM_GNU_VTENTRY",
  101: "R_ARM_GNU_VTINHERIT",
  102: "R_ARM_THM_JUMP11",
  103: "R_ARM_THM_JUMP8",
  104: "R_ARM_TLS_GD32",
  105: "R_ARM_TLS_LDM32",
  106: "R_ARM_TLS_LDO32",
  107: "R_ARM_TLS_IE32",
  108: "R_ARM_TLS_LE32",
  109: "R_ARM_TLS_LDO12",
  110: "R_ARM_TLS_LE12",
  111: "R_ARM_TLS_IE12GP",
  160: "R_ARM_IRELATIVE",
};

// Map machine type to relocation table
const RELOC_TABLES: Partial<Record<ELFMachine, Record<number, string>>> = {
  [ELFMachine.X86_64]: R_X86_64,
  [ELFMachine.AArch64]: R_AARCH64,
  [ELFMachine.ARM]: R_ARM,
};

function relocTypeName(type: number, machine: ELFMachine): string {
  const table = RELOC_TABLES[machine];
  return table?.[type] ?? `type(${type})`;
}

// Virtual-scroll renderer for relocation entries.
function renderVirtualRelocationTable(
  container: HTMLElement,
  entries: RelocationEntry[],
  usesDynSym: boolean,
  versionInfo: VersionInfo | null,
  is64: boolean,
  hasAddend: boolean,
  machine: ELFMachine
): void {
  const padW = is64 ? 16 : 8;

  const table = document.createElement("table");
  table.className = "data-table reloc-virtual";
  table.innerHTML = `
    <thead><tr>
      <th>Offset</th><th>Info</th><th>Type</th><th>Sym. Value</th><th>Sym. Name</th>
      <th>Version</th><th>Ver#</th>
      ${hasAddend ? '<th class="sym-right">Addend</th>' : ""}
    </tr></thead>
    <tbody></tbody>
  `;
  container.appendChild(table);

  attachVirtualScroll(
    table,
    entries.length,
    (i) => {
      const r = entries[i];
      const [verName, verNum, hidden] = usesDynSym
        ? versionParts(r.symIndex, versionInfo)
        : ["", "", false];
      const verNumCell = verNumCellHtml(verNum, hidden);
      const addendStr =
        r.addend !== null && r.addend !== 0n
          ? r.addend > 0n
            ? `+0x${r.addend.toString(16)}`
            : `-0x${(-r.addend).toString(16)}`
          : "";
      const addendCell = hasAddend ? `<td class="mono sym-right">${addendStr}</td>` : "";
      const tr = document.createElement("tr");
      if (i % 2 === 0) {
        tr.className = "vs-even";
      }
      tr.innerHTML = `
        <td class="mono">${hexPad(r.offset, padW)}</td>
        <td class="mono">${r.symIndex.toString(16).padStart(8, "0")}${r.type.toString(16).padStart(8, "0")}</td>
        <td class="mono">${relocTypeName(r.type, machine)}</td>
        <td class="mono">${r.symValue ? hexPad(r.symValue, padW) : ""}</td>
        <td class="mono">${r.symName}</td>
        <td class="mono sym-version">${verName}</td>
        <td class="mono">${verNumCell}</td>
        ${addendCell}
      `;
      return tr;
    },
    () => container.style.display !== "none"
  );
}

function renderRelocationSection(
  container: HTMLElement,
  section: RelocationSection,
  versionInfo: VersionInfo | null,
  is64: boolean,
  hasAddend: boolean,
  machine: ELFMachine
): void {
  if (section.entries.length === 0) {
    appendEmptyMessage(container, "No entries");
    return;
  }

  if (section.entries.length > VIRTUAL_THRESHOLD) {
    renderVirtualRelocationTable(
      container,
      section.entries,
      section.usesDynSym,
      versionInfo,
      is64,
      hasAddend,
      machine
    );
    return;
  }

  const padW = is64 ? 16 : 8;
  const table = document.createElement("table");
  table.className = "data-table";
  table.innerHTML = `
    <thead><tr>
      <th>Offset</th><th>Info</th><th>Type</th><th>Sym. Value</th><th>Sym. Name</th>
      <th>Version</th><th>Ver#</th>
      ${hasAddend ? '<th class="sym-right">Addend</th>' : ""}
    </tr></thead>
  `;
  const tbody = document.createElement("tbody");
  for (const r of section.entries) {
    const [verName, verNum, hidden] = section.usesDynSym
      ? versionParts(r.symIndex, versionInfo)
      : ["", "", false];
    const verNumCell = verNumCellHtml(verNum, hidden);
    const addendStr =
      r.addend !== null && r.addend !== 0n
        ? r.addend > 0n
          ? `+0x${r.addend.toString(16)}`
          : `-0x${(-r.addend).toString(16)}`
        : "";
    const addendCell = hasAddend ? `<td class="mono sym-right">${addendStr}</td>` : "";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${hexPad(r.offset, padW)}</td>
      <td class="mono">${r.symIndex.toString(16).padStart(8, "0")}${r.type.toString(16).padStart(8, "0")}</td>
      <td class="mono">${relocTypeName(r.type, machine)}</td>
      <td class="mono">${r.symValue ? hexPad(r.symValue, padW) : ""}</td>
      <td class="mono">${r.symName}</td>
      <td class="mono sym-version">${verName}</td>
      <td class="mono">${verNumCell}</td>
      ${addendCell}
    `;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}

export function renderRelocations(container: HTMLElement, elf: ELFFile): void {
  const sections = elf.relocations;
  const total = sections.reduce((n, s) => n + s.entries.length, 0);
  container.innerHTML = `<h2 class="view-title">Relocations (${total} total)</h2>`;

  if (sections.length === 0) {
    appendEmptyMessage(container, "No relocations");
    return;
  }

  const is64 = sections.some((s) => s.entries.some((r) => r.offset > 0xffffffffn));
  const hasAddend = sections.some((s) => s.entries.some((r) => r.addend !== null));
  const versionInfo = elf.versionInfo;
  const machine = elf.header.machine;

  // Sub-tab switcher — one tab per relocation section
  createSubTabs(
    container,
    sections.map((s) => ({
      label: `${s.name} (${s.entries.length})`,
      render: (p: HTMLElement) =>
        renderRelocationSection(p, s, versionInfo, is64, hasAddend, machine),
    }))
  );
}
