// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// ELF Header view: renders the ELF header in a readelf -h style table.

import { type ELFFile, ELFClass, ELFData, ELFType, ELFOSABI, ELFMachine } from "../parser/types.ts";
import { isPIE } from "./viewUtils.ts";

function elfTypeName(elf: ELFFile): string {
  switch (elf.header.type) {
    case ELFType.Exec:
      return "ET_EXEC (Executable file)";
    case ELFType.Dyn:
      return isPIE(elf) ? "ET_DYN (PIE file)" : "ET_DYN (Shared object file)";
    case ELFType.Rel:
      return "ET_REL (Relocatable file)";
    case ELFType.Core:
      return "ET_CORE (Core file)";
    case ELFType.None:
      return "ET_NONE (No file type)";
    default:
      return `0x${(elf.header.type as number).toString(16)} (Unknown)`;
  }
}

function machineName(m: ELFMachine): string {
  switch (m) {
    case ELFMachine.X86_64:
      return "Advanced Micro Devices X86-64";
    case ELFMachine.X86:
      return "Intel 80386";
    case ELFMachine.ARM:
      return "ARM";
    case ELFMachine.AArch64:
      return "AArch64";
    case ELFMachine.RISC_V:
      return "RISC-V";
    case ELFMachine.PPC:
      return "PowerPC";
    case ELFMachine.PPC64:
      return "PowerPC64";
    case ELFMachine.MIPS:
      return "MIPS R3000";
    case ELFMachine.IA64:
      return "Intel IA-64 processor technology";
    case ELFMachine.SPARC:
      return "Sparc";
    case ELFMachine.S390:
      return "IBM S/390";
    case ELFMachine.LoongArch:
      return "LoongArch";
    case ELFMachine.None:
      return "None";
    default:
      return `0x${(m as number).toString(16)}`;
  }
}

function osabiName(abi: ELFOSABI): string {
  switch (abi) {
    case ELFOSABI.None:
      return "UNIX - System V";
    case ELFOSABI.HPUX:
      return "HP/UX";
    case ELFOSABI.NetBSD:
      return "NetBSD";
    case ELFOSABI.Linux:
      return "Linux";
    case ELFOSABI.Solaris:
      return "Solaris";
    case ELFOSABI.AIX:
      return "IBM AIX";
    case ELFOSABI.IRIX:
      return "SGI IRIX";
    case ELFOSABI.FreeBSD:
      return "FreeBSD";
    case ELFOSABI.OpenBSD:
      return "OpenBSD";
    case ELFOSABI.ARM:
      return "ARM";
    case ELFOSABI.Standalone:
      return "Standalone App";
    default:
      return `0x${(abi as number).toString(16)}`;
  }
}

// AArch64 ELF header flags
const EF_AARCH64_CHERI_PURECAP = 0x00010000;

function elfFlagsStr(flags: number, machine: ELFMachine): string {
  const hex = `0x${flags.toString(16)}`;
  if (flags === 0) {
    return hex;
  }
  if (machine === ELFMachine.AArch64) {
    const names: string[] = [];
    if (flags & EF_AARCH64_CHERI_PURECAP) {
      names.push("CHERI_PURECAP");
    }
    return names.length > 0 ? `${hex} (${names.join(", ")})` : hex;
  }
  return hex;
}

export function renderElfHeader(container: HTMLElement, elf: ELFFile): void {
  const h = elf.header;
  const hex = (n: number | bigint) => `0x${n.toString(16)}`;
  const dec = (n: number | bigint) => `${n}`;

  const rows: [string, string][] = [
    [
      "Magic",
      `7f 45 4c 46 ${h.class === ELFClass.ELF32 ? "01" : "02"} ${h.data === ELFData.LSB ? "01" : "02"} 01 00 00 00 00 00 00 00 00 00`,
    ],
    ["Class", h.class === ELFClass.ELF64 ? "ELF64" : "ELF32"],
    [
      "Data",
      h.data === ELFData.LSB ? "2's complement, little endian" : "2's complement, big endian",
    ],
    ["Version", `${h.version} (current)`],
    ["OS/ABI", osabiName(h.osabi)],
    ["ABI Version", dec(h.abiVersion)],
    ["Type", elfTypeName(elf)],
    ["Machine", machineName(h.machine)],
    ["Version (ELF)", hex(1)],
    ["Entry point address", hex(h.entryPoint)],
    ["Start of program headers", `${h.phOffset} (bytes into file)`],
    ["Start of section headers", `${h.shOffset} (bytes into file)`],
    ["Flags", elfFlagsStr(h.flags, h.machine)],
    ["Size of this header", `${h.ehSize} (bytes)`],
    ["Size of program headers", `${h.phEntSize} (bytes)`],
    ["Number of program headers", dec(h.phNum)],
    ["Size of section headers", `${h.shEntSize} (bytes)`],
    ["Number of section headers", dec(h.shNum)],
    ["Section header string table index", dec(h.shStrNdx)],
  ];

  container.innerHTML = '<h2 class="view-title">ELF Header</h2>';
  const table = document.createElement("table");
  table.className = "info-table";
  for (const [label, value] of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="info-label">${label}</td><td class="info-value">${value}</td>`;
    table.appendChild(tr);
  }
  container.appendChild(table);
}
