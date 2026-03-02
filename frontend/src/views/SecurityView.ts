// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Security View: displays binary hardening features (PIE, RELRO, NX, Stack Canary, FORTIFY_SOURCE).

import {
  type ELFFile,
  ELFType,
  PHType,
  DynTag,
  PF_X,
  DF_BIND_NOW,
  DF_1_PIE,
  DF_1_NOW,
} from "../parser/types.ts";

type SecurityStatus = "enabled" | "partial" | "disabled" | "unknown";

interface SecurityFeature {
  name: string;
  status: SecurityStatus;
  detail: string;
  description: string;
}

function detectPIE(elf: ELFFile): SecurityFeature {
  const isDyn = elf.header.type === ELFType.Dyn;
  const isExec = elf.header.type === ELFType.Exec;
  const flags1Entry = elf.dynamicEntries.find((e) => e.tag === DynTag.Flags1);
  const hasPIEFlag =
    flags1Entry !== undefined && (flags1Entry.value & BigInt(DF_1_PIE)) !== 0n;

  let status: SecurityStatus;
  let detail: string;

  if (isExec) {
    status = "disabled";
    detail = "ET_EXEC — fixed-address executable";
  } else if (isDyn && hasPIEFlag) {
    status = "enabled";
    detail = "ET_DYN + DF_1_PIE";
  } else if (isDyn) {
    // ET_DYN without DF_1_PIE: could be a shared library or a PIE built without the flag
    status = "enabled";
    detail = "ET_DYN (PIE or shared library)";
  } else {
    status = "unknown";
    detail = `ELF type: 0x${(elf.header.type as number).toString(16)}`;
  }

  return {
    name: "PIE",
    status,
    detail,
    description: "Position Independent Executable — enables ASLR for the main binary",
  };
}

function detectRELRO(elf: ELFFile): SecurityFeature {
  const hasRelRo = elf.programHeaders.some((ph) => ph.type === PHType.GnuRelRo);
  const bindNowEntry = elf.dynamicEntries.find((e) => e.tag === DynTag.BindNow);
  const flagsEntry = elf.dynamicEntries.find((e) => e.tag === DynTag.Flags);
  const flags1Entry = elf.dynamicEntries.find((e) => e.tag === DynTag.Flags1);

  const hasBindNow =
    bindNowEntry !== undefined ||
    (flagsEntry !== undefined && (flagsEntry.value & BigInt(DF_BIND_NOW)) !== 0n) ||
    (flags1Entry !== undefined && (flags1Entry.value & BigInt(DF_1_NOW)) !== 0n);

  let status: SecurityStatus;
  let detail: string;

  if (hasRelRo && hasBindNow) {
    status = "enabled";
    detail = "PT_GNU_RELRO + BIND_NOW";
  } else if (hasRelRo) {
    status = "partial";
    detail = "PT_GNU_RELRO (no BIND_NOW)";
  } else {
    status = "disabled";
    detail = "No PT_GNU_RELRO segment";
  }

  return {
    name: "RELRO",
    status,
    detail,
    description: "Relocation Read-Only — marks the GOT read-only after dynamic linking",
  };
}

function detectNX(elf: ELFFile): SecurityFeature {
  const gnuStack = elf.programHeaders.find((ph) => ph.type === PHType.GnuStack);

  let status: SecurityStatus;
  let detail: string;

  if (gnuStack === undefined) {
    status = "unknown";
    detail = "No PT_GNU_STACK segment";
  } else if ((gnuStack.flags & PF_X) !== 0) {
    status = "disabled";
    detail = "PT_GNU_STACK has PF_X — executable stack";
  } else {
    status = "enabled";
    detail = "PT_GNU_STACK without PF_X";
  }

  return {
    name: "NX",
    status,
    detail,
    description: "Non-Executable stack — prevents shellcode execution from stack memory",
  };
}

function detectStackCanary(elf: ELFFile): SecurityFeature {
  const canaryNames = new Set(["__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie"]);
  const found = new Set<string>();
  for (const s of elf.symbols) if (canaryNames.has(s.name)) found.add(s.name);
  for (const s of elf.dynSymbols) if (canaryNames.has(s.name)) found.add(s.name);

  const hasSymbols = elf.symbols.length > 0 || elf.dynSymbols.length > 0;

  let status: SecurityStatus;
  let detail: string;

  if (found.size > 0) {
    status = "enabled";
    detail = [...found].join(", ");
  } else if (!hasSymbols) {
    status = "unknown";
    detail = "No symbol table available";
  } else {
    status = "disabled";
    detail = "No stack canary symbols found";
  }

  return {
    name: "Stack Canary",
    status,
    detail,
    description: "Detects stack buffer overflows at runtime via a canary value",
  };
}

function detectFortify(elf: ELFFile): SecurityFeature {
  const fortified = new Set<string>();
  for (const s of elf.symbols) if (s.name.startsWith("__") && s.name.endsWith("_chk")) fortified.add(s.name);
  for (const s of elf.dynSymbols) if (s.name.startsWith("__") && s.name.endsWith("_chk")) fortified.add(s.name);

  const hasSymbols = elf.symbols.length > 0 || elf.dynSymbols.length > 0;

  let status: SecurityStatus;
  let detail: string;

  if (fortified.size > 0) {
    status = "enabled";
    const names = [...fortified].sort();
    detail =
      names.slice(0, 5).join(", ") +
      (names.length > 5 ? ` (+${names.length - 5} more)` : "");
  } else if (!hasSymbols) {
    status = "unknown";
    detail = "No symbol table available";
  } else {
    status = "disabled";
    detail = "No _chk symbols found";
  }

  return {
    name: "FORTIFY_SOURCE",
    status,
    detail,
    description: "Replaces unsafe libc calls (memcpy, sprintf…) with bounds-checked variants",
  };
}

function detectRPath(elf: ELFFile): SecurityFeature {
  const rpath = elf.dynamicEntries.find((e) => e.tag === DynTag.RPath);

  return {
    name: "RPATH",
    status: rpath ? "disabled" : "enabled",
    detail: rpath ? (rpath.name ?? "(unresolved)") : "No RPATH",
    description: "Hard-coded library search path — takes precedence over LD_LIBRARY_PATH",
  };
}

function detectRunPath(elf: ELFFile): SecurityFeature {
  const runpath = elf.dynamicEntries.find((e) => e.tag === DynTag.RunPath);

  return {
    name: "RUNPATH",
    status: runpath ? "disabled" : "enabled",
    detail: runpath ? (runpath.name ?? "(unresolved)") : "No RUNPATH",
    description: "Hard-coded library search path — overridable via LD_LIBRARY_PATH",
  };
}

function detectSymbols(elf: ELFFile): SecurityFeature {
  const count = elf.symbols.length;

  return {
    name: "Symbols",
    status: count === 0 ? "enabled" : "disabled",
    detail: count === 0 ? "No Symbols" : `${count} Symbols`,
    description: "Stripped binaries are harder to reverse-engineer",
  };
}

const STATUS_LABEL: Record<SecurityStatus, string> = {
  enabled: "Enabled",
  partial: "Partial",
  disabled: "Disabled",
  unknown: "Unknown",
};

export function renderSecurity(container: HTMLElement, elf: ELFFile): void {
  const features: SecurityFeature[] = [
    detectPIE(elf),
    detectRELRO(elf),
    detectNX(elf),
    detectStackCanary(elf),
    detectFortify(elf),
    detectRPath(elf),
    detectRunPath(elf),
    detectSymbols(elf),
  ];

  container.innerHTML = `<h2 class="view-title">Security Features</h2>`;

  const table = document.createElement("table");
  table.className = "data-table security-table";
  table.innerHTML = `
    <thead>
      <tr>
        <th>Feature</th>
        <th>Status</th>
        <th>Detail</th>
        <th>Description</th>
      </tr>
    </thead>
  `;

  const tbody = document.createElement("tbody");
  for (const f of features) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="sec-feature-name">${f.name}</td>
      <td><span class="sec-badge sec-badge--${f.status}">${STATUS_LABEL[f.status]}</span></td>
      <td class="mono sec-detail">${f.detail}</td>
      <td class="sec-desc">${f.description}</td>
    `;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  container.appendChild(table);
}
