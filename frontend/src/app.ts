// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

import { parseELF, ParseError } from "./parser/elf.ts";
import { type ELFFile, PHType, SHType } from "./parser/types.ts";
import { MemoryMapView } from "./views/MemoryMapView.ts";
import { TabManager } from "./ui/TabManager.ts";
import { Sidebar } from "./ui/Sidebar.ts";
import { showContextMenu } from "./ui/ContextMenu.ts";
import { showAboutDialog } from "./ui/AboutDialog.ts";

// Detect Wails environment: window.go is injected by the Wails runtime.
export function isWails(): boolean {
  return "go" in window;
}

// Scroll to a row by id and briefly highlight it.
function scrollAndHighlight(rowId: string): void {
  // Use rAF to wait for the DOM to update after async render
  requestAnimationFrame(() => {
    setTimeout(() => {
      const el = document.getElementById(rowId);
      if (!el) {
        return;
      }
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.classList.add("highlighted");
      setTimeout(() => el.classList.remove("highlighted"), 1500);
    }, 80);
  });
}

export class App {
  private root: HTMLElement;
  private currentELF: ELFFile | null = null;
  private currentPath = "";
  private tabManager: TabManager | null = null;
  private sidebar: Sidebar | null = null;

  constructor() {
    const el = document.getElementById("app");
    if (!el) {
      throw new Error("#app element not found");
    }
    this.root = el;
  }

  async init(): Promise<void> {
    if (isWails()) {
      try {
        const { GetInitPath } = await import("./platform/wails.ts");
        const initPath = await GetInitPath();
        if (initPath) {
          await this.loadFromPath(initPath);
          return;
        }
      } catch {
        // fall through to welcome screen
      }
    }
    this.renderWelcome();
  }

  // ─── Welcome screen ─────────────────────────────────────────────────────────

  private renderWelcome(): void {
    this.currentELF = null;
    this.tabManager = null;
    this.sidebar = null;

    const isWeb = !isWails();
    this.root.innerHTML = `
      <div class="welcome">
        <h1>ELF Viewer</h1>
        <button id="openBtn">Open ELF File...</button>
        ${isWeb ? '<input type="file" id="fileInput" style="display:none">' : ""}
        <p class="hint">or pass a file path as a command-line argument</p>
        <button class="version-badge" id="aboutBtn">${__APP_VERSION__}</button>
      </div>
    `;

    document.getElementById("openBtn")!.addEventListener("click", () => {
      if (isWails()) {
        this.openViaWails();
      } else {
        document.getElementById("fileInput")!.click();
      }
    });
    document.getElementById("aboutBtn")!.addEventListener("click", showAboutDialog);

    if (isWeb) {
      const fi = document.getElementById("fileInput") as HTMLInputElement;
      fi.addEventListener("change", () => {
        if (fi.files?.[0]) {
          this.loadFromBrowserFile(fi.files[0]);
        }
      });
    }
  }

  // ─── File loading ───────────────────────────────────────────────────────────

  private async openViaWails(): Promise<void> {
    try {
      const { OpenFileDialog } = await import("./platform/wails.ts");
      const path = await OpenFileDialog();
      if (path) {
        await this.loadFromPath(path);
      }
    } catch (err) {
      this.showError(String(err));
    }
  }

  async loadFromPath(path: string): Promise<void> {
    try {
      const { ReadFileBytes } = await import("./platform/wails.ts");
      const bytes = await ReadFileBytes(path);
      await this.parseAndRender(bytes, path);
    } catch (err) {
      this.showError(String(err));
    }
  }

  async loadFromBrowserFile(file: File): Promise<void> {
    try {
      const { readFileAsBytes } = await import("./platform/web.ts");
      const bytes = await readFileAsBytes(file);
      await this.parseAndRender(bytes, file.name);
    } catch (err) {
      this.showError(String(err));
    }
  }

  // ─── Parsing and rendering ──────────────────────────────────────────────────

  private async parseAndRender(bytes: Uint8Array, filePath: string): Promise<void> {
    try {
      this.currentELF = parseELF(bytes);
      this.currentPath = filePath;
      this.renderMainView();
    } catch (err) {
      if (err instanceof ParseError) {
        this.showError(`ELF parse error: ${err.message}`);
      } else {
        this.showError(String(err));
      }
    }
  }

  // ─── Main application layout ────────────────────────────────────────────────

  private renderMainView(): void {
    const elf = this.currentELF!;
    const filePath = this.currentPath;
    const isObjFile = elf.programHeaders.filter((p) => p.type === PHType.Load).length === 0;

    const isWeb = !isWails();
    this.root.innerHTML = `
      <div class="app-layout">
        <div class="app-header">
          <span class="app-title">ELF Viewer</span>
          <span class="file-path" title="${filePath}">${filePath}</span>
          <button id="openAnotherBtn">Open Another File</button>
          <button class="version-badge" id="aboutBtn">${__APP_VERSION__}</button>
          ${isWeb ? '<input type="file" id="fileInput" style="display:none">' : ""}
        </div>
        <div class="app-body">
          <nav id="sidebar" class="sidebar"></nav>
          <div class="content-panel">
            <div id="tabBar" class="tab-bar"></div>
            <div id="tabContent" class="tab-content-area"></div>
          </div>
        </div>
      </div>
    `;

    document.getElementById("openAnotherBtn")!.addEventListener("click", () => {
      if (isWails()) {
        this.openViaWails();
      } else {
        document.getElementById("fileInput")!.click();
      }
    });
    document.getElementById("aboutBtn")!.addEventListener("click", showAboutDialog);
    if (isWeb) {
      const fi = document.getElementById("fileInput") as HTMLInputElement;
      fi.addEventListener("change", () => {
        if (fi.files?.[0]) {
          this.loadFromBrowserFile(fi.files[0]);
        }
      });
    }

    // Initialize tab manager
    const tabBar = document.getElementById("tabBar")!;
    const tabContent = document.getElementById("tabContent")!;
    this.tabManager = new TabManager(tabBar, tabContent);
    this.tabManager.onActivate = (id) => this.sidebar?.setActive(id);
    this.tabManager.onContextMenu = (id, x, y) => this.showHexDumpMenu(id, x, y, elf);

    // Initialize sidebar
    const sidebarEl = document.getElementById("sidebar")!;
    this.sidebar = new Sidebar(sidebarEl, (id) => this.handleSidebarClick(id, elf, filePath));
    this.sidebar.onContextMenu = (id, x, y) => this.showHexDumpMenu(id, x, y, elf);
    this.sidebar.setItems([
      { id: "elf-header", label: "ELF Header", group: "ELF Info" },
      {
        id: "prog-headers",
        label: "Program Headers",
        group: "ELF Info",
        disabled: elf.programHeaders.length === 0,
      },
      {
        id: "section-headers",
        label: "Section Headers",
        group: "ELF Info",
        disabled: elf.sectionHeaders.length === 0,
      },
      {
        id: "symbols",
        label: "Symbols",
        group: "Data",
        disabled: elf.symbols.length === 0 && elf.dynSymbols.length === 0,
      },
      {
        id: "relocations",
        label: "Relocations",
        group: "Data",
        disabled: elf.relocations.length === 0,
      },
      { id: "hash", label: "Hash Table", group: "Data", disabled: elf.hashTables.length === 0 },
      { id: "gnu-hash", label: "GNU Hash Table", group: "Data", disabled: !elf.gnuHashTable },
      { id: "dynamic", label: "Dynamic", group: "Data", disabled: elf.dynamicEntries.length === 0 },
      {
        id: "versions",
        label: "Versions",
        group: "Data",
        disabled:
          !elf.versionInfo ||
          (elf.versionInfo.versionDefs.length === 0 && elf.versionInfo.versionNeeds.length === 0),
      },
      { id: "notes", label: "Notes", group: "Data", disabled: elf.notes.length === 0 },
      { id: "eh-frame", label: ".eh_frame", group: "Data", disabled: !elf.ehFrame },
      { id: "debug-frame", label: ".debug_frame", group: "Data", disabled: !elf.debugFrame },
      { id: "security", label: "Security", group: "Views" },
      { id: "memory-map", label: "Memory Map", group: "Views", disabled: isObjFile },
      {
        id: "file-map",
        label: "File Map",
        group: "Views",
        disabled: elf.sectionHeaders.length <= 1,
      },
    ]);

    // Open default view
    this.handleSidebarClick(isObjFile ? "file-map" : "memory-map", elf, filePath);
  }

  private handleSidebarClick(id: string, elf: ELFFile, filePath: string): void {
    this.sidebar?.setActive(id);
    switch (id) {
      case "memory-map":
        this.openMemoryMapTab(elf, filePath);
        break;
      case "file-map":
        this.openFileMapTab(elf, filePath);
        break;
      case "elf-header":
        this.openElfHeaderTab(elf);
        break;
      case "prog-headers":
        this.openProgHeadersTab(elf);
        break;
      case "section-headers":
        this.openSectionHeadersTab(elf);
        break;
      case "symbols":
        this.openSymbolsTab(elf);
        break;
      case "relocations":
        this.openRelocationsTab(elf);
        break;
      case "hash":
        this.openHashTab(elf);
        break;
      case "gnu-hash":
        this.openGnuHashTab(elf);
        break;
      case "dynamic":
        this.openDynamicTab(elf);
        break;
      case "versions":
        this.openVersionsTab(elf);
        break;
      case "notes":
        this.openNotesTab(elf);
        break;
      case "eh-frame":
        this.openEhFrameTab(elf);
        break;
      case "debug-frame":
        this.openDebugFrameTab(elf);
        break;
      case "security":
        this.openSecurityTab(elf);
        break;
    }
  }

  // ─── Tab openers ────────────────────────────────────────────────────────────

  private openMemoryMapTab(elf: ELFFile, filePath: string): void {
    this.tabManager!.openTab({
      id: "memory-map",
      label: "Memory Map",
      closeable: true,
      render: (container) => {
        container.style.padding = "0";
        const mapEl = document.createElement("div");
        mapEl.className = "memory-map";
        container.appendChild(mapEl);

        // Legend
        const legend = document.createElement("aside");
        legend.className = "legend";
        legend.innerHTML = `
          <h3>Legend</h3>
          <div class="legend-item"><span class="swatch rx"></span>R-X (code)</div>
          <div class="legend-item"><span class="swatch rw"></span>RW- (data)</div>
          <div class="legend-item"><span class="swatch ro"></span>R-- (read-only)</div>
          <div class="legend-item"><span class="swatch other"></span>other</div>
        `;

        // Wrap in map-container for the old layout
        const wrap = document.createElement("div");
        wrap.className = "map-container";
        wrap.appendChild(mapEl);
        wrap.appendChild(legend);
        // Replace container content
        container.innerHTML = "";
        container.appendChild(wrap);

        const view = new MemoryMapView(mapEl, elf, filePath);
        view.onSectionClick = (shIndex, segIndex) => {
          if (shIndex !== null) {
            this.openSectionHeadersTab(elf, shIndex);
          } else {
            this.openProgHeadersTab(elf, segIndex);
          }
        };
        view.onElfHeaderClick = () => this.openElfHeaderTab(elf);
        view.onProgHeadersClick = () => this.openProgHeadersTab(elf);
        view.onHexDump = (label, fileOffset, size) =>
          this.openHexDumpTab(elf, label, fileOffset, size);
        view.onDynamicClick = (tag) => this.openDynamicTab(elf, tag);
        view.onNavigate = (target) => {
          switch (target) {
            case "symbols":
              this.openSymbolsTab(elf);
              break;
            case "relocations":
              this.openRelocationsTab(elf);
              break;
            case "dynamic":
              this.openDynamicTab(elf);
              break;
            case "notes":
              this.openNotesTab(elf);
              break;
            case "versions":
              this.openVersionsTab(elf);
              break;
            case "hash":
              this.openHashTab(elf);
              break;
            case "gnu-hash":
              this.openGnuHashTab(elf);
              break;
          }
        };
        view.render();
      },
    });
  }

  private openFileMapTab(elf: ELFFile, filePath: string): void {
    this.tabManager!.openTab({
      id: "file-map",
      label: "File Map",
      closeable: true,
      render: (container) => {
        container.style.padding = "0";
        const wrap = document.createElement("div");
        wrap.className = "map-container";
        container.appendChild(wrap);
        const mapEl = document.createElement("div");
        wrap.appendChild(mapEl);
        const view = new MemoryMapView(mapEl, elf, filePath, "file");
        view.onSectionClick = (shIndex) => {
          if (shIndex !== null) {
            this.openSectionHeadersTab(elf, shIndex);
          }
        };
        view.onElfHeaderClick = () => this.openElfHeaderTab(elf);
        view.onProgHeadersClick = () => this.openProgHeadersTab(elf);
        view.onSectionHeadersClick = () => this.openSectionHeadersTab(elf);
        view.onHexDump = (label, fileOffset, size) =>
          this.openHexDumpTab(elf, label, fileOffset, size);
        view.onNavigate = (target) => {
          switch (target) {
            case "symbols":
              this.openSymbolsTab(elf);
              break;
            case "relocations":
              this.openRelocationsTab(elf);
              break;
            case "dynamic":
              this.openDynamicTab(elf);
              break;
            case "notes":
              this.openNotesTab(elf);
              break;
            case "versions":
              this.openVersionsTab(elf);
              break;
            case "hash":
              this.openHashTab(elf);
              break;
            case "gnu-hash":
              this.openGnuHashTab(elf);
              break;
          }
        };
        view.render();
      },
    });
  }

  // ─── Hex Dump context menu ──────────────────────────────────────────────────

  private getHexDumpRegions(
    id: string,
    elf: ELFFile
  ): { label: string; offset: number; size: number }[] {
    switch (id) {
      case "elf-header":
        return [{ label: "ELF Header", offset: 0, size: elf.header.ehSize }];
      case "prog-headers":
        if (elf.header.phNum === 0) {
          return [];
        }
        return [
          {
            label: "Program Headers",
            offset: elf.header.phOffset,
            size: elf.header.phEntSize * elf.header.phNum,
          },
        ];
      case "section-headers":
        if (elf.header.shNum === 0) {
          return [];
        }
        return [
          {
            label: "Section Headers",
            offset: elf.header.shOffset,
            size: elf.header.shEntSize * elf.header.shNum,
          },
        ];
      case "symbols": {
        const regions: { label: string; offset: number; size: number }[] = [];
        const symtab = elf.sectionHeaders.find((s) => s.type === SHType.SymTab);
        if (symtab && symtab.size > 0) {
          regions.push({
            label: symtab.name || ".symtab",
            offset: symtab.offset,
            size: symtab.size,
          });
        }
        const dynsym = elf.sectionHeaders.find((s) => s.type === SHType.DynSym);
        if (dynsym && dynsym.size > 0) {
          regions.push({
            label: dynsym.name || ".dynsym",
            offset: dynsym.offset,
            size: dynsym.size,
          });
        } else if (elf.dynSymFileOffset !== null && elf.dynSymByteSize > 0) {
          regions.push({
            label: ".dynsym",
            offset: elf.dynSymFileOffset,
            size: elf.dynSymByteSize,
          });
        }
        return regions;
      }
      case "relocations": {
        const regions: { label: string; offset: number; size: number }[] = [];
        for (const rs of elf.relocations) {
          if (rs.fileOffset !== null && rs.byteSize > 0) {
            regions.push({ label: rs.name, offset: rs.fileOffset, size: rs.byteSize });
          }
        }
        return regions;
      }
      case "hash": {
        const regions: { label: string; offset: number; size: number }[] = [];
        for (const ht of elf.hashTables) {
          if (ht.fileOffset !== null && ht.byteSize > 0) {
            regions.push({ label: ht.sectionName, offset: ht.fileOffset, size: ht.byteSize });
          }
        }
        return regions;
      }
      case "gnu-hash": {
        const ht = elf.gnuHashTable;
        if (!ht || ht.fileOffset === null) {
          return [];
        }
        return [{ label: ht.sectionName, offset: ht.fileOffset, size: ht.byteSize }];
      }
      case "dynamic": {
        const sh = elf.sectionHeaders.find((s) => s.type === SHType.Dynamic);
        if (sh && sh.size > 0) {
          return [{ label: sh.name || ".dynamic", offset: sh.offset, size: sh.size }];
        }
        const ph = elf.programHeaders.find((p) => p.type === PHType.Dynamic);
        if (ph && ph.filesz > 0) {
          return [{ label: ".dynamic", offset: ph.offset, size: ph.filesz }];
        }
        return [];
      }
      case "versions": {
        const regions: { label: string; offset: number; size: number }[] = [];
        for (const sh of elf.sectionHeaders) {
          if (
            (sh.type === SHType.GnuVerSym ||
              sh.type === SHType.GnuVerNeed ||
              sh.type === SHType.GnuVerDef) &&
            sh.size > 0
          ) {
            regions.push({ label: sh.name, offset: sh.offset, size: sh.size });
          }
        }
        if (regions.length === 0 && elf.versionInfo) {
          const vi = elf.versionInfo;
          if (vi.verSymFileOffset !== null && vi.verSymByteSize > 0) {
            regions.push({
              label: ".gnu.version",
              offset: vi.verSymFileOffset,
              size: vi.verSymByteSize,
            });
          }
          if (vi.verNeedFileOffset !== null && vi.verNeedByteSize > 0) {
            regions.push({
              label: ".gnu.version_r",
              offset: vi.verNeedFileOffset,
              size: vi.verNeedByteSize,
            });
          }
          if (vi.verDefFileOffset !== null && vi.verDefByteSize > 0) {
            regions.push({
              label: ".gnu.version_d",
              offset: vi.verDefFileOffset,
              size: vi.verDefByteSize,
            });
          }
        }
        return regions;
      }
      case "notes": {
        const regions: { label: string; offset: number; size: number }[] = [];
        for (const sh of elf.sectionHeaders) {
          if (sh.type === SHType.Note && sh.size > 0) {
            regions.push({ label: sh.name, offset: sh.offset, size: sh.size });
          }
        }
        if (regions.length === 0) {
          for (const ph of elf.programHeaders) {
            if (ph.type === PHType.Note && ph.filesz > 0) {
              regions.push({ label: `PT_NOTE #${ph.index}`, offset: ph.offset, size: ph.filesz });
            }
          }
        }
        return regions;
      }
      default:
        return [];
    }
  }

  private showHexDumpMenu(id: string, x: number, y: number, elf: ELFFile): void {
    const regions = this.getHexDumpRegions(id, elf);
    if (regions.length === 0) {
      return;
    }
    showContextMenu(
      x,
      y,
      regions.map((r) => ({
        label: `Hex Dump: ${r.label}`,
        action: () => this.openHexDumpTab(elf, r.label, r.offset, r.size),
      }))
    );
  }

  private openHexDumpTab(elf: ELFFile, label: string, fileOffset: number, size: number): void {
    const id = `hex-dump-${fileOffset}-${size}`;
    this.tabManager!.openTab({
      id,
      label: `Hex: ${label}`,
      closeable: true,
      render: (container) => {
        import("./views/HexDumpView.ts").then(({ renderHexDump }) =>
          renderHexDump(container, elf, label, fileOffset, size)
        );
      },
    });
  }

  private openElfHeaderTab(elf: ELFFile): void {
    this.tabManager!.openTab({
      id: "elf-header",
      label: "ELF Header",
      closeable: true,
      render: (container) => {
        import("./views/ElfHeaderView.ts").then(({ renderElfHeader }) =>
          renderElfHeader(container, elf)
        );
      },
    });
  }

  private openProgHeadersTab(elf: ELFFile, scrollToPhIndex?: number): void {
    const isNew = !this.tabManager!.hasTab("prog-headers");
    this.tabManager!.openTab({
      id: "prog-headers",
      label: "Program Headers",
      closeable: true,
      render: (container) => {
        import("./views/ProgramHeadersView.ts").then(({ renderProgramHeaders }) => {
          renderProgramHeaders(
            container,
            elf,
            (label, offset, size) => this.openHexDumpTab(elf, label, offset, size),
            (target) => {
              switch (target) {
                case "dynamic":
                  this.openDynamicTab(elf);
                  break;
                case "notes":
                  this.openNotesTab(elf);
                  break;
              }
            }
          );
          if (scrollToPhIndex !== undefined) {
            scrollAndHighlight(`ph-row-${scrollToPhIndex}`);
          }
        });
      },
    });
    if (!isNew && scrollToPhIndex !== undefined) {
      scrollAndHighlight(`ph-row-${scrollToPhIndex}`);
    }
  }

  private openSectionHeadersTab(elf: ELFFile, scrollToShIndex?: number): void {
    const isNew = !this.tabManager!.hasTab("section-headers");
    this.tabManager!.openTab({
      id: "section-headers",
      label: "Section Headers",
      closeable: true,
      render: (container) => {
        import("./views/SectionHeadersView.ts").then(({ renderSectionHeaders }) => {
          renderSectionHeaders(
            container,
            elf,
            (label, offset, size) => this.openHexDumpTab(elf, label, offset, size),
            (target) => {
              switch (target) {
                case "symbols":
                  this.openSymbolsTab(elf);
                  break;
                case "relocations":
                  this.openRelocationsTab(elf);
                  break;
                case "dynamic":
                  this.openDynamicTab(elf);
                  break;
                case "notes":
                  this.openNotesTab(elf);
                  break;
                case "versions":
                  this.openVersionsTab(elf);
                  break;
                case "hash":
                  this.openHashTab(elf);
                  break;
                case "gnu-hash":
                  this.openGnuHashTab(elf);
                  break;
              }
            }
          );
          if (scrollToShIndex !== undefined) {
            scrollAndHighlight(`sh-row-${scrollToShIndex}`);
          }
        });
      },
    });
    if (!isNew && scrollToShIndex !== undefined) {
      scrollAndHighlight(`sh-row-${scrollToShIndex}`);
    }
  }

  private openSymbolsTab(elf: ELFFile): void {
    this.tabManager!.openTab({
      id: "symbols",
      label: "Symbols",
      closeable: true,
      render: (container) => {
        import("./views/SymbolsView.ts").then(({ renderSymbols }) => renderSymbols(container, elf));
      },
    });
  }

  private openRelocationsTab(elf: ELFFile): void {
    this.tabManager!.openTab({
      id: "relocations",
      label: "Relocations",
      closeable: true,
      render: (container) => {
        import("./views/RelocationsView.ts").then(({ renderRelocations }) =>
          renderRelocations(container, elf)
        );
      },
    });
  }

  private openHashTab(elf: ELFFile): void {
    this.tabManager!.openTab({
      id: "hash",
      label: "Hash Table",
      closeable: true,
      render: (container) => {
        import("./views/HashView.ts").then(({ renderHash }) => renderHash(container, elf));
      },
    });
  }

  private openGnuHashTab(elf: ELFFile): void {
    this.tabManager!.openTab({
      id: "gnu-hash",
      label: "GNU Hash Table",
      closeable: true,
      render: (container) => {
        import("./views/GnuHashView.ts").then(({ renderGnuHash }) => {
          renderGnuHash(container, elf);
        });
      },
    });
  }

  private openDynamicTab(elf: ELFFile, scrollToTag?: number): void {
    const isNew = !this.tabManager!.hasTab("dynamic");
    this.tabManager!.openTab({
      id: "dynamic",
      label: "Dynamic",
      closeable: true,
      render: (container) => {
        import("./views/DynamicView.ts").then(({ renderDynamic }) => {
          renderDynamic(
            container,
            elf,
            (target) => {
              switch (target) {
                case "symbols":
                  this.openSymbolsTab(elf);
                  break;
                case "relocations":
                  this.openRelocationsTab(elf);
                  break;
                case "dynamic":
                  this.openDynamicTab(elf);
                  break;
                case "notes":
                  this.openNotesTab(elf);
                  break;
                case "versions":
                  this.openVersionsTab(elf);
                  break;
                case "hash":
                  this.openHashTab(elf);
                  break;
                case "gnu-hash":
                  this.openGnuHashTab(elf);
                  break;
              }
            },
            (shIndex) => this.openSectionHeadersTab(elf, shIndex),
            (label, fileOffset, size) => this.openHexDumpTab(elf, label, fileOffset, size)
          );
          if (scrollToTag !== undefined) {
            scrollAndHighlight(`dyn-row-${scrollToTag}`);
          }
        });
      },
    });
    if (!isNew && scrollToTag !== undefined) {
      scrollAndHighlight(`dyn-row-${scrollToTag}`);
    }
  }

  private openNotesTab(elf: ELFFile): void {
    this.tabManager!.openTab({
      id: "notes",
      label: "Notes",
      closeable: true,
      render: (container) => {
        import("./views/NotesView.ts").then(({ renderNotes }) => renderNotes(container, elf));
      },
    });
  }

  private openEhFrameTab(elf: ELFFile): void {
    this.tabManager!.openTab({
      id: "eh-frame",
      label: ".eh_frame",
      closeable: true,
      render: (container) => {
        import("./views/EhFrameView.ts").then(({ renderEhFrame }) => renderEhFrame(container, elf));
      },
    });
  }

  private openDebugFrameTab(elf: ELFFile): void {
    this.tabManager!.openTab({
      id: "debug-frame",
      label: ".debug_frame",
      closeable: true,
      render: (container) => {
        import("./views/EhFrameView.ts").then(({ renderDebugFrame }) =>
          renderDebugFrame(container, elf)
        );
      },
    });
  }

  private openSecurityTab(elf: ELFFile): void {
    this.tabManager!.openTab({
      id: "security",
      label: "Security",
      closeable: true,
      render: (container) => {
        import("./views/SecurityView.ts").then(({ renderSecurity }) =>
          renderSecurity(container, elf)
        );
      },
    });
  }

  private openVersionsTab(elf: ELFFile): void {
    this.tabManager!.openTab({
      id: "versions",
      label: "Versions",
      closeable: true,
      render: (container) => {
        import("./views/VersionsView.ts").then(({ renderVersions }) =>
          renderVersions(container, elf)
        );
      },
    });
  }

  // ─── Error display ──────────────────────────────────────────────────────────

  showError(msg: string): void {
    this.root.innerHTML = `
      <div class="welcome">
        <div style="max-width:600px;padding:12px 16px;background:rgba(243,139,168,0.15);color:#f38ba8;border-radius:6px">${msg}</div>
        <button id="backBtn" style="margin-top:12px">Back</button>
      </div>
    `;
    document.getElementById("backBtn")!.addEventListener("click", () => this.renderWelcome());
  }
}
