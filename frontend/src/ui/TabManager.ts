// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Tab manager: manages multiple closeable, switchable content tabs.

export interface Tab {
  id: string;
  label: string;
  closeable: boolean;
  render: (container: HTMLElement) => void;
}

export class TabManager {
  private tabs: Tab[] = [];
  private activeId: string | null = null;
  private tabBar: HTMLElement;
  private contentArea: HTMLElement;
  // Cached wrapper elements: tab id → div.tab-content
  private wrappers = new Map<string, HTMLElement>();
  onActivate?: (id: string) => void;
  onContextMenu?: (id: string, x: number, y: number) => void;

  constructor(tabBar: HTMLElement, contentArea: HTMLElement) {
    this.tabBar = tabBar;
    this.contentArea = contentArea;
  }

  // Open or focus a tab. If the tab already exists, it is focused.
  openTab(tab: Tab): void {
    const existing = this.tabs.find((t) => t.id === tab.id);
    if (existing) {
      this.activate(existing.id);
      return;
    }
    this.tabs.push(tab);
    this.renderTabBar();
    this.activate(tab.id);
  }

  // Replace the render function of an existing tab and force re-render.
  updateTab(id: string, render: (container: HTMLElement) => void): void {
    const tab = this.tabs.find((t) => t.id === id);
    if (!tab) return;
    tab.render = render;
    // Destroy cached wrapper so it re-renders on next activation
    const old = this.wrappers.get(id);
    if (old) {
      old.remove();
      this.wrappers.delete(id);
    }
    if (this.activeId === id) this.showContent(id);
  }

  closeTab(id: string): void {
    const idx = this.tabs.findIndex((t) => t.id === id);
    if (idx === -1) return;
    this.tabs.splice(idx, 1);
    const wrapper = this.wrappers.get(id);
    if (wrapper) {
      wrapper.remove();
      this.wrappers.delete(id);
    }

    if (this.activeId === id) {
      const next = this.tabs[Math.min(idx, this.tabs.length - 1)];
      this.activeId = next?.id ?? null;
    }
    this.renderTabBar();
    if (this.activeId) {
      this.showContent(this.activeId);
      this.onActivate?.(this.activeId);
    }
  }

  activate(id: string): void {
    this.activeId = id;
    this.renderTabBar();
    this.showContent(id);
    this.onActivate?.(id);
  }

  private showContent(id: string): void {
    // Hide all wrappers, show the target one
    for (const [wid, el] of this.wrappers) {
      el.style.display = wid === id ? "" : "none";
    }

    // Create wrapper and render if not yet done
    if (!this.wrappers.has(id)) {
      const tab = this.tabs.find((t) => t.id === id);
      if (!tab) return;

      const wrapper = document.createElement("div");
      wrapper.className = "tab-content";
      wrapper.style.height = "100%";
      wrapper.style.overflow = "auto";
      wrapper.tabIndex = 0;
      this.contentArea.appendChild(wrapper);
      this.wrappers.set(id, wrapper);
      tab.render(wrapper);
    }

    // Focus the scroll container so Page Up/Down work immediately.
    const wrapper = this.wrappers.get(id);
    if (wrapper) wrapper.focus({ preventScroll: true });
  }

  private renderTabBar(): void {
    this.tabBar.innerHTML = "";
    for (const tab of this.tabs) {
      const tabEl = document.createElement("div");
      tabEl.className = "tab" + (tab.id === this.activeId ? " active" : "");
      tabEl.dataset.tabId = tab.id;

      tabEl.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        this.onContextMenu?.(tab.id, e.clientX, e.clientY);
      });

      tabEl.addEventListener("click", () => this.activate(tab.id));

      const label = document.createElement("span");
      label.className = "tab-label";
      label.textContent = tab.label;
      tabEl.appendChild(label);

      if (tab.closeable) {
        const closeBtn = document.createElement("button");
        closeBtn.className = "tab-close";
        closeBtn.textContent = "×";
        closeBtn.title = "Close tab";
        closeBtn.addEventListener("click", (e) => {
          e.stopPropagation();
          this.closeTab(tab.id);
        });
        tabEl.appendChild(closeBtn);
      }

      this.tabBar.appendChild(tabEl);
    }
    this.tabBar.querySelector<HTMLElement>(".tab.active")?.scrollIntoView({
      block: "nearest",
      inline: "nearest",
    });
  }

  hasTab(id: string): boolean {
    return this.tabs.some((t) => t.id === id);
  }

  getActiveId(): string | null {
    return this.activeId;
  }
}
