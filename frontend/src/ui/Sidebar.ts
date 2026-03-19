// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Left navigation sidebar.
// Each item triggers a callback (typically to open a tab in TabManager).

export interface SidebarItem {
  id: string;
  label: string;
  icon?: string;
  disabled?: boolean;
  group?: string; // optional group heading
}

export class Sidebar {
  private container: HTMLElement;
  private items: SidebarItem[] = [];
  private activeId: string | null = null;
  private onClick: (id: string) => void;
  onContextMenu?: (id: string, x: number, y: number) => void;

  constructor(container: HTMLElement, onClick: (id: string) => void) {
    this.container = container;
    this.container.className = "sidebar";
    this.onClick = onClick;
  }

  setItems(items: SidebarItem[]): void {
    this.items = items;
    this.render();
  }

  setActive(id: string | null): void {
    this.activeId = id;
    this.render();
  }

  private render(): void {
    this.container.innerHTML = "";
    let lastGroup: string | undefined = undefined;

    for (const item of this.items) {
      // Group heading
      if (item.group && item.group !== lastGroup) {
        lastGroup = item.group;
        const heading = document.createElement("div");
        heading.className = "sidebar-group";
        heading.textContent = item.group;
        this.container.appendChild(heading);
      }

      const el = document.createElement("button");
      el.className =
        "sidebar-item" +
        (item.id === this.activeId ? " active" : "") +
        (item.disabled ? " disabled" : "");
      el.textContent = (item.icon ? item.icon + " " : "") + item.label;
      el.disabled = item.disabled ?? false;
      el.addEventListener("click", () => {
        if (!item.disabled) {
          this.onClick(item.id);
        }
      });
      if (!item.disabled) {
        el.addEventListener("contextmenu", (e) => {
          e.preventDefault();
          this.onContextMenu?.(item.id, e.clientX, e.clientY);
        });
      }
      this.container.appendChild(el);
    }
  }
}
