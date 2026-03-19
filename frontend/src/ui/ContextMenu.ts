// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Simple right-click context menu utility.

export interface CtxMenuItem {
  label: string;
  action: () => void;
}

let _menu: HTMLElement | null = null;
let _dismiss: ((e: MouseEvent) => void) | null = null;

export function showContextMenu(x: number, y: number, items: CtxMenuItem[]): void {
  hideContextMenu();
  if (items.length === 0) return;

  const menu = document.createElement("div");
  menu.className = "ctx-menu";

  for (const item of items) {
    const btn = document.createElement("button");
    btn.className = "ctx-menu-item";
    btn.textContent = item.label;
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      item.action();
      hideContextMenu();
    });
    menu.appendChild(btn);
  }

  document.body.appendChild(menu);
  _menu = menu;

  // Initial position
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  // Adjust if clipping off screen
  const rect = menu.getBoundingClientRect();
  if (rect.right > window.innerWidth - 4) menu.style.left = `${x - rect.width}px`;
  if (rect.bottom > window.innerHeight - 4) menu.style.top = `${y - rect.height}px`;

  _dismiss = (e: MouseEvent) => {
    if (_menu && !_menu.contains(e.target as Node)) hideContextMenu();
  };
  setTimeout(() => document.addEventListener("mousedown", _dismiss!), 0);
}

export function hideContextMenu(): void {
  _menu?.remove();
  _menu = null;
  if (_dismiss) {
    document.removeEventListener("mousedown", _dismiss);
    _dismiss = null;
  }
}

/**
 * Attaches a right-click context menu to an element.
 * Filters out null items and does nothing if no valid items remain.
 */
export function attachCtxMenu(
  el: HTMLElement,
  items: Array<CtxMenuItem | null>,
  onBeforeShow?: () => void
): void {
  const valid = items.filter(Boolean) as CtxMenuItem[];
  if (valid.length === 0) return;
  el.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    onBeforeShow?.();
    showContextMenu(e.clientX, e.clientY, valid);
  });
}
