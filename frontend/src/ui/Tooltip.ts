// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Shared tooltip singleton used by MemoryMapView and DynamicView.

let _tooltip: HTMLElement | null = null;

function getTooltip(): HTMLElement {
  if (!_tooltip) {
    _tooltip = document.createElement("div");
    _tooltip.className = "elf-tooltip";
    _tooltip.style.display = "none";
    document.body.appendChild(_tooltip);
  }
  return _tooltip;
}

export function positionTooltip(t: HTMLElement, x: number, y: number): void {
  const margin = 14;
  const tw = t.offsetWidth,
    th = t.offsetHeight;
  const vw = window.innerWidth,
    vh = window.innerHeight;
  const left = x + tw + margin > vw - 8 ? x - tw - margin : x + margin;
  const top = y + th + margin > vh - 8 ? y - th - margin : y + margin;
  t.style.left = `${Math.max(4, left)}px`;
  t.style.top = `${Math.max(4, top)}px`;
}

export function showTooltip(html: string, x: number, y: number): void {
  const t = getTooltip();
  t.innerHTML = html;
  t.style.display = "block";
  positionTooltip(t, x, y);
}

export function hideTooltip(): void {
  if (_tooltip) _tooltip.style.display = "none";
}

export function isTooltipVisible(): boolean {
  return _tooltip?.style.display !== "none";
}

/** Reposition the tooltip if it is currently visible. */
export function moveTooltip(x: number, y: number): void {
  if (isTooltipVisible()) positionTooltip(getTooltip(), x, y);
}

export function addTooltipHandlers(el: HTMLElement, getHtml: () => string): void {
  el.addEventListener("mouseenter", (e) => showTooltip(getHtml(), e.clientX, e.clientY));
  el.addEventListener("mousemove", (e) => {
    if (isTooltipVisible()) positionTooltip(getTooltip(), e.clientX, e.clientY);
  });
  el.addEventListener("mouseleave", () => hideTooltip());
}

export function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export function ttRow(key: string, val: string): string {
  return `<tr><td class="tt-key">${key}</td><td class="tt-val">${escapeHtml(val)}</td></tr>`;
}
