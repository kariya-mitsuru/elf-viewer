// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Shared virtual-scroll implementation for large data tables.
//
// Usage:
//   1. Create a <table> with <thead> and an empty <tbody>.
//   2. Call attachVirtualScroll(table, count, buildRow, isVisible?).
//
// The function:
//   - Inserts topSpacer/botSpacer rows into tbody.
//   - Measures actual row height with a probe element.
//   - Renders only the visible subset of rows on scroll.
//   - Uses requestAnimationFrame to debounce scroll events.
//
// isVisible: optional function that returns false when the container is hidden
//   (e.g. inside a sub-tab panel). The render loop skips the update while hidden.

const BUFFER = 30; // extra rows rendered above/below the visible area

export function attachVirtualScroll(
  table: HTMLTableElement,
  count: number,
  buildRow: (i: number) => HTMLTableRowElement,
  isVisible?: () => boolean
): void {
  const tbody = table.tBodies[0];
  if (!tbody) return;

  const topSpacer = document.createElement("tr");
  const botSpacer = document.createElement("tr");
  topSpacer.style.height = "0px";
  botSpacer.style.height = "0px";
  tbody.appendChild(topSpacer);
  tbody.appendChild(botSpacer);

  // Measure actual row height with a probe element before the first render.
  // This keeps the total table height (topSpacer + rows + botSpacer) stable,
  // preventing layout shifts during scrolling.
  let ROW_H = 25;
  const probe = document.createElement("tr");
  probe.innerHTML = '<td class="mono">&nbsp;</td>';
  tbody.insertBefore(probe, botSpacer);
  const measured = probe.getBoundingClientRect().height;
  tbody.removeChild(probe);
  if (measured > 0) ROW_H = measured;

  botSpacer.style.height = `${count * ROW_H}px`;

  let rendStart = 0;
  let rendEnd = 0;
  let renderedRows: HTMLTableRowElement[] = [];
  let scrollEl: Element | null = null;

  // Walk up the DOM to find the nearest overflow: auto/scroll ancestor.
  function getScrollEl(): Element | null {
    if (scrollEl) return scrollEl;
    let node: Element | null = table.parentElement;
    while (node && node !== document.body) {
      const ov = getComputedStyle(node).overflowY;
      if (ov === "auto" || ov === "scroll") {
        scrollEl = node;
        return node;
      }
      node = node.parentElement;
    }
    return null;
  }

  function render(): void {
    if (isVisible && !isVisible()) return;
    const sc = getScrollEl();
    if (!sc) return;

    const scRect = sc.getBoundingClientRect();
    const tRect = table.getBoundingClientRect();
    const theadH = table.tHead ? table.tHead.getBoundingClientRect().height : 0;
    const scrolledPast = scRect.top - (tRect.top + theadH);
    const visStart = Math.max(0, scrolledPast);
    const visEnd = visStart + sc.clientHeight;

    const newEnd = Math.min(count, Math.ceil(visEnd / ROW_H) + BUFFER);
    const newStart = Math.min(newEnd, Math.max(0, Math.floor(visStart / ROW_H) - BUFFER));
    if (newStart === rendStart && newEnd === rendEnd) return;

    for (const tr of renderedRows) tbody.removeChild(tr);
    renderedRows = [];

    const frag = document.createDocumentFragment();
    for (let i = newStart; i < newEnd; i++) {
      const tr = buildRow(i);
      frag.appendChild(tr);
      renderedRows.push(tr);
    }
    tbody.insertBefore(frag, botSpacer);

    topSpacer.style.height = `${newStart * ROW_H}px`;
    botSpacer.style.height = `${(count - newEnd) * ROW_H}px`;
    rendStart = newStart;
    rendEnd = newEnd;
  }

  render();

  requestAnimationFrame(() => {
    const sc = getScrollEl();
    if (sc) {
      // Make the scroll container focusable so Page Up/Down work natively.
      if ((sc as HTMLElement).tabIndex < 0) {
        (sc as HTMLElement).tabIndex = 0;
      }
      // Clicking inside the table would lose focus from the scroll container,
      // breaking keyboard scroll. Re-focus on any click inside the table.
      table.addEventListener("click", () => {
        (sc as HTMLElement).focus({ preventScroll: true });
      });

      let rafId = 0;
      sc.addEventListener("scroll", () => {
        if (rafId) cancelAnimationFrame(rafId);
        rafId = requestAnimationFrame(() => {
          render();
          rafId = 0;
        });
      });
    }
  });
}
