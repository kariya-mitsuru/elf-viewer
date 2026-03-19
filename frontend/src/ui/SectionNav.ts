// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Sticky section navigator rendered below the view title.
// Provides jump links for views that contain multiple named sub-sections.

export interface NavSection {
  id: string;
  label: string;
}

/** Slugify a section name into a safe HTML id component. */
export function slugId(prefix: string, name: string): string {
  const slug = name.replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "") || "section";
  return `${prefix}-${slug}`;
}

/**
 * Inserts a sticky nav bar into `container`.
 * Does nothing if fewer than 2 sections are given.
 */
export function renderSectionNav(container: HTMLElement, sections: NavSection[]): void {
  if (sections.length < 2) {
    return;
  }
  container.classList.add("has-section-nav");
  const nav = document.createElement("nav");
  nav.className = "section-nav";
  for (const s of sections) {
    const a = document.createElement("a");
    a.className = "section-nav-link";
    a.textContent = s.label;
    a.addEventListener("click", (e) => {
      e.preventDefault();
      document.getElementById(s.id)?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
    nav.appendChild(a);
  }
  container.appendChild(nav);
}
