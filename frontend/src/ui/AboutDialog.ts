// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

const GITHUB_URL = "https://github.com/kariya-mitsuru/elf-viewer";

export function showAboutDialog(): void {
  const version = __APP_VERSION__;
  const buildDate = __BUILD_DATE__;
  const commit = __GIT_COMMIT__;

  const overlay = document.createElement("div");
  overlay.className = "about-overlay";

  overlay.innerHTML = `
    <div class="about-dialog" role="dialog" aria-modal="true" aria-label="About ELF Viewer">
      <div class="about-header">
        <span class="about-title">ELF Viewer</span>
        <button class="about-close" aria-label="Close">✕</button>
      </div>
      <div class="about-body">
        <table class="about-table">
          <tr><td class="about-key">Version</td><td class="about-val">${version}</td></tr>
          <tr><td class="about-key">Build date</td><td class="about-val">${buildDate}</td></tr>
          <tr><td class="about-key">Commit</td><td class="about-val about-mono">${commit}</td></tr>
          <tr><td class="about-key">License</td><td class="about-val">MIT</td></tr>
        </table>
        <a class="about-github" href="${GITHUB_URL}" target="_blank" rel="noopener noreferrer">
          View on GitHub ↗
        </a>
      </div>
    </div>
  `;

  const close = () => overlay.remove();

  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) {
      close();
    }
  });
  overlay.querySelector(".about-close")!.addEventListener("click", close);

  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      close();
      document.removeEventListener("keydown", onKey);
    }
  };
  document.addEventListener("keydown", onKey);
  overlay.addEventListener("remove", () => document.removeEventListener("keydown", onKey));

  document.body.appendChild(overlay);
  (overlay.querySelector(".about-close") as HTMLElement).focus();
}
