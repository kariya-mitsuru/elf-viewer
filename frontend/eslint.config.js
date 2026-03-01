// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// @ts-check
import tseslint from "typescript-eslint";
import prettierConfig from "eslint-config-prettier";

export default tseslint.config(
  tseslint.configs.recommended,
  prettierConfig,
  {
    ignores: ["dist/**", "wailsjs/**"],
  }
);
