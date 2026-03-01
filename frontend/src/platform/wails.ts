// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// Wails platform adapter.
// These functions wrap the auto-generated Wails bindings in frontend/wailsjs/.
// They are only called when running inside a Wails desktop app (isWails() === true).

export async function GetInitPath(): Promise<string> {
  const { GetInitPath } = await import("@wailsjs/go/main/App");
  return GetInitPath();
}

export async function OpenFileDialog(): Promise<string> {
  const { OpenFileDialog } = await import("@wailsjs/go/main/App");
  return OpenFileDialog();
}

// ReadFileBytes reads a file at the given path and returns its raw bytes.
// Go returns a base64 string; decode it with atob() on the JS side.
export async function ReadFileBytes(path: string): Promise<Uint8Array> {
  const { ReadFileBytes } = await import("@wailsjs/go/main/App");
  const b64 = await ReadFileBytes(path);
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
