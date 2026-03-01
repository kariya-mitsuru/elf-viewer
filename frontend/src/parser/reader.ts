// SPDX-FileCopyrightText: 2026 Mitsuru Kariya
// SPDX-License-Identifier: MIT

// ─── Reader helper ────────────────────────────────────────────────────────────

/**
 * Thin wrapper around DataView that carries endianness and class (32/64-bit)
 * so individual read sites don't need to pass those flags every time.
 *
 * All multi-byte reads use `le` to respect the file's data encoding.
 * `addr()` and `xword()` return `bigint` regardless of class so that callers
 * can work with a single type for pointer-sized values.
 */
export class Reader {
  readonly view: DataView;
  readonly le: boolean; // little-endian?
  readonly is64: boolean;

  constructor(view: DataView, le: boolean, is64: boolean) {
    this.view = view;
    this.le = le;
    this.is64 = is64;
  }

  u8(off: number): number {
    return this.view.getUint8(off);
  }
  u16(off: number): number {
    return this.view.getUint16(off, this.le);
  }
  u32(off: number): number {
    return this.view.getUint32(off, this.le);
  }
  i32(off: number): number {
    return this.view.getInt32(off, this.le);
  }
  u64(off: number): bigint {
    return this.view.getBigUint64(off, this.le);
  }
  i64(off: number): bigint {
    return this.view.getBigInt64(off, this.le);
  }

  // ELF address (Elf_Addr) – u32 for ELF32, u64 for ELF64
  addr(off: number): bigint {
    return this.is64 ? this.u64(off) : BigInt(this.u32(off));
  }
  // ELF half-word (always u16)
  half(off: number): number {
    return this.u16(off);
  }
  // ELF word (always u32)
  word(off: number): number {
    return this.u32(off);
  }
  // ELF xword – u64 for ELF64, u32 for ELF32
  xword(off: number): bigint {
    return this.is64 ? this.u64(off) : BigInt(this.u32(off));
  }

  slice(off: number, len: number): Reader {
    return new Reader(this.subView(off, len), this.le, this.is64);
  }

  subView(off: number, len: number): DataView {
    return new DataView(this.view.buffer, this.view.byteOffset + off, len);
  }
}
