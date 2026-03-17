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

  /** Create a Cursor for sequential reading starting at `off` within this Reader. */
  cursor(off: number, len?: number): Cursor {
    const view =
      len !== undefined
        ? this.subView(off, len)
        : new DataView(this.view.buffer, this.view.byteOffset + off, this.view.byteLength - off);
    return new Cursor(view, this.le, this.is64);
  }
}

// ─── Cursor (sequential reader) ──────────────────────────────────────────────

/**
 * Sequential reader that maintains an internal position.
 * Wraps a DataView with the same endianness/class awareness as Reader.
 * Each read advances the position automatically.
 */
export class Cursor {
  readonly view: DataView;
  readonly le: boolean;
  readonly is64: boolean;
  pos: number;

  constructor(view: DataView, le: boolean, is64: boolean, pos = 0) {
    this.view = view;
    this.le = le;
    this.is64 = is64;
    this.pos = pos;
  }

  /** Bytes remaining from current position. */
  get remaining(): number {
    return this.view.byteLength - this.pos;
  }

  /** Total length of the underlying view. */
  get length(): number {
    return this.view.byteLength;
  }

  // ── Fixed-width reads ────────────────────────────────────────────────────

  u8(): number {
    const v = this.view.getUint8(this.pos);
    this.pos += 1;
    return v;
  }
  i8(): number {
    const v = this.view.getInt8(this.pos);
    this.pos += 1;
    return v;
  }
  u16(): number {
    const v = this.view.getUint16(this.pos, this.le);
    this.pos += 2;
    return v;
  }
  i16(): number {
    const v = this.view.getInt16(this.pos, this.le);
    this.pos += 2;
    return v;
  }
  u32(): number {
    const v = this.view.getUint32(this.pos, this.le);
    this.pos += 4;
    return v;
  }
  i32(): number {
    const v = this.view.getInt32(this.pos, this.le);
    this.pos += 4;
    return v;
  }
  u64(): bigint {
    const v = this.view.getBigUint64(this.pos, this.le);
    this.pos += 8;
    return v;
  }
  i64(): bigint {
    const v = this.view.getBigInt64(this.pos, this.le);
    this.pos += 8;
    return v;
  }

  // ── ELF-aware reads ──────────────────────────────────────────────────────

  /** ELF address: u32 for ELF32, u64 for ELF64. */
  addr(): bigint {
    return this.is64 ? this.u64() : BigInt(this.u32());
  }

  // ── LEB128 ───────────────────────────────────────────────────────────────

  uleb128(): number {
    let result = 0;
    let shift = 0;
    let byte: number;
    do {
      byte = this.view.getUint8(this.pos++);
      result |= (byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    return result >>> 0;
  }

  sleb128(): number {
    let result = 0;
    let shift = 0;
    let byte: number;
    do {
      byte = this.view.getUint8(this.pos++);
      result |= (byte & 0x7f) << shift;
      shift += 7;
    } while (byte & 0x80);
    if (shift < 32 && byte & 0x40) result |= -(1 << shift);
    return result | 0;
  }

  // ── String ───────────────────────────────────────────────────────────────

  /** Read a NUL-terminated string and advance past the NUL byte. */
  cstring(): string {
    let end = this.pos;
    while (end < this.view.byteLength && this.view.getUint8(end) !== 0) end++;
    const bytes = new Uint8Array(
      this.view.buffer,
      this.view.byteOffset + this.pos,
      end - this.pos
    );
    this.pos = end + 1; // skip NUL
    return new TextDecoder().decode(bytes);
  }

  // ── Navigation ───────────────────────────────────────────────────────────

  /** Skip `n` bytes forward. */
  skip(n: number): void {
    this.pos += n;
  }

  /** Create a sub-Cursor of `len` bytes at the current position (does not advance). */
  sub(len: number): Cursor {
    return new Cursor(
      new DataView(this.view.buffer, this.view.byteOffset + this.pos, len),
      this.le,
      this.is64
    );
  }
}
