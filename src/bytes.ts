export class Reader {
  readonly bytes: Uint8Array;
  offset: number;

  constructor(bytes: Uint8Array, offset = 0) {
    this.bytes = bytes;
    this.offset = offset;
  }

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  get eof(): boolean {
    return this.offset >= this.bytes.length;
  }

  require(n: number): void {
    if (this.offset + n > this.bytes.length) {
      throw new Error(`truncated: need ${n} byte(s) at offset ${this.offset}, have ${this.remaining}`);
    }
  }

  u8(): number {
    this.require(1);
    return this.bytes[this.offset++]!;
  }

  peekU8(): number {
    this.require(1);
    return this.bytes[this.offset]!;
  }

  u16(): number {
    this.require(2);
    const v = (this.bytes[this.offset]! << 8) | this.bytes[this.offset + 1]!;
    this.offset += 2;
    return v;
  }

  u32(): number {
    this.require(4);
    const b = this.bytes;
    const o = this.offset;
    const v = b[o]! * 0x1000000 + (b[o + 1]! << 16) + (b[o + 2]! << 8) + b[o + 3]!;
    this.offset += 4;
    return v;
  }

  u64(): bigint {
    this.require(8);
    let v = 0n;
    for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(this.bytes[this.offset++]!);
    return v;
  }

  take(n: number): Uint8Array {
    this.require(n);
    const out = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  seek(offset: number): void {
    if (offset < 0 || offset > this.bytes.length) throw new Error(`seek out of range: ${offset}`);
    this.offset = offset;
  }

  slice(start: number, end: number): Uint8Array {
    return this.bytes.subarray(start, end);
  }
}

export function concat(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

const HEX = "0123456789abcdef";

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    out += HEX[b >> 4]! + HEX[b & 15]!;
  }
  return out;
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2 !== 0) throw new Error("hex string must have an even length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const utf8Decoder = new TextDecoder("utf-8", { fatal: false });
const utf8Encoder = new TextEncoder();

export function utf8(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

export function encodeUtf8(text: string): Uint8Array {
  return utf8Encoder.encode(text);
}

export function ascii(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]!);
  return out;
}

export function startsWith(bytes: Uint8Array, prefix: Uint8Array): boolean {
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (bytes[i] !== prefix[i]) return false;
  return true;
}

export function indexOfBytes(haystack: Uint8Array, needle: Uint8Array, from = 0): number {
  const n = needle.length;
  if (n === 0) return from;
  const last = haystack.length - n;
  for (let i = from; i <= last; i++) {
    let hit = true;
    for (let j = 0; j < n; j++) {
      if (haystack[i + j] !== needle[j]) {
        hit = false;
        break;
      }
    }
    if (hit) return i;
  }
  return -1;
}

export function base64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

export function fromBase64(text: string): Uint8Array {
  const bin = atob(text.replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function shortHash(bytes: Uint8Array, length = 8): string {
  return toHex(bytes.subarray(0, length));
}
