import { Reader, concat, toHex } from "./bytes.ts";

export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | undefined
  | CborValue[]
  | Map<CborValue, CborValue>;

export const CBOR_TAG = {
  DateString: 0,
  EpochDateTime: 1,
  PositiveBignum: 2,
  NegativeBignum: 3,
  DecimalFraction: 4,
  BigFloat: 5,
  EncodedCbor: 24,
} as const;

export interface CborDecodeOptions {
  maxDepth?: number;
}

export function decodeCbor(bytes: Uint8Array, options: CborDecodeOptions = {}): CborValue {
  const reader = new Reader(bytes);
  const value = readItem(reader, options.maxDepth ?? 64);
  if (!reader.eof) throw new Error(`trailing bytes after CBOR item: ${reader.remaining} byte(s) remain`);
  return value;
}

export function decodeCborSequence(bytes: Uint8Array, options: CborDecodeOptions = {}): CborValue[] {
  const reader = new Reader(bytes);
  const out: CborValue[] = [];
  while (!reader.eof) out.push(readItem(reader, options.maxDepth ?? 64));
  return out;
}

function readItem(reader: Reader, depth: number): CborValue {
  if (depth <= 0) throw new Error("CBOR nesting too deep");
  const initial = reader.u8();
  const major = initial >> 5;
  const additional = initial & 0x1f;
  switch (major) {
    case 0:
      return readLength(reader, additional);
    case 1: {
      const n = readLength(reader, additional);
      return -1 - n;
    }
    case 2: {
      if (additional === 31) return readIndefiniteChunks(reader, 2);
      const length = readLength(reader, additional);
      return reader.take(length);
    }
    case 3: {
      if (additional === 31) return new TextDecoder("utf-8", { fatal: false }).decode(readIndefiniteChunks(reader, 3));
      const length = readLength(reader, additional);
      return new TextDecoder("utf-8", { fatal: false }).decode(reader.take(length));
    }
    case 4: {
      const items: CborValue[] = [];
      if (additional === 31) {
        while (!isBreak(reader)) items.push(readItem(reader, depth - 1));
        consumeBreak(reader);
        return items;
      }
      const length = readLength(reader, additional);
      for (let i = 0; i < length; i++) items.push(readItem(reader, depth - 1));
      return items;
    }
    case 5: {
      const map = new Map<CborValue, CborValue>();
      const pair = () => {
        const key = readItem(reader, depth - 1);
        const value = readItem(reader, depth - 1);
        if (typeof key === "number" || typeof key === "string" || typeof key === "bigint") {
          map.set(key, value);
        } else {
          map.set(hexKey(key), value);
        }
      };
      if (additional === 31) {
        while (!isBreak(reader)) pair();
        consumeBreak(reader);
        return map;
      }
      const length = readLength(reader, additional);
      for (let i = 0; i < length; i++) pair();
      return map;
    }
    case 6: {
      const tag = readLength(reader, additional);
      const inner = readItem(reader, depth - 1);
      return applyTag(tag, inner);
    }
    case 7:
      switch (additional) {
        case 20:
          return false;
        case 21:
          return true;
        case 22:
          return null;
        case 23:
          return undefined;
        default:
          throw new Error(`unsupported CBOR simple/float value: ${additional}`);
      }
    default:
      throw new Error(`unsupported CBOR major type: ${major}`);
  }
}

function applyTag(tag: number, inner: CborValue): CborValue {
  switch (tag) {
    case CBOR_TAG.EpochDateTime:
    case CBOR_TAG.DateString:
    case CBOR_TAG.DecimalFraction:
    case CBOR_TAG.BigFloat:
    case CBOR_TAG.EncodedCbor:
      return inner;
    default:
      return inner;
  }
}

function readIndefiniteChunks(reader: Reader, expectedMajor: number): Uint8Array {
  const parts: Uint8Array[] = [];
  while (!isBreak(reader)) {
    const initial = reader.u8();
    const major = initial >> 5;
    if (major !== expectedMajor) {
      throw new Error(
        `indefinite-length string chunks must all use major type ${expectedMajor}`,
      );
    }
    const chunk = readLength(reader, initial & 0x1f);
    parts.push(reader.take(chunk));
  }
  consumeBreak(reader);
  return concat(parts);
}

function isBreak(reader: Reader): boolean {
  if (reader.eof) throw new Error("unterminated indefinite-length CBOR item");
  return reader.peekU8() === 0xff;
}

function consumeBreak(reader: Reader): void {
  if (!isBreak(reader)) throw new Error("expected CBOR break code");
  reader.u8();
}

function readLength(reader: Reader, additional: number): number {
  if (additional < 24) return additional;
  switch (additional) {
    case 24:
      return reader.u8();
    case 25:
      return reader.u16();
    case 26:
      return reader.u32();
    case 27: {
      const value = reader.u64();
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("CBOR length does not fit in a JS number");
      return Number(value);
    }
    case 31:
      throw new Error("unexpected indefinite-length CBOR item");
    default:
      throw new Error(`invalid CBOR additional information: ${additional}`);
  }
}

function hexKey(value: CborValue): CborValue {
  if (value instanceof Uint8Array) return `#${toHex(value)}` as unknown as CborValue;
  return value;
}

export function isMap(value: CborValue): value is Map<CborValue, CborValue> {
  return value instanceof Map;
}

export function mapGet(map: Map<CborValue, CborValue>, key: number | string): CborValue | undefined {
  for (const [k, v] of map) {
    if ((typeof k === "number" || typeof k === "bigint") && typeof key === "number") {
      if (Number(k) === key) return v;
    } else if (k === key) {
      return v;
    }
  }
  return undefined;
}

export function mapGetBytes(map: Map<CborValue, CborValue>, key: number | string): Uint8Array | undefined {
  const value = mapGet(map, key);
  return value instanceof Uint8Array ? value : undefined;
}

export function mapGetString(map: Map<CborValue, CborValue>, key: number | string): string | undefined {
  const value = mapGet(map, key);
  return typeof value === "string" ? value : undefined;
}

export function mapGetNumber(map: Map<CborValue, CborValue>, key: number | string): number | undefined {
  const value = mapGet(map, key);
  if (typeof value === "number") return value;
  if (typeof value === "bigint") return Number(value);
  return undefined;
}

export function mapGetBool(map: Map<CborValue, CborValue>, key: number | string): boolean | undefined {
  const value = mapGet(map, key);
  return typeof value === "boolean" ? value : undefined;
}

export function mapGetMap(map: Map<CborValue, CborValue>, key: number | string): Map<CborValue, CborValue> | undefined {
  const value = mapGet(map, key);
  return value instanceof Map ? value : undefined;
}

export function mapGetArray(map: Map<CborValue, CborValue>, key: number | string): CborValue[] | undefined {
  const value = mapGet(map, key);
  return Array.isArray(value) ? value : undefined;
}

const uint = (n: number): number[] =>
  n < 24 ? [n] : n < 0x100 ? [24, n] : n < 0x10000 ? [25, n >> 8, n & 0xff] : [26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];

export function encodeCbor(value: CborValue): Uint8Array {
  return concat(encodeParts(value));
}

function encodeParts(value: CborValue): Uint8Array[] {
  if (value === null) return [Uint8Array.of(0xf6)];
  if (value === undefined) return [Uint8Array.of(0xf7)];
  if (value === false) return [Uint8Array.of(0xf4)];
  if (value === true) return [Uint8Array.of(0xf5)];
  if (typeof value === "number") {
    if (Number.isInteger(value)) {
      return value >= 0 ? encodeHead(0, value) : encodeHead(1, -1 - value);
    }
    const buf = new ArrayBuffer(9);
    const view = new DataView(buf);
    view.setUint8(0, 0xfb);
    view.setFloat64(1, value);
    return [new Uint8Array(buf)];
  }
  if (typeof value === "bigint") {
    return value >= 0n ? encodeHead(0, Number(value)) : encodeHead(1, Number(-1n - value));
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return [...encodeHead(3, bytes.length), bytes];
  }
  if (value instanceof Uint8Array) return [...encodeHead(2, value.length), value];
  if (Array.isArray(value)) {
    return [...encodeHead(4, value.length), ...value.flatMap(encodeParts)];
  }
  const parts: Uint8Array[] = [...encodeHead(5, value.size)];
  for (const [k, v] of value) parts.push(...encodeParts(k), ...encodeParts(v));
  return parts;
}

function encodeHead(major: number, length: number): Uint8Array[] {
  const head = uint(length).map((b, i) => (i === 0 ? (major << 5) | b : b));
  return [Uint8Array.from(head)];
}
