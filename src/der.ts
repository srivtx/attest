import { Reader, toHex, utf8 } from "./bytes.ts";

export const DER_TAG = {
  Boolean: 0x01,
  Integer: 0x02,
  BitString: 0x03,
  OctetString: 0x04,
  Null: 0x05,
  OID: 0x06,
  Utf8String: 0x0c,
  PrintableString: 0x13,
  IA5String: 0x16,
  UTCTime: 0x17,
  GeneralizedTime: 0x18,
  Sequence: 0x10,
  Set: 0x11,
} as const;

export const DER_CLASS = {
  Universal: 0,
  Application: 1,
  Context: 2,
  Private: 3,
} as const;

export interface DerNode {
  readonly tag: number;
  readonly cls: number;
  readonly constructed: boolean;
  readonly headerLength: number;
  readonly length: number;
  readonly content: Uint8Array;
  readonly start: number;
  readonly end: number;
  children(): DerNode[];
}

class DerNodeImpl implements DerNode {
  private cached?: DerNode[];

  constructor(
    private readonly buffer: Uint8Array,
    readonly tag: number,
    readonly cls: number,
    readonly constructed: boolean,
    readonly headerLength: number,
    readonly length: number,
    readonly contentStart: number,
    readonly start: number,
    readonly end: number,
  ) {}

  get content(): Uint8Array {
    return this.buffer.subarray(this.contentStart, this.contentStart + this.length);
  }

  children(): DerNode[] {
    if (this.cached) return this.cached;
    if (!this.constructed) return (this.cached = []);
    const out: DerNode[] = [];
    let at = this.contentStart;
    const limit = this.contentStart + this.length;
    while (at < limit) {
      const node = readDerNode(this.buffer, at);
      out.push(node);
      at = node.end;
    }
    return (this.cached = out);
  }
}

export function readDerNode(bytes: Uint8Array, offset = 0): DerNode {
  const reader = new Reader(bytes, offset);
  const first = reader.u8();
  const cls = (first & 0xc0) >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  if (tag === 0x1f) {
    tag = 0;
    for (;;) {
      const b = reader.u8();
      tag = (tag << 7) | (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
  }
  const lengthByte = reader.u8();
  let length: number;
  if (lengthByte & 0x80) {
    const count = lengthByte & 0x7f;
    if (count === 0) throw new Error("indefinite length is not valid in DER");
    if (count > 6) throw new Error(`unsupported DER length size: ${count}`);
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + reader.u8();
  } else {
    length = lengthByte;
  }
  reader.require(length);
  const contentStart = reader.offset;
  reader.offset += length;
  return new DerNodeImpl(
    bytes,
    tag,
    cls,
    constructed,
    contentStart - offset,
    length,
    contentStart,
    offset,
    reader.offset,
  );
}

export function parseDer(bytes: Uint8Array): DerNode {
  return readDerNode(bytes, 0);
}

export function parseDerSequence(bytes: Uint8Array): DerNode[] {
  const node = parseDer(bytes);
  if (node.tag !== DER_TAG.Sequence) throw new Error(`expected SEQUENCE, got tag 0x${node.tag.toString(16)}`);
  return node.children();
}

export function derChildren(node: DerNode): DerNode[] {
  return node.children();
}

export function isTag(node: DerNode, tag: number, cls: number = DER_CLASS.Universal): boolean {
  return node.tag === tag && node.cls === cls;
}

export function derInteger(node: DerNode): bigint {
  if (!isTag(node, DER_TAG.Integer)) throw new Error(`expected INTEGER, got tag 0x${node.tag.toString(16)}`);
  let value = 0n;
  for (let i = 0; i < node.content.length; i++) value = (value << 8n) | BigInt(node.content[i]!);
  if (node.content.length > 0 && (node.content[0]! & 0x80) !== 0) {
    value -= 1n << BigInt(8 * node.content.length);
  }
  return value;
}

export function derIntegerNumber(node: DerNode): number {
  const value = derInteger(node);
  if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(Number.MIN_SAFE_INTEGER)) {
    throw new Error("INTEGER does not fit in a JS number");
  }
  return Number(value);
}

const OID_ALPHABET = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "joint-iso-itu-t"];

const OID_NAMES: Record<string, string> = {
  "1.2.840.113549.1.1.1": "rsaEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.113549.1.1.10": "rsassaPss",
  "1.2.840.10045.2.1": "id-ecPublicKey",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
  "1.2.840.10045.3.1.7": "prime256v1",
  "1.3.132.0.34": "secp384r1",
  "1.3.132.0.35": "secp521r1",
  "1.3.101.112": "Ed25519",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
  "2.5.4.3": "commonName",
  "2.5.4.6": "countryName",
  "2.5.4.7": "localityName",
  "2.5.4.8": "stateOrProvinceName",
  "2.5.4.10": "organizationName",
  "2.5.4.11": "organizationalUnitName",
  "2.5.29.14": "subjectKeyIdentifier",
  "2.5.29.15": "keyUsage",
  "2.5.29.17": "subjectAltName",
  "2.5.29.19": "basicConstraints",
  "2.5.29.31": "cRLDistributionPoints",
  "2.5.29.32": "certificatePolicies",
  "2.5.29.35": "authorityKeyIdentifier",
  "2.5.29.37": "extKeyUsage",
  "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
  "1.3.6.1.4.1.11129.2.4.2": "signedCertificateTimestampList",
};

export function derOid(node: DerNode): string {
  if (!isTag(node, DER_TAG.OID)) throw new Error(`expected OID, got tag 0x${node.tag.toString(16)}`);
  const bytes = node.content;
  if (bytes.length === 0) throw new Error("empty OID");
  const parts: number[] = [Math.floor(bytes[0]! / 40), bytes[0]! % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = value * 128 + (bytes[i]! & 0x7f);
    if ((bytes[i]! & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

export function oidName(oid: string): string {
  return OID_NAMES[oid] ?? `unknown(${oid})`;
}

export function oidDisplay(oid: string): string {
  return OID_NAMES[oid] ?? oid;
}

export function derBitString(node: DerNode): { unusedBits: number; bytes: Uint8Array } {
  if (!isTag(node, DER_TAG.BitString)) throw new Error(`expected BIT STRING, got tag 0x${node.tag.toString(16)}`);
  if (node.content.length === 0) throw new Error("empty BIT STRING");
  return { unusedBits: node.content[0]!, bytes: node.content.subarray(1) };
}

export function derString(node: DerNode): string {
  switch (node.tag) {
    case DER_TAG.Utf8String:
      return utf8(node.content);
    case DER_TAG.PrintableString:
    case DER_TAG.IA5String:
    case DER_TAG.GeneralizedTime:
    case DER_TAG.UTCTime: {
      let out = "";
      for (let i = 0; i < node.content.length; i++) out += String.fromCharCode(node.content[i]!);
      return out;
    }
    default:
      return toHex(node.content);
  }
}

export function derTime(node: DerNode): Date {
  const text = derString(node);
  if (node.tag === DER_TAG.UTCTime) {
    const yy = Number(text.slice(0, 2));
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    const month = Number(text.slice(2, 4));
    const day = Number(text.slice(4, 6));
    const hour = Number(text.slice(6, 8));
    const minute = Number(text.slice(8, 10));
    const second = Number(text.slice(10, 12) || "0");
    const offsetMinutes = timezoneOffsetMinutes(text.slice(12));
    return new Date(Date.UTC(year, month - 1, day, hour, minute, second) - offsetMinutes * 60000);
  }
  if (node.tag === DER_TAG.GeneralizedTime) {
    const year = Number(text.slice(0, 4));
    const month = Number(text.slice(4, 6));
    const day = Number(text.slice(6, 8));
    const hour = Number(text.slice(8, 10) || "0");
    const minute = Number(text.slice(10, 12) || "0");
    const second = Number(text.slice(12, 14) || "0");
    const offsetMinutes = timezoneOffsetMinutes(text.slice(14));
    return new Date(Date.UTC(year, month - 1, day, hour, minute, second) - offsetMinutes * 60000);
  }
  throw new Error(`not a time: tag 0x${node.tag.toString(16)}`);
}

function timezoneOffsetMinutes(suffix: string): number {
  if (!suffix || suffix === "Z") return 0;
  const sign = suffix[0] === "-" ? -1 : 1;
  const hours = Number(suffix.slice(1, 3));
  const minutes = Number(suffix.slice(3, 5) || "0");
  return sign * (hours * 60 + minutes);
}

export function derNodeAt(bytes: Uint8Array, start: number, end: number): DerNode {
  const node = readDerNode(bytes, start);
  if (node.end !== end) throw new Error(`trailing bytes: node ends at ${node.end}, expected ${end}`);
  return node;
}
