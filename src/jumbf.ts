import { Reader, ascii, concat, startsWith, toHex } from "./bytes.ts";

/**
 * A parsed JUMBF box. `start` and `end` are offsets into the buffer the box was
 * parsed from: for the boxes returned by {@link locateManifest} that is the
 * manifest payload (for JPEG, the concatenated APP11 envelope payloads), not the
 * enclosing file. Use the returned `ranges` for absolute file offsets.
 */
export interface JumbfBox {
  type: string;
  label: string;
  uuid?: string;
  toggle?: number;
  format: "box" | "superbox";
  payload: Uint8Array;
  content: Uint8Array;
  boxes: JumbfBox[];
  start: number;
  end: number;
  headerLength: number;
}

const JUMBF_UUID = "6a756d62";
const DESC_TYPE = "6a756d64";

export function parseJumbfBoxes(bytes: Uint8Array, offset = 0, end = bytes.length): JumbfBox[] {
  const out: JumbfBox[] = [];
  let at = offset;
  while (at + 8 <= end) {
    const box = readBox(bytes, at, end);
    if (!box) break;
    out.push(box);
    if (box.end <= at) break;
    at = box.end;
  }
  return out;
}

function readBox(bytes: Uint8Array, offset: number, end: number): JumbfBox | undefined {
  const reader = new Reader(bytes, offset);
  let length = reader.u32();
  let headerLength = 8;
  if (length === 1) {
    const extended = reader.u64();
    if (extended > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("JUMBF box is too large");
    length = Number(extended);
    headerLength = 16;
  } else if (length === 0) {
    length = end - offset;
  }
  if (length < headerLength) throw new Error(`invalid JUMBF box length: ${length}`);
  const type = ascii(reader.take(4));
  const boxEnd = Math.min(offset + length, end);
  const payload = bytes.subarray(offset + headerLength, boxEnd);
  const box: JumbfBox = {
    type,
    label: "",
    format: "box",
    payload,
    content: payload,
    boxes: [],
    start: offset,
    end: boxEnd,
    headerLength,
  };
  if (type === "jumb") {
    box.format = "superbox";
    const description = readBox(payload, 0, payload.length);
    if (!description || description.type !== "jumd") {
      throw new Error(`JUMBF superbox at ${offset} has no description box`);
    }
    applyDescription(box, description.payload);
    const consumed = description.end;
    box.content = payload.subarray(consumed);
    box.boxes = parseJumbfBoxes(payload, consumed, payload.length);
  } else if (type === "jumd") {
    applyDescription(box, payload);
  }
  return box;
}

function applyDescription(box: JumbfBox, content: Uint8Array): void {
  if (content.length < 17) throw new Error("JUMBF description box is too small");
  const uuidBytes = content.subarray(0, 16);
  box.uuid = formatUuid(uuidBytes);
  box.toggle = content[16]!;
  if ((box.toggle & 0x01) !== 0) {
    const rest = content.subarray(17);
    let labelEnd = rest.length;
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === 0) {
        labelEnd = i;
        break;
      }
    }
    box.label = ascii(rest.subarray(0, labelEnd));
  }
}

export function formatUuid(bytes: Uint8Array): string {
  const hex = toHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export interface ManifestLocation {
  boxes: JumbfBox[];
  ranges: Array<{ start: number; length: number }>;
  container: "jpeg" | "png" | "webp" | "c2pa";
}

const JPEG_SOI = Uint8Array.of(0xff, 0xd8);
const JUMBF_MARKER = Uint8Array.of(0x6a, 0x75, 0x6d, 0x62);

export function locateManifest(bytes: Uint8Array): ManifestLocation | undefined {
  if (startsWith(bytes, JPEG_SOI)) return locateInJpeg(bytes);
  if (bytes.length > 8 && startsWith(bytes, Uint8Array.of(0x89, 0x50, 0x4e, 0x47))) return locateInPng(bytes);
  if (bytes.length > 12 && ascii(bytes.subarray(0, 4)) === "RIFF" && ascii(bytes.subarray(8, 12)) === "WEBP") {
    return locateInWebp(bytes);
  }
  const boxes = parseJumbfBoxes(bytes);
  if (boxes.length > 0) return { boxes, ranges: [{ start: 0, length: bytes.length }], container: "c2pa" };
  return undefined;
}

function locateInJpeg(bytes: Uint8Array): ManifestLocation | undefined {
  const reader = new Reader(bytes, 2);
  const payloads: Uint8Array[] = [];
  const ranges: Array<{ start: number; length: number }> = [];
  while (reader.offset + 4 <= bytes.length) {
    const markerStart = reader.offset;
    if (reader.u8() !== 0xff) break;
    let marker = reader.u8();
    while (marker === 0xff) marker = reader.u8();
    if (marker === 0xda) break;
    if (marker === 0xd8 || marker === 0xd9) continue;
    const length = reader.u16();
    if (length < 2) break;
    const segmentStart = markerStart;
    const segmentEnd = reader.offset + length - 2;
    if (marker === 0xeb) {
      const payload = bytes.subarray(reader.offset, Math.min(segmentEnd, bytes.length));
      if (payload.length > 8 && payload[0] === 0x4a && payload[1] === 0x50) {
        payloads.push(payload.subarray(8));
        ranges.push({ start: segmentStart, length: segmentEnd - segmentStart });
      }
    }
    reader.seek(Math.min(segmentEnd, bytes.length));
    if (payloads.length > 0 && ranges.length > 0) {
      const total = payloads.reduce((sum, p) => sum + p.length, 0);
      if (total >= readBoxLength(payloads[0]!)) {
        const merged = concat(payloads);
        return { boxes: parseJumbfBoxes(merged), ranges, container: "jpeg" };
      }
    }
  }
  if (payloads.length === 0) return undefined;
  const merged = concat(payloads);
  if (merged.length === 0) return undefined;
  return { boxes: parseJumbfBoxes(merged), ranges, container: "jpeg" };
}

function readBoxLength(payload: Uint8Array): number {
  if (payload.length < 4) return payload.length;
  const declared = ((payload[0]! << 24) | (payload[1]! << 16) | (payload[2]! << 8) | payload[3]!) >>> 0;
  return declared === 0 || declared === 1 ? payload.length : declared;
}

function locateInPng(bytes: Uint8Array): ManifestLocation | undefined {
  const reader = new Reader(bytes, 8);
  while (reader.offset + 12 <= bytes.length) {
    const length = reader.u32();
    const type = ascii(reader.take(4));
    const dataStart = reader.offset;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > bytes.length) break;
    if (type === "caBX") {
      const payload = bytes.subarray(dataStart, dataEnd);
      const ranges = [{ start: dataStart - 8, length: length + 12 }];
      return { boxes: parseJumbfBoxes(payload), ranges, container: "png" };
    }
    if (type === "IEND") break;
    reader.seek(dataEnd + 4);
  }
  return undefined;
}

function locateInWebp(bytes: Uint8Array): ManifestLocation | undefined {
  const reader = new Reader(bytes, 12);
  while (reader.offset + 8 <= bytes.length) {
    const fourcc = ascii(reader.take(4));
    const size = reader.u32();
    const dataStart = reader.offset;
    const dataEnd = dataStart + size + (size % 2);
    if (dataEnd > bytes.length) break;
    if (fourcc === "C2PA") {
      const payload = bytes.subarray(dataStart, dataStart + size);
      return { boxes: parseJumbfBoxes(payload), ranges: [{ start: dataStart - 8, length: size + 8 }], container: "webp" };
    }
    reader.seek(dataEnd);
  }
  return undefined;
}

export function findBox(boxes: readonly JumbfBox[], label: string): JumbfBox | undefined {
  return walk(boxes).find((b) => b.label === label);
}

export function findBoxes(boxes: readonly JumbfBox[], label: string): JumbfBox[] {
  return walk(boxes).filter((b) => b.label === label);
}

export function walk(boxes: readonly JumbfBox[]): JumbfBox[] {
  const out: JumbfBox[] = [];
  const visit = (list: readonly JumbfBox[]) => {
    for (const box of list) {
      out.push(box);
      visit(box.boxes);
    }
  };
  visit(boxes);
  return out;
}

export function manifestStoreBox(boxes: readonly JumbfBox[]): JumbfBox | undefined {
  return boxes.find(
    (b) => b.type === "jumb" && (b.label === "c2pa" || b.uuid === WELL_KNOWN_UUIDS.manifestStore),
  );
}

export function findManifestLabels(boxes: readonly JumbfBox[]): string[] {
  return walk(boxes)
    .filter((b) => b.label.startsWith("c2pa.claim"))
    .map((b) => b.label);
}

export function containsJumbf(bytes: Uint8Array): boolean {
  return bytes.length >= 4 && startsWith(bytes.subarray(0, 4), JUMBF_MARKER);
}

export function boxUuid(box: JumbfBox): string {
  return box.uuid ?? toHex(new Uint8Array());
}

export const WELL_KNOWN_UUIDS = {
  manifestStore: "63327061-0011-0010-8000-00aa00389b71",
  claim: "63326d61-0011-0010-8000-00aa00389b71",
  signature: "63327367-0011-0010-8000-00aa00389b71",
  assertionStore: "63326173-0011-0010-8000-00aa00389b71",
  description: DESC_TYPE,
} as const;
