import { decodeCbor, mapGet, mapGetArray, mapGetBytes, mapGetMap, mapGetNumber, mapGetString, type CborValue } from "./cbor.ts";
import { toHex } from "./bytes.ts";
import { findBoxes, walk, type JumbfBox } from "./jumbf.ts";
import { parseCoseSign1, type CoseSign1 } from "./cose.ts";
import { parseCertificate, type Certificate } from "./x509.ts";

export type HashMode = "content" | "payload" | "inner";

export interface HashedUri {
  url: string;
  hash: Uint8Array;
  alg?: string;
}

export interface Claim {
  raw: Uint8Array;
  map: Map<CborValue, CborValue>;
  claimGenerator?: string;
  claimGeneratorName?: string;
  title?: string;
  format?: string;
  alg: string;
  instanceId?: string;
  assertions: HashedUri[];
  signature?: HashedUri;
  createdAt?: Date;
}

export interface Assertion {
  label: string;
  box: JumbfBox;
  value?: CborValue;
  hashedBytes: Uint8Array;
}

export interface Manifest {
  label: string;
  box: JumbfBox;
  claim: Claim;
  signature: CoseSign1;
  signatureBox: JumbfBox;
  signatureBytes: Uint8Array;
  assertions: Assertion[];
  claimBox: JumbfBox;
  certificates: Certificate[];
}

export interface ManifestStore {
  label: string;
  box: JumbfBox;
  manifests: Manifest[];
}

export function parseManifestStore(boxes: readonly JumbfBox[]): ManifestStore[] {
  const stores: ManifestStore[] = [];
  for (const box of boxes) {
    if (box.type !== "jumb") continue;
    const manifests = box.boxes.filter((child) => child.type === "jumb" && child.label.includes("urn:uuid:"));
    if (manifests.length === 0) continue;
    stores.push({
      label: box.label,
      box,
      manifests: manifests.map((m) => parseManifest(m)),
    });
  }
  return stores;
}

function parseManifest(box: JumbfBox): Manifest {
  const claimBox = box.boxes.find((b) => b.label.startsWith("c2pa.claim"));
  if (!claimBox) throw new Error(`manifest ${box.label} has no c2pa.claim box`);
  const signatureBox = box.boxes.find((b) => b.label.startsWith("c2pa.signature"));
  if (!signatureBox) throw new Error(`manifest ${box.label} has no c2pa.signature box`);
  const claim = parseClaim(claimBox);
  const signatureBytes = innerContent(signatureBox);
  const signature = parseCoseSign1(signatureBytes);
  const assertionBoxes = collectAssertions(box);
  const certificates = signature.x5chain.map((der) => parseCertificate(der));
  return {
    label: box.label,
    box,
    claim,
    signature,
    signatureBox,
    signatureBytes,
    assertions: assertionBoxes,
    claimBox,
    certificates,
  };
}

function collectAssertions(box: JumbfBox): Assertion[] {
  const store = box.boxes.find((b) => b.label === "c2pa.assertions");
  const list = store ? store.boxes : box.boxes.filter((b) => b.label.startsWith("c2pa.") && b.label !== "c2pa.claim" && b.label !== "c2pa.signature");
  return list
    .filter((b) => !b.label.startsWith("c2pa.claim") && !b.label.startsWith("c2pa.signature"))
    .map((b) => ({ label: b.label, box: b, value: decodeInner(b), hashedBytes: innerContent(b) }));
}

function decodeInner(box: JumbfBox): CborValue | undefined {
  const inner = box.boxes[0];
  if (!inner) return undefined;
  if (inner.type === "cbor") {
    try {
      return decodeCbor(inner.content);
    } catch {
      return undefined;
    }
  }
  if (inner.type === "json") {
    try {
      return JSON.parse(new TextDecoder().decode(inner.content)) as CborValue;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export function innerContent(box: JumbfBox): Uint8Array {
  const inner = box.boxes[0];
  if (inner && (inner.type === "cbor" || inner.type === "json" || inner.type === "bidb" || inner.type === "bfdb")) {
    return inner.content;
  }
  return box.content;
}

function parseClaim(claimBox: JumbfBox): Claim {
  const raw = innerContent(claimBox);
  const decoded = decodeCbor(raw);
  if (!(decoded instanceof Map)) throw new Error("claim is not a CBOR map");
  const generatorInfo = mapGetArray(decoded, "claim_generator_info");
  let claimGeneratorName: string | undefined;
  if (generatorInfo && generatorInfo.length > 0 && generatorInfo[0] instanceof Map) {
    claimGeneratorName = mapGetString(generatorInfo[0], "name") ?? undefined;
  }
  const created = mapGetNumber(decoded, "created");
  const claim: Claim = {
    raw,
    map: decoded,
    claimGenerator: mapGetString(decoded, "claim_generator"),
    claimGeneratorName,
    title: mapGetString(decoded, "dc:title"),
    format: mapGetString(decoded, "dc:format"),
    alg: mapGetString(decoded, "alg") ?? "sha256",
    instanceId: mapGetString(decoded, "instanceID"),
    assertions: parseHashedUris(mapGetArray(decoded, "assertions")),
    signature: parseHashedUri(mapGet(decoded, "signature")),
  };
  if (created !== undefined) claim.createdAt = new Date(created * 1000);
  return claim;
}

function parseHashedUris(list: CborValue[] | undefined): HashedUri[] {
  if (!list) return [];
  const out: HashedUri[] = [];
  for (const item of list) {
    const parsed = parseHashedUri(item);
    if (parsed) out.push(parsed);
  }
  return out;
}

function parseHashedUri(value: CborValue | undefined): HashedUri | undefined {
  if (!(value instanceof Map)) return undefined;
  const url = mapGetString(value, "url");
  const hash = mapGetBytes(value, "hash");
  if (!url || !hash) return undefined;
  return { url, hash, alg: mapGetString(value, "alg") };
}

export function assertionLabelFromUri(url: string): string {
  const marker = "jumbf=";
  const at = url.indexOf(marker);
  const path = at === -1 ? url : url.slice(at + marker.length);
  const segments = path.split("/").filter((s) => s.length > 0 && s !== "self");
  return segments[segments.length - 1] ?? path;
}

export function findAssertionByUri(manifest: Manifest, url: string): Assertion | undefined {
  const label = assertionLabelFromUri(url);
  return (
    manifest.assertions.find((a) => a.label === label) ??
    manifest.assertions.find((a) => url.endsWith(a.label)) ??
    manifest.assertions.find((a) => url.includes(a.label))
  );
}

export function findAssertion(manifest: Manifest, label: string): Assertion | undefined {
  return manifest.assertions.find((a) => a.label === label);
}

export function wellKnownAssertions(manifest: Manifest): Map<string, Assertion> {
  const map = new Map<string, Assertion>();
  for (const assertion of manifest.assertions) map.set(assertion.label, assertion);
  return map;
}

export function manifestStoreLabel(store: ManifestStore): string {
  return store.box.label;
}

export function describeStore(boxes: readonly JumbfBox[]): string[] {
  return walk(boxes).map((b) => `${b.type}${b.label ? ` ${b.label}` : ""}${b.uuid ? ` [${b.uuid}]` : ""}`);
}

export function claimTitle(claim: Claim): string {
  return claim.title ?? claim.claimGeneratorName ?? claim.claimGenerator ?? "untitled";
}

export function signatureAlgorithmLabel(manifest: Manifest): string {
  const alg = manifest.signature.alg;
  return alg === undefined ? "unknown" : toHex(new Uint8Array([alg & 0xff]));
}

export function claimAssertionLabels(claim: Claim): string[] {
  return claim.assertions.map((a) => assertionLabelFromUri(a.url));
}

export function findClaimBox(boxes: readonly JumbfBox[]): JumbfBox | undefined {
  return findBoxes(boxes, "c2pa.claim")[0];
}

export function claimMetadata(claim: Claim): Array<{ key: string; value: string }> {
  const out: Array<{ key: string; value: string }> = [];
  for (const [key, value] of claim.map) {
    if (typeof key === "string" && typeof value === "string") out.push({ key, value });
    else if (typeof key === "string" && typeof value === "number") out.push({ key, value: String(value) });
  }
  return out;
}

export function mapGetDeep(map: Map<CborValue, CborValue>, key: string): CborValue | undefined {
  return mapGetMap(map, key) ?? mapGet(map, key);
}
