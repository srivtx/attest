import { toHex } from "./bytes.ts";
import { locateManifest, type ManifestLocation } from "./jumbf.ts";
import {
  findAssertionByUri,
  parseManifestStore,
  type Assertion,
  type Claim,
  type Manifest,
} from "./c2pa.ts";
import { COSE_ALGORITHMS, verifyCoseSign1 } from "./cose.ts";
import { verifyCertificateSignature, type Certificate } from "./x509.ts";
import { evaluateTrust, type TrustList } from "./trust.ts";
import { subtleDigest } from "./crypto.ts";

export type Severity = "error" | "warning" | "info";

export interface Issue {
  code: string;
  severity: Severity;
  message: string;
}

export interface AssertionResult {
  label: string;
  declared: boolean;
  present: boolean;
  hashMatched: boolean;
  softBinding: boolean;
}

export interface ChainLink {
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  isCa: boolean;
  fingerprint: string;
  signatureValid: boolean | null;
  expired: boolean;
  errors: string[];
}

export interface Ingredient {
  title?: string;
  relationship?: string;
  format?: string;
  instanceId?: string;
  hasThumbnail: boolean;
}

export interface ActionRecord {
  action?: string;
  softwareAgent?: string;
  when?: string;
  digitalSourceType?: string;
}

export interface ManifestVerification {
  label: string;
  title?: string;
  generator?: string;
  format?: string;
  instanceId?: string;
  claimAlgorithm: string;
  signature: { valid: boolean; algorithm?: string; error?: string };
  chain: ChainLink[];
  trust: { status: "trusted" | "untrusted" | "unknown"; anchor?: string; reason?: string };
  assertions: AssertionResult[];
  hardBinding: {
    status: "matched" | "mismatch" | "missing" | "unsupported";
    algorithm?: string;
    excludedBytes?: number;
    assertedHash?: string;
    computedHash?: string;
  };
  ingredients: Ingredient[];
  actions: ActionRecord[];
  remoteManifestUrl?: string;
  issues: Issue[];
  state: "valid" | "invalid" | "untrusted";
}

export interface AssetVerification {
  file: {
    size: number;
    container?: string;
    hash: string;
  };
  hasManifestStore: boolean;
  manifests: ManifestVerification[];
  activeManifest?: string;
  issues: Issue[];
  state: "valid" | "invalid" | "untrusted" | "unsigned";
}

export interface VerifyOptions {
  trustList?: TrustList;
  assertTrusted?: boolean;
  now?: Date;
}

export async function verifyBytes(bytes: Uint8Array, options: VerifyOptions = {}): Promise<AssetVerification> {
  const fileHash = toHex(await sha256(bytes));
  const location = locateManifest(bytes);
  if (!location) {
    return {
      file: { size: bytes.length, hash: fileHash },
      hasManifestStore: false,
      manifests: [],
      issues: [{ code: "manifest.missing", severity: "warning", message: "No C2PA manifest store was found in this file." }],
      state: "unsigned",
    };
  }
  const stores = (() => {
    try {
      return parseManifestStore(location.boxes);
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  })();
  if ("error" in stores) {
    return {
      file: { size: bytes.length, container: location.container, hash: fileHash },
      hasManifestStore: true,
      manifests: [],
      issues: [
        {
          code: "manifest.malformed",
          severity: "error",
          message: `The manifest store could not be parsed: ${stores.error}`,
        },
      ],
      state: "invalid",
    };
  }
  const manifests: ManifestVerification[] = [];
  for (const store of stores) {
    for (const manifest of store.manifests) {
      try {
        manifests.push(await verifyManifest(manifest, bytes, location, options));
      } catch (error) {
        manifests.push(malformedManifest(manifest.label, error));
      }
    }
  }
  const issues: Issue[] = [];
  for (const manifest of manifests) issues.push(...manifest.issues);
  const state = aggregateState(manifests);
  const activeManifest = manifests.length > 0 ? manifests[manifests.length - 1]!.label : undefined;
  return {
    file: { size: bytes.length, container: location.container, hash: fileHash },
    hasManifestStore: true,
    manifests,
    activeManifest,
    issues,
    state,
  };
}

function malformedManifest(label: string, error: unknown): ManifestVerification {
  const message = error instanceof Error ? error.message : String(error);
  return {
    label,
    claimAlgorithm: "unknown",
    signature: { valid: false, error: message },
    chain: [],
    trust: { status: "unknown", reason: "the manifest could not be parsed" },
    assertions: [],
    hardBinding: { status: "missing" },
    ingredients: [],
    actions: [],
    issues: [
      {
        code: "manifest.malformed",
        severity: "error",
        message: `Manifest ${label} is malformed: ${message}`,
      },
    ],
    state: "invalid",
  };
}

function aggregateState(manifests: readonly ManifestVerification[]): AssetVerification["state"] {
  if (manifests.length === 0) return "unsigned";
  if (manifests.some((m) => m.state === "invalid")) return "invalid";
  if (manifests.every((m) => m.state === "valid")) return "valid";
  return "untrusted";
}

async function verifyManifest(
  manifest: Manifest,
  bytes: Uint8Array,
  location: ManifestLocation,
  options: VerifyOptions,
): Promise<ManifestVerification> {
  const issues: Issue[] = [];
  const now = options.now ?? new Date();

  const signatureResult = manifest.certificates[0]
    ? await verifyCoseSign1(manifest.signature, manifest.certificates[0], manifest.claim.raw)
    : { valid: false, error: "the signature carries no signing certificate" };
  if (manifest.certificates.length === 0) {
    issues.push({ code: "signingCredential.missing", severity: "error", message: "The COSE signature has no x5chain certificate." });
  } else if (signatureResult.valid) {
    issues.push({ code: "claimSignature.validated", severity: "info", message: `Claim signature validated (${signatureResult.algorithm}).` });
  } else {
    issues.push({ code: "claimSignature.mismatch", severity: "error", message: `Claim signature did not validate: ${signatureResult.error ?? "unknown error"}` });
  }

  const chain = await verifyChain(manifest.certificates, now, issues);
  const trust = evaluateTrust(chain, options.trustList);
  if (trust.status === "untrusted") {
    issues.push({
      code: "signingCredential.untrusted",
      severity: "warning",
      message: trust.reason ?? "The signing certificate is not on the trust list.",
    });
  } else if (trust.status === "trusted") {
    issues.push({ code: "signingCredential.trusted", severity: "info", message: `Signer is trusted: ${trust.anchor}.` });
  }

  const assertions = await verifyAssertions(manifest, bytes, location, issues);
  const hardBinding = await verifyHardBinding(manifest, bytes, location, issues);
  const ingredients = extractIngredients(manifest);
  const actions = extractActions(manifest);
  const remoteManifestUrl = extractRemoteManifest(manifest);

  const hasError = issues.some((i) => i.severity === "error");
  let state: ManifestVerification["state"] = hasError ? "invalid" : "valid";
  if (!hasError && trust.status === "untrusted" && options.assertTrusted) state = "untrusted";

  return {
    label: manifest.label,
    title: manifest.claim.title,
    generator: manifest.claim.claimGeneratorName ?? manifest.claim.claimGenerator,
    format: manifest.claim.format,
    instanceId: manifest.claim.instanceId,
    claimAlgorithm: manifest.claim.alg,
    signature: signatureResult,
    chain,
    trust,
    assertions,
    hardBinding,
    ingredients,
    actions,
    remoteManifestUrl,
    issues,
    state,
  };
}

async function verifyChain(certificates: readonly Certificate[], now: Date, issues: Issue[]): Promise<ChainLink[]> {
  const links: ChainLink[] = [];
  for (let i = 0; i < certificates.length; i++) {
    const certificate = certificates[i]!;
    const errors: string[] = [];
    const expired = now < certificate.notBefore || now > certificate.notAfter;
    if (expired) errors.push(now < certificate.notBefore ? "not yet valid" : "expired");
    let signatureValid: boolean | null = null;
    const issuer = certificates[i + 1];
    if (issuer) {
      try {
        signatureValid = await verifyCertificateSignature(certificate, issuer);
        if (!signatureValid) errors.push("issuer signature did not validate");
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error));
      }
    } else {
      const selfSigned = await verifyCertificateSignature(certificate, certificate).catch(() => false);
      signatureValid = selfSigned ? true : null;
      if (!selfSigned) {
        issues.push({
          code: "signingCredential.intermediate",
          severity: "info",
          message: `The chain does not carry the issuer of ${certificate.subjectDisplay}; trust has to come from a trust list.`,
        });
      }
    }
    const fingerprint = toHex(await sha256(certificate.raw));
    links.push({
      subject: certificate.subjectDisplay,
      issuer: certificate.issuerDisplay,
      notBefore: certificate.notBefore.toISOString(),
      notAfter: certificate.notAfter.toISOString(),
      isCa: certificate.isCa,
      fingerprint,
      signatureValid,
      expired,
      errors,
    });
    if (expired) {
      issues.push({ code: "signingCredential.expired", severity: "warning", message: `Certificate ${certificate.subjectDisplay} is outside its validity window.` });
    }
    if (signatureValid === false) {
      issues.push({ code: "signingCredential.invalid", severity: "error", message: `Certificate chain link for ${certificate.subjectDisplay} did not validate.` });
    }
  }
  return links;
}

async function verifyAssertions(
  manifest: Manifest,
  bytes: Uint8Array,
  location: ManifestLocation,
  issues: Issue[],
): Promise<AssertionResult[]> {
  const results: AssertionResult[] = [];
  const claimed = new Map<string, Assertion>();
  for (const hashed of manifest.claim.assertions) {
    const assertion = findAssertionByUri(manifest, hashed.url);
    const label = assertion?.label ?? hashed.url;
    if (!assertion) {
      results.push({ label, declared: true, present: false, hashMatched: false, softBinding: false });
      issues.push({ code: "assertion.missing", severity: "error", message: `The claim declares ${label} but it is not present in the manifest.` });
      continue;
    }
    claimed.set(assertion.label, assertion);
    const computed = await sha256(assertion.box.payload);
    const matched = toHex(computed) === toHex(hashed.hash);
    results.push({ label: assertion.label, declared: true, present: true, hashMatched: matched, softBinding: false });
    if (!matched) {
      issues.push({ code: "assertion.hashedURI.mismatch", severity: "error", message: `Hash mismatch for assertion ${assertion.label}.` });
    }
  }
  for (const assertion of manifest.assertions) {
    if (claimed.has(assertion.label)) continue;
    if (assertion.label.startsWith("c2pa.thumbnail")) continue;
    if (assertion.label.startsWith("c2pa.ingredients")) {
      results.push({ label: assertion.label, declared: false, present: true, hashMatched: true, softBinding: false });
      continue;
    }
    results.push({ label: assertion.label, declared: false, present: true, hashMatched: true, softBinding: false });
    issues.push({ code: "assertion.undeclared", severity: "warning", message: `Assertion ${assertion.label} is present but not declared in the claim.` });
  }
  return results;
}

async function verifyHardBinding(
  manifest: Manifest,
  bytes: Uint8Array,
  location: ManifestLocation,
  issues: Issue[],
): Promise<ManifestVerification["hardBinding"]> {
  const dataAssertion = manifest.assertions.find((a) => a.label === "c2pa.hash.data");
  if (dataAssertion) {
    const value = dataAssertion.value;
    if (!(value instanceof Map)) {
      issues.push({ code: "hardBinding.invalid", severity: "error", message: "The c2pa.hash.data assertion did not decode." });
      return { status: "unsupported" };
    }
    const algorithm = String(value.get("alg") ?? "sha256");
    const asserted = value.get("hash");
    if (!(asserted instanceof Uint8Array)) {
      issues.push({ code: "hardBinding.invalid", severity: "error", message: "The c2pa.hash.data assertion has no hash." });
      return { status: "unsupported" };
    }
    const ranges = readExclusions(value.get("exclusions"), location);
    const computed = await hashWithExclusions(bytes, ranges);
    const matched = toHex(computed) === toHex(asserted);
    if (matched) {
      issues.push({ code: "hardBinding.matched", severity: "info", message: `Asset bytes match the hard binding (${algorithm}).` });
    } else {
      issues.push({ code: "hardBinding.mismatch", severity: "error", message: "Asset bytes do not match the c2pa.hash.data hard binding." });
    }
    const excludedBytes = ranges.reduce((sum, r) => sum + r.length, 0);
    return {
      status: matched ? "matched" : "mismatch",
      algorithm,
      excludedBytes,
      assertedHash: toHex(asserted),
      computedHash: toHex(computed),
    };
  }
  const boxAssertion = manifest.assertions.find((a) => a.label === "c2pa.hash.boxes");
  if (boxAssertion) {
    issues.push({ code: "hardBinding.unsupported", severity: "warning", message: "c2pa.hash.boxes bindings are not evaluated by this build." });
    return { status: "unsupported" };
  }
  issues.push({ code: "hardBinding.missing", severity: "error", message: "The manifest has no hard binding assertion." });
  return { status: "missing" };
}

interface Range {
  start: number;
  length: number;
}

function readExclusions(value: unknown, location: ManifestLocation): Range[] {
  if (Array.isArray(value)) {
    const ranges: Range[] = [];
    for (const item of value) {
      if (item instanceof Map) {
        const start = item.get("start");
        const length = item.get("length");
        if (typeof start === "number" && typeof length === "number") ranges.push({ start, length });
      }
    }
    if (ranges.length > 0) return ranges;
  }
  return location.ranges.map((r) => ({ start: r.start, length: r.length }));
}

export async function hashWithExclusions(bytes: Uint8Array, ranges: readonly Range[]): Promise<Uint8Array> {
  const sorted = [...ranges].filter((r) => r.length > 0).sort((a, b) => a.start - b.start);
  const hash = new HashBuilder();
  let cursor = 0;
  for (const range of sorted) {
    const start = Math.max(0, Math.min(range.start, bytes.length));
    const end = Math.max(start, Math.min(range.start + range.length, bytes.length));
    if (start > cursor) hash.update(bytes.subarray(cursor, start));
    cursor = Math.max(cursor, end);
  }
  if (cursor < bytes.length) hash.update(bytes.subarray(cursor));
  return hash.digest();
}

class HashBuilder {
  private parts: Uint8Array[] = [];

  update(part: Uint8Array): void {
    this.parts.push(part);
  }

  async digest(): Promise<Uint8Array> {
    let total = 0;
    for (const part of this.parts) total += part.length;
    const buffer = new Uint8Array(total);
    let at = 0;
    for (const part of this.parts) {
      buffer.set(part, at);
      at += part.length;
    }
    return sha256(buffer);
  }
}

function extractIngredients(manifest: Manifest): Ingredient[] {
  const out: Ingredient[] = [];
  for (const assertion of manifest.assertions) {
    if (!assertion.label.includes("ingredients")) continue;
    const value = assertion.value;
    const list = Array.isArray(value) ? value : value instanceof Map && Array.isArray(value.get("ingredients")) ? (value.get("ingredients") as unknown[]) : [];
    for (const item of list) {
      if (!(item instanceof Map)) continue;
      out.push({
        title: stringField(item, "dc:title") ?? stringField(item, "title"),
        relationship: stringField(item, "relationship"),
        format: stringField(item, "dc:format"),
        instanceId: stringField(item, "instanceID"),
        hasThumbnail: item.has("thumbnail") || item.has("c2pa.thumbnail"),
      });
    }
  }
  return out;
}

function extractActions(manifest: Manifest): ActionRecord[] {
  const out: ActionRecord[] = [];
  for (const assertion of manifest.assertions) {
    if (assertion.label !== "c2pa.actions" && !assertion.label.startsWith("c2pa.actions")) continue;
    const value = assertion.value;
    const list = Array.isArray(value) ? value : value instanceof Map && Array.isArray(value.get("actions")) ? (value.get("actions") as unknown[]) : [];
    for (const item of list) {
      if (!(item instanceof Map)) continue;
      const when = item.get("when");
      out.push({
        action: stringField(item, "action"),
        softwareAgent: stringField(item, "softwareAgent") ?? agentName(item.get("softwareAgent")),
        when: typeof when === "string" ? when : typeof when === "number" ? new Date(when * 1000).toISOString() : undefined,
        digitalSourceType: stringField(item, "digitalSourceType"),
      });
    }
  }
  return out;
}

function agentName(value: unknown): string | undefined {
  if (value instanceof Map) return stringField(value, "name");
  return undefined;
}

function stringField(map: Map<unknown, unknown>, key: string): string | undefined {
  const value = map.get(key);
  return typeof value === "string" ? value : undefined;
}

function extractRemoteManifest(manifest: Manifest): string | undefined {
  const value = manifest.claim.map.get("remote_manifest");
  return typeof value === "string" ? value : undefined;
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return subtleDigest(bytes);
}

export function algorithmLabel(alg: number | undefined): string | undefined {
  if (alg === undefined) return undefined;
  return COSE_ALGORITHMS[alg]?.label;
}

export function claimSummary(claim: Claim): string {
  return claim.title ?? claim.claimGeneratorName ?? claim.claimGenerator ?? claim.instanceId ?? "manifest";
}
