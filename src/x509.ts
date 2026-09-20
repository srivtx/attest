import { Reader, toHex } from "./bytes.ts";
import { DER_CLASS, DER_TAG, derBitString, derInteger, derOid, derString, derTime, readDerNode, type DerNode } from "./der.ts";
import { subtleDigest, subtleImportJwk, subtleImportSpki, subtleVerify, type JwkKey } from "./crypto.ts";

export interface RdnAttribute {
  oid: string;
  value: string;
}

export interface Certificate {
  raw: Uint8Array;
  tbsCertificate: Uint8Array;
  version: number;
  serialNumber: string;
  signatureAlgorithmOid: string;
  signatureAlgorithmName: string;
  issuer: RdnAttribute[];
  issuerDisplay: string;
  subject: RdnAttribute[];
  subjectDisplay: string;
  notBefore: Date;
  notAfter: Date;
  signatureValue: Uint8Array;
  spki: Uint8Array;
  publicKeyAlgorithmOid: string;
  namedCurveOid?: string;
  keyUsage?: number;
  isCa: boolean;
  pathLenConstraint?: number;
  subjectKeyIdentifier?: string;
  authorityKeyIdentifier?: string;
  extendedKeyUsage: string[];
  subjectAltNames: string[];
  fingerprintSha256?: string;
}

const CURVE_BY_OID: Record<string, string> = {
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
};

export function parseCertificate(der: Uint8Array): Certificate {
  const root = readDerNode(der, 0);
  if (root.tag !== DER_TAG.Sequence) throw new Error("certificate is not a SEQUENCE");
  const parts = root.children();
  if (parts.length < 3) throw new Error("certificate is missing fields");
  const tbs = parts[0]!;
  const sigAlg = parts[1]!;
  const sigValue = parts[2]!;

  const sigAlgParts = sigAlg.children();
  const signatureAlgorithmOid = derOid(sigAlgParts[0]!);
  const signatureValue = derBitString(sigValue).bytes;

  const fields = tbs.children();
  let index = 0;
  let version = 1;
  if (fields[index]!.cls === DER_CLASS.Context && fields[index]!.tag === 0) {
    const inner = fields[index]!.children()[0];
    version = Number(derInteger(inner!)) + 1;
    index += 1;
  }
  const serialNumber = "0x" + derInteger(fields[index]!).toString(16);
  index += 1;
  index += 1; // tbs signature algorithm, duplicated by sigAlg
  const issuer = parseName(fields[index]!);
  index += 1;
  const validity = fields[index]!.children();
  const notBefore = derTime(validity[0]!);
  const notAfter = derTime(validity[1]!);
  index += 1;
  const subject = parseName(fields[index]!);
  index += 1;
  const spki = fields[index]!;
  index += 1;

  const spkiChildren = spki.children();
  const publicKeyAlgorithmOid = derOid(spkiChildren[0]!.children()[0]!);
  let namedCurveOid: string | undefined;
  const algParams = spkiChildren[0]!.children()[1];
  if (algParams && algParams.cls === DER_CLASS.Universal && algParams.tag === DER_TAG.OID) {
    namedCurveOid = derOid(algParams);
  }

  const extensions = new Map<string, Uint8Array>();
  for (; index < fields.length; index++) {
    const field = fields[index]!;
    if (field.cls !== DER_CLASS.Context || field.tag !== 3) continue;
    const list = field.children()[0];
    if (!list) continue;
    for (const ext of list.children()) {
      const extFields = ext.children();
      const oid = derOid(extFields[0]!);
      const valueNode = extFields[extFields.length - 1]!;
      extensions.set(oid, valueNode.content);
    }
  }

  const cert: Certificate = {
    raw: der,
    tbsCertificate: der.subarray(tbs.start, tbs.end),
    version,
    serialNumber,
    signatureAlgorithmOid,
    signatureAlgorithmName: sigAlgName(signatureAlgorithmOid),
    issuer,
    issuerDisplay: displayName(issuer),
    subject,
    subjectDisplay: displayName(subject),
    notBefore,
    notAfter,
    signatureValue,
    spki: der.subarray(spki.start, spki.end),
    publicKeyAlgorithmOid,
    namedCurveOid,
    isCa: false,
    extendedKeyUsage: [],
    subjectAltNames: [],
  };

  const basicConstraints = extensions.get("2.5.29.19");
  if (basicConstraints) {
    const inner = readDerNode(basicConstraints, 0);
    for (const child of inner.children()) {
      if (child.tag === DER_TAG.Boolean) cert.isCa = child.content[0] !== 0;
      if (child.tag === DER_TAG.Integer) cert.pathLenConstraint = Number(derInteger(child));
    }
  }

  const keyUsage = extensions.get("2.5.29.15");
  if (keyUsage) {
    const node = readDerNode(keyUsage, 0);
    const bits = derBitString(node).bytes;
    let mask = 0;
    for (let i = 0; i < bits.length; i++) mask = (mask << 8) | bits[i]!;
    const totalBits = bits.length * 8 - derBitString(node).unusedBits;
    cert.keyUsage = totalBits < 16 ? mask >> (16 - totalBits) : mask;
  }

  const ski = extensions.get("2.5.29.14");
  if (ski) {
    const inner = readDerNode(ski, 0);
    cert.subjectKeyIdentifier = toHex(inner.content);
  }

  const aki = extensions.get("2.5.29.35");
  if (aki) {
    const inner = readDerNode(aki, 0);
    for (const child of inner.children()) {
      if (child.cls === DER_CLASS.Context && child.tag === 0) cert.authorityKeyIdentifier = toHex(child.content);
    }
  }

  const eku = extensions.get("2.5.29.37");
  if (eku) {
    const inner = readDerNode(eku, 0);
    for (const child of inner.children()) cert.extendedKeyUsage.push(derOid(child));
  }

  const san = extensions.get("2.5.29.17");
  if (san) {
    const inner = readDerNode(san, 0);
    for (const child of inner.children()) {
      if (child.cls === DER_CLASS.Context && (child.tag === 2 || child.tag === 1)) {
        let out = "";
        for (let i = 0; i < child.content.length; i++) out += String.fromCharCode(child.content[i]!);
        cert.subjectAltNames.push(out);
      }
    }
  }

  return cert;
}

export function parseName(node: DerNode): RdnAttribute[] {
  const out: RdnAttribute[] = [];
  for (const set of node.children()) {
    for (const atv of set.children()) {
      const parts = atv.children();
      if (parts.length < 2) continue;
      out.push({ oid: derOid(parts[0]!), value: derString(parts[1]!) });
    }
  }
  return out;
}

export function displayName(attributes: readonly RdnAttribute[]): string {
  if (attributes.length === 0) return "(empty)";
  return attributes.map((a) => `${attributeLabel(a.oid)}=${a.value}`).join(", ");
}

function attributeLabel(oid: string): string {
  switch (oid) {
    case "2.5.4.3":
      return "CN";
    case "2.5.4.6":
      return "C";
    case "2.5.4.7":
      return "L";
    case "2.5.4.8":
      return "ST";
    case "2.5.4.10":
      return "O";
    case "2.5.4.11":
      return "OU";
    case "1.2.840.113549.1.9.1":
      return "E";
    default:
      return oid;
  }
}

function sigAlgName(oid: string): string {
  switch (oid) {
    case "1.2.840.113549.1.1.5":
      return "RSA-SHA1";
    case "1.2.840.113549.1.1.11":
      return "RSA-SHA256";
    case "1.2.840.113549.1.1.12":
      return "RSA-SHA384";
    case "1.2.840.113549.1.1.13":
      return "RSA-SHA512";
    case "1.2.840.113549.1.1.10":
      return "RSA-PSS";
    case "1.2.840.10045.4.3.2":
      return "ECDSA-SHA256";
    case "1.2.840.10045.4.3.3":
      return "ECDSA-SHA384";
    case "1.2.840.10045.4.3.4":
      return "ECDSA-SHA512";
    case "1.3.101.112":
      return "Ed25519";
    default:
      return oid;
  }
}

export function algorithmForCurve(namedCurveOid: string | undefined): string | undefined {
  if (!namedCurveOid) return undefined;
  return CURVE_BY_OID[namedCurveOid];
}

export interface SignatureAlgorithm {
  name: "ECDSA" | "RSA-PSS" | "RSASSA-PKCS1-v1_5" | "Ed25519";
  hash?: "SHA-256" | "SHA-384" | "SHA-512";
  namedCurve?: string;
  signatureFormat: "raw" | "der";
}

export function algorithmFromOid(oid: string, namedCurveOid?: string): SignatureAlgorithm {
  switch (oid) {
    case "1.2.840.10045.4.3.2":
      return { name: "ECDSA", hash: "SHA-256", namedCurve: algorithmForCurve(namedCurveOid), signatureFormat: "der" };
    case "1.2.840.10045.4.3.3":
      return { name: "ECDSA", hash: "SHA-384", namedCurve: algorithmForCurve(namedCurveOid), signatureFormat: "der" };
    case "1.2.840.10045.4.3.4":
      return { name: "ECDSA", hash: "SHA-512", namedCurve: algorithmForCurve(namedCurveOid), signatureFormat: "der" };
    case "1.2.840.113549.1.1.11":
      return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", signatureFormat: "raw" };
    case "1.2.840.113549.1.1.12":
      return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384", signatureFormat: "raw" };
    case "1.2.840.113549.1.1.13":
      return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512", signatureFormat: "raw" };
    case "1.2.840.113549.1.1.10":
      return { name: "RSA-PSS", hash: "SHA-256", signatureFormat: "raw" };
    case "1.3.101.112":
      return { name: "Ed25519", signatureFormat: "raw" };
    default:
      throw new Error(`unsupported signature algorithm OID: ${oid}`);
  }
}

export async function importPublicKey(cert: Certificate, algorithm: SignatureAlgorithm): Promise<CryptoKey> {
  if (algorithm.name === "ECDSA") {
    const namedCurve = algorithm.namedCurve ?? algorithmForCurve(cert.namedCurveOid);
    if (!namedCurve) throw new Error("ECDSA certificate is missing a supported named curve");
    return subtleImportSpki(cert.spki, { name: "ECDSA", namedCurve });
  }
  if (algorithm.name === "Ed25519") {
    return subtleImportSpki(cert.spki, { name: "Ed25519" });
  }
  const hash = algorithm.hash ?? "SHA-256";
  const params = algorithm.name === "RSA-PSS" ? { name: "RSA-PSS", hash } : { name: "RSASSA-PKCS1-v1_5", hash };
  try {
    return await subtleImportSpki(cert.spki, params as unknown as Record<string, unknown>);
  } catch (error) {
    const jwk = rsaPublicKeyJwk(cert.spki);
    if (!jwk) throw error;
    return subtleImportJwk(jwk, params as unknown as Record<string, unknown>);
  }
}

export function rsaPublicKeyJwk(spki: Uint8Array): JwkKey | undefined {
  try {
    const root = readDerNode(spki, 0);
    const parts = root.children();
    const bitStringNode = parts[parts.length - 1];
    if (!bitStringNode) return undefined;
    const keyBytes = derBitString(bitStringNode).bytes;
    const rsaKey = readDerNode(keyBytes, 0).children();
    const modulus = rsaKey[0]?.content;
    const exponent = rsaKey[1]?.content;
    if (!modulus || !exponent) return undefined;
    return { kty: "RSA", n: base64Url(modulus), e: base64Url(exponent), ext: true };
  } catch {
    return undefined;
  }
}

function base64Url(bytes: Uint8Array): string {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
  const slice = bytes.subarray(start);
  let binary = "";
  for (let i = 0; i < slice.length; i++) binary += String.fromCharCode(slice[i]!);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function derEcdsaToRaw(derSignature: Uint8Array, coordinateBytes: number): Uint8Array {
  const root = readDerNode(derSignature, 0);
  if (root.tag !== DER_TAG.Sequence) throw new Error("ECDSA signature is not a SEQUENCE");
  const [rNode, sNode] = root.children();
  if (!rNode || !sNode) throw new Error("ECDSA signature is missing r or s");
  const out = new Uint8Array(coordinateBytes * 2);
  writeFixed(rNode.content, out, 0, coordinateBytes);
  writeFixed(sNode.content, out, coordinateBytes, coordinateBytes);
  return out;
}

function writeFixed(value: Uint8Array, target: Uint8Array, offset: number, size: number): void {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start += 1;
  const slice = value.subarray(start);
  if (slice.length > size) throw new Error(`integer does not fit in ${size} bytes`);
  target.set(slice, offset + size - slice.length);
}

const CURVE_COORDINATES: Record<string, number> = { "P-256": 32, "P-384": 48, "P-521": 66 };

export function curveCoordinateBytes(namedCurve: string): number {
  const size = CURVE_COORDINATES[namedCurve];
  if (!size) throw new Error(`unknown curve: ${namedCurve}`);
  return size;
}

export async function verifyCertificateSignature(child: Certificate, issuer: Certificate): Promise<boolean> {
  const algorithm = algorithmFromOid(issuer.signatureAlgorithmOid, issuer.namedCurveOid);
  const key = await importPublicKey(issuer, algorithm);
  let signature = child.signatureValue;
  if (algorithm.name === "ECDSA") {
    const curve = algorithm.namedCurve ?? "P-256";
    signature = derEcdsaToRaw(signature, curveCoordinateBytes(curve));
  }
  const params =
    algorithm.name === "ECDSA"
      ? { name: "ECDSA", hash: algorithm.hash ?? "SHA-256" }
      : algorithm.name === "Ed25519"
        ? { name: "Ed25519" }
        : algorithm.name === "RSA-PSS"
          ? { name: "RSA-PSS", saltLength: hashBytes(algorithm.hash ?? "SHA-256") }
          : { name: "RSASSA-PKCS1-v1_5" };
  return subtleVerify(params as unknown as Record<string, unknown>, key, signature, child.tbsCertificate);
}

export function hashBytes(hash: "SHA-256" | "SHA-384" | "SHA-512"): number {
  return hash === "SHA-256" ? 32 : hash === "SHA-384" ? 48 : 64;
}

export function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s+/g, "");
  const binary = atob(body);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function certificatesFromPem(pem: string): Uint8Array[] {
  const out: Uint8Array[] = [];
  const pattern = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(pem)) !== null) out.push(pemToDer(match[0]!));
  return out;
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return subtleDigest(bytes);
}

export function readerOf(bytes: Uint8Array): Reader {
  return new Reader(bytes);
}
