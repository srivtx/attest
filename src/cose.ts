import { decodeCbor, encodeCbor, mapGetBytes, mapGetNumber, type CborValue } from "./cbor.ts";
import { concat } from "./bytes.ts";
import { algorithmForCurve, curveCoordinateBytes, importPublicKey, type Certificate, type SignatureAlgorithm } from "./x509.ts";
import { subtleVerify } from "./crypto.ts";

export interface CoseSign1 {
  protectedBytes: Uint8Array;
  protectedHeader: Map<CborValue, CborValue>;
  unprotectedHeader: Map<CborValue, CborValue>;
  payload: Uint8Array | null;
  signature: Uint8Array;
  x5chain: Uint8Array[];
  alg?: number;
  contentType?: string;
}

export const COSE_HEADER = {
  alg: 1,
  crit: 2,
  contentType: 3,
  kid: 4,
  iv: 5,
  x5chain: 33,
  x5bag: 32,
  x5u: 34,
} as const;

export const COSE_ALGORITHMS: Record<number, SignatureAlgorithm & { label: string }> = {
  [-7]: { name: "ECDSA", hash: "SHA-256", signatureFormat: "raw", label: "ES256" },
  [-35]: { name: "ECDSA", hash: "SHA-384", signatureFormat: "raw", label: "ES384" },
  [-36]: { name: "ECDSA", hash: "SHA-512", signatureFormat: "raw", label: "ES512" },
  [-37]: { name: "RSA-PSS", hash: "SHA-256", signatureFormat: "raw", label: "PS256" },
  [-38]: { name: "RSA-PSS", hash: "SHA-384", signatureFormat: "raw", label: "PS384" },
  [-39]: { name: "RSA-PSS", hash: "SHA-512", signatureFormat: "raw", label: "PS512" },
  [-257]: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", signatureFormat: "raw", label: "RS256" },
  [-8]: { name: "Ed25519", signatureFormat: "raw", label: "EdDSA" },
};

export function parseCoseSign1(bytes: Uint8Array): CoseSign1 {
  const outer = decodeCbor(bytes);
  if (!Array.isArray(outer)) throw new Error("COSE_Sign1 is not an array");
  const tagged =
    outer.length === 4 ? outer : Array.isArray(outer[0]) ? (outer[0] as CborValue[]) : outer;
  if (!Array.isArray(tagged) || tagged.length !== 4) throw new Error("COSE_Sign1 must have four elements");
  const [protectedItem, unprotectedItem, payloadItem, signatureItem] = tagged;
  if (!(protectedItem instanceof Uint8Array)) throw new Error("COSE protected header must be a byte string");
  if (!(signatureItem instanceof Uint8Array)) throw new Error("COSE signature must be a byte string");
  if (payloadItem !== null && !(payloadItem instanceof Uint8Array)) {
    throw new Error("COSE payload must be a byte string or null");
  }
  let protectedHeader = new Map<CborValue, CborValue>();
  if (protectedItem.length > 0) {
    const decoded = decodeCbor(protectedItem);
    if (!(decoded instanceof Map)) throw new Error("COSE protected header must be a map");
    protectedHeader = decoded;
  }
  let unprotectedHeader = new Map<CborValue, CborValue>();
  if (unprotectedItem instanceof Map) unprotectedHeader = unprotectedItem;

  const chain = mapGetBytes(unprotectedHeader, COSE_HEADER.x5chain) ?? mapGetBytes(protectedHeader, COSE_HEADER.x5chain);
  const x5chain: Uint8Array[] = [];
  if (chain) x5chain.push(chain);
  for (const source of [unprotectedHeader, protectedHeader]) {
    const list = source.get(COSE_HEADER.x5chain);
    if (Array.isArray(list)) {
      for (const item of list) if (item instanceof Uint8Array) x5chain.push(item);
    }
  }
  const contentType = mapGetStringLike(protectedHeader, COSE_HEADER.contentType) ?? mapGetStringLike(unprotectedHeader, COSE_HEADER.contentType);

  return {
    protectedBytes: protectedItem,
    protectedHeader,
    unprotectedHeader,
    payload: payloadItem instanceof Uint8Array ? payloadItem : null,
    signature: signatureItem,
    x5chain,
    alg: mapGetNumber(protectedHeader, COSE_HEADER.alg) ?? mapGetNumber(unprotectedHeader, COSE_HEADER.alg),
    contentType,
  };
}

function mapGetStringLike(map: Map<CborValue, CborValue>, key: number): string | undefined {
  const value = map.get(key) ?? map.get(BigInt(key) as unknown as CborValue);
  return typeof value === "string" ? value : undefined;
}

export function coseSigStructure(protectedBytes: Uint8Array, payload: Uint8Array): Uint8Array {
  return encodeCbor(["Signature1", protectedBytes, new Uint8Array(0), payload]);
}

export interface CoseVerifyResult {
  valid: boolean;
  algorithm?: string;
  error?: string;
}

export async function verifyCoseSign1(
  sign1: CoseSign1,
  certificate: Certificate,
  externalPayload?: Uint8Array,
): Promise<CoseVerifyResult> {
  if (sign1.alg === undefined) return { valid: false, error: "COSE header is missing the alg parameter" };
  const algorithm = COSE_ALGORITHMS[sign1.alg];
  if (!algorithm) return { valid: false, error: `unsupported COSE algorithm: ${sign1.alg}` };
  const payload = sign1.payload ?? externalPayload;
  if (!payload) return { valid: false, error: "COSE_Sign1 has no payload and none was supplied" };
  const curve = algorithm.name === "ECDSA" ? algorithmForCurve(certificate.namedCurveOid) : undefined;
  if (algorithm.name === "ECDSA" && !curve) {
    return { valid: false, error: "ECDSA certificate does not use a supported curve" };
  }
  try {
    const key = await importPublicKey(certificate, algorithm.name === "ECDSA" ? { ...algorithm, namedCurve: curve } : algorithm);
    const data = coseSigStructure(sign1.protectedBytes, payload);
    const params =
      algorithm.name === "ECDSA"
        ? { name: "ECDSA", hash: algorithm.hash ?? "SHA-256" }
        : algorithm.name === "Ed25519"
          ? { name: "Ed25519" }
          : algorithm.name === "RSA-PSS"
            ? { name: "RSA-PSS", saltLength: hashLength(algorithm.hash ?? "SHA-256") }
            : { name: "RSASSA-PKCS1-v1_5" };
    const valid = await subtleVerify(params as unknown as Record<string, unknown>, key, sign1.signature, data);
    return { valid, algorithm: algorithm.label };
  } catch (error) {
    return { valid: false, algorithm: algorithm.label, error: error instanceof Error ? error.message : String(error) };
  }
}

function hashLength(hash: string): number {
  return hash === "SHA-256" ? 32 : hash === "SHA-384" ? 48 : hash === "SHA-512" ? 64 : 32;
}

export function coseAlgorithmLabel(alg: number | undefined): string {
  if (alg === undefined) return "unknown";
  return COSE_ALGORITHMS[alg]?.label ?? `alg(${alg})`;
}

export function cosSign1Bytes(sign1: CoseSign1): Uint8Array {
  return concat([
    encodeCbor([sign1.protectedBytes, sign1.unprotectedHeader, sign1.payload, sign1.signature]),
  ]);
}
