export type WebCryptoAlgorithm = Record<string, unknown>;

export interface JwkKey {
  kty: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
  ext?: boolean;
}

export async function subtleDigest(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as never));
}

export async function subtleVerify(
  algorithm: WebCryptoAlgorithm,
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  return crypto.subtle.verify(algorithm as never, key, signature as never, data as never);
}

export async function subtleImportSpki(spki: Uint8Array, algorithm: WebCryptoAlgorithm): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", spki as never, algorithm as never, false, ["verify"]);
}

export async function subtleImportJwk(jwk: JwkKey, algorithm: WebCryptoAlgorithm): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk as never, algorithm as never, false, ["verify"]);
}
