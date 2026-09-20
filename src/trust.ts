import type { ChainLink } from "./verify.ts";
import { certificatesFromPem, parseCertificate } from "./x509.ts";
import { toHex } from "./bytes.ts";
import { subtleDigest } from "./crypto.ts";

export interface TrustEntry {
  certSha256?: string;
  subject?: string;
  issuer?: string;
}

export interface TrustList {
  source: string;
  entries: TrustEntry[];
}

export interface TrustEvaluation {
  status: "trusted" | "untrusted" | "unknown";
  anchor?: string;
  reason?: string;
}

export async function parseTrustList(text: string, source = "inline"): Promise<TrustList> {
  const trimmed = text.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    const parsed = JSON.parse(trimmed) as unknown;
    const entries: TrustEntry[] = [];
    const push = (value: unknown) => {
      if (!(value instanceof Object)) return;
      const record = value as Record<string, unknown>;
      const sha = firstString(record, ["cert_sha256", "certSha256", "sha256", "fingerprint"]);
      const subject = firstString(record, ["subject", "subject_dn"]);
      const issuer = firstString(record, ["issuer", "issuer_dn"]);
      if (sha || subject || issuer) {
        entries.push({
          certSha256: sha ? sha.replace(/:/g, "").toLowerCase() : undefined,
          subject,
          issuer,
        });
      }
    };
    if (Array.isArray(parsed)) for (const item of parsed) push(item);
    else {
      const record = parsed as Record<string, unknown>;
      for (const key of ["trusted_list", "trusted", "allowed", "entries", "certificates"]) {
        const value = record[key];
        if (Array.isArray(value)) for (const item of value) push(item);
      }
    }
    return { source, entries };
  }
  const entries: TrustEntry[] = [];
  for (const der of certificatesFromPem(text)) {
    const certificate = parseCertificate(der);
    entries.push({
      certSha256: toHex(await sha256(der)),
      subject: certificate.subjectDisplay,
      issuer: certificate.issuerDisplay,
    });
  }
  return { source, entries };
}

function firstString(record: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.length > 0) return value;
  }
  return undefined;
}

export function evaluateTrust(chain: readonly ChainLink[], list: TrustList | undefined): TrustEvaluation {
  if (!list || list.entries.length === 0) {
    return { status: "unknown", reason: "no trust list was supplied" };
  }
  for (const link of chain) {
    const normalized = link.fingerprint.replace(/:/g, "").toLowerCase();
    const match = list.entries.find(
      (entry) =>
        (entry.certSha256 && entry.certSha256 === normalized) ||
        (entry.subject && entry.subject === link.subject),
    );
    if (match) {
      return { status: "trusted", anchor: link.subject };
    }
  }
  return {
    status: "untrusted",
    reason: `${chain.length} certificate(s) in the chain are absent from the trust list (${list.source})`,
  };
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return subtleDigest(bytes);
}
