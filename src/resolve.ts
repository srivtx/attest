import { toHex } from "./bytes.ts";
import { manifestToCard } from "./report.ts";
import type { AssetVerification } from "./verify.ts";
import { sha256 } from "./verify.ts";

export const CARD_VERSION = "attest/card/1";

export interface ProvenanceCard {
  version: typeof CARD_VERSION;
  asset: { sha256: string; size: number; container?: string };
  state: AssetVerification["state"];
  manifests: Record<string, unknown>[];
  issuedAt: string;
}

export function toCard(asset: AssetVerification, issuedAt = new Date()): ProvenanceCard {
  return {
    version: CARD_VERSION,
    asset: { sha256: asset.file.hash, size: asset.file.size, container: asset.file.container },
    state: asset.state,
    manifests: asset.manifests.map(manifestToCard),
    issuedAt: issuedAt.toISOString(),
  };
}

export async function cardId(card: ProvenanceCard): Promise<string> {
  const canonical = JSON.stringify({
    version: card.version,
    asset: card.asset,
    state: card.state,
    manifests: card.manifests,
  });
  return toHex(await sha256(new TextEncoder().encode(canonical)));
}

export function serializeCard(card: ProvenanceCard): string {
  return JSON.stringify(card);
}

export function parseRegistry(text: string): ProvenanceCard[] {
  const cards: ProvenanceCard[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    try {
      const parsed = JSON.parse(trimmed) as ProvenanceCard;
      if (parsed && parsed.version === CARD_VERSION) cards.push(parsed);
    } catch {
      continue;
    }
  }
  return cards;
}

export function resolveByHash(cards: readonly ProvenanceCard[], assetSha256: string): ProvenanceCard | undefined {
  const needle = assetSha256.replace(/^sha256:/, "").toLowerCase();
  return cards.find((card) => card.asset.sha256.toLowerCase() === needle);
}

export interface CardMatch {
  ok: boolean;
  card: ProvenanceCard;
  reasons: string[];
}

export function matchCard(card: ProvenanceCard, asset: AssetVerification): CardMatch {
  const reasons: string[] = [];
  if (card.asset.sha256.toLowerCase() !== asset.file.hash.toLowerCase()) {
    reasons.push("the file's SHA-256 does not match the card");
  }
  if (card.asset.size !== asset.file.size) {
    reasons.push("the file size does not match the card");
  }
  const cardManifest = card.manifests[card.manifests.length - 1] as Record<string, unknown> | undefined;
  const liveManifest = asset.manifests[asset.manifests.length - 1];
  if (cardManifest && liveManifest) {
    if (cardManifest["label"] !== liveManifest.label) reasons.push("the active manifest id changed");
    const cardBinding = cardManifest["hardBinding"] as Record<string, unknown> | undefined;
    if (cardBinding && cardBinding["assertedHash"] !== liveManifest.hardBinding.assertedHash) {
      reasons.push("the hard binding hash changed");
    }
    const cardSignature = cardManifest["signature"] as Record<string, unknown> | undefined;
    if (cardSignature && cardSignature["valid"] !== liveManifest.signature.valid) {
      reasons.push("the signature state changed");
    }
  } else if (Boolean(cardManifest) !== Boolean(liveManifest)) {
    reasons.push("the manifest set changed");
  }
  return { ok: reasons.length === 0, card, reasons };
}
