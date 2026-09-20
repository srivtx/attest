import { describe, expect, test } from "bun:test";
import { verifyBytes } from "../src/verify.ts";
import { cardId, matchCard, parseRegistry, resolveByHash, serializeCard, toCard } from "../src/resolve.ts";
import { formatJson, formatReport, summarize } from "../src/report.ts";
import { readFixture, SIGNED_JPEG, tamper } from "./helpers.ts";

const signed = readFixture(SIGNED_JPEG);

describe("provenance cards", () => {
  test("builds a card with the asset identity and the validation state", async () => {
    const asset = await verifyBytes(signed);
    const card = toCard(asset, new Date("2026-09-20T00:00:00Z"));
    expect(card.version).toBe("attest/card/1");
    expect(card.asset.sha256).toBe(asset.file.hash);
    expect(card.asset.size).toBe(signed.length);
    expect(card.asset.container).toBe("jpeg");
    expect(card.state).toBe("valid");
    expect(card.issuedAt).toBe("2026-09-20T00:00:00.000Z");
    expect(card.manifests).toHaveLength(1);
  });

  test("the card id is stable for the same content and changes when the state changes", async () => {
    const asset = await verifyBytes(signed);
    const card = toCard(asset, new Date("2026-09-20T00:00:00Z"));
    const first = await cardId(card);
    const second = await cardId(toCard(asset, new Date("2027-01-01T00:00:00Z")));
    expect(first).toBe(second);
    const changed = { ...card, state: "invalid" as const };
    expect(await cardId(changed)).not.toBe(first);
  });

  test("matches a card against the same file and rejects a tampered one", async () => {
    const asset = await verifyBytes(signed);
    const card = toCard(asset);
    expect(matchCard(card, asset).ok).toBe(true);
    const tampered = await verifyBytes(tamper(signed, signed.length - 200));
    const result = matchCard(card, tampered);
    expect(result.ok).toBe(false);
    expect(result.reasons.join(" ")).toMatch(/SHA-256|hard binding/);
  });
});

describe("registry", () => {
  test("round-trips cards through JSON Lines and resolves by hash", async () => {
    const asset = await verifyBytes(signed);
    const card = toCard(asset);
    const text = [serializeCard(card), serializeCard({ ...card, asset: { ...card.asset, sha256: "f".repeat(64) } })].join("\n");
    const cards = parseRegistry(text);
    expect(cards).toHaveLength(2);
    expect(resolveByHash(cards, asset.file.hash)?.asset.size).toBe(signed.length);
    expect(resolveByHash(cards, `sha256:${asset.file.hash.toUpperCase()}`)?.asset.container).toBe("jpeg");
    expect(resolveByHash(cards, "0".repeat(64))).toBeUndefined();
  });

  test("ignores blank lines and malformed entries", () => {
    const cards = parseRegistry(['{"version":"attest/card/1","asset":{}}', "", "not json", '{"version":"other"}'].join("\n"));
    expect(cards).toHaveLength(1);
  });
});

describe("reports", () => {
  test("the human report names the state, the signature, and the hard binding", async () => {
    const asset = await verifyBytes(signed);
    const text = formatReport(asset, { verbose: true });
    expect(text).toContain("VALID");
    expect(text).toContain("signature  valid (PS256)");
    expect(text).toContain("hard binding  matched (sha256)");
    expect(text).toContain("c2pa.hash.data");
    expect(text).toContain("assertions    4");
  });

  test("the summary line is one line", async () => {
    const asset = await verifyBytes(signed);
    const line = summarize(asset);
    expect(line.split("\n")).toHaveLength(1);
    expect(line).toContain("valid");
  });

  test("the JSON report is valid JSON with the same state", async () => {
    const asset = await verifyBytes(signed);
    const parsed = JSON.parse(formatJson(asset)) as typeof asset;
    expect(parsed.state).toBe(asset.state);
    expect(parsed.manifests[0]!.hardBinding.status).toBe("matched");
  });

  test("an unsigned file is summarised honestly", async () => {
    const asset = await verifyBytes(new Uint8Array([1, 2, 3]));
    expect(summarize(asset)).toContain("unsigned");
  });
});
