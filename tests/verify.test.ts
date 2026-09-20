import { describe, expect, test } from "bun:test";
import { verifyBytes, hashWithExclusions } from "../src/verify.ts";
import { parseTrustList, evaluateTrust } from "../src/trust.ts";
import { locateManifest, walk } from "../src/jumbf.ts";
import { readFixture, SIGNED_JPEG, tamper, unsignedPng } from "./helpers.ts";

const signed = readFixture(SIGNED_JPEG);

describe("verifyBytes on a real signed image", () => {
  test("reports valid, with a matching hard binding and four assertions", async () => {
    const asset = await verifyBytes(signed);
    expect(asset.state).toBe("valid");
    expect(asset.hasManifestStore).toBe(true);
    expect(asset.file.container).toBe("jpeg");
    expect(asset.file.hash).toHaveLength(64);
    const manifest = asset.manifests[0]!;
    expect(manifest.signature.valid).toBe(true);
    expect(manifest.signature.algorithm).toBe("PS256");
    expect(manifest.hardBinding.status).toBe("matched");
    expect(manifest.assertions.length).toBe(4);
    expect(manifest.assertions.every((a) => a.hashMatched)).toBe(true);
    expect(manifest.issues.some((i) => i.severity === "error")).toBe(false);
  });

  test("records the generator and the recorded action", async () => {
    const asset = await verifyBytes(signed);
    const manifest = asset.manifests[0]!;
    expect(manifest.generator).toBe("make_test_images");
    expect(manifest.actions.map((a) => a.action)).toContain("c2pa.created");
    expect(manifest.actions[0]!.softwareAgent).toBe("Make Test Images 0.33.1");
  });

  test("walks the certificate chain and flags the missing root as untrusted, not invalid", async () => {
    const asset = await verifyBytes(signed);
    const manifest = asset.manifests[0]!;
    expect(manifest.chain).toHaveLength(2);
    expect(manifest.chain[0]!.signatureValid).toBe(true);
    expect(manifest.trust.status).toBe("unknown");
    expect(manifest.issues.some((i) => i.code === "signingCredential.intermediate")).toBe(true);
    expect(manifest.issues.some((i) => i.code === "signingCredential.invalid")).toBe(false);
  });

  test("reports the claimant hash with exclusions", async () => {
    const asset = await verifyBytes(signed);
    const manifest = asset.manifests[0]!;
    expect(manifest.hardBinding.assertedHash).toBe(manifest.hardBinding.computedHash);
    expect(manifest.hardBinding.excludedBytes).toBeGreaterThan(40000);
    expect(manifest.hardBinding.algorithm).toBe("sha256");
  });
});

describe("tamper detection", () => {
  test("a single flipped byte in the image stream breaks the hard binding", async () => {
    const asset = await verifyBytes(tamper(signed, signed.length - 200));
    expect(asset.state).toBe("invalid");
    const manifest = asset.manifests[0]!;
    expect(manifest.signature.valid).toBe(true);
    expect(manifest.hardBinding.status).toBe("mismatch");
    expect(asset.issues.some((i) => i.code === "hardBinding.mismatch" && i.severity === "error")).toBe(true);
  });

  test("a flipped byte in the claim breaks the COSE signature", async () => {
    const location = locateManifest(signed)!;
    const claim = walk(location.boxes).find((b) => b.label === "c2pa.claim")!;
    const inner = claim.boxes[0]!;
    // Box offsets are relative to the buffer they were parsed from: for a JPEG the
    // manifest boxes are parsed from the merged APP11 payload, which begins 12 bytes
    // after the segment start (2 marker + 2 length + 8 JP envelope).
    const segmentStart = location.ranges[0]!.start + 12;
    const offset = segmentStart + claim.start + claim.headerLength + inner.start + inner.headerLength + 4;
    const asset = await verifyBytes(tamper(signed, offset));
    expect(asset.state).toBe("invalid");
    expect(
      asset.issues.some((i) => i.code === "claimSignature.mismatch" || i.code === "manifest.malformed"),
    ).toBe(true);
  });

  test("the bytes the hard binding excludes are exactly the manifest segment", async () => {
    const location = locateManifest(signed)!;
    const range = location.ranges[0]!;
    const inside = await verifyBytes(tamper(signed, range.start + 40));
    expect(inside.state).toBe("valid");
    const outside = await verifyBytes(tamper(signed, range.start + range.length + 10));
    expect(outside.state).toBe("invalid");
  });
});

describe("unsigned input", () => {
  test("a plain PNG is reported as unsigned, not invalid", async () => {
    const asset = await verifyBytes(unsignedPng());
    expect(asset.state).toBe("unsigned");
    expect(asset.hasManifestStore).toBe(false);
    expect(asset.manifests).toHaveLength(0);
    expect(asset.issues[0]!.code).toBe("manifest.missing");
  });
});

describe("hashWithExclusions", () => {
  test("hashing with no exclusions equals hashing the whole buffer", async () => {
    const whole = await hashWithExclusions(signed, []);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", signed as never));
    expect(whole).toEqual(digest);
  });

  test("excluding a range changes the digest", async () => {
    const whole = await hashWithExclusions(signed, []);
    const partial = await hashWithExclusions(signed, [{ start: 0, length: 40 }]);
    expect(partial).not.toEqual(whole);
  });

  test("overlapping and out-of-range exclusions are clamped", async () => {
    const a = await hashWithExclusions(signed, [
      { start: 0, length: 10 },
      { start: 5, length: 10 },
    ]);
    const b = await hashWithExclusions(signed, [{ start: 0, length: 15 }]);
    expect(a).toEqual(b);
    const clamped = await hashWithExclusions(signed, [{ start: signed.length - 4, length: 1000 }]);
    expect(clamped).toEqual(await hashWithExclusions(signed, [{ start: signed.length - 4, length: 4 }]));
  });
});

describe("trust lists", () => {
  test("accepts a C2PA-shaped JSON trust list", async () => {
    const list = await parseTrustList(
      JSON.stringify({ trusted_list: [{ cert_sha256: "AA:BB", subject: "CN=Test Signer" }] }),
      "test.json",
    );
    expect(list.entries).toHaveLength(1);
    expect(list.entries[0]!.certSha256).toBe("aabb");
  });

  test("accepts a bare array of fingerprint entries", async () => {
    const list = await parseTrustList(JSON.stringify([{ sha256: "ccdd", subject: "CN=Root" }]));
    expect(list.entries[0]!.certSha256).toBe("ccdd");
  });

  test("returns unknown when no list is supplied", () => {
    expect(evaluateTrust([], undefined).status).toBe("unknown");
  });

  test("marks a chain untrusted when no entry matches", async () => {
    const list = await parseTrustList(JSON.stringify([{ cert_sha256: "00" }]));
    const asset = await verifyBytes(signed, { trustList: list });
    const manifest = asset.manifests[0]!;
    expect(manifest.trust.status).toBe("untrusted");
    expect(manifest.issues.some((i) => i.code === "signingCredential.untrusted")).toBe(true);
    expect(asset.state).toBe("valid");
  });

  test("marks a chain trusted when the leaf fingerprint matches", async () => {
    const asset = await verifyBytes(signed);
    const fingerprint = asset.manifests[0]!.chain[0]!.fingerprint;
    const list = await parseTrustList(JSON.stringify([{ cert_sha256: fingerprint }]));
    const trusted = await verifyBytes(signed, { trustList: list });
    expect(trusted.manifests[0]!.trust.status).toBe("trusted");
    expect(trusted.manifests[0]!.trust.anchor).toContain("CN=C2PA Signer");
  });

  test("--require-trusted flips an untrusted chain to the untrusted state", async () => {
    const list = await parseTrustList(JSON.stringify([{ cert_sha256: "00" }]));
    const asset = await verifyBytes(signed, { trustList: list, assertTrusted: true });
    expect(asset.state).toBe("untrusted");
  });
});
