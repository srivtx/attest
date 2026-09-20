import { describe, expect, test } from "bun:test";
import { locateManifest, walk, findBox } from "../src/jumbf.ts";
import { parseManifestStore, assertionLabelFromUri } from "../src/c2pa.ts";
import { parseCoseSign1, verifyCoseSign1 } from "../src/cose.ts";
import { parseCertificate } from "../src/x509.ts";
import { readFixture, SIGNED_JPEG, tamper } from "./helpers.ts";

const bytes = readFixture(SIGNED_JPEG);

describe("JUMBF manifest discovery", () => {
  test("finds the manifest store in a JPEG APP11 segment", () => {
    const location = locateManifest(bytes);
    expect(location).toBeDefined();
    expect(location!.container).toBe("jpeg");
    expect(location!.ranges.length).toBeGreaterThan(0);
    const store = location!.boxes[0]!;
    expect(store.type).toBe("jumb");
    expect(store.label).toBe("c2pa");
    expect(store.uuid).toBe("63327061-0011-0010-8000-00aa00389b71");
  });

  test("reports the byte range of the manifest for hard-binding exclusions", () => {
    const location = locateManifest(bytes)!;
    const range = location.ranges[0]!;
    expect(range.length).toBeGreaterThan(1000);
    expect(range.start).toBe(20);
    expect(range.start + range.length).toBe(location.ranges[0]!.start + location.ranges[0]!.length);
  });

  test("exposes the claim, signature, and assertion boxes as a tree", () => {
    const labels = walk(locateManifest(bytes)!.boxes).map((b) => b.label);
    expect(labels).toContain("c2pa.claim");
    expect(labels).toContain("c2pa.signature");
    expect(labels).toContain("c2pa.hash.data");
    expect(labels).toContain("c2pa.actions");
    expect(findBox(locateManifest(bytes)!.boxes, "c2pa.hash.data")).toBeDefined();
  });
});

describe("manifest model", () => {
  const manifest = parseManifestStore(locateManifest(bytes)!.boxes)[0]!.manifests[0]!;

  test("reads the claim metadata", () => {
    expect(manifest.claim.title).toBe("C.jpg");
    expect(manifest.claim.format).toBe("image/jpeg");
    expect(manifest.claim.claimGeneratorName).toBe("make_test_images");
    expect(manifest.claim.instanceId?.startsWith("xmp:iid:")).toBe(true);
    expect(manifest.claim.alg).toBe("sha256");
  });

  test("indexes every assertion the claim declares", () => {
    const labels = manifest.assertions.map((a) => a.label).sort();
    expect(labels).toEqual([
      "c2pa.actions",
      "c2pa.hash.data",
      "c2pa.thumbnail.claim.jpeg",
      "stds.schema-org.CreativeWork",
    ]);
    expect(manifest.claim.assertions.length).toBeGreaterThanOrEqual(4);
  });

  test("maps a hashed URI to the assertion label", () => {
    expect(assertionLabelFromUri("self#jumbf=c2pa.assertions/c2pa.hash.data")).toBe("c2pa.hash.data");
    expect(assertionLabelFromUri("self#jumbf=c2pa.assertions/c2pa.ingredients/c2pa.ingredient.v3")).toBe("c2pa.ingredient.v3");
  });

  test("links the leaf certificate to its issuer in the chain", () => {
    const leaf = manifest.certificates[0]!;
    const issuer = manifest.certificates[1]!;
    expect(leaf.issuerDisplay).toBe(issuer.subjectDisplay);
    expect(leaf.authorityKeyIdentifier ?? "").toBe(issuer.subjectKeyIdentifier ?? "");
  });
});

describe("COSE signature", () => {
  const manifest = parseManifestStore(locateManifest(bytes)!.boxes)[0]!.manifests[0]!;

  test("carries an x5chain of parseable certificates", () => {
    expect(manifest.certificates.length).toBe(2);
    const leaf = manifest.certificates[0]!;
    expect(leaf.subjectDisplay).toContain("CN=C2PA Signer");
    expect(leaf.isCa).toBe(false);
    expect(manifest.certificates[1]!.isCa).toBe(true);
  });

  test("declares PS256 and a detached payload", () => {
    expect(manifest.signature.alg).toBe(-37);
    expect(manifest.signature.payload).toBeNull();
    expect(manifest.signature.signature.length).toBe(512);
  });

  test("validates the signature over the claim bytes", async () => {
    const result = await verifyCoseSign1(manifest.signature, manifest.certificates[0]!, manifest.claim.raw);
    expect(result.valid).toBe(true);
    expect(result.algorithm).toBe("PS256");
  });

  test("rejects a tampered claim", async () => {
    const forged = new Uint8Array(manifest.claim.raw);
    forged[forged.length - 1] = forged[forged.length - 1]! ^ 0x01;
    const result = await verifyCoseSign1(manifest.signature, manifest.certificates[0]!, forged);
    expect(result.valid).toBe(false);
  });

  test("rejects a signature from the wrong certificate", async () => {
    const result = await verifyCoseSign1(manifest.signature, manifest.certificates[1]!, manifest.claim.raw);
    expect(result.valid).toBe(false);
  });
});

describe("certificates", () => {
  test("parses the leaf certificate from the fixture", () => {
    const manifest = parseManifestStore(locateManifest(bytes)!.boxes)[0]!.manifests[0]!;
    const leaf = parseCertificate(manifest.certificates[0]!.raw);
    expect(leaf.version).toBe(3);
    expect(leaf.publicKeyAlgorithmOid).toBe("1.2.840.113549.1.1.10");
    expect(leaf.notAfter.getTime()).toBeGreaterThan(leaf.notBefore.getTime());
    expect(leaf.spki.length).toBeGreaterThan(200);
  });

  test("keeps parsing a certificate whose signature covers a tampered manifest", () => {
    const forged = tamper(bytes, 100);
    const store = parseManifestStore(locateManifest(forged)!.boxes)[0]!;
    expect(store.manifests[0]!.certificates[0]!.subjectDisplay).toContain("C2PA Signer");
  });
});
