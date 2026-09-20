# attest

> Offline C2PA Content Credentials verifier and provenance tool.

**by svx** · MIT Licensed

[![CI](https://github.com/srivtx/attest/actions/workflows/ci.yml/badge.svg)](https://github.com/srivtx/attest/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/srivtx/attest?sort=semver&color=c026d3)](https://github.com/srivtx/attest/releases)
[![license](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

---

`attest` reads the JUMBF manifest store out of a JPEG, PNG, WebP, or raw JUMBF
file, decodes the CBOR claim, verifies the COSE_Sign1 signature against the
`x5chain`, verifies every assertion hash, checks the `c2pa.hash.data` hard
binding over the asset bytes, walks the certificate chain, evaluates a trust
list, and reports a validation state with stable issue codes. It runs entirely
in-process, in Bun or the browser, with no upload and no account. It can also
emit a portable provenance card and anchor cards in a JSON Lines registry.

The normative description of what is and is not checked is
[`spec/SPEC.md`](spec/SPEC.md).

## Why

A Content Credential is only useful if you can check it yourself. The common
alternatives are a vendor service that uploads your file, an account you have to
create, or a hard dependency on a closed platform. `attest` is none of those:

- **Offline.** It never opens a socket. The manifest, the certificate chain, and
  the signatures are all verified from the bytes you hand it.
- **No upload, no account.** Your media never leaves the machine.
- **Verifiable in CI.** The CLI returns stable exit codes, so a pipeline can
  fail a build when a signed asset is tampered with or a signer is not trusted.
- **Transparency you can point at.** From 2 August 2026, EU AI Act Article 50
  requires providers and deployers of certain AI systems to mark and disclose
  AI-generated or AI-manipulated content. A C2PA manifest is one of the
  machine-readable disclosures that obligation can rest on; `attest` verifies
  that a manifest is present, signed, and internally consistent without sending
  the asset anywhere.

Verification tells you who signed these exact bytes and whether they have been
altered since. It does not tell you the content is true; see
[What is not verified](#what-is-not-verified).

## Quick start

Requires [Bun](https://bun.sh) (>= 1.1.0).

```bash
bun install
bun src/cli.ts inspect fixtures/C2PA-signed.jpg --verbose
```

```text
VALID  jpeg  132518 bytes
sha256  a2d14755db55de67a47c04090340d8266e892367be4104a45626d7a6fa6e9ffd

manifest  contentauth:urn:uuid:b2b1f7fa-b119-4de1-9c0d-c97fbea3f2c3
  title      C.jpg
  generator  make_test_images
  format     image/jpeg
  instance   xmp:iid:22704d84-c37f-4733-a207-56c4c2e67b1a
  signature  valid (PS256)
  trust      unknown — no trust list was supplied
  chain
    . C=US, ST=CA, L=Somewhere, O=C2PA Test Signing Cert, OU=FOR TESTING_ONLY, CN=C2PA Signer
        2022-06-10T18:46:28.000Z to 2030-08-26T18:46:28.000Z  68e2ccccf0ee0529
    . C=US, ST=CA, L=Somewhere, O=C2PA Test Intermediate Root CA, OU=FOR TESTING_ONLY, CN=Intermediate CA  [CA]
        2022-06-10T18:46:26.000Z to 2030-08-27T18:46:26.000Z  28f3833389548b0e
  actions
    c2pa.created  by Make Test Images 0.33.1
  hard binding  matched (sha256)
    computed  81664d10e30740d8942df03fb4ee470f66b03b060c037b677d43c0a48afd72c9
    asserted  81664d10e30740d8942df03fb4ee470f66b03b060c037b677d43c0a48afd72c9
  assertions    4
    c2pa.thumbnail.claim.jpeg  declared, present, hash ok
    stds.schema-org.CreativeWork  declared, present, hash ok
    c2pa.actions  declared, present, hash ok
    c2pa.hash.data  declared, present, hash ok

0 error(s), 0 warning(s)
  INFO  claimSignature.validated  Claim signature validated (PS256).
  INFO  signingCredential.intermediate  The chain does not carry the issuer of C=US, ST=CA, L=Somewhere, O=C2PA Test Intermediate Root CA, OU=FOR TESTING_ONLY, CN=Intermediate CA; trust has to come from a trust list.
  INFO  hardBinding.matched  Asset bytes match the hard binding (sha256).
```

The default `verify` prints one line:

```bash
bun src/cli.ts verify fixtures/C2PA-signed.jpg
```

```text
valid: C.jpg — signature valid, hard binding matched
```

Change one byte of the scan data and the hard binding fails. (This reproduces
the `/tmp/opencode/tampered.jpg` used below from the committed fixture.)

```bash
cp fixtures/C2PA-signed.jpg /tmp/opencode/tampered.jpg
printf '\xd2' | dd of=/tmp/opencode/tampered.jpg bs=1 seek=127518 conv=notrunc count=1 2>/dev/null
bun src/cli.ts verify /tmp/opencode/tampered.jpg
```

```text
invalid: C.jpg — signature valid, hard binding mismatch
```

The exit code is `1` and the claim signature still validates: the bytes changed,
the signature covers the claim, and the hard binding is what detects the change.

## CLI

```text
attest inspect <file> [options]        verify and print a full report
attest verify <file> [options]         verify; one summary line unless --verbose
attest card <file>                     print a portable provenance card as JSON
attest anchor <file> --registry <p>    append a provenance card to a registry
attest resolve <hash|file> --registry <p>
                                       look up a card, and re-verify a file against it
attest mcp                             run the MCP server over stdio
```

`inspect` and `verify` are the same verification; `inspect` prints the full
report and `verify` prints the one-line summary unless `--verbose` is passed.
`check` is accepted as an alias of `inspect`. A target of `-` reads the media
bytes from stdin.

| Flag | Meaning |
|---|---|
| `--trust <file>` | Trust list: a C2PA-style trust list JSON or PEM certificates |
| `--require-trusted` | Treat an untrusted signer as a failure (exit `1`) |
| `--json` | Print machine-readable JSON instead of text |
| `--verbose`, `-v` | Include per-assertion detail and certificate validity windows |
| `--quiet`, `-q` | Suppress output; rely on the exit code |
| `--registry <path>` | Registry file for `anchor` and `resolve` (JSON Lines) |
| `-h`, `--help` | Show the usage text |
| `--version` | Print the version and exit `0` |

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Valid, or nothing to report. An untrusted signer is `0` unless `--require-trusted` is set |
| `1` | Invalid, untrusted under `--require-trusted`, unsigned, or a card was not found / did not match |
| `2` | Usage error: unknown flag, unknown command, missing target, or unreadable format |
| `3` | I/O error: a file could not be read, or a trust list could not be loaded |

## MCP

Any MCP-capable agent can verify media over stdio. The MCP server takes the file
bytes as base64 and makes no network calls.

```json
{
  "mcpServers": {
    "attest": {
      "command": "bunx",
      "args": ["github:srivtx/attest#main", "mcp"]
    }
  }
}
```

The server exposes three tools:

| Tool | Arguments | Returns |
|---|---|---|
| `provenance_verify` | `data` (base64), optional `name` | The summary line, the validation state, signer chain, hard binding result, actions, and issues |
| `provenance_inspect` | `data` (base64), optional `name` | The full verbose report, every assertion with its declared/present/hash state |
| `provenance_card` | `data` (base64) | The portable provenance card and the validation state as JSON |

It implements `initialize`, `notifications/initialized`, `ping`, `tools/list`,
and `tools/call`. The tool names are stable.

## JavaScript API

`src/index.ts` is the public surface, and it is browser-safe: no `node:`
imports, only WebCrypto and standard web APIs. `scripts/build-site.mjs` bundles
it into `site/assets/studio.js` as the global `Attest`.

```ts
import { verifyBytes, toCard, parseTrustList, evaluateTrust } from "attest";

const bytes = new Uint8Array(await (await fetch(url)).arrayBuffer());
const asset = await verifyBytes(bytes);

console.log(asset.state);          // "valid" | "invalid" | "untrusted" | "unsigned"
console.log(asset.file.hash);      // sha256 of the file
for (const manifest of asset.manifests) {
  console.log(manifest.signature.valid, manifest.hardBinding.status);
}

const card = toCard(asset);
```

Exported groups:

| Group | Exports |
|---|---|
| Bytes | `Reader`, `concat`, `toHex`, `fromHex`, `base64`, `fromBase64`, `utf8`, `encodeUtf8`, `bytesEqual`, `startsWith`, `indexOfBytes` |
| CBOR | `decodeCbor`, `encodeCbor`, `CborValue`, and the `mapGet*` accessors |
| DER | `DER_TAG`, `DER_CLASS`, `parseDer`, `readDerNode`, `derOid`, `oidName`, `DerNode` |
| X.509 | `parseCertificate`, `importPublicKey`, `verifyCertificateSignature`, `algorithmFromOid`, `certificatesFromPem`, `pemToDer`, `Certificate`, `SignatureAlgorithm` |
| COSE | `parseCoseSign1`, `verifyCoseSign1`, `coseSigStructure`, `COSE_ALGORITHMS`, `coseAlgorithmLabel`, `CoseSign1` |
| JUMBF | `locateManifest`, `parseJumbfBoxes`, `walk`, `findBox`, `findBoxes`, `formatUuid`, `JumbfBox`, `ManifestLocation` |
| C2PA | `parseManifestStore`, `assertionLabelFromUri`, `findAssertionByUri`, `Manifest`, `ManifestStore`, `Claim`, `Assertion` |
| Verify | `verifyBytes`, `hashWithExclusions`, `sha256`, `AssetVerification`, `ManifestVerification`, `Issue`, `VerifyOptions`, `ChainLink`, `Ingredient`, `ActionRecord` |
| Trust | `parseTrustList`, `evaluateTrust`, `TrustList`, `TrustEntry`, `TrustEvaluation` |
| Report | `formatReport`, `formatJson`, `summarize`, `TextReportOptions` |
| Card | `toCard`, `cardId`, `serializeCard`, `parseRegistry`, `resolveByHash`, `matchCard`, `CARD_VERSION`, `ProvenanceCard`, `CardMatch` |

`verifyBytes(bytes, options)` takes `trustList`, `assertTrusted`, and an optional
`now` date for testing expiry.

## Trust list formats

A trust list is supplied with `--trust`. Two formats are accepted.

**JSON.** Either a top-level array of entries, or an object with one of the keys
`trusted_list`, `trusted`, `allowed`, `entries`, or `certificates` holding an
array. An entry may carry any of:

```json
{
  "trusted_list": [
    {
      "cert_sha256": "68e2ccccf0ee0529528e931abd0f68ec8077238da4e041d344d900498a2b953c",
      "subject": "C=US, ST=CA, L=Somewhere, O=C2PA Test Signing Cert, OU=FOR_TESTING_ONLY, CN=C2PA Signer"
    }
  ]
}
```

The fingerprint keys accepted are `cert_sha256`, `certSha256`, `sha256`, and
`fingerprint`; the subject keys are `subject` and `subject_dn`; the issuer keys
are `issuer` and `issuer_dn`. Fingerprints are normalized by stripping `:` and
lowercasing. The issuer field is parsed but not used when matching.

**PEM.** One or more `-----BEGIN CERTIFICATE-----` blocks. Each is parsed and
recorded by its SHA-256 fingerprint and its subject and issuer distinguished
names.

Evaluation walks the chain as reported in the manifest. The first link whose
fingerprint equals `cert_sha256` or whose subject equals `subject` marks the
chain **trusted** (with that subject as the anchor). If no link matches, the
chain is **untrusted**. If no list was supplied, trust is **unknown**, and the
asset stays `valid`; only `--require-trusted` turns an untrusted evaluation into
the asset state `untrusted` and exit `1`.

## Provenance card and registry

`attest card` emits a portable JSON record of a verification:

```json
{
  "version": "attest/card/1",
  "asset": { "sha256": "…", "size": 132518, "container": "jpeg" },
  "state": "valid",
  "manifests": [
    {
      "label": "…",
      "title": "C.jpg",
      "generator": "make_test_images",
      "format": "image/jpeg",
      "instanceId": "…",
      "signature": { "valid": true, "algorithm": "PS256" },
      "trust": { "status": "unknown", "reason": "no trust list was supplied" },
      "hardBinding": { "status": "matched", "algorithm": "sha256", "assertedHash": "…", "computedHash": "…" },
      "actions": [ { "action": "c2pa.created", "softwareAgent": "Make Test Images 0.33.1" } ],
      "ingredients": [],
      "chain": [ { "subject": "…", "fingerprint": "…" } ]
    }
  ],
  "issuedAt": "2026-09-20T15:48:29.306Z"
}
```

The card id is the SHA-256 of the canonical JSON of `version`, `asset`, `state`,
and `manifests` — `issuedAt` is deliberately excluded — so the same verification
always yields the same id.

`attest anchor <file> --registry <path>` verifies the file and appends the card
as one line of JSON to the registry. The registry is JSON Lines; a line that
does not parse or is not `attest/card/1` is ignored on read.

`attest resolve <hash|file> --registry <path>` looks a card up by asset SHA-256
(an optional `sha256:` prefix is accepted) or verifies a file and looks it up by
its hash. For a file it also re-checks that the card still matches: the file
hash, the file size, the active manifest id, the hard binding asserted hash, and
the signature state must all be unchanged. `resolve` exits `0` on a match and
`1` if the card is missing or the file changed.

## What is verified

- **Container and manifest location.** The manifest store is found in a JPEG
  (APP11 segments), PNG (`caBX` chunk), WebP (`C2PA` RIFF chunk), or a raw JUMBF
  file, and the exact byte ranges that hold it are recorded.
- **JUMBF structure.** Box headers, superboxes, description boxes (type UUID,
  toggle byte, NUL-terminated label), the manifest store, each manifest, the
  claim box, the signature box, and the assertion set.
- **The CBOR claim.** The claim map is decoded, including the fields listed in
  the spec, and the declared assertion list is read as hashed URIs.
- **The claim signature.** The COSE_Sign1 `Signature1` Sig_structure is built
  over the protected header and the claim bytes, and the signature is verified
  with WebCrypto against the leaf certificate's public key. The algorithms
  `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`, `RS256`, and `EdDSA`
  (Ed25519) are supported.
- **Every assertion hash.** For each hashed URI the claim declares, the assertion
  is located and SHA-256 over its box payload is compared with the declared hash.
- **The hard binding.** `c2pa.hash.data` is re-computed over the asset bytes with
  the declared exclusions removed and compared with the asserted hash.
- **The certificate chain.** Each certificate's signature is checked against the
  next certificate in the `x5chain`, and every certificate's validity window is
  checked against the current time.
- **The trust list.** The chain is evaluated against a supplied trust list.
- **A stable result.** A validation state and a set of issue codes with
  severities, plus a portable provenance card and registry lookup.

## What is not verified

This list is deliberately blunt. `attest` is a focused verifier, not a
conformance authority.

- **No BMFF or box-hash bindings.** A `c2pa.hash.boxes` assertion is reported as
  `hardBinding.unsupported`; it is not evaluated.
- **No OCSP or CRL revocation.** A certificate that was revoked but not expired
  still verifies. There is no revocation check of any kind.
- **No remote manifests.** The claim's `remote_manifest` URL is read and shown,
  but it is never fetched. Only the store embedded in the file is inspected.
- **No platform trust store.** The OS or browser trust store is not consulted.
  Without `--trust`, trust is `unknown`; a signature can be cryptographically
  valid and still be from an untrusted issuer.
- **Provenance is not truth.** A valid signature proves that the holder of the
  signing key signed this claim over these bytes. It does not prove the content
  is accurate, unedited in meaning, not misleading, or AI-generated or not
  AI-generated. It does not prove the signer is who they say they are beyond what
  the certificate and trust list establish.
- **No assertion semantics.** Assertions are checked for presence and hash
  integrity, not for meaning: schema.org payloads, action vocabularies,
  thumbnails, and ingredient metadata are not validated.
- **No ingredient or manifest-chain recursion.** Ingredients are listed, but
  their manifests and thumbnails are not resolved or verified.
- **No CAWG identity assertion validation.** An identity assertion is treated as
  opaque bytes.
- **Only SHA-256.** All digests — assertion hashes and the hard binding — are
  SHA-256. The claim's `alg` and the hard binding's `alg` are read and displayed,
  but no other hash algorithm is implemented.
- **No path building.** The `x5chain` is read in order; issuer and subject are
  not matched, name constraints and policies are not processed, and key usage is
  not enforced. A chain that does not terminate in a self-signed root produces an
  info-level `signingCredential.intermediate` and leaves trust to the list.
- **The claim's `signature` hashed URI is not checked.** Only entries in the
  claim's `assertions` array are hash-verified.
- **No signing.** `attest` cannot create or sign a manifest.
- **Float CBOR and indefinite-length text strings.** The CBOR decoder does not
  decode floating-point items and enforces byte-string chunks inside an
  indefinite-length text string (where the standard uses text-string chunks).
- **`--version` prints only the version string.** There is no build metadata or commit hash.

## Validation states

The asset state is one of:

| State | Meaning | Exit |
|---|---|---|
| `valid` | A manifest store was found and verified, with no error-severity issue | `0` |
| `invalid` | At least one error-severity issue (a failed signature, a hash mismatch, a mismatched hard binding, or a missing hard binding) | `1` |
| `untrusted` | Verification found no error, but the signer is not on the trust list and `--require-trusted` is set | `1` |
| `unsigned` | No C2PA manifest store was found | `1` |

The per-manifest state is `valid`, `invalid`, or `untrusted`. The asset state is
`invalid` if any manifest is invalid, `valid` if all are valid, `untrusted` if
the remainder is untrusted, and `unsigned` if there are no manifests. A broken
hard binding is an error; a missing issuer is not.

Issue severities are `error` (invalidates the manifest), `warning` (reported but
does not invalidate), and `info`. The complete code set is in
[`spec/SPEC.md`](spec/SPEC.md).

## File formats

| Container | Where the manifest is | Notes |
|---|---|---|
| JPEG | APP11 segments (`0xFF 0xEB`) | Multiple JP segments are concatenated until the declared box length is reached |
| PNG | `caBX` chunk | The first `caBX` chunk is used |
| WebP | `C2PA` RIFF chunk | The first `C2PA` chunk is used |
| Raw JUMBF | The whole file | Used when the file is not a recognized image |

Not supported: BMFF/ISO base media (HEIF, AVIF, MP4), TIFF, SVG, PDF, or any
other container not listed above.

## Install

`attest` is not published to npm. Requires [Bun](https://bun.sh) (>= 1.1.0).
Install from GitHub:

```bash
# Install the `attest` binary globally
bun add -g github:srivtx/attest

# Or run once, without installing
bunx github:srivtx/attest#main --help

# Add to a project
bun add -d github:srivtx/attest
```

Then:

```bash
attest verify signed.jpg --trust trust.pem
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development gate and the code
conventions, and [`AGENTS.md`](AGENTS.md) for the layout and the hard rules.
Change behavior and [`spec/SPEC.md`](spec/SPEC.md) together.

## License

MIT — see [LICENSE](LICENSE).
