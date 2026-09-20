# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-20

### Added

- The `attest` CLI: `inspect`, `verify` (with the `check` alias), `card`,
  `anchor`, `resolve`, and `mcp`, with plain-text and `--json` output, `--verbose`,
  `--quiet`, `--trust`, `--require-trusted`, and `--registry`.
- Offline C2PA verification: manifest-store location in JPEG (APP11), PNG
  (`caBX`), WebP (`C2PA`), and raw JUMBF; JUMBF box and superbox parsing with
  description boxes; CBOR claim decoding; and the assertion set.
- COSE_Sign1 verification with the `Signature1` Sig_structure, an empty external
  AAD, and the detached-payload rule, supporting `ES256`, `ES384`, `ES512`,
  `PS256`, `PS384`, `PS512`, `RS256`, and `EdDSA` over WebCrypto.
- X.509 certificate parsing and chain verification, including the raw `r || s`
  ECDSA form, the DER-to-raw conversion for chain signatures, and RSA public-key
  import through a JWK when the SPKI carries RSASSA-PSS parameters.
- Assertion hash verification (SHA-256 over the assertion box payload) and
  `c2pa.hash.data` hard-binding verification with exclusions and a fallback to
  the manifest byte ranges.
- Trust-list parsing for C2PA-style JSON and PEM certificates, and trust
  evaluation against the certificate chain.
- Stable validation states (`valid`, `invalid`, `untrusted`, `unsigned`) and
  stable issue codes with severities.
- Portable provenance cards (`attest/card/1`) with a content-derived card id,
  and a JSON Lines registry with `anchor`/`resolve` and card matching.
- An MCP server over stdio exposing `provenance_verify`, `provenance_inspect`,
  and `provenance_card`.
- A browser-safe TypeScript library (`src/index.ts`) covering the byte, CBOR,
  DER, X.509, COSE, JUMBF, C2PA, verify, trust, report, and card modules, bundled
  into `site/assets/studio.js` by `scripts/build-site.mjs`.
- The normative `spec/SPEC.md`, including the explicit out-of-scope list.
- The conformance fixture `fixtures/C2PA-signed.jpg`, a signed JPEG from the
  `contentauth/c2pa-rs` test fixtures.

[Unreleased]: https://github.com/srivtx/attest/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/srivtx/attest/releases/tag/v0.1.0
