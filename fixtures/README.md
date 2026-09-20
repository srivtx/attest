# Fixtures

This directory is the conformance corpus for `attest`. Every media file here is
an input the implementation is expected to verify, and the reference results are
described in [`../spec/SPEC.md`](../spec/SPEC.md) section 14.

**Do not edit, regenerate, trim, or re-sign any file in this directory.**
Changing the bytes changes every hash, signature, and validation result the
fixtures exist to pin. If a fixture must be replaced, add the new file and
record why the old one is obsolete; do not overwrite a fixture in place.

## `C2PA-signed.jpg`

- **Origin:** the `contentauth/c2pa-rs` project test fixtures, copied from
  `sdk/tests/fixtures/C.jpg` in
  [contentauth/c2pa-rs](https://github.com/contentauth/c2pa-rs).
- **License / provenance:** `c2pa-rs` is distributed under the MIT license or
  the Apache License 2.0 (MIT OR Apache-2.0), copyright 2020 Adobe. The fixture
  is redistributed here unchanged for conformance testing under those terms.
- **What it exercises:** the full verification path on a real signed JPEG —
  manifest-store location in an APP11 segment, JUMBF and description-box parsing,
  CBOR claim decoding, COSE_Sign1 `PS256` signature verification against the
  `x5chain` leaf with WebCrypto, assertion hash verification for all four
  assertions, the `c2pa.hash.data` hard binding over the asset bytes with the
  APP11 exclusion range, certificate-chain link verification, the
  `signingCredential.intermediate` report when the issuer is absent, trust
  evaluation, and the provenance card and registry round-trip.
- **Signing certificate:** a C2PA test certificate (`C2PA Signer`, issued by
  `C2PA Test Intermediate Root CA`, both marked `FOR_TESTING_ONLY`). The issuer
  of the intermediate CA is **not** included in the chain, so the chain does not
  reach a self-signed root. Verification therefore reports an info-level
  `signingCredential.intermediate`; with no trust list the asset state is
  `valid` and trust is `unknown`.
- **Known values:** file SHA-256
  `a2d14755db55de67a47c04090340d8266e892367be4104a45626d7a6fa6e9ffd`; manifest
  label `contentauth:urn:uuid:b2b1f7fa-b119-4de1-9c0d-c97fbea3f2c3`; hard binding
  asserted and computed hash
  `81664d10e30740d8942df03fb4ee470f66b03b060c037b677d43c0a48afd72c9`.

There are no other fixtures in this directory.
