# SPEC — what `attest` verifies

This document is the normative description of the verification that `attest`
performs. It describes this implementation, not the C2PA specification; where
they differ, this document says so. Behavior is defined by `src/`, and this
document is changed with it.

## 1. Scope

`attest` accepts a media file or raw JUMBF bytes and returns an
`AssetVerification`:

```
{
  file: { size, container?, hash },
  hasManifestStore: boolean,
  manifests: ManifestVerification[],
  activeManifest?: string,
  issues: Issue[],
  state: "valid" | "invalid" | "untrusted" | "unsigned"
}
```

`hash` is the lowercase hex SHA-256 of the whole input. `container` is one of
`jpeg`, `png`, `webp`, or `c2pa`, as located in section 3.

## 2. Conformance language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are used as in RFC 2119. A "manifest" is
one C2PA manifest; the "store" is the JUMBF superbox that carries it or them. A
"hashed URI" is a CBOR map with `url` and `hash`. All hashes compared in this
document are SHA-256.

## 3. Input containers and manifest location

`locateManifest(bytes)` recognizes a container by its leading bytes and returns
the JUMBF boxes it parsed plus the byte ranges that hold the manifest store. The
detection order is JPEG, PNG, WebP, then raw JUMBF.

### 3.1 JPEG

A file beginning with `0xFF 0xD8` (`SOI`) is a JPEG. Scanning starts at offset 2.
The scanner walks marker segments:

- A segment starts with `0xFF`; any run of additional `0xFF` bytes is skipped.
- `0xD8` (`SOI`) and `0xD9` (`EOI`) are markers without a length and are skipped.
- `0xDA` (`SOS`) ends the scan; entropy-coded scan data is not walked.
- Otherwise a 2-byte big-endian length follows. `length` counts the two length
  bytes, so the segment payload is `length - 2` bytes.

An APP11 segment (`0xEB`) is a manifest carrier. Its payload MUST begin with the
two bytes `0x4A 0x50` (`JP`). The 8 bytes after the start of the payload are the
JP envelope: `JP`, a 2-byte box instance number, and a 4-byte box instance
sequence number. The JUMBF box begins immediately after; counted from the APP11
marker, the box begins at byte offset 12 (2 marker + 2 length + 8 envelope). The
bytes after the envelope are appended to a buffer.

Multiple APP11 segments are concatenated until the accumulated length reaches
the length declared by the first box (read as a 4-byte big-endian value; a value
of 0 or 1 is treated as "the rest of the payload"). The scanner stops early once
that length is reached. If the scan ends with buffered segments, the merged
buffer is parsed anyway.

The recorded exclusions are one range per contributing APP11 segment: from the
marker byte (`0xFF`) through the end of the segment payload.

### 3.2 PNG

A file beginning with `0x89 0x50 0x4E 0x47` (`\x89PNG`) is a PNG. Scanning
starts at offset 8, inside the chunk stream. Each chunk is a 4-byte big-endian
length, a 4-byte ASCII type, `length` bytes of data, and a 4-byte CRC. The first
chunk of type `caBX` carries the manifest; scanning stops at `IEND`. The
recorded range is `length + 12` bytes starting 8 bytes before the data (the
length and type fields plus the data plus the CRC).

### 3.3 WebP

A file whose first four bytes are `RIFF` and whose bytes 8 through 11 are
`WEBP` is a WebP. Scanning starts at offset 12. Each chunk is a 4-byte ASCII
FourCC, a 4-byte little-endian size, and `size` bytes padded to an even length
(`size + (size % 2)`). The first chunk whose FourCC is `C2PA` carries the
manifest. The recorded range is `size + 8` bytes starting 8 bytes before the
data (the FourCC and size fields plus the data; padding is not included in the
range).

### 3.4 Raw JUMBF

If the input matches none of the above, the whole file is parsed as JUMBF boxes.
If at least one box parses, the container is `c2pa` and the recorded range is
the whole file.

## 4. JUMBF box model

### 4.1 Box header

A box is a length, a type, and a payload:

- Read a 4-byte big-endian length.
- If the length is `1`, read an 8-byte big-endian extended length; the header is
  16 bytes. If it is `0`, the box extends to the end of the enclosing region.
  Otherwise the header is 8 bytes.
- Read a 4-byte ASCII type.
- The payload is the bytes between the end of the header and the box end.

A length smaller than the header length is an error. `parseJumbfBoxes` reads
sibling boxes while at least 8 bytes remain and stops on a box that does not
advance the cursor.

### 4.2 Description box

A description box of type `jumd` MUST be at least 17 bytes:

- Bytes 0 through 15 are the 16-byte type UUID, formatted as the canonical
  `8-4-4-4-12` hex string.
- Byte 16 is a toggle byte.
- If bit 0 of the toggle byte is set, the label is the ASCII bytes from byte 17
  up to the first `0x00` (or to the end if there is no NUL).

The `jumd` type constant is `6a756d64`. The `jumb` type constant is `6a756d62`.
This implementation does not require a description box to carry any particular
UUID for the manifest store; it identifies structures by box type (`jumb`,
`jumd`) and by label (section 4.4).

### 4.3 Superbox

A box of type `jumb` is a superbox. Its payload MUST begin with a description
box. The superbox's `content` is the payload after the description box, and its
child boxes are the siblings parsed from that remainder. A superbox's `payload`
(used below for assertion hashing) includes the description box; its `content`
does not. The well-known description UUIDs recorded for reference are:

| Structure | UUID |
|---|---|
| Manifest store | `63327061-0011-0010-8000-00aa00389b71` |
| Claim | `63326d61-0011-0010-8000-00aa00389b71` |
| Signature | `63327367-0011-0010-8000-00aa00389b71` |
| Assertion store | `63326173-0011-0010-8000-00aa00389b71` |

### 4.4 Manifest store and manifests

`parseManifestStore` considers each top-level box of type `jumb`. Its direct
child boxes of type `jumb` whose label contains `urn:uuid:` are manifests. A
store with no such child is skipped. Each manifest is parsed with:

- The claim box is the first child whose label starts with `c2pa.claim`. A
  manifest without one is an error.
- The signature box is the first child whose label starts with
  `c2pa.signature`. A manifest without one is an error.
- The chain is the COSE `x5chain`, each certificate parsed as in section 9.

### 4.5 Claim, signature, and assertions

The claim is the inner content of the claim box. The signature is the inner
content of the signature box. The assertion list is collected from the manifest
box:

- If a child box is labeled exactly `c2pa.assertions` (the assertion store), its
  children are the assertions.
- Otherwise the direct children whose labels start with `c2pa.` but not
  `c2pa.claim` or `c2pa.signature` are the assertions.
- The result is filtered again to exclude claim and signature boxes.

Each assertion has a label, its box, and a decoded value. The inner content of a
box is the content of its first child when that child's type is `cbor`, `json`,
`bidb`, or `bfdb`; otherwise the box's own content. An assertion value is
decoded from that inner box: CBOR for `cbor`, `JSON.parse` for `json`, and
`undefined` for anything else.

## 5. CBOR decoding

### 5.1 Types

`decodeCbor` reads one item and requires the input to be fully consumed;
trailing bytes are an error. The decoder supports:

| Major type | Result |
|---|---|
| 0 | non-negative integer |
| 1 | negative integer |
| 2 | byte string (`Uint8Array`) |
| 3 | UTF-8 text string |
| 4 | array |
| 5 | map (`Map`) |
| 6 | tag: decoded, then unwrapped to its inner value |
| 7 | only `false`, `true`, `null`, and `undefined` |

Floating-point items and other simple values in major type 7 are not supported
and raise an error. A default nesting depth of 64 applies.

### 5.2 Indefinite lengths

Additional information `31` introduces an indefinite-length item for major types
2, 3, 4, and 5, terminated by the break byte `0xFF`:

- Indefinite byte strings concatenate their chunks. Each chunk MUST be a byte
  string; otherwise decoding fails.
- Indefinite text strings are read with the same routine, so each chunk MUST
  also be a byte string. (The CBOR standard uses text-string chunks here; this
  implementation is stricter and rejects standard indefinite text strings.)
- Indefinite arrays and maps read items until the break byte.

A length that does not fit a JavaScript number is an error.

### 5.3 Map keys and tags

A map key that is a byte string is replaced by the string `#<hex>` in the
`Map`; this implementation does not otherwise support non-scalar keys. For
lookups, `mapGet` compares numeric keys by value. Tags are unwrapped: a tagged
item is returned as its inner value, including epoch-date, bignum, decimal
fraction, and encoded-CBOR tags. Tagged bignums are therefore byte strings, not
integers.

### 5.4 Claim fields

The claim is a CBOR map. The following fields are read:

| Field | Type | Meaning |
|---|---|---|
| `dc:title` | text | `title` |
| `dc:format` | text | `format` |
| `claim_generator` | text | `claimGenerator` |
| `claim_generator_info` | array | the first map's `name` becomes `claimGeneratorName` |
| `instanceID` | text | `instanceId` |
| `alg` | text | `alg`, defaulting to `sha256` |
| `assertions` | array | hashed URIs: `url`, `hash`, optional `alg` |
| `signature` | map | one hashed URI (parsed, not verified) |
| `created` | number | epoch seconds, converted to `createdAt` |
| `remote_manifest` | text | recorded as `remoteManifestUrl` |

The report prefers `claimGeneratorName`, then `claimGenerator`.

## 6. COSE_Sign1

### 6.1 Parse

The signature box content is decoded as a CBOR array of four elements:
`[protected, unprotected, payload, signature]`.

- `protected` MUST be a byte string. When non-empty it is decoded as a CBOR map;
  an empty byte string means an empty protected header.
- `unprotected` is used as a map when it is one.
- `payload` MUST be a byte string or `null`.
- `signature` MUST be a byte string.

Headers read are `alg` (key 1) and `content_type` (key 3), from protected first,
then unprotected. The `x5chain` (key 33) may be a byte string holding one
certificate or an array of byte strings; certificates are collected from both
protected and unprotected headers.

### 6.2 The Sig_structure

The signed bytes are the CBOR encoding of the four-element array:

```
["Signature1", protectedBytes, external_aad, payload]
```

where `external_aad` is an empty byte string (zero length). `attest` always uses
an empty external AAD; it does not support a C2PA-specific external AAD.

### 6.3 Detached payload

If the COSE payload is `null`, the payload used in the Sig_structure is the
detached external payload supplied by the caller. During manifest verification
the caller supplies the claim bytes (the inner content of the claim box). If the
payload is neither present nor supplied, verification fails with "COSE_Sign1 has
no payload and none was supplied".

### 6.4 Algorithms

The `alg` parameter selects one of:

| COSE alg | Label | WebCrypto family |
|---|---|---|
| `-7` | `ES256` | ECDSA, SHA-256 |
| `-35` | `ES384` | ECDSA, SHA-384 |
| `-36` | `ES512` | ECDSA, SHA-512 |
| `-37` | `PS256` | RSA-PSS, SHA-256 |
| `-38` | `PS384` | RSA-PSS, SHA-384 |
| `-39` | `PS512` | RSA-PSS, SHA-512 |
| `-257` | `RS256` | RSASSA-PKCS1-v1_5, SHA-256 |
| `-8` | `EdDSA` | Ed25519 |

A missing `alg` fails with "COSE header is missing the alg parameter"; an
unrecognized value fails with "unsupported COSE algorithm". The parameters
passed to WebCrypto are:

- ECDSA: `{ name: "ECDSA", hash }`, with the curve taken from the certificate's
  named-curve OID (`P-256`, `P-384`, or `P-521`).
- RSA-PSS: `{ name: "RSA-PSS", saltLength }`, where `saltLength` is the hash
  length in bytes (32, 48, or 64).
- RSASSA-PKCS1-v1_5: `{ name: "RSASSA-PKCS1-v1_5" }`.
- Ed25519: `{ name: "Ed25519" }`.

### 6.5 ECDSA signature form

A COSE ECDSA signature is the raw fixed-width `r || s` concatenation, so it is
passed to WebCrypto unchanged. For an X.509 certificate signature (section 9),
the value is DER `SEQUENCE { INTEGER r, INTEGER s }` and is converted to the raw
form first: leading zero bytes are stripped and each integer is written
left-padded into its coordinate size (32 bytes for P-256, 48 for P-384, 66 for
P-521). An integer too large for its coordinate size is an error.

### 6.6 RSA public-key import

RSA public keys are imported from the certificate's `SubjectPublicKeyInfo`.
Because an SPKI that carries RSASSA-PSS parameters can be rejected by
`crypto.subtle.importKey`, the import falls back to a JWK built from the SPKI's
RSA modulus and exponent (`kty: "RSA"`, base64url `n` and `e`, `ext: true`).
The leading zero byte of a DER INTEGER modulus is stripped before base64url
encoding.

## 7. Assertion hashing

For every entry in the claim's `assertions` array:

1. The assertion is located by label. The label is the last path segment of the
   hashed URI after `jumbf=`; segments equal to `self` are dropped. If that fails,
   a suffix match, then a substring match, is tried.
2. If no assertion matches, the result is marked `present: false` and an
   `assertion.missing` error is recorded.
3. Otherwise SHA-256 is computed over the assertion box's **payload** — the bytes
   following the box header, which for a superbox includes its description box —
   and compared with the `hash` in the hashed URI. A mismatch records
   `assertion.hashedURI.mismatch`.

Assertions present in the manifest but not declared in the claim are reported
with `declared: false`. A `c2pa.thumbnail*` assertion is skipped silently. Any
other undeclared assertion records an `assertion.undeclared` warning. The hash
algorithm used is always SHA-256, regardless of any `alg` field.

## 8. Hard binding

The hard binding is the assertion labeled exactly `c2pa.hash.data`. Its value
must be a CBOR map with:

- `alg`: a text algorithm name, default `sha256`. It is displayed, but the
  computation is always SHA-256.
- `hash`: the asserted digest, a byte string. Missing or non-byte-string values
  record `hardBinding.invalid`.
- `exclusions` (optional): an array of maps with numeric `start` and `length`.
  When present and non-empty, these ranges are excluded. When absent or not in
  that shape, the ranges recorded by the container locator (section 3) are used
  instead.

The asset digest is computed by sorting the ranges by start, skipping each range
(clamped to the file length and merged when they overlap), and SHA-256 hashing
the remaining bytes in order. Ranges of length zero are ignored.

The result is one of:

| Status | Condition | Issue |
|---|---|---|
| `matched` | computed equals asserted | `hardBinding.matched` (info) |
| `mismatch` | computed differs | `hardBinding.mismatch` (error) |
| `unsupported` | the assertion did not decode, or only `c2pa.hash.boxes` is present | `hardBinding.invalid` (error) or `hardBinding.unsupported` (warning) |
| `missing` | no hard binding assertion at all | `hardBinding.missing` (error) |

The result also records `excludedBytes`, `assertedHash`, and `computedHash`.

## 9. Certificate chain

The chain is the certificates of the COSE `x5chain`, in order, leaf first. A
manifest with no certificate records `signingCredential.missing` (error).

For each certificate at index `i`:

- The issuer is the certificate at index `i + 1`, if any. The certificate's
  `signatureValue` is verified over its `tbsCertificate` using the issuer's
  public key and the issuer's signature-algorithm OID. A failure records
  `signingCredential.invalid` (error).
- If there is no issuer, the certificate is tested against itself. If it is not
  self-signed, the chain is noted with `signingCredential.intermediate` (info):
  the chain does not reach a self-signed root, so a root signature could not be
  checked and trust must come from a trust list. This is **not** an error and
  does not by itself make the manifest invalid.
- If the current time is before `notBefore` or after `notAfter`, the link is
  marked expired and records `signingCredential.expired` (warning).
- The fingerprint is the lowercase hex SHA-256 of the certificate's DER.

Chain validation records `subject`, `issuer`, validity window, CA flag,
fingerprint, a `signatureValid` of `true`, `false`, or `null` (unknown, for an
unresolved issuer), and expiry. The chain is not reordered and no path building
is performed. The design choice is that an unverifiable chain reaches a
non-error state: an untrusted chain is reported as untrusted through the trust
evaluation rather than as a cryptographic invalid.

## 10. Trust list

Two trust-list formats are accepted.

- **JSON.** The trimmed text starting with `{` or `[` is parsed as JSON. A
  top-level array contributes one entry per item. A top-level object contributes
  the items of the first present array among `trusted_list`, `trusted`,
  `allowed`, `entries`, and `certificates`. An entry is kept when it has at least
  one of: a fingerprint (`cert_sha256`, `certSha256`, `sha256`, or
  `fingerprint`), a subject (`subject` or `subject_dn`), or an issuer (`issuer`
  or `issuer_dn`). Fingerprints have `:` stripped and are lowercased.
- **PEM.** Every `-----BEGIN CERTIFICATE-----` block is decoded and parsed. Each
  contributes its SHA-256 fingerprint, subject, and issuer.

Evaluation walks the chain in order. The first link whose fingerprint equals the
entry's `cert_sha256` or whose subject equals the entry's `subject` marks the
result **trusted**, with that subject as the anchor. If no link matches, the
result is **untrusted** with a reason naming the list source. With no list, or a
list with no entries, the result is **unknown**. The `issuer` field is parsed but
not used for matching. A trust list that cannot be parsed is an I/O error in the
CLI (exit `3`).

## 11. Validation states and issue codes

A manifest is `invalid` when it has at least one error-severity issue. Otherwise
it is `valid`, unless the trust result is `untrusted` and `assertTrusted` was
requested, in which case it is `untrusted`.

The asset state is the aggregation:

1. No manifests: `unsigned`.
2. Any manifest invalid: `invalid`.
3. Every manifest valid: `valid`.
4. Otherwise: `untrusted`.

The complete issue set:

| Code | Severity | Raised when |
|---|---|---|
| `manifest.missing` | warning | No C2PA manifest store was found |
| `signingCredential.missing` | error | The COSE signature has no `x5chain` certificate |
| `claimSignature.validated` | info | The claim signature validated |
| `claimSignature.mismatch` | error | The claim signature did not validate |
| `signingCredential.untrusted` | warning | The signer is not on the trust list |
| `signingCredential.trusted` | info | The signer is on the trust list |
| `signingCredential.intermediate` | info | The chain does not carry the issuer of the last certificate |
| `signingCredential.expired` | warning | A certificate is outside its validity window |
| `signingCredential.invalid` | error | A chain link's signature did not validate |
| `assertion.missing` | error | A declared assertion is absent |
| `assertion.hashedURI.mismatch` | error | An assertion's payload hash differs from the declared hash |
| `assertion.undeclared` | warning | An assertion is present but not declared |
| `hardBinding.invalid` | error | The `c2pa.hash.data` assertion did not decode or has no hash |
| `hardBinding.matched` | info | The asset matches the hard binding |
| `hardBinding.mismatch` | error | The asset does not match the hard binding |
| `hardBinding.unsupported` | warning | Only a `c2pa.hash.boxes` binding is present |
| `hardBinding.missing` | error | There is no hard binding assertion |

The CLI exit code is `0` for `valid`; `1` for `invalid`, `unsigned`, or
`untrusted` under `--require-trusted`; and `2` or `3` for usage and I/O errors.

## 12. Provenance card

`toCard` projects a verification into a portable card:

```
{
  version: "attest/card/1",
  asset: { sha256, size, container? },
  state,
  manifests: [ { label, title, generator, format, instanceId,
                 signature, trust, hardBinding, actions, ingredients,
                 chain: [ { subject, fingerprint } ] } ],
  issuedAt: ISO-8601 string
}
```

`cardId` is the lowercase hex SHA-256 of the canonical JSON of the `version`,
`asset`, `state`, and `manifests` members, in that order; `issuedAt` is excluded
so the id is stable across runs. `serializeCard` is compact JSON on one line.

A registry is a JSON Lines file. `parseRegistry` ignores blank lines, lines that
do not parse, and lines whose `version` is not `attest/card/1`. `resolveByHash`
matches `asset.sha256`, accepting an optional `sha256:` prefix and comparing
case-insensitively. `matchCard` reports a match only when the file hash, the
file size, the active manifest label, the hard binding asserted hash, the
signature validity, and the presence of a manifest all agree with the card.

## 13. Out of scope

The following are explicitly not implemented:

1. BMFF / ISO base media formats (HEIF, AVIF, MP4) and any container other than
   JPEG, PNG, WebP, or raw JUMBF.
2. `c2pa.hash.boxes` and any box-hash hard binding. It is reported as
   `hardBinding.unsupported`.
3. OCSP and CRL revocation checking of any kind.
4. Fetching a `remote_manifest`; only the embedded store is inspected.
5. Consulting a platform or OS trust store. Trust comes only from `--trust`.
6. Verifying an ingredient manifest or thumbnail referenced by an ingredient.
7. Validating the semantics of any assertion (schema.org, action vocabulary,
   thumbnails, ingredient metadata).
8. CAWG identity assertion validation.
9. Hash algorithms other than SHA-256, and honoring the `alg` fields for hashing.
10. Certificate path building, issuer/subject matching between chain links,
    name constraints, certificate policies, or key-usage enforcement.
11. Verifying the claim's `signature` hashed URI.
12. Creating or signing manifests.
13. C2PA-specific external AAD in the COSE Sig_structure (the external AAD is
    always empty).
14. Canonical or deterministic CBOR checks; any valid decode is accepted.
15. Decoding CBOR floating-point items, and standard indefinite-length text
    strings.
16. Revocation of, or transparency logging for, the signing certificate.

## 14. Conformance

The conformance corpus is `fixtures/`. The reference asset is
`fixtures/C2PA-signed.jpg`, taken from the `c2pa-rs` test fixtures
(`contentauth/c2pa-rs`, `sdk/tests/fixtures/C.jpg`). It is a test image produced
by `make_test_images` 0.33.1 and signed with a C2PA test certificate whose chain
does not include the issuer of its intermediate CA.

Verified properties of this fixture:

- The container is `jpeg`; the manifest store is in one APP11 segment. The
  exclusion range is 45,884 bytes, covering that segment.
- The manifest label is
  `contentauth:urn:uuid:b2b1f7fa-b119-4de1-9c0d-c97fbea3f2c3`.
- The claim signature is `PS256` and validates against the leaf certificate.
- The hard binding is `sha256` and matches; the file's SHA-256 is
  `a2d14755db55de67a47c04090340d8266e892367be4104a45626d7a6fa6e9ffd`.
- Four assertions are declared and all four hash correctly:
  `c2pa.thumbnail.claim.jpeg`, `stds.schema-org.CreativeWork`, `c2pa.actions`,
  and `c2pa.hash.data`.
- One action is recorded: `c2pa.created` by `Make Test Images 0.33.1`.
- The chain has two certificates (the signer and its intermediate CA). The
  intermediate's issuer is not present, so `signingCredential.intermediate`
  (info) is raised, the asset state is `valid`, and trust is `unknown` with no
  trust list.
- Changing a single byte of the scan data flips the hard binding to `mismatch`,
  the asset state to `invalid`, and the exit code to `1`, while the claim
  signature still validates. This proves the hard binding is load-bearing
  independently of the signature.

Any implementation reading these bytes MUST reach the same state and issue
codes. The fixture is a conformance input; it MUST NOT be edited or regenerated.
