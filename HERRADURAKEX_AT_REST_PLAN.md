# HerraduraKEx At-Rest Encryption Plan

This note defines the initial implementation direction for using algorithms
from the HerraduraKEx cryptosuite inside CaumeDSE. The scope is internal data
encryption at rest for protected values stored in SQLite-backed databases and
protected file parts. TLS channel encryption, HTTPS certificates, and transport
authentication remain handled by the existing web/TLS stack.

## Local Storage Crypto Baseline

CaumeDSE currently protects stored values through OpenSSL EVP wrappers in
`crypto.c`:

- `cmeProtectByteString()` calls `cmeCipherByteString()` to encrypt byte
  strings, then base64-encodes the encrypted bytes.
- `cmeUnprotectByteString()` base64-decodes protected bytes, then calls
  `cmeCipherByteString()` to decrypt them.
- `cmeCipherByteString()` resolves `encAlg` with `EVP_get_cipherbyname()`,
  derives key and IV material with `cmePBKDFProfile()`, and handles GCM tag
  append/verify when the OpenSSL cipher is a GCM mode cipher.
- New protected data uses PBKDF2-HMAC-SHA256 with
  `cmeDefaultPBKDFCount`. Decryption can retry the legacy PBKDF2-HMAC-SHA1
  profile for older protected values.
- `cmeHMACByteString()` uses the key length of `cmeDefaultEncAlg` for HMAC
  key derivation and currently uses OpenSSL HMAC/SHA-256 by default.

Storage paths that depend on this behavior include:

- ResourcesDB, RolesDB, LogsDB, and secure metadata values created through
  `cmeProtectDBValue()` and `cmeProtectDBSaltedValue()`.
- ColumnFile DB `meta` values for column attributes and attribute data.
- ColumnFile DB `data` values, including `value`, `MAC`, and
  `MACProtected` columns.
- Raw-compatible file parts encrypted by `cmeRAWFileToSecureFile()` and read
  back by `cmeSecureFileToTmpRAWFile()`.
- Protected lookup values in ResourcesDB, which are deterministic HMAC values
  and should remain separate from randomized storage encryption.

## Non-Goals

The first HerraduraKEx implementation must not change these areas:

- TLS ciphersuites, HTTPS certificate generation, or libmicrohttpd/GnuTLS
  transport behavior.
- Client authentication, certificate validation, OAuth delegation, or
  per-request authorization.
- Public-key document sharing or recipient encryption.
- Signature workflows.
- Existing OpenSSL EVP algorithm names and behavior for already-encrypted
  databases.
- Automatic migration of existing AES-protected SQLite data.

## Upstream HerraduraKEx Findings

Primary upstream sources reviewed:

- `https://github.com/Caume/HerraduraKEx`
- `https://github.com/Caume/HerraduraKEx/blob/master/README.md`
- `https://github.com/Caume/HerraduraKEx/blob/master/llms.txt`
- `https://github.com/Caume/HerraduraKEx/blob/master/spec/herradura-protocol-spec.json`
- `https://github.com/Caume/HerraduraKEx/blob/master/docs/INTRODUCTION.md`
- `https://github.com/Caume/HerraduraKEx/blob/master/docs/TUTORIAL.md`
- `https://github.com/Caume/HerraduraKEx/blob/master/herradura.h`

Reviewed upstream reference:

- `Caume/HerraduraKEx` `master` commit
  `13e5fb0346ca5ec81202dee8bb3302633780ec35`.

Relevant implementation facts:

- The repository provides a header-only C API in `herradura.h`.
- The current FFI shim exposes the classical HKEX-GF, HSKE, HPKS, and HPKE
  quartet, but not the NL/PQC or Stern APIs needed for this storage plan.
  CaumeDSE should use direct C integration for the initial PQC profiles.
- `herradura.h` uses 256-bit key material for the reviewed symmetric paths.
- Upstream declares `hske-nla1`, `hske-duplex`, `hske-nla2`, `hfscx-256`,
  `hfscx-256-ds`, and `hkex-rnl` as production-status primitives or
  protocols with conjectured quantum resistance in the protocol spec.
- Upstream marks classical `hske` as not quantum-resistant.
- Upstream marks Stern-based HPKE/HPKS flows as demo-only or dependent on
  production decoder/round requirements. They are not appropriate for the
  first CDSE storage implementation.
- The repository license metadata is non-standard. Build integration must
  complete a license compatibility review before vendoring or linking.

## Algorithm Recommendations

### Primary Candidate: `herradura-hske-nla1-aead-256`

Use this as the first PQC-oriented storage encryption candidate if CDSE tests
confirm the upstream C function handles arbitrary-length protected values:

- Upstream API of interest: `hske_nl_aead_encrypt()` and
  `hske_nl_aead_decrypt()`.
- Fit for CDSE: randomized AEAD maps closely to the existing AES-GCM storage
  model where encrypted bytes are stored with an authentication tag.
- Required CDSE checks: round-trip variable-size fields, empty fields,
  multi-kilobyte raw file parts, modified nonce, modified tag, modified
  ciphertext, wrong key, wrong salt, and malformed frame.

### Variable-Length AEAD Evaluation: `herradura-hske-duplex-256`

Evaluate this as the preferred long-term profile when its C API is clearer for
arbitrary-length SQLite fields than HSKE-NL-A1 AEAD:

- Fit for CDSE: direct arbitrary-length AEAD would reduce framing and chunking
  decisions for secure DB values and raw-compatible file parts.
- Decision gate: select it only after the API is inspected, wrapped, and
  covered by the same tamper tests as HSKE-NL-A1.

### Experimental Candidate: `herradura-hske-nla2-256`

Keep this as an experimental profile:

- Fit for CDSE: may be useful where a reversible permutation-style construction
  is intentionally desired.
- Limit: do not make it the default storage profile unless a concrete storage
  use case and integrity construction are documented.

### Hash/MAC Candidates: `hfscx-256` and `hfscx-256-ds`

Treat these as candidates for Herradura-native MAC or domain-separated integrity
work after the AEAD storage frame is stable:

- Existing compatibility path: keep `cmeHMACByteString()` and
  `cmeDefaultMACAlg` behavior unchanged in the first implementation.
- Future option: evaluate domain-separated `hfscx-256-ds` for new
  Herradura-only metadata once mixed AES/Herradura databases are supported.

### Deferred: `hkex-rnl`

Do not use HKEX-RNL for direct SQLite field encryption:

- Fit for CDSE: future key-wrapping, offline key-establishment, or
  organization-key rotation workflows.
- Initial storage plan: not needed because CDSE already receives an
  organization key for at-rest encryption and does not need a transport
  key-exchange change.

### Excluded From Initial Storage Use

Do not implement these as initial CDSE storage algorithms:

- `hske`: upstream marks it classical, so it does not satisfy the PQC-oriented
  storage goal.
- `hkex-gf`: key exchange, not direct at-rest encryption, and not the target
  PQC storage primitive.
- `hpke`, `hpke-nl`, `hpke-stern`, `hpke-stern-kem`: public-key encryption or
  KEM flows are not needed for direct SQLite value encryption.
- `hpks`, `hpks-nl`, `hpks-stern`, WOTS, XMSS, and ring signatures:
  signature algorithms do not encrypt stored data.
- Stern-based production paths: upstream documentation says production use
  depends on decoder or round settings that are not suitable for this first
  CDSE storage profile.

## Storage Design Direction

Future implementation should add a storage crypto profile abstraction before
calling HerraduraKEx directly from existing EVP-only paths.

Profile metadata should include:

- Algorithm id, for example `herradura-hske-nla1-aead-256`.
- Provider id, for example `openssl-evp` or `herradurakex`.
- Key length, nonce length, salt length, tag length, and AEAD support flag.
- Ciphertext frame version.
- Whether the profile is allowed as a default algorithm.
- Whether the profile is compiled into the current binary.

Herradura ciphertexts should use a new protected-value frame so they cannot be
confused with existing OpenSSL ciphertexts. A candidate binary layout is:

```text
CDSEHKX1 || profile_id || flags || nonce || tag || ciphertext
```

The existing outer storage behavior should remain compatible:

- The encrypted frame is still base64-encoded by the protect helpers.
- The per-record hex salt remains stored in the existing SQLite salt column.
- Existing AES-GCM records remain readable.
- Herradura-protected records require a Herradura-enabled binary.

Associated data should bind stable storage context without making normal
updates impossible. Candidate associated data fields:

- Profile id.
- PBKDF profile id.
- Hex salt.
- Database role, such as ResourcesDB, RolesDB, LogsDB, ColumnFile meta, or
  ColumnFile data.
- Stable table and column names.
- Stable document, storage, organization, or column identifiers where they are
  immutable for the lifetime of the protected value.

Avoid mutable associated data such as last-modified timestamps, row ordering
that may be rewritten, transport request parameters, or values that are not
available on every decrypt path.

## Compatibility and Migration Rules

Initial HerraduraKEx support should be opt-in:

- Default builds continue to use OpenSSL EVP and `aes-256-gcm`.
- Herradura profiles are rejected when the binary lacks HerraduraKEx support.
- Existing SQLite databases are not rewritten automatically.
- Mixed AES/Herradura data should be allowed only when metadata records the
  exact algorithm used for each protected value or protected dataset.
- Failure messages should distinguish unsupported algorithm, missing provider,
  corrupted frame, authentication failure, and KDF/salt errors.

## Verification Requirements

The first implementation batch should add tests before enabling the profile in
normal flows:

- Unit or DEBUG component tests for profile lookup and frame parsing.
- Round-trip encryption/decryption for empty, short, and multi-kilobyte values.
- Negative tests for wrong org key, wrong salt, modified nonce, modified tag,
  modified ciphertext, truncated frame, and unsupported profile id.
- Mixed-profile tests proving current AES-GCM values remain readable.
- Live verifier coverage that proves data can be uploaded and read normally
  while the SQLite-protected bytes are not plaintext.
- HTTP and HTTPS live verifier coverage only to confirm ordinary API behavior;
  no TLS algorithm changes should be tested or introduced.

## Implementation Order

1. Add optional build integration and license-gated dependency handling.
2. Add storage crypto profile metadata and dispatch.
3. Add Herradura frame encode/decode helpers.
4. Add `herradura-hske-nla1-aead-256` wrappers and DEBUG tests.
5. Evaluate `herradura-hske-duplex-256` against the same tests.
6. Add metadata/configuration safeguards.
7. Add live verifier coverage.
8. Document operational guidance and rollback behavior.

## Build Integration Status

CaumeDSE provides an opt-in configure path for HerraduraKEx provider checks:

```sh
./configure --enable-HERRADURAKEX --with-herradurakex=/path/to/HerraduraKEx
```

The path may point either at the repository root containing `herradura.h` or at
an include directory containing `herradura.h`. The default build does not look
for HerraduraKEx and does not enable any Herradura algorithm names.

When enabled, configure verifies:

- `herradura.h` is available.
- `KEYBITS` is 256.
- `KEYBYTES` is 32.
- `hske_nl_aead_encrypt()` and `hske_nl_aead_decrypt()` are exposed by the
  header.

This integration intentionally does not vendor upstream code yet. Vendoring or
linking must wait for the license compatibility review because the upstream
GitHub metadata reports a non-standard license. Runtime Herradura encryption is
also intentionally deferred to the later storage profile and wrapper TODOs.
