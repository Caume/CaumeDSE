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
  `ad42138af14a40eb3b47127872f39509723c789f` (v9.5.23).
- Historical storage/vector reference:
  `13e5fb0346ca5ec81202dee8bb3302633780ec35` (pre-5.0.0).

Relevant implementation facts:

- The repository provides a header-only C API in `herradura.h`.
- CaumeDSE uses the direct header-only C API, not the FFI shim.
- `herradura.h` uses 256-bit key material for the reviewed symmetric paths.
- Upstream classifies `hske-nla1`, `hfscx-256`, and `hfscx-256-ds` as production
  under explicit conjectured assumptions. `hske-duplex` and `hske-duplex3` are
  research; `hske-nla2` and `hske-nla3` are demo-only. Newer v3 variants are
  considered but deliberately not enabled for at-rest writes.
- Upstream marks classical `hske` as not quantum-resistant.
- Upstream marks Stern-based HPKE/HPKS flows as demo-only or dependent on
  production decoder/round requirements. They are not appropriate for the
  first CDSE storage implementation.
- Current upstream declares dual GPLv3/MIT licensing. The header is supplied
  externally; this integration does not vendor upstream code.

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

### Legacy Migration Only: `herradura-hske-duplex-256`

Upstream v5.0.0 changed the v2 permutation and broke old duplex ciphertexts.
The existing `CDSEHKX1` profile id 2 is reserved for the original construction.
New writes and default selection are rejected. Readback is enabled only when
configure reproduces the historical known-answer tag. Current headers fail
that probe and reject legacy frames before invoking the changed algorithm.
Re-protect all legacy duplex values to AES-GCM or HSKE-NL-A1 with a compatible
pre-5.0.0 header and verify complete readback before upgrading. Back up data first.
The current duplex and duplex3 constructions are research, so neither gets a
new writable storage profile in this change.

### Experimental Candidate: `herradura-hske-nla2-256`

Keep this as an unimplemented, demo-only metadata profile:

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

CaumeDSE now has a storage crypto profile abstraction before calling
HerraduraKEx directly from existing EVP-only paths. The current abstraction
resolves existing OpenSSL EVP algorithm names dynamically and exposes guarded
HSKE-NL-A1 wrappers, compatibility-gated legacy duplex readback, and an
unimplemented NLA2 metadata profile.

Profile metadata should include:

- Algorithm id, for example `herradura-hske-nla1-aead-256`.
- Provider id, for example `openssl-evp` or `herradurakex`.
- Key length, nonce length, salt length, tag length, and AEAD support flag.
- Ciphertext frame version.
- Whether the profile is allowed as a default algorithm.
- Whether the profile is compiled into the current binary.

Known HerraduraKEx storage profile ids:

- `herradura-hske-nla1-aead-256`
- `herradura-hske-duplex-256`
- `herradura-hske-nla2-256`

Only HSKE-NL-A1 AEAD is allowed as an opt-in default in a Herradura-enabled
build. Duplex is read-only and implemented only when the header passes the
legacy compatibility probe. Default builds reject Herradura profile names.

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
- Mixed AES/Herradura data is allowed without rewriting existing rows:
  Herradura frames carry the exact compact profile id for each protected value,
  and unframed legacy values continue to use the existing AES-GCM storage
  profile.
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
- The HSKE-NL-A1 known-answer tag and decrypt match the original storage vector.
- The legacy duplex known-answer tag determines whether profile id 2 can be read.
- Width-aware headers are initialized with `BA_INIT`; historical headers use
  the byte-array initializer. Provider cross-builds are rejected because these
  compatibility probes must execute.

This integration uses an externally supplied header. HSKE-NL-A1 encryption is
available for direct wrapper calls and as an opt-in default storage profile in
Herradura-enabled builds. Default builds reject Herradura profile names.
The pinned-header CI matrix tests both reviewed revisions and verifies their
SHA-256 digests before building. New dependency revisions require compatibility
review rather than silently changing the cryptographic construction.

## Wrapper Status

CaumeDSE has guarded HerraduraKEx byte-string wrappers for:

- `herradura-hske-nla1-aead-256`
- `herradura-hske-duplex-256`

The wrappers use a versioned binary frame:

```text
CDSEHKX1 || profile_id || flags || nonce32 || tag32 || ciphertext
```

The existing per-record hex salt is still stored outside the frame and is used
with PBKDF2-HMAC-SHA256 to derive the 32-byte Herradura key from the
organization key. Associated data currently binds the CDSE Herradura AAD domain,
algorithm id, and salt. The draft context contract below proposes stable
database/table/field binding; it is not implemented or approved for storage.

## Metadata and Configuration Status

HerraduraKEx protected values are discoverable from the stored ciphertext
frame. The `profile_id` maps to the exact Herradura algorithm used for that
value. On decrypt, CaumeDSE uses this embedded metadata instead of relying only
on the currently configured default encryption algorithm. Unframed protected
values are treated as legacy AES-GCM values, which keeps existing SQLite rows
readable when a Herradura profile is selected for new writes.

Configuration remains fail-closed:

- Default builds reject Herradura profile names because they are not compiled
  in or allowed as defaults.
- Herradura-enabled builds may set `CDSE_DEFAULT_ENC_ALG` or the config-file
  default to `herradura-hske-nla1-aead-256`. Legacy duplex cannot be a default
  or a destination for re-protection; it can only be a migration source when
  the header passes its historical compatibility probe.
- Existing AES data is not migrated automatically.
- Herradura-protected values require a Herradura-enabled binary for rollback or
  readback.

## Whole-Export Upgrade Executor

`caumedse-admin reprotect-storage` implements TODO #144 for an exact-path,
owner-only, flat offline export containing ResourcesDB, RolesDB, LogsDB and
every registered ColumnFile/raw part. See the root README for dry-run, commit
and authenticated restart/resume commands. One source key must verify all
records; mixed-key or remote deployments must first produce independently
complete supported exports. Unsupported layouts and unaccounted artifacts fail
closed rather than disappearing from migration inventory.

The executor inventories exact Herradura frame ids, verifies field/payload MACs
and existing lookups, rotates data/metadata/shuffle and raw parts, regenerates
lookups and registered file MACs, and verifies persisted target readback.
Historical duplex reads require the historical compatibility provider; use an
AES source fallback, not duplex as a runtime default. Target profile validation
refuses closeout if any legacy duplex frame remains in the confirmed export.

Protected before/after snapshots, target-key-authenticated parameter/source
bindings and synced status support restart after complete source capture. No
source mutation or automatic live publication occurs. A verified export is not
deployment-wide closeout: inventory other scopes/backups, publish DBs/payloads
consistently while stopped, preserve the staged absolute accessPath, change the
runtime default and externally managed keys, then verify operational readback.

## Draft Context Contract (#147)

Status: design review required. No production frame, API, schema, KDF or default
changes in this design PR. `TEST/herradura_context_contract.py` is an executable
serialization reference, not encryption code. Its tests show distinct AAD and
proposed dispatch behavior, not authenticated rejection by an AEAD provider.
TODO #147 remains open until review and end-to-end runtime integration pass.

### Storage-Path Inventory

| Surface | Current writers/readers | Missing stable inputs |
| --- | --- | --- |
| ResourcesDB, RolesDB, LogsDB fields | `cmePostProtectDBRegister`, `cmeGetUnprotectDBRegisters`, update/delete/search variants in `engine_interface.c`; direct registration in `engine_admin.c` | Generic SQLite handles do not identify DB role. Organization identifiers and selected fields can be encrypted; current row ids are not persistent cryptographic identities. |
| ColumnFile `meta`/`data` | `cmeMemSecureDBProtect`, `cmeMemSecureDBUnprotect`, integrity/re-protection helpers in `db.c` | Standalone in-memory DBs lack trusted document/column identity. Metadata is decrypted before its contents are available; shuffling/re-protection rewrites row ids/order. |
| Raw parts | `cmeRAWFileToSecureFile`, `cmeSecureFileToTmpRAWFileInDir` in `filehandling.c` | Filename, document identifiers and part order are insufficient immutable context; registered metadata must be available before decryption. |
| Offline export/checkpoint/readback | `storage_migration.c`, command fixtures | Schema inventory, artifact classification and checkpoints currently understand V1 profiles, not a context registry or V2 floor. Paths change between before/after snapshots. |

Every direct and indirect caller must be inventoried before enabling V2. Thread
local variables, global defaults, filenames and request parameters cannot fill
missing context implicitly. API lookup strings are not immutable identities.

### Identity And Trust

Schema 1 proposes five 16-byte binary identifiers, generated once and retained:
deployment, organization security scope, storage, resource, and record. All must
be nonzero except storage: internal DB roles require an all-zero storage value;
ColumnFile and RawPart require a nonzero storage identifier. UUID bytes are
opaque and never derived from secrets, display names, SQL ids or paths.

- Resource means the DB instance for internal DBs, the registered logical column
  for ColumnFile, and the registered logical document for RawPart.
- Record means an immutable internal row, ColumnFile meta/data row, or raw part.
  Do not use `rowOrder`, mutable `id`, part numbering or transient file names.
- Database role and canonical table/field names are assigned by the caller from
  the schema. RawPart uses synthetic table `payload` and field `bytes`.
- The caller supplies expected identifiers from an authenticated registration
  mapping scoped to an independently trusted deployment/organization identity.
  It must not accept context copied from the candidate frame or unauthenticated
  SQLite metadata. Provisioning, registry authentication and restoration remain
  review blockers, not existing supported features.

The registry must bind logical lookup/registration to expected immutable ids
before encrypted fields are read, avoiding circular use of encrypted org or
document names. Plain UUID metadata alone is insufficient. Whole-artifact or
registry substitution is not prevented if a reader trusts the attacker's whole
mapping. AAD also does not prevent replay of an authentic earlier value in the
same context; freshness requires a separately reviewed trusted policy.

Renaming paths, updating fields and shuffling rows retain ids. Copying a value
to a different organization/storage/resource/record requires decrypting under
the source context and re-encrypting under the target context. Cloning identity
or migrating deployment namespaces needs an explicit reviewed operator policy.

### Proposed Binary Encoding

All multi-byte integers are unsigned big-endian. The draft header is 80 bytes:

```text
CDSEHKX2[8] || profile[1] || flags[1] || kdf[1] || context_schema[1]
            || ciphertext_length[4] || nonce[32] || tag[32] || ciphertext[N]
```

Draft profile 1 is existing HSKE-NL-A1 AEAD-256 only; no new duplex writes or
NLA2 implementation. Draft KDF id 1 explicitly means PBKDF2-HMAC-SHA256,
10000 iterations, 16-byte decoded salt and 32-byte key. This freezes the current
Herradura wrapper parameters rather than relying on a changing compiled
default, and is not a recommendation to expand or approve that KDF policy.
Future KDF changes require a new reviewed id. Context schema is 1; flags are 0.

The proposed AAD bytes are exactly:

```text
"CDSE-HKX-AAD-v2" || NUL
|| header bytes 0..47 (magic through nonce, excluding tag)
|| decoded salt[16] || role[1]
|| deployment[16] || organization[16] || storage[16] || resource[16] || record[16]
|| table_length[1] || table[ASCII] || field_length[1] || field[ASCII]
```

Role ids: ResourcesDB=1, RolesDB=2, LogsDB=3, ColumnFile=4, RawPart=5. Names use
canonical case-sensitive schema spelling and `[A-Za-z_][A-Za-z0-9_]{0,63}`
(including role fields such as `_get`).
Do not normalize identifier/name bytes during reads. Decode the existing hex
salt strictly to 16 bytes for V2 only; preserve V1's literal salt spelling.
Lengths bound allocation before arithmetic; `N <= INT_MAX - 80`, and total input
must equal `80 + N` with no ignored trailing bytes. Zero-length ciphertext is
valid at the frame level; individual storage APIs may impose stricter rules.
Unknown profile/KDF/schema/flags, absent ids, missing context, invalid names,
truncation and inconsistent lengths fail closed before invoking the provider.

The tag authenticates ciphertext and these AAD bytes. Context is deliberately
not embedded as an authoritative value in the frame. Base64 wrapping and the
external salt column remain unchanged. Length delimiting distinguishes names
such as table/field `ab`/`c` from `a`/`bc` without separator ambiguity.

### Compatibility And Rollout Gates

1. Keep `CDSEHKX1` bytes, AAD construction and profile ids unchanged. Profile 2
   remains historical-provider migration readback only; unframed legacy AES
   handling remains unchanged in current binaries.
2. Introduce explicitly named context-aware APIs in a future reviewed patch;
   contextless APIs must reject V2, never retry V1/AES after V2 authentication
   failure. Unknown `CDSEHKX*` versions must not enter an AES fallback.
3. Authenticate a per-scope minimum-format policy independently of the candidate
   frame. Compatibility mode can read V1/AES; after verified V2 closeout the
   floor is 2 and all legacy substitutions fail. Frame version alone cannot
   prevent replacement by valid same-key legacy ciphertext.
4. Add schema/registry provisioning before V2 writes. Thread expected context
   through all inventory paths, including standalone commands, metadata reads,
   MAC checks, registration, copy/delete and debug fixtures. No runtime default
   switches until those paths can reconstruct it independently.
5. Extend migration inventories, authenticated checkpoints and target readback
   to include ids and the format floor. Preserve ids across staging/restarts,
   regenerate field/file MACs and lookups, verify all persisted artifacts, and
   refuse closeout while any artifact or registry is missing or remains legacy.
6. Gate activation on independent provider vectors and actual tag-failure tests
   for changes to every context id, role, table/field, salt and header parameter;
   include same-key cross-record/field/resource substitutions, malformed frames,
   V1/AES persisted readback, mixed formats, wrong keys, downgrade policy,
   interrupted migration and release/ASAN/UBSAN builds. Serialization inequality
   tests are necessary but do not satisfy these authentication/readback gates.

Review must settle registry ownership/authentication, identity lifecycle,
scope/floor trust and recovery before accepting this draft. The current
production wrappers still write/read V1; no V2 storage-security claim is made.

## Registry Trust And Lifecycle Reference (#147, Phase 2)

We can now make the draft's trust boundary concrete without enabling V2 writes.
I inspected the generic DB callers and the offline migration checkpoint code:
neither supplies an independent immutable registry identity to the cipher API.
The checkpoint HMAC protects one migration operation, not a live context
registry or an externally retained format floor. We must keep those authorities
separate rather than treating existing checkpoint authentication as sufficient.

### Ownership Decision

I recommend extending the existing external-manager boundary to own the registry
authentication key and current anchor. The anchor contains deployment and
organization ids, generation, minimum format, and SHA-256 of the canonical
snapshot. It arrives over an independently authenticated manager channel, never
from the storage export, candidate frame, snapshot envelope or request arguments.

We considered three options. A storage-local authenticated file is the simplest
baseline, but a valid older file and its colocated anchor can be replayed together.
An external-manager anchor prevents that storage-only replacement when the
reader obtains the current anchor independently. A new dedicated registry
service offers a separate authority and operational owner, but adds another
service and recovery dependency before the project has any V2 storage callers.

| Dimension | Local file and anchor | Existing external manager (recommended) | New registry service |
| --- | --- | --- | --- |
| Security | No independent rollback floor | Independent pinned snapshot; compromised manager remains trusted | Similar pinning, separate privileged authority |
| Latency | Local read/hash | Authenticated anchor retrieval or reviewed lease | Additional service hop |
| Memory | Snapshot/index | Snapshot/index plus anchor state | Same reader state plus service resources |
| Availability | Local files only | Deny V2 operations when no current valid anchor is available | Additional outage dependency |
| Operations | Easy backup, unsafe colocated recovery | Key, generation and independent-anchor recovery procedure | New deployment, monitoring and recovery owner |
| Compatibility | Cannot meet proposed trust invariant | Additive manager contract; V1 stays readable until closeout | More integration work for the same initial invariant |

These costs are source-derived expectations, not measured benchmarks. We should
measure full-scope snapshot verification memory, registry size, anchor lookup
latency and failed-manager behavior before choosing caching or a lease. A new
service becomes preferable if existing managers cannot protect monotonic state
or authenticate scope-bound anchors. We have not approved a manager protocol or
implemented a service in this patch.

### Reference Authentication Contract

`TEST/herradura_registry_contract.py` implements synthetic registry issuance,
authentication, pin verification and context lookup. It uses the standard-library
HMAC-SHA256 implementation, not a new MAC. Its separate 32-byte random registry
key must not be an organization encryption key, password or migration key.
Production provisioning, protected key transport and key rotation remain future
integration work; this test module must not become production key handling.

The snapshot is schema 1 canonical ASCII JSON: sorted object keys, compact
separators, entries sorted by immutable lookup handle, lowercase 16-byte hex ids,
and exactly these fields: `schema`, `deployment`, `organization`, `generation`,
`minimumFormat`, `entries`. Each entry contains `lookup`, `state`, `context`.
Contexts use the complete frame contract. The tag is HMAC-SHA256 over
`CDSE-HKX-REGISTRY-v1` followed by NUL and the canonical snapshot bytes.
Verify size, tag, external digest pin, canonical encoding, namespace, generation
and format floor before exposing any expected context. Snapshot size is at most
1 MiB, at most 4096 entries, and lookup handles are bounded ASCII opaque handles
of length 1..128, not filesystem paths or plaintext values decrypted from a row.
Duplicate lookups/contexts, foreign namespaces and extra fields are rejected.

The external manager must retain and atomically compare-and-swap the current
anchor. A verifier holding the symmetric key can calculate tags; it cannot
authorize a different snapshot without an independently updated digest pin.
The reference returns an anchor to the issuer for testing, but that return value
is not authority to install the anchor at a reader. HMAC alone does not prevent
rollback. Trusting an old authentic anchor permits old snapshots by definition.

### Identity State And Commit Ordering

We preserve immutable lookup-to-context registrations across exact consecutive
generations. Registration starts active; deletion retains a revoked tombstone.
Revoked handles cannot be revived, removed or assigned a different context.
Duplicate contexts cannot be reintroduced under another handle. The reference
checks registration transitions, not a complete UUID allocator or resource-wide
tombstone catalog; those are required before runtime provisioning can claim
never-reused identities across all fields and resources. Mutable display aliases
must be a separately authenticated manager mapping, not changed context handles.

An update prepares a new snapshot under the manager's serialization lock, syncs
it durably, then atomically advances the independently protected anchor by one
generation. Publishing an anchor before its snapshot is durable is forbidden.
Readers obtain the current anchor and open exactly its pinned snapshot. A crash
before anchor publication leaves the previous snapshot authoritative; staged
orphans can be discarded. A crash afterward requires the pinned snapshot or
fail-closed recovery, not silently adopting a previous generation.

The floor starts at 1 for compatible reads. Raising it to 2 requires complete
authenticated V2 artifact inventory/readback; it never decreases in normal
operation. The reference enforces monotonicity but does not implement or validate
that inventory proof. Revocation and rollback protection depend on obtaining a
fresh manager anchor for each new operation; an old in-memory registry cannot
detect a newer anchor by itself. A future lease needs explicit expiry, operation
rechecks and revocation semantics, not indefinite successful-cache fallback.

Recovery restores registry, key and current anchor together from independently
protected state. If the current generation cannot be recovered, operators must
stop V2 access and perform explicit reviewed reprovisioning/re-encryption into a
new namespace. Key rotation reauthenticates a pinned snapshot and requires an
independently authenticated key-id transition; it is not implemented here.

### Current Runtime Protection And Remaining Work

The C dispatcher now rejects unsupported/truncated `CDSEHKX*` frames with error
33 before the AES fallback path. Existing valid V1 and unframed legacy AES paths
outside the reserved `CDSEHKX` prefix remain unchanged. The ownership fixture repeats V2, unknown-version and truncated
V1 rejection with no returned plaintext or allocated output. This guard does not
implement V2 encryption, registry lookup or provider tag verification.

Twelve registry tests exercise real HMAC/pin rejection, foreign namespaces,
same-generation alternate snapshots, rollback/floor policy, immutable context,
revocation, canonical encoding and bounds. These prove the reference's tested
transitions only. Next integration must define the concrete manager anchor API,
durable CAS and allocation catalog; thread verified contexts through every
storage caller; implement reviewed V2 provider operations and persisted migration
readback; and test cross-context tag failures with independent provider vectors.
TODO #147 stays open until those production integration gates pass.

## C Reader Boundary (#147, Phase 3)

`context_registry.h` now defines an additive internal C reader API. No HTTP route,
configuration switch or storage caller activates it. Existing V1/AES operations
remain unchanged, and contextless cipher APIs still reject V2. This is a reader
boundary, not production registry provisioning or an approved V2 write path.

### Manager Adapter Contract

`cmeContextRegistryOpen` takes the expected deployment/organization scope, the
candidate snapshot/tag, a separately provisioned 32-byte registry key, and a
trusted `cmeContextAnchorFetch` callback with an opaque manager argument. The
callback must obtain the current independently authenticated anchor on **each
open** and return zero only on success. The anchor contains binary 16-byte scope
ids, a nonzero unsigned 64-bit generation, floor 1 or 2, and a 32-byte SHA-256 pin.
The C reader rejects mismatched callback scope, invalid generation/floor, callback
failure, wrong HMAC or a snapshot that differs from the pin before parsing JSON.
The domain and canonical bytes match the phase-2 Python reference exactly.

The callback is a trusted in-process adapter, not an untrusted plugin or an HTTP
request hook. Do not derive its anchor or registry key from candidate bytes,
SQLite storage metadata or caller-supplied request arguments. A callback that
returns an old authentic anchor authorizes old state by definition; the C library
cannot prove manager freshness. The manager still needs an authenticated transport,
durable monotonic CAS, independently protected recovery and key provisioning.
None of those services is implemented or automatically contacted here.

Each successful open returns an opaque operation-scoped handle. The caller must
free it with `cmeContextRegistryFree` at operation completion and open again for
the next operation. Do not keep handles as indefinite successful caches. A
revocation published during a long operation does not invalidate an existing
handle; operation boundaries, cancellation/rechecks and any lease require review
before storage integration. Freeing null handles is safe and nulls the pointer.

### Parsing And Lookup

The reader uses the linked SQLite JSON parser, not a bespoke JSON parser. If
JSON support is absent, parsing fails closed; existing non-registry workflows
do not acquire a new runtime dependency. Snapshots are limited to 1 MiB and 4096
entries. After HMAC/pin verification, exact field/type checks reject extra or
duplicate keys, foreign namespaces, invalid identities/names/roles and invalid
registration states. Reconstructing canonical JSON and comparing it byte for
byte rejects whitespace, escapes, alternate number spellings, unsorted or
duplicate lookup handles and mismatched generation/floor. A sorted context index
rejects duplicate contexts even under different handles or revoked entries.
The full uint64 generation is compared through canonical reconstruction rather
than a lossy SQLite numeric conversion.

`cmeContextRegistryLookup` uses the immutable lookup handle, not a filename or
decrypted row value. It copies the five binary ids, role, table and field into
`cmeStorageContext` and returns the trusted format floor only for active entries.
Missing, invalid or revoked handles clear both outputs and fail. Handles own
their verified contexts; mutating or releasing the candidate snapshot afterward
cannot change a lookup. This API returns policy; it does not apply that floor to
legacy decrypt calls or authenticate V2 ciphertext on its own.

Opening a reader validates one current snapshot, not an issuance transition.
Immutable identity allocation, consecutive publication, nondecreasing floors and
irrevocable tombstones remain the manager issuer's responsibility. The Python
reference tests those transitions; the C reader relies on the independently
trusted current anchor, rather than trying to infer history from candidate data.

`test_context_registry.sh` is part of `make check`. Its synthetic C manager
adapter is check-only and never installed. Python reference-issued snapshots
exercise real C HMAC/pin verification, exact schema/canonical rejection, scope,
all roles, missing/revoked entries, owned output, manager failure and uint64
generation boundaries. The fixture's command arguments are test authority, not
a production provisioning interface. These tests do not prove V2 provider
authentication or complete UUID/resource lifecycle support. #147 remains open
for manager integration, provisioning, V2 provider/storage plumbing and persisted
cross-context authentication/legacy-readback tests.

## Local Manager Publication (#147, Phase 4)

`context_manager.h/.c` adds a trusted in-process owner implementation and a
`cmeContextManagerFetch` adapter for the reader callback. It is not a network
manager, authenticated transport, installed provisioning command or connection
to existing storage/web routes. The separate 32-byte registry key is supplied
by the owner and cleansed on close; it is never persisted in this database.
Callers must finish concurrent operations before close and keep publication
inputs unchanged during a call.

The manager requires a preexisting canonical uid-owned mode-0700 directory,
protected against rename, outside every CaumeDSE storage export. Its fixed
`registry.sqlite` must be a uid-owned mode-0600 regular file with one link;
symlinks, replaced files and missing authority fail closed. Parent-path safety,
same-uid isolation, backups and key custody are operator responsibilities.
Creation is explicit and exclusive; reopening never creates a database. Failed
initialization can leave an unusable file requiring owner review, not automatic
repair, overwrite or reset.

Unlike the separate-file publication ordering described in phase 2, this local
implementation stores the canonical snapshot, HMAC and full current anchor in
one SQLite transaction. It requires DELETE journaling and synchronous EXTRA,
syncs the directory after initialization, and uses BEGIN IMMEDIATE to serialize
publishers. An initialized marker is committed with the first publication;
deleting the current row later cannot silently reinitialize generation 1.
These durability guarantees depend on SQLite and the filesystem honoring sync.

An approved issuer supplies already canonical authenticated bytes and a proposed
anchor. The manager verifies them with the C reader before publishing. Initial
publication requires generation 1 and floor 1. Later publications compare the
entire previous anchor, advance generation by exactly one without overflow,
retain all prior lookups and contexts, forbid revival of revoked entries, and
never lower the format floor. New identities still require an approved allocator
and resource lifecycle. Raising the floor to 2 still requires issuer approval
based on a complete V2 inventory proof; this API does not produce or validate
that proof and does not enable V2 writes.

`cmeContextManagerPublish` returns 0 on success, 2 on CAS conflict and 1 on
invalid/unavailable state. After an uncertain commit or lost acknowledgement,
refresh current state and reconcile the proposed anchor; do not blindly retry
or reset authority. Snapshot export returns owned candidate bytes, not reader
authority. Each reader open must fetch the independently current manager anchor;
the adapter reloads and authenticates committed state even on long-lived manager
handles. Already-open registry handles remain operation-scoped, not revocation
leases for future operations.

The protected manager database is the authority, independent of untrusted
CaumeDSE storage. Replaying a whole authentic manager database or host backup
is NOT detected by its own HMAC or generation column. Protect that authority
with an independent monotonic recovery policy before production use. This work
does not provide hardware rollback protection, remote owner authentication,
key rotation or automatic backup recovery.

The check-only fixture is never installed. Thirteen Python-issued C integration
tests cover bootstrap, exact CAS, generation/floor/lifecycle rules, stale and
foreign candidates, corrupt authority, private paths, concurrent processes and
fresh callbacks across two existing connections. Abrupt exits before writes,
before commit and after commit test old-or-new recovery and lost acknowledgement;
they are process-crash tests, not physical power-loss certification. Crash hooks
are compiled only into the fixture, never the engine. #147 remains open for
authenticated manager deployment, identity provisioning, V2 provider/storage
integration and persisted cross-context authentication/legacy-readback tests.

## Manager Identity Provisioning (#147, Phase 5)

`cmeContextManagerProvision` adds a trusted owner-side issuer using the existing
authenticated registry as its durable identity mapping. There is no separate
catalog or database schema migration. Deployment/organization identifiers still
come from trusted provisioning at manager open; this API allocates only their
subordinate storage, resource and record UUIDs. An external authenticated owner
must approve registration handles and their association with real resources;
untrusted API parameters, filenames and candidate-frame metadata are not owner
authority.

The explicit allocation levels are:

| Level | Required Parent | Identity Behavior |
| --- | --- | --- |
| NewStorage | None; ColumnFile or RawPart only | Allocate storage, resource and record. |
| NewResource | None for internal DB roles; active external parent for external roles | Internal storage stays zero; external storage is inherited. Allocate resource and record. |
| NewRecord | Active same-role registration | Retain storage/resource, allocate record; the canonical table may differ within the resource. |
| NewField | Active same-role, same-table registration | Retain all IDs and register another field. Duplicate contexts are rejected. |

ResourcesDB, RolesDB and LogsDB retain all-zero storage; RawPart always uses
`payload`/`bytes`. A new external resource may inherit a storage ID from either
external role, but never its resource/record IDs. No implicit cross-scope copy,
identity aliasing or clone operation is provided.

UUIDv4 values use OpenSSL `RAND_bytes`, with version/variant bits set explicitly.
They are not derived from lookup names, secrets, SQL row IDs or paths. Every
allocation checks prior IDs, including revoked registrations, and IDs generated
earlier in the same operation. RNG failure or sixteen unsuccessful collision
attempts fails closed without weak fallback. SQLite JSON APIs build structured
snapshots, with the existing C reader enforcing canonical bytes, schema,
unique contexts and size/count limits before publication commits.

Provisioning reads authenticated current state, checks the supplied full anchor,
issues the next generation and invokes the existing publication CAS. An update
between preparation and publication returns conflict; no separate ID reservation
or catalog write can survive a failed CAS. Initial provisioning requires NULL
expected state, generation 1 and floor 1. Later provisioning preserves the floor
and refuses generation overflow. Successful output is the committed context and
anchor. Failed calls clear outputs. Expected and published anchors may alias;
other inputs must not overlap outputs and must remain unchanged during a call.

`cmeContextManagerRevoke` changes exactly one active field registration into a
retained tombstone through the same CAS. It is not storage/resource-wide or
cascading revocation. Missing/already-revoked lookups fail; reuse or revival is
forbidden. Revoked parents cannot authorize new child registrations; another
active field remains independently usable. Phase 6 below adds an explicit
owner-side batch operation; this single-field API remains noncascading.

Lookup strings are stable registration handles allocated before encrypted
metadata is read, not mutable display names or paths. Renames, row shuffles and
staging must keep the original registration-to-ID mapping rather than call
provisioning again. Moving a registration into a different namespace or copying
ciphertext requires reviewed source/target context handling; it is not a rename.
There is no authenticated live mapping from current storage rows to these handles
yet, so real storage paths do not consume the new IDs in this phase.

After an interrupted or unacknowledged commit, obtain a fresh snapshot/anchor and
look up the registration before deciding whether to retry. Do not allocate a
replacement identity blindly. The low-level `cmeContextManagerPublish` API still
trusts an approved issuer to supply valid external IDs; it does not require UUID
allocator provenance and cannot make untrusted callers into trusted managers.
Existing publication-only databases and fixtures remain compatible.

The manager fixture adds fifteen identity/lifecycle tests to the previous
thirteen publication checks. Deterministic RNG/error injection, like crash hooks,
is compiled into the fixture only, never the engine. Process-crash tests do not
certify physical power-loss behavior. Whole-manager rollback protection, key
custody, authenticated owner deployment, real resource/row lifecycle mapping,
V2 provider/storage APIs and persisted context-substitution/legacy-readback tests
remain open gates for #147; no V2 write or runtime-default switch is enabled.

## Atomic Scope Revocation (#147, Phase 6)

`cmeContextManagerRevokeScope` provides a prerequisite for future resource and
storage deletion: one authenticated snapshot publication revokes every matching
registration, instead of leaving a partially revoked group after multiple
single-field calls. It is an internal trusted-owner API, not a live delete route
or a storage-to-registration mapping service. Existing storage, crypto formats
and HTTP behavior remain unchanged.

The owner supplies an active registration handle and an explicit scope:

| Scope | Match Within the Authenticated Current Namespace |
| --- | --- |
| Resource | Same role, storage UUID and resource UUID, across all records, tables and fields. |
| Storage | Same nonzero external storage UUID, across ColumnFile and RawPart resources. |

The seed context comes only from authenticated manager state. Lookup prefixes,
paths, SQL row positions, display names and caller-supplied UUIDs do not select
membership. Resource matching includes role to isolate externally issued
contexts even if an issuer reused resource bytes across roles. Storage scope
rejects internal database roles: their shared zero storage value is not a
storage identity. Missing/revoked seeds and invalid scopes fail without a new
publication. If the original field was revoked separately, an owner must select
another active field before revoking the wider group.

The operation retains every lookup and immutable context, including existing
tombstones, preserves the format floor and advances exactly one generation.
Candidate preparation uses authenticated current state and the full expected
anchor; the existing publication CAS makes concurrent child allocation and
scope revocation mutually exclusive. A conflict requires a fresh snapshot and
owner review of the expanded group before retry. A revoked parent cannot be
used by provisioning to create new children. Revocation does not prohibit an
approved low-level publisher from later adding externally issued registrations
with those IDs; enforcing permanent resource/storage bans requires a separate
policy and is not claimed here.

Return codes, cleared outputs and expected/published anchor aliasing follow the
existing provisioning contract. Generation overflow, corrupt authority and
snapshot size/count limits fail closed without partial revocation. In particular,
`revoked` is longer than `active`; a registry near the 1 MiB limit can lack room
for tombstones. Operators must reserve headroom; this phase supplies no compactor,
automatic capacity repair or tombstone deletion. Do not delete backing files
on a failed or uncertain revocation. After lost acknowledgement, refresh current
state and reconcile every intended member before continuing; do not reset the
manager or infer success from process exit alone.

Ten new fixture tests cover resource membership, both external roles, internal
database isolation, authenticated IDs rather than names, invalid inputs, output
aliasing, retained tombstones/floors, irreversible history, concurrent allocation,
stale candidates, generation overflow, corrupt authority, capacity failure and
old-or-new process-crash recovery. Crash hooks remain fixture-only. These tests
do not certify physical power-loss behavior or end-to-end V2 authentication.
Authenticated live resource/row mapping, independent whole-manager rollback
protection and the remaining V2 integration gates still keep #147 open.

## Operation-Scoped Storage Binding (#147, Phase 7)

`cmeContextManagerBind` adds the internal boundary between an approved physical
slot map and authenticated immutable contexts. The owner supplies an independently
trusted resource registration handle, expected schema role, full current anchor
and bounded array of `(lookup, table, signed-64-bit row, field)` slots. The manager
authenticates current state and checks the full anchor in one read transaction.
Every referenced registration, including the resource seed, must be active.
Slots must match the seed's deployment/organization/storage/resource and role,
and their canonical table/field names must match the registration.

The API validates an owner-approved map; it does NOT authenticate its provenance,
persist a physical map or provide a live owner adapter. The owner must approve
both the resource handle and the entire map for that anchor before calling.
Never construct it from encrypted/candidate metadata, candidate lookup columns,
filenames or HTTP parameters. Successful registry authentication proves that
registrations are current, not that a caller chose the correct physical slots.
Whole-artifact replacement or same-resource record-map substitution remains a
rollout blocker if an adapter accepts an attacker's map. No V2 path is enabled.

Within each canonical table, the map must be one-to-one between physical rows
and record UUIDs, while permitting multiple fields of the same record. Duplicate
`(table,row,field)` slots, mixed record IDs at one row, or one record split across
multiple rows fail the whole bind without a usable partial handle. Table is part
of the physical key; externally issued contexts may reuse record bytes across
different tables without making their schema-qualified contexts identical.
Two sorted indexes enforce these rules in O(n log n); lookups use binary search.
The count is bounded by 4096. Signed row extrema are supported without subtraction
overflow; adapters remain responsible for physical row/part bounds and semantics.
Partial maps are allowed: this is not a complete inventory, migration closeout
proof, candidate DB integrity check or proof of provider tag rejection.

The opaque `cmeContextBinding` owns copied contexts and slot locations, independent
of caller strings/arrays or SQLite statement lifetimes. `cmeContextBindingLookup`
accepts only the schema-qualified physical slot, not a candidate registration
handle, and copies the context and pinned format floor. The caller supplies schema
names from its trusted code, with the row/part location used only as a selector.
Invalid or missing slots clear context/floor outputs. `cmeContextBindingFree`
releases and nulls the handle; all concurrent lookups must finish before free.

Binding returns 0 on success, 2 on an obsolete full anchor and 1 on invalid or
unavailable state, with a null output handle on failure. It never provisions
identities or changes manager authority. Unrelated publications invalidate the
anchor too: refresh and obtain owner approval again, rather than infer that an
old map remains suitable. Namespace, field/table spelling, role and format floor
are never copied from a candidate frame to fill missing trusted context.

`cmeContextBindingCheck` independently reloads/authenticates current manager state
and compares the full pinned anchor: 0 current, 2 changed, 1 invalid/unavailable.
It detects updates through an already-open manager, including another connection's
revocation or an otherwise unrelated publication. It is only a point-in-time
recheck, not a lease, storage lock or atomic commit with backing-file writes.
Local lookups intentionally retain the copied operation snapshot and do not
silently refresh it. Rebind for every new operation; write/revocation ordering and
any multi-step storage transaction still need a reviewed integration policy.

Renames and offline staging preserve the owner-approved resource/registration
handles and UUIDs. A row shuffle requires an independently approved updated slot
permutation, not reprovisioning IDs or using mutable row IDs as identity. The
synthetic SQLite lifecycle fixture tests selection across filename rename,
physical row permutation and staging, deliberately ignoring candidate lookup
columns. Its plaintext fixture labels are known to the synthetic owner only;
this is not a production recipe for deriving authority from DB contents.

Seventeen new fixture checks cover copied ownership, sorted/multifield selection,
resource/storage/role isolation, schema/name/count/signed-slot bounds, duplicate
and split records, every role, revoked/missing handles, exact anchors, floor 2,
partial maps, output clearing/null handling, rechecks after publications and
corrupt authority, a valid 1024-slot map and the synthetic SQLite lifecycle.
Durable authenticated owner mapping and atomic storage lifecycle integration remain pending, along
with V2 provider/storage APIs and persisted substitution/legacy-readback tests.
TODO #147 stays open; no storage-security or physical power-loss claim is added.

## Durable Owner Maps (#147, Phase 8)

The opt-in owner-map catalog adds durable authenticated physical slot mappings
to the same protected manager SQLite database, outside every storage export.
It does not add HTTP routes, enable V2, change registry snapshot/frame formats,
or atomically commit changes to backing files. Trusted in-process owners still
approve the resource handle, map name and complete slot map; HMAC authentication
of that approval is not remote owner authentication or a substitute for access
control/key custody. Map names are stable owner handles, not candidate filenames,
request values or lookup columns read from an untrusted artifact.

`cmeContextManagerMapInit` is an explicit one-time extension of an already
initialized manager. In one SQLite transaction it adds `mapping_version=1` to
`registry_meta`, creates `context_maps`, `context_map_slots` and
`context_map_head`, and publishes authenticated empty catalog revision 1. The
persistent marker prevents a missing head/table from being treated as fresh
state. Reinitialization or implicit repair is forbidden. Existing registry-only
databases remain unchanged until the owner opts in; their existing APIs and
schema-1 registry snapshots remain compatible. Older registry-only code ignores
the extra catalog columns/tables, but cannot read or update stored maps.

The catalog has a separate `cmeContextMapAnchor`: unsigned 64-bit revision plus
SHA-256 digest. Revision is stored as an 8-byte big-endian BLOB, not a signed SQL
integer. Each publication advances it by exactly one; overflow fails closed.
`MapFetch` authenticates current registry authority and every catalog row before
returning this anchor. A valid catalog does not prove that all referenced
registrations remain active; `MapBind` performs that separate current-state
validation. Registry publications do not rewrite the catalog or its revision.

### Catalog Authentication Encoding

The HMAC-SHA256 key is the supplied registry-manager key, not an organization
password. Domain separation uses the following canonical typed encoding, with
all integers big-endian and all strings bounded ASCII:

```text
"CDSE-HKX-MAP-v1" || NUL || deployment[16] || organization[16]
|| revision[8] || retained_map_count[4]
|| each map, ordered by name using binary ASCII comparison:
     name_length[1] || name || resource_lookup_length[1] || resource_lookup
     || role[1] || active[1] || slot_count[4]
     || each slot, ordered by table, signed row value, field:
          table_length[1] || table || row[8, two's-complement]
          || field_length[1] || field || lookup_length[1] || lookup
```

Names/resource/registration lookups use the existing 1..128-byte handle grammar;
table/field names use the existing 1..64-byte schema grammar. Role is 1..5 and
active is 0 or 1. Active maps have at least one slot; tombstones have none. The
digest is SHA-256 over these same bytes. The stored head contains revision and
HMAC; readers reconstruct and authenticate the complete encoding from typed SQL
rows. Type/name/bounds violations, embedded NULs, orphan slots, bad signatures,
foreign scope and missing state fail closed. Canonical ordering is independent
of insertion order. Limits are 4096 retained names, 4096 total slots and 1 MiB of
encoded catalog bytes. A separate Python encoder checks interoperability.

### Publication And Binding

`MapStore` replaces one entire approved map. It first applies the existing
binding/schema/resource checks, then reloads current registry/catalog state in
`BEGIN IMMEDIATE` and compares both full anchors. Slot rows, catalog revision
and signature commit together using the manager's existing DELETE/EXTRA
journaling policy. There is no separately committed partial row permutation.
An existing name cannot change its resource registration handle or role.
`MapRemove` retains that name/resource/role as an irreversible tombstone and
removes its slots in the same publication. It does not revoke UUID registrations,
other owner maps or backing files. Different approved maps may represent multiple
views/staging positions of a resource; the API does not authorize identity clones.

Initialization/writes return 0 success, 2 anchor conflict and 1 invalid/unavailable
state, clearing outputs on failure. Expected/published catalog anchors may alias;
other inputs remain stable and nonoverlapping until return. Failed CAS, size/count
limits, bad binding shape or overflow roll back every candidate row. After a
lost acknowledgement, refresh both anchors and reconcile intended map membership
before deciding to retry. `MapRead` returns an owned authenticated copy of the
complete map metadata, including tombstones and references that were later
revoked, for exact membership/status comparison; free it with `MapFree`. It is
not a validated crypto binding and must never bypass `MapBind`'s active-context
checks. Do not recreate catalog authority or infer that a
backing-file change committed from the catalog transaction alone.

`MapBind` accepts an independently trusted map name and both expected anchors.
It authenticates durable map state, copies the approved slots, validates their
active resource/record/schema registrations against the expected registry, and
rechecks both anchors before returning an operation-scoped handle. A concurrent
catalog or registry publication causes failure/conflict rather than a usable
partial binding. `cmeContextBindingCheck` compares both anchors in one current
read transaction for stored bindings, including changes from other connections;
direct phase-7 bindings continue to pin registry state only. Local Lookup retains
the operation snapshot. Neither check is a lease or storage lock; rebind each
operation and coordinate writes/revocation with a reviewed storage policy.

An owner can publish an approved row permutation without allocating replacement
UUIDs. Path rename/staging keeps the stable owner map name. However, the correct
map must still be selected outside candidate metadata, and live ordering between
storage mutations and catalog publication remains a rollout blocker. This phase
does not implement a live storage adapter or an atomic two-database transaction.

The protected database is still authority. Replaying an authentic complete
catalog/head or whole manager backup is NOT detected by its own HMAC/revision;
an independently retained newer anchor detects replay only while it remains
trusted. Protect recovery with external monotonic policy before production use.
No hardware rollback resistance, owner network service, key rotation or automatic
restore/compaction is supplied. Tombstone names count toward the lifetime limit.

Nineteen new integration checks cover opt-in/backward compatibility, independent
encoding, reopen, all roles/signed slots/floors, both CAS pins, aliasing, immutable
names/tombstones, map validation, fresh cross-connection checks, corrupt/foreign
and missing authority, signed-but-invalid maps, orphan rows, revision overflow,
count/byte exhaustion, competing owners, registry revocation races and old-or-new
initialization/replacement/removal crash recovery. Process exits do not certify
physical power-loss recovery. #147 remains open for authenticated owner deployment,
live storage lifecycle ordering, V2 provider integration and persisted
cross-context substitution/legacy-readback tests.

## Offline Shuffle Recovery (#147, Phase 9)

The internal manager now coordinates one independently approved offline
ColumnFile replacement with its durable owner map. This is an explicit opt-in
facility, not a live storage adapter, shuffler or V2 encryption implementation.
Stop every reader/writer, close/checkpoint SQLite and retain exclusive ownership
until recovery is reconciled. File metadata checks are not locks or leases.
The owner must independently verify source and target contents, approve their
SHA-256 digests and supply the complete identity-preserving permutation of the
stored map's slots. Partial maps still do not prove complete file inventory.

`cmeContextManagerShuffleInit` requires both current anchors and upgrades the
catalog once, atomically, adding `shuffle_version=1`, `context_shuffles` and
`context_shuffle_slots`. Registry schema, snapshot format and frame format do
not change. Existing catalogs keep phase-8 behavior until explicit upgrade.
Older catalog implementations fail authentication afterward; registry-only
operations remain compatible. Missing or corrupt upgraded state never resets.

The v2 authenticated encoding retains the phase-8 layout with domain
`CDSE-HKX-MAP-v2\0`, followed by a four-byte job count. Jobs sort by map name
in binary order and encode: one-byte-length map name, 32-byte random job token,
one-byte state (1 prepared, 2 completed, 3 aborted), eight-byte finished revision,
two-byte-length active and staged path bytes, 32-byte source and target digests,
and four-byte target-slot count. Target slots use the phase-8 table/row/field/
lookup encoding and ordering. Numbers are big-endian; signed rows use two's
complement. Prepared finished revision is zero; receipts retain their commit
revision. The same independent HMAC-SHA-256 key and SHA-256 anchor construction
authenticate the entire encoding. Limits remain 1 MiB total encoding and 4096
map names/ordinary slots, with at most 4096 retained jobs and 4096 target slots.

`ShufflePrepare` accepts only active role-4 maps and the same set of lookup,
table and field identities. Active contexts and row/record bijection are checked
against the current registry. Source and target must be distinct approved bytes,
regular uid-owned 0600 files, no symlinks/hardlinks or SQLite sidecars, in distinct
canonical uid-owned 0700 directories on the same filesystem. Neither parent may
be the manager directory; staging must be outside every storage export (an owner
precondition, not an export-discovery check). Files are bounded to 256 MiB and
must have a rollback-format SQLite header. Header checks do not validate SQL
integrity, ciphertext, tags or equivalence of payloads to the supplied map.

Prepare verifies digest pins, fsyncs files and parent directories, then commits
the signed intent and target slots using both full-anchor CAS pins. It does not
replace the file. A pending intent blocks `MapBind`, `MapStore` and `MapRemove`
for that map and reserves both paths against other pending jobs. Authenticated
metadata reads remain available for reconciliation. Direct caller-approved
binding is not a bypass for the required offline/exclusive ownership policy.

`ShuffleRecover(..., complete=1)` rechecks both authorities and active target
contexts. If approved source bytes are active, it verifies staged target bytes,
atomically renames staged over active and fsyncs both directories. If approved
target bytes are already active after an interrupted install, it syncs the
directories and rolls forward. Only afterward does one manager transaction
replace the map and record a completed receipt. `complete=0` records an aborted
receipt only while approved source bytes remain active; it never restores the
source after target installation. Unknown/missing bytes, revoked contexts or
unsafe files leave the intent blocked for explicit operator reconciliation.
No files are automatically deleted during abort and no backup is created.

`ShuffleRead` returns owned authenticated intent/receipt metadata; free with
`cmeContextShuffleFree`. Receipts support lost-ack retries only with matching
job/mode/file digest and the exact finished catalog revision. A later catalog
change returns conflict and requires reconciliation. The next prepare on the
same active map replaces its old receipt with a fresh job token; old tokens
cannot complete a new job. Map tombstones remain permanent. Registry revocation
is independent: completion refuses newly revoked contexts before installation;
source abort can unblock metadata but does not make revoked bindings usable.

Nineteen new tests cover the independent v2 encoder, UUID preservation and real
SQLite readback, intent/receipt lifecycle, dual CAS, aliasing, path reservation,
competing recoveries, revocation, unsafe files, corruption/types/orphans, overflow,
and process crashes before/after intent commit, rename, directory sync and final
map commit. Test hooks are fixture-only. Recovery is fail-closed and forward-only,
not an atomic two-database transaction or physical power-loss certification.
The protected manager database remains authority: its own HMAC/revision does not
detect replay of a complete authentic backup. Independent monotonic recovery,
authenticated owner deployment, live storage lifecycle integration, V2 provider
integration and persisted substitution/legacy-readback tests keep #147 open.

## Offline Owner Command (#147, Phase 10)

`caumedse-admin context-shuffle` exposes the phase-9 coordinator to a trusted
local operator. It requires an existing provisioned manager and owner-map
catalog; it never initializes registry authority, provisions identities or
discovers expected context from candidate metadata. Manager key provisioning,
complete-backup rollback defense and live adapters remain separate open gates.

An independently approved JSON manifest selects the manager, deployment/scope,
map, both full anchors, source/target paths and SHA-256 pins, and target slots.
Manifest and registry-key file must be canonical uid-owned regular 0600 files,
with one link, in canonical uid-owned 0700 parent directories. Symlinks, hardlinks,
FIFOs, embedded NULs, oversized files and public control directories fail closed.
The registry-key file contains exactly 64 lowercase hex digits encoding the
separate 32-byte manager key, optionally one trailing newline. It is not an
organization password. Never supply key bytes on the command line.

Schema 1 has exactly these fields (no unknown/duplicate keys):

```json
{
  "schema": 1,
  "manager": "/private/manager",
  "deployment": "11111111111111111111111111111111",
  "organization": "22222222222222222222222222222222",
  "map": "approved-column",
  "registry": "OWNER_APPROVED_REGISTRY_ANCHOR_HEX",
  "catalog": "OWNER_APPROVED_CATALOG_ANCHOR_HEX",
  "active": "/offline/export/column.sqlite",
  "staged": "/private/staging/column.sqlite",
  "source": "OWNER_APPROVED_SOURCE_SHA256_HEX",
  "target": "OWNER_APPROVED_TARGET_SHA256_HEX",
  "slots": [["approved-record-field", "data", 20, "value"]]
}
```

The example is a field template, not a complete inventory or valid approval.
Registry anchor is 73 bytes as lowercase hex: deployment[16], organization[16],
generation[8 big-endian], minimum-format[1], digest[32]. Catalog anchor is 40 bytes:
revision[8 big-endian], digest[32]. IDs/digests/job tokens are lowercase hex.
Slots are `[lookup, table, signed-integer-row, field]`, with the existing handle/
schema bounds and at most 4096 entries. JSON strings must not contain NULs;
booleans, real/string rows, duplicate slots and malformed tuples are refused.
Manifest limit is 1 MiB. Protect its integrity outside storage exports: ownership
and file modes are the local authorization boundary, not a remote signature or
proof that a person approved the correct resource. The owner, not candidate DB
contents, must choose all pins and registration handles.

Stop every reader/writer, checkpoint and close SQLite, independently verify the
source payload, and retain exclusive offline ownership through reconciliation.
`--confirmed-offline` must exactly equal the approval's canonical absolute path.
This acknowledges the offline precondition; it cannot prove that another process
stopped writing. Manager, staged artifact, manifest and key must be outside the
active file's export directory tree. The adapter checks this one export boundary;
the owner must additionally keep control/staging files outside every other export.
Private same-filesystem artifact/parent and 256 MiB limits still apply.

```sh
caumedse-admin context-shuffle --approval "$APPROVAL" \
  --registry-key-file "$REGISTRY_KEY_FILE" --confirmed-offline "$APPROVAL" --init
# Independently reconcile the returned catalog pin and reapprove the manifest.
caumedse-admin context-shuffle --approval "$APPROVAL" \
  --registry-key-file "$REGISTRY_KEY_FILE" --confirmed-offline "$APPROVAL" --prepare
# Retain the returned job token, reconcile/reapprove the returned catalog pin.
caumedse-admin context-shuffle --approval "$APPROVAL" \
  --registry-key-file "$REGISTRY_KEY_FILE" --confirmed-offline "$APPROVAL" --status
caumedse-admin context-shuffle --approval "$APPROVAL" \
  --registry-key-file "$REGISTRY_KEY_FILE" --confirmed-offline "$APPROVAL" --complete "$JOB"
```

`--init` explicitly upgrades a phase-8 catalog once; omit it if already upgraded.
Each invocation has exactly one action. `--prepare` does not change the active
file. It authenticates the current map, validates target binding, checks approved
digests, and requires complete row coverage of both `data` and `meta`. Both files
must have the existing supported ColumnFile schema, matching table DDL and no
extra application objects, triggers, indexes, unsupported helper data or invalid
IDs. Full SQLite integrity checks must pass. Each source row is selected through
its authenticated owner slots, never candidate labels; its target row must have
the same SQLite types and values in every column except integer primary key `id`.
This includes salts, ciphertext, integrity tags and logical `rowOrder`. All map
fields must name actual non-id columns. Missing/extra rows, partial inventories,
changed cells, inconsistent mappings or excessive verification work fail before
intent publication. Verification bounds SQLite values/rows to 1 MiB, SQL to
64 KiB and approximately 20 million VM instructions per file. No decrypt/tag
verification is performed; byte equivalence preserves the independently verified
source, but does not turn an invalid source into a valid encrypted artifact.
This narrow command cannot rotate keys/tags, regenerate shuffle metadata or
replace registered ResourcesDB file MACs/lookups; do not use it for live exports.

`--status` reads an existing authenticated intent/receipt and reports state, job
and the approved catalog anchor. It does not inspect payload bytes, establish
binding usability or discover/adopt a newer trusted pin. Complete/abort require
the job token and exact agreement of the manifest's paths, digests and entire
target map with signed intent metadata, including after restart. `--abort JOB`
is allowed only while approved source bytes remain active. If target bytes are
already installed and the staged file is absent, `--complete JOB` rolls forward
using the recorded intent; retain both private parent directories for recovery.
This relies on prior trusted intent approval; it is not
an attestation that an intent created by another API was verified by this CLI.

Successful mutations emit only state, catalog token and (for prepare) job token.
The manifest is never rewritten. Retain/reconcile output, then explicitly update
and reapprove the catalog pin before the next command; reconcile registry pins
separately after registry changes. Status includes the job token for lost prepare
acknowledgements once the owner supplies the reconciled current catalog pin.
Stale valid pins return conflict (2), invalid/missing pins or unavailable state return 1, and
success returns 0. Never auto-refresh a pin from candidate metadata or restore
authority to resolve a conflict. Receipts permit exact-revision idempotent retry;
a later catalog edit requires manual reconciliation. Errors omit paths, keys and
payloads. No implicit backup, file cleanup, restore, lock/lease or V2 activation.

Eighteen command regressions use protected synthetic ColumnFiles and cover
persisted AES readback after byte-preserving data/meta shuffles, explicit pins,
approval parsing/types/limits/protection, scope/key/job mismatch, complete row
coverage, cell/schema tampering, exact receipt reconciliation, revocation and
roll-forward after the fixture interrupts atomic rename. They do not prove V2
provider authentication, independently monotonic authority or power-loss safety.
TODO #147 remains open for production trust/recovery and live lifecycle adapters,
context-aware V2 operations, migration/floor closeout and acceptance tests.

## Independent Anchor Witness (#147, Phase 11)

An opt-in local witness retains the last explicitly approved registry/catalog
anchor pair outside the manager/export/staging trees, using a separate HMAC key.
It detects a manager plus approval backup restored behind an independently
retained newer witness. This is an owner checkpoint, not a hardware counter,
remote authority, storage lock, lease or atomic two-database transaction.
Its own authentic complete backup replay is NOT detectable by the witness file
itself. Protect its directory, key and identity in an independently retained
recovery domain; merely placing a file in another directory is insufficient
against whole-host rollback. All intended writers/readers must adopt this guard.
Schema-1 approvals and direct manager APIs remain unchanged and can bypass it;
no live production or V2 security claim is added.

`context-witness` uses the same private owner approval contract as phase 10.
Schema 2 has exactly the schema-1 fields plus `"witness": "/private/witness"`.
Both witness and guarded shuffle commands additionally require:

```sh
--witness-directory "$TRUSTED_WITNESS_DIRECTORY" --witness-key-file "$WITNESS_KEY_FILE"
```

Select that directory and key from independent trusted owner configuration, never
from a candidate artifact or restored manifest. The CLI directory must exactly
match the manifest's canonical witness path; a replayed manifest cannot redirect
the independently selected checkpoint. Keep both witness flags fixed to prevent
an old schema-1 manifest from downgrading the guarded command. Changing trusted
configuration to an old checkpoint defeats this guarantee by definition.
Wrong scope or either key fails closed. Keys are separate externally provisioned
random 32-byte values (64 lowercase hex digits, optional newline), must differ,
and remain in separate private canonical 0600 one-link files under 0700 parents.
The command does not generate, transport or rotate keys, prove their entropy or
independent custody, or bootstrap registry identities. Both keys are cleansed
from owner/witness/manager memory on cleanup; diagnostics omit keys and paths.

Witness directory must be canonical uid-owned 0700, disjoint from the manager,
the active export and staging parent trees. Exact directory inode aliases with
manager/staging are rejected too. Manifest and both keys must be outside the
witness tree; both keys must also be outside the manager tree, and the witness
key outside the active export. The owner must exclude all control material from
every other export and from shared rollback backups. Filesystem path checks do
not prove independent backup policy or hardware isolation.

`context-witness --init` requires existing authenticated manager/catalog state
matching the explicit manifest pins, then provisions a new `witness.sqlite`
and durable empty `witness.initialized` marker. Existing DB/marker refuses init.
The marker is synced before DB creation, so missing or incompletely initialized
DB state cannot silently become a new witness on retry. Reopen never creates,
repairs or resets authority. A failed precommit initialization remains unavailable
for explicit operator reconciliation in a reviewed recovery procedure; do not
delete its marker or initialize another witness to bypass a recovery conflict.
Lost initialization acknowledgement after commit is reconciled with `--status`.

Both files are regular uid-owned 0600 one-link files; links, public modes,
missing/corrupt records or version/type/length mismatches fail closed. SQLite uses
FULLMUTEX, NOFOLLOW, DELETE journaling and synchronous EXTRA, with private inode
guards and mutex-protected transactions. No secrets or deployment data are
written into the witness beyond scope and non-secret checkpoint tokens.

The fixed canonical HMAC-SHA-256 encoding is:

```text
"CDSE-HKX-WITNESS-v1" || NUL || deployment[16] || organization[16]
|| witness_revision[8] || registry_anchor[73] || catalog_anchor[40]
|| previous_witness_token[40]
```

Numbers are big-endian; registry/catalog tokens use phase-10 packing. The witness
token is revision[8] plus SHA-256 of these bytes. Revision starts at 1 with a
zero previous token; subsequent records retain the previous revision/digest as
the last advance receipt. Version, singleton count and all typed BLOB lengths
are checked before interpreting/authenticating rows. The independent witness
key, not the manager key, authenticates the record in this distinct domain.

`cmeContextManagerCheckAnchors` authenticates both supplied pins in one current
manager read transaction. In schema-2 shuffle commands it runs before witness
checking, and the manager operation still performs its own full CAS. No witness
is advanced automatically. After a successful shuffle/catalog/registry publication
the manager may be one step ahead, deliberately blocking the next guarded action
until the owner retains/reconciles output and explicitly reapproves its manifest.

```sh
caumedse-admin context-witness --approval "$APPROVAL" \
  --registry-key-file "$REGISTRY_KEY_FILE" --confirmed-offline "$APPROVAL" \
  --witness-directory "$TRUSTED_WITNESS_DIRECTORY" --witness-key-file "$WITNESS_KEY_FILE" --init
# Retain the returned witness token independently. Run one approved guarded action.
# Reconcile/reapprove its published manager pins, then explicitly advance:
caumedse-admin context-witness --approval "$APPROVAL" \
  --registry-key-file "$REGISTRY_KEY_FILE" --confirmed-offline "$APPROVAL" \
  --witness-directory "$TRUSTED_WITNESS_DIRECTORY" --witness-key-file "$WITNESS_KEY_FILE" \
  --advance "$PREVIOUS_WITNESS_TOKEN"
```

`--advance` first checks the approved pair against current authenticated manager
state, then uses the full previous witness token for witness CAS. Exactly one
manager counter may advance by one; the other entire anchor must stay identical.
Registry floor cannot decrease. Same-counter digest forks, rollback, skips,
simultaneous counter changes and witness/counter overflow fail without publication.
This counter check is not issuer-history, inventory or payload verification:
owner approval and normal manager lifecycle checks remain necessary. Multiple
unguarded publications cannot be silently reconciled; this patch supplies no
skip/force/reset path or automated multi-step restoration procedure.

Advance commits only the witness. Its signed last-transition receipt permits an
exact lost-ack retry with the previous token and identical approved manager pair,
returning the same witness token without increment. After another advance that
receipt is gone and old tokens conflict. Stale pins/tokens return 2; malformed,
unavailable or forbidden transitions return 1; success returns 0. Status reports
the exact approved current witness token, not a payload verification result.
If manager publication succeeded but witness advance was interrupted, reconcile
the owner-approved current pair, then retry advance; never adopt a candidate's
newer counter automatically. An installed shuffle target can still roll forward
from the current prepared witness, followed by explicit witness advancement.

Twenty-four new tests cover independent encoding, scoped authentication, CAS,
last-transition receipts, aliasing, semantic counter/floor rules, corruption,
overflow, missing DB/marker, crash ordering and competing publishers. Installed
owner integration checks exercise manager/approval rollback, checkpoint redirect
rejection, protected distinct keys, opt-in/backward compatibility, skipped
unguarded publications and interrupted-target recovery. An explicit complete
witness replay test documents the independent-retention limitation instead of
asserting hardware rollback protection. Crash hooks are fixture-only.
TODO #147 remains open for production key custody/rotation and independently
monotonic recovery deployment, live lifecycle integration, V2 context APIs and
persisted migration/floor/provider acceptance tests.

### Read-only witness recovery (#147 phase 12)

`context-witness --reconcile RETAINED_WITNESS_TOKEN` checks an independently
retained token without updating the witness, manager, approval or payload files.
Use the same schema-2 approval, protected keys, trusted witness directory and
exclusive offline confirmation as `--advance`. The approved registry/catalog
pair must first match current authenticated manager state in one read transaction;
stale approval pins are rejected, not refreshed from candidate data.

```sh
caumedse-admin context-witness --approval "$APPROVAL" \
  --registry-key-file "$MANAGER_KEY_FILE" --confirmed-offline "$APPROVAL" \
  --witness-directory "$TRUSTED_WITNESS_DIRECTORY" --witness-key-file "$WITNESS_KEY_FILE" \
  --reconcile "$RETAINED_WITNESS_TOKEN"
```

Successful output has `state` and `witness` fields only:

- `current`: retained token and approved manager pair exactly match the witness.
- `advance-required`: retained token matches, and the manager pair is exactly
  one permitted publication ahead. Output is the unchanged witness token. Review
  the publication and payload separately, then explicitly run `--advance` with
  that token; this result does not authorize another guarded mutation.
- `already-advanced`: the retained token is the signed previous token and the
  approved manager pair exactly matches the current witness. A last advance
  committed despite a lost acknowledgement. Retain the returned current token
  independently; an exact `--advance` retry remains idempotent.

Return 0 means classified, not recovered or payload-authenticated. Return 2
means conflict (including stale tokens, rollback, forks, skipped or simultaneous
publications); return 1 means malformed/unavailable state. No tokens are emitted
on failure. A read transaction authenticates and classifies one witness snapshot.
There is no manager/witness atomic snapshot or lease: maintain exclusive ownership
and recheck before a mutation, whose normal CAS remains mandatory.

#### Independent retention and restoration procedure

1. Keep the canonical witness selector, separate key custody and latest acknowledged
   token under operator control outside manager/export backups. Retain previous
   tokens only as explicitly pending acknowledgement records. A disjoint directory
   is not independent retention against whole-host rollback; use a separately
   administered retention boundary and review its restore/access policy. This
   local command does not implement that boundary or a remote monotonic authority.
2. Stop every reader/writer and preserve failure artifacts before restore. Never
   delete initialization markers, reinitialize authority, change trusted witness
   selection or copy an older witness over the retained checkpoint to clear a
   conflict. Restore manager/export state only into a reviewed offline recovery
   workflow, with keys and witness kept out of automatic restore jobs.
3. Independently authenticate/inventory the proposed manager and backing payload
   state; explicitly reapprove exact manager pins. Run `--reconcile` using the
   independently retained latest token (or the recorded pending transition token
   after a lost acknowledgement), not a token read from the restored backup.
4. For `current`, reconcile any prepared shuffle intent and verify persisted
   payloads before resuming. For `advance-required`, verify the single intended
   publication, explicitly advance, retain its receipt/token, and check again.
   For `already-advanced`, retain the returned token and check `current` with it.
   An installed-but-unpublished shuffle target still requires the phase-10
   approved roll-forward path; witness classification does not finish it.
5. On conflict, missing/corrupt state, skipped publications or incomplete bootstrap,
   stop. Recover a matching approved manager/export checkpoint through review;
   there is no skip, force, downgrade, key-rotation or automatic reconstruction
   operation. A valid old manager/approval restore is rejected by a retained newer
   witness. An old whole-witness restore is rejected when the independently
   retained newer token is supplied; restoring both witness and token defeats
   this check, as does key compromise or bypassing the guarded APIs.

The additive C `cmeContextWitnessReconcile` API exposes these classifications
with cleared outputs on failure and token/output alias support. Like the existing
witness core it does not authenticate the manager pair itself; that is a mandatory
caller responsibility. TODO #147 remains open for independently monotonic
deployment, production key custody/rotation, live lifecycle adapters, V2 crypto
operations and complete migration/provider acceptance gates.

### Registered shuffle preflight (#147 phase 13)

`caumedse-admin context-registered-shuffle --check` adds an offline, read-only
paired-artifact gate before a future registered-resource publisher. A ColumnFile
primary-key permutation changes its serialized bytes, so its registered ResourcesDB
`partMAC` must change even though encrypted values, salts, tags and logical
`rowOrder` stay exact. The older single-file coordinator cannot atomically publish
that second artifact. This command does NOT install either file, prepare an
intent, modify lookup values or update the manager/witness. It emits only:

```text
state=verified-pair
publication=disabled
```

Use a private canonical schema-3 approval with exactly the schema-2 fields plus:

```json
{
  "resources": "/offline/export/ResourcesDB",
  "stagedResources": "/offline/staging/ResourcesDB",
  "resourcesSource": "64 lowercase hex SHA256 characters",
  "resourcesTarget": "64 lowercase hex SHA256 characters",
  "registration": [1, "document-id", "storage-id", "organization-id", "column-id"],
  "profile": "aes-256-gcm"
}
```

The fragment is not a standalone manifest. `registration` has exactly five
entries: positive signed-64-bit ResourcesDB document row id followed by four
nonempty strings (at most 128 bytes each). These are independent owner selectors,
not labels adopted from a candidate. The organization string is the registered
`orgResourceId`, not the manager organization UUID. Resource and staged resource
paths must be the `ResourcesDB` sibling of the approved active and staged
ColumnFile respectively. All four file SHA256 digests must be independently
reviewed/reapproved; a newer candidate pin is never refreshed automatically.

```sh
caumedse-admin context-registered-shuffle --approval "$REGISTERED_APPROVAL" \
  --registry-key-file "$MANAGER_KEY_FILE" --confirmed-offline "$REGISTERED_APPROVAL" \
  --witness-directory "$TRUSTED_WITNESS_DIRECTORY" --witness-key-file "$WITNESS_KEY_FILE" \
  --retained-witness-token "$RETAINED_CURRENT_WITNESS_TOKEN" \
  --org-key-file "$ORG_KEY_FILE" --check
```

The retained token must exactly identify the current witness, not its previous
receipt. The explicitly approved manager pair must be current and match the
independently selected witness. Resolve any phase-12 pending advance first and
retain the new token independently. The source owner map must be active, unblocked
and role 4. The existing complete-slot permutation comparison verifies every
data/meta row and non-id cell; authenticated bindings/pins are rechecked after
the crypto preflight. These checks are snapshots, not a lease or atomic cross-DB
transaction. Stop every reader/writer for the entire operation.

Scope is deliberately bounded: one local, single-part `file.csv` registration,
one organization key, current ResourcesDB schema/definitions and populated
document/storage/organization lookup columns. Verification is legacy/floor-1
only; floor 2 is rejected even with
current authenticated pins. Do not lower a raised floor to run this command.
Metadata, value and optional encrypted-row-order protection must use the
approved AES-256-GCM, AES-256-CBC or compiled-in allowed NLA1 profile.
No algorithm/key migration occurs.
Approved AES checks reject Herradura frame prefixes; NLA1 checks require the
V1 NLA1 frame id before provider dispatch. Self-dispatch cannot substitute
another framed profile for owner approval. Legacy
duplex and research/demo profiles are not accepted as approved profiles. Mixed
metadata/data/shuffle fallback profiles, NULL selected protected fields, missing
lookup values, remote storage and multipart registrations require a separate
reviewed adapter. Key files contain 1-256 bytes plus an optional final newline,
are canonical private 0600 one-link files in 0700 parents, and remain outside
export, staging, manager and witness trees. Approval and both authority keys must
also remain outside those trees for this contract.

Verification authenticates/decrypts every selected protected registration field,
checks the independent selectors/type/part counters and unique backing filename,
recomputes all three selected lookups, and authenticates the complete source and
candidate ColumnFile bytes against their selected decrypted `partMAC` values.
It decrypts persisted data/meta fields, validates complete logical row-order
permutations (including encrypted `rowOrder`) and checks declared MAC/sign tags
through the existing integrity verifier. Unsupported attributes/profile settings,
NUL aliases and malformed salted plaintext fail closed. Full typed logical
ResourcesDB comparison allows only the selected encrypted `partMAC` to differ;
salt, identity, timestamps, lookup values, all other records and every schema
object must remain exact. Exactly one matching protected local storage record
must be present. This is not a whole-export crypto inventory: unchanged unrelated
records/payloads are not certified, and other document filenames/storage selectors
must be readable with the same approved key/profile for ambiguity checks.

Files must be closed rollback-format SQLite in private canonical 0700 directories,
0600 regular one-link files with no symlinks or journal/WAL/SHM sidecars. Existing
256 MiB per-file, 1 MiB per-cell, 4096-slot limits apply; ResourcesDB comparison
also caps the combined table/schema row count at 4096. SQLite SQL/VM budgets bound
parsing/verification. Source/candidate directories must be disjoint.
The command requires JSON and `pragma_table_list` support in SQLite; unavailable
features fail closed rather than enabling a weaker schema check. DEBUG helper
output is silenced before crypto calls; failures emit only generic diagnostics,
not keys, paths, decrypted identifiers or candidate-derived approval tokens.
Return 0 means the approved pair passed this gate, 2 means stale/conflicting
authority, and 1 means invalid/unavailable state. No durable receipt is written.

Owners must build/review both candidates independently before checking: copy the
approved ResourcesDB and replace only the selected `partMAC`, encrypted using
the unchanged row salt and organization key with the usual field-HMAC prefix.
Do not use key-rotation output as a byte-preserving shuffle candidate. Candidate
generation is not supplied by this command. Interrupted checks can be repeated
against the same pins without restoration/publication because they are read-only.
A partial/missing candidate is rejected, never repaired or silently adopted.

At phase 13, schema 3 was accepted ONLY by the new check-only command: existing witness and
single-file shuffle commands reject it, and `--prepare`, `--complete`, `--abort`
and `--init` cannot publish a registered approval. Older schema-1/2 commands and
direct APIs remain compatible and unguarded with respect to ResourcesDB pairing;
do not strip registration fields or use them as a publication bypass. A successful
preflight is not an install authorization, recovery receipt, ResourcesDB context
binding or proof of V2 cross-context rejection. TODO #147 remains open. The next
publisher must durably authenticate both files/digests, the selected registration,
slot permutation and phase ordering, keep bindings blocked through partial
installation, and reconcile file/ResourcesDB/catalog/witness crash boundaries
before any live-use claim. Production custody/monotonic deployment, V2 APIs and
migration/floor/provider acceptance gates are also still pending.

### Paired manager recovery (#147 phase 14)

The trusted in-process manager adds `cmeContextManagerShufflePairInit`,
`cmeContextManagerShufflePairPrepare` and `cmeContextManagerShufflePairRecover`.
This is the durable paired-file coordinator core, NOT an installed publisher.
At phase 14, `context-registered-shuffle` remained schema-3/check-only; existing installed
shuffle/witness commands still reject schema 3. No live route uses these APIs.
The guarded owner adapter and its acceptance tests are still required; never
substitute direct fixture calls for the missing authorization/preflight handoff.

An explicit idle-catalog upgrade from shuffle catalog v2 enables `pair_version=1`
and the separate `CDSE-HKX-MAP-v3\0` authentication domain. It advances only the
catalog revision by one; no prepared intent may exist. Existing v1/v2 catalogs
remain compatible, and older readers fail authentication on upgraded catalogs.
Never downgrade the marker or restore old authority to circumvent an intent.

The v3 canonical encoding is the entire v2 encoding under the new domain, then a
big-endian uint32 companion-row count and rows ordered by binary map name. Each
row encodes uint8-length map-name text, uint16-length active/staged ResourcesDB
paths, and three 32-byte values: source SHA256, target SHA256 and nonzero
`selectionDigest`. Counts, types, lengths, orphans, NUL aliases and sibling path
relations are checked before authentication succeeds. The independent Python
encoder verifies the resulting HMAC and digest, including finished receipts.

`cmeContextShufflePair` supplies those paths/digests and an **opaque owner-reviewed
SHA256 commitment to the registration selectors and algorithm profile**. The core
authenticates the commitment but does not interpret, generate or verify its
preimage. A future adapter must define a canonical selector/profile encoding and
compare it across prepare/status/recovery, never adopt it from a candidate.
The phase-13 registration, lookup, field/file MAC, payload/tag, salt and allowed
`partMAC`-only mutation checks remain mandatory caller preconditions. Synthetic
manager fixtures verify mechanics, not cryptographic payload acceptance.

Prepare requires approved four-file digests, a complete identity-preserving slot
permutation, and closed private rollback-format SQLite files with the existing
256 MiB/file and catalog capacity limits. Parents are canonical owned 0700
directories; files are owned 0600 regular one-link files without sidecars.
Companions must be distinct `ResourcesDB` siblings of the respective ColumnFiles;
export/staging parents must be disjoint and on the same filesystem. Stop every
reader/writer and protect parent paths throughout: these checks are not a lease
or an atomic snapshot against concurrent writes.

Prepare syncs artifacts/directories and atomically commits both file pairs,
selection commitment, target slots, random job id and prepared state into the
authenticated catalog. No other prepared intent is allowed when preparing a
pair. A pending pair blocks **all stored maps** against binding, edits, deletion
and new shuffle preparation because ResourcesDB may be shared. Previously issued
mapped bindings fail their catalog pin check. Read-only map/intent metadata
remains available; registry-only binding/provisioning APIs are not disabled and
must not be used to bypass the storage guard.

Complete checks current registry/catalog CAS, active registrations and both
active digests. It validates both remaining candidates before any install, then:

1. Renames ColumnFile into place and syncs export/staging directories.
2. Renames ResourcesDB into place and syncs both directories.
3. Atomically commits target slots and the completed exact-revision receipt,
   unblocking stored maps.

The durable prepared intent survives partial installation. Retry recognizes
source/source, target/source and target/target states, syncs installed artifacts
and recovers forward. Source/target violates publication order and fails closed.
Unknown/missing active bytes, corrupt/missing remaining candidates, stale pins,
revoked target registrations or revision overflow never unblock maps. Abort
requires both sources; it does not restore files or delete candidates. After
either install, abort is forbidden.

`cmeContextManagerShuffleRead` returns owned companion metadata in `pair`.
Single-file recovery rejects paired jobs, even abort/finished retries; paired
recovery rejects single-file jobs. Finished retries require the exact job,
compatible outcome, exact finished catalog revision and BOTH active digests.
Later catalog publication expires a receipt; a new job may replace a receipt
under ordinary exact-pin CAS.

Witness advancement stays explicit: review/reapprove and advance/retain after
each upgrade, prepare and complete/abort publication before another publication.
A partial file install does not change the prepared manager pair; current witness
agreement therefore does not imply usable bindings. Skipping the prepared
checkpoint and advancing directly from pre-prepare to completion is rejected.
Tests cover independent witness advance and lost acknowledgements, but these
manager primitives do not enforce witness authorization themselves.

At phase 14, the next gate was the guarded installed owner adapter, canonical
selector/profile commitment, preflight-to-prepare handoff, authenticated-intent
recovery without deleted candidates, retained-current-witness checks, explicit
reapproval at each catalog revision and exact paired receipt comparisons.
Production key custody/rotation, independent monotonic deployment, live lifecycle
adapters, V2 crypto and migration/provider acceptance gates remain pending.
No two-file atomic visibility to unguarded readers or physical power-loss
certification is claimed.

### Guarded paired owner adapter (#147 phase 15)

`caumedse-admin context-registered-shuffle` now accepts `--init`, `--prepare`,
`--status`, `--complete JOB_HEX` and `--abort JOB_HEX`, in addition to the unchanged
read-only `--check`. Every action requires the full private schema-3 approval,
exact current registry/catalog pins, explicit offline confirmation, independent
witness directory/key, independently retained **current** witness token and the
protected organization-key file. All phase-13 path/key/layout limits and floor-1
restriction remain. This is an offline owner operation, never a live API route.

Init and prepare perform the complete phase-13 crypto preflight again, not merely
trust a previous check. They verify the complete byte-preserving permutation,
registration/file/field integrity, all lookups and allowed ResourcesDB mutation,
then recheck bindings, both manager pins and the current witness checkpoint.
`--init` explicitly upgrades an idle shuffle-v2 catalog to paired-v3; `--prepare`
calls the paired manager coordinator with the same approved four file digests.
Its fresh file hashes and catalog CAS prevent adopting bytes/authority different
from those checked. Exclusive offline ownership of paths is still mandatory;
there is no concurrent-writer lease or atomic manager/witness transaction.

The registration/profile commitment is SHA256 over exactly:

```text
"CDSE-REGISTERED-SHUFFLE-v1\0"
uint64_be(documentRowId)
uint16_be(length(documentId_bytes)) || documentId_bytes
uint16_be(length(storageId_bytes)) || storageId_bytes
uint16_be(length(orgResourceId_bytes)) || orgResourceId_bytes
uint16_be(length(columnId_bytes)) || columnId_bytes
uint16_be(length(profile_bytes)) || profile_bytes
```

Lengths count the decoded JSON string bytes, not JSON escape spelling or code
points. No string terminators are appended; the domain includes its final NUL.
The existing positive signed-64 document-id and 128-byte selector limits apply.
Manager/witness pins are deliberately excluded so the same intent can be
explicitly reapproved at each catalog revision. Both file pairs, digests, map
name and complete target slots are separately authenticated in the catalog and
compared against approval. Reordering JSON or equivalent escaping does not change
the commitment; changing a selector/profile does. It is not printed/adopted from
candidate metadata.

Status/recovery first authenticate the current manager/witness pair and retained
token, then read the signed paired intent and compare every approved path/digest,
slot and selection commitment. Single-file intents are refused. Status returns
authenticated metadata only: `state`, `job` and `catalog`, not file acceptance or
a usable binding. It may report prepared even if an active file was corrupted;
complete/abort still refuse unknown bytes and preserve blocking. The older
single-file command now also rejects paired metadata, not just paired recovery.

Complete/abort recheck current authority and delegate to the paired coordinator.
They do not reopen deleted candidates or repeat the source/candidate crypto
comparison: preparation committed proof of the approved exact bytes, and recovery
checks the installed/remaining bytes against that authenticated intent. The org
key file remains a required protected control input, but recovery does not decrypt
payloads or validate its contents as a crypto key. No rotation occurs. A missing
remaining candidate, unknown bytes, unsafe paths or expired receipt still fail
closed. Finished retries require the exact finished catalog revision and both
active digests; status alone never renews a receipt.

The operator workflow is deliberately explicit:

1. Provision/approve the manager and independent witness using the existing
   owner workflow. If the catalog is v1, use schema-2 `context-shuffle --init`
   to enable shuffle-v2. Review the new catalog pin and separately advance/retain
   the witness with a schema-2 `context-witness --advance CURRENT_TOKEN` approval.
2. Independently build/review both candidates and a schema-3 approval, then run
   registered `--init` with the exact current witness token to enable paired-v3.
   Reapprove the new manager pair and explicitly advance/retain the witness again.
3. Run registered `--prepare`; retain its job/catalog receipt. Reapprove the
   prepared manager pair and separately advance/retain the witness before any
   registered status/recovery action. All stored maps are blocked at prepare.
4. Run registered `--complete JOB` (or `--abort JOB` only while both sources are
   active). After catalog publication, reapprove and explicitly advance/retain
   the witness again before status or a finished retry. Review receipts before
   updating pins; no command refreshes the approval automatically.
5. On partial installation, keep the same prepared pins and retained current
   witness token, and recover forward with the same schema-3 selection/file pins
   and job. After a lost prepare/complete/abort acknowledgement, independently
   review the current catalog and advance its witness checkpoint before status
   can reveal the signed job. A lost init acknowledgement instead requires
   reviewing the authenticated catalog version/pin before proceeding to prepare;
   init creates no job. A lost witness acknowledgement uses the existing schema-2
   `--reconcile` receipt procedure. Never reset authority, skip counters, lower a
   floor or strip registration fields to bypass these guards.

Use the phase-13 invocation with the chosen action instead of `--check`; do not
pass `--org-key-file`/`--retained-witness-token` to schema-2 witness commands.
Schema-2 witness approvals retain exactly their original fields and independently
reviewed current pins. Source/target digests and selections in the schema-3
approval stay unchanged across recovery, even after staged files disappear.
Keep both parent directories until receipt and witness reconciliation finish;
the coordinator still needs them for safety checks and directory sync.
Success emits only state/job/catalog tokens (check keeps its old two-line output).
Failures emit generic diagnostics and no success tokens. Crypto DEBUG output
remains silenced. Return codes remain 0 success, 2 stale/conflicting authority,
1 invalid/unavailable state.

Tests exercise installed-owner prepare and final reconciliation around fixture-
injected crashes after each rename, sync and catalog write/commit, without
compiling crash hooks into the installed command. Lost acknowledgements, explicit
witness advance, exact selection encoding and file/slot/selector substitution are
covered. Process crashes are not physical power-loss certification. Direct core
APIs remain trusted-owner interfaces and do not enforce these command guards;
production custody must prevent their misuse. TODO #147 remains open for reviewed
production key custody/rotation and independent monotonic recovery deployment,
live lifecycle/UUID adapters, V2 crypto and migration/floor/provider acceptance.

### Copy identity preparation (#147 phase 16)

`cmeContextManagerCopyProvision` adds a trusted in-process identity-preparation
adapter for a same-storage ColumnFile copy. It does NOT copy files, update a
ResourcesDB registration, install a destination map or expose a live/installed
copy command. It is the registry-allocation step needed before a future reviewed
copy workflow can re-encrypt under new contexts and publish its artifacts.

Supply an independently trusted source map name, exact registry/catalog anchors
and one unused destination lookup per source slot. The order is the authenticated
`MapRead` order: binary table name, signed row number, binary field name. Lookups
are stable owner registration handles, never derived from filenames or candidate
metadata. The first destination lookup becomes the new resource handle in the
returned allocation descriptor. The source must be active, unblocked, role 4 and
floor 1; internal DBs, RawPart and floor-2 sources require a different reviewed
adapter. Neither another organization nor another storage can be selected.

The adapter authenticates/binds the stored source map, retains its deployment,
organization, storage, schema names and physical slots, and generates one fresh
UUIDv4 resource plus one fresh UUIDv4 record for each source table/slot. Existing
binding invariants guarantee that fields in a source table/slot share one record
and a record occupies only one slot per table. Their copied fields therefore
share one new record UUID. UUIDs are random, not hashes of names/positions, and
are checked against every retained identity (including tombstones), earlier batch
entries and the newly generated resource. Destination lookups must be distinct
and absent even from revoked registrations.

All additions are signed into one canonical next registry snapshot, preserving
every original registration/context/tombstone and the format floor. Candidate
construction commits no identity reservation. Final publication uses the existing
authenticated immutable-transition checks and, in the SAME `BEGIN IMMEDIATE`
transaction, rechecks both original anchors and source shuffle blocking. A source
map change, removal, registry revocation or shuffle preparation between candidate
construction and publication conflicts/fails without allocating any copy IDs.
Only registry generation advances, exactly once; the catalog remains byte-for-
byte unchanged. RNG/collision, capacity/encoding limits and generation overflow
fail closed. Existing 4096-entry/1 MiB registry and owner-map limits apply; a stored
map may be partial, so this is not a complete ColumnFile inventory proof.

On success the caller owns a `cmeContextMap` allocation descriptor (free it with
`cmeContextMapFree`), not a durable destination map or file acceptance receipt.
Its lookup/table/row/field vectors can be reviewed for a later `MapStore` under a
new owner-selected map name. The allocation advances the registry only: review
and explicitly advance/retain the independent witness BEFORE a later catalog
publication, then advance it again afterward. Advancing both counters at once or
skipping either checkpoint remains forbidden. These core APIs do not enforce
witness authorization themselves; the installed guards are described in phases
18 and 25 below.

No output survives a failed call; expected/published registry anchors may alias.
Return codes remain 0 success, 2 stale pins, 1 invalid/unavailable. Before commit,
process failure leaves no new identities. A lost commit acknowledgement leaves
the ENTIRE batch or none: independently inspect and authenticate the approved
destination lookups/snapshot before proceeding. Never blindly retry with fresh
lookups or reset authority. Old-pin retries conflict; refreshed retries with the
same already committed lookups are rejected. This phase supplies no allocation
job receipt, automatic orphan cleanup, cross-file recovery or owner authentication.

Rename/row shuffle retain the original UUIDs through existing owner mappings;
copy allocates fresh resource/record IDs. Tests cover grouped multi-field records,
independent canonical registry verification, source/catalog preservation, output
clearing/aliasing, RNG and batch collisions, retained tombstones, stale pins,
source revocation/removal/blocking, capacity/floor/overflow, process crashes and
controlled concurrent writes between preparation and publication. Pause/crash
hooks exist only in the non-installed fixture build.

Persisted legacy AES readback after path rename/byte copy remains compatible.
Binding a destination descriptor against the source resource (or source slots
against the new resource) is rejected by trusted registry checks. Neither is an
AEAD cross-context tag-failure proof: same-key legacy ciphertext clones remain
readable because V1/AES does not authenticate these new UUIDs. Do not publish such
bytes as V2 or treat this allocation as authorization for a registered file copy.
Actual persisted V2 substitution rejection and legacy/mixed-format migration
acceptance remain required before enabling V2 writes.

TODO #147 remains open. Next connect this preparation step to a guarded local
copy owner protocol with authenticated allocation recovery, complete registration/
payload inventory, context-aware re-encryption and durable artifact/catalog
publication. Rename/delete lifecycle adapters, production custody/rotation and
independent monotonic deployment, V2 provider APIs and migration/floor/provider
acceptance remain pending. No runtime default, physical file format, live route,
hardware rollback guarantee or physical power-loss certification changes.

### Retained copy allocation plans (#147 phase 17)

The trusted offline manager now offers an optional two-phase alternative to
`CopyProvision`: `cmeContextManagerCopyPlanPrepare`, `CopyPlanStatus` and
`CopyPlanCommit`. Prepare performs the same active-source, floor-1, same-storage
checks and fresh grouped UUID allocation, but publishes NOTHING. It returns owned
opaque plan bytes and their SHA256. The plan fixes the exact original registry/
catalog pins, source map, destination descriptor and signed next registry snapshot.
There is no manager schema/catalog upgrade, reservation table or backing-file
format change.
The original one-shot API and its uncertain-acknowledgement rules remain unchanged.

The owner must review the planned operation, independently retain the approved
SHA256, and durably store the EXACT plan bytes before allowing Commit. Use a
private file outside exports, protect it from replacement, finish/fsync its write
and sync the containing directory. These core APIs supply bytes, not a file-save
command or durability guarantee. Do not replace a lost plan by preparing a new
one after an uncertain commit. Plans contain registration metadata, not keys;
protect them under the same owner-custody rules as other authority metadata.

Status authenticates both the retained digest and the plan MAC before decoding.
It returns `state=1` only at the exact original registry/catalog pair and
`state=2` only at the exact planned next registry with the original catalog.
Commit publishes that snapshot using both original pins and the source-shuffle
check under the existing final `BEGIN IMMEDIATE` transaction. An exact retry
at the planned next pair succeeds without writing or allocating again. Another
plan, later generation, changed catalog, revoked source or pending shuffle cannot
be adopted as successful recovery. A separately prepared competing plan has
different UUIDs/digest and conflicts after the first commits. The registry
advances at most once; no destination map or backing file is published.

Both APIs return owned allocation descriptors, not validated backing-file
bindings or copy authorizations. Before commit, the descriptor is a candidate
only. Supply the ORIGINAL owner-approved registry/catalog pins and retained
plan/digest on every retry, never candidate-discovered refreshed pins. A later
catalog publication expires this exact-pair recovery window. Retain the plan
until independently approved witness recovery and subsequent workflow checkpoints
are durable; no automatic receipt deletion, cancellation or orphan cleanup is
provided. Explicitly abandoning an uncommitted plan needs no authority write,
but protect old plans from accidental later submission while their pins are current.

`cmeContextWitnessCopyCommit` adds an opt-in trusted in-process witness guard.
For a ready plan it requires the exact current witness pair and independently
retained token; an unapproved advance-required step is refused. For an already
committed plan it permits authenticated current, advance-required or exact
already-advanced reconciliation, including a lost witness acknowledgement.
An advance-required witness must still match the plan's FULL original pair;
a same-generation checkpoint with a different registry digest is rejected.
It NEVER advances the witness. After allocation, explicitly approve its registry
step, advance/retain the witness token, then separately approve any catalog step.
Stop all readers/writers during the workflow: manager and witness checks are
point-in-time, not a cross-database transaction, revocation lease or substitute
for independent monotonic custody. Missing/corrupt/replayed authority fails closed
against independently retained pins; replay of all owner evidence is not detected.

The version-1 plan encoding is bounded and typed, not serialized C memory:

1. ASCII `CDSE-HKX-COPY-v1` plus NUL; original registry anchor (73 bytes),
   catalog anchor (8-byte revision plus 32-byte digest), planned next registry
   anchor (73 bytes), and next snapshot HMAC (32 bytes).
2. Source map name (one-byte length, ASCII bytes), slot count (four-byte unsigned
   big-endian), then slots in binary table/signed row/binary field order. Each
   slot has destination lookup and table (one-byte lengths and ASCII bytes),
   row (eight-byte two's-complement big-endian) and field (one-byte length/ASCII).
3. Snapshot length (four-byte big-endian), exact canonical registry JSON bytes,
   and HMAC-SHA256 over ALL preceding plan bytes under the registry key. The
   independently retained SHA256 covers the entire plan including its MAC.

Existing name/count limits apply. Metadata through snapshot length is capped at
1 MiB; the snapshot is separately capped at 1 MiB; total is at most 2 MiB + 32
bytes. Parsing rejects truncation/trailing bytes, invalid names/order/counts,
namespace/floor/generation changes and invalid inner snapshot authentication.
The distinct domain binds scope and request metadata, while the inner registry
MAC retains the existing registry domain. Holding the registry key still makes
one a trusted issuer; this is not a provenance guarantee against that issuer.

Tests independently decode/verify plan and snapshot encodings, retain/fsync plans,
exercise prepare without publication, exact retry with unchanged authority bytes,
competing plans, tampering even after rehashing, malformed signed metadata,
signed-row extremes, stale pins/source removal, witness reapproval/rollback,
and crashes before write, before commit and after commit. Existing one-shot
copy-identity tests remain regression coverage. No physical power-loss, V2 AEAD
cross-context rejection or complete payload-inventory claim is added.

TODO #147 remains open. Next expose a reviewed owner-side durable-plan handoff
and recovery command, then connect complete registration/payload inventory,
context-aware re-encryption and durable artifact/catalog publication. Rename/
delete adapters, production custody/rotation and independent monotonic deployment,
V2/provider acceptance and migration/floor checks remain required. No installed
copy command, live route, physical copy or V2 write is enabled by this phase.

### Installed copy-plan handoff (#147 phase 18)

`caumedse-admin context-copy-plan` exposes the retained-plan allocation protocol
to a trusted local offline owner. Its schema-1 approval is a separate protocol
from shuffle/witness approval schemas; it does not accept their extra fields.
No backing files are opened, copied or re-encrypted, and no destination map or
ResourcesDB registration is published. The command advances the registry only
when `--commit` is explicitly requested, and advances the witness only through
the separately approved `--advance-witness` action.

Create a private uid-owned 0700 custody directory outside the manager, witness
and approved export directories. All four directories must be canonical and
disjoint (no equal/nested directory names or equal directory identities). Keep
the manager outside ALL actual exports, not merely the one declared here, and
hold the directory hierarchy fixed. Approval/key files must be canonical regular
uid-owned 0600 single-link files outside manager/witness/export directories.
Registry and witness keys must be distinct 32-byte lower-case hex values, with
an optional final newline. The witness must already exist; this command never
bootstraps, repairs or resets authority. Stop all authority/storage readers and
writers throughout the workflow. These checks are not a filesystem or witness
lease and do not authenticate an export declaration supplied by an untrusted user.

The approval JSON has exactly these keys (no duplicates/unknown fields):

```json
{
  "schema": 1,
  "manager": "/private/manager",
  "deployment": "OWNER_APPROVED_DEPLOYMENT_HEX_32",
  "organization": "OWNER_APPROVED_ORGANIZATION_HEX_32",
  "map": "source-owner-map",
  "registry": "ORIGINAL_REGISTRY_TOKEN_HEX_146",
  "catalog": "ORIGINAL_CATALOG_TOKEN_HEX_80",
  "witness": "/private/witness",
  "export": "/private/export",
  "plan": "/private/copy-custody/allocation.plan",
  "lookups": ["copy/field-0", "copy/field-1"]
}
```

Replace placeholders with independently approved values. `lookups` must contain
one unused destination registration handle per authenticated source slot, in
`MapRead` order (binary table, signed row, binary field). These are stable handles,
not filenames. Keep this approval's ORIGINAL registry/catalog pins unchanged
through recovery; never refresh them from a candidate or from a changed manager.
The source map name AND lookup vector are authenticated against the retained plan
through `cmeContextManagerCopyPlanMatch`, so swapping another valid source map or
reordering destination handles cannot silently authorize a different request.

Each invocation requires these explicit common options:

```sh
caumedse-admin context-copy-plan \
  --approval /private/copy-approval.json \
  --confirmed-offline /private/copy-approval.json \
  --registry-key-file /private/registry.key \
  --witness-directory /private/witness \
  --witness-key-file /private/witness.key \
  --retained-witness-token "$INDEPENDENTLY_RETAINED_WITNESS_TOKEN" \
  --prepare
```

`--prepare` requires exact current manager/witness pins. It creates the plan
with `O_EXCL`/`O_NOFOLLOW`, mode 0600, writes the entire signed byte sequence,
syncs the file and containing directory, verifies its identity, then acknowledges
its SHA256 (`plan-digest`) and planned next `registry` pin. No registry IDs are
reserved or published. Existing names of ANY type are refused, including after
a lost prepare acknowledgement. Failed/uncertain writes retain partial files:
never delete/replace them blindly or let a retry overwrite owner evidence.

Review the saved plan/request, independently retain its SHA256 and planned next
pin, and protect the exact file from replacement. For a lost prepare response,
an owner may independently inspect/authenticate the retained file and compute its
digest, then explicitly approve that digest; the command never adopts it
automatically. A partial/invalid plan cannot be committed. Abandoning or replacing
an unusable file requires independent review proving allocation has not occurred;
there is no automatic cleanup/reset or physical power-loss certification.

Use the SAME common options and unchanged original approval, replacing the action
with `--status --plan-digest "$RETAINED_PLAN_DIGEST"` or
`--commit --plan-digest "$RETAINED_PLAN_DIGEST"`. Both require an explicit retained
digest and witness token, authenticate the request and exact original/planned
pair, and read only private regular single-link 0600 plan files. The reader bounds
length, checks file identity/metadata, and syncs the read plan and parent before
allowing publication. Symlinks, hard links, FIFOs, noncanonical paths and public
files/directories fail closed. Status publishes nothing: it reports `ready` or
`committed`, the planned registry/catalog pins, digest and witness reconciliation
class. Commit uses the guarded core protocol and supports exact lost-ack retries
without reallocating, republishing or refreshing pins. No secret/key/path values
are printed; output pins/digests remain owner-sensitive metadata.

After a commit, `witness-state=advance-required` is expected until independently
approved. Separately review the planned next registry token and run the common
options with this explicit action (original approval/pins still unchanged):

```sh
--advance-witness --plan-digest "$RETAINED_PLAN_DIGEST" \
  --approved-registry "$INDEPENDENTLY_APPROVED_PLANNED_NEXT_REGISTRY_TOKEN"
```

This refuses an uncommitted plan or a different registry token, revalidates the
guard and current manager pair, then advances only the registry witness step.
It emits `witness-token` only for this explicit action; independently retain it
before any later catalog publication. Exact lost-ack witness retries and an
already-current approved checkpoint do not advance again. Committed recovery
with an advance-required witness still checks the FULL original pair, not only
its generation. Restoring an older witness fails against a retained newer token;
restoring all owner evidence together remains outside local rollback detection.

Exit codes remain 0 success, 2 stale/conflicting authority, 1 invalid/unavailable.
No failed operation prints a success response. An uncertain commit may already
have allocated the entire batch: retain the exact plan/digest/original pins and
reconcile status, never regenerate UUIDs blindly. Later registry/catalog changes
expire this exact-pair recovery window. Later map/artifact publication is NOT
provided by this command, and must use separately reviewed workflow checkpoints.

Tests exercise the installed command's complete lifecycle, explicit witness
advance/retry, request substitution, partial-write retention, unsafe file types,
directory/key separation, strict schema/options, stale/replayed/missing authority,
and installed recovery after fixture-injected write/commit crashes. Fault injection
remains confined to the non-installed fixture; no CLI crash environment hooks are
added. Metadata allocation is not complete inventory, file acceptance, V2 AEAD
authentication or a physical power-loss guarantee.

TODO #147 stays open. Next design guarded physical-copy inventory and candidate
preflight/recovery without labeling byte-cloned legacy ciphertext as V2. Connect
reviewed context-aware re-encryption and durable artifact/catalog publication only
after the applicable V2/provider/migration gates. Rename/delete adapters,
production key custody/rotation and independent monotonic deployment remain open.

### Legacy copy candidate preflight (#147 phase 19)

`context-copy-plan --check-candidate` adds a trusted offline CHECK-ONLY step for
an independently selected ColumnFile and an already existing byte-exact legacy
candidate. It uses schema 2, the retained allocation-plan digest, original plan
pins and an independently retained witness token. It never allocates IDs, copies
files, advances witnesses, publishes maps/artifacts/ResourcesDB registrations or
creates a durable acceptance receipt. A successful check is point-in-time metadata,
not authorization for a later install. Keep all readers/writers stopped and the
directory hierarchy fixed; recheck after any approval, authority or file change.

Start from the phase-18 schema-1 allocation approval, change `schema` to 2, and
add exactly these five independently reviewed fields:

```json
{
  "source": "/private/export/source.sqlite",
  "candidate": "/private/copy-candidates/candidate.sqlite",
  "sourceDigest": "APPROVED_SOURCE_SHA256_HEX_64",
  "candidateDigest": "APPROVED_CANDIDATE_SHA256_HEX_64",
  "profile": "aes-256-gcm"
}
```

This is a fragment of the complete approval: retain ALL eleven phase-18 keys,
including the unchanged original `registry`, `catalog`, source `map`, destination
`lookups`, private `plan`, witness and export paths. Unknown/duplicate keys and
missing fields fail closed. Schema 2 permits ONLY `--check-candidate`; it cannot
authorize prepare/commit/witness advancement. Schema 1 remains unchanged and
rejects these extra fields. Continue using a separately reviewed schema-1 approval
for allocation operations; candidate validation does not gate that low-level
allocation protocol or turn allocation into physical-copy authorization.

Use the same common phase-18 options, then:

```sh
--check-candidate --plan-digest "$INDEPENDENTLY_RETAINED_PLAN_DIGEST" \
  --org-key-file /private/organization.key
```

The organization key is a canonical private regular uid-owned 0600 single-link
file containing 1-256 non-NUL bytes, with an optional final newline. It must be
separate from registry/witness key paths and the plan, and outside manager,
witness, export and candidate directories. No organization key is accepted on
schema-1 allocation actions. Runtime crypto diagnostics are suppressed; failures
emit only generic status, never protected values, keys, plaintext or file paths.

The source must be an immediate child of the approved canonical private export
directory. The existing candidate must have its own canonical uid-owned 0700
directory, disjoint from export, manager, witness and plan custody (including
equal directory identities); approval/control files stay outside it. Both files
must be private regular single-link 0600 SQLite rollback-journal files, with
distinct identities and parent directories, no symlinks/hard links/sidecars,
and independently approved full-file SHA256 pins. The current profile supports
ONLY byte-exact clones: both approved hashes AND both observed hashes must agree.
Changed rows, re-encryption, fresh salts or physical SQLite rewrites are refused,
even when they would preserve logical plaintext. The command does not create the
candidate or infer its identity from a filename or embedded metadata.

The retained plan must match the independently approved source map name and
destination lookup vector. Current manager/witness checks permit the plan's exact
ready pair or exact committed pair, with explicit witness reconciliation and the
full original-pair check for advance-required committed recovery. Active source
bindings and the catalog are checked before and after preflight; committed plans
also validate destination bindings. Ready-plan destinations remain authenticated
allocation candidates, not registered identities. Later registry/catalog changes
expire this exact-pair window. No pins or witness tokens are adopted automatically.

Coverage must be COMPLETE for the selected ColumnFile's identity-bearing cells:
for EVERY physical `data.id`, exactly one source-map slot for each of `value`,
`userId`, `orgId`, `rowOrder`; for EVERY `meta.id`, exactly one for each of
`attribute`, `attributeData`, `userId`, `orgId`. The authenticated destination
descriptor must retain the same table/row/field vector. Missing fields/rows,
additional slots, unrecognized fields/tables and partial maps are rejected.
Integer IDs, salt and integrity/helper columns are not separately allocated cell
identities: legacy schema/crypto/integrity checks validate their supported form.
Existing 4096-slot, registry and offline-file limits apply. This proves coverage
of the selected ColumnFile only, NOT completeness of an export or its ResourcesDB
registration, nor cryptographic provenance of its relation to an owner map.

The check reuses strict registered-owner ColumnFile verification, SQLite schema
and `integrity_check`, bounded read-only queries, and existing legacy decryption,
metadata/profile, row-order and configured MAC/sign integrity checks. Supported
profiles are `aes-256-gcm` and `aes-256-cbc`; CBC retains its existing configured
integrity properties and gains no AEAD guarantee. Unknown/optional provider
profiles and `CDSEHKX` frames (including forged V2 headers) fail closed in this
legacy-only step. No new cryptographic primitive or storage format is introduced.
File identity/metadata and current authority bindings are rechecked afterward.

Success reports `state=verified-legacy-candidate`,
`inventory=complete-columnfile-cells`, `context-authentication=absent`,
`publication=disabled` and the approved plan digest. The fresh resource/record
UUIDs exist only in the allocation protocol; legacy ciphertext clones remain
same-key readable and do NOT authenticate those UUIDs. Do not label these bytes
as V2, treat this report as a portable acceptance token or publish a destination
registration using it. ResourcesDB partMAC/selector/storage association checks,
whole-export inventory, context-aware re-encryption and cross-context V2 tag-failure
proofs remain separate required gates before guarded physical-copy publication.

Tests cover complete ready/committed plans, AES-GCM/CBC, absence of authority/file
publication, partial maps and omitted rows/fields, unmapped rows despite reapproved
equal hashes, ciphertext/V2-header tampering, rehashed nonidentical candidates,
schema objects, stale pins, unsafe paths/files/sidecars and request substitution.
Neither process-crash testing elsewhere nor this read-only check certifies
physical power-loss recovery. TODO #147 stays open for complete registration/
export preflight, reviewed candidate recovery/publication and the remaining
V2/provider/migration, rename/delete and production custody/monotonic gates.

### Source registration preflight (#147 phase 20)

`context-copy-plan --check-registration` extends the legacy candidate check with
a source ResourcesDB association check. It is a separate schema-3 CHECK-ONLY
action, not a destination-registration publisher, artifact install, witness advance
or durable acceptance receipt. All phase-19 ColumnFile crypto/inventory, distinct
byte-exact candidate, retained-plan request matching and original manager/witness
pin checks still apply, including ready/committed reconciliation and post-check
binding validation. Schema-1 allocation actions and schema-2 candidate checks
retain their existing contracts.

Start from the complete phase-19 schema-2 approval, change `schema` to 3, and add
exactly these four independently reviewed fields:

```json
{
  "resources": "/private/export/ResourcesDB",
  "resourcesDigest": "APPROVED_RESOURCESDB_SHA256_HEX_64",
  "registration": [1, "approved-document", "approved-storage", "approved-org-resource", "1"],
  "storageAccessPath": "/independently-approved/original-storage/"
}
```

This is a fragment, not the full approval. Retain all sixteen prior keys,
including the ORIGINAL registry/catalog pins, source map, destination lookup
vector, plan path and independently approved ColumnFile/candidate hashes/profile.
The registration vector is exactly `[documentRow, documentId, storageId,
orgResourceId, columnId]`: positive signed-64-bit integer row and four nonempty
strings of at most 128 bytes. Booleans/floats/overflow and missing/duplicate/extra
fields fail closed. Independently approve this tuple for the manager's namespace;
the command does not derive registry UUIDs from plaintext identifiers or discover
approval from candidate metadata. Schema 3 permits ONLY `--check-registration`,
not allocation, witness advancement, status or the weaker `--check-candidate`.

Use the common phase-18 options with:

```sh
--check-registration --plan-digest "$INDEPENDENTLY_RETAINED_PLAN_DIGEST" \
  --org-key-file /private/organization.key
```

`resources` must be exactly `ResourcesDB` in the approved source export directory.
It must be a canonical private uid-owned 0600 single-link regular SQLite rollback-
journal file, with no sidecars/symlink/hardlink, a distinct file identity from both
ColumnFiles and its own approved full-file SHA256. The source ResourcesDB shares
the source export directory; it is NOT placed beside or inferred from the candidate.
No candidate ResourcesDB is accepted by this action. Existing private key/control
and disjoint custody/export/candidate/authority rules remain unchanged.

The check opens all three artifacts in bounded read-only SQLite transactions,
disables trusted schema, verifies strict internal ResourcesDB schema/version/
definitions and SQLite integrity, and rechecks file identities/metadata after
closing. It never migrates or repairs a DB. It reuses the registered-owner verifier
to check the selected document row's field MACs and protected values, `file.csv`
type, exact source basename, approved selector tuple and all three domain-specific
lookup values (`documentIdLookup`, `storageIdLookup`, `orgResourceIdLookup`). It
requires a single part (`partId=1`, `totalParts=1`) and authenticates the decrypted
`partMAC` against the ENTIRE pinned source ColumnFile bytes under the approved
organization key and row salt. Fresh valid ciphertext with new salts is rejected
if its source registration still carries the old file MAC, even when the weaker
ColumnFile-only check and newly approved file hashes pass.

Another document row may not reference the selected source basename or duplicate
the approved document/storage/org-resource/column selector tuple, even under a
different filename. A unique matching storage row must authenticate the same
storage and org-resource identifiers, declare `type=local`, and have an encrypted
access path exactly equal to the independently approved `storageAccessPath`.
That expected string must be absolute, but is compared literally: it is historical
storage metadata and need NOT equal the current offline export path or exist on
this machine. It is never resolved, normalized, used to open files or refreshed
from the DB. Remote, duplicate, mismatched and ambiguous associations fail closed.

The selected source association is checked within the same preflight as the full
ColumnFile cell inventory and candidate-byte equality. Reusing the bounded paired
metadata verifier with the source snapshot on both sides preserves schema,
duplicate-basename and unique-local-storage checks without manufacturing a target
ResourcesDB. It is NOT a proof that every unrelated DB field/payload has been
cryptographically verified or that all exported files/part groups are accounted
for. A full-export inventory and destination registration design remain pending.
Unreadable unrelated filename/selector/storage-identity fields are refused,
not skipped; mixed-key/profile source snapshots are not silently accepted.
Existing 4096-entry/row and offline-file limits apply; profiles remain AES-GCM/CBC
only with their existing integrity properties. Neither CBC nor cloned legacy GCM
bytes gain UUID-bound AEAD authentication.

Success reports `state=verified-legacy-registration`,
`registration=selected-source-columnfile`, the approved ResourcesDB hash and plan
digest, `inventory=complete-columnfile-cells`, `context-authentication=absent` and
`publication=disabled`. No IDs, plaintext selector/path values or keys are printed;
crypto diagnostics remain suppressed. Pins/digests are still owner-sensitive.
The result is point-in-time metadata, not a portable install token. Stop all
readers/writers and keep directories fixed; authority/file checks are not leases.
No file, map, registration or witness is published, and no V2 write is enabled.

Tests cover ready/committed read-only GCM/CBC checks, selected-row/tuple mismatch,
each lookup mismatch despite a newly approved DB hash, a valid new ColumnFile with
the old registered file MAC, filename/selector/storage duplicates, multipart and
remote refusal, org/access-path mismatches, private DB paths/modes/sidecars/links,
schema/metadata downgrade and schema/action/plan/witness approval isolation.
TODO #147 remains open for whole-export inventory, destination registration and
guarded copy recovery/publication, context-aware re-encryption and persisted V2
substitution rejection, provider/migration/floor acceptance, rename/delete adapters
and production custody/independent monotonic deployment. No physical power-loss
certification or live storage integration is added.

### Source export inventory (#147 phase 21)

`context-copy-plan --check-export` is a separate schema-4 read-only action.
Use exactly the twenty phase-20 approval keys, changing `schema` from 3 to 4,
and the same independent plan digest, witness token and organization-key options:

```sh
--check-export --plan-digest "$INDEPENDENTLY_RETAINED_PLAN_DIGEST" \
  --org-key-file /private/organization.key
```

All selected ColumnFile/candidate, registration, original manager/plan and witness
checks still apply. Schema 4 cannot authorize allocation, status, commit, witness
advancement or either weaker check. Schemas 1 through 3 retain their contracts.
The source must be a complete stopped local export, containing exactly
ResourcesDB, RolesDB, LogsDB and the payloads named by its documents table.
The candidate and custody files remain outside that export.

The command authenticates every document's protected fields and three lookup
values with the approved key/profile. It rejects empty or unsafe filenames,
reserved DB names, duplicate filenames, invalid part numbers, incomplete groups,
duplicate part IDs, inconsistent totals and missing storage associations. Groups
are keyed by document, storage, org-resource, type and column identifiers. Each
part and total must be decimal, positive and at most 4096; part IDs must cover
exactly 1 through the group's common total. Identifiers and types are nonempty
and at most 128 bytes. All storage records, including unused records, must have
authenticated local type, unique storage/org-resource identity, and exactly the
one independently approved historical `storageAccessPath`. Multi-root exports,
remote storage and mixed-key/profile inventories fail closed. The historical path
is compared literally and is never used to open files or infer UUID identities.

For each payload, authenticate the entire file against its registered partMAC and
row salt. Opaque files need not be SQLite; they must be nonempty, at most 256 MiB,
canonical, private uid-owned 0600 single-link regular files, without sidecars or
links. These checks do not decrypt or validate the internal representation of
unselected payloads. Only the selected ColumnFile receives the complete phase-19
cell/legacy crypto check. File MACs do not provide UUID-bound V2 authentication.

ResourcesDB retains its independently approved hash and strict bounded read-only
SQLite transaction. RolesDB and LogsDB must be private rollback-journal SQLite
files with valid file headers; their protected contents, schemas and independent
hash approvals are outside this inventory contract. They must not be treated as
cryptographically accepted for a later migration or destination publication.
Enumeration rejects every extra file or directory, including DB sidecars. Retain
bounded payload file metadata rather than thousands of open descriptors; recheck
every file identity/metadata through the held export directory, enumerate twice,
and reject directory identity or modification changes. The 4096-row bounds and
SQLite work budgets apply. Stop all readers/writers and hold the directory tree
fixed throughout; this point-in-time check supplies no concurrent-reader lease.

Success reports `state=verified-legacy-export`,
`export-inventory=complete-registered-payloads`,
`payload-authentication=registered-file-macs`, plus the selected-registration,
plan/hash metadata, `publication=disabled` and `context-authentication=absent`
fields. No plaintext paths, identifiers or keys are printed. No file, authority,
map, registration or witness is changed and no acceptance receipt is created.

TODO #147 remains open. Next design independently approved destination registration
and guarded copy recovery/publication, then context-aware V2 re-encryption and
persisted substitution rejection, provider/migration/floor acceptance,
rename/delete adapters and production custody/independent monotonic deployment.
This phase makes no physical power-loss or live storage integration claim.

### Destination registration preflight (#147 phase 22)

`context-copy-plan --check-destination` adds a read-only staged registration check
to the complete source-export inventory. Start from the twenty phase-21 keys,
set `schema` to 5, and add exactly four independently reviewed fields:

```json
{
  "destinationResources": "/private/candidates/ResourcesDB",
  "destinationResourcesDigest": "APPROVED_DESTINATION_RESOURCESDB_SHA256_HEX_64",
  "destinationRegistration": [4, "approved-new-document", "approved-storage", "approved-org-resource", "1"],
  "destinationStorageAccessPath": "/independently-approved/original-storage/"
}
```

This is a fragment, not a complete manifest. Retain the ORIGINAL manager pins,
source map and destination lookup vector, independently retained allocation-plan
digest and witness token, source/candidate hashes, profile, source registration,
ResourcesDB hash and historical storage path. Use the common command options with:

```sh
--check-destination --plan-digest "$INDEPENDENTLY_RETAINED_PLAN_DIGEST" \
  --org-key-file /private/organization.key
```

Schema 5 permits only this check. It cannot authorize prepare/status/commit,
witness advancement or a weaker check. Schemas 1 through 4 keep their contracts.
Both ready and exactly committed allocation plans retain their existing guarded
reconciliation and post-check binding/witness validation. All legacy candidate,
selected source registration and whole source-export checks remain mandatory.

`destinationResources` must be exactly `ResourcesDB` beside the candidate
ColumnFile, in its disjoint private staging directory. The source and candidate
ColumnFile basenames must differ; neither a reserved internal DB name nor a
candidate alias for a source artifact is accepted. All four DB artifacts must
have distinct file identities, private canonical uid-owned 0600 single-link
regular rollback-journal files without links or sidecars. Each ResourcesDB has
its own independently approved full-file SHA256. Existing disjoint control,
custody, authority, source-export and candidate-directory rules still apply.

The destination registration vector has the same exact five-element types and
limits as the source vector. Its positive row ID must be unused in the source
ResourcesDB and differ from the selected source row. Its document ID must differ
from EVERY existing source document ID, including documents with another column
or type. Storage ID, org-resource ID and column ID must equal the independently
approved source association. The destination storage path must be independently
supplied and equal the source's approved historical path literally. This phase
supports only a fresh-document, same-storage, same-column legacy copy, not a
cross-storage move or arbitrary metadata edit. Neither path is used to open files
or derive registry UUIDs. The trusted owner must independently approve the bridge
between those plaintext selectors and the manager namespace.

Hold bounded read-only SQLite transactions on both ColumnFiles and both
ResourcesDBs, disable trusted schema, and verify ResourcesDB schema/version,
definitions and integrity. Authenticate every protected field of the new row,
all three lookup values, its exact candidate basename, `file.csv`, single-part
shape, unique selector/filename, unique approved local storage association and
whole-candidate partMAC under that row's salt and the approved organization key.
The candidate remains a byte-exact legacy clone, so a new row salt requires its
own correct file MAC even though payload bytes are unchanged.

Then compare the source DB against the staged DB with ONLY the new approved
document row excluded. Every existing logical cell, SQL type, salt, protected
value, lookup, metadata row and schema object must remain exact; deleting,
replacing, modifying or adding other rows/objects fails closed. Only physical DB
layout/free pages may differ, and the full-file approved hash pins those bytes.
The new row must retain the source row's decoded user/org, resourceInfo, type,
storage/org-resource, part count/ID, lastModified and column ID. Re-salting and
re-encrypting that new row is allowed; its row/document identity, filename,
salt/field ciphertexts and corresponding file MAC are the intended differences.

Success adds `state=verified-legacy-destination`,
`destination-registration=verified-add-only-copy` and the independently approved
`destination-resources-digest`, retaining source inventory/registration and plan
metadata, `publication=disabled` and `context-authentication=absent`. No plaintext
paths, IDs or keys are printed. File identities/metadata and authority bindings
are rechecked after verification. Existing 4096-row/work budgets and stopped,
fixed-directory preconditions apply; this result is not a lease or durable
acceptance receipt. Staging needs only the candidate ColumnFile and ResourcesDB;
it is not accepted as a complete destination export or runtime installation.
Unselected payload contents and RolesDB/LogsDB retain phase-21's limited checks.

TODO #147 remains open. Next implement reviewed durable copy publication and crash
reconciliation tying candidate artifacts, registration and destination map to the
retained allocation plan and explicit witness approvals. Context-aware V2
re-encryption/substitution rejection, provider/migration/floor acceptance,
rename/delete adapters and production custody/independent monotonic deployment
remain pending. No file copying, map/catalog publication, witness advancement,
V2 write, live storage integration or physical power-loss guarantee is added.

### Durable publication intent (#147 phase 23)

`context-copy-plan --prepare-publication` creates the durable owner evidence
needed before a future copy publisher may install artifacts or publish a map.
`--publication-status` authenticates that evidence and rechecks its approvals.
These schema-6 actions preserve all phase-22 candidate/source-export/destination
registration checks. Schemas 1 through 5 retain their existing actions.

Use exactly the twenty-four phase-22 approval keys, set `schema` to 6, and add:

```json
{
  "publicationPlan": "/private/custody/publication.plan",
  "destinationMap": "independently-approved-copy-map"
}
```

This fragment is not a complete manifest. Retain ORIGINAL allocation pins and the
independently retained allocation-plan SHA256. First commit the allocation through
schema 1 and explicitly advance the witness to the exact committed registry with
unchanged catalog. Independently retain that CURRENT witness token; the old token
from the last transition is refused here even when allocation recovery could
reconcile it. Neither action commits identities or advances the witness for you.

Use the common approval/confirmation/manager/witness options with:

```sh
--prepare-publication --plan-digest "$RETAINED_ALLOCATION_DIGEST" \
  --org-key-file /private/organization.key
```

Prepare performs complete legacy preflight and requires the exact committed
allocation registry, original catalog, current witness token and an unused valid
destination map name, distinct from the source map. The trusted manager produces
deterministic signed binary bytes binding the full allocation digest, a canonical
typed request SHA256, committed 73-byte registry anchor, 40-byte catalog anchor
and length-prefixed destination map name. The domain is
`CDSE-HKX-COPY-PUBLISH-v1` followed by NUL; HMAC-SHA256 under the manager key covers
all preceding bytes, and a separate SHA256 covers the entire signed intent.
The bounded format is at most 512 bytes. Manager APIs treat requestDigest as a
trusted issuer assertion; the installed owner supplies the artifact verification
and witness checks. A holder of the manager key remains a trusted issuer.

The request fingerprint uses domain `CDSE-HKX-COPY-REQUEST-v1` plus NUL and schema
byte 6. It covers every parsed approval string in fixed internal field order
(including custody and destination map), with eight-byte big-endian lengths;
unused internal fields are empty. Raw JSON arrays are replaced by their typed
contents: eight-byte lookup count, ordered length-prefixed lookup strings, then
source and destination eight-byte row IDs and their four length-prefixed selector
strings each. JSON key order, whitespace and equivalent string escaping are not
identity. Paths, profile, digests, selector values and lookup order remain exact
approved evidence. Reapproving even a logically equivalent ResourcesDB with
different physical bytes invalidates the retained intent. No pins are refreshed.

`publicationPlan` must be a different canonical basename in the SAME private
custody directory as the allocation plan, disjoint from approval/key controls,
source export, staging and manager/witness authority. Prepare exclusively creates
an owned 0600 single-link regular file, writes the exact signed bytes, fsyncs the
file and custody directory, and rechecks authority/witness approval before
reporting success. Existing, partial and uncertain names are never overwritten
or deleted. Other source/artifact/authority files remain unchanged. There is no
manager receipt table, catalog schema upgrade or binding block in this phase.

Independently review and retain `publication-plan-digest` before any future
publication, in addition to the allocation digest and witness evidence. If prepare
loses its acknowledgement, retain the file and independently review/approve its
digest; never regenerate blindly. Status requires:

```sh
--publication-status --plan-digest "$RETAINED_ALLOCATION_DIGEST" \
  --publication-digest "$INDEPENDENTLY_RETAINED_PUBLICATION_DIGEST" \
  --org-key-file /private/organization.key
```

Status requires the exact same semantic schema-6 request and both retained
digests. It reads and syncs the private bounded file, authenticates its complete
bytes/request, repeats preflight and checks the exact current manager/witness
pair plus unused map name. Missing, truncated, oversized, linked, public,
tampered or substituted evidence fails closed; no file is recreated or repaired.
Later registry/catalog changes expire this preparation window. Files must still
be staged and unchanged; status is not a recovery command after installation.

Success reports `state=publication-prepared` or `publication-current`, allocation
`plan-digest`, `publication-plan-digest`, `request-digest`, `publication=disabled`
and `context-authentication=absent`. No plaintext paths/IDs/map names or keys are
printed. Hashes remain owner-sensitive. Stop all readers/writers and hold the
directory hierarchy fixed; these checks provide no concurrent-reader lease.

Tests cover normal GCM/CBC handoff, unchanged authority/artifacts, unavailable or
unadvanced allocation/witness, no overwrite, bounded partial writes, real SIGKILL
with acknowledgement withheld, tampering despite a reapproved file hash, wrong
requests/custody, canonical JSON, freshly reapproved physical DB bytes, stale
authority, unsafe evidence and strict schema/action isolation. Neither process
interruption testing nor fsync certifies physical power-loss recovery.

TODO #147 remains open. Next connect this retained intent to a guarded durable
artifact/catalog publisher with blocking and crash reconciliation; the intent
alone does not enforce use by other trusted manager APIs. No files are copied or
installed, no map/catalog/witness is published, and no durable acceptance token,
live adapter or V2 write is enabled. V2/provider/migration/floor, rename/delete
and production custody/independent monotonic deployment gates remain pending.

### Manager copy publication and recovery (#147 phase 24)

Trusted offline owners can now use `cmeContextManagerCopyInstallInit/Prepare/Read/Recover`
to publish a same-storage legacy ColumnFile copy and its ResourcesDB registration,
then atomically publish the destination map in the manager catalog. This is the
manager core, not an installed publisher command or live storage adapter. It
accepts an independently retained phase-23 allocation/publication intent and an
owner-verified artifact assertion. It never validates organization-key crypto or
advances a witness. Keep every reader/writer stopped and directory hierarchy fixed.

Initialize catalog v2 (shuffle), then v3 (paired artifacts), then explicitly opt
into v4 with `CopyInstallInit`, each against exact independently approved registry/
catalog pins. Separately approve and advance the witness after EACH catalog write.
Do this BEFORE preparing allocation and publication intents. Upgrading an existing
intent's catalog expires that intent; never refresh its original pins blindly.
Init requires no prepared shuffle and cannot repeat. The registry format and file
crypto formats remain unchanged. The new `copy_version=1` marker, `context_copies`
table and `CDSE-HKX-MAP-v4` authentication domain make older catalog readers fail
closed. Legacy catalogs keep their existing formats until explicit opt-in.
Catalog v4 also refuses triggers, views, virtual and shadow tables in the authority
DB, preventing unauthenticated SQL schema from changing a job during signed writes.

After ordinary copy allocation, explicit witness advancement and full phase-22/23
preflight, pass the exact signed allocation/intent bytes, BOTH retained digests,
ORIGINAL registry/catalog pins, canonical request digest, destination map name and
`cmeContextCopyArtifacts` to `CopyInstallPrepare`. The artifacts specify source
ColumnFile, staged byte-exact clone, active/staged ResourcesDB and their three
independently approved SHA256 values. The owner must verify that the opaque
request digest commits to THESE EXACT paths/hashes/selectors and enforce the
organization-key registration/whole-export contract. The core trusts this issuer
assertion, like the earlier paired-shuffle selection commitment; a holder of the
manager key is not an adversarial caller.

The new installed ColumnFile path is the source export directory plus the staged
ColumnFile basename. It must be absent even if preexisting bytes happen to match.
Source and staged basenames must differ; reserved ResourcesDB/RolesDB/LogsDB names
are refused. ResourcesDB paths must be exact siblings of their ColumnFiles.
Export, staging and authority directories must be canonical, disjoint, private
uid-owned 0700 directories on the same filesystem. Files must be canonical,
private uid-owned 0600 single-link regular rollback-journal SQLite files without
links or sidecars. All four inputs have distinct identities. Size bounds remain
256 MiB per artifact; target slots require positive physical row IDs.

Prepare verifies the committed allocation pair and retained intent, active target
bindings, source/candidate hashes, file identities, unused destination map and
absence of other pending copies/shuffles. It signs a durable job under the full
catalog-v4 HMAC before changing any artifact. The bounded job body records source/
destination names, target resource/slots, five canonical paths, three hashes,
allocation/intent/request digests, committed registry and original catalog. Job ID
is the independently retained publication-intent digest. All map/job names, typed
blob bytes, states and completion revisions are authenticated; at most one job is
prepared globally. It simulates final-map signing inside a rolled-back savepoint
to reserve catalog capacity before allowing irreversible file operations.

The prepare catalog commit advances only catalog revision by one. It blocks ALL
stored-map bindings and normal catalog/registry writers, since ResourcesDB is
shared. Existing mapped operation bindings also fail their changed catalog pin.
Metadata reads can expose `blocked`; low-level unmapped binding/issuer APIs are
trusted primitives, not a live-reader enforcement boundary. Independently retain
the job/published catalog pins, then separately approve/advance the witness before
calling recovery. The core does not implement that witness guard for the caller.

`CopyInstallRead` returns owned authenticated metadata; free it with
`cmeContextCopyInstallFree`. On complete, `CopyInstallRecover` rechecks exact current
registry/catalog and retained job ID, the original source ColumnFile, active file
classification and ALL still-needed candidates before the first move. It creates
the new ColumnFile with Linux `renameat2(RENAME_NOREPLACE)`, syncs both directories,
replaces ResourcesDB only from the approved original bytes, syncs again, then
commits the destination map and completed receipt together in one catalog update.
The original source ColumnFile, source map and registry identities are preserved.
Linux kernel no-replace support is required; unavailable primitives fail closed.
There is no fallback to an overwriting rename for the new ColumnFile.

An interruption before or after either move retains the signed prepared job and
binding block. Recovery accepts only the approved old/new file classifications,
can finish from already-installed bytes without the consumed staging file, and
publishes the map exactly once. Unknown/missing active bytes retain the block.
Abort requires the original source ColumnFile/ResourcesDB and absent new file;
once the new ColumnFile exists, only forward completion is allowed. Abort changes
no artifacts and retains candidates/evidence. Completed/aborted jobs remain as
authenticated receipts; names are not reused by another copy job. An exact
lost-ack retry at the finished registry/catalog pair verifies active artifacts and
syncs directories without another revision change. Later authority changes expire
the retry window. After either completion or abort, independently approve and
advance the witness to the new catalog before subsequent owner operations.

Tests exercise actual GCM/CBC encrypted readback, map publication and source
preservation, global blocking, no-replace conflicts including a paused writer,
typed authentication rules, original-only abort, missing/tampered files,
retained-intent mismatches, catalog output aliasing, journal/schema tampering,
real process-kill checkpoints before/after both file moves and SQL commit, and
lost-ack retries. A retained actual catalog-v3 reader is an optional regression
probe and rejects v4. No cross-file transaction, concurrent-reader lease, V2
context authentication or physical power-loss certification is claimed.

Phase 24 leaves the installed witness-guarded owner adapter to phase 25 below.
TODO #147 remains open for the remaining V2 and deployment acceptance work. V2 re-encryption/substitution rejection, provider/
migration/floor acceptance, rename/delete and production custody/independent
monotonic deployment remain pending. Installed schema-1 through schema-6 command
contracts and live routes remain unchanged.


## Installed copy publication (#147 phase 25)

`caumedse-admin context-copy-plan` now exposes the phase-24 publisher through
explicit owner and witness guards. This is an offline, Linux-only, byte-preserving
legacy copy. Stop all readers/writers and keep authority, custody, export and
staging directories fixed throughout; no live-reader lease is acquired.

Before creating allocation or publication plans, explicitly upgrade the catalog
through the existing shuffle/pair initialization steps and advance the independent
witness after each. Then use the phase-18 **schema-1** allocation approval with
`--init-install`, the registry/witness keys, exact offline confirmation and the
independently retained current witness token. This upgrades v3 to v4 and prints the
new catalog pin plus `witness-state=advance-required`. It creates no allocation or
job and cannot be repeated. Independently review that catalog publication and use
the existing **schema-2** `context-witness --advance PREVIOUS_TOKEN` contract to
advance the witness; retain its new token. Reapprove the new catalog in the
allocation manifest before generating/committing an allocation plan. Do not reset
an uncertain initialization; review current manager pins and reconcile the witness.

Retain and review the allocation digest, commit it, advance the witness, and
prepare/retain the phase-23 schema-6 publication intent and its digest as before.
The original schema-6 manifest remains unchanged for every install/recovery action.
All commands use the original private approval file and canonical offline
confirmation, registry key, witness directory/key and retained witness token.

```sh
# Repeat complete payload/registration/export/destination crypto checks, verify
# both retained plans, then persist the authenticated block without moving files.
caumedse-admin context-copy-plan --approval "$APPROVAL" \
  --confirmed-offline "$APPROVAL" --registry-key-file "$REGISTRY_KEY" \
  --witness-directory "$WITNESS" --witness-key-file "$WITNESS_KEY" \
  --retained-witness-token "$RETAINED_TOKEN" --prepare-install \
  --plan-digest "$ALLOCATION_DIGEST" --publication-digest "$PUBLICATION_DIGEST" \
  --org-key-file "$ORG_KEY"

# After independent review, explicitly approve the CURRENT manager pair.
# Use this common argument set for --install-status, --complete-install,
# --abort-install and --advance-install-witness. No organization key is needed
# after prepare: the authenticated journal binds its completed preflight.
caumedse-admin context-copy-plan --approval "$APPROVAL" \
  --confirmed-offline "$APPROVAL" --registry-key-file "$REGISTRY_KEY" \
  --witness-directory "$WITNESS" --witness-key-file "$WITNESS_KEY" \
  --retained-witness-token "$RETAINED_TOKEN" --install-status \
  --plan-digest "$ALLOCATION_DIGEST" --publication-digest "$PUBLICATION_DIGEST" \
  --current-registry "$APPROVED_CURRENT_REGISTRY" \
  --current-catalog "$APPROVED_CURRENT_CATALOG"
```

Prepare returns the published catalog pin and leaves the witness unchanged.
`--install-status` verifies the current authenticated job, original request,
original allocation signature and both retained file digests. It reports job state
and witness reconciliation without installing anything. The original request
includes all canonical phase-23 artifact, registration, pin and custody fields;
changing/reapproving the original manifest cannot substitute another request.
Current pins must be separately reviewed; they are never adopted from a candidate
or automatically fetched by the command. Status is journal state, not renewed
artifact/preflight acceptance. Missing/tampered retained evidence fails closed.

Run `--advance-install-witness` with the independently approved prepared pair and
retain the returned witness token before completing or aborting. A pending job
requires an exact current retained token; the previous token after a lost witness
acknowledgement is accepted only for an explicit witness-advance retry. Use
`--complete-install` to install forward, or `--abort-install` only while the source
files are original and the new target absent. Neither action advances the witness.
Review the resulting catalog, explicitly advance again, and retain the new token.
The complete/abort operation retains all phase-24 no-overwrite, blocking, hash,
path, typed journal, durable receipt and exact finished-pair retry protections.

After interruption, retain both plans and the original manifest, independently
review the current manager pins, then inspect status/reconcile the witness.
Recovery authenticates the journal's request/allocation/intent digests and original
catalog instead of rerunning checks on staging files that may have been consumed.
Unknown active bytes retain the block; once a move happened recovery is forward
only. An exact completed retry checks installed bytes and syncs directories without
another catalog write. Abort and completed receipts expire for this adapter after
a later catalog change. Explicit witness advancement supports exact lost-ack and
already-current retries without another witness revision.

Schema-1 through schema-6 allocation/check/publication-intent actions retain their
existing behavior. Install-only arguments on those actions, mixed actions, wrong
schemas and organization-key arguments on recovery are refused. Output is bounded
to states/pins/digests and generic diagnostics; preflight's legacy crypto logging
is suppressed as with the existing publication checks.

TODO #147 remains open. Next implement context-aware V2 copy re-encryption and
substitution-rejection acceptance before connecting this workflow to V2 runtime
writes. Provider/migration/floor acceptance, rename/delete and production custody/
independent monotonic deployment also remain pending. No V2 context authentication,
provider acceptance, cross-file transaction or physical power-loss certification
is claimed.


## Draft V2 provider acceptance (#147 phase 26)

The next prerequisite for V2 copy integration is now executable: a **test-only**
C codec and copy harness, `context-frame-fixture`, built by `make check` and
excluded from every installed binary. The draft remains subject to review.
Production `crypto.c`, storage schemas, installed owner actions and HTTP routes
are unchanged. `CDSEHKX2` is still rejected by contextless production readers;
the ownership fixture now exercises a complete, independently generated valid
empty V2 frame as well as unknown/truncated frame rejection.

The harness implements the proposed 80-byte frame, canonical context encoding,
AAD domain and frozen KDF id 1 literally. It uses the optional existing
HSKE-NL-A1 provider, PBKDF2-HMAC-SHA256 with 10000 iterations and 16-byte decoded
salt. No duplex/NLA2/V3 profile or configurable compiled KDF default is accepted.
Parsing checks exact frame lengths, supported header fields, complete nonzero
identifiers, internal-role storage sentinels and bounded canonical ASCII names.
RawPart requires `payload`/`bytes`. A 16384-byte fixture input/output cap is an
additional test resource bound, not a revision to the draft wire limit.

`aad` checks serialization even without a provider. `available` reports whether
the provider was configured; absent-provider builds refuse cipher operations
and explicitly skip the two provider-dependent test classes. `seal`, `open` and
`copy` consume hex-encoded **synthetic test** inputs. Nonces are deterministic,
provided by tests for reproducibility. This is not a safe secret-handling CLI,
a random nonce allocator or a deployable crypto API; never supply real keys or
use its deterministic examples as storage code. Secret buffers and unsuccessful
plaintext outputs are cleansed. Failed opens emit no plaintext; the harness also
checks the provider's promised untouched output buffer on authentication failure.

The fixture's V2-only reader accepts approved floors 1 or 2 but rejects every
legacy/unknown frame, without fallback. It does not implement future mixed-format
compatibility dispatch or migration closeout. Tests compose the existing C HMAC
registry reader with the codec: independently pinned signed source/target contexts
and floor 2 feed a copy; a bad registry tag is refused. This is an explicit test
composition, not an operation-scoped manager/storage adapter or revocation lease.

The copy probe decrypts/authenticates the source, then seals equal plaintext under
a different resource and record with fresh salt and nonce. It restricts the test
operation to same-deployment/organization/storage ColumnFile contexts and unchanged
table/field names. It rejects identity reuse, changed scope/field, reused salt or
nonce and invalid source authentication. Persisted temporary source/target frames
prove the source is preserved, destination bytes differ, destination plaintext
matches, and each frame is rejected under the other context. Nothing is installed,
registered, mapped or published; no ColumnFile SQL cells, field/file MACs, export
inventories, witness checkpoints or durable copy jobs are changed by this probe.

The four committed known-answer frames (0/1/33/97 plaintext bytes) were generated
using the **upstream Python implementation**, independently of the C harness,
from the same pinned revision used by current-provider CI:
`ad42138af14a40eb3b47127872f39509723c789f`. The JSON records the Python source
SHA-256. Regeneration refuses another source hash and needs no installed Python
provider package:

```sh
git -C /path/to/HerraduraKEx show \
  'ad42138af14a40eb3b47127872f39509723c789f:Herradura cryptographic suite.py' \
  > /tmp/cdse-hkx-reference.py
python3 TEST/generate_context_frame_vectors.py /tmp/cdse-hkx-reference.py \
  > /tmp/cdse-context-vectors.json
cmp TEST/testfiles/herradurakex-context-v2-vectors.json /tmp/cdse-context-vectors.json
```

Both immutable CI headers must match these cross-language answers. This checks
interoperability and actual tag rejection, not independent cryptanalysis, algorithm
approval or a production context-authentication claim. Existing primitive vectors
and legacy storage compatibility tests remain separate. Mutation checks cover each
context ID, valid alternative role/table/field, name delimiters, salt/key, every
nonce/tag/ciphertext byte, header parameters/lengths and unsupported floors/versions.
Boundary tests include empty and 16304-byte plaintext and all five roles.

TODO #147 remains open. Next implement a reviewed, explicitly opt-in context-aware
runtime codec using authenticated operation-scoped bindings, then integrate V2
ColumnFile cell re-encryption, regenerated integrity/registration metadata and
full persisted readback into the owner staging/publication workflow. Mixed-format
and floor closeout, provider/migration acceptance, rename/delete and independent
production custody/monotonic deployment remain pending. The installed phase-25
publisher continues to accept only its existing byte-preserving legacy workflow.


## Binding-aware V2 memory codec (#147 phase 27)

`context_crypto.h/.c` now supplies explicitly named, opt-in in-process V2 APIs:
`cmeContextV2Seal`, `cmeContextV2Open` and `cmeContextV2BufferFree`. They are linked
with the existing runtime, but no installed command, storage reader/writer or
HTTP route calls them. Contextless `crypto.c` dispatch remains unchanged and
rejects V2. This adds a memory codec boundary; the draft's wider integration and
rollout gates are still open.

The caller supplies a live manager, an owner-approved **stored-map binding** from
`cmeContextManagerMapBind`, canonical table/field selectors and an operation-local
physical row. `cmeContextBindingCheckMapped` rejects raw registry-only bindings
and checks both the registry and catalog anchors. Context UUIDs and the minimum
format floor come only from that authenticated binding. Candidate frames provide
neither authority nor context. A row move under a freshly approved map preserves
cryptographic identity: the physical row is a lookup selector, not part of AAD.
Scope, role, table/field and all immutable IDs remain authenticated.

Both calls validate bounds, check the mapped binding, resolve the slot, perform
crypto work in private owned buffers, then check the binding again before
releasing any output. Revocation, floor/registry updates or catalog changes
invalidate the old binding; a post-crypto mismatch destroys tentative plaintext
or ciphertext. No secrets, candidate bytes or paths are logged by the codec.
These are point-in-time checks, not a revocation lease, concurrent-reader lock,
atomic storage transaction or independent rollback defense. The trusted caller
must retain/reconcile independent pins/witnesses, keep authority namespaces fixed,
and coordinate publication after return. A manager/witness backup replay is not
solved by adding AAD or by trusting a pin read from the replayed manager itself.

The frame/AAD encoding matches the phase-26 cross-language vectors exactly:
`CDSEHKX2`, profile 1 (existing optional NLA1), flags 0, KDF 1, context schema 1,
80-byte header, decoded binary 16-byte salt and canonical structured context.
KDF 1 freezes PBKDF2-HMAC-SHA256 at 10000 iterations and a 32-byte key; this is
compatibility with the draft, not a new password-policy recommendation. Unknown
header fields, inconsistent/trailing lengths, invalid selectors and all legacy/
unknown frames fail closed. Floors 1 and 2 are read from the binding; the V2-only
reader never falls back to V1/AES, even at floor 1. A future reviewed compatibility
dispatch must not treat an authentication failure as permission to retry legacy.

Seal generates a fresh 16-byte salt and 32-byte nonce using checked OpenSSL
`RAND_bytes` calls. There is no runtime nonce override or deterministic test mode.
Password inputs are 1..256 counted bytes (embedded zero bytes are significant);
plaintext is binary and may be empty. The API has an explicit 16 MiB plaintext
resource cap, independent of the draft wire limit and the smaller phase-26 fixture
cap. Frame bounds are checked before allocation. There is no implicit Base64,
external salt-column encoding, SQL field MAC, file MAC or registration update.

Outputs are caller-owned `cmeContextV2Buffer` tuples with an additional trailing
zero outside the counted data, plus Seal's separate 16-byte salt. Inputs and
output regions must be stable/nonoverlapping during a call. Output structures
must own no allocation on entry, and the returned pointer/length must be preserved
until `cmeContextV2BufferFree`, which cleanses the whole allocation and resets the
tuple. It is safe on NULL or already-cleared tuples. Every failure clears outputs;
Seal also clears its salt output. Return codes are 0 success, 1 invalid/auth/RNG/
allocation failure, 2 stale authority and 3 optional provider unavailable. The
provider-disabled build has the same API and refuses cipher work explicitly.

The check-only `context-crypto-fixture` tests the actual runtime implementation.
Its build alone enables pause/RNG-failure hooks; production objects contain none
of their environment keys. Tests exercise source/target slots, all five roles,
independent Python known answers at both floors, phase-26 codec interoperability,
empty/binary plaintext and counted passwords, fresh random salt/nonces, salt/nonce
RNG failures, malformed frames and substitutions, raw-binding refusal and cleared
outputs. Real two-process handshakes change registry or catalog authority before
the precheck, between the precheck and crypto, or after crypto. Tests verify stale
results are withheld; a poisoned test RNG also proves precheck refusal happens
before generating output. Memory buffers are not file-installation receipts.

TODO #147 remains open. Next define an authenticated target-staging binding tied
to the independently retained copy allocation/publication intent, then integrate
V2 ColumnFile cell re-encryption and regenerated integrity/registration metadata
with full persisted readback and guarded owner publication. A raw allocation
map descriptor cannot bypass this codec's stored-map requirement, and a target
map must not be prematurely published merely to obtain a binding. Mixed-format
migration/floor closeout, provider acceptance, rename/delete and production
custody/independent monotonic deployment also remain pending. Installed copy
publication still supports its existing byte-preserving legacy workflow only.


## Authenticated copy-target staging (#147 phase 28)

The missing unpublished-target boundary is now explicit. A read-only constructor
can derive an operation-local `cmeContextCopyTarget` from the independently retained
signed copy-allocation plan/digest, original registry/catalog pins, and separately
approved source-map name and target lookup vector. It requires the exact committed
allocation and an independently advanced witness with the exact current retained
token. It creates no destination map, SQLite row, artifact, copy job or witness
revision. Source maps and registrations stay unchanged.

The core `cmeContextManagerCopyPlanBind` authenticates the plan/request, classifies
the allocation as committed, requires the original catalog to remain current and
the source to be active/unblocked, validates positive ColumnFile slots, and binds
the allocated target contexts against the current authenticated registry. Its
opaque binding has a separate target kind and copied catalog anchor. It returns
the committed registry anchor and clears both outputs on failure; the committed
anchor may alias the original input. It does not prove allocation provenance
against a trusted issuer holding the registry key, verify payloads or guard a
witness. A raw descriptor alone cannot become a target binding.

The public `cmeContextWitnessCopyTargetBind` wraps this core with a separate opaque
capability. It copies the binding/context data and approved pins/token and borrows
the existing witness handle. The caller may release the original plan buffers
after construction, but must retain/review the original durable evidence and keep
manager/witness handles and namespaces fixed until all calls finish. Free the
capability with `cmeContextCopyTargetFree` before closing the borrowed witness.
NULL and already-freed capability pointers are safe. The constructor never
advances, repairs or adopts authority. Ready allocations, stale pins, changed
source/lookups, substituted or rehashed-but-unauthenticated plans, missing evidence
and previous witness tokens fail closed. Even an exact lost-ack token classified
as `AlreadyAdvanced` must be explicitly reconciled/retained before construction.

Typical trusted offline sequence:

1. Prepare and independently retain/review the signed allocation plan, digest,
   original pins, source map and desired lookup vector.
2. Commit that allocation through the existing witness guard. This publishes
   identities only; retain and review the resulting registry anchor.
3. Explicitly advance the witness and independently retain its new token.
4. Construct `cmeContextWitnessCopyTargetBind` from the original plan/request pins
   plus the exact current retained witness token.
5. Use `cmeContextV2SealCopyTarget`/`cmeContextV2OpenCopyTarget` on approved slots.
   Release buffers and the capability when finished; coordinate further staging
   and publication through a separately reviewed owner workflow.

The target variants use the same strict V2 frame/AAD/KDF, checked random salt/nonce,
16 MiB limit, counted binary credentials, cleansing buffers and error codes as the
stored-map APIs. Context/floor come only from the authenticated capability.
`cmeContextCopyTargetCheck` rechecks registry/catalog state around strict witness
reconciliation; crypto checks it before and after provider work. A registry or
catalog change, lost witness currency or witness replay detected against the
retained token withholds and destroys tentative output. These are point-in-time
checks, not a joint transaction, lease, power-loss guarantee or independent
hardware/backup freshness mechanism. Lookup alone is not a current-state check.
Keep all authority readers/writers quiesced and apply the established independent
retention/custody policy; selecting an old manager, witness and old retained token
together defeats this software checkpoint by definition.

Ordinary `cmeContextV2Seal`/`Open` continue to require stored-map bindings;
`cmeContextBindingCheckMapped` now tests that exact kind rather than truthiness.
Raw and core-only target bindings cannot bypass it. Only the separately typed,
witness-guarded capability can enter target crypto. No target map is prematurely
published to obtain this authorization. Catalog/registry generation changes
invalidate the capability even if its particular registrations remain active.

**Current version-1 allocation plans are floor-1-only.** Raising the trusted floor
expires the capability; the existing allocator refuses new floor-2 plans. This
phase preserves that compatibility gate. Stored-map V2 reads at floors 1 and 2
remain unchanged. Copying after floor closeout needs a separately reviewed plan/
migration contract; no decoder or allocation policy is silently broadened here.

Tests persist source/target synthetic frames, prove equal decrypted plaintext,
preserve the source and both authority databases, and reject cross-resource/
record/field substitution. Other cases cover exact retained evidence/request pins,
ready/unacknowledged/forked plans, witness rollback, positive slot bounds, token
strictness, raw/stored/target kind separation, all allocated slots, RNG failures,
capability expiry and no map/witness publication. Real two-process pauses replay a
witness or change registry/catalog state before checks, between checks and crypto,
and after crypto; all detected changes withhold results.

TODO #147 remains open. This capability authenticates **identity allocation**, not
organization-key preflight, complete SQL inventory, transformation intent, file
hashes, field/file MACs or registration integrity. Next add reviewed V2 ColumnFile
staging with complete source/destination verification and regenerated integrity/
registration metadata, then design the corresponding V2 acceptance/publication
contract. Existing legacy publication intents and installed byte-preserving owner
commands are unchanged and must not be reused as V2 artifact-acceptance receipts.
Mixed-format migration/floor closeout, full provider acceptance, rename/delete and
production custody/independent monotonic deployment also remain pending.


## Complete-source ColumnFile staging (#147 phase 29)

`cmeContextColumnStageCreate` is an opt-in trusted offline **memory-only**
legacy-to-V2 candidate builder. It takes the independently retained and approved
SHA-256 digest of a complete closed SQLite image, the image bytes, a legacy
organization key and profile, counted target credentials and the phase-28 target
capability. No file path or caller SQLite connection is opened or modified. The
source digest is an external approval pin; it does not authenticate ResourcesDB
registration, establish source provenance by itself or make legacy CBC cells
context-bound. Protect the digest/evidence outside the export.

The capability now retains its approved source-map name. The read-only
`cmeContextCopyTargetSource` obtains an owned map and stored-map binding using
that capability's committed registry and original catalog pins, with exact
witness checks around construction. The staging API cannot select another map
or trust labels supplied by a candidate artifact. Callers free these results with
MapFree/BindingFree. Existing target lifetime and quiescence rules still apply.

The builder copies and hashes the source before parsing an immutable private
SQLite image. It accepts only rollback-format headers, data/meta tables with the
known INTEGER-primary-key/TEXT schema, no additional objects or generated/hidden
columns, positive bounded row IDs, no OTP helpers, valid text types and SQLite
integrity. WAL images, alternate schemas, triggers and auxiliary tables refuse.
SQLite defensive/query-only/trusted-schema settings, length/column/SQL limits
and a progress budget bound parsing. Builds without SQLite deserialize return
unavailable (3), without introducing an unconditional dependency on that symbol.

For each data row, the authenticated source map must contain exactly value,
userId, orgId and rowOrder; each meta row requires attribute, attributeData,
userId and orgId. No missing, duplicate, extra or unsupported slots are accepted.
The snapshot and map must cover the same complete row inventory. Sources are
restricted to homogeneous `aes-256-gcm` or `aes-256-cbc` data and metadata under
the supplied key, at the existing version-1 allocation floor 1. Canonical Base64
content (allowing legacy newline wrapping), 16-byte hexadecimal row salts,
salted-value prefixes, successful explicit-profile decryption, known unique
metadata declarations, required name/protect metadata and complete row-order
permutations are checked. All enabled MAC/sign/MACProtected/signProtected tags
are verified with the existing SHA-256 HMAC semantics; disabled tags and OTP
helpers must be empty. These legacy sign fields remain HMAC compatibility fields,
not digital-signature claims. No global encryption profile is changed.

**All source preflight completes before any target entropy/provider operation.**
The builder then stages every approved cell with fresh V2 salt/nonce using the
phase-28 target-specific codec and opens it under the same allocated target
identity to compare plaintext before returning. Protect/shuffle attributeData
values are rewritten to the explicit draft candidate profile
`herradura-hske-nl-v2-profile1`; other identity-bearing metadata is preserved.
Integer physical row IDs and logical rowOrder semantics are retained. The staged
object contains only slot coordinates, per-cell salts and encrypted frames;
it never carries plaintext or copied legacy integrity/helper columns.

`cmeContextColumnStageCount` and `cmeContextColumnStageCell` return a borrowed
immutable view until `cmeContextColumnStageFree`. NULL/out-of-range accessors
return zero/NULL; free is NULL-safe and idempotent. The output starts empty and
stays empty on every error; tentative frames and plaintext are cleansed on
failure. Free all owned buffers, including allocation trailing zeros, using the
provided functions. Successful construction owns its ciphertext independently of
the input image. Bounds are 16 MiB per source image, 256 KiB per SQL cell, 4096
registry slots and 32 MiB total candidate storage. Source keys are bounded C
strings; target passwords remain counted binary credentials. Provider absence
returns 3 after valid source preflight; there is no alternate-provider fallback.

The stored source binding and target capability are checked after preflight and
before releasing the complete candidate. Each cell also uses the codec's existing
pre/post registry/catalog/witness checks. Detected revocation, catalog changes or
witness replay destroy and withhold the entire partial candidate. These checks
are point-in-time, without a lease or joint database/witness transaction. Keep
writers and authority namespaces quiesced through subsequent owner decisions.
A returned candidate may later expire; accessors alone do not authorize use or
publication. Retain original evidence and revalidate authority in future flows.

This is **not a persisted V2 ColumnFile format or an acceptance receipt**. It does
not regenerate legacy row tags, file MACs, ResourcesDB records, target map entries
or owner publication intents. Its AEAD tags authenticate candidate cells only.
Phase 30 below defines the serialized V2 field/salt and container-integrity
representation. Still regenerate/verify complete destination registration integrity and design a retained
transformation/acceptance contract before adding physical publication. Existing
legacy byte-preserving commands and intents must not consume this candidate.
Mixed-profile/provider sources, floor-2 allocation/migration closeout, production
custody and independent monotonic deployment remain open under TODO #147.


## Serialized V2 ColumnFile container (#147 phase 30)

`cmeContextColumnStageSerialize` and `cmeContextColumnStageDeserialize` add an
explicit **offline, unpublished** container codec around the phase-29 candidate.
They return owned bytes or encrypted cells in memory. They open no file paths,
change no registration or authority state and enable no live/legacy dispatch.
This format is separate from the legacy data/meta ColumnFile schema. It must not
be handed to installed legacy publication intents as an accepted artifact.

Container schema version 1 uses a rollback-format SQLite image with 4096-byte
pages, UTF-8 database encoding, application_id `0x43445332` (1128551218, CDS2),
user_version 1, an exact page-count/byte-length match and no freelist pages. WAL,
trailing bytes, other page sizes and unsupported header values refuse. SQLite
integrity_check must pass. The two sqlite_master table definitions must match
these exact strings, with no extra objects, indexes, triggers or schema variants:

```sql
CREATE TABLE cdse_column_v2(version INTEGER NOT NULL,profile TEXT NOT NULL,integrity TEXT NOT NULL,cellCount INTEGER NOT NULL)
CREATE TABLE cdse_column_v2_cells(ordinal INTEGER PRIMARY KEY,salt BLOB NOT NULL,frame BLOB NOT NULL)
```

The header table has exactly one row at rowid 1: integer version 1, text profile
`herradura-hske-nl-v2-profile1`, text integrity
`aead-context+inventory+sha256-pin`, and integer cellCount equal to the complete
capability source-map inventory. Unknown versions/profiles/integrity declarations,
types and duplicate/missing header rows refuse. Schema definitions are deliberately
strict; this is not a generic importer of semantically similar SQLite schemas.
The overall SQLite byte encoding is not promised canonical across SQLite versions;
independently retain the hash of the actual image produced and approved.

Cell ordinals are consecutive INTEGER primary keys 1..cellCount in the approved
map's canonical ASCII table, numeric physical row, ASCII field order. Every data
row has exactly orgId, rowOrder, userId, value, and every meta row has exactly
attribute, attributeData, orgId, userId in that order. At least one row of each
table is required. No missing/duplicate/extra/unsupported map slots or cell rows
are accepted. The container stores **no lookup, UUID, resource name or coordinate
labels**. Its ordinal is resolved only through the authenticated map retained by
the target plan; file-supplied labels cannot become identities.

Each salt is exactly 16 BLOB bytes. Each frame is a BLOB containing the existing
strict CDSEHKX2/profile1/KDF1/AAD-schema1 header, nonce, AEAD tag and ciphertext;
there is no Base64 or legacy-frame fallback. No plaintext is stored in SQLite.
The writer builds a fresh in-memory database and never deletes/updates plaintext
rows, avoiding historical plaintext in free pages. The reader copies the image
before hashing/parsing it, uses read-only deserialize plus defensive/query-only/
trusted-schema settings, length/column/SQL limits and a VM progress budget. It
validates the entire structural inventory before the first cell crypto call.

Container integrity is the conjunction of:

- Successful V2 AEAD verification of every cell under its allocated target context.
- Exact coverage/ordinal resolution through the independently approved complete
  source map and current registry/catalog/witness capability.
- An **independently retained and approved SHA-256 pin of every image byte**,
  checked before SQLite parsing. A hash merely attached to an untrusted file is
  not authentication, registration validation or source-provenance approval.

The serializer requires target credentials and always runs the authenticated
reader on its private serialized image before releasing either bytes or digest.
Serialization/readback generates no new crypto entropy: it preserves the staged
salts/frames exactly. Entropy was generated and checked during phase-29 staging.
The reader opens every frame, rejects embedded-NUL plaintext, verifies unique
known metadata declarations, required name/protect entries, the exact V2 protect/
shuffle profile, SHA-256 provenance algorithm declarations, and a complete logical
rowOrder permutation. Empty data values and counted binary passwords are supported.
Plaintext is bounded and cleansed; only an owned encrypted candidate is returned.
The original image can be freed after successful readback.

Legacy MAC/sign/MACProtected/signProtected **algorithm declarations** are retained
as source provenance because their cells belong to the approved inventory. They
do not activate legacy helper columns in this format. Those columns do not exist;
container integrity is exclusively the fixed scheme above. This adds no new MAC
primitive and makes no digital-signature claim. Whole-file registration integrity
and ResourcesDB partMAC/profile representation need a separate reviewed contract.

Both APIs clear all outputs on error and return 0/1/2/3 as the V2 codec; SQLite
serialize/deserialize absence also returns unavailable (3). Use V2BufferFree for
the image and StageFree for readback cells. Inputs/outputs must be stable and
nonoverlapping, with no output allocation owned on entry. Limits are 32 MiB per
container, the existing 4096 slots/32 MiB candidate bound, 256 KiB plaintext per
cell and 16 MiB total transient plaintext. Source staging remains floor-1-only.

Registry/catalog and exact witness currency are checked around construction,
each crypto operation and final output release. Detected changes destroy the
entire image/candidate, including earlier decrypted cells. These are point-in-time
checks, not a lease or joint authority/file transaction. A digest and returned
candidate are **not** transformation/acceptance receipts. Keep namespaces and
writers quiesced, retain original evidence independently, and revalidate authority
in any later owner flow. Coherent replay of old authorities and old retained
pins still requires the existing independent rollback/custody defenses.

TODO #147 remains open. Phase 31 below binds the source, allocation and candidate
to retained transformation evidence plus an external registration-approval pin.
Complete registration/integrity validation and acceptance remain required before guarded
physical publication and published-map reads. Full mixed-profile/provider source
acceptance, floor-2 migration/allocation closeout, rename/delete and production
custody/independent monotonic deployment also remain pending.


## Retained ColumnFile transformation receipts (#147 phase 31)

`cmeContextColumnTransformPrepare` and `cmeContextColumnTransformVerify` add a
separately retained **transformation receipt**, not a complete artifact-acceptance
or publication receipt. Both require the independently approved source/candidate
image hashes, homogeneous AES-GCM/CBC source profile, absent destination-map name
and nonzero SHA-256 digest of an independently protected registration approval
document. Keep the original images, allocation plan/request, pins and approval
document independently; do not adopt values supplied by an untrusted artifact.

**The registrationEvidenceDigest is an opaque external approval pin.** These APIs
do not parse ResourcesDB, verify its selected rows, regenerate partMAC, prove
physical source provenance or verify complete destination registration integrity.
A caller-supplied hash is not a registration check. That remaining acceptance
boundary must be implemented before any consumer can publish an artifact. The
new receipt is intentionally incompatible with legacy copy-publication intents.

Preparation and verification both authenticate and inventory the entire pinned
legacy source using the phase-29 schema/key/salt/metadata/order/HMAC rules. They
read back the pinned V2 image using phase 30, then compare every approved cell's
plaintext byte-for-byte under the target binding. Only the already defined
protect/shuffle attributeData rewrite to `herradura-hske-nl-v2-profile1` is allowed.
All other values, user/org fields, metadata and logical rowOrder must match.
A valid AEAD image containing an unauthorized changed value is insufficient;
even a syntactically correct manager-signed receipt cannot bypass this comparison.
Plaintext stays private, bounded and cleansed, with no output plaintext exposed.

The target capability now retains the exact allocation-plan digest.
`cmeContextCopyTargetEvidence` returns its copied allocation digest, committed
registry anchor, original catalog pin and exact acknowledged witness token,
checking current authority before and after copying. Outputs clear on failure.
The underlying plan still authenticates the original source-map/request approval;
no candidate-supplied labels or pins become authority. Existing target/witness
lifetime, fixed-namespace, floor-1 allocation and quiescence rules still apply.

Receipt v1 canonical body is the following concatenation (integers big-endian):

1. `CDSE-HKX-COLUMN-TRANSFORM-v1` including its trailing NUL byte.
2. Retained allocation-plan SHA-256 digest (32 bytes).
3. Committed registry anchor (73 bytes): deployment UUID, organization UUID,
   uint64 generation, uint8 floor, SHA-256 registry digest.
4. Original catalog pin: uint64 revision and 32-byte digest.
5. Exact retained witness token: uint64 revision and 32-byte digest.
6. Source-profile byte: 1 for aes-256-gcm, 2 for aes-256-cbc.
7. Source-image digest, candidate-image digest and registration-evidence digest,
   each 32 bytes.
8. Destination map: uint8 byte length and 1..128 ASCII bytes using the existing
   manager lookup alphabet (letters, digits, underscore, slash, colon, hyphen).

Compute requestDigest = SHA-256(body). The final 32-byte tag is HMAC-SHA-256
under the separate manager registry key over:

`CDSE-HKX-COLUMN-TRANSFORM-SEAL-v1` including NUL, followed by the 73-byte registry
anchor, 40-byte catalog pin, length-prefixed destination name and requestDigest.
The receipt is body || tag, at most 512 bytes. The returned receiptDigest is
SHA-256 of all receipt bytes including the tag. Neither organization keys nor
passwords/fingerprints/plaintext are serialized. There is no timestamp, entropy
or one-time-consumption promise; equal evidence produces equal receipts.

`cmeContextManagerColumnTransformSign` is a **trusted-core signature primitive**.
It checks manager/catalog pins and absence of the destination name in a read-only
manager transaction. It does not inspect payloads, witness state or registration
approval and must never be used alone as an acceptance verifier. The high-level
APIs surround it with exact target/witness checks and complete artifact comparison.
Verify first checks the independently retained receipt hash, exact canonical
request/evidence body and tag, then reruns source/candidate verification. Checking
only the signature/hash is deliberately not an exposed high-level success path.

Source and candidate validation are read-only and entropy-free; they do not
regenerate fresh staging frames. No global profile, authority, witness, copy job,
map, ResourcesDB row or physical file changes. An existing destination name,
including the source name, refuses. A later registry/catalog/witness change
expires the operation/receipt; no automatic adoption, witness advancement, reset
or intent conversion occurs. Final checks withhold the entire receipt or Verify
success when a change is detected after comparison/signing. These are still
point-in-time checks, not a joint transaction or lease; independent custody and
rollback defenses remain necessary against coherent replay of old state/pins.

Prepare returns an owned V2Buffer receipt plus digest; free with V2BufferFree.
Both outputs clear on failure. Verify returns only status. All inputs/outputs
must remain stable and nonoverlapping; output buffers own no allocation on entry.
Return codes remain 0 success, 1 invalid/auth/comparison/unavailable-state failure,
2 stale authority conflict, 3 unavailable codec/SQLite feature. Existing 16 MiB
source, 32 MiB container and cell/inventory/plaintext bounds remain in force.

Phase 32 below adds selected ResourcesDB registration-integrity verification;
phase 33 consumes that evidence for complete supplied CSV-export acceptance.
TODO #147 remains open for physical custody, guarded publication, published-map
reads and the prior mixed-profile/provider/floor-2 migration, lifecycle and
production-custody closeout gates.


## Verified V2 copy registrations (#147 phase 32)

`cmeContextColumnRegisteredPrepare` and `cmeContextColumnRegisteredVerify` layer
actual selected-registration checks over the phase-31 transformation receipt.
They take independently pinned source/candidate ResourcesDB images, a typed
registration approval and explicit credentials/payload buffers. They never open
artifact paths, rewrite metadata, publish files/maps, advance a witness or enable
live readers. Callers must separately prepare and approve the candidate snapshots.

Scope is one single-part local ColumnFile copy. The candidate ResourcesDB must
preserve every existing logical cell and sqlite_master definition byte-exact,
including the original source registration, and add exactly the independently
approved destination documents row. Raw SQLite layout may differ only under its
separately approved whole-image hash; no unrelated row/field/schema change is
allowed. Require current ResourcesDB schema metadata, the known seven-table
layout and column counts, proper primary keys, no hidden/generated columns,
virtual/shadow tables, triggers or unknown objects. Supported indexes remain
identical to the source. Integrity checks, read-only deserialize, defensive/
query-only/trusted-schema settings, SQL/cell/column limits and a VM budget bound
parsing. WAL snapshots are refused. The API changes no global encryption profile.

Metadata remains homogeneous legacy AES-GCM or AES-CBC in BOTH ResourcesDB
images under the same registration key. This profile/key is explicit and separate
from source-payload profile/key and counted binary V2 credentials. No metadata
key/profile rotation is implied. Every protected field of the two selected rows
must authenticate its existing HMAC prefix and strict salted-value encoding.
Selector lookup fields must equal the existing deterministic, field-separated
keyed lookup of documentId/storageId/orgResourceId. Metadata decoder reuse is
private; it does not add a contextless V2 or legacy fallback.

The selected source row must match approved row ID, basename, document ID,
storage ID, orgResourceId and column ID, type file.csv, and totalParts/partId 1.
The added destination row must match its independently approved new row ID,
new basename and new document ID, retain the same storage/org/column selectors,
and use type **file.csv.cdse-v2** with totalParts/partId 1. That new type is an
explicit OFFLINE V2 container marker; installed legacy routes/commands are not
extended to consume it. No extra ResourcesDB column or schema version is added.
The protected source/destination userId, orgId, resourceInfo, storage/org/column,
part counters and lastModified plaintext must remain equal. New row salt,
ciphertexts and lookup for the new document ID may differ as required.

For each selected row, decrypt partMAC and verify the existing SHA-256 HMAC over
the **exact entire corresponding payload image**, using that documents row's salt
and the registration key. This is registration integrity in addition to the V2
container's per-cell AEAD/inventory/hash checks; it does not replace them. Source
and candidate payload hashes must also match the independent transformation
approval. Altering the candidate but regenerating a valid registration MAC cannot
bypass the source plaintext-equivalence comparison.

Enumerate document associations in both snapshots. Reject duplicate source
selectors/basenames, any existing destination basename or document ID, and any
extra destination association. Other columns of an existing source document can
remain as distinct approved registrations. Authenticate selectors/lookups used
for these uniqueness decisions; other pre-existing logical metadata stays exact
under the pinned source snapshot. Require exactly one matching local storage
registration and exact approved protected accessPath. Never follow that historical
path or fetch a remote provider. Multipart, remote, cross-storage, document-ID
reuse and broader metadata/export transformations remain unsupported here.

`cmeContextColumnRegistrationDigest` is a **canonical approval hash helper**, not
an artifact verifier. Independently review/retain all typed fields and both
snapshot hashes, then explicitly supply its result as the transformation approval's
registrationEvidenceDigest. The registered APIs recompute and compare this digest;
they never adopt a value from an artifact or overwrite an opaque approval pin.
The canonical v1 hash input, without a separate signature, is:

1. `CDSE-HKX-COLUMN-REGISTRATION-v1` including trailing NUL.
2. Metadata-profile byte and source-payload-profile byte (1 GCM, 2 CBC).
3. Source ResourcesDB, candidate ResourcesDB, source payload and candidate image
   SHA-256 digests, each 32 bytes, in that order.
4. Source and destination documents row IDs as uint64 big-endian.
5. Nine strings, each uint16 big-endian byte length followed by the exact bytes:
   source basename, destination basename, source document ID, destination document
   ID, storage ID, orgResourceId, column ID, approved absolute storagePath and
   destination-map name.

Row IDs are positive, different and <= INT_MAX. Basenames are different ASCII
leaf names up to 255 bytes using letters/digits/underscore/hyphen/dot, without a
leading dot or internal DB reserved name. Document IDs are different; selectors
are bounded non-control C strings up to 128 bytes. storagePath is an approved
literal absolute string up to 1024 bytes, not a filesystem-resolution claim.
Destination map must also satisfy the existing transformation API's lookup rules.

After registration verification, invoke the full TransformPrepare/Verify pipeline,
including source/candidate hashes, payload crypto/plaintext equivalence, allocation
and current registry/catalog/exact witness checks, absent destination and manager
HMAC. Recheck authority before releasing a result. Temporary decrypted metadata
and private image copies are cleansed. Operations generate no entropy and write
no authority/file state. Limits include 16 MiB per ResourcesDB image, 256 KiB SQL
cells and the existing 4096-row inventory budget. Existing payload/credential/
receipt bounds and 0/1/2/3 statuses remain unchanged. Outputs clear on failure.

The receipt wire format stays phase-31 v1. **The signature does not encode which
verifier was used.** A generic TransformVerify success is not registration
verification; consumers needing this guarantee MUST use RegisteredVerify with the
actual snapshots and independently approved typed fields. A valid generic receipt
whose referenced ResourcesDB has a wrong type, lookup or MAC still refuses.

This verifies supplied metadata snapshots and selected payload association, not
physical file/inode custody, completeness of all sibling payloads/RolesDB/LogsDB,
backup freshness or a one-time publication transaction. Phase 33 below adds a
complete retained acceptance contract for supplied single-part local CSV exports.
Physical custody/publication, published-map/live reads and prior migration/
provider/lifecycle/custody gates remain under TODO #147.


## Complete supplied-export acceptance (#147 phase 33)

`cmeContextColumnExportPrepare/Verify` consume a retained phase-32 registration
receipt and all of its independently approved inputs. They add a complete
**supplied memory inventory** contract and a distinct manager-authenticated
acceptance receipt. They never open artifact paths or enumerate export directories,
write artifacts, publish maps, advance authority, or grant publication permission.
Existing manager/target APIs still read their trusted authority state.

The supported profile is a complete local export whose source documents are all
single-part `file.csv` registrations under the explicit homogeneous legacy AES
metadata key/profile. The selected destination alone becomes `file.csv.cdse-v2`.
Non-CSV siblings, multipart, remote storage, and metadata key/profile rotation
are refused. The phase-32 logical/schema clone-plus-one rule still applies.

Supply companions sorted by ASCII leaf name: exactly every source documents
payload plus `RolesDB` and `LogsDB`. ResourcesDB and the one new V2 payload are
already separate RegistrationInputs. Each companion has a name, length, an
independently approved SHA-256 pin, and actual source/candidate buffers of that
length. Both buffers must match the same pin, so every original payload and
internal companion is retained byte-exact. The source and candidate ResourcesDB
and selected payload pins are additionally checked by RegisteredVerify. Missing,
extra, duplicate, unsorted, reserved/unsafe payload names refuse. Names use the
phase-32 ASCII leaf rules; internal companion names are the two explicit exceptions.
The accepted candidate inventory is therefore the complete source inventory,
with its ResourcesDB replaced by the verified clone-plus-one snapshot and exactly
one new approved V2 payload. This does not enumerate or certify a physical directory.

Authenticate every source documents protected field and selector lookup, require
single part 1/1 and type file.csv, verify its whole-payload SHA-256 HMAC, and reject
duplicate names or document/storage/org/column associations. All storage entries
must authenticate as unique local storage/org pairs at the independently approved
literal storagePath; every document must resolve to a registered pair. Source
sibling payloads are authenticated as unchanged legacy bytes; this API does not
decrypt or transform their cell contents. Selected V2 plaintext equivalence still
runs in full through RegisteredVerify. A valid selected-registration or manager
signature cannot bypass missing sibling artifacts or a bad sibling MAC.

RolesDB and LogsDB must be closed rollback-format SQLite images with current
class/schema metadata and required columns, integrity checks, no views/triggers
or virtual/shadow objects, and bounded defensive/query-only/trusted-schema-off
parsing. Their independent pins authenticate unchanged bytes, not semantic
validation of every historical protected role/log field. Extra non-executable
schema objects accepted by the existing internal schema checker are not removed
or normalized. Snapshots, keys and authority must be quiesced by the owner.

Bounds: 4098 companions (4096 documents plus two internal DBs), 32 MiB per
payload, 16 MiB per internal DB, 64 MiB aggregate companion bytes per export.
Private ResourcesDB/internal DB parsing copies are cleansed. SQLite cell/SQL/VM
limits and existing selected-artifact/credential bounds remain in force. API
inputs must remain stable and nonoverlapping; no entropy is generated.

Independently review/retain the companion names, lengths and pins before using
`cmeContextColumnExportDigest`. It hashes canonical bytes only and never adopts
artifact hashes. Canonical export approval SHA-256 input:

1. `CDSE-HKX-COLUMN-EXPORT-v1` including trailing NUL.
2. The 32-byte canonical phase-32 RegistrationDigest (which binds all selected
   selectors and ResourcesDB/payload pins).
3. Companion count as uint64 big-endian.
4. Each sorted companion: uint16 big-endian name length, name bytes, uint64
   big-endian artifact length, and the 32-byte independently approved digest.

Explicitly retain this result as ExportInputs.approvalDigest, separately from
any untrusted export. Retain the registration receipt hash independently too.
Prepare and Verify recompute these approvals, authenticate the phase-32 receipt,
and repeat all registration, transformation, full-inventory and current-authority
checks. Neither trusts a signature as a replacement for artifact verification.

Acceptance receipt v1 bytes are `CDSE-HKX-COLUMN-ACCEPTANCE-v1` including NUL,
32-byte export approval digest, uint16 big-endian registration-receipt length,
exact retained registration receipt bytes, then a 32-byte manager HMAC tag.
The tag is HMAC-SHA256 under the separate manager registry key over
`CDSE-HKX-COLUMN-ACCEPTANCE-SEAL-v1` including NUL, the 73-byte registry anchor,
40-byte catalog pin, uint8 length-prefixed destination-map name, and SHA-256 of
all acceptance receipt bytes preceding the tag. The nested receipt binds exact
allocation/witness/registry/catalog and selected-artifact evidence. This distinct
wire format cannot be used as a transformation receipt or legacy publication
intent. `cmeContextManagerColumnAcceptanceSign` is a trusted-core signature
primitive only; it does not verify artifacts. Its shared implementation preserves
the old transformation signature domain and bytes.

Prepare returns an owned V2Buffer plus SHA-256 over the entire acceptance receipt;
free with V2BufferFree. Outputs clear on every error. Verify requires that
independently retained whole-receipt pin, exact framing/body/tag, and actual
artifact revalidation. Maximum receipt 640 bytes; statuses 0/1/2/3 remain as before.
No passwords, registration keys, plaintext or paths are serialized in the receipt.
Recheck authority before returning either receipt or success, including after
signing and validation. Checks remain point-in-time and receipts replayable while
pins remain current: there is no joint transaction, lease, one-time consumption
or independent backup-freshness proof.

This completes retained acceptance for the bounded supplied CSV-only export
profile. Phase 34 below adds actual file/inode checks and exact directory
inventory through independently approved parent descriptors. TODO #147 remains
open for guarded publication/recovery, published-map/live V2 reads, wider/mixed
migrations and prior provider/lifecycle/production-custody closeout gates.
Do not feed this receipt to legacy publication workflows.


## Physical export custody (#147 phase 34)

`cmeContextColumnCustodyOpen` consumes the retained phase-33 acceptance receipt,
its independent hash, the existing typed transformation/registration/export
approvals, explicit credentials and two independently approved directory roots.
It reads the **actual files** and invokes full ExportVerify on private copies;
caller-supplied payload/ResourcesDB/companion byte buffers are ignored. The result
is an opaque ephemeral custody handle, not a new signed receipt or permission
to publish. Existing acceptance/registration receipt wire formats are unchanged.

Each root approval is an already-open parent directory descriptor plus one ASCII
child leaf name. The trusted caller approves the parent **object**, opens it
securely, and keeps manager/catalog/witness/key/receipt controls outside both
exports. This API does not resolve absolute artifact paths or certify any
ancestor pathname above that parent object. It duplicates both parent descriptors
with CLOEXEC and opens children relative to them using O_DIRECTORY/NOFOLLOW/
CLOEXEC. Parents and roots require current-euid ownership, mode 0700 and nonzero
links. Roots must be distinct and neither may be an ancestor of the other; an
inaccessible or >256-level ancestry walk refuses. Parent path renames above the
trusted namespace anchors are outside this contract. Closing the caller's parent
descriptors after Open is safe.

Enumerate each held root with an independent directory stream. The source permits
exactly every approved companion and ResourcesDB; candidate permits the same
companions, verified candidate ResourcesDB and exactly the approved new V2 file.
No hidden/extra entries, subdirectories or SQLite sidecars are allowed. Root and
artifact leaf names use ASCII letters/digits/underscore/hyphen/dot, no leading
dot, length <= NAME_MAX. All -wal/-shm/-journal suffixes are reserved here, even
if a memory-only approval would otherwise permit that name. Supplied inventory
names/pins remain independently approved; filenames or on-disk metadata never
supply crypto identities or replacement approval pins.

Open each file through its held root with O_RDONLY/NOFOLLOW/NONBLOCK/CLOEXEC.
Require current-euid-owned regular files with mode 0600, a single link, at least
100 bytes and a closed rollback-format SQLite header. Symlinks, hardlinks, FIFO/
socket/device entries and directory substitutes refuse without blocking. Exact
approved companion lengths/pins must match both source/candidate files. ResourcesDB
images are <=16 MiB and the new V2 image <=32 MiB, pinned by their existing
independent approvals. The phase-33 companion count/per-file/64 MiB aggregate
bounds remain in force. All copied artifact bytes are cleansed/freed before Open
returns, including on failure. Only the explicit credentials fields of
RegistrationInputs are read; only companion names/lengths/digests and retained
registration evidence from ExportInputs are read.

Hash each actual file with bounded pread; compare descriptor and named-entry
metadata before/after the read. Run full acceptance, actual registration/MAC/
lookup, plaintext-equivalence and current-authority verification over those file
copies. Then reopen and rehash every file against the captured object metadata,
re-enumerate both roots, and recheck every named-file stat and root binding plus
current authority before returning. All file comparisons include device, inode,
size, owner, group, mode, link count, nanosecond mtime and ctime; atime is excluded
because read-only verification may update it. Root comparisons include the same
identity/change metadata; parent checks retain object identity, group and private
ownership/mode, not an unrelated parent-entry inventory.

`cmeContextColumnCustodyCheck` repeats the physical hash/stat/inventory/root-binding
and target-authority checks. The private handle owns four directory descriptors
and bounded filename/stat/hash metadata, not one descriptor per payload. It keeps
no passwords, registration keys, payload bytes or receipt bytes. Manager and target
are borrowed and must outlive the handle. The target's exact retained allocation/
registry/catalog/witness context remains mandatory; a stale authority returns 2.
Any observed failure permanently poisons the handle, including after permissions
or files are restored. `cmeContextColumnCustodyFree` closes owned descriptors,
releases metadata and nulls the pointer; NULL/repeated frees are safe. Open clears
its output on every failure, and 0/1/2/3 statuses remain as before.

These are point-in-time checks across sequential files and authority reads, not
a joint filesystem/database snapshot, exclusive lease or filesystem freeze. The
owner must quiesce writers and protect the approved namespace anchors. Success
cannot rule out a writer acting after the final check; no absolute-path ancestry,
physical power-loss or privileged-filesystem-adversary guarantee is introduced.
The source/candidate roots can be staging objects distinct from the protected
historical storagePath; that literal registration field is still authenticated,
not interpreted as proof of the actual root's absolute location.

No artifact/authority writes, entropy, fsync, rename, one-time receipt consumption,
intent publication, crash recovery or live V2 dispatch is added by custody alone.
Do not serialize/reconstruct this opaque handle or treat the phase-33 receipt
alone as physical custody. Phase 35 below consumes fresh custody for a separate
guarded whole-export directory promotion and recovery protocol. Published-map/
live readers, wider migration/provider/floor-2/lifecycle gates and production
ownership/rollback closeout remain under TODO #147.


## Guarded export publication and recovery (#147 phase 35)

`cmeContextColumnPublicationPrepare/Publish/Recover` promote the **entire verified
candidate export directory** to one independently approved absent sibling name.
Source export files are never replaced. The destination parent must be the
original staging parent object, so one Linux RENAME_NOREPLACE directory operation
makes the candidate inventory visible without overwriting any existing object.
This is offline export promotion, not replacement of active engine ResourcesDB,
map/catalog/witness advancement, storagePath rewriting or live V2 activation.

The typed publication approval supplies an already-open private control-directory
object, an ASCII intent leaf name <=128 bytes, and an approved destination parent
object/child name. It reserves `name`, `name.tmp`, `name.done`, `name.done.tmp`.
Control must be current-euid-owned mode 0700 and outside BOTH export roots; it can
be their private parent. Destination/control-name collisions refuse. Existing
custody root/leaf/private-file policy remains in force. Protect all namespace
anchors and quiesce noncooperating export/control writers independently.

Each operation independently opens the control directory and holds a nonblocking
exclusive flock on that open description. Cooperating publishers/recoverers
serialize, including calls using the same original parent FD. This advisory lock
does not freeze files or constrain other writers. Manager/target lifetimes and
serialization of each custody object remain the caller's responsibility.

Prepare first requires fresh custody, an absent destination and absent completion
marker, and fsyncs each staged candidate file, its directory and parent. It
builds a deterministic domain-separated manager-signed intent from exact custody,
acceptance and publication evidence. Write the intent through exclusive private
mode-0600 NOFOLLOW/CLOEXEC temporary creation, complete writes, file fsync,
no-replace rename and control-directory fsync. Recheck custody/journal before
returning the whole-intent SHA-256; independently retain that pin before Publish.
Identical Prepare retries revalidate canonical bytes and return the same pin,
without replacing a committed intent. A failure can leave reserved temporary or
prepared intent state; no artifact promotion is performed by Prepare.

Publish requires the externally retained intent pin and the same live fresh
custody. Recompute the complete canonical intent, compare the actual private
single-link intent file, require an absent destination/marker, sync candidate
files and recheck custody/authority/control immediately before promotion. Use
RENAME_NOREPLACE for the staging directory; no ordinary overwrite fallback exists.
A successful rename permanently consumes the old custody handle even if a later
step fails. Reverify the promoted root/files through held descriptors, allowing
only the directory ctime change caused by rename; sync its directory/parent,
then atomically persist `name.done` using the SAME intent bytes and the private
temporary/write/fsync/no-replace/directory-sync sequence. Recheck the journal,
actual promoted files and current authority before reporting state 2 completed.
Completion is never inferred from a marker alone.

Recover takes the ORIGINAL source/staging approvals, typed transformation/
registration/export inputs and explicit credentials, retained acceptance bytes/
SHA-256, publication approval and independently retained intent SHA-256. Exactly
one of staging/destination must exist. Both present, both absent, a marker with
staging present, stale authority, unapproved/replaced objects, altered file
metadata, wrong pins or invalid journal bytes refuse. Open fresh custody on the
surviving stage or promoted directory and repeat complete actual-byte acceptance,
registration/MAC/lookup/plaintext-equivalence and authority validation. Derive the
same signed intent using the original staging name and match the pinned intent
BEFORE any promotion or completion writes. A valid prepared stage resumes the
no-replace promotion; a valid promoted directory completes syncing/marking without
a second rename. Completed recovery retries revalidate actual files and journals.
Recovery is roll-forward only: no deletion/rollback of published directories,
authority reset, automatic pin adoption or regeneration of missing payloads.

Reserved temporaries from interrupted writes may be retried only when they are
private, current-euid-owned, single-link regular files whose bytes are an exact
prefix (including empty) of the expected canonical intent. Then discard/rewrite
that reserved temporary under the lock. Symlink/hardlink/insecure/unknown bytes
refuse and are preserved. Fully named intent/marker files must match exactly;
forged committed marker bytes are never silently repaired. Atomic intent/marker
installation makes a partially written fully named control file unnecessary.
If initial Prepare was interrupted before its pin was independently retained,
retry Prepare against fresh independently approved custody; do not adopt a hash
from an untrusted leftover file.

Canonical evidence uses SHA-256 and fixed unsigned uint64 big-endian numbers.
Text is uint16 big-endian byte length followed by exact bytes. The manifest is:

1. `CDSE-HKX-COLUMN-PUBLICATION-MANIFEST-v1` including NUL, acceptance SHA-256,
   allocation digest, deployment UUID, organization UUID, registry generation,
   minimum format as uint64, registry digest, catalog revision/digest and exact
   witness revision/digest, then destination-map text.
2. Control-directory stat identity and intent-name text; destination-parent stat
   identity and destination leaf text. Identity is device, inode, full mode,
   uid, gid (five uint64 numbers).
3. Source then candidate: approved parent identity, original root-name text,
   root stat, file count; each file in ASCII-name order has name text, full file
   stat and whole-file SHA-256. Root stat is identity plus link count, size,
   mtime seconds/nanoseconds. File stat additionally includes ctime seconds/
   nanoseconds. All times are nonnegative in this publication profile.

Root ctime is intentionally excluded from retained intent equality because the
approved rename changes it. File identities/ctime and root identities/inventory
remain fixed; parent/control size/link/timestamps are excluded to allow journal
and sibling-name updates. Atime is excluded throughout. Fresh custody still
checks directory ctime within each operation. This does not prove absence of all
historical directory-entry changes across a restart.

Intent v1 is `CDSE-HKX-COLUMN-PUBLICATION-v1` including NUL, manifest SHA-256,
acceptance SHA-256, then a 32-byte manager HMAC. Its tag is HMAC-SHA256 under the
separate manager registry key over `CDSE-HKX-COLUMN-PUBLICATION-SEAL-v1` including
NUL, canonical 73-byte registry anchor, 40-byte catalog pin, uint8 length-prefixed
destination-map name and SHA-256 of the intent bytes preceding the tag. Maximum
intent size 256 bytes. The trusted-core `ColumnPublicationSign` primitive does
not inspect artifacts; high-level APIs always require actual custody. Old
acceptance/registration/legacy intent formats remain unchanged and cannot be
substituted for this intent. No credentials, receipt bytes or absolute artifact
paths are serialized. Custody retains only the acceptance hash and map label in
addition to existing metadata, never credentials or payload/receipt bytes.

Prepare clears its digest on failure; Publish/Recover clear state to 0 on failure
and return state 2 only after verified completion. Return statuses 0/1/2/3 remain
as before; Linux no-replace support is required. A failed Publish/Recover MAY have
renamed the directory or persisted control state. Retain intent/acceptance pins
outside both exports, preserve both namespace approvals, and recover explicitly.
Do not guess success from directory presence, overwrite a destination, refresh
pins, or delete unfamiliar artifacts to make a retry pass.

Validation injects abrupt process exits around temporary intent creation,
prepared intent persistence, directory rename, parent syncing, temporary marker
creation and completion persistence. These are process-crash/ordering tests,
not certification of physical power-loss durability. Require a filesystem that
honors file/directory fsync and no-replace semantics; malicious/noncooperating
writers, privileged filesystem changes and coherent authority/control rollback
still need independent ownership/rollback defenses. TODO #147 remains open for
published-map integration, coordinated authority/witness promotion and recovery,
live V2 readers, wider mixed-profile/floor-2 migrations and prior provider/
lifecycle/production-custody closeout.


## Blocked map admission core (#147 phase 36)

This trusted offline foundation prepares the catalog side of published-map
integration. It is not wired to phase-35 publication or to installed/live
commands. The physical proof adapter is supplied separately in phase 37 below;
the release protocol remains pending.
Keep authority readers/writers stopped and both exports fixed throughout use.
Do not call these core APIs on unverified files or use catalog presence as proof
of acceptance, publication, witness acknowledgement, or permission to read V2.

`cmeContextManagerColumnAdmissionPlan` requires an already committed signed copy
allocation, its independently retained hash and original registry/catalog pins,
the exact committed registry, an unused destination-map name, and an opaque
owner-approved evidence SHA-256. It authenticates the allocation and its current
registry contexts. Catalog v4 must have been initialized explicitly **before**
allocation/acceptance; no upgrade occurs here. A rollback-only transaction
previews the exact next catalog, including both the destination map and a
prepared admission job. Success returns the signed ticket, its SHA-256 and that
next catalog pin, without committing any authority change. SQLite may still
write rollback/journal bytes. The evidence digest has no built-in physical-file
semantics: this phase neither constructs nor verifies a physical snapshot.

Before committing, the owner must privately persist/fsync the exact ticket and
independently retain its SHA-256, evidence digest, registry, original and next
catalog pins and original witness token outside manager/export backups.
Losing these retained approvals cannot be repaired by trusting candidate state.
Tickets contain no credentials, keys, payloads or absolute paths.

`cmeContextManagerColumnAdmissionStep` authenticates the ticket/hash, evidence,
name, registry and exact original/next catalog pins. `commit=0` classifies a
ready transition as state 1, or an exact committed transition as state 2, without
committing. `commit=1` atomically inserts the destination map and a prepared,
domain-distinct `context_copies` job and advances the catalog by exactly one.
The registry and source map stay unchanged. Both before and after commit it
checks the exact authenticated authority, including the complete job bytes on
retry. Competing/later authority and altered tickets fail closed. Failed calls
can have committed; recover with the original retained ticket and pins, never
with a newly adopted catalog or a regenerated ticket.

The prepared job deliberately blocks **all stored-map bindings and mapped
crypto**, as well as normal catalog/registry writers. Authenticated map metadata
remains inspectable with `blocked=1`. Old bindings expire when the catalog
advances. Legacy copy-install recovery cannot decode the new ticket and cannot
release this block. State 2 means **admitted but blocked**, including after a
witness acknowledgement. There is no release/abort API in this phase; callers
must not edit/delete the job to bypass recovery. Low-level raw bindings and
external signing issuers remain trusted core surfaces, not an application
permission boundary or a substitute for mapped reads.

`cmeContextWitnessColumnAdmissionCommit` additionally requires the independently
retained witness token. A ready transition needs the exact original witness
pair. An admitted retry permits that exact original pair awaiting advancement,
its exact one-step acknowledged successor, or the separately retained current
acknowledgement. It rejects an unrelated pair that happens to be one revision
behind and a future acknowledgement before the catalog commit. It never
advances the witness. After authenticating the committed catalog, the owner
must separately approve `cmeContextWitnessAdvance`, durably retain its token,
and reconcile with the original admission approvals. Existing witness lost-ack
reconciliation handles interruption on either side of this separate advance.
There is no cross-database transaction, lease or independent rollback defense.

Ticket wire format (big-endian, text is uint8 length-prefixed ASCII):

1. `CDSE-HKX-COLUMN-MAP-ADMISSION-v1` including NUL; canonical registry anchor
   (73 bytes), original catalog revision/digest (40 bytes), evidence SHA-256.
2. Destination-map name, allocated resource lookup, uint32 slot count; each
   slot is lookup, table, positive uint64 row no greater than `INT64_MAX`, field.
   Slots strictly ascend by table, row, field without duplicates.
3. HMAC-SHA256 with the separate manager registry key over all preceding bytes.
   The independently retained ticket SHA-256 covers the entire ticket and tag.

Maximum ticket size is `cmeContextRegistryMaxBytes`; count is bounded by
`cmeContextRegistryMaxEntries`. Names, active contexts, table/field association,
role, resource, format floor and catalog capacity use existing manager checks.
The exact next catalog is independently pinned because the ticket authenticates
the original transition inputs rather than incorporating its own catalog hash.
Invalid/unavailable returns 1, conflicting authority returns 2, success returns
0. Outputs clear on failure; all inputs/outputs must be stable/nonoverlapping.
Free the owned ticket with `free`. Process-crash tests establish transactional
behavior, not physical power-loss certification.

Phase 37 below supplies the durable, independently pinned physical snapshot
from completed publication/fresh custody and orchestrates these authority/witness
operations after target expiry. TODO #147 remains open for an explicit
witness-guarded release protocol and live V2 readers.
Wider mixed-profile/floor-2 migration, provider acceptance, rename/delete
lifecycle and production custody/monotonic deployment also remain pending.


## Physical-proof admission and recovery (#147 phase 37)

`cmeContextColumnAdmissionPrepare/Run` connect completed phase-35 publication to
phase-36 blocked catalog admission and witness recovery. These are trusted
**offline C APIs**, not installed commands or live-route adapters. Release and
live V2 reads remain pending. Quiesce all physical/authority writers, protect
manager/witness namespaces, and independently approve the source and published
parent objects plus leaf names. Descriptor approval does not certify absolute
path ancestry or exclude privileged/noncooperating writers.

Prepare needs fresh `CustodyOpen` over the source and **published** export,
the original staging leaf, separately retained publication intent hash and
committed signed allocation plan/hash/original registry. It requires the exact
completed intent and completion marker, no staging root and no reserved pending
temporary control objects. It verifies current custody and target evidence,
records a canonical physical snapshot, and asks the phase-36 core to sign a
ticket committing that snapshot's SHA-256 and exact allocated destination map.
The allocation hash must match the custody target's retained allocation.
It previews the exact next catalog in a rolled-back transaction, then rechecks
completed publication and custody before returning owned journal bytes/hash.
No authority commit or automatic journal-file creation occurs at Prepare;
SQLite can still write rollback/journal bytes during its preview.

The owner MUST privately persist/fsync the complete journal and its directory,
and independently retain its SHA-256 outside both exports and manager backups,
**before Run**. Use `cmeContextV2BufferFree` to release returned bytes. Do not
replace uncertain journals, refresh their hash from candidate disk state or
regenerate a plan after partial authority publication. Keep the original
allocation/acceptance/publication approvals under their established retention
policy. The retained journal contains no credentials, payloads, keys or absolute
paths; it binds the reviewed proofs and object identities.

Run/recover takes manager/witness handles, the original independent journal
hash, journal bytes and approved source/published parent descriptors and names.
It authenticates the signed ticket against the exact original or planned next
catalog and unchanged registry. It reopens the roots and compares their full
original identity/stat plus sorted inventories, private single-link regular
file stat/length/SHA-256 and closed SQLite headers. No old target capability,
credentials or receipt bytes are needed: the ticket authenticates the exact
snapshot constructed from fresh full acceptance/custody. This continues after
the catalog change expires the old target. Publication controls are checked at
Prepare; Run relies on the signed retained proof rather than reopening mutable
intent/marker files or repeating their old-capability-dependent signature API.

After a fresh physical check, Run invokes the witness-guarded catalog commit.
The destination map and its prepared job appear atomically, while all stored-map
bindings/crypto and normal registry/catalog writers remain blocked. Run checks
the physical proof again, authenticates the exact committed catalog and original
witness pair, and advances that witness to the pinned next catalog. It accepts
only the original transition or its exact previous-token lost acknowledgement.
Final physical and authority checks precede success. It never adopts current
pins as approvals, signs a replacement proof, releases the prepared job or
changes the registry generation. Completion returns state 2, unchanged registry,
exact next catalog and acknowledged witness token; independently retain that
token as well. State 2 means **admitted and witness acknowledged, still blocked**.

Failure clears all outputs but MAY have committed either database. Recover
using the ORIGINAL journal/hash and namespace approvals. A crash after catalog
commit leaves the original witness and global block; a crash after witness
commit is an exact lost acknowledgement. Completed retries reverify all files
and both authorities without further increments. Late/replaced/unknown bytes,
metadata, names or authority fail closed and preserve blocking, including after
an intermediate authority commit. No abort, repair, release, live lease,
cross-database transaction or independent coherent-backup rollback defense is
introduced. File checks are point-in-time and do not replace writer coordination.
Process-crash tests do not certify physical power-loss durability.

Canonical journal v1 uses big-endian counters and uint16 length-prefixed text:

1. `CDSE-HKX-COLUMN-ADMISSION-v1` including NUL, registry anchor (73 bytes),
   original catalog (40), original witness (40), planned next catalog (40),
   destination-map name, uint32 ticket length and exact phase-36 ticket bytes,
   uint32 physical-proof length and exact proof bytes. The externally retained
   SHA-256 covers every journal byte; the ticket's independent SHA-256 is
   recomputed and verified by the core. The next catalog/witness metadata is
   independently pinned through the retained whole-journal hash.
2. Physical proof starts with `CDSE-HKX-COLUMN-ADMISSION-FILES-v1` including NUL,
   acceptance, publication-intent and allocation SHA-256 pins. Source then
   published root each contain parent identity, root leaf, full root stat,
   uint32 file count, then sorted unique file leaf/full stat/SHA-256 records.
3. Parent identity is five uint64 values: device, inode, full mode, uid, gid.
   Full stat adds link count, size, mtime seconds/nanoseconds and ctime
   seconds/nanoseconds (eleven values total). Times must be nonnegative and
   nanoseconds below one billion. Atime is excluded. Parent times/link count/
   size are excluded so unrelated private control creation is permitted;
   export-root ctime is included because this snapshot is taken AFTER rename.

Bounds: journal 6 MiB, physical proof 4 MiB, core ticket at most
`cmeContextRegistryMaxBytes`, at most 4100 files per root, existing private leaf
rules and per-file SQLite limits (ResourcesDB 16 MiB, other images 32 MiB).
Prepare inherits the stronger complete-export acceptance bounds. Inputs/outputs
must be stable/nonoverlapping; return statuses are 0 success, 1 invalid or
unavailable, 2 authority conflict, 3 unavailable provider through fresh custody.
There is no credential buffer retained by the physical proof or journal.

TODO #147 remains open. Next design an explicit witness-guarded release protocol
for the prepared admission job, with retained physical proof and exact current
pins checked on every release/retry. Keep maps blocked through ambiguous states.
Existing generic mapped crypto does not check witness freshness: clearing its
catalog block before matching witness acknowledgement would expose a read
interval. Future release must guard readers across that interval before
unblocking. Installed handoff/orchestration, live V2 readers, wider mixed-profile/floor-2
migration/provider acceptance, rename/delete lifecycle and production protected
custody/monotonic deployment also remain pending.


## Scoped witness-aware read release (#147 phase 38)

`cmeContextColumnReadReleaseOpen/Check/Free` and `cmeContextColumnRead` add a
**scoped read-only release** for the published V2 export already admitted and
acknowledged by phase 37. This is the first post-admission plaintext read path.
It does not clear the catalog block, finish the prepared job, enable generic
mapped crypto/writers or dispatch live HTTP routes. The existing v4 catalog
would let older generic readers ignore a new witness gate if its job were
marked completed. Preserve their fail-closed prepared-job block until a future
explicit catalog/reader transition can guard all readers across witness commits.

Open requires the original phase-37 journal and independently retained SHA-256,
source/published parent object and leaf approvals, manager/witness handles and
**the independently retained acknowledged witness token returned by Run**.
Ready admission, pending witness advancement, previous tokens and changed pins
are rejected. No adoption, admission, witness advancement or repair occurs.
Open copies journal/names/pins, duplicates both parent descriptors and checks
exact committed ticket/catalog/registry, original-to-acknowledged witness
transition, current acknowledged token and complete physical snapshot. Inputs
may be freed and original parent descriptors closed after successful Open;
manager and witness must outlive the capability. Serialize Check/Read/Free.

Check repeats the physical and authority proof. Any observed proof/authority
failure permanently poisons that capability, including if authority is later
restored. Free it and obtain a newly reviewed capability with the ORIGINAL
retained approvals; never refresh pins from candidate disk state. This is
point-in-time checking, not a lease, revocation of previously returned plaintext,
absolute-path ancestry proof or independent coherent-backup rollback defense.
Keep writers stopped and namespaces/keys/journals protected as in phase 37.

Read takes a logical table/row/field and counted target password, not candidate
frame bytes or a caller-selected file. The signed full inventory must identify
exactly one extra published file beyond all source files; that is the admitted
V2 image. Read loads only that original inode/stat/hash-matched SQLite image,
uses the existing bounded strict container schema/inventory/AEAD and plaintext
metadata/order validation, then selects the approved cell. It checks current
witness, physical proof and both manager pins again before returning plaintext.
Wrong credentials, absent cells or changed bytes yield no output; candidate
plaintext is wiped on failure. A witness rollback or physical change after
successful decryption still withholds plaintext. No credential/plaintext is
retained in the capability. Wrong passwords/missing cells alone do not poison
otherwise valid state. The caller owns returned bytes and must use
`cmeContextV2BufferFree`; no legacy/provider fallback is introduced.

The trusted manager core returns a distinct type-3 admission binding only after
authenticating the exact committed prepared ticket and map. Generic mapped and
copy-target codec gates reject it. A private read-only codec entry is used only
inside the guarded full-container read path; there is no admission seal API.
These low-level core functions do not independently authenticate witnesses or
physical proof and remain trusted in-process issuer surfaces, not application
permission boundaries. Public generic codec behavior remains unchanged.

All operations preserve registry/catalog/witness counters, manager job state,
source and published files. A crash during release construction/read creates no
durable release state; retry using the original journal/hash and acknowledged
token. Return codes 0/1/2/3 and stable/nonoverlapping input/empty-output contracts
match preceding APIs; 3 includes unavailable provider/SQLite-deserialize support.
The original journal format and existing SQLite/image/ciphertext formats do not
change. Full profile limits remain 32 MiB image, 16 MiB validated plaintext,
4096 logical slots and 1..256 target password bytes. Checking the entire image
per read is an offline correctness boundary, not a live-reader performance claim.

TODO #147 remains open. Next design an explicit opt-in catalog transition and
witness-aware binding checks for every affected generic read before globally
clearing the prepared-job block. Older readers must reject that transition.
Then add durable global-release recovery, installed handoff/orchestration and
live V2 dispatch. Wider mixed-profile/floor-2/provider acceptance, rename/delete
lifecycle and production protected-custody/monotonic deployment remain pending.


## Global catalog release and witnessed bindings (#147 phase 39)

`cmeContextColumnGlobalReleasePrepare/Run` explicitly opt the admitted catalog
into witness-required v5 and complete the exact phase-36 prepared admission job.
This releases the global catalog permission block. It does not replace active
engine databases or install a live storage dispatcher. Existing v1-v4 catalogs
and their ordinary bindings retain their previous behavior. Opt-in is
irreversible through these APIs; older readers reject v5 authentication rather
than bypassing the witness requirement.

Prepare requires the original retained phase-37 admission journal/hash, approved
source/published directory objects and names, manager/witness handles and the
independently retained acknowledged W1 token at admitted registry R1/catalog C1.
It opens and checks phase-38 scoped custody, previews C2 in a rolled-back SQLite
transaction and returns owned envelope bytes and SHA-256. It changes no authority
or files. The owner must privately persist/fsync the envelope and its directory
and independently retain its hash BEFORE calling Run. Run cannot establish that
external durability or independent retention for the caller. Free returned
bytes with `cmeContextV2BufferFree`.

The envelope is `CDSE-HKX-COLUMN-GLOBAL-RELEASE-v1\0`, uint32 admission-journal
length, exact original journal, W1 revision/digest (8+32 bytes) and C2
revision/digest (8+32 bytes), with big-endian integers. SHA-256 of the prefix
through W1 is the release request digest; SHA-256 of the entire envelope is the
independently retained approval. The bound is admission maximum 6 MiB plus
512 bytes. Physical proof and original signed ticket remain unchanged.

Run verifies the envelope hash, original manager-signed admission and exact
physical inventory/stat/hash proof. At R1/C1 it requires current acknowledged
W1. A single transaction adds `registry_meta.witness_version=1`, the singleton
`context_read_policy` row, and completes the exact job with state 2 and finished
revision C2=C1+1. It signs the new catalog under `CDSE-HKX-MAP-v5\0` using the
full canonical v4 typed payload followed by uint32 policy length and policy
bytes. The policy contains `CDSE-HKX-COLUMN-GLOBAL-POLICY-v1\0`, packed R1
(73 bytes), original C0 (40), admitted C1 (40), original ticket SHA-256,
physical-proof SHA-256, release-request SHA-256 and uint8-length map name.
The singleton, types, bounds and witness flag are validated on every catalog
authentication. Removing/replacing the policy, changing the flag or computing
the old v4 signature cannot authenticate the new catalog.

After C2 commits, Run rechecks physical proof and exact manager state, then
advances W1 to W2 at R1/C2. It checks all three again before returning state 2,
unchanged R1, C2 and W2. Retain W2 independently before using it. Failure clears
outputs but either authority may already have committed: retry with the ORIGINAL
envelope/hash and directory approvals. Recovery accepts exact C1/W1, C2 with
W1 awaiting advancement, or C2/W2 after lost acknowledgement. Changed/later
registry, catalog or witness state refuses; no repair, token adoption or reset
is automatic. Manager transactions and witness storage retain their existing
crash/durability assumptions; process-crash tests are not physical power-loss
certification. Physical changes withhold acknowledgement even after C2 commits.

`cmeContextManagerWitnessRequired` authenticates exact pins and reports opt-in.
Ordinary `cmeContextManagerMapBind` always refuses v5, including after W2 is
acknowledged. `cmeContextManagerMapBindWitness` requires an independently
retained CURRENT witness token matching the supplied registry/catalog and an
active unblocked map. Its distinct type-4 binding borrows the witness until
`cmeContextBindingFree`; keep both manager and witness alive and serialize use
and destruction. Binding validation checks witness freshness before and after
the manager check. Public V2 memory Open/Seal already repeat binding validation
around crypto, so a late witness change withholds plaintext/ciphertext. There
is no implicit witness advancement, ordinary-binding fallback, provider fallback
or witness lease. Unlike scoped phase-38 capabilities, ordinary bindings do not
promise permanent poisoning; obtain fresh reviewed bindings for operations.

Between C2 commit and W2 acknowledgement, old readers fail catalog
authentication, ordinary new bindings refuse and witnessed bindings with W1
fail freshness. C1-scoped read capabilities and prior approval pins expire at
C2. Trusted low-level GlobalPlan/Step treat physical evidence and request digest
as opaque issuer inputs; applications must use the guarded column adapter.
Generic witnessed memory crypto checks authority, not physical file identity;
its caller must supply approved frames. File-level V2 readers and installed/live
adapters carrying full container/custody checks remain pending. Older CLI,
copy/shuffle owner workflows using ordinary bindings fail closed on v5 and need
an explicit witness-aware migration before use there. Trusted normal metadata
writers may advance pins after release; retained old bindings then fail until
separate witness review/advancement and new binding construction.

Registry generation, physical files, ciphertext formats and original admission
journals are preserved. Inputs must remain stable and nonoverlapping; statuses
0/1/2/3 and empty-output contracts follow earlier APIs. Protect namespaces,
keys/envelopes and independent witness retention; keep writers stopped during
physical admission/release. Point-in-time checks do not revoke returned
plaintext or defend independent coherent-backup rollback without deployment
custody/monotonic controls.

TODO #147 stays open for installed/live v5 adapters and active handoff, wider
mixed-profile/floor-2 migration/provider acceptance, rename/delete lifecycle and
production protected-custody/monotonic deployment.


## V2 file reads after global release (#147 phase 40)

`cmeContextColumnGlobalReadOpen` adds the read-only physical-file adapter for the
exact completed phase-39 v5 release. Pass the ORIGINAL retained release envelope
and independently retained SHA-256, approved source/published directory objects
and names, manager/witness handles, and the independently retained acknowledged
W2 token. It returns the existing opaque `cmeContextColumnReadRelease` capability;
use `cmeContextColumnReadReleaseCheck`, `cmeContextColumnRead` and
`cmeContextColumnReadReleaseFree` with it. The old Open still authorizes only
the phase-38 C1-scoped read and expires at C2; no ordinary-binding fallback is
introduced. Existing v1-v4 behavior and private type-3 gates remain unchanged.

Open copies the envelope/hash/names, duplicates both parent descriptors and
checks twice before returning. Callers may then free the input envelope/names
and close their original parent descriptors. The manager and witness must
outlive the capability; serialize Check/Read/Free and protect retained approvals.
No credentials or plaintext are retained. Failed Open clears the output handle.

Check decodes the shared bounded phase-39 envelope and embedded original
admission, authenticates the manager-signed ticket and exact completed job/policy
at R1/C2, and requires the original W1-to-W2 transition and separately retained
W2 to agree with current witness state. It checks the entire original physical
proof and repeats manager/witness freshness checks afterwards. Prepared C1,
committed C2 with an unadvanced witness, missing/wrong acknowledgements and
later/different registry/catalog/witness state refuse. Check never calls global
commit or witness advancement, adopts new pins or completes an interrupted
release. Recover with GlobalReleaseRun and ORIGINAL approvals separately.

Read checks the capability, loads only the unique additional published V2 image
identified by the original signed admission proof, and obtains an unblocked
witnessed type-4 binding for the exact admitted map. It reuses the bounded strict
SQLite container schema/integrity/inventory/AEAD and full plaintext-metadata/order
checks for EVERY cell, then decrypts the requested table/row/field. The private
mapped deserializer preserves the stored map's active/block flags; it cannot
use the admission-only block override. Public memory crypto repeats witnessed
binding checks around decryption. Before returning any plaintext, Read repeats
the full physical and authority check; even a changed companion file or witness
after successful decryption withholds the candidate plaintext and wipes it.

Any observed physical-proof or authority failure permanently poisons this
capability, including failures during image loading and failures detected while
handling a crypto error. Restoring witness state does not revive it; free it and
reopen only with the original independently reviewed approvals. Bad passwords,
invalid selectors or unavailable providers alone do not poison otherwise valid
physical/authority state. Failed reads clear outputs; callers own successful
bytes and must free them with `cmeContextV2BufferFree`.

The APIs make no authoritative registry/catalog/witness commits and preserve
source/published files, release envelopes, counters and ciphertext formats.
Bounds and statuses 0/1/2/3 follow earlier APIs: envelope at most 6 MiB + 512,
image at most 32 MiB, validated plaintext at most 16 MiB, existing 4096-slot
inventory limit and counted passwords 1..256 bytes. Inputs must remain stable
and nonoverlapping. Full-export rehash and full-container verification per read
are offline correctness checks, not a live-reader performance claim. Keep
writers stopped and namespaces/evidence protected. These point-in-time checks
are not a lease, revocation of previously returned plaintext, absolute-ancestry
proof or defense against independently restored coherent backups. No physical
power-loss certification is added.

TODO #147 remains open for installed owner orchestration, live witnessed V2
reader integration/active handoff, wider mixed-profile/floor-2/provider/migration
acceptance, rename/delete lifecycle and production protected custody/monotonic
deployment. This phase supplies the post-release file-reading boundary without
enabling HTTP dispatch or changing active engine database paths.


## Installed V2 file read command (#147 phase 41)

Use `caumedse-admin context-column-read` to read a single verified cell from a
completed v5 release. Keep export writers stopped and supply the original
directory paths, envelope and independently retained approvals from phases 39
and 40.

```sh
caumedse-admin context-column-read \
  --registry-directory "$registry_directory" --witness-directory "$witness_directory" \
  --deployment "$deployment_hex" --organization "$organization_hex" \
  --registry-key-file "$registry_key_file" --witness-key-file "$witness_key_file" \
  --source-export "$source_export" --published-export "$published_export" \
  --release-envelope "$release_envelope" --release-digest "$retained_release_sha256" \
  --retained-witness-token "$retained_w2_token" --password-file "$target_password_file" \
  --table data --row 1 --field value
```

Use absolute canonical paths without symlink components. The registry, witness,
export roots and export parents must be owned directories with mode `0700`.
Store the envelope and each credential in an owned regular file with mode
`0600`, one hard link and a private `0700` parent. Registry and witness keys
must be distinct. Each key file contains 64 lowercase hexadecimal digits and
may end with one newline. The deployment and organization IDs each contain 32
lowercase hexadecimal digits. The separately retained release digest and W2
token contain 64 and 80 lowercase hexadecimal digits, respectively. The
password file contains 1 to 256 raw bytes. A newline or NUL byte is part of the
password.

The command opens the existing manager and witness and passes the original
envelope, retained digest and token to the verified file adapter. The adapter
checks the completed release, the physical proof and the full container before
it returns a cell. It rechecks physical and witness state after decryption.
The command writes the verified bytes to stdout without a newline or encoding.
Choose a private destination when capturing plaintext and keep the output
separate from the approved inputs and export roots.

Exit status `0` reports a successful read and write. Status `1` reports
invalid input, unavailable data, bad credentials or an output error. Status
`2` reports an authority conflict, including stale or pending release
acknowledgement. Status `3` reports unavailable V2 support. Failed validation
writes no cell bytes, and diagnostics omit paths, credentials and plaintext.
For an interrupted release, recover it separately with the original approvals
before reading.

TODO #147 remains open for installed release orchestration, live witnessed
reader integration and active handoff, wider migration and provider acceptance,
lifecycle transitions and production custody.


## Installed v5 release command (#147 phase 42)

Use `caumedse-admin context-column-release` with a published export and a
completed phase-37 admission. Keep export writers stopped. Pass the same
absolute canonical paths, private authority directories, scope IDs and distinct
key files used for the installed read command.

```bash
release_args=(
  --registry-directory "$registry_directory" --witness-directory "$witness_directory"
  --deployment "$deployment_hex" --organization "$organization_hex"
  --registry-key-file "$registry_key_file" --witness-key-file "$witness_key_file"
  --source-export "$source_export" --published-export "$published_export"
  --release-envelope "$release_envelope"
)

caumedse-admin context-column-release prepare "${release_args[@]}" \
  --admission-journal "$admission_journal" --admission-digest "$retained_admission_sha256" \
  --retained-witness-token "$retained_w1_token"

# Independently retain the printed digest before running complete.
caumedse-admin context-column-release complete "${release_args[@]}" \
  --release-digest "$retained_release_sha256"
```

`prepare` validates the original retained admission journal, its SHA-256
digest and the independently acknowledged W1 token. It previews the v5
catalog and exclusively creates the release envelope with mode `0600`.
Choose a new path in an owned `0700` directory outside the exports and
authority directories. The command syncs the envelope and parent before
printing `release-digest=<sha256>`. Catalog and witness advancement happen
during `complete`. If preparation or its output fails, preserve any partial
or uncertain file. While the original admission is current, use a fresh path
and the same original approvals to prepare again.

`complete` reads and syncs the private envelope and parent, then checks the
independently retained release digest and original physical proof. The v5
transition completes the catalog job and advances the witness at the approved
checkpoint. Success prints `catalog=<token>` and `witness-token=<token>`, each
with a 40-byte value serialized as 80 lowercase hexadecimal digits. Keep the
envelope and digest and independently retain the W2 token. Pass that token and
the same envelope and digest explicitly to `context-column-read`.

Use the same `complete` invocation after interruption or uncertain output.
The recovery logic accepts only the original approved catalog and witness
transition, including a committed catalog awaiting its witness or an already
completed release awaiting acknowledgement. A repeated successful invocation
returns the same tokens. A failure can leave one or both authority stores
committed. Preserve the original envelope and separately retained digest for
recovery. Approval or proof failures emit no result tokens. An output error
returns failure even if the command already committed the transition.

The command uses the phase-39 release statuses and provides a generic
diagnostic on failure. The operator supplies retention and acknowledgement
through separate invocations and protected storage. The installed workflow
begins with a completed admission. TODO #147 remains open for installed
admission and publication orchestration, live witnessed readers and active
handoff, broader migration acceptance, lifecycle and production custody.


## Installed V2 admission command (#147 phase 43)

Use `caumedse-admin context-column-admission` after the verified export has
been published and its original publication intent and completion marker are
retained. Keep export writers stopped for preparation and completion.

```bash
admission_args=(
  --registry-directory "$registry_directory" --witness-directory "$witness_directory"
  --deployment "$deployment_hex" --organization "$organization_hex"
  --registry-key-file "$registry_key_file" --witness-key-file "$witness_key_file"
  --source-export "$source_export" --published-export "$published_export"
  --admission-journal "$admission_journal"
)

caumedse-admin context-column-admission prepare "${admission_args[@]}" \
  --approval "$approval_json" --approval-digest "$retained_approval_sha256" \
  --retained-witness-token "$retained_w0_token" \
  --source-key-file "$source_key_file" --registration-key-file "$registration_key_file" \
  --password-file "$password_file"

# Independently retain the printed journal digest before completion.
caumedse-admin context-column-admission complete "${admission_args[@]}" \
  --admission-digest "$retained_admission_sha256"
```

Prepare uses a private schema-1 JSON object up to 4 MiB. Review the approval
against the retained allocation, registration and publication evidence and
independently retain the SHA-256 of the exact JSON bytes. Every field below is
required except `publicationDigest`, which may be supplied as
`--publication-digest`. Supply the digest in exactly one place so an approval
used for publication can carry forward unchanged. Unknown fields, duplicate
names and mistyped values fail validation. Substitute the original approved
values for the placeholders.

```json
{
  "schema": 1,
  "originalRegistry": "<allocation's original 73-byte registry token in hex>",
  "catalog": "<original 40-byte catalog token in hex>",
  "sourceMap": "<approved source map>",
  "lookups": ["<first allocation lookup>", "<next allocation lookup>"],
  "allocationPlan": "/private/control/copy.plan",
  "allocationDigest": "<retained allocation SHA-256>",
  "sourceProfile": "aes-256-gcm",
  "destinationMap": "<approved destination map>",
  "sourceDigest": "<source ColumnFile SHA-256>",
  "candidateDigest": "<V2 ColumnFile SHA-256>",
  "registrationEvidenceDigest": "<registration approval SHA-256>",
  "metadataProfile": "aes-256-gcm",
  "sourceFile": "source.sqlite",
  "destinationFile": "candidate.sqlite",
  "sourceDocument": "<source document selector>",
  "destinationDocument": "<destination document selector>",
  "storageId": "<approved local storage selector>",
  "organizationResource": "<approved organization resource>",
  "columnId": "<approved column selector>",
  "storagePath": "<literal approved registration path>",
  "sourceRow": 1,
  "destinationRow": 2,
  "sourceResourcesDigest": "<source ResourcesDB SHA-256>",
  "candidateResourcesDigest": "<candidate ResourcesDB SHA-256>",
  "exportDigest": "<complete export approval SHA-256>",
  "registrationReceipt": "/private/control/registration.receipt",
  "registrationReceiptDigest": "<retained registration receipt SHA-256>",
  "companions": [
    ["LogsDB", 4096, "<LogsDB SHA-256>"],
    ["RolesDB", 4096, "<RolesDB SHA-256>"],
    ["source.sqlite", 4096, "<source ColumnFile SHA-256>"]
  ],
  "acceptanceReceipt": "/private/control/acceptance.receipt",
  "acceptanceDigest": "<retained export acceptance SHA-256>",
  "publicationDirectory": "/private/publication-control",
  "publicationJob": "<original publication job leaf>",
  "publicationDigest": "<retained publication intent SHA-256>",
  "staging": "<original now-absent staging leaf>"
}
```

Supply canonical absolute paths for the approval and receipt files, allocation
plan and publication control directory. The approved registration
`storagePath` is the literal stored value. Use the allocation's exact lookup
order and include every approved companion in ascending ASCII leaf order,
with the actual byte length and original retained SHA-256. Registry and
catalog tokens and digests use lowercase hexadecimal digits. The original
registry token precedes allocation. W0 acknowledges the committed allocation
registry and its original catalog, as required by the copy target binding.
Use the approved legacy AES profile for each source and metadata field.

Use the phase-41 private file conventions for the authority keys and target
password. The source and registration keys are separate inputs containing
1 to 256 exact bytes with no NULs. A trailing newline is part of the key.
Keep the approval, all receipts, keys and journal in private files with
mode `0600`, one hard link and owned `0700` parents outside both export roots.
The new journal path must also be outside the authority directories.

Prepare reopens the retained allocation and verifies the registered V2
candidate and complete export through physical custody. It checks the original
publication intent and completion marker before writing a private journal.
After syncing the journal and its directory it prints
`admission-digest=<sha256>`. The authority transition happens during
completion. Preserve any partial or uncertain journal and use a fresh path for
another preparation while the original approvals are current.

Complete reads and syncs the retained journal, validates its independently
retained digest and rechecks the signed physical proof. It prints
`catalog=<token>` and `witness-token=<token>` only after the blocked catalog
and witness commits are verified. Both tokens are 40-byte values in lowercase
hexadecimal. Repeat the same command after interruption or uncertain output
using the original journal and digest. Recovery uses the existing registry and
witness key files and the approved export paths. Preparation credentials and
receipts are only required during preparation. Failed validation emits no
result tokens. An output error can follow a successful authority commit.

The admitted catalog still blocks ordinary reads. Retain W1 independently
and pass it with the original journal and digest to `context-column-release
prepare`, then follow the release and read workflow. TODO #147 continues with
installed publication orchestration, live witnessed readers, broader migration
and lifecycle acceptance, and production custody.


## Installed V2 publication command (#147 phase 44)

Use `caumedse-admin context-column-publication` with a source export, a
verified staged V2 export and its retained acceptance and registration
receipts. Quiesce export readers and writers. The staging and published
directories must be distinct children of the same owned, private parent.
Pass the intended destination as `--published-export`. The `staging` field
of the independently pinned approval selects the original staging leaf under
that parent. The destination must be absent before promotion.
For the admission handoff, initialize the copy-install catalog (v4) before the
original allocation, as described in phase 36.

Use the schema-1 approval shown in phase 43, omitting `publicationDigest`.
Retain the SHA-256 of the original approval bytes and the committed
allocation's W0 witness token. The `publicationDirectory` in the approval
identifies the private control directory outside the exports, and
`publicationJob` selects the job file. Keep the approval, receipts and
credential files in the private locations described in phase 43.

```bash
publication_args=(
  --registry-directory "$registry_directory" --witness-directory "$witness_directory"
  --deployment "$deployment_hex" --organization "$organization_hex"
  --registry-key-file "$registry_key_file" --witness-key-file "$witness_key_file"
  --source-export "$source_export" --published-export "$published_export"
  --approval "$approval_json" --approval-digest "$retained_approval_sha256"
  --retained-witness-token "$retained_w0_token"
  --source-key-file "$source_key_file" --registration-key-file "$registration_key_file"
  --password-file "$password_file"
)

caumedse-admin context-column-publication prepare "${publication_args[@]}"

# Independently retain the printed digest before promotion.
caumedse-admin context-column-publication publish "${publication_args[@]}" \
  --publication-digest "$retained_publication_sha256"
```

`prepare` checks the approval digest, current witness, actual export contents
and retained receipts. It syncs the stage and saves the signed intent, then
prints `publication-digest=<sha256>`. Repeat an interrupted preparation with
the same approvals while the original stage survives and the destination is
absent. Identical preparations can return the same digest.

`publish` checks the independently retained intent digest and fresh custody,
then promotes the original staged directory with Linux atomic no-replace
rename. It syncs the promoted directory and its parent and completes the
`<publicationJob>.done` marker. After verified success it prints
`publication-complete`. Catalog admission and witness advancement are separate
steps.

If publication is interrupted or its response is lost, retain the original
control files and run recovery with the same paths and approvals.

```bash
caumedse-admin context-column-publication recover "${publication_args[@]}" \
  --publication-digest "$retained_publication_sha256"
```

Recovery reverifies whichever of the stage or published export survives. It
checks the retained intent before resuming promotion or completing the marker.
It refuses ambiguous or replaced objects, including a destination that
appeared while the stage still exists. Successful recovery prints the same
completion result. Failed verification emits no result. An output error can
follow a completed rename and marker commit, so use recovery to verify the
outcome.

Pass the same approval and W0 and the independently retained publication digest
to the installed admission command. The publication intent and marker remain
evidence for admission.

```bash
caumedse-admin context-column-admission prepare "${publication_args[@]}" \
  --publication-digest "$retained_publication_sha256" \
  --admission-journal "$admission_journal"
```

## Live witnessed V2 read (#147 phase 45)

After completing phase 42 and retaining the release digest and the new
witness token independently, an operator can bind one released export to
one route on an engine built with V2 HerraduraKEx support. Start the engine
with the following environment variables. The active engine must already recognize the HTTP organization
and storage IDs. Choose the binding for the release owned by that organization.
Keep the original release artifacts and authority directories protected and
quiesce their writers while the route is enabled.

| Variable | Value |
| --- | --- |
| `CDSE_V2_READ_ENABLED` | Set to `1` to enable. The default is disabled. |
| `CDSE_V2_READ_ORG`, `CDSE_V2_READ_STORAGE`, `CDSE_V2_READ_DOCUMENT` | Exact HTTP resource identifiers for the one exposed document. |
| `CDSE_V2_READ_DEPLOYMENT`, `CDSE_V2_READ_ORGANIZATION` | The release authority's deployment and organization identifiers, each 32 lowercase hexadecimal digits. |
| `CDSE_V2_READ_REGISTRY_DIRECTORY`, `CDSE_V2_READ_WITNESS_DIRECTORY` | Absolute canonical paths to the existing authority and separate witness directories. |
| `CDSE_V2_READ_SOURCE_EXPORT`, `CDSE_V2_READ_PUBLISHED_EXPORT` | Absolute canonical paths to the original source and published exports. |
| `CDSE_V2_READ_RELEASE_ENVELOPE`, `CDSE_V2_READ_RELEASE_DIGEST` | Original phase-42 envelope path and independently retained SHA-256 digest, 64 lowercase hexadecimal digits. |
| `CDSE_V2_READ_WITNESS_TOKEN` | Independently retained W2 token printed on completing the release, 80 lowercase hexadecimal digits. |
| `CDSE_V2_READ_REGISTRY_KEY_FILE`, `CDSE_V2_READ_WITNESS_KEY_FILE` | Paths to files with distinct keys, each 64 lowercase hexadecimal digits with an optional trailing newline. |
| `CDSE_V2_READ_PASSWORD_FILE` | Path to the exact 1–256 target password bytes, including any newline present in the password. |

Use absolute canonical paths, owned mode-`0700` directories, and owned
mode-`0600` files with a single link for the envelope and credentials.
Keep the credential bytes in those private files.

Send an HTTPS GET to
`/organizations/{organization}/storage/{storage}/documentTypes/file.csv.cdse-v2/documents/{document}/contentRows/{contentRow}`.
Use the normal client certificate chain, `userId`, `orgId`, and `orgKey`.
The authenticated organization must match the URL organization and the
configured binding. The account needs the `contentRows` GET permission.
The row is a positive decimal integer through `9223372036854775807`.
The optional `outputType=json` selects the route's default format.
The response contains `valueHex`, the lowercase hexadecimal bytes of the
logical `data/value` cell, and carries `Cache-Control: no-store`.

The reader opens the existing authority and witness and verifies the retained
pins and original proof before returning a cell. It repeats the checks for
each request and processes one verified read at a time. A busy reader, missing
cell, stale witness, or failed artifact verification returns `503`. A disabled
or unmatched binding returns `404` after successful authorization. The
reserved document type serves only this GET. DEBUG authorization and HTTP
certificate bypasses cannot access it.

This binding serves the fixed offline export from the running HTTPS engine.
Phase 46 adds the active catalog mode below.

## Active catalog V2 reads (#147 phase 46)

Set `CDSE_V2_READ_CATALOG=1` alongside the phase-45 enablement, organization,
storage, authority paths and retained release approvals. In this mode the
published registration determines the document identifier. Omit
`CDSE_V2_READ_DOCUMENT`. An unset catalog flag or the value `0` selects the
phase-45 direct document pin. The same HTTPS route, certificate and
`contentRows` GET permission apply in either mode.

Provision one matching document record in the engine's active
`ResourcesDB` during offline maintenance with the phase-47 installer below.
The protected cells and lookup values come from the released `ResourcesDB`
registration for the V2 payload. The active SQLite integer `id` may be
assigned independently.

Each catalog-mode request derives the three protected lookups from the
authenticated organization, storage and document. It verifies the published
registration against the original release proof, checks the decrypted
selectors and single-part V2 payload name, and compares the active record
with the pinned protected record. The reader reopens the active catalog and
repeats the comparison after decryption. The published proof determines
which payload file is read. Catalog access is read-only.

A missing registration returns `404`. A mismatched or duplicate registration,
an invalid proof or a stale witness returns `503`. The release and witness
checks still apply on each request. Protect the active catalog and release
directories during operation. The checks apply at the time of each read.

## Offline V2 registration installation (#147 phase 47)

After phase 42 completes the release, use the original release envelope,
its independently retained SHA-256 and the separately acknowledged W2
token. Stop the engine and other catalog, release, and authority writers
before running the installer. The active database must be an existing
`ResourcesDB` outside the release and authority directories. Use an absolute
canonical path, an owned mode-`0700` parent, and a mode-`0600` single-link
database. A cleanly closed catalog can use WAL or rollback journaling.
If SQLite recovery is pending, complete it during maintenance before retrying.

```bash
caumedse-admin context-column-register \
  --registry-directory "$registry_directory" --witness-directory "$witness_directory" \
  --deployment "$deployment_hex" --organization "$organization_hex" \
  --registry-key-file "$registry_key_file" --witness-key-file "$witness_key_file" \
  --source-export "$source_export" --published-export "$published_export" \
  --release-envelope "$release_envelope" --release-digest "$retained_release_digest" \
  --retained-witness-token "$retained_w2_token" \
  --active-resources "$active_resources_db" --metadata-profile "$metadata_profile" \
  --registration-key-file "$registration_key_file" \
  --org-resource-id "$org_resource_id" --storage-id "$storage_id" --document-id "$document_id"
```

The registration key file holds 1–256 NUL-free bytes of the existing
organization key, including a newline only if it belongs to the key.
Use the same `aes-256-gcm` or `aes-256-cbc` metadata profile as the release
registration and the active engine. The active catalog must already
contain the authorized organization and local storage.

The installer copies the exact protected cells and lookups into one
locally numbered row. It verifies the release, checks for conflicting
document and payload registrations, and compares the inserted row with
the approved record before committing. SQLite commits the row atomically.
An exact existing row succeeds with the same `registration=present`
output. Retry with the original approvals after losing the output.
A conflict, unsupported catalog layout, or stale witness leaves existing
registrations intact. Start the engine with `CDSE_V2_READ_CATALOG=1`
after a successful installation. Live mutations and production
credential custody remain open under #147.

## Mixed-profile export acceptance (#147 phase 48)

Use schema `2` in the owner approval for a mixed AES export. Keep the
existing approval fields and use four elements for every entry in
`companions`. Keep the entries sorted by ASCII leaf name.

| Entry | Elements |
| --- | --- |
| Legacy CSV document | File name, byte length, SHA-256, `aes-256-gcm` or `aes-256-cbc` |
| `RolesDB` or `LogsDB` | File name, byte length, SHA-256, JSON `null` |

Include the selected source document and make its fourth element equal to
`sourceProfile`. Use the existing source key file for all legacy payloads.
The `metadataProfile` and registration key continue to govern the
protected catalog metadata and registration MACs.

To compute the schema-2 `exportDigest`, initialize SHA-256 with
`CDSE-HKX-COLUMN-EXPORT-v2` followed by a NUL byte. Append the 32-byte
registration approval digest and the big-endian uint64 companion count.
For each sorted companion append the big-endian uint16 name length, name
bytes, big-endian uint64 file length, 32-byte SHA-256 and one profile
byte. Use `0` for the two internal databases, `1` for AES-GCM, and `2`
for AES-CBC. Independently retain the resulting digest and the acceptance
receipt before publication and admission. The three-element schema-1
approval and its original digest remain supported.

During acceptance the checker authenticates the protected registration
and file MAC, then verifies each legacy companion's SQLite schema, AES
profile declarations, decrypted cells, row order, and integrity tags.
The source and candidate exports retain each legacy document byte for
byte. The selected document is transformed to V2 under its existing
witnessed approval. Publication, admission, release and registration
installation continue to use the same sequence. This phase covers
single-part local CSV documents with one explicit AES profile per
payload and a common source key.

## Offline V2 registration retirement (#147 phase 49)

Use `caumedse-admin context-column-unregister` with the same arguments as
phase-47 registration installation. Stop the engine and catalog, release,
and authority writers before running it. Use the original release envelope
and independently retained digest, the current acknowledged witness token,
and the existing organization key and AES metadata profile.

The command authenticates the released registration and the existing active
organization and local storage. It removes the single byte-matching
protected document row from the active `ResourcesDB` in one SQLite
transaction. It refuses mismatched or duplicate registrations and rolls back
a deletion that would change additional rows through a foreign-key action.
A busy commit rolls back.

Success prints `registration=absent`. Repeat the command with the same
approvals after losing the result. An already absent registration succeeds
when the same release, witness, and catalog checks pass. The command preserves
the release files and authority state. After the engine restarts with
`CDSE_V2_READ_CATALOG=1`, a request for that document returns `404`.
The phase-45 direct document pin continues to use the retained release
independently of the active catalog.

## Witnessed V2 release revocation (#147 phase 50)

Stop the engine, export writers, and authority writers. Use the registry,
witness, identity, key-file and export arguments from the original release.
If the active `ResourcesDB` registration also needs retirement, run the
phase-49 command first while its release is still readable.

```bash
caumedse-admin context-column-revoke prepare "${owner_args[@]}" \
    --release-envelope "$release" --release-digest "$release_digest" \
    --retained-witness-token "$w2" --revocation-envelope "$revocation"
caumedse-admin context-column-revoke complete "${owner_args[@]}" \
    --release-envelope "$release" --release-digest "$release_digest" \
    --revocation-envelope "$revocation" --revocation-digest "$revocation_digest"
```

Prepare verifies the original completed release, physical proof, and exact
acknowledged witness token W2. It previews removal of the release's map and
records its original release digest, W2, and exact successor catalog pin. It
saves the approval in a new private file outside the export and authority
trees. Retain `revocation-digest` from prepare independently before completing.

Complete rechecks the original release and witness before committing the
approved catalog successor in one SQLite transaction.
It tombstones the release's map and removes its slots. The catalog revision
advances by one while the registry generation, other maps and slots, export
files, and active `ResourcesDB` retain their existing state. Existing generic
V2 map bindings expire when their catalog anchor changes. Bind other maps
again with the successor catalog and witness token.

If the process stops after committing the catalog, reads of the revoked
release already fail. Repeat `complete` with the original approvals to
advance the witness or recover the lost result. Recovery verifies the exact
successor and its tombstone before updating the witness. Retain the returned
`catalog` and `witness-token` values separately before restarting readers.
The offline reader refuses the revoked release and both HTTPS modes return
`503`, including when configured with the successor witness token.
