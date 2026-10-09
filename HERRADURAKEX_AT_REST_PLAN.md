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
