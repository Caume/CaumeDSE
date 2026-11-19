#ifndef CME_CONTEXT_COLUMN_H
#define CME_CONTEXT_COLUMN_H

#include "context_crypto.h"

#define cmeContextColumnMaxBytes (16U*1024U*1024U)
#define cmeContextColumnMaxCellBytes (256U*1024U)
#define cmeContextColumnMaxStageBytes (32U*1024U*1024U)

typedef struct cmeContextColumnStage cmeContextColumnStage;
typedef struct
{
    char table[5],field[14];
    int64_t row;
    unsigned char salt[16];
    cmeContextV2Buffer frame;
} cmeContextColumnCell;

/* Trusted OFFLINE memory-only legacy-to-V2 staging. Independently approve and
   retain sourceDigest and the complete SQLite image; it is not registration
   authentication. Source bytes/key/profile and target credentials remain stable
   and nonoverlapping for the call. Source key is a 1..256 byte C string; target
   password is counted binary, 1..256 bytes. GCM/CBC sources only, format floor 1.
   The source map comes exclusively from the retained target plan. Require exact
   four-field coverage per data/meta row, known schema/attributes, valid keys,
   salts, row order and all declared legacy integrity tags before target entropy.
   Each candidate cell has fresh V2 salt/nonce and verified plaintext readback.
   Protect/shuffle metadata is rewritten to the explicit V2 staging profile.
   Other metadata is preserved; legacy data tags/helper columns are not copied.

   Returns 0/1/2/3 as the codec (3 also if SQLite deserialize is unavailable).
   Require a closed rollback-format SQLite image; WAL snapshots are refused.
   Output clears on ALL failures. No caller SQLite
   handle, file, map, job, witness, global profile or registration is changed.
   The owned result is an ephemeral candidate, NOT a serialized ColumnFile,
   integrity/registration receipt or permission to publish. Use the explicit
   container APIs below for serialization. Rechecks are point-in-time; quiesce writers.
   There is no legacy/provider fallback or floor-2 migration approval. */
int cmeContextColumnStageCreate(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const unsigned char *source, size_t length, const unsigned char sourceDigest[32],
    const char *sourceKey, const char *sourceProfile,
    const unsigned char *password, size_t passwordLength, cmeContextColumnStage **stage);

/* Borrowed immutable cell view, valid until StageFree. No current-state check.
   Preserve the opaque result and all returned contents until Free. */
size_t cmeContextColumnStageCount(const cmeContextColumnStage *stage);
const cmeContextColumnCell *cmeContextColumnStageCell(const cmeContextColumnStage *stage, size_t index);
void cmeContextColumnStageFree(cmeContextColumnStage **stage);

#define cmeContextColumnStageProfile "herradura-hske-nl-v2-profile1"

#define cmeContextColumnMaxImageBytes (32U*1024U*1024U)
#define cmeContextColumnImageIntegrity "aead-context+inventory+sha256-pin"
/* Offline container v1 for V2 frames. Serializer emits a fresh, plaintext-free
   SQLite image with fixed schema/application ID/profile/integrity declarations.
   Ordinals follow the capability's canonical (table,row,field) source inventory;
   file labels never supply crypto identities. Complete four-field groups only.
   Readback authenticates every cell and checks metadata/order semantics. The
   serializer always performs this readback before releasing image and digest.

   Independently retain/approve the SHA-256 digest of ALL image bytes. Reader
   requires that external pin; a digest bundled with an untrusted file is not
   authentication. Cell AEAD + exact inventory + the trusted image pin define
   container integrity; no legacy row/helper MAC columns are copied or implied.
   Legacy MAC/sign algorithm declarations remain provenance metadata only.

   Returns 0/1/2/3 as the codec; 3 also if SQLite serialize/deserialize unavailable.
   All outputs clear on failure; use V2BufferFree for image, StageFree for stage.
   Outputs must own no allocation on entry; all inputs/outputs are stable and
   nonoverlapping. No file/path/registration/map/job/witness writes, live reader
   dispatch, stored-map publication or acceptance receipt. Floor-1 allocation
   and target/witness lifetime/quiescence requirements still apply. */
int cmeContextColumnStageSerialize(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnStage *stage, const unsigned char *password, size_t passwordLength,
    cmeContextV2Buffer *image, unsigned char digest[32]);
int cmeContextColumnStageDeserialize(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const unsigned char *image, size_t length, const unsigned char digest[32],
    const unsigned char *password, size_t passwordLength, cmeContextColumnStage **stage);

typedef struct
{
    const char *sourceProfile,*destinationMap;
    unsigned char sourceDigest[32],candidateDigest[32],registrationEvidenceDigest[32];
} cmeContextColumnTransformApproval;
#define cmeContextColumnTransformMaxBytes 512U
/* Retained OFFLINE transformation receipt, NOT full registration acceptance.
   Independently approve/retain all approval fields and both artifacts. The
   nonzero registrationEvidenceDigest pins an EXTERNAL owner approval document;
   this API does not parse/verify ResourcesDB, partMAC or its registration fields.
   A caller-supplied digest alone is not a verified registration or provenance.

   Prepare and Verify BOTH reverify the complete legacy source, strict V2 image,
   all plaintext equality (including the defined protect/shuffle rewrites), the
   retained allocation/current registry/catalog/witness and absent destination.
   A domain-separated manager HMAC binds canonical evidence/approval bytes. Verify
   also requires an independently retained hash of the receipt; signature-only
   verification never replaces artifact comparison. No secrets in the receipt.
   No entropy, authority/file writes, publication or legacy-intent compatibility.
   Binding/custody/quiescence/floor/source bounds remain as above. All inputs and
   outputs stable/nonoverlapping; receipt owns no allocation on entry. Outputs
   clear on error; V2BufferFree releases receipt. Return 0/1/2/3 as the codec. */
int cmeContextColumnTransformPrepare(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *approval,
    const unsigned char *source, size_t sourceLength, const char *sourceKey,
    const unsigned char *image, size_t imageLength, const unsigned char *password, size_t passwordLength,
    cmeContextV2Buffer *receipt, unsigned char receiptDigest[32]);
int cmeContextColumnTransformVerify(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *approval,
    const unsigned char *source, size_t sourceLength, const char *sourceKey,
    const unsigned char *image, size_t imageLength, const unsigned char *password, size_t passwordLength,
    const unsigned char *receipt, size_t receiptLength, const unsigned char receiptDigest[32]);

#define cmeContextColumnRegistrationType "file.csv.cdse-v2"
typedef struct
{
    const char *metadataProfile,*sourceFile,*destinationFile,*sourceDocument,*destinationDocument;
    const char *storageId,*organizationResource,*columnId,*storagePath;
    int64_t sourceRow,destinationRow;
    unsigned char sourceResourcesDigest[32],candidateResourcesDigest[32];
} cmeContextColumnRegistrationApproval;
typedef struct
{
    const unsigned char *source,*candidate,*sourceResources,*candidateResources,*password;
    size_t sourceLength,candidateLength,sourceResourcesLength,candidateResourcesLength,passwordLength;
    const char *sourceKey,*registrationKey;
} cmeContextColumnRegistrationInputs;
/* Canonical approval hash only: no artifact authentication. Independently review
   and retain all inputs and this hash before assigning registrationEvidenceDigest.
   Binds both ResourcesDB pins, payload pins, selectors, leaf names, local storage
   path and destination map. Output clears on error, returns 0/1. */
int cmeContextColumnRegistrationDigest(const cmeContextColumnTransformApproval *transform,
    const cmeContextColumnRegistrationApproval *approval, unsigned char digest[32]);
/* Read-only selected single-part local ColumnFile copy registration verification.
   Require pinned current-schema ResourcesDB snapshots. Preserve ALL original
   logical rows/cells/schema byte-exact and add ONLY the approved destination row.
   Authenticate selected protected fields/lookups, unique source/destination
   associations and local storage path; verify source/candidate partMAC over the
   exact payload bytes. Destination type is file.csv.cdse-v2; metadata remains
   homogeneous legacy AES under the same bounded C-string registration key.
   Other selected metadata stays equal, including user/org/resourceInfo/timestamp.
   No metadata key rotation, multipart, remote storage, file/path opens or writes.

   Require transform.registrationEvidenceDigest to match RegistrationDigest;
   never adopt a digest from an artifact. Then invoke full TransformPrepare/Verify
   and recheck authority before output. Same receipt wire format/ownership/status
   as Transform APIs; a plain TransformVerify is NOT registration verification.
   All pointers stable/nonoverlapping. Bounds: 16 MiB each ResourcesDB, 4096 total
   existing rows, 256 KiB SQL cells, selectors <=128 bytes, leaf names <=255,
   approved absolute storagePath <=1024. No publication/complete export acceptance
   or physical file provenance claim; those require the separate owner workflow. */
int cmeContextColumnRegisteredPrepare(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *approval,
    const cmeContextColumnRegistrationInputs *inputs, cmeContextV2Buffer *receipt, unsigned char receiptDigest[32]);
int cmeContextColumnRegisteredVerify(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *approval,
    const cmeContextColumnRegistrationInputs *inputs,
    const unsigned char *receipt, size_t receiptLength, const unsigned char receiptDigest[32]);
/* Complete memory-supplied single-part local CSV export, without filesystem
   custody/publication. Companions are ALL source documents plus RolesDB/LogsDB,
   sorted by ASCII leaf name. Both exports retain identical companion bytes;
   ResourcesDB and the new V2 payload are supplied by RegistrationInputs.
   Independently approve names, lengths and SHA256 pins before calling Digest;
   this helper does not inspect bytes. Never adopt pins from untrusted exports.
   Every source registration/lookup/whole-payload MAC is authenticated. All stores
   must be unique local registrations at the approved literal storagePath.
   RolesDB/LogsDB require current bounded SQLite schemas/integrity; their retained
   pins authenticate unchanged bytes, not individual historical field semantics.
   No multipart/remote/non-CSV sibling profiles. At most 4098 companions, 32 MiB
   each, 64 MiB aggregate per export; internal DBs at most 16 MiB. */
typedef struct
{
    const char *name;
    const unsigned char *source,*candidate;
    size_t length;
    unsigned char digest[32];
} cmeContextColumnExportArtifact;
typedef struct
{
    const cmeContextColumnExportArtifact *companions;
    size_t count;
    unsigned char approvalDigest[32];
    const unsigned char *registrationReceipt;
    size_t registrationReceiptLength;
    unsigned char registrationReceiptDigest[32];
} cmeContextColumnExportInputs;
#define cmeContextColumnExportMaxBytes (64U*1024U*1024U)
#define cmeContextColumnAcceptanceMaxBytes 640U
int cmeContextColumnExportDigest(const cmeContextColumnTransformApproval *transform,
    const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnExportArtifact *companions, size_t count, unsigned char digest[32]);
/* New domain-separated retained acceptance receipt, distinct from transformation
   receipts and legacy publication intents. Both calls reverify the retained
   registration receipt, full transformation, complete supplied inventories and
   current authority. Verify also requires an independently retained receipt hash.
   Read-only/entropy-free, point-in-time and replayable while authority is current;
   no one-time consumption, path/inode provenance, freshness or publish permission.
   Stable/nonoverlapping inputs, empty owned outputs, V2BufferFree and 0/1/2/3
   statuses as above. All outputs clear on failure. */
int cmeContextColumnExportPrepare(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnRegistrationInputs *inputs, const cmeContextColumnExportInputs *export,
    cmeContextV2Buffer *receipt, unsigned char receiptDigest[32]);
int cmeContextColumnExportVerify(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnRegistrationInputs *inputs, const cmeContextColumnExportInputs *export,
    const unsigned char *receipt, size_t receiptLength, const unsigned char receiptDigest[32]);

typedef struct cmeContextColumnCustody cmeContextColumnCustody;
typedef struct
{
    int parent;
    const char *name;
} cmeContextColumnCustodyRoot;
/* Physical, read-only custody for the phase-33 complete CSV export profile.
   Independently approve already-open parent directory objects and child leaf
   names. Parents/roots must be owned by this euid with mode 0700. Root names
   use ASCII leaf rules, roots must be distinct and not nested. Parents remain
   caller-trusted namespace anchors, not proof of any absolute path ancestry.
   Keep authority, keys, receipts and other controls outside BOTH export roots.

   Open duplicates parents and opens children with NOFOLLOW/CLOEXEC. Exact root
   enumeration permits only the approved companions, ResourcesDB and (candidate
   only) new V2 file. Files must be regular, owned mode 0600, single-link, closed rollback-format SQLite images, without
   sidecars (all -wal/-shm/-journal suffixes reserved). Read actual bounded files
   through held roots, compare pins, then run full ExportVerify on those private
   bytes. RegistrationInputs supplies C-string source/metadata keys and counted
   target password ONLY: its artifact pointers/lengths are ignored. ExportInputs
   supplies approved companion names/lengths/pins and retained registration
   evidence ONLY: its companion byte pointers are ignored. Approval/receipt pins
   must be independently retained, never adopted from disk. All inputs stable;
   output handle is NULL on ALL failures. 0/1/2/3 statuses remain as above.

   Returned handle owns four directory descriptors and bounded stat/hash metadata;
   it retains NO credentials, payload bytes or receipt bytes. Manager and target
   are borrowed and MUST outlive the handle; serialize Check/Free calls. Check
   reopens/hashes every file and
   compares inode/dev/owner/group/mode/link/size/mtime/ctime, directory identities,
   named-root bindings, inventories and current target authority. Observed failure
   permanently poisons the handle. No thousands-of-descriptors requirement.
   Checks are point-in-time, NOT an exclusive lease or atomic storage/authority
   transaction. Coordinate writers independently; no writes/fsync/rename, durable
   custody receipt, crash recovery, publication or live V2 dispatch is provided. */
int cmeContextColumnCustodyOpen(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnRegistrationInputs *credentials, const cmeContextColumnExportInputs *export,
    const cmeContextColumnCustodyRoot *source, const cmeContextColumnCustodyRoot *candidate,
    const unsigned char *acceptance, size_t acceptanceLength, const unsigned char acceptanceDigest[32],
    cmeContextColumnCustody **custody);
int cmeContextColumnCustodyCheck(cmeContextColumnCustody *custody);
void cmeContextColumnCustodyFree(cmeContextColumnCustody **custody);
#endif
