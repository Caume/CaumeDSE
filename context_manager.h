#ifndef CME_CONTEXT_MANAGER_H
#define CME_CONTEXT_MANAGER_H

#include "context_registry.h"

typedef struct cmeContextManager cmeContextManager;
typedef struct cmeContextBinding cmeContextBinding;

typedef struct
{
    char *activePath, *stagedPath;
    unsigned char sourceDigest[32], targetDigest[32], selectionDigest[32];
} cmeContextShufflePair;

typedef struct
{
    uint64_t revision;
    unsigned char digest[32];
} cmeContextMapAnchor;

typedef struct
{
    const char *lookup, *table, *field;
    int64_t row; /* Physical operation-local slot, never a cryptographic ID. */
} cmeContextSlot;

/* Read-only owned metadata; keep pointers/count unchanged until MapFree. */
typedef struct
{
    char *resource;
    unsigned int role;
    int active;
    int blocked; /* Pending offline intent; metadata is never a crypto binding. */
    size_t count;
    cmeContextSlot *slots;
} cmeContextMap;

typedef enum
{
    cmeContextNewStorage=1,
    cmeContextNewResource=2,
    cmeContextNewRecord=3,
    cmeContextNewField=4
} cmeContextAllocation;

typedef enum
{
    cmeContextRevokeResource=1,
    cmeContextRevokeStorage=2
} cmeContextRevocationScope;

/* Trusted in-process manager only. Directory must be canonical, private, owned
   by this uid, protected from rename, and outside every CaumeDSE storage export.
   create=1 requires a new DB; reopening never creates or resets authority.
   The separate registry key is supplied by the owner, never stored in the DB. */
int cmeContextManagerOpen(const char *directory, int create, const unsigned char key[32],
                          const unsigned char deployment[16], const unsigned char organization[16],
                          cmeContextManager **manager);
/* Owner must finish all concurrent operations before close. */
void cmeContextManagerClose(cmeContextManager **manager);

/* Approved issuer publishes canonical authenticated bytes. NULL expected is
   allowed only for first generation 1/floor 1. Otherwise the full previous anchor
   must match. Returns 0 success, 2 CAS conflict, 1 invalid/unavailable state.
   A failed/uncertain commit requires refresh, never blind retry or reset.
   Input buffers/anchors must remain unchanged for the duration of the call. */
int cmeContextManagerPublish(cmeContextManager *manager, const unsigned char *body, size_t length,
                             const unsigned char tag[32], const cmeContextAnchor *next,
                             const cmeContextAnchor *expected);

/* Export an owned candidate snapshot. free(*body) after use. This is not an
   independent authority for a reader; obtain its current anchor via Fetch. */
int cmeContextManagerSnapshot(cmeContextManager *manager, unsigned char **body, size_t *length,
                              unsigned char tag[32], cmeContextAnchor *anchor);
/* cmeContextAnchorFetch adapter: reload and authenticate committed state each call. */
int cmeContextManagerFetch(void *manager, const unsigned char deployment[16],
                           const unsigned char organization[16], cmeContextAnchor *anchor);

/* Trusted issuer only; lookups are stable registration handles, not file paths.
   NewStorage: external roles, no parent; allocate storage/resource/record UUIDs.
   NewResource: internal roles need no parent (zero storage); external roles need
   an active external parent to retain its storage. Allocate resource/record.
   NewRecord: active same-role parent; retain storage/resource, allocate record.
   NewField: active same-role/same-table parent; retain all IDs.
   IDs are random UUIDv4, never derived from names. Revoked lookups stay reserved.
   Initial expected=NULL only; otherwise supply the full current anchor. Floor
   is preserved. Returns 0 success, 2 CAS conflict, 1 invalid/unavailable state.
   Outputs are cleared on failure; uncertain commits require fresh lookup.
   Expected/published may alias; other inputs must not overlap outputs and must
   remain unchanged during the call. Low-level Publish still trusts its issuer
   to approve externally supplied IDs; it does not enforce allocator provenance.
   Existing mappings survive path renames/row shuffles without reprovisioning. */
int cmeContextManagerProvision(cmeContextManager *manager, const char *lookup,
                               cmeContextAllocation allocation, unsigned int role,
                               const char *table, const char *field, const char *parent,
                               const cmeContextAnchor *expected, cmeStorageContext *context,
                               cmeContextAnchor *published);
/* Revoke one active field registration, not an entire resource or storage.
   Tombstones are retained; no removal, revival or implicit cascading. */
int cmeContextManagerRevoke(cmeContextManager *manager, const char *lookup,
                            const cmeContextAnchor *expected, cmeContextAnchor *published);

/* Atomically revoke all retained registrations in an active seed's scope.
   Resource matches role/storage/resource; storage matches a nonzero external
   storage UUID across ColumnFile and RawPart. No paths or caller-supplied IDs.
   One generation/CAS, unchanged contexts/floor, retained tombstones. An active
   seed is required; invalid scope or internal storage fails without publication.
   Same return, output, aliasing and uncertain-commit rules as Provision.
   This is not deletion of files or a permanent ban on trusted external issuers. */
int cmeContextManagerRevokeScope(cmeContextManager *manager, const char *lookup,
                                 cmeContextRevocationScope scope,
                                 const cmeContextAnchor *expected, cmeContextAnchor *published);

/* Trusted owner supplies the resource handle, schema role and approved slot map
   for the full expected anchor. Never construct it from candidate DB/frame
   metadata, filenames, request parameters or untrusted lookup columns.
   Bind verifies active registrations in one current authenticated snapshot.
   All slots must match the seed's role/storage/resource and their schema names.
   Within each table, a slot has one record ID and a record has one slot.
   Partial maps are allowed, not complete-inventory or storage-integrity proofs.
   Returns 0 success, 2 stale anchor, 1 invalid/unavailable; clears *binding on
   failure. Copies all input data; inputs must remain stable until return and
   must not overlap the output pointer. Finish concurrent lookups before Free.
   Free and rebind for each operation; this does not persist/authenticate the
   owner's map, acquire a revocation lease, or enable V2 storage paths. */
int cmeContextManagerBind(cmeContextManager *manager, const char *resource,
                          unsigned int role, const cmeContextSlot *slots, size_t count,
                          const cmeContextAnchor *expected, cmeContextBinding **binding);
/* Immutable operation-local lookup; schema names come from the trusted caller.
   Copies context/floor; clears outputs for missing or invalid slots. Inputs must
   not overlap outputs. */
int cmeContextBindingLookup(const cmeContextBinding *binding, const char *table,
                            int64_t row, const char *field, cmeStorageContext *context,
                            unsigned int *minimumFormat);
/* 0 still current, 2 changed anchor, 1 invalid/unavailable authority. This is
   a point-in-time recheck, not a lock/lease or atomic commit with storage writes. */
int cmeContextBindingCheck(cmeContextManager *manager, const cmeContextBinding *binding);
void cmeContextBindingFree(cmeContextBinding **binding);

/* Opt-in trusted-owner catalog in the private manager DB. Init is explicit and
   one-time; missing/corrupt state is never recreated. All writes require the
   full current registry anchor; Store/Remove also require the current catalog
   revision/digest. Map names are stable owner handles, not candidate filenames.
   Store replaces a whole approved slot map atomically. Its resource handle/role
   cannot change; Remove retains a permanent name tombstone. Catalog limits:
   4096 retained names, 4096 total slots, 1 MiB authenticated encoding.
   Returns 0 success, 2 CAS conflict, 1 invalid/unavailable. Outputs are cleared
   on failure. Expected map/published anchors may alias; all other inputs must
   remain stable and not overlap outputs. Lost acknowledgements require refresh
   and reconciliation, never blind reset/retry. No backing-file transaction,
   remote owner authentication, V2 writes or independent rollback protection. */
int cmeContextManagerMapInit(cmeContextManager *manager, const cmeContextAnchor *expected,
                             cmeContextMapAnchor *published);
int cmeContextManagerMapFetch(cmeContextManager *manager, cmeContextMapAnchor *anchor);
/* Authenticate and compare both supplied pins in one current read transaction.
   Returns 0 exact, 2 conflict, 1 invalid/unavailable; not a storage lease. */
int cmeContextManagerCheckAnchors(cmeContextManager *manager, const cmeContextAnchor *registry,
                                  const cmeContextMapAnchor *catalog);
int cmeContextManagerMapStore(cmeContextManager *manager, const char *name, const char *resource,
                              unsigned int role, const cmeContextSlot *slots, size_t count,
                              const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                              cmeContextMapAnchor *published);
int cmeContextManagerMapRemove(cmeContextManager *manager, const char *name,
                               const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                               cmeContextMapAnchor *published);
/* Owned authenticated metadata for exact reconciliation, including tombstones
   and mappings whose registrations were subsequently revoked. This is NOT a
   validated storage binding. Free with MapFree; never use it to skip MapBind. */
int cmeContextManagerMapRead(cmeContextManager *manager, const char *name,
                             const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                             cmeContextMap **map);
void cmeContextMapFree(cmeContextMap **map);
/* Select only by an independently trusted owner map name. Authenticates the
   durable map, revalidates active contexts and pins both anchors. Check then
   detects registry OR catalog changes; local Lookup remains operation-scoped. */
int cmeContextManagerMapBind(cmeContextManager *manager, const char *name,
                             const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                             cmeContextBinding **binding);

/* Trusted OFFLINE identity preparation for a same-storage ColumnFile copy.
   Select a current active/unblocked stored map, floor 1 only. Supply one unused
   destination lookup per source slot, in MapRead's table/row/field order.
   Atomically allocate a fresh resource and fresh records (shared by all fields
   of a source table/slot), retaining scope/storage/schema and physical slots.
   Both registry and catalog pins are checked under the final publication lock;
   only registry generation advances, once. Existing registrations/maps/files
   are untouched. Output is an owned ALLOCATION DESCRIPTOR, not a stored map,
   inventory proof, physical copy authorization or V2 crypto binding. Free with
   MapFree. A separately approved MapStore may publish it later, with explicit
   witness advancement between registry and catalog publications. No witness
   guard, file copy, AEAD re-encryption or cross-storage/org copy is supplied.
   Return 0/2/1 and output/alias rules match Provision; copy/published clear on
   failure. No partial identities survive failure before commit. Lost commit
   acknowledgements require independent snapshot review, never blind retry. */
int cmeContextManagerCopyProvision(cmeContextManager *manager, const char *sourceName,
    const char *const *lookups, size_t count, const cmeContextAnchor *expected,
    const cmeContextMapAnchor *catalog, cmeContextMap **copy, cmeContextAnchor *published);

#define cmeContextCopyPlanMaxBytes (2U*cmeContextRegistryMaxBytes+32U)
/* Trusted OFFLINE two-phase allocation. Prepare commits nothing; returns owned
   opaque signed bytes and their SHA256. free(*plan) after use. Independently
   review/retain the digest and durably save the EXACT bytes before Commit.
   The caller supplies private-file creation, fsync and directory durability.
   Do not regenerate after an uncertain commit. Plans contain metadata, no keys.
   Status authenticates the plan and classifies the current exact pair as
   1 ready (original registry), 2 committed (planned next registry); other pairs
   conflict. Commit permits exact lost-ack retry only at that next registry and
   unchanged catalog, never republishes or reallocates on retry. Both return
   an owned allocation descriptor and planned next anchor, not file authority.
   Supply the ORIGINAL independently approved registry/catalog pins on retries.
   Low-level APIs do not guard witnesses. Return 0/2/1; outputs clear on failure.
   expected/next may alias; other inputs/outputs must not overlap and remain
   stable. Keep all readers/writers stopped; no storage or witness lease. */
int cmeContextManagerCopyPlanPrepare(cmeContextManager *manager, const char *sourceName,
    const char *const *lookups, size_t count, const cmeContextAnchor *expected,
    const cmeContextMapAnchor *catalog, unsigned char **plan, size_t *length, unsigned char digest[32]);
int cmeContextManagerCopyPlanStatus(cmeContextManager *manager, const unsigned char *plan,
    size_t length, const unsigned char digest[32], const cmeContextAnchor *expected,
    const cmeContextMapAnchor *catalog, int *state, cmeContextMap **copy, cmeContextAnchor *next);
int cmeContextManagerCopyPlanCommit(cmeContextManager *manager, const unsigned char *plan,
    size_t length, const unsigned char digest[32], const cmeContextAnchor *expected,
    const cmeContextMapAnchor *catalog, cmeContextMap **copy, cmeContextAnchor *published);

typedef struct
{
    unsigned char job[32], sourceDigest[32], targetDigest[32];
    char *activePath, *stagedPath;
    int state; /* 1 prepared, 2 completed, 3 aborted */
    uint64_t finishedRevision;
    cmeContextMap *target;
    cmeContextShufflePair *pair; /* Optional authenticated ResourcesDB companion. */
} cmeContextShuffle;

/* Explicit upgrade to catalog authentication v2; older catalog readers fail
   closed afterward. Registry-only APIs/formats remain unchanged. */
int cmeContextManagerShuffleInit(cmeContextManager *manager, const cmeContextAnchor *expected,
                                 const cmeContextMapAnchor *mapExpected, cmeContextMapAnchor *published);
/* OFFLINE trusted owner only: stop all readers/writers, close/checkpoint SQLite,
   independently verify and approve both file digests and the complete shuffle.
   Private canonical directories/files (0700/0600), no links/sidecars, same FS;
   staging must be outside all exports. Only role-4, identity-preserving slot
   permutations are accepted. File size bound is 256 MiB. No payload/tag proof.
   Prepare fsyncs approved files/directories, persists intent and blocks stored
   binding.
   Outputs clear on failure; mapExpected/published may alias. Other inputs must
   remain stable and nonoverlapping. Returns 0/2/1 as catalog writes do. */
int cmeContextManagerShufflePrepare(cmeContextManager *manager, const char *name,
                                    const char *activePath, const char *stagedPath,
                                    const unsigned char sourceDigest[32], const unsigned char targetDigest[32],
                                    const cmeContextSlot *slots, size_t count,
                                    const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                                    unsigned char job[32], cmeContextMapAnchor *published);
/* Owned authenticated metadata, not a payload/binding proof. Read clears the
   output on failure; retain metadata unchanged until ShuffleFree. */
int cmeContextManagerShuffleRead(cmeContextManager *manager, const char *name,
                                 const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                                 cmeContextShuffle **shuffle);
void cmeContextShuffleFree(cmeContextShuffle **shuffle);
/* complete=1 installs the approved target (atomic rename + directory fsync),
   then commits its map. complete=0 aborts only while approved source is active.
   Unknown/missing bytes leave intent blocked. Receipts permit lost-ack retry
   only at their exact finished catalog revision and matching file digest.
   This is fail-closed recovery, not a cross-file transaction, live lease,
   hardware rollback defense, or physical power-loss certification. */
int cmeContextManagerShuffleRecover(cmeContextManager *manager, const char *name,
                                    const unsigned char job[32], int complete,
                                    const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                                    cmeContextMapAnchor *published);

/* Explicit opt-in catalog-v3 upgrade, only with no prepared intents. Older
   readers fail authentication. These are trusted OFFLINE manager primitives,
   not installed commands or payload/registration validators. Pair paths must
   be ResourcesDB siblings of the respective ColumnFiles. selectionDigest is
   an owner-reviewed SHA256 commitment to registration selectors and profile;
   the caller must independently verify the phase-13 paired-artifact contract.
   Prepare blocks ALL stored maps until both files and the catalog reconcile.
   Single-file Recover rejects paired intents. Witness advance remains explicit.
   Complete installs ColumnFile first, then ResourcesDB, then publishes the map;
   abort requires both sources. Partial installs recover forward only. Exact
   finished-revision retries verify BOTH active digests. No live lease, V2 crypto,
   independent rollback defense or physical power-loss certification is implied.
   Output/alias/error conventions match the single-file APIs above. */
int cmeContextManagerShufflePairInit(cmeContextManager *manager, const cmeContextAnchor *expected,
                                     const cmeContextMapAnchor *mapExpected, cmeContextMapAnchor *published);
int cmeContextManagerShufflePairPrepare(cmeContextManager *manager, const char *name,
    const char *activePath, const char *stagedPath,
    const unsigned char sourceDigest[32], const unsigned char targetDigest[32],
    const cmeContextSlot *slots, size_t count, const cmeContextShufflePair *pair,
    const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
    unsigned char job[32], cmeContextMapAnchor *published);
int cmeContextManagerShufflePairRecover(cmeContextManager *manager, const char *name,
    const unsigned char job[32], int complete, const cmeContextAnchor *expected,
    const cmeContextMapAnchor *mapExpected, cmeContextMapAnchor *published);

#endif
