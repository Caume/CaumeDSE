#ifndef CME_CONTEXT_MANAGER_H
#define CME_CONTEXT_MANAGER_H

#include "context_registry.h"

typedef struct cmeContextManager cmeContextManager;

typedef enum
{
    cmeContextNewStorage=1,
    cmeContextNewResource=2,
    cmeContextNewRecord=3,
    cmeContextNewField=4
} cmeContextAllocation;

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

#endif
