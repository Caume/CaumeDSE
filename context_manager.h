#ifndef CME_CONTEXT_MANAGER_H
#define CME_CONTEXT_MANAGER_H

#include "context_registry.h"

typedef struct cmeContextManager cmeContextManager;

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

#endif
