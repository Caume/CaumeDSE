#ifndef CME_CONTEXT_REGISTRY_H
#define CME_CONTEXT_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#define cmeContextRegistryMaxBytes (1024U*1024U)
#define cmeContextRegistryMaxEntries 4096U

typedef struct
{
    unsigned char deployment[16], organization[16];
    uint64_t generation;
    unsigned int minimumFormat;
    unsigned char digest[32];
} cmeContextAnchor;

typedef struct
{
    unsigned char ids[5][16]; /* deployment, organization, storage, resource, record */
    unsigned int role; /* ResourcesDB=1, RolesDB=2, LogsDB=3, ColumnFile=4, RawPart=5 */
    char table[65], field[65];
} cmeStorageContext;

typedef struct cmeContextRegistry cmeContextRegistry;

/* Trusted manager adapter: fetch current independently authenticated state on each open. */
typedef int (*cmeContextAnchorFetch)(void *manager, const unsigned char deployment[16],
                                   const unsigned char organization[16], cmeContextAnchor *anchor);

/* Returns 0 on success; 1 invalid input, 2 manager/auth failure, 3 invalid snapshot,
   4 allocation failure. No transport, key provisioning or storage writes are enabled. */
int cmeContextRegistryOpen(const unsigned char *body, size_t length,
                           const unsigned char *tag, size_t tagLength,
                           const unsigned char *key, size_t keyLength,
                           const unsigned char deployment[16], const unsigned char organization[16],
                           cmeContextAnchorFetch fetch, void *manager, cmeContextRegistry **registry);
/* Copies context/floor only for active registrations; clears outputs on failure.
   Handles belong to one operation and must not be cached across manager updates. */
int cmeContextRegistryLookup(const cmeContextRegistry *registry, const char *lookup,
                            cmeStorageContext *context, unsigned int *minimumFormat);
void cmeContextRegistryFree(cmeContextRegistry **registry);

#endif
