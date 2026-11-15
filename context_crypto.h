#ifndef CME_CONTEXT_CRYPTO_H
#define CME_CONTEXT_CRYPTO_H

#include "context_witness.h"

#define cmeContextV2HeaderBytes 80U
#define cmeContextV2SaltBytes 16U
#define cmeContextV2MaxPlaintext (16U*1024U*1024U)

typedef struct
{
    unsigned char *bytes;
    size_t length;
} cmeContextV2Buffer;

/* Explicit in-process opt-in. Requires an owner-approved stored-map binding,
   independently pinned manager state and fixed authority namespaces. Inputs are
   stable/nonoverlapping for the call; finish calls before freeing bindings.
   Password is 1..256 counted bytes; salt is exactly 16 binary bytes. Plaintext
   may be NULL only at length zero. Output structures must own no allocation on
   entry; all outputs clear on failure. Preserve owned pointer/length until Free.
   Returns 0 success, 1 invalid/auth/allocation/RNG failure, 2 stale binding,
   3 provider unavailable. No fallback to legacy crypto is permitted on failure.
   Bounds are checked before allocation. Empty plaintext is supported.

   Seal generates salt and nonce internally with RAND_bytes. Open accepts only
   strict CDSEHKX2/profile1/KDF1/schema1/flags0 frames at trusted floors 1 or 2.
   Context and floor come exclusively from the authenticated mapped binding.
   Both operations recheck authority before releasing any output. These are
   point-in-time checks, not a lease or atomic storage/witness transaction.
   Callers must coordinate subsequent publication and independent rollback
   defense. No legacy dispatch, SQL/integrity transformation or file writes. */
int cmeContextV2Seal(cmeContextManager *manager, const cmeContextBinding *binding,
    const char *table, int64_t row, const char *field,
    const unsigned char *password, size_t passwordLength,
    const unsigned char *plaintext, size_t length,
    cmeContextV2Buffer *frame, unsigned char salt[cmeContextV2SaltBytes]);
int cmeContextV2Open(cmeContextManager *manager, const cmeContextBinding *binding,
    const char *table, int64_t row, const char *field,
    const unsigned char *password, size_t passwordLength,
    const unsigned char salt[cmeContextV2SaltBytes], const unsigned char *frame, size_t length,
    cmeContextV2Buffer *plaintext);
/* Explicit unpublished-copy-target variants. Accept ONLY a witness-guarded
   cmeContextCopyTarget, never a raw descriptor or ordinary stored-map binding.
   Recheck registry/catalog plus the retained witness before/after crypto. Same
   buffer, bound, return and entropy contracts as Seal/Open. No map/file/job or
   witness writes; this is staging crypto, not artifact acceptance/publication.
   Current copy-allocation version 1 is floor-1-only; no floor closeout approval. */
int cmeContextV2SealCopyTarget(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const char *table, int64_t row, const char *field,
    const unsigned char *password, size_t passwordLength,
    const unsigned char *plaintext, size_t length, cmeContextV2Buffer *frame,
    unsigned char salt[cmeContextV2SaltBytes]);
int cmeContextV2OpenCopyTarget(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const char *table, int64_t row, const char *field,
    const unsigned char *password, size_t passwordLength,
    const unsigned char salt[cmeContextV2SaltBytes], const unsigned char *frame, size_t length,
    cmeContextV2Buffer *plaintext);

/* Cleanses the owned bytes (including the allocation's trailing zero), frees,
   and clears the structure. NULL and already-cleared buffers are safe. */
void cmeContextV2BufferFree(cmeContextV2Buffer *buffer);

#endif
