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
   integrity/registration receipt or permission to publish. Define those formats
   separately. Rechecks are point-in-time; quiesce authority/namespace writers.
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
#endif
