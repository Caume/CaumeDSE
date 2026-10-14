#ifndef CME_CONTEXT_WITNESS_H
#define CME_CONTEXT_WITNESS_H

#include "context_manager.h"

typedef struct cmeContextWitness cmeContextWitness;
typedef struct
{
    uint64_t revision;
    unsigned char digest[32];
} cmeContextWitnessAnchor;
typedef struct
{
    cmeContextWitnessAnchor anchor;
    cmeContextAnchor registry;
    cmeContextMapAnchor catalog;
} cmeContextWitnessState;

/* Independently protected local checkpoint, outside manager/export backups.
   Separate random key and private canonical uid-owned 0700 directory required.
   Explicit create requires a new DB and independently approved current pins.
   This API does NOT authenticate manager state: the owner must check that pair
   against its manager before creation/advance. Never adopt candidate pins.
   Reopen never creates/repairs state. Whole-witness replay is NOT detectable by
   this file itself; independent retention/custody remains an owner precondition. */
int cmeContextWitnessOpen(const char *directory, int create, const unsigned char key[32],
                          const unsigned char deployment[16], const unsigned char organization[16],
                          const cmeContextAnchor *registry, const cmeContextMapAnchor *catalog,
                          cmeContextWitness **witness);
/* Protect directory from rename; finish concurrent operations before close. */
void cmeContextWitnessClose(cmeContextWitness **witness);
int cmeContextWitnessFetch(cmeContextWitness *witness, cmeContextWitnessState *state);
/* 0 exact current pair, 2 mismatch, 1 invalid/unavailable. No lease. */
int cmeContextWitnessCheck(cmeContextWitness *witness, const cmeContextAnchor *registry,
                           const cmeContextMapAnchor *catalog);
typedef enum
{
    cmeWitnessRecoveryInvalid=0,
    cmeWitnessRecoveryCurrent=1,
    cmeWitnessRecoveryAdvanceRequired=2,
    cmeWitnessRecoveryAlreadyAdvanced=3
} cmeContextWitnessRecovery;
/* Read-only authenticated snapshot against an independently retained token and
   owner-approved manager pair. 0 classified, 2 conflict, 1 invalid/unavailable.
   No manager authentication or lease; caller must check manager pins separately.
   Never advances/adopts state. Outputs clear on failure; token/output may alias.
   Other inputs/outputs must not overlap. */
int cmeContextWitnessReconcile(cmeContextWitness *witness, const cmeContextWitnessAnchor *expected,
                               const cmeContextAnchor *registry, const cmeContextMapAnchor *catalog,
                               cmeContextWitnessRecovery *recovery, cmeContextWitnessAnchor *current);
/* Full witness-anchor CAS; exactly one manager counter advances by one, other
   pin stays exact. Same-counter digest changes/floor decreases fail closed.
   Last transition supports exact lost-ack retry with its previous token.
   Outputs clear on failure; expected/published may alias. Other inputs stable,
   nonoverlapping. No atomic transaction with the manager or external storage. */
int cmeContextWitnessAdvance(cmeContextWitness *witness, const cmeContextWitnessAnchor *expected,
                             const cmeContextAnchor *registry, const cmeContextMapAnchor *catalog,
                             cmeContextWitnessAnchor *published);

#endif
