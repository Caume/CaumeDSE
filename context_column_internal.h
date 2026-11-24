#ifndef CME_CONTEXT_COLUMN_INTERNAL_H
#define CME_CONTEXT_COLUMN_INTERNAL_H

#include "context_offline.h"

/* Private representation shared by the staging and container codecs. */
struct cmeContextColumnStage
{
    size_t count;
    cmeContextColumnCell *cells;
};
typedef struct
{
    int parent,directory;
    char name[NAME_MAX+1];
    struct stat anchor,status;
} cmeCustodyDirectory;
typedef struct
{
    char name[NAME_MAX+1];
    size_t length,maximum;
    unsigned char digest[32];
    struct stat status;
} cmeCustodyFile;
struct cmeContextColumnCustody
{
    cmeContextManager *manager;
    const cmeContextCopyTarget *target;
    cmeCustodyDirectory roots[2];
    cmeCustodyFile *files[2];
    size_t count[2];
    unsigned char acceptanceDigest[32];
    char destinationMap[129];
    int failed;
};

typedef struct
{
    unsigned char *resources;
    size_t length;
    unsigned char digest[32];
    char payload[NAME_MAX+1];
} cmeColumnCatalogSnapshot;

typedef struct
{
    const char *path,*organization,*storage,*document,*key,*profile;
} cmeColumnCatalogQuery;

enum { cmeColumnCatalogMissing=4 };

typedef enum
{
    cmeColumnCatalogRegister,
    cmeColumnCatalogUnregister
} cmeColumnCatalogAction;

int cmeColumnCatalogMatch(const cmeColumnCatalogSnapshot *snapshot, const cmeColumnCatalogQuery *query);
int cmeColumnCatalogUpdate(const cmeColumnCatalogSnapshot *snapshot, const cmeColumnCatalogQuery *query,
    const cmeOfflineArtifact *active, cmeContextColumnReadRelease *release, cmeColumnCatalogAction action);
int cmeColumnUpdateRegistration(cmeContextColumnReadRelease *release, const cmeColumnCatalogQuery *query,
    cmeColumnCatalogAction action);
int cmeColumnReadRegistered(cmeContextColumnReadRelease *release, const cmeColumnCatalogQuery *query,
    int64_t row, const unsigned char *password, size_t passwordLength, cmeContextV2Buffer *plaintext);
int cmeContextV2OpenAdmissionBinding(cmeContextManager *manager, const cmeContextBinding *binding,
    const char *table, int64_t row, const char *field, const unsigned char *password, size_t passwordLength,
    const unsigned char salt[16], const unsigned char *frame, size_t length, cmeContextV2Buffer *plaintext);
int cmeColumnStageDeserializeAdmission(cmeContextManager *manager, const cmeContextBinding *binding,
    const cmeContextMap *map, const unsigned char *image, size_t length, const unsigned char digest[32],
    const unsigned char *password, size_t passwordLength, cmeContextColumnStage **stage);
/* Authenticated unblocked stored-map inventory; no admission block override. */
int cmeColumnStageDeserializeMapped(cmeContextManager *manager, const cmeContextBinding *binding,
    const cmeContextMap *map, const unsigned char *image, size_t length, const unsigned char digest[32],
    const unsigned char *password, size_t passwordLength, cmeContextColumnStage **stage);
int cmeCustodyRead(const cmeCustodyDirectory *root, cmeCustodyFile *entry, unsigned char **output, int initial);
int cmeCustodyRootOpen(const cmeContextColumnCustodyRoot *input, cmeCustodyDirectory *root);
int cmeCustodyPhysicalCheck(cmeContextColumnCustody *custody);
int cmeColumnPublicationCompleted(cmeContextColumnCustody *custody,
    const cmeContextColumnPublication *publication, const char *staging, const unsigned char pin[32]);
int cmeCustodyLeaf(const char *name);
int cmeCustodyIdentity(const struct stat *a, const struct stat *b);
int cmeCustodySame(const struct stat *a, const struct stat *b);
int cmeCustodyPrivate(const struct stat *status);
int cmeCustodyNested(int directory, const struct stat *other);
/* Strict legacy AES salted-value decoder, after SQL length/type checks. */
int cmeContextColumnLegacyDecode(const char *value, const char *salt, const char *key,
    const char *profile, char **plain);
int cmeContextColumnLegacyCheck(const unsigned char *source, size_t length, const unsigned char digest[32],
    const char *key, const char *profile);
/* Reverify the complete legacy source and target container, then compare every
   transformed plaintext. No entropy, writes or externally returned plaintext. */
int cmeContextColumnTransformCheck(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const unsigned char *source, size_t sourceLength, const unsigned char sourceDigest[32],
    const char *sourceKey, const char *sourceProfile,
    const unsigned char *image, size_t imageLength, const unsigned char imageDigest[32],
    const unsigned char *password, size_t passwordLength);
int cmeContextColumnExportCheck(const cmeContextColumnTransformApproval *transform,
    const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnRegistrationInputs *inputs, const cmeContextColumnExportInputs *export);
#endif
