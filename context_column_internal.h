#ifndef CME_CONTEXT_COLUMN_INTERNAL_H
#define CME_CONTEXT_COLUMN_INTERNAL_H

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
