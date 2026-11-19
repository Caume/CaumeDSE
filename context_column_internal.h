#ifndef CME_CONTEXT_COLUMN_INTERNAL_H
#define CME_CONTEXT_COLUMN_INTERNAL_H

/* Private representation shared by the staging and container codecs. */
struct cmeContextColumnStage
{
    size_t count;
    cmeContextColumnCell *cells;
};
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
