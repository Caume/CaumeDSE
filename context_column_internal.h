#ifndef CME_CONTEXT_COLUMN_INTERNAL_H
#define CME_CONTEXT_COLUMN_INTERNAL_H

/* Private representation shared by the staging and container codecs. */
struct cmeContextColumnStage
{
    size_t count;
    cmeContextColumnCell *cells;
};
/* Reverify the complete legacy source and target container, then compare every
   transformed plaintext. No entropy, writes or externally returned plaintext. */
int cmeContextColumnTransformCheck(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const unsigned char *source, size_t sourceLength, const unsigned char sourceDigest[32],
    const char *sourceKey, const char *sourceProfile,
    const unsigned char *image, size_t imageLength, const unsigned char imageDigest[32],
    const unsigned char *password, size_t passwordLength);
#endif
