/* Retained transformation evidence only; registration acceptance stays external. */
#include "common.h"
#include "context_column.h"
#include "context_column_internal.h"

static void cmeTransformCheckpoint(const char *stage)
{
#ifdef CDSE_CONTEXT_COLUMN_TESTING
    const char *pause=getenv("CDSE_CONTEXT_TRANSFORM_PAUSE");
    if (pause && !strcmp(pause,stage))
    {
        const char *ready=getenv("CDSE_CONTEXT_TRANSFORM_READY_FD"),*resume=getenv("CDSE_CONTEXT_TRANSFORM_RESUME_FD");
        char byte;
        if (!ready || !resume || atoi(ready)<3 || atoi(resume)<3 ||
            write(atoi(ready),"1",1)!=1 || read(atoi(resume),&byte,1)!=1) _exit(87);
    }
#else
    (void)stage;
#endif
}

static void cmeTransformNumber(unsigned char *out, uint64_t value)
{
    size_t i;
    for (i=0;i<8;i++) out[i]=(unsigned char)(value>>(8*(7-i)));
}

static int cmeTransformBody(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *approval, unsigned char body[cmeContextColumnTransformMaxBytes],
    size_t *length, cmeContextCopyEvidence *evidence, unsigned char requestDigest[32])
{
    static const unsigned char domain[]="CDSE-HKX-COLUMN-TRANSFORM-v1";
    unsigned char zero[32]={0},profile;
    unsigned int written=0;
    size_t i,name,offset=0;
    int result;
    *length=0;
    if (!approval || !approval->sourceProfile || !approval->destinationMap ||
        CRYPTO_memcmp(approval->registrationEvidenceDigest,zero,32)==0) return(1);
    if (!strcmp(approval->sourceProfile,"aes-256-gcm")) profile=1;
    else if (!strcmp(approval->sourceProfile,"aes-256-cbc")) profile=2;
    else return(1);
    name=strnlen(approval->destinationMap,129); if (!name || name>128) return(1);
    for (i=0;i<name;i++)
    {
        unsigned char c=approval->destinationMap[i];
        if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') ||
            c=='_' || c=='/' || c==':' || c=='-')) return(1);
    }
    result=cmeContextCopyTargetEvidence(manager,target,evidence); if (result) return(result);
    _Static_assert(sizeof(domain)+32+73+40+40+1+96+129+32<=cmeContextColumnTransformMaxBytes,"receipt bound");
#define CME_TRANSFORM_APPEND(p,n) do { memcpy(body+offset,p,n); offset+=(n); } while (0)
    CME_TRANSFORM_APPEND(domain,sizeof(domain));
    CME_TRANSFORM_APPEND(evidence->allocationDigest,32);
    CME_TRANSFORM_APPEND(evidence->registry.deployment,16); CME_TRANSFORM_APPEND(evidence->registry.organization,16);
    cmeTransformNumber(body+offset,evidence->registry.generation); offset+=8;
    body[offset++]=(unsigned char)evidence->registry.minimumFormat; CME_TRANSFORM_APPEND(evidence->registry.digest,32);
    cmeTransformNumber(body+offset,evidence->catalog.revision); offset+=8; CME_TRANSFORM_APPEND(evidence->catalog.digest,32);
    cmeTransformNumber(body+offset,evidence->witness.revision); offset+=8; CME_TRANSFORM_APPEND(evidence->witness.digest,32);
    body[offset++]=profile;
    CME_TRANSFORM_APPEND(approval->sourceDigest,32); CME_TRANSFORM_APPEND(approval->candidateDigest,32);
    CME_TRANSFORM_APPEND(approval->registrationEvidenceDigest,32);
    body[offset++]=(unsigned char)name; CME_TRANSFORM_APPEND(approval->destinationMap,name);
#undef CME_TRANSFORM_APPEND
    if (!EVP_Digest(body,offset,requestDigest,&written,EVP_sha256(),NULL) || written!=32) return(1);
    *length=offset; return(0);
}

static int cmeTransformSign(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *approval, const cmeContextCopyEvidence *evidence,
    const unsigned char requestDigest[32], unsigned char signature[32])
{
    int result=cmeContextCopyTargetCheck(manager,target);
    if (!result) result=cmeContextManagerColumnTransformSign(manager,&evidence->registry,&evidence->catalog,
        approval->destinationMap,requestDigest,signature);
    if (!result) result=cmeContextCopyTargetCheck(manager,target);
    if (result) memset(signature,0,32);
    return(result);
}

int cmeContextColumnTransformPrepare(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *approval,
    const unsigned char *source, size_t sourceLength, const char *sourceKey,
    const unsigned char *image, size_t imageLength, const unsigned char *password, size_t passwordLength,
    cmeContextV2Buffer *receipt, unsigned char receiptDigest[32])
{
    cmeContextCopyEvidence evidence={0};
    cmeContextV2Buffer candidate={0};
    unsigned char body[cmeContextColumnTransformMaxBytes],request[32],signature[32],digest[32];
    unsigned int written=0;
    size_t length=0;
    int result=1;
    if (receipt) memset(receipt,0,sizeof(*receipt));
    if (receiptDigest) memset(receiptDigest,0,32);
    if (!receipt || !receiptDigest || !manager || !target) goto done;
    result=cmeTransformBody(manager,target,approval,body,&length,&evidence,request); if (result) goto done;
    result=cmeContextColumnTransformCheck(manager,target,source,sourceLength,approval->sourceDigest,sourceKey,
        approval->sourceProfile,image,imageLength,approval->candidateDigest,password,passwordLength);
    if (result) goto done;
    cmeTransformCheckpoint("after-compare");
    result=cmeTransformSign(manager,target,approval,&evidence,request,signature); if (result) goto done;
    cmeTransformCheckpoint("after-sign");
    result=1;
    candidate.bytes=malloc(length+32+1); if (!candidate.bytes) goto done;
    candidate.length=length+32; memcpy(candidate.bytes,body,length); memcpy(candidate.bytes+length,signature,32);
    candidate.bytes[candidate.length]=0;
    if (!EVP_Digest(candidate.bytes,candidate.length,digest,&written,EVP_sha256(),NULL) || written!=32) goto done;
    result=cmeContextCopyTargetCheck(manager,target); if (result) goto done;
    *receipt=candidate; memset(&candidate,0,sizeof(candidate)); memcpy(receiptDigest,digest,32);
done:
    cmeContextV2BufferFree(&candidate); OPENSSL_cleanse(body,sizeof(body)); OPENSSL_cleanse(request,sizeof(request));
    OPENSSL_cleanse(signature,sizeof(signature)); OPENSSL_cleanse(digest,sizeof(digest)); return(result);
}

int cmeContextColumnTransformVerify(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *approval,
    const unsigned char *source, size_t sourceLength, const char *sourceKey,
    const unsigned char *image, size_t imageLength, const unsigned char *password, size_t passwordLength,
    const unsigned char *receipt, size_t receiptLength, const unsigned char receiptDigest[32])
{
    cmeContextCopyEvidence evidence={0};
    unsigned char body[cmeContextColumnTransformMaxBytes],request[32],signature[32],digest[32];
    unsigned int written=0;
    size_t length=0;
    int result=1;
    if (!manager || !target || !receipt || receiptLength<32 || receiptLength>cmeContextColumnTransformMaxBytes ||
        !receiptDigest || !EVP_Digest(receipt,receiptLength,digest,&written,EVP_sha256(),NULL) || written!=32 ||
        CRYPTO_memcmp(digest,receiptDigest,32)) goto done;
    result=cmeTransformBody(manager,target,approval,body,&length,&evidence,request); if (result) goto done;
    result=1;
    if (receiptLength!=length+32 || CRYPTO_memcmp(receipt,body,length)) goto done;
    result=cmeTransformSign(manager,target,approval,&evidence,request,signature); if (result) goto done;
    result=1;
    if (CRYPTO_memcmp(receipt+length,signature,32)) goto done;
    result=cmeContextColumnTransformCheck(manager,target,source,sourceLength,approval->sourceDigest,sourceKey,
        approval->sourceProfile,image,imageLength,approval->candidateDigest,password,passwordLength);
    if (!result)
    {
        cmeTransformCheckpoint("after-compare");
        result=cmeContextCopyTargetCheck(manager,target);
    }
done:
    OPENSSL_cleanse(body,sizeof(body)); OPENSSL_cleanse(request,sizeof(request));
    OPENSSL_cleanse(signature,sizeof(signature)); OPENSSL_cleanse(digest,sizeof(digest)); return(result);
}
