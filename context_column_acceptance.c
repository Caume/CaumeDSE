/* Retained complete supplied-export acceptance; no physical publication. */
#include "common.h"
#include "context_column.h"
#include "context_column_internal.h"

static void cmeAcceptanceCheckpoint(void)
{
#ifdef CDSE_CONTEXT_COLUMN_TESTING
    if (getenv("CDSE_CONTEXT_EXPORT_PAUSE"))
    {
        const char *ready=getenv("CDSE_CONTEXT_EXPORT_READY_FD"),*resume=getenv("CDSE_CONTEXT_EXPORT_RESUME_FD");
        char byte;
        if (!ready || !resume || atoi(ready)<3 || atoi(resume)<3 ||
            write(atoi(ready),"1",1)!=1 || read(atoi(resume),&byte,1)!=1) _exit(87);
    }
#endif
}

static int cmeAcceptanceBuild(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnRegistrationInputs *inputs, const cmeContextColumnExportInputs *export,
    const unsigned char *expected, size_t expectedLength,
    cmeContextV2Buffer *receipt, unsigned char receiptDigest[32])
{
    static const unsigned char domain[]="CDSE-HKX-COLUMN-ACCEPTANCE-v1";
    cmeContextCopyEvidence evidence={0};
    cmeContextV2Buffer candidate={0};
    unsigned char body[cmeContextColumnAcceptanceMaxBytes],request[32],signature[32],digest[32];
    unsigned int written=0;
    size_t length=0,n;
    int result=1;
    if (!manager || !target || !transform || !export || !export->registrationReceipt ||
        !(n=export->registrationReceiptLength) || n>cmeContextColumnTransformMaxBytes) goto done;
    result=cmeContextCopyTargetEvidence(manager,target,&evidence); if (result) goto done;
    _Static_assert(sizeof(domain)+32+2+cmeContextColumnTransformMaxBytes+32<=cmeContextColumnAcceptanceMaxBytes,"acceptance bound");
    memcpy(body,domain,sizeof(domain)); length=sizeof(domain);
    memcpy(body+length,export->approvalDigest,32); length+=32;
    body[length++]=(unsigned char)(n>>8); body[length++]=(unsigned char)n;
    memcpy(body+length,export->registrationReceipt,n); length+=n;
    result=1;
    if (!EVP_Digest(body,length,request,&written,EVP_sha256(),NULL) || written!=32) goto done;
    result=cmeContextManagerColumnAcceptanceSign(manager,&evidence.registry,&evidence.catalog,transform->destinationMap,request,signature);
    if (result) goto done;
    memcpy(body+length,signature,32); length+=32;
    result=1;
    if (expected && (expectedLength!=length || CRYPTO_memcmp(expected,body,length))) goto done;
    result=cmeContextColumnExportCheck(transform,registration,inputs,export); if (result) goto done;
    result=cmeContextColumnRegisteredVerify(manager,target,transform,registration,inputs,
        export->registrationReceipt,n,export->registrationReceiptDigest); if (result) goto done;
    cmeAcceptanceCheckpoint();
    result=1;
    candidate.bytes=malloc(length+1); if (!candidate.bytes) goto done;
    candidate.length=length; memcpy(candidate.bytes,body,length); candidate.bytes[length]=0;
    if (!EVP_Digest(body,length,digest,&written,EVP_sha256(),NULL) || written!=32) goto done;
    result=cmeContextCopyTargetCheck(manager,target); if (result) goto done;
    *receipt=candidate; memset(&candidate,0,sizeof(candidate)); memcpy(receiptDigest,digest,32);
done:
    cmeContextV2BufferFree(&candidate); OPENSSL_cleanse(body,sizeof(body)); OPENSSL_cleanse(request,sizeof(request));
    OPENSSL_cleanse(signature,sizeof(signature)); OPENSSL_cleanse(digest,sizeof(digest)); return(result);
}

int cmeContextColumnExportPrepare(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnRegistrationInputs *inputs, const cmeContextColumnExportInputs *export,
    cmeContextV2Buffer *receipt, unsigned char receiptDigest[32])
{
    if (receipt) memset(receipt,0,sizeof(*receipt));
    if (receiptDigest) memset(receiptDigest,0,32);
    if (!receipt || !receiptDigest) return(1);
    return(cmeAcceptanceBuild(manager,target,transform,registration,inputs,export,NULL,0,receipt,receiptDigest));
}

int cmeContextColumnExportVerify(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnRegistrationInputs *inputs, const cmeContextColumnExportInputs *export,
    const unsigned char *receipt, size_t receiptLength, const unsigned char receiptDigest[32])
{
    cmeContextV2Buffer expected={0};
    unsigned char digest[32];
    unsigned int written=0;
    int result=1;
    if (!receipt || receiptLength<32 || receiptLength>cmeContextColumnAcceptanceMaxBytes || !receiptDigest ||
        !EVP_Digest(receipt,receiptLength,digest,&written,EVP_sha256(),NULL) || written!=32 ||
        CRYPTO_memcmp(digest,receiptDigest,32)) goto done;
    result=cmeAcceptanceBuild(manager,target,transform,registration,inputs,export,receipt,receiptLength,&expected,digest);
    if (!result) result=cmeContextCopyTargetCheck(manager,target);
done:
    cmeContextV2BufferFree(&expected); OPENSSL_cleanse(digest,sizeof(digest)); return(result);
}
