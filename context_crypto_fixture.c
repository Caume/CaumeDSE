/* Synthetic owner harness only; never installed or used with real secrets. */
#include "config.h"
#include "context_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/crypto.h>
#ifdef CDSE_CONTEXT_COLUMN_TESTING
#include "context_column.h"
#include <unistd.h>
#include <fcntl.h>
#endif

static int cmeFixtureHex(const char *text, unsigned char *bytes, size_t length)
{
    size_t i;
    if (!text || strlen(text)!=length*2) return(1);
    for (i=0;i<length*2;i++)
    {
        unsigned int digit;
        if (text[i]>='0' && text[i]<='9') digit=text[i]-'0';
        else if (text[i]>='a' && text[i]<='f') digit=text[i]-'a'+10;
        else return(1);
        if (!(i%2)) bytes[i/2]=(unsigned char)(digit<<4);
        else bytes[i/2]|=(unsigned char)digit;
    }
    return(0);
}

static int cmeFixtureAnchor(const char *text, cmeContextAnchor *anchor)
{
    unsigned char bytes[73];
    size_t i;
    if (cmeFixtureHex(text,bytes,73)) return(1);
    memcpy(anchor->deployment,bytes,16); memcpy(anchor->organization,bytes+16,16);
    for (i=0;i<8;i++) anchor->generation=(anchor->generation<<8)|bytes[32+i];
    anchor->minimumFormat=bytes[40]; memcpy(anchor->digest,bytes+41,32); return(0);
}

static void cmeFixturePrint(const unsigned char *bytes, size_t length)
{
    size_t i;
    for (i=0;i<length;i++) printf("%02x",bytes[i]);
}

static int cmeFixtureContract(cmeContextManager *manager, const cmeContextBinding *binding)
{
    unsigned char salt[16],zero[16]={0},password[]="fixture-v2-password",input=0;
    cmeContextV2Buffer output={0};
    int result=1;
#define CME_BAD_CALL(call) do { \
    output.bytes=(unsigned char *)1; output.length=99; memset(salt,0xa5,16); \
    if ((call)!=1 || output.bytes || output.length || memcmp(salt,zero,16)) goto done; \
} while (0)
    CME_BAD_CALL(cmeContextV2Seal(NULL,binding,"data",1,"value",password,sizeof(password)-1,&input,1,&output,salt));
    CME_BAD_CALL(cmeContextV2Seal(manager,NULL,"data",1,"value",password,sizeof(password)-1,&input,1,&output,salt));
    CME_BAD_CALL(cmeContextV2Seal(manager,binding,NULL,1,"value",password,sizeof(password)-1,&input,1,&output,salt));
    CME_BAD_CALL(cmeContextV2Seal(manager,binding,"data",1,NULL,password,sizeof(password)-1,&input,1,&output,salt));
    CME_BAD_CALL(cmeContextV2Seal(manager,binding,"data",1,"value",NULL,1,&input,1,&output,salt));
    CME_BAD_CALL(cmeContextV2Seal(manager,binding,"data",1,"value",password,0,&input,1,&output,salt));
    CME_BAD_CALL(cmeContextV2Seal(manager,binding,"data",1,"value",password,257,&input,1,&output,salt));
    CME_BAD_CALL(cmeContextV2Seal(manager,binding,"data",1,"value",password,sizeof(password)-1,NULL,1,&output,salt));
    CME_BAD_CALL(cmeContextV2Seal(manager,binding,"data",1,"value",password,sizeof(password)-1,&input,
        (size_t)cmeContextV2MaxPlaintext+1,&output,salt));
    memset(&output,0,sizeof(output)); memset(salt,0xa5,16);
    if (cmeContextV2Seal(manager,binding,"data",1,"value",password,sizeof(password)-1,&input,1,NULL,salt)!=1 ||
        memcmp(salt,zero,16)) goto done;
    output.bytes=(unsigned char *)1; output.length=99;
    if (cmeContextV2Seal(manager,binding,"data",1,"value",password,sizeof(password)-1,&input,1,&output,NULL)!=1 ||
        output.bytes || output.length) goto done;
    output.bytes=(unsigned char *)1; output.length=99;
    if (cmeContextV2Open(manager,binding,"data",1,"value",password,sizeof(password)-1,salt,&input,
        (size_t)cmeContextV2MaxPlaintext+81,&output)!=1 || output.bytes || output.length) goto done;
    if (cmeContextV2Open(manager,binding,"data",1,"value",password,sizeof(password)-1,salt,&input,1,NULL)!=1) goto done;
    output.bytes=(unsigned char *)1; output.length=99;
    if (cmeContextV2Open(manager,binding,"data",1,"value",password,sizeof(password)-1,NULL,&input,1,&output)!=1 ||
        output.bytes || output.length) goto done;
    {
        int empty=cmeContextV2Seal(manager,binding,"data",1,"value",password,sizeof(password)-1,NULL,0,&output,salt);
#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
        if (empty || !output.bytes || output.length!=80) goto done;
#else
        if (empty!=3 || output.bytes || output.length || memcmp(salt,zero,16)) goto done;
#endif
    }
    cmeContextV2BufferFree(NULL); cmeContextV2BufferFree(&output); cmeContextV2BufferFree(&output);
    result=0;
done:
    return(result);
#undef CME_BAD_CALL
}

#ifdef CDSE_CONTEXT_COLUMN_TESTING
static int cmeFixtureReadBounded(const char *path, size_t maximum, unsigned char **bytes, size_t *length)
{
    FILE *file=fopen(path,"rb");
    unsigned char *candidate=NULL;
    long size;
    int result=1;
    *bytes=NULL; *length=0;
    if (!file || fseek(file,0,SEEK_END) || (size=ftell(file))<1 || (unsigned long)size>maximum ||
        fseek(file,0,SEEK_SET) || !(candidate=malloc(size+1)) || fread(candidate,1,size,file)!=(size_t)size) goto done;
    candidate[size]=0; *bytes=candidate; candidate=NULL; *length=size; result=0;
done:
    if (file) fclose(file);
    free(candidate); return(result);
}

static int cmeFixtureExport(cmeContextManager *manager, cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *approval,
    const cmeContextColumnRegistrationInputs *inputs, int verify, int argc, char **argv,
    cmeContextV2Buffer *output, unsigned char digest[32])
{
    cmeContextColumnExportArtifact entries[16]={0};
    cmeContextColumnExportInputs export={0},bad;
    unsigned char *registration=NULL,*acceptance=NULL,zero[32]={0},pin[32];
    size_t i,n,actual=0,acceptanceLength=0;
    char *end;
    int result=1;
    if (argc<4) goto done;
    n=strtoul(argv[3],&end,10);
    if (!*argv[3] || *end || n>16 || argc!=(int)(4+4*n+(verify ? 2 : 0))) goto done;
    export.companions=entries; export.count=n;
    if (cmeFixtureReadBounded(argv[0],cmeContextColumnTransformMaxBytes,&registration,&export.registrationReceiptLength) ||
        cmeFixtureHex(argv[1],export.registrationReceiptDigest,32) || cmeFixtureHex(argv[2],export.approvalDigest,32)) goto done;
    export.registrationReceipt=registration;
    for (i=0;i<n;i++)
    {
        unsigned char *source=NULL,*candidate=NULL;
        entries[i].name=argv[4+4*i];
        if (cmeFixtureReadBounded(argv[5+4*i],cmeContextColumnMaxImageBytes,&source,&entries[i].length)) goto done;
        entries[i].source=source;
        if (cmeFixtureReadBounded(argv[6+4*i],cmeContextColumnMaxImageBytes,&candidate,&actual)) goto done;
        entries[i].candidate=candidate;
        if (actual!=entries[i].length || cmeFixtureHex(argv[7+4*i],entries[i].digest,32)) goto done;
    }
    if (getenv("CDSE_CONTEXT_EXPORT_CONTRACT"))
    {
        if (cmeContextColumnExportDigest(transform,approval,entries,n,pin) || memcmp(pin,export.approvalDigest,32)) goto done;
        memset(pin,0xa5,32);
        if (cmeContextColumnExportDigest(NULL,approval,entries,n,pin)!=1 || memcmp(pin,zero,32) ||
            cmeContextColumnExportDigest(transform,NULL,entries,n,pin)!=1 || memcmp(pin,zero,32) ||
            cmeContextColumnExportDigest(transform,approval,NULL,n,pin)!=1 || memcmp(pin,zero,32) ||
            cmeContextColumnExportDigest(transform,approval,entries,4099,pin)!=1 || memcmp(pin,zero,32) ||
            cmeContextColumnExportDigest(transform,approval,entries,n,NULL)!=1) goto done;
        bad=export; bad.count=4099;
        output->bytes=(unsigned char *)1; output->length=99; memset(digest,0xa5,32);
        if (cmeContextColumnExportPrepare(manager,target,transform,approval,inputs,&bad,output,digest)!=1 ||
            output->bytes || output->length || memcmp(digest,zero,32)) { result=99; goto done; }
        output->bytes=(unsigned char *)1; output->length=99;
        if (cmeContextColumnExportPrepare(manager,target,transform,approval,inputs,NULL,output,digest)!=1 ||
            output->bytes || output->length || memcmp(digest,zero,32) ||
            cmeContextColumnExportPrepare(manager,target,transform,approval,inputs,&export,NULL,digest)!=1 ||
            memcmp(digest,zero,32)) goto done;
    }
    if (verify)
    {
        if (cmeFixtureReadBounded(argv[4+4*n],cmeContextColumnAcceptanceMaxBytes,&acceptance,&acceptanceLength) ||
            cmeFixtureHex(argv[5+4*n],digest,32)) goto done;
        result=cmeContextColumnExportVerify(manager,target,transform,approval,inputs,&export,acceptance,acceptanceLength,digest);
    }
    else
    {
        output->bytes=(unsigned char *)1; output->length=99; memset(digest,0xa5,32);
        result=cmeContextColumnExportPrepare(manager,target,transform,approval,inputs,&export,output,digest);
        if (result && (output->bytes || output->length || memcmp(digest,zero,32))) result=99;
    }
done:
    for (i=0;i<16;i++)
    {
        if (entries[i].source) OPENSSL_cleanse((void *)entries[i].source,entries[i].length);
        free((void *)entries[i].source); free((void *)entries[i].candidate);
    }
    free(registration); free(acceptance); return(result);
}

static int cmeFixtureRegistered(cmeContextManager *manager, cmeContextCopyTarget *target,
    const char *action, int argc, char **argv)
{
    cmeContextColumnTransformApproval transform={0};
    cmeContextColumnRegistrationApproval approval={0};
    cmeContextColumnRegistrationInputs inputs={0},bad;
    cmeContextV2Buffer output={0};
    unsigned char *source=NULL,*image=NULL,*before=NULL,*after=NULL,*receipt=NULL,password[256],digest[32],zero[32]={0};
    size_t receiptLength=0;
    char *end;
    int result=1,saved=-1,sink=-1,accepting=!strncmp(action,"target-export-",14),
        verify=!strcmp(action,"target-registered-verify") || !strcmp(action,"target-export-verify");
    if ((accepting ? argc<29 : argc!=(verify ? 27 : 25)) || cmeFixtureHex(argv[1],transform.sourceDigest,32) ||
        cmeFixtureHex(argv[5],transform.candidateDigest,32) || cmeFixtureHex(argv[6],transform.registrationEvidenceDigest,32) ||
        cmeFixtureHex(argv[10],approval.sourceResourcesDigest,32) || cmeFixtureHex(argv[12],approval.candidateResourcesDigest,32) ||
        strlen(argv[8])%2 || strlen(argv[8])>512) goto done;
    inputs.passwordLength=strlen(argv[8])/2; inputs.password=password;
    if (cmeFixtureHex(argv[8],password,inputs.passwordLength)) goto done;
    errno=0; approval.sourceRow=strtoll(argv[15],&end,10); if (errno || !*argv[15] || *end) goto done;
    errno=0; approval.destinationRow=strtoll(argv[16],&end,10); if (errno || !*argv[16] || *end) goto done;
    transform.sourceProfile=argv[3]; transform.destinationMap=argv[7]; inputs.sourceKey=argv[2]; inputs.registrationKey=argv[13];
    approval.metadataProfile=argv[14]; approval.sourceFile=argv[17]; approval.destinationFile=argv[18];
    approval.sourceDocument=argv[19]; approval.destinationDocument=argv[20]; approval.storageId=argv[21];
    approval.organizationResource=argv[22]; approval.columnId=argv[23]; approval.storagePath=argv[24];
    if (cmeFixtureReadBounded(argv[0],cmeContextColumnMaxBytes,&source,&inputs.sourceLength) ||
        cmeFixtureReadBounded(argv[4],cmeContextColumnMaxImageBytes,&image,&inputs.candidateLength) ||
        cmeFixtureReadBounded(argv[9],cmeContextColumnMaxBytes,&before,&inputs.sourceResourcesLength) ||
        cmeFixtureReadBounded(argv[11],cmeContextColumnMaxBytes,&after,&inputs.candidateResourcesLength)) goto done;
    inputs.source=source; inputs.candidate=image; inputs.sourceResources=before; inputs.candidateResources=after;
    if (verify && !accepting && (cmeFixtureReadBounded(argv[25],cmeContextColumnTransformMaxBytes,&receipt,&receiptLength) ||
        cmeFixtureHex(argv[26],digest,32))) goto done;
    fflush(stdout); saved=dup(STDOUT_FILENO); sink=open("/dev/null",O_WRONLY);
    if (saved<0 || sink<0 || dup2(sink,STDOUT_FILENO)<0) goto done;
    if (!verify && getenv("CDSE_CONTEXT_REGISTRATION_CONTRACT"))
    {
        if (cmeContextColumnRegistrationDigest(&transform,&approval,digest) || memcmp(digest,transform.registrationEvidenceDigest,32)) goto done;
        memset(digest,0xa5,32);
        if (cmeContextColumnRegistrationDigest(NULL,&approval,digest)!=1 || memcmp(digest,zero,32) ||
            cmeContextColumnRegistrationDigest(&transform,NULL,digest)!=1 || memcmp(digest,zero,32) ||
            cmeContextColumnRegistrationDigest(&transform,&approval,NULL)!=1) goto done;
#define CME_REGISTER_BAD(t,a,in) do { \
    output.bytes=(unsigned char *)1; output.length=99; memset(digest,0xa5,32); \
    if (cmeContextColumnRegisteredPrepare(manager,target,t,a,in,&output,digest)!=1 || output.bytes || output.length || memcmp(digest,zero,32)) \
    { result=99; goto done; } \
} while (0)
        CME_REGISTER_BAD(NULL,&approval,&inputs); CME_REGISTER_BAD(&transform,NULL,&inputs); CME_REGISTER_BAD(&transform,&approval,NULL);
        bad=inputs; bad.sourceResourcesLength=cmeContextColumnMaxBytes+1; CME_REGISTER_BAD(&transform,&approval,&bad);
        bad=inputs; bad.candidateResources=NULL; CME_REGISTER_BAD(&transform,&approval,&bad);
        bad=inputs; bad.registrationKey=NULL; CME_REGISTER_BAD(&transform,&approval,&bad);
#undef CME_REGISTER_BAD
        memset(digest,0xa5,32);
        if (cmeContextColumnRegisteredPrepare(manager,target,&transform,&approval,&inputs,NULL,digest)!=1 || memcmp(digest,zero,32)) goto done;
        output.bytes=(unsigned char *)1; output.length=99;
        if (cmeContextColumnRegisteredPrepare(manager,target,&transform,&approval,&inputs,&output,NULL)!=1 || output.bytes || output.length) goto done;
    }
    if (accepting) result=cmeFixtureExport(manager,target,&transform,&approval,&inputs,verify,argc-25,argv+25,&output,digest);
    else if (verify) result=cmeContextColumnRegisteredVerify(manager,target,&transform,&approval,&inputs,receipt,receiptLength,digest);
    else
    {
        output.bytes=(unsigned char *)1; output.length=99; memset(digest,0xa5,32);
        result=cmeContextColumnRegisteredPrepare(manager,target,&transform,&approval,&inputs,&output,digest);
        if (result && (output.bytes || output.length || memcmp(digest,zero,32))) result=99;
    }
    fflush(stdout); if (dup2(saved,STDOUT_FILENO)<0) _exit(89);
    close(saved); saved=-1; close(sink); sink=-1;
    if (!result)
    {
        if (verify) puts(accepting ? "export-verified" : "registered-verified");
        else { cmeFixturePrint(digest,32); putchar(' '); cmeFixturePrint(output.bytes,output.length); putchar('\n'); }
    }
done:
    if (saved>=0) { fflush(stdout); if (dup2(saved,STDOUT_FILENO)<0) _exit(89); close(saved); }
    if (sink>=0) close(sink);
    if (output.bytes!=(unsigned char *)1) cmeContextV2BufferFree(&output);
    if (source) OPENSSL_cleanse(source,inputs.sourceLength);
    if (image) OPENSSL_cleanse(image,inputs.candidateLength);
    if (before) OPENSSL_cleanse(before,inputs.sourceResourcesLength);
    if (after) OPENSSL_cleanse(after,inputs.candidateResourcesLength);
    free(source); free(image); free(before); free(after); free(receipt); OPENSSL_cleanse(password,sizeof(password)); return(result);
}

static int cmeFixtureTransform(cmeContextManager *manager, cmeContextCopyTarget *target,
    const char *action, int argc, char **argv)
{
    cmeContextColumnTransformApproval approval={0};
    cmeContextV2Buffer output={0};
    cmeContextCopyEvidence evidence={0},zeroEvidence={0};
    unsigned char *source=NULL,*image=NULL,*receipt=NULL,password[256],digest[32],zero[32]={0};
    size_t sourceLength=0,imageLength=0,receiptLength=0,passwordLength;
    int verify=!strcmp(action,"target-transform-verify"),saved=-1,sink=-1,result=1;
    if (argc!=(verify ? 11 : 9) || cmeFixtureHex(argv[1],approval.sourceDigest,32) ||
        cmeFixtureHex(argv[5],approval.candidateDigest,32) || cmeFixtureHex(argv[6],approval.registrationEvidenceDigest,32) ||
        strlen(argv[8])%2 || strlen(argv[8])>512) goto done;
    approval.sourceProfile=argv[3]; approval.destinationMap=argv[7]; passwordLength=strlen(argv[8])/2;
    if (cmeFixtureHex(argv[8],password,passwordLength) ||
        cmeFixtureReadBounded(argv[0],cmeContextColumnMaxBytes,&source,&sourceLength) ||
        cmeFixtureReadBounded(argv[4],cmeContextColumnMaxImageBytes,&image,&imageLength)) goto done;
    if (verify && (cmeFixtureReadBounded(argv[9],cmeContextColumnTransformMaxBytes,&receipt,&receiptLength) ||
        cmeFixtureHex(argv[10],digest,32))) goto done;
    fflush(stdout); saved=dup(STDOUT_FILENO); sink=open("/dev/null",O_WRONLY);
    if (saved<0 || sink<0 || dup2(sink,STDOUT_FILENO)<0) goto done;
    if (getenv("CDSE_CONTEXT_TRANSFORM_CONTRACT"))
    {
        memset(&evidence,0xa5,sizeof(evidence));
        if (cmeContextCopyTargetEvidence(manager,NULL,&evidence)!=1 || memcmp(&evidence,&zeroEvidence,sizeof(evidence)) ||
            cmeContextCopyTargetEvidence(manager,target,NULL)!=1 || cmeContextCopyTargetEvidence(manager,target,&evidence)) goto done;
#define CME_TRANSFORM_BAD(call) do { \
        output.bytes=(unsigned char *)1; output.length=99; memset(digest,0xa5,32); \
        if ((call)!=1 || output.bytes || output.length || memcmp(digest,zero,32)) { result=99; goto done; } \
} while (0)
        CME_TRANSFORM_BAD(cmeContextColumnTransformPrepare(NULL,target,&approval,source,sourceLength,argv[2],image,imageLength,password,passwordLength,&output,digest));
        CME_TRANSFORM_BAD(cmeContextColumnTransformPrepare(manager,NULL,&approval,source,sourceLength,argv[2],image,imageLength,password,passwordLength,&output,digest));
        CME_TRANSFORM_BAD(cmeContextColumnTransformPrepare(manager,target,NULL,source,sourceLength,argv[2],image,imageLength,password,passwordLength,&output,digest));
        CME_TRANSFORM_BAD(cmeContextColumnTransformPrepare(manager,target,&approval,NULL,sourceLength,argv[2],image,imageLength,password,passwordLength,&output,digest));
        CME_TRANSFORM_BAD(cmeContextColumnTransformPrepare(manager,target,&approval,source,cmeContextColumnMaxBytes+1,argv[2],image,imageLength,password,passwordLength,&output,digest));
        CME_TRANSFORM_BAD(cmeContextColumnTransformPrepare(manager,target,&approval,source,sourceLength,argv[2],image,cmeContextColumnMaxImageBytes+1,password,passwordLength,&output,digest));
        CME_TRANSFORM_BAD(cmeContextColumnTransformPrepare(manager,target,&approval,source,sourceLength,argv[2],image,imageLength,NULL,passwordLength,&output,digest));
        CME_TRANSFORM_BAD(cmeContextColumnTransformPrepare(manager,target,&approval,source,sourceLength,argv[2],image,imageLength,password,257,&output,digest));
#undef CME_TRANSFORM_BAD
        memset(digest,0xa5,32);
        if (cmeContextColumnTransformPrepare(manager,target,&approval,source,sourceLength,argv[2],image,imageLength,password,passwordLength,NULL,digest)!=1 || memcmp(digest,zero,32)) goto done;
        output.bytes=(unsigned char *)1; output.length=99;
        if (cmeContextColumnTransformPrepare(manager,target,&approval,source,sourceLength,argv[2],image,imageLength,password,passwordLength,&output,NULL)!=1 || output.bytes || output.length) goto done;
        memset(digest,0xa5,32);
        if (cmeContextManagerColumnTransformSign(NULL,&evidence.registry,&evidence.catalog,approval.destinationMap,approval.sourceDigest,digest)!=1 ||
            memcmp(digest,zero,32) || cmeContextColumnTransformVerify(manager,target,&approval,source,sourceLength,argv[2],image,imageLength,
            password,passwordLength,NULL,32,zero)!=1 || cmeContextColumnTransformVerify(manager,target,&approval,source,sourceLength,argv[2],image,imageLength,
            password,passwordLength,zero,cmeContextColumnTransformMaxBytes+1,zero)!=1) goto done;
    }
    if (verify) result=cmeContextColumnTransformVerify(manager,target,&approval,source,sourceLength,argv[2],image,imageLength,
        password,passwordLength,receipt,receiptLength,digest);
    else
    {
        output.bytes=(unsigned char *)1; output.length=99; memset(digest,0xa5,32);
        result=cmeContextColumnTransformPrepare(manager,target,&approval,source,sourceLength,argv[2],image,imageLength,
            password,passwordLength,&output,digest);
        if (result && (output.bytes || output.length || memcmp(digest,zero,32))) result=99;
    }
    fflush(stdout); if (dup2(saved,STDOUT_FILENO)<0) _exit(89);
    close(saved); saved=-1; close(sink); sink=-1;
    if (!result)
    {
        if (verify) puts("verified");
        else { cmeFixturePrint(digest,32); putchar(' '); cmeFixturePrint(output.bytes,output.length); putchar('\n'); }
    }
done:
    if (saved>=0) { fflush(stdout); if (dup2(saved,STDOUT_FILENO)<0) _exit(89); close(saved); }
    if (sink>=0) close(sink);
    if (output.bytes!=(unsigned char *)1) cmeContextV2BufferFree(&output);
    if (source) OPENSSL_cleanse(source,sourceLength);
    if (image) OPENSSL_cleanse(image,imageLength);
    free(source); free(image); free(receipt); OPENSSL_cleanse(password,sizeof(password)); return(result);
}

static int cmeFixtureImageContracts(cmeContextManager *manager, cmeContextCopyTarget *target,
    cmeContextColumnStage *stage, const unsigned char *image, size_t length, const unsigned char digest[32],
    const unsigned char *password, size_t passwordLength)
{
    cmeContextV2Buffer output={0};
    cmeContextColumnStage *decoded=NULL;
    unsigned char tag[32],zero[32]={0};
#define CME_IMAGE_BAD_SEAL(call) do { \
    output.bytes=(unsigned char *)1; output.length=99; memset(tag,0xa5,32); \
    if ((call)!=1 || output.bytes || output.length || memcmp(tag,zero,32)) return(99); \
} while (0)
    CME_IMAGE_BAD_SEAL(cmeContextColumnStageSerialize(NULL,target,stage,password,passwordLength,&output,tag));
    CME_IMAGE_BAD_SEAL(cmeContextColumnStageSerialize(manager,NULL,stage,password,passwordLength,&output,tag));
    CME_IMAGE_BAD_SEAL(cmeContextColumnStageSerialize(manager,target,NULL,password,passwordLength,&output,tag));
    CME_IMAGE_BAD_SEAL(cmeContextColumnStageSerialize(manager,target,stage,NULL,passwordLength,&output,tag));
    CME_IMAGE_BAD_SEAL(cmeContextColumnStageSerialize(manager,target,stage,password,0,&output,tag));
    CME_IMAGE_BAD_SEAL(cmeContextColumnStageSerialize(manager,target,stage,password,257,&output,tag));
    memset(tag,0xa5,32);
    if (cmeContextColumnStageSerialize(manager,target,stage,password,passwordLength,NULL,tag)!=1 || memcmp(tag,zero,32)) return(99);
    output.bytes=(unsigned char *)1; output.length=99;
    if (cmeContextColumnStageSerialize(manager,target,stage,password,passwordLength,&output,NULL)!=1 || output.bytes || output.length) return(99);
#undef CME_IMAGE_BAD_SEAL
#define CME_IMAGE_BAD_OPEN(call) do { \
    decoded=(cmeContextColumnStage *)1; \
    if ((call)!=1 || decoded) return(99); \
} while (0)
    CME_IMAGE_BAD_OPEN(cmeContextColumnStageDeserialize(NULL,target,image,length,digest,password,passwordLength,&decoded));
    CME_IMAGE_BAD_OPEN(cmeContextColumnStageDeserialize(manager,NULL,image,length,digest,password,passwordLength,&decoded));
    CME_IMAGE_BAD_OPEN(cmeContextColumnStageDeserialize(manager,target,NULL,length,digest,password,passwordLength,&decoded));
    CME_IMAGE_BAD_OPEN(cmeContextColumnStageDeserialize(manager,target,image,4095,digest,password,passwordLength,&decoded));
    CME_IMAGE_BAD_OPEN(cmeContextColumnStageDeserialize(manager,target,image,cmeContextColumnMaxImageBytes+1,digest,password,passwordLength,&decoded));
    CME_IMAGE_BAD_OPEN(cmeContextColumnStageDeserialize(manager,target,image,length,NULL,password,passwordLength,&decoded));
    CME_IMAGE_BAD_OPEN(cmeContextColumnStageDeserialize(manager,target,image,length,digest,NULL,passwordLength,&decoded));
    CME_IMAGE_BAD_OPEN(cmeContextColumnStageDeserialize(manager,target,image,length,digest,password,0,&decoded));
    CME_IMAGE_BAD_OPEN(cmeContextColumnStageDeserialize(manager,target,image,length,digest,password,257,&decoded));
    if (cmeContextColumnStageDeserialize(manager,target,image,length,digest,password,passwordLength,NULL)!=1) return(99);
#undef CME_IMAGE_BAD_OPEN
    return(0);
}

static int cmeFixtureColumn(cmeContextManager *manager, cmeContextCopyTarget *target, const char *action, int argc, char **argv)
{
    FILE *file=NULL;
    cmeContextColumnStage *stage=NULL;
    cmeContextV2Buffer container={0};
    unsigned char *image=NULL,password[256],digest[32];
    size_t length=0,passwordLength=0,i;
    long size;
    int result=1,saved=-1,sink=-1,import=!strcmp(action,"target-column-import"),export=!strcmp(action,"target-column-export");
    int passwordIndex=import ? 2 : 4;
    if (argc!=(import ? 3 : 5) || cmeFixtureHex(argv[1],digest,32) || strlen(argv[passwordIndex])%2 ||
        strlen(argv[passwordIndex])>512) goto done;
    passwordLength=strlen(argv[passwordIndex])/2;
    if (cmeFixtureHex(argv[passwordIndex],password,passwordLength)) goto done;
    file=fopen(argv[0],"rb");
    if (!file || fseek(file,0,SEEK_END) || (size=ftell(file))<1 ||
        (unsigned long)size>(import ? cmeContextColumnMaxImageBytes : cmeContextColumnMaxBytes) ||
        fseek(file,0,SEEK_SET) || !(image=malloc(size))) goto done;
    length=size; if (fread(image,1,length,file)!=length) goto done;
    fclose(file); file=NULL;
    /* Legacy DEBUG helpers log to stdout. Retain only the final synthetic cells. */
    fflush(stdout); saved=dup(STDOUT_FILENO); sink=open("/dev/null",O_WRONLY);
    if (saved<0 || sink<0 || dup2(sink,STDOUT_FILENO)<0) goto done;
    if (!import && getenv("CDSE_CONTEXT_COLUMN_CONTRACT"))
    {
        cmeContextMap *sourceMap=(cmeContextMap *)1;
        cmeContextBinding *sourceBinding=(cmeContextBinding *)1;
#define CME_COLUMN_BAD(m,t,s,n,d,k,p,w,wn) do { \
        stage=(cmeContextColumnStage *)1; \
        if (cmeContextColumnStageCreate(m,t,s,n,d,k,p,w,wn,&stage)!=1 || stage) { stage=NULL; result=99; goto done; } \
    } while (0)
        CME_COLUMN_BAD(NULL,target,image,length,digest,argv[2],argv[3],password,passwordLength);
        CME_COLUMN_BAD(manager,NULL,image,length,digest,argv[2],argv[3],password,passwordLength);
        CME_COLUMN_BAD(manager,target,NULL,length,digest,argv[2],argv[3],password,passwordLength);
        CME_COLUMN_BAD(manager,target,image,99,digest,argv[2],argv[3],password,passwordLength);
        CME_COLUMN_BAD(manager,target,image,cmeContextColumnMaxBytes+1,digest,argv[2],argv[3],password,passwordLength);
        CME_COLUMN_BAD(manager,target,image,length,NULL,argv[2],argv[3],password,passwordLength);
        CME_COLUMN_BAD(manager,target,image,length,digest,NULL,argv[3],password,passwordLength);
        CME_COLUMN_BAD(manager,target,image,length,digest,argv[2],NULL,password,passwordLength);
        CME_COLUMN_BAD(manager,target,image,length,digest,argv[2],argv[3],NULL,passwordLength);
        CME_COLUMN_BAD(manager,target,image,length,digest,argv[2],argv[3],password,257);
#undef CME_COLUMN_BAD
        if (cmeContextColumnStageCreate(manager,target,image,length,digest,argv[2],argv[3],password,passwordLength,NULL)!=1 ||
            cmeContextCopyTargetSource(manager,NULL,&sourceMap,&sourceBinding)!=1 || sourceMap || sourceBinding)
        { result=99; goto done; }
        cmeContextColumnStageFree(&stage); cmeContextColumnStageFree(&stage);
    }
    stage=(cmeContextColumnStage *)1;
    if (import) result=cmeContextColumnStageDeserialize(manager,target,image,length,digest,password,passwordLength,&stage);
    else result=cmeContextColumnStageCreate(manager,target,image,length,digest,argv[2],argv[3],password,passwordLength,&stage);
    if (!result && export && getenv("CDSE_CONTEXT_COLUMN_IMAGE_CONTRACT"))
        result=cmeFixtureImageContracts(manager,target,stage,image,length,digest,password,passwordLength);
    if (!result && export)
    {
        if (getenv("CDSE_CONTEXT_COLUMN_SERIALIZE_NO_RNG")) setenv("CDSE_CONTEXT_CRYPTO_RNG_FAIL","all",1);
        memset(digest,0xa5,32); container.bytes=(unsigned char *)1; container.length=99;
        result=cmeContextColumnStageSerialize(manager,target,stage,password,passwordLength,&container,digest);
        if (result && (container.bytes || container.length || memcmp(digest,(unsigned char[32]){0},32))) result=99;
    }
    fflush(stdout); if (dup2(saved,STDOUT_FILENO)<0) _exit(89);
    close(saved); saved=-1; close(sink); sink=-1;
    if (result) { if (stage==(cmeContextColumnStage *)1 || (!export && stage)) { stage=NULL; result=99; } goto done; }
    free(image); image=NULL; /* Result owns its frames, not the source image. */
    if (export)
    {
        cmeContextColumnStageFree(&stage);
        cmeFixturePrint(digest,32); putchar(' '); cmeFixturePrint(container.bytes,container.length); putchar('\n');
        goto done;
    }
    if (!cmeContextColumnStageCount(stage) || cmeContextColumnStageCount(NULL) ||
        cmeContextColumnStageCell(NULL,0) || cmeContextColumnStageCell(stage,cmeContextColumnStageCount(stage)))
    { result=99; goto done; }
    for (i=0;i<cmeContextColumnStageCount(stage);i++)
    {
        const cmeContextColumnCell *cell=cmeContextColumnStageCell(stage,i);
        printf("%s %lld %s ",cell->table,(long long)cell->row,cell->field);
        cmeFixturePrint(cell->salt,16); putchar(' '); cmeFixturePrint(cell->frame.bytes,cell->frame.length); putchar('\n');
    }
done:
    if (file) fclose(file);
    if (saved>=0) { fflush(stdout); if (dup2(saved,STDOUT_FILENO)<0) _exit(89); close(saved); }
    if (sink>=0) close(sink);
    if (stage!=(cmeContextColumnStage *)1) cmeContextColumnStageFree(&stage);
    cmeContextColumnStageFree(NULL); cmeContextColumnStageFree(&stage);
    if (container.bytes!=(unsigned char *)1) cmeContextV2BufferFree(&container);
    free(image); OPENSSL_cleanse(password,sizeof(password)); return(result);
}
#endif

static int cmeFixtureTarget(int argc, char **argv)
{
    cmeContextManager *manager=NULL;
    cmeContextWitness *witness=NULL;
    cmeContextCopyTarget *target=NULL;
    cmeContextBinding *core=NULL;
    cmeContextAnchor original={0},committed={0};
    cmeContextMapAnchor catalog={0};
    cmeContextWitnessAnchor retained={0};
    cmeContextV2Buffer output={0};
    unsigned char key[32],witnessKey[32],deployment[16],organization[16],bytes[40],digest[32],salt[16],zero[16]={0};
    unsigned char *plan=NULL,*password=NULL,*input=NULL;
    size_t length=0,passwordLength=0,planLength=0,count,offset,i;
    int result=1,seal;
    int64_t row;
    char *end;
    FILE *file=NULL;
    long size;
    if (argc<13 || cmeFixtureHex(argv[3],deployment,16) || cmeFixtureHex(argv[4],organization,16) ||
        cmeFixtureAnchor(argv[5],&original) || cmeFixtureHex(argv[6],bytes,40)) goto done;
    for (i=0;i<8;i++) catalog.revision=(catalog.revision<<8)|bytes[i];
    memcpy(catalog.digest,bytes+8,32);
    if (cmeFixtureHex(argv[8],bytes,40) || cmeFixtureHex(argv[10],digest,32)) goto done;
    for (i=0;i<8;i++) retained.revision=(retained.revision<<8)|bytes[i];
    memcpy(retained.digest,bytes+8,32);
    errno=0; count=strtoul(argv[12],&end,10);
    if (errno || *end || !*argv[12] || count>cmeContextRegistryMaxEntries || count>(size_t)argc-13) goto done;
    offset=13+count; memset(key,'k',32); memset(witnessKey,'w',32);
    file=fopen(argv[9],"rb");
    if (!file || fseek(file,0,SEEK_END) || (size=ftell(file))<1 ||
        (unsigned long)size>cmeContextCopyPlanMaxBytes || fseek(file,0,SEEK_SET)) goto done;
    planLength=(size_t)size; plan=malloc(planLength);
    if (!plan || fread(plan,1,planLength,file)!=planLength) goto done;
    fclose(file); file=NULL;
    if (cmeContextManagerOpen(argv[1],0,key,deployment,organization,&manager) ||
        cmeContextWitnessOpen(argv[7],0,witnessKey,deployment,organization,&original,&catalog,&witness)) goto done;
    target=(cmeContextCopyTarget *)1;
    result=cmeContextWitnessCopyTargetBind(manager,witness,&retained,plan,planLength,digest,&original,&catalog,
        argv[11],(const char *const *)(argv+13),count,&target);
    if (result) { if (target) result=99; goto done; }
    if (!target) { result=99; goto done; }
    result=1;
    if (!strcmp(argv[2],"target-bind") && (size_t)argc==offset)
    {
        result=cmeContextCopyTargetCheck(manager,target);
        if (!result) puts("bound");
        goto done;
    }
    if (!strcmp(argv[2],"target-contract") && (size_t)argc==offset)
    {
        cmeStorageContext context,empty={0};
        unsigned int floor=99;
        unsigned char plain=0;
        memset(&context,0xff,sizeof(context));
        if (cmeContextCopyTargetLookup(NULL,"data",10,"value",&context,&floor)!=1 || floor ||
            memcmp(&context,&empty,sizeof(context)) || cmeContextCopyTargetCheck(NULL,target)!=1 ||
            cmeContextCopyTargetCheck(manager,NULL)!=1) goto done;
        if (cmeContextCopyTargetLookup(target,"data",10,"value",&context,&floor) || floor!=original.minimumFormat) goto done;
        if (cmeContextManagerCopyPlanBind(manager,plan,planLength,digest,&original,&catalog,argv[11],
            (const char *const *)(argv+13),count,&core,&committed) ||
            cmeContextBindingCheckMapped(manager,core)!=1 || cmeContextBindingCheckCopyTarget(manager,core)) goto done;
        output.bytes=(unsigned char *)1; output.length=99; memset(salt,0xa5,16);
        if (cmeContextV2Seal(manager,core,"data",10,"value",&plain,1,&plain,1,&output,salt)!=1 ||
            output.bytes || output.length || memcmp(salt,zero,16)) goto done;
        output.bytes=(unsigned char *)1; output.length=99; memset(salt,0xa5,16);
        if (cmeContextV2SealCopyTarget(manager,NULL,"data",10,"value",&plain,1,&plain,1,&output,salt)!=1 ||
            output.bytes || output.length || memcmp(salt,zero,16)) goto done;
        output.bytes=(unsigned char *)1; output.length=99;
        if (cmeContextV2OpenCopyTarget(manager,NULL,"data",10,"value",&plain,1,salt,&plain,1,&output)!=1 ||
            output.bytes || output.length) goto done;
        output.bytes=(unsigned char *)1; output.length=99; memset(salt,0xa5,16);
        if (cmeContextV2SealCopyTarget(manager,target,"data",10,"value",NULL,1,&plain,1,&output,salt)!=1 ||
            output.bytes || output.length || memcmp(salt,zero,16)) goto done;
        cmeContextBindingFree(&core);
        committed=original;
        if (cmeContextManagerCopyPlanBind(manager,plan,planLength,digest,&committed,&catalog,argv[11],
            (const char *const *)(argv+13),count,&core,&committed) ||
            cmeContextBindingCheckCopyTarget(manager,core)) goto done;
        cmeContextCopyTargetFree(NULL);
        cmeContextCopyTargetFree(&target); cmeContextCopyTargetFree(&target);
        puts("contract"); result=0; goto done;
    }
#ifdef CDSE_CONTEXT_COLUMN_TESTING
    if (!strcmp(argv[2],"target-registered-prepare") || !strcmp(argv[2],"target-registered-verify") ||
        !strcmp(argv[2],"target-export-prepare") || !strcmp(argv[2],"target-export-verify"))
    { result=cmeFixtureRegistered(manager,target,argv[2],argc-offset,argv+offset); goto done; }
    if (!strcmp(argv[2],"target-transform-prepare") || !strcmp(argv[2],"target-transform-verify"))
    { result=cmeFixtureTransform(manager,target,argv[2],argc-offset,argv+offset); goto done; }
    if (!strcmp(argv[2],"target-column") || !strcmp(argv[2],"target-column-export") || !strcmp(argv[2],"target-column-import"))
    { result=cmeFixtureColumn(manager,target,argv[2],argc-offset,argv+offset); goto done; }
#endif
    seal=!strcmp(argv[2],"target-seal");
    if (seal ? (size_t)argc!=offset+5 : (strcmp(argv[2],"target-open") || (size_t)argc!=offset+6)) goto done;
    errno=0; row=strtoll(argv[offset+1],&end,10); if (errno || *end || !*argv[offset+1]) goto done;
    if (strlen(argv[offset+3])%2 || strlen(argv[offset+3])>512) goto done;
    passwordLength=strlen(argv[offset+3])/2; password=malloc(passwordLength+1);
    length=strlen(argv[offset+(seal ? 4 : 5)]);
    if (length%2 || length>2*(cmeContextV2MaxPlaintext+80)) goto done;
    length/=2; input=malloc(length+1);
    if (!password || !input || cmeFixtureHex(argv[offset+3],password,passwordLength) ||
        cmeFixtureHex(argv[offset+(seal ? 4 : 5)],input,length)) goto done;
    if (!seal && cmeFixtureHex(argv[offset+4],salt,16)) goto done;
    /* Binding owns the decoded slots: original plan bytes are not needed now. */
    free(plan); plan=NULL;
    output.bytes=(unsigned char *)1; output.length=99;
    if (seal)
    {
        memset(salt,0xa5,16);
        result=cmeContextV2SealCopyTarget(manager,target,argv[offset],row,argv[offset+2],password,passwordLength,
            input,length,&output,salt);
    }
    else result=cmeContextV2OpenCopyTarget(manager,target,argv[offset],row,argv[offset+2],password,passwordLength,
        salt,input,length,&output);
    if (result)
    {
        if (output.bytes || output.length || (seal && memcmp(salt,zero,16))) result=99;
        goto done;
    }
    if (seal) { cmeFixturePrint(salt,16); putchar(' '); }
    cmeFixturePrint(output.bytes,output.length); putchar('\n');
done:
    if (file) fclose(file);
    free(plan);
    if (password) { OPENSSL_cleanse(password,passwordLength); free(password); }
    if (input) { OPENSSL_cleanse(input,length); free(input); }
    if (output.bytes!=(unsigned char *)1) cmeContextV2BufferFree(&output);
    cmeContextBindingFree(&core);
    if (target!=(cmeContextCopyTarget *)1) cmeContextCopyTargetFree(&target);
    cmeContextWitnessClose(&witness); cmeContextManagerClose(&manager);
    OPENSSL_cleanse(key,sizeof(key)); OPENSSL_cleanse(witnessKey,sizeof(witnessKey));
    return(result);
}

int main(int argc, char **argv)
{
    if (argc>2 && !strncmp(argv[2],"target-",7)) return(cmeFixtureTarget(argc,argv));
    cmeContextManager *manager=NULL;
    cmeContextBinding *binding=NULL;
    cmeContextMap *map=NULL;
    cmeContextAnchor registry={0};
    cmeContextMapAnchor catalog={0};
    cmeContextV2Buffer output={0};
    unsigned char key[32],deployment[16],organization[16],bytes[40],salt[16],zero[16]={0};
    unsigned char *password=NULL,*input=NULL;
    size_t passwordLength=0,length=0,i;
    int result=1,seal;
    int64_t row;
    char *end;
    if (argc==2 && !strcmp(argv[1],"available"))
    {
#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
        puts("1");
#else
        puts("0");
#endif
        return(0);
    }
    if (argc<8 || cmeFixtureHex(argv[3],deployment,16) || cmeFixtureHex(argv[4],organization,16) ||
        cmeFixtureAnchor(argv[5],&registry) || cmeFixtureHex(argv[6],bytes,40)) goto done;
    for (i=0;i<8;i++) catalog.revision=(catalog.revision<<8)|bytes[i];
    memcpy(catalog.digest,bytes+8,32); memset(key,'k',32);
    if (cmeContextManagerOpen(argv[1],0,key,deployment,organization,&manager)) goto done;
    if (!strcmp(argv[2],"raw-seal"))
    {
        if (cmeContextManagerMapRead(manager,argv[7],&registry,&catalog,&map) ||
            cmeContextManagerBind(manager,map->resource,map->role,map->slots,map->count,&registry,&binding)) goto done;
    }
    else
    {
        result=cmeContextManagerMapBind(manager,argv[7],&registry,&catalog,&binding); if (result) goto done;
    }
    result=1;
    if (!strcmp(argv[2],"contract") && argc==8)
    { result=cmeFixtureContract(manager,binding); goto done; }
    seal=!strcmp(argv[2],"seal") || !strcmp(argv[2],"raw-seal");
    if (seal ? argc!=13 : (strcmp(argv[2],"open") || argc!=14)) goto done;
    errno=0; row=strtoll(argv[9],&end,10); if (errno || *end || !*argv[9]) goto done;
    if (strlen(argv[11])%2 || strlen(argv[11])>512) goto done;
    passwordLength=strlen(argv[11])/2; password=malloc(passwordLength+1);
    length=strlen(argv[seal ? 12 : 13]); if (length%2 || length>2*(cmeContextV2MaxPlaintext+80)) goto done;
    length/=2; input=malloc(length+1);
    if (!password || !input || cmeFixtureHex(argv[11],password,passwordLength) ||
        cmeFixtureHex(argv[seal ? 12 : 13],input,length)) goto done;
    if (!seal && cmeFixtureHex(argv[12],salt,16)) goto done;
    output.bytes=(unsigned char *)1; output.length=99;
    if (seal)
    {
        memset(salt,0xa5,16);
        result=cmeContextV2Seal(manager,binding,argv[8],row,argv[10],password,passwordLength,input,length,&output,salt);
    }
    else result=cmeContextV2Open(manager,binding,argv[8],row,argv[10],password,passwordLength,salt,input,length,&output);
    if (result)
    {
        if (output.bytes || output.length || (seal && memcmp(salt,zero,16))) result=99;
        goto done;
    }
    if (seal) { cmeFixturePrint(salt,16); putchar(' '); }
    cmeFixturePrint(output.bytes,output.length); putchar('\n');
done:
    if (output.bytes!=(unsigned char *)1) cmeContextV2BufferFree(&output);
    if (password) { OPENSSL_cleanse(password,passwordLength); free(password); }
    if (input) { OPENSSL_cleanse(input,length); free(input); }
    OPENSSL_cleanse(key,sizeof(key));
    cmeContextBindingFree(&binding); cmeContextMapFree(&map); cmeContextManagerClose(&manager);
    return(result);
}
