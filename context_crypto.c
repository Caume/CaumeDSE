/* Explicit binding-aware V2 memory codec. No implicit storage dispatch. */
#include "config.h"
#include "context_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#ifdef CDSE_CONTEXT_CRYPTO_TESTING
#include <unistd.h>
#endif
#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
#include "herradura_compat.h"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#endif

void cmeContextV2BufferFree(cmeContextV2Buffer *buffer)
{
    if (!buffer) return;
    if (buffer->bytes)
    {
        OPENSSL_cleanse(buffer->bytes,buffer->length+1);
        free(buffer->bytes);
    }
    memset(buffer,0,sizeof(*buffer));
}

static void cmeContextV2Checkpoint(const char *stage)
{
#ifdef CDSE_CONTEXT_CRYPTO_TESTING
    const char *pause=getenv("CDSE_CONTEXT_CRYPTO_PAUSE");
    if (pause && !strcmp(pause,stage))
    {
        const char *selected=getenv("CDSE_CONTEXT_CRYPTO_PAUSE_HIT");
        static unsigned int hits=0;
        const char *ready=getenv("CDSE_CONTEXT_CRYPTO_READY_FD"),*resume=getenv("CDSE_CONTEXT_CRYPTO_RESUME_FD");
        char byte;
        if (selected && (!*selected || strspn(selected,"0123456789")!=strlen(selected) ||
            strlen(selected)>4 || !atoi(selected))) _exit(87);
        if (selected && ++hits!=(unsigned int)atoi(selected)) return;
        if (!ready || !resume || atoi(ready)<3 || atoi(resume)<3 ||
            write(atoi(ready),"1",1)!=1 || read(atoi(resume),&byte,1)!=1) _exit(87);
    }
#else
    (void)stage;
#endif
}

#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
static int cmeContextV2Random(unsigned char *bytes, int length)
{
#ifdef CDSE_CONTEXT_CRYPTO_TESTING
    const char *failure=getenv("CDSE_CONTEXT_CRYPTO_RNG_FAIL");
    if (failure && (!strcmp(failure,"all") || (length==16 && !strcmp(failure,"salt")) ||
        (length==32 && !strcmp(failure,"nonce")))) return(0);
#endif
    return(RAND_bytes(bytes,length)==1);
}

static int cmeContextV2Name(const char *text, size_t *length)
{
    size_t i;
    *length=strnlen(text,65);
    if (!*length || *length>64) return(1);
    for (i=0;i<*length;i++)
        if (!((text[i]>='a' && text[i]<='z') || (text[i]>='A' && text[i]<='Z') || text[i]=='_' ||
            (i && text[i]>='0' && text[i]<='9'))) return(1);
    return(0);
}

static int cmeContextV2AAD(const cmeStorageContext *context, const unsigned char salt[16],
    const unsigned char header[80], unsigned char aad[320], size_t *length)
{
    static const unsigned char domain[]="CDSE-HKX-AAD-v2";
    unsigned char zero[16]={0};
    size_t i,table,field,offset=sizeof(domain)+64;
    if (context->role<1 || context->role>5 || cmeContextV2Name(context->table,&table) ||
        cmeContextV2Name(context->field,&field)) return(1);
    for (i=0;i<5;i++)
    {
        int empty=!memcmp(context->ids[i],zero,16);
        if (i==2 ? (context->role<=3 ? !empty : empty) : empty) return(1);
    }
    if (context->role==5 && (strcmp(context->table,"payload") || strcmp(context->field,"bytes"))) return(1);
    memcpy(aad,domain,sizeof(domain)); memcpy(aad+sizeof(domain),header,48);
    memcpy(aad+sizeof(domain)+48,salt,16); aad[offset++]=(unsigned char)context->role;
    memcpy(aad+offset,context->ids,80); offset+=80;
    aad[offset++]=(unsigned char)table; memcpy(aad+offset,context->table,table); offset+=table;
    aad[offset++]=(unsigned char)field; memcpy(aad+offset,context->field,field); offset+=field;
    *length=offset; return(0);
}
#endif

static int cmeContextV2Parse(const unsigned char *frame, size_t length)
{
    uint32_t size;
    if (!frame || length<80 || length>cmeContextV2MaxPlaintext+80 || memcmp(frame,"CDSEHKX2",8) ||
        frame[8]!=1 || frame[9] || frame[10]!=1 || frame[11]!=1) return(1);
    size=((uint32_t)frame[12]<<24)|((uint32_t)frame[13]<<16)|((uint32_t)frame[14]<<8)|frame[15];
    return(size>cmeContextV2MaxPlaintext || length!=80+(size_t)size);
}

static int cmeContextV2Cipher(cmeContextManager *manager, const cmeContextBinding *binding,
    const cmeContextCopyTarget *target, const char *table, int64_t row, const char *field,
    const unsigned char *password, size_t passwordLength, const unsigned char *input, size_t length, const unsigned char *inputSalt,
    int encrypt, cmeContextV2Buffer *output, unsigned char *outputSalt, int admission)
{
    cmeStorageContext context={0};
    cmeContextV2Buffer candidate={0};
    unsigned int floor=0;
    unsigned char salt[16]={0};
    int result=1;
#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
    BitArray key=BA_INIT,nonce=BA_INIT;
    unsigned char aad[320]={0};
    const unsigned char empty=0;
    size_t aadLength=0,i;
    _Static_assert(KEYBYTES==32,"V2 profile 1 requires a 256-bit provider");
    _Static_assert(cmeContextV2MaxPlaintext<=INT_MAX-80,"V2 allocation bound");
#endif
    if (output) memset(output,0,sizeof(*output));
    if (outputSalt) memset(outputSalt,0,16);
    if (!output || !manager || (!binding && !target) || (binding && target) || !password || !passwordLength || passwordLength>256 ||
        (encrypt ? (!outputSalt || length>cmeContextV2MaxPlaintext || (!input && length)) :
        (!inputSalt || cmeContextV2Parse(input,length)))) goto done;
    if (admission && (encrypt || target || !binding)) goto done;
    cmeContextV2Checkpoint("before-check");
    result=target ? cmeContextCopyTargetCheck(manager,target) : (admission ? cmeContextBindingCheckAdmission(manager,binding) : cmeContextBindingCheckMapped(manager,binding));
    if (result) goto done;
    result=1;
    if ((target ? cmeContextCopyTargetLookup(target,table,row,field,&context,&floor) :
        cmeContextBindingLookup(binding,table,row,field,&context,&floor)) || (floor!=1 && floor!=2)) goto done;
    cmeContextV2Checkpoint("before-crypto");
#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
    candidate.length=encrypt ? length+80 : length-80;
    candidate.bytes=calloc(candidate.length+1,1); if (!candidate.bytes) goto done;
    if (encrypt)
    {
        if (!cmeContextV2Random(salt,16) || !cmeContextV2Random(nonce.b,32)) goto done;
        memcpy(candidate.bytes,"CDSEHKX2",8); candidate.bytes[8]=1; candidate.bytes[10]=1; candidate.bytes[11]=1;
        for (i=0;i<4;i++) candidate.bytes[12+i]=(unsigned char)(length>>(24-8*i));
        memcpy(candidate.bytes+16,nonce.b,32);
    }
    else
    {
        memcpy(salt,inputSalt,16); memcpy(nonce.b,input+16,32);
    }
    if (cmeContextV2AAD(&context,salt,encrypt ? candidate.bytes : input,aad,&aadLength) ||
        !PKCS5_PBKDF2_HMAC((const char *)password,(int)passwordLength,salt,16,10000,EVP_sha256(),32,key.b)) goto done;
    if (encrypt)
        hske_nl_aead_encrypt(&key,&nonce,aad,aadLength,input ? input : &empty,length,candidate.bytes+80,candidate.bytes+48);
    else if (!hske_nl_aead_decrypt(&key,&nonce,aad,aadLength,input+80,candidate.length,input+48,candidate.bytes)) goto done;
    cmeContextV2Checkpoint("after-crypto");
    result=target ? cmeContextCopyTargetCheck(manager,target) : (admission ? cmeContextBindingCheckAdmission(manager,binding) : cmeContextBindingCheckMapped(manager,binding));
    if (result) goto done;
    *output=candidate; memset(&candidate,0,sizeof(candidate));
    if (encrypt) memcpy(outputSalt,salt,16);
    result=0;
#else
    result=3;
#endif
done:
    cmeContextV2BufferFree(&candidate); OPENSSL_cleanse(salt,sizeof(salt));
    OPENSSL_cleanse(&context,sizeof(context));
#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
    OPENSSL_cleanse(&key,sizeof(key)); OPENSSL_cleanse(&nonce,sizeof(nonce)); OPENSSL_cleanse(aad,sizeof(aad));
#endif
    return(result);
}

int cmeContextV2Seal(cmeContextManager *manager, const cmeContextBinding *binding,
    const char *table, int64_t row, const char *field, const unsigned char *password, size_t passwordLength,
    const unsigned char *plaintext, size_t length, cmeContextV2Buffer *frame, unsigned char salt[16])
{
    return(cmeContextV2Cipher(manager,binding,NULL,table,row,field,password,passwordLength,
        plaintext,length,NULL,1,frame,salt,0));
}

int cmeContextV2Open(cmeContextManager *manager, const cmeContextBinding *binding,
    const char *table, int64_t row, const char *field, const unsigned char *password, size_t passwordLength,
    const unsigned char salt[16], const unsigned char *frame, size_t length, cmeContextV2Buffer *plaintext)
{
    return(cmeContextV2Cipher(manager,binding,NULL,table,row,field,password,passwordLength,
        frame,length,salt,0,plaintext,NULL,0));
}

int cmeContextV2SealCopyTarget(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const char *table, int64_t row, const char *field, const unsigned char *password, size_t passwordLength,
    const unsigned char *plaintext, size_t length, cmeContextV2Buffer *frame, unsigned char salt[16])
{
    return(cmeContextV2Cipher(manager,NULL,target,table,row,field,password,passwordLength,
        plaintext,length,NULL,1,frame,salt,0));
}

int cmeContextV2OpenCopyTarget(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const char *table, int64_t row, const char *field, const unsigned char *password, size_t passwordLength,
    const unsigned char salt[16], const unsigned char *frame, size_t length, cmeContextV2Buffer *plaintext)
{
    return(cmeContextV2Cipher(manager,NULL,target,table,row,field,password,passwordLength,
        frame,length,salt,0,plaintext,NULL,0));
}

/* Trusted private core: callers must guard witness and physical proof around
   this read. No public seal counterpart exists for admission bindings. */
int cmeContextV2OpenAdmissionBinding(cmeContextManager *manager, const cmeContextBinding *binding,
    const char *table, int64_t row, const char *field, const unsigned char *password, size_t passwordLength,
    const unsigned char salt[16], const unsigned char *frame, size_t length, cmeContextV2Buffer *plaintext)
{
    return(cmeContextV2Cipher(manager,binding,NULL,table,row,field,password,passwordLength,
        frame,length,salt,0,plaintext,NULL,1));
}
