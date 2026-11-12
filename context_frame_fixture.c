/* Draft V2 acceptance harness only. Never linked into an installed binary.
   Deterministic nonces and command-line secrets are for synthetic tests only. */
#include "config.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
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

#define CME_FRAME_LIMIT 16384U
#define CME_CONTEXT_LIMIT 211U

typedef struct
{
    unsigned char *bytes;
    size_t length;
} cmeFrameBytes;

static void cmeFrameFree(cmeFrameBytes *value)
{
    if (value->bytes) { OPENSSL_cleanse(value->bytes,value->length); free(value->bytes); }
    value->bytes=NULL; value->length=0;
}

static int cmeFrameHex(const char *text, cmeFrameBytes *value)
{
    size_t i,length=strlen(text);
    if (length%2 || length>2*CME_FRAME_LIMIT) return(1);
    value->bytes=calloc(length/2+1,1); value->length=length/2;
    if (!value->bytes) return(1);
    for (i=0;i<length;i++)
    {
        unsigned int digit;
        if (text[i]>='0' && text[i]<='9') digit=text[i]-'0';
        else if (text[i]>='a' && text[i]<='f') digit=text[i]-'a'+10;
        else return(1);
        value->bytes[i/2]|=(unsigned char)(digit<<(i%2 ? 0 : 4));
    }
    return(0);
}

static int cmeFrameName(const unsigned char *text, size_t length)
{
    size_t i;
    if (!length || length>64) return(1);
    for (i=0;i<length;i++)
        if (!((text[i]>='a' && text[i]<='z') || (text[i]>='A' && text[i]<='Z') ||
            text[i]=='_' || (i && text[i]>='0' && text[i]<='9'))) return(1);
    return(0);
}

static int cmeFrameContext(const cmeFrameBytes *context)
{
    unsigned char zero[16]={0};
    size_t i,table,field;
    const unsigned char *p=context->bytes;
    if (context->length<85 || context->length>CME_CONTEXT_LIMIT || p[0]<1 || p[0]>5) return(1);
    for (i=0;i<5;i++)
    {
        int empty=!memcmp(p+1+16*i,zero,16);
        if (i==2 ? (p[0]<=3 ? !empty : empty) : empty) return(1);
    }
    table=p[81];
    if (table>64 || context->length<83+table || cmeFrameName(p+82,table)) return(1);
    field=p[82+table];
    if (context->length!=83+table+field || cmeFrameName(p+83+table,field)) return(1);
    if (p[0]==5 && (table!=7 || field!=5 || memcmp(p+82,"payload",7) || memcmp(p+83+table,"bytes",5))) return(1);
    return(0);
}

static int cmeFrameParse(const cmeFrameBytes *frame)
{
    uint32_t length;
    const unsigned char *p=frame->bytes;
    if (frame->length<80 || memcmp(p,"CDSEHKX2",8) || p[8]!=1 || p[9] || p[10]!=1 || p[11]!=1) return(1);
    length=((uint32_t)p[12]<<24)|((uint32_t)p[13]<<16)|((uint32_t)p[14]<<8)|p[15];
    return(length>INT_MAX-80 || frame->length!=80+(size_t)length);
}

static int cmeFrameAAD(const cmeFrameBytes *context, const cmeFrameBytes *salt,
    const cmeFrameBytes *frame, unsigned char aad[320], size_t *length)
{
    static const unsigned char domain[]="CDSE-HKX-AAD-v2";
    if (cmeFrameContext(context) || salt->length!=16 || cmeFrameParse(frame)) return(1);
    memcpy(aad,domain,sizeof(domain)); memcpy(aad+sizeof(domain),frame->bytes,48);
    memcpy(aad+sizeof(domain)+48,salt->bytes,16);
    memcpy(aad+sizeof(domain)+64,context->bytes,context->length);
    *length=sizeof(domain)+64+context->length; return(0);
}

#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
static int cmeFrameCipher(const cmeFrameBytes *context, const cmeFrameBytes *salt,
    const cmeFrameBytes *password, const cmeFrameBytes *nonce, const cmeFrameBytes *input,
    int encrypt, unsigned int floor, cmeFrameBytes *output)
{
    BitArray key=BA_INIT,iv=BA_INIT;
    unsigned char aad[320];
    size_t aadLength=0,i;
    int result=1;
    _Static_assert(KEYBYTES==32,"draft V2 requires the 256-bit provider");
    if (!password->length || password->length>256 || salt->length!=16 ||
        (floor!=1 && floor!=2) || cmeFrameContext(context)) goto done;
    if (encrypt)
    {
        if (nonce->length!=32 || input->length>CME_FRAME_LIMIT-80) goto done;
        output->length=80+input->length; output->bytes=calloc(output->length+1,1);
        if (!output->bytes) goto done;
        memcpy(output->bytes,"CDSEHKX2",8); output->bytes[8]=1; output->bytes[10]=1; output->bytes[11]=1;
        for (i=0;i<4;i++) output->bytes[12+i]=(unsigned char)(input->length>>(24-8*i));
        memcpy(output->bytes+16,nonce->bytes,32);
        if (cmeFrameAAD(context,salt,output,aad,&aadLength)) goto done;
        memcpy(iv.b,nonce->bytes,32);
    }
    else
    {
        if (cmeFrameAAD(context,salt,input,aad,&aadLength)) goto done;
        output->length=input->length-80; output->bytes=malloc(output->length+1);
        if (!output->bytes) goto done;
        memset(output->bytes,0xa5,output->length+1); memcpy(iv.b,input->bytes+16,32);
    }
    /* Draft KDF id 1 freezes these parameters, independent of engine defaults. */
    if (!PKCS5_PBKDF2_HMAC((const char *)password->bytes,(int)password->length,salt->bytes,16,
        10000,EVP_sha256(),32,key.b)) goto done;
    if (encrypt)
        hske_nl_aead_encrypt(&key,&iv,aad,aadLength,input->bytes,input->length,output->bytes+80,output->bytes+48);
    else if (!hske_nl_aead_decrypt(&key,&iv,aad,aadLength,input->bytes+80,output->length,input->bytes+48,output->bytes))
    {
        /* The provider promises verify-before-decrypt; detect any partial release. */
        for (i=0;i<=output->length;i++) if (output->bytes[i]!=0xa5) { result=3; goto done; }
        goto done;
    }
    result=0;
done:
    OPENSSL_cleanse(&key,sizeof(key)); OPENSSL_cleanse(&iv,sizeof(iv)); OPENSSL_cleanse(aad,sizeof(aad));
    if (result) cmeFrameFree(output);
    return(result);
}
#endif

int main(int argc, char **argv)
{
    cmeFrameBytes args[7]={{0}},output={0},plain={0};
    unsigned char aad[320];
    size_t i,length=0;
    int result=1;
    if (argc==2 && !strcmp(argv[1],"available"))
    {
        #if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
        puts("1");
#else
        puts("0");
#endif
        return(0);
    }
    if (argc<2 || argc>9) goto done;
    for (i=2;i<(size_t)argc;i++) if (cmeFrameHex(argv[i],&args[i-2])) goto done;
    if (!strcmp(argv[1],"aad") && argc==5)
    {
        if (cmeFrameAAD(&args[0],&args[1],&args[2],aad,&length)) goto done;
        for (i=0;i<length;i++) printf("%02x",aad[i]);
        putchar('\n'); result=0; goto done;
    }
#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
    if (!strcmp(argv[1],"seal") && argc==7)
        result=cmeFrameCipher(&args[0],&args[1],&args[3],&args[2],&args[4],1,2,&output);
    else if (!strcmp(argv[1],"open") && argc==7 && args[3].length==1)
        result=cmeFrameCipher(&args[0],&args[1],&args[2],NULL,&args[4],0,args[3].bytes[0],&output);
    else if (!strcmp(argv[1],"copy") && argc==9)
    {
        if (cmeFrameContext(&args[0]) || cmeFrameContext(&args[1]) || args[0].bytes[0]!=4 || args[1].bytes[0]!=4 ||
            args[0].length!=args[1].length || memcmp(args[0].bytes+1,args[1].bytes+1,48) ||
            !memcmp(args[0].bytes+49,args[1].bytes+49,16) || !memcmp(args[0].bytes+65,args[1].bytes+65,16) ||
            memcmp(args[0].bytes+81,args[1].bytes+81,args[0].length-81) || args[2].length!=16 || args[3].length!=16 ||
            !memcmp(args[2].bytes,args[3].bytes,16) || args[4].length!=32 || cmeFrameParse(&args[6]) ||
            !memcmp(args[4].bytes,args[6].bytes+16,32)) goto done;
        result=cmeFrameCipher(&args[0],&args[2],&args[5],NULL,&args[6],0,2,&plain);
        if (!result) result=cmeFrameCipher(&args[1],&args[3],&args[5],&args[4],&plain,1,2,&output);
    }
#else
    if ((!strcmp(argv[1],"seal") && argc==7) || (!strcmp(argv[1],"open") && argc==7) ||
        (!strcmp(argv[1],"copy") && argc==9)) result=77;
#endif
    if (!result)
    {
        for (i=0;i<output.length;i++) printf("%02x",output.bytes[i]);
        putchar('\n');
    }
done:
    for (i=0;i<7;i++) cmeFrameFree(&args[i]);
    cmeFrameFree(&output); cmeFrameFree(&plain); OPENSSL_cleanse(aad,sizeof(aad));
    if (result) fprintf(stderr,"context-frame-fixture: rejected\n");
    return(result);
}
