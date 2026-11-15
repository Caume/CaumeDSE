/* Synthetic owner harness only; never installed or used with real secrets. */
#include "config.h"
#include "context_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/crypto.h>

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

int main(int argc, char **argv)
{
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
