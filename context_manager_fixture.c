/* Synthetic manager owner only. This check program is never installed. */
#include "common.h"
#include "context_manager.h"

static int cmeFixtureDecode(const char *text, unsigned char *bytes, size_t length)
{
    size_t i;
    if (strlen(text)!=2*length) return(1);
    for (i=0;i<length;i++)
    {
        unsigned int value;
        if (sscanf(text+2*i,"%2x",&value)!=1) return(1);
        bytes[i]=(unsigned char)value;
    }
    return(0);
}

static void cmeFixturePrint(const unsigned char *bytes, size_t length)
{
    size_t i;
    for (i=0;i<length;i++) printf("%02x",bytes[i]);
}

int main(int argc, char **argv)
{
    cmeContextManager *manager=NULL,*second=NULL;
    cmeContextRegistry *registry=NULL;
    cmeContextAnchor next={0},expected={0},anchor={0};
    cmeStorageContext context;
    unsigned char key[32],tag[32],token[73],*body=NULL,*oldBody=NULL,oldTag[32];
    unsigned int floor;
    size_t length=0,oldLength=0,i;
    FILE *file=NULL;
    int result=1;
    if (argc<5) return(2);
    memset(key,getenv("CDSE_REGISTRY_WRONG_KEY") ? 'x' : 'k',32);
    if (cmeFixtureDecode(argv[3],next.deployment,16) || cmeFixtureDecode(argv[4],next.organization,16)) return(2);
    if (cmeContextManagerOpen(argv[1],!strcmp(argv[2],"init"),key,next.deployment,next.organization,&manager)) goto done;
    if (!strcmp(argv[2],"init") && argc==5) { result=0; goto done; }
    if (!strcmp(argv[2],"anchor") && argc==5)
    {
        if (cmeContextManagerFetch(manager,next.deployment,next.organization,&anchor)) goto done;
        cmeFixturePrint(anchor.deployment,16); cmeFixturePrint(anchor.organization,16);
        for (i=0;i<8;i++) token[i]=(unsigned char)(anchor.generation>>(56-8*i));
        cmeFixturePrint(token,8); printf("%02x",anchor.minimumFormat); cmeFixturePrint(anchor.digest,32);
        putchar('\n'); result=0; goto done;
    }
    if (((!strcmp(argv[2],"publish") || !strcmp(argv[2],"handoff")) && argc==11) ||
        (!strcmp(argv[2],"verify") && argc==8))
    {
        body=malloc(cmeContextRegistryMaxBytes+1);
        file=fopen(argv[5],"rb");
        if (!body || !file || cmeFixtureDecode(argv[6],tag,32)) goto done;
        length=fread(body,1,cmeContextRegistryMaxBytes+1,file);
        if (ferror(file)) goto done;
        fclose(file); file=NULL;
    }
    if ((!strcmp(argv[2],"publish") || !strcmp(argv[2],"handoff")) && argc==11)
    {
        if (cmeFixtureDecode(argv[7],next.digest,32)) goto done;
        next.generation=strtoull(argv[8],NULL,10); next.minimumFormat=(unsigned int)strtoul(argv[9],NULL,10);
        if (strcmp(argv[10],"-"))
        {
            if (cmeFixtureDecode(argv[10],token,sizeof(token))) goto done;
            memcpy(expected.deployment,token,16); memcpy(expected.organization,token+16,16);
            for (i=0;i<8;i++) expected.generation=(expected.generation<<8)|token[32+i];
            expected.minimumFormat=token[40]; memcpy(expected.digest,token+41,32);
        }
        if (!strcmp(argv[2],"handoff"))
        {
            if (cmeContextManagerSnapshot(manager,&oldBody,&oldLength,oldTag,&anchor) ||
                cmeContextManagerOpen(argv[1],0,key,next.deployment,next.organization,&second) ||
                cmeContextManagerPublish(second,body,length,tag,&next,&expected) ||
                !cmeContextRegistryOpen(oldBody,oldLength,oldTag,32,key,32,next.deployment,next.organization,
                    cmeContextManagerFetch,manager,&registry) || registry ||
                cmeContextManagerFetch(manager,next.deployment,next.organization,&anchor) ||
                anchor.generation!=next.generation || anchor.minimumFormat!=next.minimumFormat ||
                memcmp(anchor.digest,next.digest,32)) goto done;
            result=0;
        }
        else result=cmeContextManagerPublish(manager,body,length,tag,&next,strcmp(argv[10],"-") ? &expected : NULL);
        goto done;
    }
    if (!strcmp(argv[2],"read") && argc==6)
    {
        if (cmeContextManagerSnapshot(manager,&body,&length,tag,&anchor)) goto done;
    }
    else if (strcmp(argv[2],"verify") || argc!=8) goto done;
    if (cmeContextRegistryOpen(body,length,tag,32,key,32,next.deployment,next.organization,
        cmeContextManagerFetch,manager,&registry) || cmeContextRegistryLookup(registry,
        !strcmp(argv[2],"read") ? argv[5] : argv[7],&context,&floor)) goto done;
    printf("{\"floor\":%u,\"record\":\"",floor); cmeFixturePrint(context.ids[4],16); puts("\"}");
    result=0;
done:
    if (file) fclose(file);
    free(body); free(oldBody); cmeContextRegistryFree(&registry);
    cmeContextManagerClose(&second);
    cmeContextManagerClose(&manager); cmeContextManagerClose(&manager);
    return(result);
}
