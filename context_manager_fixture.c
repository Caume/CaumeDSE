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

static int cmeFixtureBinding(cmeContextManager *manager, int argc, char **argv)
{
    cmeContextBinding *binding=NULL,*fresh=NULL;
    cmeContextManager *second=NULL;
    cmeContextSlot *slots=NULL;
    cmeContextAnchor expected={0},next={0};
    unsigned char token[73],key[32];
    size_t count,queries,i,offset;
    int result=1,current,newResult;
    const char *revoke=getenv("CDSE_CONTEXT_BIND_REVOKE");
    if (argc<10 || cmeFixtureDecode(argv[7],token,sizeof(token))) goto done;
    memcpy(expected.deployment,token,16); memcpy(expected.organization,token+16,16);
    for (i=0;i<8;i++) expected.generation=(expected.generation<<8)|token[32+i];
    expected.minimumFormat=token[40]; memcpy(expected.digest,token+41,32);
    count=strtoul(argv[8],NULL,10);
    if (count>cmeContextRegistryMaxEntries+1 || count>(size_t)(argc-10)/4) goto done;
    offset=9+count*4; queries=strtoul(argv[offset],NULL,10);
    if (queries>(size_t)(argc-offset-1)/3 || offset+1+queries*3!=(size_t)argc) goto done;
    if (count)
    {
        slots=calloc(count,sizeof(*slots));
        if (!slots) goto done;
    }
    for (i=0;i<count;i++)
    {
        slots[i].lookup=argv[9+i*4]; slots[i].table=argv[10+i*4];
        slots[i].row=strtoll(argv[11+i*4],NULL,10); slots[i].field=argv[12+i*4];
    }
    binding=(cmeContextBinding *)manager;
    result=cmeContextManagerBind(manager,argv[5],(unsigned int)strtoul(argv[6],NULL,10),
        slots,count,&expected,&binding);
    if (result)
    {
        if (binding) { binding=NULL; result=3; }
        goto done;
    }
    result=1;
    if (cmeContextBindingCheck(manager,binding) || !cmeContextBindingCheck(NULL,binding) ||
        !cmeContextBindingCheck(manager,NULL)) goto done;
    {
        cmeStorageContext context,empty={0};
        unsigned int floor=99;
        memset(&context,0xff,sizeof(context));
        if (cmeContextManagerBind(NULL,argv[5],1,slots,count,&expected,&fresh)!=1 || fresh ||
            cmeContextManagerBind(manager,argv[5],1,slots,count,NULL,&fresh)!=1 || fresh ||
            cmeContextManagerBind(manager,argv[5],1,slots,count,&expected,NULL)!=1 ||
            cmeContextBindingLookup(NULL,"data",0,"value",&context,&floor)!=1 ||
            floor || memcmp(&context,&empty,sizeof(empty))) goto done;
        floor=99; memset(&context,0xff,sizeof(context));
        if (cmeContextBindingLookup(binding,NULL,0,"value",&context,&floor)!=1 ||
            floor || memcmp(&context,&empty,sizeof(empty))) goto done;
        floor=99;
        if (cmeContextBindingLookup(binding,"data",0,"value",NULL,&floor)!=1 || floor) goto done;
        memset(&context,0xff,sizeof(context));
        if (cmeContextBindingLookup(binding,"data",0,"value",&context,NULL)!=1 ||
            memcmp(&context,&empty,sizeof(empty))) goto done;
    }
    if (revoke || getenv("CDSE_CONTEXT_BIND_UPDATE"))
    {
        cmeStorageContext allocated;
        memset(key,'k',32);
        if (cmeContextManagerOpen(argv[1],0,key,expected.deployment,expected.organization,&second)) goto done;
        if (revoke ? cmeContextManagerRevoke(second,revoke,&expected,&next) :
            cmeContextManagerProvision(second,"unrelated/update",cmeContextNewStorage,4,"data","value",
                NULL,&expected,&allocated,&next)) goto done;
    }
    if (getenv("CDSE_CONTEXT_BIND_CORRUPT"))
    {
        sqlite3 *damaged=NULL;
        char *path=sqlite3_mprintf("%s/registry.sqlite",argv[1]);
        int failed=!path || sqlite3_open(path,&damaged)!=SQLITE_OK ||
            sqlite3_exec(damaged,"UPDATE registry_current SET tag=zeroblob(32)",NULL,NULL,NULL)!=SQLITE_OK;
        sqlite3_close(damaged); sqlite3_free(path);
        if (failed) goto done;
    }
    current=cmeContextBindingCheck(manager,binding);
    if (cmeContextManagerFetch(manager,expected.deployment,expected.organization,&next)) next=expected;
    newResult=cmeContextManagerBind(manager,argv[5],(unsigned int)strtoul(argv[6],NULL,10),
        slots,count,&next,&fresh);
    /* The operation owns its contexts, not the caller's strings/slot array. */
    for (i=0;i<count;i++)
    {
        memset(argv[9+i*4],'!',strlen(argv[9+i*4]));
        memset(argv[10+i*4],'!',strlen(argv[10+i*4]));
        memset(argv[12+i*4],'!',strlen(argv[12+i*4]));
    }
    free(slots); slots=NULL;
    printf("{\"current\":%d,\"fresh\":%d,\"results\":[",current,newResult);
    for (i=0;i<queries;i++)
    {
        cmeStorageContext context,empty={0};
        unsigned int floor=99;
        int found=cmeContextBindingLookup(binding,argv[offset+1+i*3],
            strtoll(argv[offset+2+i*3],NULL,10),argv[offset+3+i*3],&context,&floor);
        if (found && (floor || memcmp(&context,&empty,sizeof(empty)))) goto done;
        printf("%s{\"result\":%d,\"floor\":%u,\"record\":\"",i ? "," : "",found,floor);
        cmeFixturePrint(context.ids[4],16); printf("\",\"resource\":\"");
        cmeFixturePrint(context.ids[3],16); printf("\"}");
    }
    puts("]}"); result=0;
done:
    free(slots); cmeContextBindingFree(&binding); cmeContextBindingFree(&fresh);
    cmeContextBindingFree(&binding); cmeContextBindingFree(NULL);
    cmeContextManagerClose(&second);
    return(result);
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
    if (!strcmp(argv[2],"bind")) { result=cmeFixtureBinding(manager,argc,argv); goto done; }
    if (!strcmp(argv[2],"anchor") && argc==5)
    {
        if (cmeContextManagerFetch(manager,next.deployment,next.organization,&anchor)) goto done;
        cmeFixturePrint(anchor.deployment,16); cmeFixturePrint(anchor.organization,16);
        for (i=0;i<8;i++) token[i]=(unsigned char)(anchor.generation>>(56-8*i));
        cmeFixturePrint(token,8); printf("%02x",anchor.minimumFormat); cmeFixturePrint(anchor.digest,32);
        putchar('\n'); result=0; goto done;
    }
    if ((!strcmp(argv[2],"provision") && argc==12) || (!strcmp(argv[2],"revoke") && argc==7) ||
        (!strcmp(argv[2],"revoke-scope") && argc==8))
    {
        const char *previous=!strcmp(argv[2],"provision") ? argv[11] :
            (!strcmp(argv[2],"revoke-scope") ? argv[7] : argv[6]);
        const cmeContextAnchor *expectedPointer=NULL;
        cmeContextAnchor *publishedPointer=&anchor;
        if (strcmp(previous,"-"))
        {
            if (cmeFixtureDecode(previous,token,sizeof(token))) goto done;
            memcpy(expected.deployment,token,16); memcpy(expected.organization,token+16,16);
            for (i=0;i<8;i++) expected.generation=(expected.generation<<8)|token[32+i];
            expected.minimumFormat=token[40]; memcpy(expected.digest,token+41,32);
            expectedPointer=&expected;
            if (getenv("CDSE_CONTEXT_MANAGER_ALIAS")) publishedPointer=&expected;
        }
        memset(&context,0xff,sizeof(context));
        if (!strcmp(argv[2],"provision"))
            result=cmeContextManagerProvision(manager,argv[5],(cmeContextAllocation)strtoul(argv[6],NULL,10),
                (unsigned int)strtoul(argv[7],NULL,10),argv[8],argv[9],strcmp(argv[10],"-") ? argv[10] : NULL,
                expectedPointer,&context,publishedPointer);
        else if (!strcmp(argv[2],"revoke-scope"))
            result=cmeContextManagerRevokeScope(manager,argv[5],
                (cmeContextRevocationScope)strtoul(argv[6],NULL,10),expectedPointer,publishedPointer);
        else result=cmeContextManagerRevoke(manager,argv[5],expectedPointer,publishedPointer);
        if (result)
        {
            cmeContextAnchor cleared={0};
            cmeStorageContext empty={0};
            if (memcmp(publishedPointer,&cleared,sizeof(cleared)) ||
                (!strcmp(argv[2],"provision") && memcmp(&context,&empty,sizeof(empty)))) result=3;
        }
        if (!result)
        {
            if (cmeContextManagerSnapshot(manager,&body,&length,tag,&next)) { result=1; goto done; }
            fwrite(body,1,length,stdout); putchar('\n');
        }
        goto done;
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
