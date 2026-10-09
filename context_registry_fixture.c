/* Synthetic test adapter only; command arguments are not a production trust source. */
#include "common.h"
#include "context_registry.h"

typedef struct
{
    cmeContextAnchor anchor;
    unsigned int calls;
} cmeFixtureManager;

static int cmeFixtureHex(const char *text, unsigned char *bytes, size_t length)
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

static int cmeFixtureAnchor(void *opaque, const unsigned char deployment[16],
                           const unsigned char organization[16], cmeContextAnchor *anchor)
{
    cmeFixtureManager *manager=opaque;
    manager->calls++;
    if (memcmp(deployment,manager->anchor.deployment,16) ||
        memcmp(organization,manager->anchor.organization,16) || getenv("CDSE_REGISTRY_MANAGER_FAIL")) return(1);
    *anchor=manager->anchor;
    if (getenv("CDSE_REGISTRY_MANAGER_FOREIGN")) anchor->organization[0]^=1;
    return(0);
}

int main(int argc, char **argv)
{
    cmeFixtureManager manager={0};
    cmeContextRegistry *registry=NULL,*again=NULL;
    cmeStorageContext context,second,zero={0};
    unsigned int floor=0,secondFloor=0;
    unsigned char body[cmeContextRegistryMaxBytes+1],tag[32],key[32];
    size_t length,i,j;
    FILE *input=NULL;
    int result=1;
    if (argc!=9) return(2);
    memset(key,getenv("CDSE_REGISTRY_WRONG_KEY") ? 'x' : 'k',sizeof(key));
    manager.anchor.generation=strtoull(argv[4],NULL,10);
    manager.anchor.minimumFormat=(unsigned int)strtoul(argv[5],NULL,10);
    if (cmeFixtureHex(argv[2],tag,32) || cmeFixtureHex(argv[3],manager.anchor.digest,32) ||
        cmeFixtureHex(argv[7],manager.anchor.deployment,16) ||
        cmeFixtureHex(argv[8],manager.anchor.organization,16)) return(2);
    input=fopen(argv[1],"rb");
    if (!input) return(2);
    length=fread(body,1,sizeof(body),input);
    if (ferror(input)) { fclose(input); return(2); }
    fclose(input);
    if (!cmeContextRegistryOpen(NULL,length,tag,32,key,32,manager.anchor.deployment,
        manager.anchor.organization,cmeFixtureAnchor,&manager,&registry) || registry || manager.calls ||
        !cmeContextRegistryOpen(body,length,tag,31,key,32,manager.anchor.deployment,
        manager.anchor.organization,cmeFixtureAnchor,&manager,&registry) || registry || manager.calls ||
        !cmeContextRegistryOpen(body,length,tag,32,key,31,manager.anchor.deployment,
        manager.anchor.organization,cmeFixtureAnchor,&manager,&registry) || registry || manager.calls) return(2);
    if (cmeContextRegistryOpen(body,length,tag,32,key,32,manager.anchor.deployment,
        manager.anchor.organization,cmeFixtureAnchor,&manager,&registry))
    {
        if (registry) result=2;
        goto done;
    }
    if (manager.calls!=1) goto done;
    memset(body,'x',length); /* The handle must own its verified contexts. */
    if (!strcmp(argv[6],"@open-only")) { result=0; goto done; }
    memset(&context,0xff,sizeof(context)); floor=99;
    if (cmeContextRegistryLookup(registry,argv[6],&context,&floor))
    {
        if (memcmp(&context,&zero,sizeof(context)) || floor) result=2;
        goto done;
    }
    if (cmeContextRegistryLookup(registry,argv[6],&second,&secondFloor) ||
        memcmp(&context,&second,sizeof(context)) || floor!=secondFloor) goto done;
    memset(&second,0xff,sizeof(second)); secondFloor=99;
    if (!cmeContextRegistryLookup(registry,"missing!",&second,&secondFloor) ||
        memcmp(&second,&zero,sizeof(second)) || secondFloor) goto done;
    manager.anchor.generation++;
    if (!cmeContextRegistryOpen(body,length,tag,32,key,32,manager.anchor.deployment,
        manager.anchor.organization,cmeFixtureAnchor,&manager,&again) || again || manager.calls!=2) goto done;
    printf("%u %02x",floor,context.role);
    for (i=0;i<5;i++) for (j=0;j<16;j++) printf("%02x",context.ids[i][j]);
    printf("%02x",(unsigned int)strlen(context.table));
    for (i=0;context.table[i];i++) printf("%02x",(unsigned char)context.table[i]);
    printf("%02x",(unsigned int)strlen(context.field));
    for (i=0;context.field[i];i++) printf("%02x",(unsigned char)context.field[i]);
    putchar('\n');
    result=0;
done:
    cmeContextRegistryFree(&registry); cmeContextRegistryFree(&registry);
    cmeContextRegistryFree(&again);
    return(result);
}
