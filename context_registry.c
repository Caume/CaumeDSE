#include "common.h"
#include "context_registry.h"

typedef struct
{
    char lookup[129], canonical[512];
    int active;
    cmeStorageContext context;
} cmeContextEntry;

struct cmeContextRegistry
{
    cmeContextAnchor anchor;
    size_t count;
    cmeContextEntry *entries;
};

static const char *cmeContextRoles[]={"ResourcesDB","RolesDB","LogsDB","ColumnFile","RawPart"};

static int cmeContextNonzero(const unsigned char id[16])
{
    unsigned int i,any=0;
    for (i=0;i<16;i++) any|=id[i];
    return(any!=0);
}

static int cmeContextId(const char *text, unsigned char id[16])
{
    size_t i;
    if (strlen(text)!=32) return(1);
    for (i=0;i<32;i++)
    {
        unsigned int digit;
        if (text[i]>='0' && text[i]<='9') digit=text[i]-'0';
        else if (text[i]>='a' && text[i]<='f') digit=text[i]-'a'+10;
        else return(1);
        if (!(i%2)) id[i/2]=(unsigned char)(digit<<4);
        else id[i/2]|=(unsigned char)digit;
    }
    return(0);
}

static void cmeContextHex(const unsigned char *bytes, size_t length, char *text)
{
    static const char digits[]="0123456789abcdef";
    size_t i;
    for (i=0;i<length;i++) { text[2*i]=digits[bytes[i]>>4]; text[2*i+1]=digits[bytes[i]&15]; }
    text[2*length]=0;
}

static int cmeContextName(const char *text, int lookup)
{
    size_t i,length=strlen(text);
    if (!length || length>(lookup ? 128U : 64U)) return(1);
    for (i=0;i<length;i++)
    {
        int letter=(text[i]>='A' && text[i]<='Z') || (text[i]>='a' && text[i]<='z');
        int digit=text[i]>='0' && text[i]<='9';
        if (letter || text[i]=='_' || (digit && (lookup || i))) continue;
        if (lookup && (text[i]=='/' || text[i]==':' || text[i]=='-')) continue;
        return(1);
    }
    return(0);
}

/* SQLite parses JSON; exact field/type checks and byte-for-byte reconstruction
   reject duplicate keys, escapes, whitespace and noncanonical number spellings. */
static int cmeContextObject(sqlite3 *db, const char *json, const char **names,
                            const char **types, size_t count, char **values)
{
    sqlite3_stmt *stmt=NULL;
    size_t i,seen=0;
    int step,result=3;
    if (sqlite3_prepare_v2(db,"SELECT key,type,value FROM json_each(?1) WHERE json_type(?1)='object'",
                           -1,&stmt,NULL)!=SQLITE_OK) goto done;
    if (sqlite3_bind_text(stmt,1,json,-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        const char *name=(const char *)sqlite3_column_text(stmt,0);
        const char *type=(const char *)sqlite3_column_text(stmt,1);
        const char *value=(const char *)sqlite3_column_text(stmt,2);
        if (!name || !type || !value || strlen(name)!=(size_t)sqlite3_column_bytes(stmt,0) ||
            strlen(value)!=(size_t)sqlite3_column_bytes(stmt,2)) goto done;
        for (i=0;i<count;i++) if (!strcmp(name,names[i])) break;
        if (i==count || values[i] || strcmp(type,types[i])) goto done;
        values[i]=sqlite3_mprintf("%s",value);
        if (!values[i]) { result=4; goto done; }
        seen++;
    }
    if (step==SQLITE_DONE && seen==count) result=0;
done:
    sqlite3_finalize(stmt);
    return(result);
}

static void cmeContextValuesFree(char **values, size_t count)
{
    size_t i;
    for (i=0;i<count;i++) sqlite3_free(values[i]);
}

static int cmeContextDecode(sqlite3 *db, const char *json, const cmeContextAnchor *anchor,
                            cmeContextEntry *entry)
{
    const char *names[]={"deployment","organization","storage","resource","record","role","table","field"};
    const char *types[]={"text","text","text","text","text","text","text","text"};
    char *v[8]={0};
    size_t i;
    int result=cmeContextObject(db,json,names,types,8,v);
    if (result) goto done;
    result=3;
    for (i=0;i<5;i++) if (cmeContextId(v[i],entry->context.ids[i])) goto done;
    for (i=0;i<5;i++) if (!strcmp(v[5],cmeContextRoles[i])) break;
    if (i==5) goto done;
    entry->context.role=(unsigned int)i+1;
    for (i=0;i<5;i++)
    {
        int required=i!=2 || entry->context.role>=4;
        if (cmeContextNonzero(entry->context.ids[i])!=required) goto done;
    }
    if (memcmp(entry->context.ids[0],anchor->deployment,16) ||
        memcmp(entry->context.ids[1],anchor->organization,16) ||
        cmeContextName(v[6],0) || cmeContextName(v[7],0)) goto done;
    if (entry->context.role==5 && (strcmp(v[6],"payload") || strcmp(v[7],"bytes"))) goto done;
    strcpy(entry->context.table,v[6]); strcpy(entry->context.field,v[7]);
    snprintf(entry->canonical,sizeof(entry->canonical),
        "{\"deployment\":\"%s\",\"field\":\"%s\",\"organization\":\"%s\",\"record\":\"%s\",\"resource\":\"%s\",\"role\":\"%s\",\"storage\":\"%s\",\"table\":\"%s\"}",
        v[0],v[7],v[1],v[4],v[3],v[5],v[2],v[6]);
    result=0;
done:
    cmeContextValuesFree(v,8);
    return(result);
}

static int cmeContextCompare(const void *a, const void *b)
{
    const cmeContextEntry *const *left=a,*const *right=b;
    return(strcmp((*left)->canonical,(*right)->canonical));
}

static int cmeContextAppend(char *buffer, size_t *used, const char *format, ...)
{
    va_list args;
    int length;
    va_start(args,format);
    length=vsnprintf(buffer+*used,cmeContextRegistryMaxBytes+1-*used,format,args);
    va_end(args);
    if (length<0 || (size_t)length>cmeContextRegistryMaxBytes-*used) return(3);
    *used+=(size_t)length;
    return(0);
}

static int cmeContextParse(const unsigned char *body, size_t length, cmeContextRegistry *registry)
{
    const char *names[]={"schema","deployment","organization","generation","minimumFormat","entries"};
    const char *types[]={"integer","text","text","integer","integer","array"};
    const char *entryNames[]={"lookup","state","context"};
    const char *entryTypes[]={"text","text","object"};
    char *v[6]={0},*e[3]={0},*canonical=NULL;
    char deployment[33],organization[33];
    sqlite3 *db=NULL;
    sqlite3_stmt *stmt=NULL;
    cmeContextEntry **ordered=NULL;
    size_t i,used=0;
    int result=3,step;
    if (memchr(body,0,length) || sqlite3_open(":memory:",&db)!=SQLITE_OK) goto done;
    result=cmeContextObject(db,(const char *)body,names,types,6,v);
    if (result) goto done;
    result=3;
    cmeContextHex(registry->anchor.deployment,16,deployment);
    cmeContextHex(registry->anchor.organization,16,organization);
    if (strcmp(v[0],"1") || strcmp(v[1],deployment) || strcmp(v[2],organization)) goto done;
    registry->entries=calloc(cmeContextRegistryMaxEntries,sizeof(*registry->entries));
    ordered=calloc(cmeContextRegistryMaxEntries,sizeof(*ordered));
    canonical=malloc(cmeContextRegistryMaxBytes+1);
    if (!registry->entries || !ordered || !canonical) { result=4; goto done; }
    if (sqlite3_prepare_v2(db,"SELECT type,value FROM json_each(?1)",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,v[5],-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
    if (cmeContextAppend(canonical,&used,"{\"deployment\":\"%s\",\"entries\":[",deployment)) goto done;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        cmeContextEntry *entry;
        const char *type=(const char *)sqlite3_column_text(stmt,0);
        const char *value=(const char *)sqlite3_column_text(stmt,1);
        if (registry->count==cmeContextRegistryMaxEntries ||
            !type || !value || strcmp(type,"object")) goto done;
        result=cmeContextObject(db,value,entryNames,entryTypes,3,e);
        if (result) goto done;
        result=3;
        entry=&registry->entries[registry->count];
        if (cmeContextName(e[0],1) || (strcmp(e[1],"active") && strcmp(e[1],"revoked"))) goto done;
        strcpy(entry->lookup,e[0]); entry->active=!strcmp(e[1],"active");
        if (registry->count && strcmp(registry->entries[registry->count-1].lookup,entry->lookup)>=0) goto done;
        result=cmeContextDecode(db,e[2],&registry->anchor,entry);
        if (result) goto done;
        result=3;
        if (cmeContextAppend(canonical,&used,"%s{\"context\":%s,\"lookup\":\"%s\",\"state\":\"%s\"}",
                             registry->count ? "," : "",entry->canonical,entry->lookup,e[1])) goto done;
        ordered[registry->count++]=entry;
        cmeContextValuesFree(e,3); memset(e,0,sizeof(e));
    }
    if (step!=SQLITE_DONE) goto done;
    qsort(ordered,registry->count,sizeof(*ordered),cmeContextCompare);
    for (i=1;i<registry->count;i++) if (!strcmp(ordered[i-1]->canonical,ordered[i]->canonical)) goto done;
    if (cmeContextAppend(canonical,&used,
        "],\"generation\":%llu,\"minimumFormat\":%u,\"organization\":\"%s\",\"schema\":1}",
        (unsigned long long)registry->anchor.generation,registry->anchor.minimumFormat,organization)) goto done;
    if (used==length && !memcmp(canonical,body,length)) result=0;
done:
    sqlite3_finalize(stmt);
    cmeContextValuesFree(v,6); cmeContextValuesFree(e,3);
    sqlite3_close(db);
    free(ordered); free(canonical);
    return(result);
}

void cmeContextRegistryFree(cmeContextRegistry **registry)
{
    if (registry && *registry)
    {
        free((*registry)->entries); free(*registry); *registry=NULL;
    }
}

int cmeContextRegistryOpen(const unsigned char *body, size_t length,
                           const unsigned char *tag, size_t tagLength,
                           const unsigned char *key, size_t keyLength,
                           const unsigned char deployment[16], const unsigned char organization[16],
                           cmeContextAnchorFetch fetch, void *manager, cmeContextRegistry **registry)
{
    static const unsigned char domain[]="CDSE-HKX-REGISTRY-v1";
    cmeContextAnchor anchor={0};
    cmeContextRegistry *candidate=NULL;
    unsigned char *copy=NULL,*message=NULL,digest[32],mac[32];
    unsigned int written=0;
    int result=2;
    if (registry) *registry=NULL;
    if (!registry || !body || !length || length>cmeContextRegistryMaxBytes || !tag || tagLength!=32 ||
        !key || keyLength!=32 || !deployment || !organization || !fetch ||
        !cmeContextNonzero(deployment) || !cmeContextNonzero(organization)) return(1);
    if (fetch(manager,deployment,organization,&anchor) || !anchor.generation ||
        (anchor.minimumFormat!=1 && anchor.minimumFormat!=2) ||
        memcmp(anchor.deployment,deployment,16) || memcmp(anchor.organization,organization,16)) return(2);
    copy=malloc(length+1); message=malloc(sizeof(domain)+length);
    candidate=calloc(1,sizeof(*candidate));
    if (!copy || !message || !candidate) { result=4; goto done; }
    memcpy(copy,body,length); copy[length]=0;
    memcpy(message,domain,sizeof(domain)); memcpy(message+sizeof(domain),copy,length);
    if (!HMAC(EVP_sha256(),key,32,message,sizeof(domain)+length,mac,&written) || written!=32 ||
        CRYPTO_memcmp(mac,tag,32) || !EVP_Digest(copy,length,digest,&written,EVP_sha256(),NULL) ||
        written!=32 || CRYPTO_memcmp(digest,anchor.digest,32)) goto done;
    candidate->anchor=anchor;
    result=cmeContextParse(copy,length,candidate);
    if (!result) { *registry=candidate; candidate=NULL; }
done:
    cmeContextRegistryFree(&candidate); free(copy); free(message);
    return(result);
}

int cmeContextRegistryLookup(const cmeContextRegistry *registry, const char *lookup,
                            cmeStorageContext *context, unsigned int *minimumFormat)
{
    size_t low=0,high;
    if (context) memset(context,0,sizeof(*context));
    if (minimumFormat) *minimumFormat=0;
    if (!registry || !lookup || !context || !minimumFormat || cmeContextName(lookup,1)) return(1);
    high=registry->count;
    while (low<high)
    {
        size_t middle=low+(high-low)/2;
        int comparison=strcmp(lookup,registry->entries[middle].lookup);
        if (comparison<0) high=middle;
        else if (comparison>0) low=middle+1;
        else
        {
            if (!registry->entries[middle].active) return(1);
            *context=registry->entries[middle].context;
            *minimumFormat=registry->anchor.minimumFormat;
            return(0);
        }
    }
    return(1);
}
