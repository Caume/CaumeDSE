/* Private, bounded candidate cells; no installed storage-format dispatch. */
#include "common.h"
#include "context_column.h"
#include "context_column_internal.h"

size_t cmeContextColumnStageCount(const cmeContextColumnStage *stage)
{
    return(stage ? stage->count : 0);
}

const cmeContextColumnCell *cmeContextColumnStageCell(const cmeContextColumnStage *stage, size_t index)
{
    return(stage && index<stage->count ? &stage->cells[index] : NULL);
}

void cmeContextColumnStageFree(cmeContextColumnStage **stage)
{
    size_t i;
    if (!stage || !*stage) return;
    for (i=0;i<(*stage)->count;i++) cmeContextV2BufferFree(&(*stage)->cells[i].frame);
    free((*stage)->cells); free(*stage); *stage=NULL;
}

#if defined(HAVE_SQLITE3_DESERIALIZE)
static int cmeColumnBudget(void *context)
{
    unsigned int *budget=context;
    if (!*budget) return(1);
    --*budget; return(0);
}

static const char *cmeColumnText(sqlite3_stmt *stmt, int column)
{
    const char *text;
    if (sqlite3_column_type(stmt,column)!=SQLITE_TEXT ||
        sqlite3_column_bytes(stmt,column)>(int)cmeContextColumnMaxCellBytes) return(NULL);
    text=(const char *)sqlite3_column_text(stmt,column);
    return(text && strlen(text)==(size_t)sqlite3_column_bytes(stmt,column) ? text : NULL);
}

static int cmeColumnSchema(sqlite3 *db)
{
    static const char *names[2][11]={
        {"id","userId","orgId","salt","value","rowOrder","MAC","sign","MACProtected","signProtected","otphDKey"},
        {"id","userId","orgId","salt","attribute","attributeData"}};
    sqlite3_stmt *stmt=NULL;
    int result=1,table,column,step;
    if (sqlite3_prepare_v2(db,"SELECT 1 FROM sqlite_master WHERE type!='table' OR name NOT IN ('data','meta')",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(db,"PRAGMA integrity_check",-1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
        !sqlite3_column_text(stmt,0) || strcmp((const char *)sqlite3_column_text(stmt,0),"ok") ||
        sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    for (table=0;table<2;table++)
    {
        if (sqlite3_prepare_v2(db,table ? "PRAGMA table_xinfo(meta)" : "PRAGMA table_xinfo(data)",-1,&stmt,NULL)!=SQLITE_OK) goto done;
        column=0;
        while ((step=sqlite3_step(stmt))==SQLITE_ROW)
        {
            const char *name=(const char *)sqlite3_column_text(stmt,1),*type=(const char *)sqlite3_column_text(stmt,2);
            if (column>=(table ? 6 : 11) || !name || !type || strcmp(name,names[table][column]) ||
                strcmp(type,column ? "TEXT" : "INTEGER") || sqlite3_column_int(stmt,5)!=(column ? 0 : 1) ||
                sqlite3_column_int(stmt,6)) goto done;
            column++;
        }
        if (step!=SQLITE_DONE || column!=(table ? 6 : 11)) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
    }
    result=0;
done:
    sqlite3_finalize(stmt); return(result);
}

static int cmeColumnDecode(const char *value, const char *saltText, const char *key,
    const char *profile, char **plain)
{
    char *salt=NULL,*decoded=NULL,*compact=NULL,*canonical=NULL;
    unsigned char *frame=NULL;
    int frameLength=0,written=0,result=1;
    size_t i,n=0,padding=0;
    *plain=NULL;
    if (!value || !saltText || strlen(saltText)!=32 || strspn(saltText,"0123456789abcdefABCDEF")!=32 ||
        !(salt=strdup(saltText)) || !(compact=malloc(strlen(value)+1))) goto done;
    for (i=0;value[i];i++) if (value[i]!='\n') compact[n++]=value[i];
    compact[n]=0;
    if (!n || n%4 || !(frame=malloc(n)) || !(canonical=malloc(n+1))) goto done;
    for (i=0;i<n;i++)
    {
        unsigned char c=compact[i];
        if (c=='=') { if (++padding>2 || i<n-2) goto done; }
        else if (padding || !((c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9') || c=='+' || c=='/')) goto done;
    }
    frameLength=EVP_DecodeBlock(frame,(unsigned char *)compact,n);
    if (frameLength<=(int)padding) goto done;
    frameLength-=padding;
    if (EVP_EncodeBlock((unsigned char *)canonical,frame,frameLength)!=(int)n || memcmp(canonical,compact,n) ||
        (frameLength>=7 && !memcmp(frame,"CDSEHKX",7))) goto done;
    if (cmeCipherByteString(frame,(unsigned char **)&decoded,(unsigned char **)&salt,frameLength,&written,profile,key,'d') ||
        !decoded || written<32 ||
        memchr(decoded,0,written) || strspn(decoded,"0123456789abcdefABCDEF")<32 ||
        !(*plain=strdup(decoded+32))) goto done;
    result=0;
done:
    if (decoded) OPENSSL_cleanse(decoded,written>0 ? written : 1);
    free(decoded); free(frame); free(salt); free(compact); free(canonical); return(result);
}

static int cmeColumnTag(const char *value, const char *stored, const char *saltText, const char *key, int enabled)
{
    char *salt=NULL,*tag=NULL;
    int result=1,written=0;
    if (!stored || !value) return(1);
    if (!enabled) return(*stored!=0);
    salt=strdup(saltText);
    if (!salt || cmeHMACByteString((const unsigned char *)value,(unsigned char **)&tag,strlen(value),&written,
        "sha256",&salt,key) || written!=64 || strlen(stored)!=64 || CRYPTO_memcmp(stored,tag,64)) goto done;
    result=0;
done:
    free(salt); free(tag); return(result);
}

/* Inventory and decode ALL rows before the first target seal. All plaintext is
   private, bounded by the source image, and destroyed on every exit. */
static int cmeColumnRead(sqlite3 *db, const cmeContextMap *map, const char *key, const char *profile, char **plain)
{
    static const char *fields[2][4]={{"userId","orgId","attribute","attributeData"},
        {"userId","orgId","value","rowOrder"}};
    static const char *attributes[]={"name","protect","shuffle","MAC","sign","MACProtected","signProtected"};
    unsigned char seen[7]={0},orders[cmeContextRegistryMaxEntries]={0};
    sqlite3_stmt *stmt=NULL;
    size_t i,j,cells=0,rows=0,total=0,indices[4];
    int table,field,step,result=1;
    if (!map->active || map->blocked || map->role!=4 || !map->count || map->count>cmeContextRegistryMaxEntries) return(1);
    for (table=0;table<2;table++)
    {
        if (sqlite3_prepare_v2(db,table ? "SELECT * FROM data ORDER BY id" : "SELECT * FROM meta ORDER BY id",
            -1,&stmt,NULL)!=SQLITE_OK) goto done;
        while ((step=sqlite3_step(stmt))==SQLITE_ROW)
        {
            int64_t row=sqlite3_column_int64(stmt,0);
            const char *salt=cmeColumnText(stmt,3);
            if (sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || row<1 || row>INT_MAX || !salt ||
                strlen(salt)!=32 || strspn(salt,"0123456789abcdefABCDEF")!=32) goto done;
            for (field=0;field<4;field++)
            {
                const char *text=cmeColumnText(stmt,field<2 ? field+1 : field+2);
                size_t matches=0,index=0;
                for (i=0;i<map->count;i++)
                    if (map->slots[i].row==row && !strcmp(map->slots[i].table,table ? "data" : "meta") &&
                        !strcmp(map->slots[i].field,fields[table][field])) { matches++; index=i; }
                if (matches!=1 || !text || plain[index] || ++cells>map->count) goto done;
                indices[field]=index;
                if (table && field==3 && !seen[2]) plain[index]=strdup(text);
                else if (cmeColumnDecode(text,salt,key,profile,&plain[index])) goto done;
                if (!plain[index] || (total+=strlen(plain[index])+1)>cmeContextColumnMaxBytes) goto done;
            }
            if (!table)
            {
                for (j=0;j<7;j++) if (!strcmp(plain[indices[2]],attributes[j])) break;
                if (j==7 || seen[j]++) goto done;
                if ((j==1 || j==2) && strcmp(plain[indices[3]],profile)) goto done;
                if (j>=3 && strcmp(plain[indices[3]],"sha256")) goto done;
            }
            else
            {
                char *end=NULL;
                unsigned long order;
                const char *text=plain[indices[3]],*otp=cmeColumnText(stmt,10),*value=cmeColumnText(stmt,4);
                errno=0; order=strtoul(text,&end,10);
                if (!*text || strspn(text,"0123456789")!=strlen(text) || errno || *end || !order ||
                    order>cmeContextRegistryMaxEntries || orders[order-1]++ || !otp || *otp || !value ||
                    ++rows>cmeContextRegistryMaxEntries) goto done;
                for (j=0;j<4;j++) if (cmeColumnTag(j<2 ? plain[indices[2]] : value,
                    cmeColumnText(stmt,6+j),salt,key,seen[3+j])) goto done;
            }
        }
        if (step!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
        if (!table && (!seen[0] || !seen[1])) goto done;
    }
    if (!rows || cells!=map->count) goto done;
    for (i=0;i<rows;i++) if (!orders[i]) goto done;
    /* Source declarations are provenance, not the destination profile. Rewrite
       both protect and shuffle declarations before target encryption. */
    for (i=0;i<map->count;i++)
        if (!strcmp(map->slots[i].table,"meta") && !strcmp(map->slots[i].field,"attribute") &&
            (!strcmp(plain[i],"protect") || !strcmp(plain[i],"shuffle")))
            for (j=0;j<map->count;j++)
                if (!strcmp(map->slots[j].table,"meta") && map->slots[j].row==map->slots[i].row &&
                    !strcmp(map->slots[j].field,"attributeData"))
                {
                    OPENSSL_cleanse(plain[j],strlen(plain[j])); free(plain[j]);
                    plain[j]=strdup(cmeContextColumnStageProfile); if (!plain[j]) goto done;
                }
    result=0;
done:
    sqlite3_finalize(stmt); return(result);
}

int cmeContextColumnStageCreate(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const unsigned char *source, size_t length, const unsigned char sourceDigest[32],
    const char *sourceKey, const char *sourceProfile,
    const unsigned char *password, size_t passwordLength, cmeContextColumnStage **stage)
{
    sqlite3 *db=NULL;
    unsigned char *image=NULL,digest[32];
    unsigned int written=0,budget=20000;
    cmeContextMap *map=NULL;
    cmeContextBinding *binding=NULL;
    cmeContextColumnStage *candidate=NULL;
    cmeContextV2Buffer readback={0};
    char **plain=NULL;
    size_t i,total=0;
    int result=1;
    if (stage) *stage=NULL;
    if (!stage || !manager || !target || !source || length<100 || length>cmeContextColumnMaxBytes || !sourceDigest ||
        !sourceKey || !*sourceKey || strnlen(sourceKey,257)>256 || !sourceProfile ||
        (strcmp(sourceProfile,"aes-256-gcm") && strcmp(sourceProfile,"aes-256-cbc")) ||
        !password || !passwordLength || passwordLength>256) goto done;
    result=cmeContextCopyTargetSource(manager,target,&map,&binding); if (result) goto done;
    result=1;
    if (!map->count || map->count>cmeContextRegistryMaxEntries || !(image=sqlite3_malloc64(length))) goto done;
    memcpy(image,source,length);
    if (!EVP_Digest(image,length,digest,&written,EVP_sha256(),NULL) || written!=32 || CRYPTO_memcmp(digest,sourceDigest,32) ||
        memcmp(image,"SQLite format 3",16) || image[18]!=1 || image[19]!=1 ||
        sqlite3_open(":memory:",&db)!=SQLITE_OK) goto done;
    if (sqlite3_deserialize(db,"main",image,length,length,SQLITE_DESERIALIZE_READONLY)!=SQLITE_OK) goto done;
    sqlite3_limit(db,SQLITE_LIMIT_LENGTH,cmeContextColumnMaxCellBytes);
    sqlite3_limit(db,SQLITE_LIMIT_SQL_LENGTH,65536);
    sqlite3_limit(db,SQLITE_LIMIT_COLUMN,16);
    sqlite3_progress_handler(db,1000,cmeColumnBudget,&budget);
    if (sqlite3_db_config(db,SQLITE_DBCONFIG_DEFENSIVE,1,NULL)!=SQLITE_OK ||
        sqlite3_exec(db,"PRAGMA trusted_schema=OFF; PRAGMA query_only=ON",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeColumnSchema(db) || !(plain=calloc(map->count,sizeof(*plain))) ||
        cmeColumnRead(db,map,sourceKey,sourceProfile,plain)) goto done;
    candidate=calloc(1,sizeof(*candidate)); if (!candidate) goto done;
    candidate->cells=calloc(map->count,sizeof(*candidate->cells)); if (!candidate->cells) goto done;
    candidate->count=map->count;
    result=cmeContextBindingCheckMapped(manager,binding); if (result) goto done;
    for (i=0;i<map->count;i++)
    {
        const cmeContextSlot *slot=&map->slots[i];
        cmeContextColumnCell *cell=&candidate->cells[i];
        strcpy(cell->table,slot->table); strcpy(cell->field,slot->field); cell->row=slot->row;
        result=cmeContextV2SealCopyTarget(manager,target,slot->table,slot->row,slot->field,password,passwordLength,
            (const unsigned char *)plain[i],strlen(plain[i]),&cell->frame,cell->salt);
        if (result) goto done;
        result=1;
        if ((total+=cell->frame.length+sizeof(*cell))>cmeContextColumnMaxStageBytes) goto done;
        result=cmeContextV2OpenCopyTarget(manager,target,slot->table,slot->row,slot->field,password,passwordLength,
            cell->salt,cell->frame.bytes,cell->frame.length,&readback);
        if (result) goto done;
        result=1;
        if (readback.length!=strlen(plain[i]) || CRYPTO_memcmp(readback.bytes,plain[i],readback.length)) goto done;
        cmeContextV2BufferFree(&readback);
    }
    result=cmeContextBindingCheckMapped(manager,binding); if (result) goto done;
    result=cmeContextCopyTargetCheck(manager,target); if (result) goto done;
    *stage=candidate; candidate=NULL;
done:
    cmeContextV2BufferFree(&readback);
    cmeContextColumnStageFree(&candidate);
    if (plain) for (i=0;i<map->count;i++) if (plain[i]) { OPENSSL_cleanse(plain[i],strlen(plain[i])); free(plain[i]); }
    free(plain); cmeContextBindingFree(&binding); cmeContextMapFree(&map);
    sqlite3_close(db);
    if (image) OPENSSL_cleanse(image,length);
    sqlite3_free(image); OPENSSL_cleanse(digest,sizeof(digest)); return(result);
}
#else
int cmeContextColumnStageCreate(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const unsigned char *source, size_t length, const unsigned char sourceDigest[32],
    const char *sourceKey, const char *sourceProfile,
    const unsigned char *password, size_t passwordLength, cmeContextColumnStage **stage)
{
    (void)manager; (void)target; (void)source; (void)length; (void)sourceDigest;
    (void)sourceKey; (void)sourceProfile; (void)password; (void)passwordLength;
    if (stage) *stage=NULL;
    return(stage ? 3 : 1);
}
#endif
