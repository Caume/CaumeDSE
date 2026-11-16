/* Explicit offline V2 container; no legacy or live-storage dispatch. */
#include "common.h"
#include "context_column.h"
#include "context_column_internal.h"

#if defined(HAVE_SQLITE3_SERIALIZE) && defined(HAVE_SQLITE3_DESERIALIZE)
static const char cmeColumnImageHeaderSQL[]=
    "CREATE TABLE cdse_column_v2(version INTEGER NOT NULL,profile TEXT NOT NULL,integrity TEXT NOT NULL,cellCount INTEGER NOT NULL)";
static const char cmeColumnImageCellsSQL[]=
    "CREATE TABLE cdse_column_v2_cells(ordinal INTEGER PRIMARY KEY,salt BLOB NOT NULL,frame BLOB NOT NULL)";

static int cmeColumnImageBudget(void *context)
{
    unsigned int *budget=context;
    if (!*budget) return(1);
    --*budget; return(0);
}

static int cmeColumnImageCompare(const void *left, const void *right)
{
    const cmeContextSlot *a=*(const cmeContextSlot *const *)left,*b=*(const cmeContextSlot *const *)right;
    int result=strcmp(a->table,b->table);
    if (result) return(result);
    if (a->row!=b->row) return(a->row<b->row ? -1 : 1);
    return(strcmp(a->field,b->field));
}

static int cmeColumnImageInventory(const cmeContextMap *map, const cmeContextSlot ***ordered)
{
    static const char *fields[2][4]={{"orgId","rowOrder","userId","value"},
        {"attribute","attributeData","orgId","userId"}};
    const cmeContextSlot **slots=NULL;
    size_t i,j,groups[2]={0,0};
    int table;
    *ordered=NULL;
    if (!map || !map->active || map->blocked || map->role!=4 || !map->count || map->count%4 ||
        map->count>cmeContextRegistryMaxEntries || !(slots=calloc(map->count,sizeof(*slots)))) return(1);
    for (i=0;i<map->count;i++) slots[i]=&map->slots[i];
    qsort(slots,map->count,sizeof(*slots),cmeColumnImageCompare);
    for (i=0;i<map->count;i+=4)
    {
        table=!strcmp(slots[i]->table,"meta");
        if ((!table && strcmp(slots[i]->table,"data")) || slots[i]->row<1 || slots[i]->row>INT_MAX) goto bad;
        if (i && !strcmp(slots[i]->table,slots[i-1]->table) && slots[i]->row==slots[i-1]->row) goto bad;
        for (j=0;j<4;j++)
            if (strcmp(slots[i+j]->table,slots[i]->table) || slots[i+j]->row!=slots[i]->row ||
                strcmp(slots[i+j]->field,fields[table][j])) goto bad;
        groups[table]++;
    }
    if (!groups[0] || !groups[1]) goto bad;
    *ordered=slots; return(0);
bad:
    free(slots); return(1);
}

static int cmeColumnImagePlain(const cmeContextColumnStage *stage, const cmeContextV2Buffer *plain)
{
    static const char *attributes[]={"name","protect","shuffle","MAC","sign","MACProtected","signProtected"};
    unsigned char seen[7]={0},orders[cmeContextRegistryMaxEntries]={0};
    size_t i,j,rows=0;
    for (i=0;i<stage->count;i+=4)
    {
        if (!strcmp(stage->cells[i].table,"meta"))
        {
            const char *attribute=(const char *)plain[i].bytes,*value=(const char *)plain[i+1].bytes;
            for (j=0;j<7;j++) if (!strcmp(attribute,attributes[j])) break;
            if (j==7 || seen[j]++) return(1);
            if ((j==1 || j==2) && strcmp(value,cmeContextColumnStageProfile)) return(1);
            if (j>=3 && strcmp(value,"sha256")) return(1);
        }
        else
        {
            const char *text=(const char *)plain[i+1].bytes;
            char *end=NULL;
            unsigned long order;
            errno=0; order=strtoul(text,&end,10);
            if (!*text || strspn(text,"0123456789")!=strlen(text) || errno || *end || !order ||
                order>cmeContextRegistryMaxEntries || orders[order-1]++) return(1);
            rows++;
        }
    }
    if (!seen[0] || !seen[1] || !rows) return(1);
    for (i=0;i<rows;i++) if (!orders[i]) return(1);
    return(0);
}

static int cmeColumnImageText(sqlite3_stmt *stmt, int column, const char *expected)
{
    const unsigned char *value;
    size_t length=strlen(expected);
    if (sqlite3_column_type(stmt,column)!=SQLITE_TEXT) return(1);
    value=sqlite3_column_text(stmt,column);
    return(!value ||
        sqlite3_column_bytes(stmt,column)!=(int)length || memcmp(value,expected,length));
}

static uint32_t cmeColumnImageU32(const unsigned char *bytes)
{
    return(((uint32_t)bytes[0]<<24)|((uint32_t)bytes[1]<<16)|((uint32_t)bytes[2]<<8)|bytes[3]);
}

int cmeContextColumnStageDeserialize(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const unsigned char *image, size_t length, const unsigned char digest[32],
    const unsigned char *password, size_t passwordLength, cmeContextColumnStage **stage)
{
    cmeContextMap *map=NULL;
    cmeContextBinding *binding=NULL;
    const cmeContextSlot **slots=NULL;
    cmeContextColumnStage *candidate=NULL;
    cmeContextV2Buffer *plain=NULL;
    sqlite3 *db=NULL;
    sqlite3_stmt *stmt=NULL;
    unsigned char *copy=NULL,actual[32];
    unsigned int written=0,budget=20000;
    size_t i,total=0,plainTotal=0;
    int result=1,step;
    if (stage) *stage=NULL;
    if (!stage || !manager || !target || !image || length<4096 || length>cmeContextColumnMaxImageBytes ||
        !digest || !password || !passwordLength || passwordLength>256) goto done;
    result=cmeContextCopyTargetSource(manager,target,&map,&binding); if (result) goto done;
    result=1;
    if (cmeColumnImageInventory(map,&slots) || !(copy=sqlite3_malloc64(length))) goto done;
    memcpy(copy,image,length);
    if (!EVP_Digest(copy,length,actual,&written,EVP_sha256(),NULL) || written!=32 || CRYPTO_memcmp(actual,digest,32) ||
        memcmp(copy,"SQLite format 3",16) || copy[16]!=0x10 || copy[17] || copy[18]!=1 || copy[19]!=1 || copy[20] ||
        length%4096 || cmeColumnImageU32(copy+28)!=length/4096 || cmeColumnImageU32(copy+32) || cmeColumnImageU32(copy+36) ||
        cmeColumnImageU32(copy+56)!=1 || cmeColumnImageU32(copy+60)!=1 || cmeColumnImageU32(copy+68)!=0x43445332 ||
        sqlite3_open(":memory:",&db)!=SQLITE_OK) goto done;
    if (sqlite3_deserialize(db,"main",copy,length,length,SQLITE_DESERIALIZE_READONLY)!=SQLITE_OK) goto done;
    sqlite3_limit(db,SQLITE_LIMIT_LENGTH,cmeContextColumnMaxCellBytes+4096);
    sqlite3_limit(db,SQLITE_LIMIT_SQL_LENGTH,65536); sqlite3_limit(db,SQLITE_LIMIT_COLUMN,16);
    sqlite3_progress_handler(db,1000,cmeColumnImageBudget,&budget);
    if (sqlite3_db_config(db,SQLITE_DBCONFIG_DEFENSIVE,1,NULL)!=SQLITE_OK ||
        sqlite3_exec(db,"PRAGMA trusted_schema=OFF; PRAGMA query_only=ON",NULL,NULL,NULL)!=SQLITE_OK ||
        sqlite3_prepare_v2(db,"SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name",-1,&stmt,NULL)!=SQLITE_OK) goto done;
    for (i=0;i<2;i++)
    {
        const char *name=i ? "cdse_column_v2_cells" : "cdse_column_v2";
        if (sqlite3_step(stmt)!=SQLITE_ROW || cmeColumnImageText(stmt,0,"table") || cmeColumnImageText(stmt,1,name) ||
            cmeColumnImageText(stmt,2,name) || cmeColumnImageText(stmt,3,i ? cmeColumnImageCellsSQL : cmeColumnImageHeaderSQL)) goto done;
    }
    if (sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(db,"PRAGMA integrity_check",-1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
        cmeColumnImageText(stmt,0,"ok") || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(db,"SELECT rowid,version,profile,integrity,cellCount FROM cdse_column_v2",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_ROW || sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || sqlite3_column_int64(stmt,0)!=1 ||
        sqlite3_column_type(stmt,1)!=SQLITE_INTEGER || sqlite3_column_int64(stmt,1)!=1 ||
        cmeColumnImageText(stmt,2,cmeContextColumnStageProfile) || cmeColumnImageText(stmt,3,cmeContextColumnImageIntegrity) ||
        sqlite3_column_type(stmt,4)!=SQLITE_INTEGER || sqlite3_column_int64(stmt,4)!=(sqlite3_int64)map->count ||
        sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    candidate=calloc(1,sizeof(*candidate)); if (!candidate) goto done;
    candidate->cells=calloc(map->count,sizeof(*candidate->cells)); if (!candidate->cells) goto done;
    candidate->count=map->count;
    if (sqlite3_prepare_v2(db,"SELECT ordinal,salt,frame FROM cdse_column_v2_cells ORDER BY ordinal",-1,&stmt,NULL)!=SQLITE_OK) goto done;
    i=0;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        cmeContextColumnCell *cell;
        const void *salt,*frame;
        int size;
        if (sqlite3_column_type(stmt,1)!=SQLITE_BLOB || sqlite3_column_type(stmt,2)!=SQLITE_BLOB) goto done;
        salt=sqlite3_column_blob(stmt,1); frame=sqlite3_column_blob(stmt,2); size=sqlite3_column_bytes(stmt,2);
        if (i>=map->count || sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || sqlite3_column_int64(stmt,0)!=(sqlite3_int64)i+1 ||
            sqlite3_column_type(stmt,1)!=SQLITE_BLOB || sqlite3_column_bytes(stmt,1)!=16 || !salt ||
            sqlite3_column_type(stmt,2)!=SQLITE_BLOB || size<80 || size>(int)cmeContextColumnMaxCellBytes+80 || !frame ||
            (total+=(size_t)size+sizeof(*cell))>cmeContextColumnMaxStageBytes) goto done;
        cell=&candidate->cells[i];
        strcpy(cell->table,slots[i]->table); strcpy(cell->field,slots[i]->field); cell->row=slots[i]->row;
        memcpy(cell->salt,salt,16); cell->frame.bytes=malloc((size_t)size+1); if (!cell->frame.bytes) goto done;
        memcpy(cell->frame.bytes,frame,size); cell->frame.bytes[size]=0; cell->frame.length=size; i++;
    }
    if (step!=SQLITE_DONE || i!=map->count || !(plain=calloc(map->count,sizeof(*plain)))) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    for (i=0;i<map->count;i++)
    {
        cmeContextColumnCell *cell=&candidate->cells[i];
        result=cmeContextV2OpenCopyTarget(manager,target,cell->table,cell->row,cell->field,password,passwordLength,
            cell->salt,cell->frame.bytes,cell->frame.length,&plain[i]);
        if (result) goto done;
        result=1;
        if (memchr(plain[i].bytes,0,plain[i].length) || (plainTotal+=plain[i].length+1)>cmeContextColumnMaxBytes) goto done;
    }
    if (cmeColumnImagePlain(candidate,plain)) goto done;
    result=cmeContextBindingCheckMapped(manager,binding); if (result) goto done;
    result=cmeContextCopyTargetCheck(manager,target); if (result) goto done;
    *stage=candidate; candidate=NULL;
done:
    if (plain) for (i=0;i<map->count;i++) cmeContextV2BufferFree(&plain[i]);
    free(plain); cmeContextColumnStageFree(&candidate); free(slots);
    cmeContextBindingFree(&binding); cmeContextMapFree(&map); sqlite3_finalize(stmt); sqlite3_close(db);
    if (copy) OPENSSL_cleanse(copy,length);
    sqlite3_free(copy); OPENSSL_cleanse(actual,sizeof(actual)); return(result);
}

int cmeContextColumnStageSerialize(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnStage *stage, const unsigned char *password, size_t passwordLength,
    cmeContextV2Buffer *image, unsigned char digest[32])
{
    cmeContextMap *map=NULL;
    cmeContextBinding *binding=NULL;
    const cmeContextSlot **slots=NULL;
    cmeContextColumnStage *check=NULL;
    cmeContextV2Buffer candidate={0};
    sqlite3 *db=NULL;
    sqlite3_stmt *stmt=NULL;
    unsigned char *serialized=NULL,actual[32];
    sqlite3_int64 length=0;
    unsigned int written=0;
    size_t i,total=0;
    int result=1;
    if (image) memset(image,0,sizeof(*image));
    if (digest) memset(digest,0,32);
    if (!image || !digest || !manager || !target || !stage || !password || !passwordLength || passwordLength>256) goto done;
    result=cmeContextCopyTargetSource(manager,target,&map,&binding); if (result) goto done;
    result=1;
    if (stage->count!=map->count || cmeColumnImageInventory(map,&slots)) goto done;
    for (i=0;i<stage->count;i++)
    {
        const cmeContextColumnCell *cell=&stage->cells[i];
        if (strcmp(cell->table,slots[i]->table) || cell->row!=slots[i]->row || strcmp(cell->field,slots[i]->field) ||
            !cell->frame.bytes || cell->frame.length<80 || cell->frame.length>cmeContextColumnMaxCellBytes+80 ||
            (total+=cell->frame.length+sizeof(*cell))>cmeContextColumnMaxStageBytes) goto done;
    }
    if (sqlite3_open(":memory:",&db)!=SQLITE_OK || sqlite3_exec(db,
        "PRAGMA page_size=4096; PRAGMA encoding='UTF-8'; PRAGMA auto_vacuum=NONE; PRAGMA journal_mode=MEMORY;"
        "PRAGMA application_id=1128551218; PRAGMA user_version=1; BEGIN",NULL,NULL,NULL)!=SQLITE_OK ||
        sqlite3_exec(db,cmeColumnImageHeaderSQL,NULL,NULL,NULL)!=SQLITE_OK ||
        sqlite3_exec(db,cmeColumnImageCellsSQL,NULL,NULL,NULL)!=SQLITE_OK ||
        sqlite3_prepare_v2(db,"INSERT INTO cdse_column_v2 VALUES(1,?1,?2,?3)",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,cmeContextColumnStageProfile,-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,2,cmeContextColumnImageIntegrity,-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_int64(stmt,3,stage->count)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(db,"INSERT INTO cdse_column_v2_cells VALUES(?1,?2,?3)",-1,&stmt,NULL)!=SQLITE_OK) goto done;
    for (i=0;i<stage->count;i++)
    {
        const cmeContextColumnCell *cell=&stage->cells[i];
        if (sqlite3_bind_int64(stmt,1,i+1)!=SQLITE_OK || sqlite3_bind_blob(stmt,2,cell->salt,16,SQLITE_TRANSIENT)!=SQLITE_OK ||
            sqlite3_bind_blob(stmt,3,cell->frame.bytes,cell->frame.length,SQLITE_TRANSIENT)!=SQLITE_OK ||
            sqlite3_step(stmt)!=SQLITE_DONE || sqlite3_reset(stmt)!=SQLITE_OK || sqlite3_clear_bindings(stmt)!=SQLITE_OK) goto done;
    }
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK || !(serialized=sqlite3_serialize(db,"main",&length,0)) ||
        length<4096 || length>cmeContextColumnMaxImageBytes || !(candidate.bytes=malloc((size_t)length+1))) goto done;
    candidate.length=length; memcpy(candidate.bytes,serialized,length); candidate.bytes[length]=0;
    if (!EVP_Digest(candidate.bytes,candidate.length,actual,&written,EVP_sha256(),NULL) || written!=32) goto done;
    result=cmeContextColumnStageDeserialize(manager,target,candidate.bytes,candidate.length,actual,password,passwordLength,&check);
    if (result) goto done;
    result=cmeContextBindingCheckMapped(manager,binding); if (result) goto done;
    result=cmeContextCopyTargetCheck(manager,target); if (result) goto done;
    *image=candidate; memset(&candidate,0,sizeof(candidate)); memcpy(digest,actual,32);
done:
    cmeContextColumnStageFree(&check); cmeContextV2BufferFree(&candidate); free(slots);
    cmeContextBindingFree(&binding); cmeContextMapFree(&map); sqlite3_finalize(stmt); sqlite3_close(db);
    if (serialized) OPENSSL_cleanse(serialized,length);
    sqlite3_free(serialized); OPENSSL_cleanse(actual,sizeof(actual)); return(result);
}
#else
int cmeContextColumnStageDeserialize(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const unsigned char *image, size_t length, const unsigned char digest[32],
    const unsigned char *password, size_t passwordLength, cmeContextColumnStage **stage)
{
    (void)manager; (void)target; (void)image; (void)length; (void)digest; (void)password; (void)passwordLength;
    if (stage) *stage=NULL;
    return(stage ? 3 : 1);
}

int cmeContextColumnStageSerialize(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnStage *stage, const unsigned char *password, size_t passwordLength,
    cmeContextV2Buffer *image, unsigned char digest[32])
{
    (void)manager; (void)target; (void)stage; (void)password; (void)passwordLength;
    if (image) memset(image,0,sizeof(*image));
    if (digest) memset(digest,0,32);
    return(image && digest ? 3 : 1);
}
#endif
