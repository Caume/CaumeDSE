/* Explicit local owner approval for offline, byte-preserving ColumnFile moves. */
#include "admin.h"
#include "context_manager.h"
#include "context_offline.h"
#include "context_witness.h"

typedef struct
{
    char *values[19],*registration[4];
    sqlite3_int64 documentRow;
    int schema;
    cmeContextSlot *slots;
    size_t count;
    unsigned char deployment[16],organization[16],source[32],target[32];
    unsigned char resourcesSource[32],resourcesTarget[32];
    cmeContextAnchor registry;
    cmeContextMapAnchor catalog;
} cmeOwnerApproval;

static int cmeOwnerSameSlot(const cmeContextSlot *a, const cmeContextSlot *b);

static int cmeOwnerHex(const char *value, unsigned char *bytes, size_t length)
{
    size_t i;
    if (!value || strlen(value)!=2*length) return(1);
    for (i=0;i<2*length;i++)
    {
        unsigned int digit;
        if (value[i]>='0' && value[i]<='9') digit=value[i]-'0';
        else if (value[i]>='a' && value[i]<='f') digit=value[i]-'a'+10;
        else return(1);
        if (!(i%2)) bytes[i/2]=(unsigned char)(digit<<4);
        else bytes[i/2]|=(unsigned char)digit;
    }
    return(0);
}

static void cmeOwnerPrint(const unsigned char *bytes, size_t length)
{
    size_t i;
    for (i=0;i<length;i++) printf("%02x",bytes[i]);
}

static void cmeOwnerFree(cmeOwnerApproval *approval)
{
    size_t i;
    for (i=0;i<19;i++) free(approval->values[i]);
    for (i=0;i<4;i++) free(approval->registration[i]);
    for (i=0;i<approval->count;i++)
    {
        free((char *)approval->slots[i].lookup); free((char *)approval->slots[i].table);
        free((char *)approval->slots[i].field);
    }
    free(approval->slots);
}

static char *cmeOwnerText(sqlite3_stmt *stmt, int column, size_t maximum)
{
    const char *value;
    size_t length;
    if (sqlite3_column_type(stmt,column)!=SQLITE_TEXT) return(NULL);
    value=(const char *)sqlite3_column_text(stmt,column);
    if (!value || !(length=strlen(value)) || length>maximum ||
        length!=(size_t)sqlite3_column_bytes(stmt,column)) return(NULL);
    return(strdup(value));
}

static int cmeOwnerParse(const char *body, cmeOwnerApproval *approval)
{
    static const char *names[]={"schema","manager","deployment","organization","map","registry",
        "catalog","active","staged","source","target","slots","witness","resources","stagedResources",
        "resourcesSource","resourcesTarget","registration","profile"};
    sqlite3 *db=NULL;
    sqlite3_stmt *stmt=NULL,*slot=NULL;
    unsigned char bytes[73];
    size_t i,seen=0;
    int result=1,step;
    if (sqlite3_open(":memory:",&db)!=SQLITE_OK || sqlite3_prepare_v2(db,
        "SELECT key,type,value FROM json_each(?1) WHERE json_valid(?1)=1 AND json_type(?1)='object'",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,body,-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        const char *key=(const char *)sqlite3_column_text(stmt,0),*type=(const char *)sqlite3_column_text(stmt,1);
        if (!key || !type || strlen(key)!=(size_t)sqlite3_column_bytes(stmt,0)) goto done;
        for (i=0;i<19;i++) if (!strcmp(key,names[i])) break;
        if (i==19 || approval->values[i] || strcmp(type,i==0 ? "integer" : ((i==11 || i==17) ? "array" : "text"))) goto done;
        if (!i)
        {
            if (sqlite3_column_type(stmt,2)!=SQLITE_INTEGER ||
                (sqlite3_column_int64(stmt,2)<1 || sqlite3_column_int64(stmt,2)>3)) goto done;
            approval->schema=(int)sqlite3_column_int64(stmt,2);
            approval->values[i]=strdup("1");
        }
        else approval->values[i]=cmeOwnerText(stmt,2,i==11 ? cmeContextRegistryMaxBytes : PATH_MAX-1);
        if (!approval->values[i]) goto done;
        seen++;
    }
    if (step!=SQLITE_DONE || seen!=(approval->schema==1 ? 12U : (approval->schema==2 ? 13U : 19U)) ||
        (approval->schema==1 ? approval->values[12]!=NULL : approval->values[12]==NULL) ||
        cmeOwnerHex(approval->values[2],approval->deployment,16) ||
        cmeOwnerHex(approval->values[3],approval->organization,16) || cmeOwnerHex(approval->values[5],bytes,73)) goto done;
    for (i=0;i<(approval->schema==1 ? 12U : (approval->schema==2 ? 13U : 19U));i++)
        if (!approval->values[i]) goto done;
    memcpy(approval->registry.deployment,bytes,16); memcpy(approval->registry.organization,bytes+16,16);
    for (i=0;i<8;i++) approval->registry.generation=(approval->registry.generation<<8)|bytes[32+i];
    approval->registry.minimumFormat=bytes[40]; memcpy(approval->registry.digest,bytes+41,32);
    if (memcmp(approval->deployment,bytes,16) || memcmp(approval->organization,bytes+16,16) ||
        cmeOwnerHex(approval->values[6],bytes,40) || cmeOwnerHex(approval->values[9],approval->source,32) ||
        cmeOwnerHex(approval->values[10],approval->target,32)) goto done;
    for (i=0;i<8;i++) approval->catalog.revision=(approval->catalog.revision<<8)|bytes[i];
    memcpy(approval->catalog.digest,bytes+8,32);
    sqlite3_finalize(stmt); stmt=NULL;
    if (approval->schema==3)
    {
        if (cmeOwnerHex(approval->values[15],approval->resourcesSource,32) ||
            cmeOwnerHex(approval->values[16],approval->resourcesTarget,32) || sqlite3_prepare_v2(db,
            "SELECT json_extract(?1,'$[0]'),json_extract(?1,'$[1]'),json_extract(?1,'$[2]'),"
            "json_extract(?1,'$[3]'),json_extract(?1,'$[4]') WHERE json_array_length(?1)=5 AND "
            "json_type(?1,'$[0]')='integer' AND json_type(?1,'$[1]')='text' AND json_type(?1,'$[2]')='text' "
            "AND json_type(?1,'$[3]')='text' AND json_type(?1,'$[4]')='text'",-1,&stmt,NULL)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,1,approval->values[17],-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
            sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || (approval->documentRow=sqlite3_column_int64(stmt,0))<1) goto done;
        for (i=0;i<4;i++) if (!(approval->registration[i]=cmeOwnerText(stmt,(int)i+1,128))) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
    }
    approval->slots=calloc(cmeContextRegistryMaxEntries,sizeof(*approval->slots));
    if (!approval->slots || sqlite3_prepare_v2(db,"SELECT type,value FROM json_each(?1)",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,approval->values[11],-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_prepare_v2(db,
        "SELECT json_array_length(?1),json_extract(?1,'$[0]'),json_extract(?1,'$[1]'),"
        "json_extract(?1,'$[2]'),json_extract(?1,'$[3]') WHERE json_type(?1,'$[0]')='text' "
        "AND json_type(?1,'$[1]')='text' AND json_type(?1,'$[2]')='integer' AND json_type(?1,'$[3]')='text'",
        -1,&slot,NULL)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        cmeContextSlot *entry;
        if (approval->count==cmeContextRegistryMaxEntries || strcmp((const char *)sqlite3_column_text(stmt,0),"array") ||
            sqlite3_bind_text(slot,1,(const char *)sqlite3_column_text(stmt,1),-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
            sqlite3_step(slot)!=SQLITE_ROW || sqlite3_column_int(slot,0)!=4 ||
            sqlite3_column_type(slot,3)!=SQLITE_INTEGER) goto done;
        entry=&approval->slots[approval->count++];
        entry->lookup=cmeOwnerText(slot,1,128); entry->table=cmeOwnerText(slot,2,64);
        entry->row=sqlite3_column_int64(slot,3); entry->field=cmeOwnerText(slot,4,64);
        if (!entry->lookup || !entry->table || !entry->field || sqlite3_reset(slot)!=SQLITE_OK) goto done;
        for (i=0;i+1<approval->count;i++)
            if (cmeOwnerSameSlot(entry,&approval->slots[i]) ||
                (!strcmp(entry->table,approval->slots[i].table) && entry->row==approval->slots[i].row &&
                 !strcmp(entry->field,approval->slots[i].field))) goto done;
    }
    if (step==SQLITE_DONE && approval->count) result=0;
done:
    sqlite3_finalize(stmt); sqlite3_finalize(slot); sqlite3_close(db); return(result);
}

static int cmeOwnerFile(const char *path, size_t maximum, char **body)
{
    cmeOfflineArtifact parent={.file=-1,.directory=-1};
    struct stat before,after;
    char canonical[PATH_MAX],*candidate=NULL;
    size_t offset=0;
    int fd=-1,result=1;
    *body=NULL;
    if (!realpath(path,canonical) || strcmp(path,canonical) || cmeOfflineOpen(path,0,&parent)) goto done;
    fd=openat(parent.directory,parent.name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
    if (fd<0 || fstat(fd,&before) || !S_ISREG(before.st_mode) || before.st_uid!=geteuid() ||
        (before.st_mode&07777)!=0600 || before.st_nlink!=1 || before.st_size<1 ||
        (uint64_t)before.st_size>maximum || !(candidate=malloc((size_t)before.st_size+1))) goto done;
    while (offset<(size_t)before.st_size)
    {
        ssize_t count=read(fd,candidate+offset,(size_t)before.st_size-offset);
        if (count<0 && errno==EINTR) continue;
        if (count<=0) goto done;
        offset+=(size_t)count;
    }
    if (fstat(fd,&after) || before.st_size!=after.st_size || before.st_mtim.tv_sec!=after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec || before.st_ctim.tv_sec!=after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec || memchr(candidate,0,offset) ||
        fstatat(parent.directory,parent.name,&after,AT_SYMLINK_NOFOLLOW) ||
        before.st_dev!=after.st_dev || before.st_ino!=after.st_ino) goto done;
    candidate[offset]=0; *body=candidate; candidate=NULL; result=0;
done:
    if (candidate) { OPENSSL_cleanse(candidate,offset); free(candidate); }
    if (fd>=0) close(fd);
    cmeOfflineClose(&parent); return(result);
}

static int cmeOwnerOutside(const char *export, const char *path)
{
    size_t length=strlen(export);
    return(strncmp(export,path,length) || (path[length] && path[length]!='/'));
}

static int cmeOwnerPaths(const cmeOwnerApproval *approval, const char *manifest, const char *key)
{
    char export[PATH_MAX],canonical[PATH_MAX],*slash;
    const char *paths[]={approval->values[1],approval->values[8],manifest,key};
    size_t i;
    if (*approval->values[7]!='/' || strlen(approval->values[7])>=sizeof(export)) return(1);
    strcpy(export,approval->values[7]); slash=strrchr(export,'/');
    if (!slash || slash==export || !slash[1]) return(1);
    *slash=0;
    if (!realpath(export,canonical) || strcmp(export,canonical)) return(1);
    for (i=0;i<4;i++) if (!cmeOwnerOutside(export,paths[i])) return(1);
    /* Manager and staged paths must also be canonical, including a missing staged basename. */
    if (!realpath(paths[0],canonical) || strcmp(paths[0],canonical)) return(1);
    {
        cmeOfflineArtifact parent={.file=-1,.directory=-1};
        int result=cmeOfflineOpen(paths[1],0,&parent);
        cmeOfflineClose(&parent); return(result);
    }
}

static int cmeOwnerSameSlot(const cmeContextSlot *a, const cmeContextSlot *b)
{
    return(!strcmp(a->lookup,b->lookup) && !strcmp(a->table,b->table) && !strcmp(a->field,b->field));
}

static int cmeOwnerWitnessPaths(const cmeOwnerApproval *approval, const char *manifest, const char *keyFile, const char *witnessKey)
{
    char canonical[PATH_MAX],export[PATH_MAX],staging[PATH_MAX],*slash;
    struct stat managerDirectory,witnessDirectory,stagedDirectory;
    const char *directory=approval->values[12];
    if (!directory || !witnessKey || !realpath(directory,canonical) || strcmp(directory,canonical) ||
        !cmeOwnerOutside(approval->values[1],directory) || !cmeOwnerOutside(directory,approval->values[1]) ||
        !cmeOwnerOutside(directory,keyFile) || !cmeOwnerOutside(directory,witnessKey) || !cmeOwnerOutside(directory,manifest) ||
        !cmeOwnerOutside(approval->values[1],keyFile) || !cmeOwnerOutside(approval->values[1],witnessKey) ||
        lstat(directory,&witnessDirectory) || lstat(approval->values[1],&managerDirectory) ||
        (witnessDirectory.st_dev==managerDirectory.st_dev && witnessDirectory.st_ino==managerDirectory.st_ino)) return(1);
    strcpy(staging,approval->values[8]); slash=strrchr(staging,'/');
    if (!slash || slash==staging) return(1);
    *slash=0;
    if (!cmeOwnerOutside(directory,staging) || !cmeOwnerOutside(staging,directory) || lstat(staging,&stagedDirectory) ||
        (witnessDirectory.st_dev==stagedDirectory.st_dev && witnessDirectory.st_ino==stagedDirectory.st_ino)) return(1);
    strcpy(export,approval->values[7]); slash=strrchr(export,'/');
    if (!slash || slash==export) return(1);
    *slash=0;
    return(!cmeOwnerOutside(export,directory) || !cmeOwnerOutside(directory,export) || !cmeOwnerOutside(export,witnessKey));
}

static int cmeOwnerReceipt(const cmeOwnerApproval *approval, const cmeContextShuffle *shuffle)
{
    size_t i,j;
    if (strcmp(approval->values[7],shuffle->activePath) || strcmp(approval->values[8],shuffle->stagedPath) ||
        memcmp(approval->source,shuffle->sourceDigest,32) || memcmp(approval->target,shuffle->targetDigest,32) ||
        approval->count!=shuffle->target->count) return(1);
    for (i=0;i<shuffle->target->count;i++)
    {
        size_t matches=0;
        for (j=0;j<approval->count;j++)
            if (cmeOwnerSameSlot(&approval->slots[j],&shuffle->target->slots[i]) &&
                approval->slots[j].row==shuffle->target->slots[i].row) matches++;
        if (matches!=1) return(1);
    }
    return(0);
}

static int cmeOwnerCell(sqlite3_stmt *a, sqlite3_stmt *b, int column)
{
    int type=sqlite3_column_type(a,column);
    if (type!=sqlite3_column_type(b,column)) return(1);
    if (type==SQLITE_NULL) return(0);
    if (type==SQLITE_INTEGER) return(sqlite3_column_int64(a,column)!=sqlite3_column_int64(b,column));
    if (type==SQLITE_FLOAT)
    {
        double left=sqlite3_column_double(a,column),right=sqlite3_column_double(b,column);
        return(memcmp(&left,&right,sizeof(left))!=0);
    }
    {
        int length=sqlite3_column_bytes(a,column);
        const void *left=sqlite3_column_blob(a,column),*right=sqlite3_column_blob(b,column);
        return(length!=sqlite3_column_bytes(b,column) || (length && (!left || !right || memcmp(left,right,(size_t)length))));
    }
}

static int cmeOwnerBudget(void *context)
{
    unsigned int *remaining=context;
    if (!*remaining) return(1);
    --*remaining; return(0);
}

/* Compare all rows/columns by authenticated source slots, never candidate labels.
   Only integer primary-key relocation is allowed; salts, tags and rowOrder stay unchanged. */
static int cmeOwnerPermutation(const cmeOwnerApproval *approval, const cmeContextMap *source)
{
    cmeOfflineArtifact active={.file=-1,.directory=-1},staged={.file=-1,.directory=-1};
    sqlite3 *a=NULL,*b=NULL;
    sqlite3_stmt *left=NULL,*right=NULL;
    size_t i,j,k,rows[2]={0,0};
    unsigned int leftBudget=20000,rightBudget=20000;
    int result=1,table,column;
    if (cmeOfflineOpen(approval->values[7],1,&active) || cmeOfflineOpen(approval->values[8],1,&staged) ||
        memcmp(active.digest,approval->source,32) || memcmp(staged.digest,approval->target,32) ||
        source->count!=approval->count || sqlite3_open_v2(approval->values[7],&a,SQLITE_OPEN_READONLY|SQLITE_OPEN_NOFOLLOW,NULL)!=SQLITE_OK ||
        sqlite3_open_v2(approval->values[8],&b,SQLITE_OPEN_READONLY|SQLITE_OPEN_NOFOLLOW,NULL)!=SQLITE_OK) goto done;
    sqlite3_limit(a,SQLITE_LIMIT_LENGTH,cmeContextRegistryMaxBytes);
    sqlite3_limit(b,SQLITE_LIMIT_LENGTH,cmeContextRegistryMaxBytes);
    sqlite3_limit(a,SQLITE_LIMIT_SQL_LENGTH,65536); sqlite3_limit(b,SQLITE_LIMIT_SQL_LENGTH,65536);
    sqlite3_progress_handler(a,1000,cmeOwnerBudget,&leftBudget);
    sqlite3_progress_handler(b,1000,cmeOwnerBudget,&rightBudget);
    if (sqlite3_exec(a,"PRAGMA trusted_schema=OFF",NULL,NULL,NULL)!=SQLITE_OK ||
        sqlite3_exec(b,"PRAGMA trusted_schema=OFF",NULL,NULL,NULL)!=SQLITE_OK || cmeAdminSchema(a) || cmeAdminSchema(b)) goto done;
    for (table=0;table<2;table++)
    {
        const char *name=table ? "meta" : "data";
        if (sqlite3_prepare_v2(a,"SELECT sql FROM sqlite_master WHERE name=?1",-1,&left,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(b,"SELECT sql FROM sqlite_master WHERE name=?1",-1,&right,NULL)!=SQLITE_OK ||
            sqlite3_bind_text(left,1,name,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_bind_text(right,1,name,-1,SQLITE_STATIC)!=SQLITE_OK ||
            sqlite3_step(left)!=SQLITE_ROW || sqlite3_step(right)!=SQLITE_ROW || cmeOwnerCell(left,right,0)) goto done;
        sqlite3_finalize(left); left=NULL; sqlite3_finalize(right); right=NULL;
        if (sqlite3_prepare_v2(a,"PRAGMA integrity_check",-1,&left,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(b,"PRAGMA integrity_check",-1,&right,NULL)!=SQLITE_OK ||
            sqlite3_step(left)!=SQLITE_ROW || sqlite3_step(right)!=SQLITE_ROW ||
            strcmp((const char *)sqlite3_column_text(left,0),"ok") || strcmp((const char *)sqlite3_column_text(right,0),"ok") ||
            sqlite3_step(left)!=SQLITE_DONE || sqlite3_step(right)!=SQLITE_DONE) goto done;
        sqlite3_finalize(left); left=NULL; sqlite3_finalize(right); right=NULL;
        if (sqlite3_prepare_v2(a,table ? "SELECT * FROM meta WHERE id=?1" : "SELECT * FROM data WHERE id=?1",-1,&left,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(b,table ? "SELECT * FROM meta WHERE id=?1" : "SELECT * FROM data WHERE id=?1",-1,&right,NULL)!=SQLITE_OK) goto done;
        for (i=0;i<source->count;i++)
        {
            const cmeContextSlot *slot=&source->slots[i];
            if (strcmp(slot->table,name)) continue;
            for (j=0;j<approval->count;j++) if (cmeOwnerSameSlot(slot,&approval->slots[j])) break;
            if (j==approval->count || sqlite3_bind_int64(left,1,slot->row)!=SQLITE_OK ||
                sqlite3_bind_int64(right,1,approval->slots[j].row)!=SQLITE_OK ||
                sqlite3_step(left)!=SQLITE_ROW || sqlite3_step(right)!=SQLITE_ROW) goto done;
            for (column=1;column<sqlite3_column_count(left);column++) if (cmeOwnerCell(left,right,column)) goto done;
            for (column=1;column<sqlite3_column_count(left);column++)
                if (!strcmp(slot->field,sqlite3_column_name(left,column))) break;
            if (column==sqlite3_column_count(left) || sqlite3_step(left)!=SQLITE_DONE || sqlite3_step(right)!=SQLITE_DONE ||
                sqlite3_reset(left)!=SQLITE_OK || sqlite3_reset(right)!=SQLITE_OK) goto done;
            for (k=0;k<i;k++) if (!strcmp(source->slots[k].table,name) && source->slots[k].row==slot->row) break;
            if (k==i) rows[table]++;
        }
        sqlite3_finalize(left); left=NULL; sqlite3_finalize(right); right=NULL;
        if (sqlite3_prepare_v2(a,table ? "SELECT count(*) FROM meta" : "SELECT count(*) FROM data",-1,&left,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(b,table ? "SELECT count(*) FROM meta" : "SELECT count(*) FROM data",-1,&right,NULL)!=SQLITE_OK ||
            sqlite3_step(left)!=SQLITE_ROW || sqlite3_step(right)!=SQLITE_ROW ||
            sqlite3_column_int64(left,0)!=(sqlite3_int64)rows[table] || sqlite3_column_int64(right,0)!=(sqlite3_int64)rows[table]) goto done;
        sqlite3_finalize(left); left=NULL; sqlite3_finalize(right); right=NULL;
    }
    for (i=0;i<source->count;i++) if (strcmp(source->slots[i].table,"data") && strcmp(source->slots[i].table,"meta")) goto done;
    if (sqlite3_close(a)!=SQLITE_OK) goto done;
    a=NULL;
    if (sqlite3_close(b)!=SQLITE_OK) goto done;
    b=NULL;
    if (cmeOfflineVerify(&active) || cmeOfflineVerify(&staged)) goto done;
    result=0;
done:
    sqlite3_finalize(left); sqlite3_finalize(right); sqlite3_close(a); sqlite3_close(b);
    cmeOfflineClose(&active); cmeOfflineClose(&staged); return(result);
}

static int cmeOwnerRegisteredPaths(const cmeOwnerApproval *approval, const char *manifest,
                                   const char *managerKey, const char *witnessKey, const char *orgKey)
{
    char export[PATH_MAX],staging[PATH_MAX],expected[PATH_MAX],*slash;
    const char *controls[]={manifest,managerKey,witnessKey,orgKey};
    size_t i;
    strcpy(export,approval->values[7]); slash=strrchr(export,'/'); if (!slash) return(1); *slash=0;
    strcpy(staging,approval->values[8]); slash=strrchr(staging,'/'); if (!slash) return(1); *slash=0;
    if (snprintf(expected,sizeof(expected),"%s/ResourcesDB",export)>=(int)sizeof(expected) ||
        strcmp(expected,approval->values[13]) ||
        snprintf(expected,sizeof(expected),"%s/ResourcesDB",staging)>=(int)sizeof(expected) ||
        strcmp(expected,approval->values[14]) || !cmeOwnerOutside(export,staging) || !cmeOwnerOutside(staging,export)) return(1);
    for (i=0;i<4;i++)
        if (!controls[i] || !cmeOwnerOutside(export,controls[i]) || !cmeOwnerOutside(staging,controls[i]) ||
            !cmeOwnerOutside(approval->values[1],controls[i]) || !cmeOwnerOutside(approval->values[12],controls[i])) return(1);
    return(0);
}

static int cmeOwnerRegisteredDecode(const char *value, const char *saltText, const char *key,
                                    const char *profile, int prefixed, char **plain)
{
    char *salt=NULL,*tag=NULL,*decoded=NULL;
    unsigned char *frame=NULL;
    int written=0,size=0,frameLength=0,result=1;
    *plain=NULL;
    if (!value || !saltText || !(salt=strdup(saltText)) || strlen(salt)!=32 || strspn(salt,"0123456789abcdefABCDEF")!=32) goto done;
    if (prefixed)
    {
        if (strlen(value)<=64 || cmeHMACByteString((const unsigned char *)value+64,(unsigned char **)&tag,strlen(value+64),
            &written,cmeDefaultMACAlg,&salt,key) || written!=64 || CRYPTO_memcmp(value,tag,64)) goto done;
        value+=64;
    }
    if (cmeB64ToStr((unsigned char *)value,&frame,strlen(value),&frameLength) || !frame) goto done;
    if (!strcmp(profile,cmeHerraduraKExProfileHSKENLA1AEAD256))
    {
        if (frameLength<9 || memcmp(frame,cmeHerraduraKExFrameMagic,8) ||
            frame[8]!=cmeHerraduraKExProfileIdHSKENLA1AEAD256) goto done;
    }
    else if (frameLength>=7 && !memcmp(frame,"CDSEHKX",7)) goto done;
    if (cmeUnprotectByteString(value,&decoded,profile,&salt,key,&size,strlen(value)) || size<32 ||
        memchr(decoded,0,size) || strspn(decoded,"0123456789abcdefABCDEF")<32 || !(*plain=strdup(decoded+32))) goto done;
    result=0;
done:
    if (decoded) OPENSSL_cleanse(decoded,size>0 ? size : 1);
    free(frame); free(decoded); free(salt); free(tag); return(result);
}

static int cmeOwnerRegisteredValue(sqlite3_stmt *stmt, int column, const char *key,
                                   const char *profile, char **plain)
{
    char *value=cmeOwnerText(stmt,column,cmeContextRegistryMaxBytes),*salt=cmeOwnerText(stmt,3,32);
    int result=cmeOwnerRegisteredDecode(value,salt,key,profile,1,plain);
    free(value); free(salt); return(result);
}

static int cmeOwnerRegisteredColumn(sqlite3 *db, const char *key, const char *profile)
{
    static const char *attributes[]={"name","protect","shuffle","MAC","sign","MACProtected","signProtected"};
    const char *queries[]={"SELECT salt,attribute,attributeData,userId,orgId FROM meta ORDER BY id",
        "SELECT salt,value,userId,orgId,rowOrder FROM data ORDER BY id"};
    unsigned char seen[7]={0},orders[cmeContextRegistryMaxEntries]={0};
    sqlite3_stmt *stmt=NULL;
    char *salt=NULL,*value=NULL,*plain[4]={0};
    size_t rows=0;
    int table,column,result=1,step,i;
    if (cmeAdminSchema(db)) return(1);
    for (table=0;table<2;table++)
    {
        if (sqlite3_prepare_v2(db,queries[table],-1,&stmt,NULL)!=SQLITE_OK) goto done;
        while ((step=sqlite3_step(stmt))==SQLITE_ROW)
        {
            salt=cmeOwnerText(stmt,0,32);
            if (!salt) goto done;
            for (column=1;column<=4;column++)
            {
                value=cmeOwnerText(stmt,column,cmeContextRegistryMaxBytes);
                if (!value) goto done;
                if (table && column==4 && !seen[2]) plain[column-1]=strdup(value);
                else if (cmeOwnerRegisteredDecode(value,salt,key,profile,0,&plain[column-1])) goto done;
                if (!plain[column-1]) goto done;
                free(value); value=NULL;
            }
            if (!table)
            {
                for (i=0;i<7;i++) if (!strcmp(plain[0],attributes[i])) break;
                if (i==7 || seen[i]++) goto done;
                if ((i==1 || i==2) && strcmp(plain[1],profile)) goto done;
                if (i>=3 && strcmp(plain[1],cmeDefaultMACAlg)) goto done;
            }
            else
            {
                char *end=NULL;
                unsigned long long order;
                errno=0; order=strtoull(plain[3],&end,10);
                if (!*plain[3] || strspn(plain[3],"0123456789")!=strlen(plain[3]) || errno || !end || *end ||
                    !order || order>cmeContextRegistryMaxEntries || orders[order-1]++ || ++rows>cmeContextRegistryMaxEntries) goto done;
            }
            for (i=0;i<4;i++) { OPENSSL_cleanse(plain[i],strlen(plain[i])); free(plain[i]); plain[i]=NULL; }
            free(salt); salt=NULL;
        }
        if (step!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
        if (!table && !seen[1]) goto done;
    }
    for (i=0;i<(int)rows;i++) if (!orders[i]) goto done;
    if (cmeVerifyMemSecureDBIntegrity(db,key,profile,0)) goto done;
    result=0;
done:
    for (i=0;i<4;i++) if (plain[i]) { OPENSSL_cleanse(plain[i],strlen(plain[i])); free(plain[i]); }
    free(salt); free(value); sqlite3_finalize(stmt); return(result);
}

static int cmeOwnerRegisteredMAC(const cmeOfflineArtifact *artifact, const char *saltText,
                                 const char *key, const char *stored)
{
    char *bytes=NULL,*salt=NULL,*tag=NULL;
    off_t offset=0;
    int result=1,written=0;
    if (!(bytes=malloc((size_t)artifact->status.st_size)) || !(salt=strdup(saltText))) goto done;
    while (offset<artifact->status.st_size)
    {
        ssize_t got=pread(artifact->file,bytes+offset,(size_t)(artifact->status.st_size-offset),offset);
        if (got<0 && errno==EINTR) continue;
        if (got<=0) goto done;
        offset+=got;
    }
    if (cmeHMACByteString((const unsigned char *)bytes,(unsigned char **)&tag,(int)offset,&written,
        cmeDefaultMACAlg,&salt,key) || written!=64 || strlen(stored)!=64 || CRYPTO_memcmp(tag,stored,64) ||
        cmeOfflineVerify(artifact)) goto done;
    result=0;
done:
    free(bytes); free(salt); free(tag); return(result);
}

static int cmeOwnerRegisteredRow(sqlite3 *db, const cmeOwnerApproval *approval,
                                 const cmeOfflineArtifact *column, const char *key)
{
    static const char *names[]={"id","userId","orgId","salt","resourceInfo","columnFile","type","documentId",
        "storageId","orgResourceId","partMAC","totalParts","partId","lastModified","columnId",
        "documentIdLookup","storageIdLookup","orgResourceIdLookup"};
    static const int identity[]={7,8,9,14};
    sqlite3_stmt *stmt=NULL;
    char *plain[18]={0},*lookup=NULL;
    int result=1,i;
    if (sqlite3_prepare_v2(db,"SELECT * FROM documents WHERE id=?1",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_int64(stmt,1,approval->documentRow)!=SQLITE_OK || sqlite3_column_count(stmt)!=18) goto done;
    for (i=0;i<18;i++) if (strcmp(sqlite3_column_name(stmt,i),names[i])) goto done;
    if (sqlite3_step(stmt)!=SQLITE_ROW || sqlite3_column_type(stmt,0)!=SQLITE_INTEGER ||
        sqlite3_column_int64(stmt,0)!=approval->documentRow) goto done;
    for (i=1;i<15;i++) if (i!=3 && cmeOwnerRegisteredValue(stmt,i,key,approval->values[18],&plain[i])) goto done;
    if (strcmp(plain[5],strrchr(approval->values[7],'/')+1) || strcmp(plain[6],"file.csv") ||
        strcmp(plain[11],"1") || strcmp(plain[12],"1")) goto done;
    for (i=0;i<4;i++) if (strcmp(plain[identity[i]],approval->registration[i])) goto done;
    for (i=0;i<3;i++)
    {
        char *stored=cmeOwnerText(stmt,15+i,64);
        int bad=!stored || cmeGetProtectDBLookupValue(names[7+i],plain[7+i],key,&lookup) ||
            strlen(stored)!=64 || !lookup || strlen(lookup)!=64 || CRYPTO_memcmp(stored,lookup,64);
        free(stored); free(lookup); lookup=NULL;
        if (bad) goto done;
    }
    plain[3]=cmeOwnerText(stmt,3,32);
    if (!plain[3] || cmeOwnerRegisteredMAC(column,plain[3],key,plain[10]) || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    result=0;
done:
    for (i=0;i<18;i++) if (plain[i]) { OPENSSL_cleanse(plain[i],strlen(plain[i])); free(plain[i]); }
    free(lookup); sqlite3_finalize(stmt); return(result);
}

/* Every logical ResourcesDB cell remains exact except the selected encrypted
   partMAC. Whole-file hashes additionally pin physical bytes, including free pages. */
static int cmeOwnerRegisteredMetadata(sqlite3 *a, sqlite3 *b, const cmeOwnerApproval *approval, const char *key)
{
    static const char *tables[]={"documents","users","organizations","storage","filterWhitelist","filterBlacklist","schema_meta"};
    sqlite3_stmt *left=NULL,*right=NULL;
    char *query=NULL,*value=NULL,*storage=NULL,*organization=NULL,*type=NULL;
    size_t table,rows=0,selected=0,matches=0;
    int result=1,sa,sb,column;
    for (table=0;table<2;table++)
    {
        sqlite3 *db=table ? b : a;
        if (cmeCheckInternalDBSchema(db,"ResourcesDB",0) || sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type NOT IN ('table','index') OR "
            "tbl_name NOT IN ('documents','users','organizations','storage','filterWhitelist','filterBlacklist','schema_meta') "
            "UNION ALL SELECT 1 FROM pragma_table_list WHERE schema='main' AND type IN ('virtual','shadow')",
            -1,&left,NULL)!=SQLITE_OK || sqlite3_step(left)!=SQLITE_DONE) goto done;
        sqlite3_finalize(left); left=NULL;
        if (sqlite3_prepare_v2(db,"PRAGMA integrity_check",-1,&left,NULL)!=SQLITE_OK || sqlite3_step(left)!=SQLITE_ROW ||
            strcmp((const char *)sqlite3_column_text(left,0),"ok") || sqlite3_step(left)!=SQLITE_DONE) goto done;
        sqlite3_finalize(left); left=NULL;
    }
    for (table=0;table<8;table++)
    {
        query=table==7 ? sqlite3_mprintf("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name COLLATE BINARY") :
            sqlite3_mprintf("SELECT * FROM \"%w\" ORDER BY %s",tables[table],table==6 ? "key COLLATE BINARY" : "id");
        if (!query || sqlite3_prepare_v2(a,query,-1,&left,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(b,query,-1,&right,NULL)!=SQLITE_OK || sqlite3_column_count(left)!=sqlite3_column_count(right)) goto done;
        if (sqlite3_column_count(left)!=(table==0 ? 18 : (table==2 ? 8 : (table==6 ? 2 : (table==7 ? 4 : 12))))) goto done;
        sqlite3_free(query); query=NULL;
        for (column=0;column<sqlite3_column_count(left);column++)
            if (strcmp(sqlite3_column_name(left,column),sqlite3_column_name(right,column))) goto done;
        while ((sa=sqlite3_step(left))==SQLITE_ROW)
        {
            sb=sqlite3_step(right);
            if (sb!=SQLITE_ROW || ++rows>cmeContextRegistryMaxEntries) goto done;
            if (table<6 && (sqlite3_column_type(left,0)!=SQLITE_INTEGER || sqlite3_column_int64(left,0)<1)) goto done;
            for (column=0;column<sqlite3_column_count(left);column++)
                if ((table || column!=10 || sqlite3_column_int64(left,0)!=approval->documentRow) && cmeOwnerCell(left,right,column)) goto done;
            if (table==6)
            {
                const char *name=(const char *)sqlite3_column_text(left,0),*text=(const char *)sqlite3_column_text(left,1),*expected=NULL;
                char version[24];
                snprintf(version,sizeof(version),"%d",cmeInternalDBSchemaVersion);
                if (!name || !text || sqlite3_column_type(left,0)!=SQLITE_TEXT || sqlite3_column_type(left,1)!=SQLITE_TEXT ||
                    strlen(name)!=(size_t)sqlite3_column_bytes(left,0) || strlen(text)!=(size_t)sqlite3_column_bytes(left,1)) goto done;
                if (!strcmp(name,"schemaClass")) expected="ResourcesDB";
                else if (!strcmp(name,"schemaVersion")) expected=version;
                else if (!strcmp(name,"definitionsVersion")) expected=cmeInternalDBDefinitionsVersion;
                else if (!strcmp(name,"migrationState")) expected="complete";
                if (!expected || strcmp(text,expected)) goto done;
            }
            if (!table)
            {
                if (sqlite3_column_int64(left,0)==approval->documentRow) selected++;
                if (cmeOwnerRegisteredValue(left,5,key,approval->values[18],&value)) goto done;
                if (!strcmp(value,strrchr(approval->values[7],'/')+1) && sqlite3_column_int64(left,0)!=approval->documentRow) goto done;
                OPENSSL_cleanse(value,strlen(value)); free(value); value=NULL;
            }
        }
        if (sa!=SQLITE_DONE || sqlite3_step(right)!=SQLITE_DONE) goto done;
        sqlite3_finalize(left); left=NULL; sqlite3_finalize(right); right=NULL;
    }
    if (selected!=1 || sqlite3_prepare_v2(a,"SELECT * FROM storage",-1,&left,NULL)!=SQLITE_OK ||
        sqlite3_column_count(left)!=12) goto done;
    while ((sa=sqlite3_step(left))==SQLITE_ROW)
    {
        if (cmeOwnerRegisteredValue(left,7,key,approval->values[18],&storage) ||
            cmeOwnerRegisteredValue(left,11,key,approval->values[18],&organization)) goto done;
        if (!strcmp(storage,approval->registration[1]) && !strcmp(organization,approval->registration[2]))
        {
            if (++matches!=1 || cmeOwnerRegisteredValue(left,6,key,approval->values[18],&type) || strcmp(type,"local")) goto done;
            free(type); type=NULL;
        }
        OPENSSL_cleanse(storage,strlen(storage)); free(storage); storage=NULL;
        OPENSSL_cleanse(organization,strlen(organization)); free(organization); organization=NULL;
    }
    if (sa==SQLITE_DONE && matches==1) result=0;
done:
    if (value) { OPENSSL_cleanse(value,strlen(value)); free(value); }
    if (storage) { OPENSSL_cleanse(storage,strlen(storage)); free(storage); }
    if (organization) { OPENSSL_cleanse(organization,strlen(organization)); free(organization); }
    free(type); sqlite3_free(query); sqlite3_finalize(left); sqlite3_finalize(right); return(result);
}

static int cmeOwnerRegisteredVerify(const cmeOwnerApproval *approval, const char *key)
{
    const char *paths[]={approval->values[7],approval->values[8],approval->values[13],approval->values[14]};
    const unsigned char *pins[]={approval->source,approval->target,approval->resourcesSource,approval->resourcesTarget};
    cmeOfflineArtifact files[4];
    sqlite3 *db[4]={NULL,NULL,NULL,NULL};
    unsigned int budgets[4]={20000,20000,20000,20000};
    cmeCryptoProfile profile;
    char savedProfile[64];
    int i,j,result=1;
    for (i=0;i<4;i++) { memset(&files[i],0,sizeof(files[i])); files[i].file=-1; files[i].directory=-1; }
    strcpy(savedProfile,cmeDefaultEncAlg);
    if ((strcmp(approval->values[18],"aes-256-gcm") && strcmp(approval->values[18],"aes-256-cbc") &&
        strcmp(approval->values[18],cmeHerraduraKExProfileHSKENLA1AEAD256)) ||
        cmeGetCryptoProfile(&profile,approval->values[18]) || !profile.implemented || !profile.allowedAsDefault ||
        strlen(approval->values[18])>=sizeof(savedProfile)) goto done;
    strcpy(cmeDefaultEncAlg,approval->values[18]);
    for (i=0;i<4;i++)
    {
        if (cmeOfflineOpen(paths[i],1,&files[i]) || memcmp(files[i].digest,pins[i],32) ||
            sqlite3_open_v2(paths[i],&db[i],SQLITE_OPEN_READONLY|SQLITE_OPEN_NOFOLLOW,NULL)!=SQLITE_OK) goto done;
        sqlite3_limit(db[i],SQLITE_LIMIT_LENGTH,cmeContextRegistryMaxBytes);
        sqlite3_limit(db[i],SQLITE_LIMIT_SQL_LENGTH,65536);
        sqlite3_progress_handler(db[i],1000,cmeOwnerBudget,&budgets[i]);
        if (sqlite3_exec(db[i],"PRAGMA trusted_schema=OFF; BEGIN",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    }
    if (files[0].parent.st_dev==files[1].parent.st_dev && files[0].parent.st_ino==files[1].parent.st_ino) goto done;
    for (i=0;i<4;i++) for (j=0;j<i;j++)
        if (files[i].status.st_dev==files[j].status.st_dev && files[i].status.st_ino==files[j].status.st_ino) goto done;
    if (cmeOwnerRegisteredColumn(db[0],key,approval->values[18]) ||
        cmeOwnerRegisteredColumn(db[1],key,approval->values[18]) || cmeOwnerRegisteredRow(db[2],approval,&files[0],key) ||
        cmeOwnerRegisteredRow(db[3],approval,&files[1],key) || cmeOwnerRegisteredMetadata(db[2],db[3],approval,key)) goto done;
    for (i=0;i<4;i++)
        if (sqlite3_exec(db[i],"COMMIT",NULL,NULL,NULL)!=SQLITE_OK || cmeOfflineVerify(&files[i])) goto done;
    result=0;
done:
    strcpy(cmeDefaultEncAlg,savedProfile);
    for (i=0;i<4;i++) { sqlite3_close(db[i]); cmeOfflineClose(&files[i]); }
    return(result);
}

int cmeContextOwnerMain(int argc, char **argv)
{
    cmeOwnerApproval approval={0};
    cmeContextManager *manager=NULL;
    cmeContextMap *source=NULL;
    cmeContextBinding *binding=NULL;
    cmeContextShuffle *shuffle=NULL;
    cmeContextMapAnchor published={0};
    cmeContextWitness *witness=NULL;
    cmeContextWitnessState witnessed={0};
    cmeContextWitnessAnchor witnessExpected={0},witnessPublished={0};
    cmeContextWitnessRecovery recovery=cmeWitnessRecoveryInvalid;
    const char *manifest=NULL,*keyFile=NULL,*confirmation=NULL,*action=NULL,*jobText=NULL,*witnessFile=NULL,*witnessDirectory=NULL;
    const char *orgFile=NULL,*retainedToken=NULL;
    char *body=NULL,*keyText=NULL,*witnessText=NULL,*orgText=NULL;
    FILE *output=NULL,*diagnostics=NULL;
    unsigned char key[32]={0},witnessKey[32]={0},job[32]={0},bytes[40];
    int i,result=1,witnessCommand=argc>1 && !strcmp(argv[1],"context-witness");
    int registeredCommand=argc>1 && !strcmp(argv[1],"context-registered-shuffle");
    if (argc==3 && !strcmp(argv[2],"--help"))
    {
        puts("Usage: caumedse-admin (context-shuffle | context-witness | context-registered-shuffle)\n"
             "  --approval FILE --registry-key-file FILE\n"
             "  --confirmed-offline APPROVAL_REALPATH\n"
             "  Shuffle: (--init | --status | --prepare | --complete JOB_HEX | --abort JOB_HEX)\n"
             "  Schema 2/3: --witness-directory TRUSTED_DIRECTORY --witness-key-file FILE\n"
             "  Witness: (--init | --status | --advance WITNESS_TOKEN | --reconcile WITNESS_TOKEN)\n"
             "  Registered schema 3: --check --org-key-file FILE --retained-witness-token TOKEN\n"
             "Registered checks are floor-1-only and never install files or publish manager/witness state.\n"
             "Schemas 2/3 require witness directory and independent witness key; schema 1 is unchanged.\n"
             "Explicit registry/catalog pins, no automatic refresh. Witness advance is separately approved.\n"
             "Stop all readers/writers. Prepare verifies a complete byte-preserving row permutation.\n"
             "No encryption rotation, automatic backup/restore, live lease or V2 activation.");
        return(0);
    }
    for (i=2;i<argc;i++)
    {
        const char **option=NULL;
        if (!strcmp(argv[i],"--init") || !strcmp(argv[i],"--status") || !strcmp(argv[i],"--prepare") ||
            !strcmp(argv[i],"--complete") || !strcmp(argv[i],"--abort") || !strcmp(argv[i],"--advance") ||
            !strcmp(argv[i],"--reconcile") || !strcmp(argv[i],"--check"))
        {
            if (action) goto done;
            action=argv[i];
            if (!strcmp(action,"--complete") || !strcmp(action,"--abort") || !strcmp(action,"--advance") || !strcmp(action,"--reconcile"))
            { if (++i>=argc) goto done; jobText=argv[i]; }
            continue;
        }
        if (!strcmp(argv[i],"--approval")) option=&manifest;
        else if (!strcmp(argv[i],"--registry-key-file")) option=&keyFile;
        else if (!strcmp(argv[i],"--confirmed-offline")) option=&confirmation;
        else if (!strcmp(argv[i],"--witness-key-file")) option=&witnessFile;
        else if (!strcmp(argv[i],"--witness-directory")) option=&witnessDirectory;
        else if (!strcmp(argv[i],"--org-key-file")) option=&orgFile;
        else if (!strcmp(argv[i],"--retained-witness-token")) option=&retainedToken;
        if (!option || *option || ++i>=argc || !argv[i][0]) goto done;
        *option=argv[i];
    }
    if (!manifest || !keyFile || !confirmation || !action || strcmp(manifest,confirmation) ||
        cmeOwnerFile(manifest,cmeContextRegistryMaxBytes,&body) || cmeOwnerParse(body,&approval) ||
        cmeOwnerPaths(&approval,manifest,keyFile) || cmeOwnerFile(keyFile,65,&keyText)) goto done;
    if (strlen(keyText)==65 && keyText[64]=='\n') keyText[64]=0;
    if ((registeredCommand ? (approval.schema!=3 || strcmp(action,"--check") || !orgFile || !retainedToken ||
        approval.registry.minimumFormat!=1) :
        (approval.schema==3 || orgFile || retainedToken || !strcmp(action,"--check"))) ||
        cmeOwnerHex(keyText,key,32) || (!witnessCommand && jobText && cmeOwnerHex(jobText,job,32)) ||
        (witnessCommand && strcmp(action,"--init") && strcmp(action,"--status") && strcmp(action,"--advance") && strcmp(action,"--reconcile")) ||
        (!witnessCommand && (!strcmp(action,"--advance") || !strcmp(action,"--reconcile"))) ||
        (approval.schema==1 && (witnessCommand || witnessFile || witnessDirectory)) ||
        cmeContextManagerOpen(approval.values[1],0,key,approval.deployment,approval.organization,&manager)) goto done;
    if (approval.schema>=2)
    {
        if (!witnessDirectory || strcmp(witnessDirectory,approval.values[12]) ||
            cmeOwnerWitnessPaths(&approval,manifest,keyFile,witnessFile) || cmeOwnerFile(witnessFile,65,&witnessText)) goto done;
        if (strlen(witnessText)==65 && witnessText[64]=='\n') witnessText[64]=0;
        if (cmeOwnerHex(witnessText,witnessKey,32) || !CRYPTO_memcmp(key,witnessKey,32)) goto done;
        result=cmeContextManagerCheckAnchors(manager,&approval.registry,&approval.catalog); if (result) goto done;
        result=1;
        if (cmeContextWitnessOpen(approval.values[12],witnessCommand && !strcmp(action,"--init"),witnessKey,
            approval.deployment,approval.organization,&approval.registry,&approval.catalog,&witness)) goto done;
        if (registeredCommand)
        {
            if (cmeOwnerHex(retainedToken,bytes,40)) goto done;
            for (i=0;i<8;i++) witnessExpected.revision=(witnessExpected.revision<<8)|bytes[i];
            memcpy(witnessExpected.digest,bytes+8,32);
            result=cmeContextWitnessReconcile(witness,&witnessExpected,&approval.registry,&approval.catalog,&recovery,&witnessPublished);
            if (result) goto done;
            if (recovery!=cmeWitnessRecoveryCurrent) { result=2; goto done; }
        }
        else if (witnessCommand && (!strcmp(action,"--advance") || !strcmp(action,"--reconcile")))
        {
            if (!jobText || cmeOwnerHex(jobText,bytes,40)) goto done;
            for (i=0;i<8;i++) witnessExpected.revision=(witnessExpected.revision<<8)|bytes[i];
            memcpy(witnessExpected.digest,bytes+8,32);
            if (!strcmp(action,"--reconcile"))
                result=cmeContextWitnessReconcile(witness,&witnessExpected,&approval.registry,&approval.catalog,&recovery,&witnessPublished);
            else result=cmeContextWitnessAdvance(witness,&witnessExpected,&approval.registry,&approval.catalog,&witnessPublished);
            if (result) goto done;
        }
        else
        { result=cmeContextWitnessCheck(witness,&approval.registry,&approval.catalog); if (result) goto done; }
        if (witnessCommand)
        {
            if (!strcmp(action,"--advance") || !strcmp(action,"--reconcile")) witnessed.anchor=witnessPublished;
            else
            {
                result=cmeContextWitnessFetch(witness,&witnessed); if (result) goto done;
                if (witnessed.registry.generation!=approval.registry.generation ||
                    witnessed.registry.minimumFormat!=approval.registry.minimumFormat ||
                    memcmp(witnessed.registry.digest,approval.registry.digest,32) ||
                    witnessed.catalog.revision!=approval.catalog.revision || memcmp(witnessed.catalog.digest,approval.catalog.digest,32))
                { result=2; goto done; }
            }
            printf("state=%s\nwitness=",recovery==cmeWitnessRecoveryAdvanceRequired ? "advance-required" :
                (recovery==cmeWitnessRecoveryAlreadyAdvanced ? "already-advanced" : "current"));
            for (i=0;i<8;i++) bytes[i]=(unsigned char)(witnessed.anchor.revision>>(56-8*i));
            cmeOwnerPrint(bytes,8); cmeOwnerPrint(witnessed.anchor.digest,32); putchar('\n');
            goto done;
        }
    }
    if (registeredCommand)
    {
        result=1;
        if (cmeOwnerRegisteredPaths(&approval,manifest,keyFile,witnessFile,orgFile) || cmeOwnerFile(orgFile,257,&orgText)) goto done;
        if (orgText[strlen(orgText)-1]=='\n') orgText[strlen(orgText)-1]=0;
        if (!*orgText || strlen(orgText)>256) goto done;
        result=cmeContextManagerMapRead(manager,approval.values[4],&approval.registry,&approval.catalog,&source);
        if (result) goto done;
        result=1;
        if (!source->active || source->blocked || source->role!=4 || cmeOwnerPermutation(&approval,source)) goto done;
        result=cmeContextManagerMapBind(manager,approval.values[4],&approval.registry,&approval.catalog,&binding);
        if (result) goto done;
        result=1;
        output=fdopen(dup(STDOUT_FILENO),"w"); diagnostics=fdopen(dup(STDERR_FILENO),"w");
        if (!output || !diagnostics || fflush(NULL) || !freopen("/dev/null","w",stdout) || !freopen("/dev/null","w",stderr)) goto done;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        OpenSSL_add_all_algorithms();
#else
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS,NULL);
#endif
        if (cmeOwnerRegisteredVerify(&approval,orgText)) goto done;
        result=cmeContextBindingCheck(manager,binding); if (result) goto done;
        result=cmeContextManagerCheckAnchors(manager,&approval.registry,&approval.catalog); if (result) goto done;
        result=cmeContextWitnessReconcile(witness,&witnessExpected,&approval.registry,&approval.catalog,&recovery,&witnessPublished);
        if (result) goto done;
        if (recovery!=cmeWitnessRecoveryCurrent) { result=2; goto done; }
        fprintf(output,"state=verified-pair\npublication=disabled\n");
        goto done;
    }
    if (!strcmp(action,"--init"))
        result=cmeContextManagerShuffleInit(manager,&approval.registry,&approval.catalog,&published);
    else if (!strcmp(action,"--prepare"))
    {
        result=cmeContextManagerMapRead(manager,approval.values[4],&approval.registry,&approval.catalog,&source);
        if (result) goto done;
        result=1; if (!source->active || source->blocked || source->role!=4) goto done;
        result=cmeContextManagerBind(manager,source->resource,4,approval.slots,approval.count,&approval.registry,&binding);
        if (result) goto done;
        result=1; if (cmeOwnerPermutation(&approval,source)) goto done;
        result=cmeContextManagerShufflePrepare(manager,approval.values[4],approval.values[7],approval.values[8],
            approval.source,approval.target,approval.slots,approval.count,&approval.registry,&approval.catalog,job,&published);
    }
    else
    {
        result=cmeContextManagerShuffleRead(manager,approval.values[4],&approval.registry,&approval.catalog,&shuffle);
        if (result) goto done;
        result=1; if (cmeOwnerReceipt(&approval,shuffle)) goto done;
        if (!strcmp(action,"--status")) { published=approval.catalog; memcpy(job,shuffle->job,32); result=0; }
        else result=cmeContextManagerShuffleRecover(manager,approval.values[4],job,!strcmp(action,"--complete"),
            &approval.registry,&approval.catalog,&published);
    }
    if (!result)
    {
        printf("state=%s\n",!strcmp(action,"--status") ?
            (shuffle->state==1 ? "prepared" : (shuffle->state==2 ? "completed" : "aborted")) : action+2);
        if (!strcmp(action,"--prepare") || !strcmp(action,"--status"))
        { printf("job="); cmeOwnerPrint(job,32); putchar('\n'); }
        for (i=0;i<8;i++) bytes[i]=(unsigned char)(published.revision>>(56-8*i));
        printf("catalog="); cmeOwnerPrint(bytes,8); cmeOwnerPrint(published.digest,32); putchar('\n');
    }
done:
    if (result) fprintf(diagnostics ? diagnostics : stderr,"%s: %s\n",
        registeredCommand ? "context-registered-shuffle" : (witnessCommand ? "context-witness" : "context-shuffle"),
        result==2 ? "stale approval; reconcile owner pins" : "invalid approval or unavailable state");
    if (keyText) { OPENSSL_cleanse(keyText,strlen(keyText)); free(keyText); }
    if (witnessText) { OPENSSL_cleanse(witnessText,strlen(witnessText)); free(witnessText); }
    if (orgText) { OPENSSL_cleanse(orgText,strlen(orgText)); free(orgText); }
    OPENSSL_cleanse(key,sizeof(key)); OPENSSL_cleanse(witnessKey,sizeof(witnessKey));
    if (body) { OPENSSL_cleanse(body,strlen(body)); free(body); }
    cmeOwnerFree(&approval);
    cmeContextWitnessClose(&witness);
    if (output) fclose(output);
    if (diagnostics) fclose(diagnostics);
    cmeContextBindingFree(&binding); cmeContextMapFree(&source); cmeContextShuffleFree(&shuffle);
    cmeContextManagerClose(&manager); return(result);
}
