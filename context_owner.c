/* Explicit local owner approval for offline, byte-preserving ColumnFile moves. */
#include "admin.h"
#include "context_manager.h"
#include "context_offline.h"

typedef struct
{
    char *values[12];
    cmeContextSlot *slots;
    size_t count;
    unsigned char deployment[16],organization[16],source[32],target[32];
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
    for (i=0;i<12;i++) free(approval->values[i]);
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
        "catalog","active","staged","source","target","slots"};
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
        for (i=0;i<12;i++) if (!strcmp(key,names[i])) break;
        if (i==12 || approval->values[i] || strcmp(type,i==0 ? "integer" : (i==11 ? "array" : "text"))) goto done;
        if (!i)
        {
            if (sqlite3_column_type(stmt,2)!=SQLITE_INTEGER || sqlite3_column_int64(stmt,2)!=1) goto done;
            approval->values[i]=strdup("1");
        }
        else approval->values[i]=cmeOwnerText(stmt,2,i==11 ? cmeContextRegistryMaxBytes : PATH_MAX-1);
        if (!approval->values[i]) goto done;
        seen++;
    }
    if (step!=SQLITE_DONE || seen!=12 || cmeOwnerHex(approval->values[2],approval->deployment,16) ||
        cmeOwnerHex(approval->values[3],approval->organization,16) || cmeOwnerHex(approval->values[5],bytes,73)) goto done;
    memcpy(approval->registry.deployment,bytes,16); memcpy(approval->registry.organization,bytes+16,16);
    for (i=0;i<8;i++) approval->registry.generation=(approval->registry.generation<<8)|bytes[32+i];
    approval->registry.minimumFormat=bytes[40]; memcpy(approval->registry.digest,bytes+41,32);
    if (memcmp(approval->deployment,bytes,16) || memcmp(approval->organization,bytes+16,16) ||
        cmeOwnerHex(approval->values[6],bytes,40) || cmeOwnerHex(approval->values[9],approval->source,32) ||
        cmeOwnerHex(approval->values[10],approval->target,32)) goto done;
    for (i=0;i<8;i++) approval->catalog.revision=(approval->catalog.revision<<8)|bytes[i];
    memcpy(approval->catalog.digest,bytes+8,32);
    sqlite3_finalize(stmt); stmt=NULL;
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

int cmeContextOwnerMain(int argc, char **argv)
{
    cmeOwnerApproval approval={0};
    cmeContextManager *manager=NULL;
    cmeContextMap *source=NULL;
    cmeContextBinding *binding=NULL;
    cmeContextShuffle *shuffle=NULL;
    cmeContextMapAnchor published={0};
    const char *manifest=NULL,*keyFile=NULL,*confirmation=NULL,*action=NULL,*jobText=NULL;
    char *body=NULL,*keyText=NULL;
    unsigned char key[32]={0},job[32]={0},bytes[8];
    int i,result=1;
    if (argc==3 && !strcmp(argv[2],"--help"))
    {
        puts("Usage: caumedse-admin context-shuffle --approval FILE --registry-key-file FILE\n"
             "  --confirmed-offline APPROVAL_REALPATH\n"
             "  (--init | --status | --prepare | --complete JOB_HEX | --abort JOB_HEX)\n"
             "Private owner approval schema 1; explicit registry/catalog pins, no automatic refresh.\n"
             "Stop all readers/writers. Prepare verifies a complete byte-preserving row permutation.\n"
             "No encryption rotation, automatic backup/restore, live lease or V2 activation.");
        return(0);
    }
    for (i=2;i<argc;i++)
    {
        const char **option=NULL;
        if (!strcmp(argv[i],"--init") || !strcmp(argv[i],"--status") || !strcmp(argv[i],"--prepare") ||
            !strcmp(argv[i],"--complete") || !strcmp(argv[i],"--abort"))
        {
            if (action) goto done;
            action=argv[i];
            if (!strcmp(action,"--complete") || !strcmp(action,"--abort"))
            { if (++i>=argc) goto done; jobText=argv[i]; }
            continue;
        }
        if (!strcmp(argv[i],"--approval")) option=&manifest;
        else if (!strcmp(argv[i],"--registry-key-file")) option=&keyFile;
        else if (!strcmp(argv[i],"--confirmed-offline")) option=&confirmation;
        if (!option || *option || ++i>=argc || !argv[i][0]) goto done;
        *option=argv[i];
    }
    if (!manifest || !keyFile || !confirmation || !action || strcmp(manifest,confirmation) ||
        cmeOwnerFile(manifest,cmeContextRegistryMaxBytes,&body) || cmeOwnerParse(body,&approval) ||
        cmeOwnerPaths(&approval,manifest,keyFile) || cmeOwnerFile(keyFile,65,&keyText)) goto done;
    if (strlen(keyText)==65 && keyText[64]=='\n') keyText[64]=0;
    if (cmeOwnerHex(keyText,key,32) || (jobText && cmeOwnerHex(jobText,job,32)) ||
        cmeContextManagerOpen(approval.values[1],0,key,approval.deployment,approval.organization,&manager)) goto done;
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
    if (result) fputs(result==2 ? "context-shuffle: stale approval; reconcile owner pins\n" :
        "context-shuffle: invalid approval or unavailable state\n",stderr);
    if (keyText) { OPENSSL_cleanse(keyText,strlen(keyText)); free(keyText); }
    OPENSSL_cleanse(key,sizeof(key)); free(body); cmeOwnerFree(&approval);
    cmeContextBindingFree(&binding); cmeContextMapFree(&source); cmeContextShuffleFree(&shuffle);
    cmeContextManagerClose(&manager); return(result);
}
