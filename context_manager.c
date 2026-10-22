#include "common.h"
#include "context_manager.h"
#include "context_offline.h"
#include <limits.h>
#include <openssl/rand.h>

#define CME_ANCHOR_BYTES 73

struct cmeContextManager
{
    sqlite3 *db;
    int directory;
    dev_t device;
    ino_t inode;
    pthread_mutex_t mutex;
    unsigned char key[32], deployment[16], organization[16];
};

typedef struct
{
    unsigned char *body,tag[32];
    size_t length;
    int initialized;
    cmeContextAnchor anchor;
} cmeManagerState;

static int cmeMapLoad(cmeContextManager *manager, cmeContextMapAnchor *anchor);
static int cmeMapMatch(const cmeContextMapAnchor *actual, const cmeContextMapAnchor *expected);
static int cmeShufflePending(cmeContextManager *manager, const char *name, int *pending);

static int cmeManagerAnchorFetch(void *opaque, const unsigned char deployment[16],
                                const unsigned char organization[16], cmeContextAnchor *anchor)
{
    const cmeContextAnchor *expected=opaque;
    if (memcmp(deployment,expected->deployment,16) || memcmp(organization,expected->organization,16)) return(1);
    *anchor=*expected;
    return(0);
}

static int cmeManagerAnchorPack(const cmeContextAnchor *anchor, unsigned char bytes[CME_ANCHOR_BYTES])
{
    unsigned int i,dep=0,org=0;
    if (!anchor || !anchor->generation || (anchor->minimumFormat!=1 && anchor->minimumFormat!=2)) return(1);
    for (i=0;i<16;i++) { dep|=anchor->deployment[i]; org|=anchor->organization[i]; }
    if (!dep || !org) return(1);
    memcpy(bytes,anchor->deployment,16); memcpy(bytes+16,anchor->organization,16);
    for (i=0;i<8;i++) bytes[32+i]=(unsigned char)(anchor->generation>>(56-8*i));
    bytes[40]=(unsigned char)anchor->minimumFormat;
    memcpy(bytes+41,anchor->digest,32);
    return(0);
}

static int cmeManagerAnchorUnpack(const unsigned char *bytes, cmeContextAnchor *anchor)
{
    unsigned int i;
    unsigned char canonical[CME_ANCHOR_BYTES];
    memset(anchor,0,sizeof(*anchor));
    memcpy(anchor->deployment,bytes,16); memcpy(anchor->organization,bytes+16,16);
    for (i=0;i<8;i++) anchor->generation=(anchor->generation<<8)|bytes[32+i];
    anchor->minimumFormat=bytes[40]; memcpy(anchor->digest,bytes+41,32);
    return(cmeManagerAnchorPack(anchor,canonical));
}

static int cmeManagerPrivate(cmeContextManager *manager)
{
    struct stat directory,file;
    return(fstat(manager->directory,&directory) || !S_ISDIR(directory.st_mode) ||
           directory.st_uid!=geteuid() || (directory.st_mode&07777)!=0700 || !directory.st_nlink ||
           fstatat(manager->directory,"registry.sqlite",&file,AT_SYMLINK_NOFOLLOW) ||
           !S_ISREG(file.st_mode) || file.st_uid!=geteuid() || (file.st_mode&07777)!=0600 ||
           file.st_nlink!=1 || file.st_dev!=manager->device || file.st_ino!=manager->inode);
}

static void cmeManagerStateFree(cmeManagerState *state)
{
    free(state->body); memset(state,0,sizeof(*state));
}

/* Caller holds the manager mutex and a SQLite transaction. Never repair a
   missing/corrupt publication or infer a fresh bootstrap from an empty table. */
static int cmeManagerLoad(cmeContextManager *manager, cmeManagerState *state)
{
    sqlite3_stmt *stmt=NULL;
    cmeContextRegistry *verified=NULL;
    int result=1,step;
    if (sqlite3_prepare_v2(manager->db,"SELECT schema_version,deployment,organization,initialized FROM registry_meta WHERE singleton=1",
                           -1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW) goto done;
    if (sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || sqlite3_column_int64(stmt,0)!=1 ||
        sqlite3_column_type(stmt,1)!=SQLITE_BLOB || sqlite3_column_bytes(stmt,1)!=16 ||
        sqlite3_column_type(stmt,2)!=SQLITE_BLOB || sqlite3_column_bytes(stmt,2)!=16 ||
        !sqlite3_column_blob(stmt,1) || !sqlite3_column_blob(stmt,2) ||
        memcmp(sqlite3_column_blob(stmt,1),manager->deployment,16) ||
        memcmp(sqlite3_column_blob(stmt,2),manager->organization,16) ||
        sqlite3_column_type(stmt,3)!=SQLITE_INTEGER ||
        (sqlite3_column_int64(stmt,3)!=0 && sqlite3_column_int64(stmt,3)!=1)) goto done;
    state->initialized=sqlite3_column_int(stmt,3);
    if ((state->initialized!=0 && state->initialized!=1) || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(manager->db,"SELECT anchor,body,tag FROM registry_current WHERE singleton=1",
                           -1,&stmt,NULL)!=SQLITE_OK) goto done;
    step=sqlite3_step(stmt);
    if (step==SQLITE_DONE && !state->initialized) { result=0; goto done; }
    if (step!=SQLITE_ROW || !state->initialized || sqlite3_column_type(stmt,0)!=SQLITE_BLOB ||
        sqlite3_column_bytes(stmt,0)!=CME_ANCHOR_BYTES || !sqlite3_column_blob(stmt,0) ||
        sqlite3_column_type(stmt,1)!=SQLITE_BLOB || sqlite3_column_bytes(stmt,1)<1 ||
        sqlite3_column_bytes(stmt,1)>(int)cmeContextRegistryMaxBytes || !sqlite3_column_blob(stmt,1) ||
        sqlite3_column_type(stmt,2)!=SQLITE_BLOB || sqlite3_column_bytes(stmt,2)!=32 ||
        !sqlite3_column_blob(stmt,2)) goto done;
    if (cmeManagerAnchorUnpack(sqlite3_column_blob(stmt,0),&state->anchor)) goto done;
    state->length=(size_t)sqlite3_column_bytes(stmt,1);
    state->body=malloc(state->length+1);
    if (!state->body) goto done;
    memcpy(state->body,sqlite3_column_blob(stmt,1),state->length); state->body[state->length]=0;
    memcpy(state->tag,sqlite3_column_blob(stmt,2),32);
    if (sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (cmeContextRegistryOpen(state->body,state->length,state->tag,32,manager->key,32,
        manager->deployment,manager->organization,cmeManagerAnchorFetch,&state->anchor,&verified)) goto done;
    result=0;
done:
    sqlite3_finalize(stmt); cmeContextRegistryFree(&verified);
    if (result) cmeManagerStateFree(state);
    return(result);
}

void cmeContextManagerClose(cmeContextManager **manager)
{
    if (!manager || !*manager) return;
    sqlite3_close((*manager)->db);
    if ((*manager)->directory>=0) close((*manager)->directory);
    pthread_mutex_destroy(&(*manager)->mutex);
    OPENSSL_cleanse((*manager)->key,32);
    free(*manager); *manager=NULL;
}

int cmeContextManagerOpen(const char *directory, int create, const unsigned char key[32],
                          const unsigned char deployment[16], const unsigned char organization[16],
                          cmeContextManager **manager)
{
    char canonical[PATH_MAX],path[PATH_MAX];
    struct stat st,opened;
    sqlite3_stmt *stmt=NULL;
    cmeContextManager *candidate=NULL;
    cmeManagerState state={0};
    unsigned int i,dep=0,org=0;
    int fd=-1,result=1;
    if (manager) *manager=NULL;
    if (!manager || !directory || !key || !deployment || !organization || (create!=0 && create!=1) ||
        !realpath(directory,canonical) || strcmp(directory,canonical) || lstat(directory,&st) ||
        !S_ISDIR(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&07777)!=0700 ||
        snprintf(path,sizeof(path),"%s/registry.sqlite",canonical)>=(int)sizeof(path)) return(1);
    for (i=0;i<16;i++) { dep|=deployment[i]; org|=organization[i]; }
    if (!dep || !org) return(1);
    candidate=calloc(1,sizeof(*candidate));
    if (!candidate) return(1);
    candidate->directory=-1;
    if (pthread_mutex_init(&candidate->mutex,NULL)) { free(candidate); return(1); }
    candidate->directory=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if (candidate->directory<0 || fstat(candidate->directory,&opened) ||
        st.st_dev!=opened.st_dev || st.st_ino!=opened.st_ino) goto done;
    /* Extra descriptors on an existing SQLite DB can release another connection's
       process-wide POSIX locks when closed. Use metadata checks, not an extra open. */
    if (create)
    {
        fd=openat(candidate->directory,"registry.sqlite",O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_CREAT|O_EXCL,0600);
        if (fd<0 || fstat(fd,&st)) goto done;
        close(fd); fd=-1;
    }
    else if (fstatat(candidate->directory,"registry.sqlite",&st,AT_SYMLINK_NOFOLLOW)) goto done;
    candidate->device=st.st_dev; candidate->inode=st.st_ino;
    if (cmeManagerPrivate(candidate)) goto done;
    memcpy(candidate->key,key,32); memcpy(candidate->deployment,deployment,16);
    memcpy(candidate->organization,organization,16);
#ifdef SQLITE_OPEN_NOFOLLOW
    if (sqlite3_open_v2(path,&candidate->db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_FULLMUTEX|SQLITE_OPEN_NOFOLLOW,NULL)!=SQLITE_OK) goto done;
#else
    goto done;
#endif
    if (cmeManagerPrivate(candidate) || sqlite3_busy_timeout(candidate->db,5000)!=SQLITE_OK ||
        sqlite3_exec(candidate->db,"PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA trusted_schema=OFF;",NULL,NULL,NULL)!=SQLITE_OK ||
        sqlite3_prepare_v2(candidate->db,"PRAGMA synchronous",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_ROW || sqlite3_column_int(stmt,0)!=3) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(candidate->db,"PRAGMA journal_mode",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_ROW || !sqlite3_column_text(stmt,0) ||
        strcmp((const char *)sqlite3_column_text(stmt,0),"delete")) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (create)
    {
        if (sqlite3_exec(candidate->db,"BEGIN IMMEDIATE;"
            "CREATE TABLE registry_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL CHECK(schema_version=1),deployment BLOB NOT NULL CHECK(length(deployment)=16),organization BLOB NOT NULL CHECK(length(organization)=16),initialized INTEGER NOT NULL CHECK(initialized IN(0,1)));"
            "CREATE TABLE registry_current(singleton INTEGER PRIMARY KEY CHECK(singleton=1),anchor BLOB NOT NULL CHECK(length(anchor)=73),body BLOB NOT NULL,tag BLOB NOT NULL CHECK(length(tag)=32));",
            NULL,NULL,NULL)!=SQLITE_OK || sqlite3_prepare_v2(candidate->db,
            "INSERT INTO registry_meta VALUES(1,1,?1,?2,0)",-1,&stmt,NULL)!=SQLITE_OK ||
            sqlite3_bind_blob(stmt,1,deployment,16,SQLITE_STATIC)!=SQLITE_OK ||
            sqlite3_bind_blob(stmt,2,organization,16,SQLITE_STATIC)!=SQLITE_OK ||
            sqlite3_step(stmt)!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
        if (sqlite3_exec(candidate->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK || fsync(candidate->directory)) goto done;
    }
    if (sqlite3_exec(candidate->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK || cmeManagerLoad(candidate,&state) ||
        sqlite3_exec(candidate->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    *manager=candidate; candidate=NULL; result=0;
done:
    sqlite3_finalize(stmt); cmeManagerStateFree(&state);
    if (fd>=0) close(fd);
    if (candidate && candidate->db && !sqlite3_get_autocommit(candidate->db)) sqlite3_exec(candidate->db,"ROLLBACK",NULL,NULL,NULL);
    cmeContextManagerClose(&candidate);
    return(result);
}

int cmeContextManagerSnapshot(cmeContextManager *manager, unsigned char **body, size_t *length,
                              unsigned char tag[32], cmeContextAnchor *anchor)
{
    cmeManagerState state={0};
    int result=1;
    if (body) *body=NULL;
    if (length) *length=0;
    if (tag) memset(tag,0,32);
    if (anchor) memset(anchor,0,sizeof(*anchor));
    if (!manager || !body || !length || !tag || !anchor) return(1);
    pthread_mutex_lock(&manager->mutex);
    if (cmeManagerPrivate(manager) || sqlite3_exec(manager->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeManagerLoad(manager,&state) || !state.initialized ||
        sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    *body=state.body; state.body=NULL; *length=state.length; *anchor=state.anchor;
    memcpy(tag,state.tag,32); result=0;
done:
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex);
    return(result);
}

int cmeContextManagerFetch(void *opaque, const unsigned char deployment[16],
                           const unsigned char organization[16], cmeContextAnchor *anchor)
{
    cmeContextManager *manager=opaque;
    unsigned char *body=NULL,tag[32];
    size_t length=0;
    int result=1;
    if (anchor) memset(anchor,0,sizeof(*anchor));
    if (!manager || !deployment || !organization || !anchor ||
        memcmp(deployment,manager->deployment,16) || memcmp(organization,manager->organization,16)) return(1);
    if (!cmeContextManagerSnapshot(manager,&body,&length,tag,anchor)) result=0;
    free(body);
    return(result);
}

static void cmeManagerCheckpoint(const char *point)
{
#ifdef CDSE_CONTEXT_MANAGER_TESTING
    const char *requested=getenv("CDSE_CONTEXT_MANAGER_CRASH");
    if (requested && !strcmp(requested,point)) _exit(86);
    requested=getenv("CDSE_CONTEXT_MANAGER_PAUSE");
    if (requested && !strcmp(requested,point))
    {
        const char *ready=getenv("CDSE_CONTEXT_MANAGER_READY_FD"),*resume=getenv("CDSE_CONTEXT_MANAGER_RESUME_FD");
        char byte;
        if (!ready || !resume || atoi(ready)<3 || atoi(resume)<3 ||
            write(atoi(ready),"1",1)!=1 || read(atoi(resume),&byte,1)!=1) _exit(87);
    }
#else
    (void)point;
#endif
}

static int cmeManagerPublishPinned(cmeContextManager *manager, const unsigned char *body, size_t length,
                             const unsigned char tag[32], const cmeContextAnchor *next,
                             const cmeContextAnchor *expected, const cmeContextMapAnchor *catalog,
                             const char *sourceMap, int retry)
{
    cmeContextRegistry *verified=NULL;
    cmeManagerState state={0};
    sqlite3_stmt *stmt=NULL;
    unsigned char nextBytes[CME_ANCHOR_BYTES],expectedBytes[CME_ANCHOR_BYTES],currentBytes[CME_ANCHOR_BYTES];
    int result=1;
    if (!manager || !body || !tag || cmeManagerAnchorPack(next,nextBytes) ||
        (expected && cmeManagerAnchorPack(expected,expectedBytes)) ||
        cmeContextRegistryOpen(body,length,tag,32,manager->key,32,manager->deployment,
            manager->organization,cmeManagerAnchorFetch,(void *)next,&verified)) return(1);
    cmeContextRegistryFree(&verified);
    pthread_mutex_lock(&manager->mutex);
    if (cmeManagerPrivate(manager) || sqlite3_exec(manager->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeManagerLoad(manager,&state)) goto done;
    if (catalog)
    {
        cmeContextMapAnchor current={0};
        int pending=0;
        if (cmeMapLoad(manager,&current)) goto done;
        result=cmeMapMatch(&current,catalog); if (result) goto done;
        result=1;
        if (cmeShufflePending(manager,sourceMap,&pending) || pending) goto done;
    }
    cmeManagerCheckpoint("after-begin");
    if (retry && state.initialized && !cmeManagerAnchorPack(&state.anchor,currentBytes) &&
        !CRYPTO_memcmp(currentBytes,nextBytes,CME_ANCHOR_BYTES)) { result=0; goto done; }
    if ((!state.initialized && expected) || (state.initialized && !expected)) { result=2; goto done; }
    if (state.initialized)
    {
        if (cmeManagerAnchorPack(&state.anchor,currentBytes)) goto done;
        if (CRYPTO_memcmp(currentBytes,expectedBytes,CME_ANCHOR_BYTES)) { result=2; goto done; }
        if (state.anchor.generation==UINT64_MAX || next->generation!=state.anchor.generation+1 ||
            next->minimumFormat<state.anchor.minimumFormat) goto done;
        if (sqlite3_prepare_v2(manager->db,
            "SELECT 1 FROM json_each(?1,'$.entries') AS old LEFT JOIN json_each(?2,'$.entries') AS new "
            "ON json_extract(old.value,'$.lookup')=json_extract(new.value,'$.lookup') "
            "WHERE new.value IS NULL OR json_extract(old.value,'$.context')!=json_extract(new.value,'$.context') "
            "OR (json_extract(old.value,'$.state')='revoked' AND json_extract(new.value,'$.state')!='revoked') LIMIT 1",
            -1,&stmt,NULL)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,1,(const char *)state.body,(int)state.length,SQLITE_STATIC)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,2,(const char *)body,(int)length,SQLITE_STATIC)!=SQLITE_OK ||
            sqlite3_step(stmt)!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
    }
    else if (next->generation!=1 || next->minimumFormat!=1) goto done;
    if (sqlite3_prepare_v2(manager->db,
        "INSERT INTO registry_current VALUES(1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET anchor=excluded.anchor,body=excluded.body,tag=excluded.tag",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_bind_blob(stmt,1,nextBytes,CME_ANCHOR_BYTES,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,2,body,(int)length,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,3,tag,32,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_exec(manager->db,"UPDATE registry_meta SET initialized=1 WHERE singleton=1",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    cmeManagerCheckpoint("after-write");
    if (sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    cmeManagerCheckpoint("after-commit");
    result=0;
done:
    sqlite3_finalize(stmt);
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex);
    return(result);
}

int cmeContextManagerPublish(cmeContextManager *manager, const unsigned char *body, size_t length,
                             const unsigned char tag[32], const cmeContextAnchor *next,
                             const cmeContextAnchor *expected)
{
    return(cmeManagerPublishPinned(manager,body,length,tag,next,expected,NULL,NULL,0));
}

static int cmeManagerName(const char *text, int lookup)
{
    size_t i,length;
    if (!text) return(1);
    length=strlen(text);
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

/* Check against every retained identity, including tombstones, and IDs already
   generated in this operation. A failed RNG or repeated collision fails closed. */
static int cmeManagerUUID(cmeContextManager *manager, const cmeManagerState *state,
                          cmeStorageContext *context, unsigned int index)
{
    sqlite3_stmt *stmt=NULL;
    unsigned int attempt,i;
    int result=1,step,collision;
    if (sqlite3_prepare_v2(manager->db,
        "SELECT 1 FROM json_tree(?1) WHERE type='text' AND value=lower(hex(?2)) LIMIT 1",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_bind_text(stmt,1,
        state->body ? (const char *)state->body : "{}",-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
    for (attempt=0;attempt<16;attempt++)
    {
#ifdef CDSE_CONTEXT_MANAGER_TESTING
        const char *mode=getenv("CDSE_CONTEXT_MANAGER_RANDOM");
        if (mode && !strcmp(mode,"fail")) goto done;
#endif
        if (RAND_bytes(context->ids[index],16)!=1) goto done;
        context->ids[index][6]=(context->ids[index][6]&15)|0x40;
        context->ids[index][8]=(context->ids[index][8]&63)|0x80;
#ifdef CDSE_CONTEXT_MANAGER_TESTING
        if (mode && !strcmp(mode,"collision")) memcpy(context->ids[index],manager->deployment,16);
        if (mode && strlen(mode)==32 && strspn(mode,"0123456789abcdef")==32)
            for (i=0;i<16;i++)
            {
                unsigned int byte;
                if (sscanf(mode+2*i,"%2x",&byte)!=1) goto done;
                context->ids[index][i]=(unsigned char)byte;
            }
#endif
        collision=0;
        for (i=0;i<index;i++) if (!memcmp(context->ids[index],context->ids[i],16)) collision=1;
        if (collision) continue;
        if (sqlite3_bind_blob(stmt,2,context->ids[index],16,SQLITE_STATIC)!=SQLITE_OK) goto done;
        step=sqlite3_step(stmt);
        if (step==SQLITE_DONE) { result=0; break; }
        if (step!=SQLITE_ROW || sqlite3_reset(stmt)!=SQLITE_OK) goto done;
    }
done:
    sqlite3_finalize(stmt);
    return(result);
}

static int cmeManagerCurrentMatch(const cmeManagerState *state, const cmeContextAnchor *expected)
{
    unsigned char actualBytes[CME_ANCHOR_BYTES],expectedBytes[CME_ANCHOR_BYTES];
    if (!state->initialized) return(expected ? 2 : 0);
    if (!expected) return(2);
    if (cmeManagerAnchorPack(expected,expectedBytes) || cmeManagerAnchorPack(&state->anchor,actualBytes)) return(1);
    return(CRYPTO_memcmp(actualBytes,expectedBytes,sizeof(actualBytes)) ? 2 : 0);
}

/* SQLite emits escaped structured JSON; the existing C reader subsequently
   verifies the exact canonical schema before the publication can commit. */
static char *cmeManagerContextJSON(sqlite3 *db, const cmeStorageContext *context)
{
    static const char *roles[]={"ResourcesDB","RolesDB","LogsDB","ColumnFile","RawPart"};
    sqlite3_stmt *stmt=NULL;
    char *json=NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT json_object('deployment',lower(hex(?1)),'field',?2,'organization',lower(hex(?3)),"
        "'record',lower(hex(?4)),'resource',lower(hex(?5)),'role',?6,'storage',lower(hex(?7)),'table',?8)",
        -1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,1,context->ids[0],16,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,2,context->field,-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,3,context->ids[1],16,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,4,context->ids[4],16,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,5,context->ids[3],16,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,6,roles[context->role-1],-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,7,context->ids[2],16,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,8,context->table,-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_ROW || !sqlite3_column_text(stmt,0)) goto done;
    json=sqlite3_mprintf("%s",sqlite3_column_text(stmt,0));
done:
    sqlite3_finalize(stmt);
    return(json);
}

static int cmeManagerIssue(cmeContextManager *manager, const cmeManagerState *state,
                           const char *lookup, const char *contextJSON,
                           unsigned int scope, const char *scopeJSON,
                           unsigned char **body, size_t *length, unsigned char tag[32],
                           cmeContextAnchor *next)
{
    static const unsigned char domain[]="CDSE-HKX-REGISTRY-v1";
    sqlite3_stmt *stmt=NULL;
    char *json=NULL,*prefix=NULL;
    unsigned char *message=NULL;
    unsigned int written=0;
    int result=1;
    const char *query=contextJSON ?
        "SELECT json_group_array(json(value)) FROM (SELECT value FROM ("
        "SELECT value FROM json_each(?1,'$.entries') UNION ALL "
        "SELECT json_object('context',json(?3),'lookup',?2,'state','active') AS value) "
        "ORDER BY json_extract(value,'$.lookup') COLLATE BINARY)" :
        "SELECT json_group_array(json(CASE WHEN json_extract(value,'$.lookup')=?2 OR "
        "(?4>0 AND json_extract(value,'$.context.storage')=json_extract(?5,'$.storage') AND "
        "(?4=2 OR (json_extract(value,'$.context.resource')=json_extract(?5,'$.resource') AND "
        "json_extract(value,'$.context.role')=json_extract(?5,'$.role')))) "
        "THEN json_set(value,'$.state','revoked') ELSE value END)) FROM json_each(?1,'$.entries')";
    if (state->initialized && state->anchor.generation==UINT64_MAX) return(1);
    memcpy(next->deployment,manager->deployment,16); memcpy(next->organization,manager->organization,16);
    next->generation=state->initialized ? state->anchor.generation+1 : 1;
    next->minimumFormat=state->initialized ? state->anchor.minimumFormat : 1;
    if (sqlite3_prepare_v2(manager->db,query,-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,state->body ? (const char *)state->body : "{\"entries\":[]}",-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,2,lookup,-1,SQLITE_STATIC)!=SQLITE_OK ||
        (contextJSON && sqlite3_bind_text(stmt,3,contextJSON,-1,SQLITE_STATIC)!=SQLITE_OK) ||
        (!contextJSON && (sqlite3_bind_int(stmt,4,(int)scope)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,5,scopeJSON ? scopeJSON : "{}",-1,SQLITE_STATIC)!=SQLITE_OK)) ||
        sqlite3_step(stmt)!=SQLITE_ROW || !sqlite3_column_text(stmt,0)) goto done;
    /* Namespace hex comes from SQLite rather than accepting caller-controlled JSON. */
    json=sqlite3_mprintf("%s",sqlite3_column_text(stmt,0));
    sqlite3_finalize(stmt); stmt=NULL;
    if (!json || sqlite3_prepare_v2(manager->db,"SELECT lower(hex(?1)),lower(hex(?2))",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,1,manager->deployment,16,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,2,manager->organization,16,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_ROW || !sqlite3_column_text(stmt,0) || !sqlite3_column_text(stmt,1)) goto done;
    prefix=sqlite3_mprintf("{\"deployment\":\"%s\",\"entries\":%s,\"generation\":%llu,\"minimumFormat\":%u,\"organization\":\"%s\",\"schema\":1}",
        sqlite3_column_text(stmt,0),json,(unsigned long long)next->generation,next->minimumFormat,sqlite3_column_text(stmt,1));
    if (!prefix || !(*length=strlen(prefix)) || *length>cmeContextRegistryMaxBytes) goto done;
    *body=malloc(*length+1); message=malloc(sizeof(domain)+*length);
    if (!*body || !message) goto done;
    memcpy(*body,prefix,*length+1); memcpy(message,domain,sizeof(domain)); memcpy(message+sizeof(domain),*body,*length);
    if (!HMAC(EVP_sha256(),manager->key,32,message,sizeof(domain)+*length,tag,&written) || written!=32 ||
        !EVP_Digest(*body,*length,next->digest,&written,EVP_sha256(),NULL) || written!=32) goto done;
    result=0;
done:
    sqlite3_finalize(stmt); sqlite3_free(json); sqlite3_free(prefix); free(message);
    if (result) { free(*body); *body=NULL; *length=0; }
    return(result);
}

static int cmeManagerRegistration(cmeContextManager *manager, const char *lookup,
                                  cmeContextAllocation allocation, unsigned int role,
                                  const char *table, const char *field, const char *parent,
                                  const cmeContextAnchor *expected, cmeStorageContext *context,
                                  cmeContextAnchor *published, int revoke)
{
    cmeManagerState state={0};
    cmeContextRegistry *registry=NULL;
    cmeStorageContext candidate={0},ancestor={0};
    cmeContextAnchor next={0},expectedCopy;
    sqlite3_stmt *stmt=NULL;
    char *contextJSON=NULL,*scopeJSON=NULL;
    unsigned char *body=NULL,tag[32];
    unsigned int floor=0,i,start;
    size_t length=0;
    int result=1;
    if (expected) { expectedCopy=*expected; expected=&expectedCopy; }
    if (context) memset(context,0,sizeof(*context));
    if (published) memset(published,0,sizeof(*published));
    if (!manager || !published || revoke<0 || revoke>3 || cmeManagerName(lookup,1) ||
        (!revoke && (!context || allocation<cmeContextNewStorage || allocation>cmeContextNewField ||
        role<1 || role>5 || cmeManagerName(table,0) || cmeManagerName(field,0) ||
        (role==5 && (strcmp(table,"payload") || strcmp(field,"bytes"))) ||
        (parent && cmeManagerName(parent,1))))) return(1);
    pthread_mutex_lock(&manager->mutex);
    if (cmeManagerPrivate(manager) || sqlite3_exec(manager->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeManagerLoad(manager,&state)) goto done;
    result=cmeManagerCurrentMatch(&state,expected);
    if (result) goto done;
    result=1;
    if (state.initialized && cmeContextRegistryOpen(state.body,state.length,state.tag,32,manager->key,32,
        manager->deployment,manager->organization,cmeManagerAnchorFetch,&state.anchor,&registry)) goto done;
    if (revoke)
    {
        if (cmeContextRegistryLookup(registry,lookup,&candidate,&floor)) goto done;
        if (revoke>1)
        {
            if (revoke==3 && candidate.role<4) goto done;
            scopeJSON=cmeManagerContextJSON(manager->db,&candidate);
            if (!scopeJSON) goto done;
        }
    }
    else
    {
        if (sqlite3_prepare_v2(manager->db,
            "SELECT 1 FROM json_each(?1,'$.entries') WHERE json_extract(value,'$.lookup')=?2 LIMIT 1",
            -1,&stmt,NULL)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,1,state.body ? (const char *)state.body : "{}",-1,SQLITE_STATIC)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,2,lookup,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
        if (parent && cmeContextRegistryLookup(registry,parent,&ancestor,&floor)) goto done;
        if (allocation==cmeContextNewStorage)
        {
            if (role<4 || parent) goto done;
            start=2;
        }
        else if (allocation==cmeContextNewResource)
        {
            if (role<4 ? parent!=NULL : (!parent || ancestor.role<4)) goto done;
            if (parent) memcpy(candidate.ids[2],ancestor.ids[2],16);
            start=3;
        }
        else
        {
            if (!parent || ancestor.role!=role ||
                (allocation==cmeContextNewField && strcmp(table,ancestor.table))) goto done;
            candidate=ancestor;
            start=allocation==cmeContextNewRecord ? 4 : 5;
        }
        memcpy(candidate.ids[0],manager->deployment,16); memcpy(candidate.ids[1],manager->organization,16);
        candidate.role=role; strcpy(candidate.table,table); strcpy(candidate.field,field);
        for (i=start;i<5;i++) if (cmeManagerUUID(manager,&state,&candidate,i)) goto done;
        contextJSON=cmeManagerContextJSON(manager->db,&candidate);
        if (!contextJSON) goto done;
    }
    if (cmeManagerIssue(manager,&state,lookup,contextJSON,revoke>1 ? (unsigned int)revoke-1 : 0,
        scopeJSON,&body,&length,tag,&next) ||
        sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    result=0;
done:
    sqlite3_finalize(stmt);
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); cmeContextRegistryFree(&registry);
    sqlite3_free(contextJSON); sqlite3_free(scopeJSON);
    pthread_mutex_unlock(&manager->mutex);
    /* No allocated identity is durable until this existing CAS commits. A
       concurrent writer causes conflict, not a separately committed catalog. */
    if (!result)
    {
        result=cmeContextManagerPublish(manager,body,length,tag,&next,expected);
        if (!result) { if (context) *context=candidate; *published=next; }
    }
    free(body);
    return(result);
}

int cmeContextManagerProvision(cmeContextManager *manager, const char *lookup,
                               cmeContextAllocation allocation, unsigned int role,
                               const char *table, const char *field, const char *parent,
                               const cmeContextAnchor *expected, cmeStorageContext *context,
                               cmeContextAnchor *published)
{
    return(cmeManagerRegistration(manager,lookup,allocation,role,table,field,parent,expected,context,published,0));
}

int cmeContextManagerRevoke(cmeContextManager *manager, const char *lookup,
                            const cmeContextAnchor *expected, cmeContextAnchor *published)
{
    return(cmeManagerRegistration(manager,lookup,0,0,NULL,NULL,NULL,expected,NULL,published,1));
}

int cmeContextManagerRevokeScope(cmeContextManager *manager, const char *lookup,
                                 cmeContextRevocationScope scope,
                                 const cmeContextAnchor *expected, cmeContextAnchor *published)
{
    /* Invalid enum values must not select single-field revocation or allocation. */
    int revoke=(scope==cmeContextRevokeResource || scope==cmeContextRevokeStorage) ? (int)scope+1 : 4;
    return(cmeManagerRegistration(manager,lookup,0,0,NULL,NULL,NULL,expected,NULL,published,revoke));
}

typedef struct
{
    int64_t row;
    cmeStorageContext context;
} cmeBoundSlot;

struct cmeContextBinding
{
    cmeContextAnchor anchor;
    cmeContextMapAnchor mapAnchor;
    int mapped;
    size_t count;
    cmeBoundSlot *slots;
};

static int cmeBindingSlotCompare(const void *left, const void *right)
{
    const cmeBoundSlot *a=left,*b=right;
    int comparison=strcmp(a->context.table,b->context.table);
    if (comparison) return(comparison);
    if (a->row!=b->row) return(a->row<b->row ? -1 : 1);
    return(strcmp(a->context.field,b->context.field));
}

static int cmeBindingRecordCompare(const void *left, const void *right)
{
    const cmeBoundSlot *a=*(const cmeBoundSlot *const *)left,*b=*(const cmeBoundSlot *const *)right;
    int comparison=strcmp(a->context.table,b->context.table);
    return(comparison ? comparison : memcmp(a->context.ids[4],b->context.ids[4],16));
}

void cmeContextBindingFree(cmeContextBinding **binding)
{
    if (!binding || !*binding) return;
    free((*binding)->slots); free(*binding); *binding=NULL;
}

int cmeContextManagerBind(cmeContextManager *manager, const char *resource,
                          unsigned int role, const cmeContextSlot *slots, size_t count,
                          const cmeContextAnchor *expected, cmeContextBinding **binding)
{
    cmeManagerState state={0};
    cmeContextRegistry *registry=NULL;
    cmeContextBinding *candidate=NULL;
    cmeBoundSlot **records=NULL;
    cmeStorageContext seed={0};
    unsigned int floor=0;
    size_t i;
    int result=1;
    if (binding) *binding=NULL;
    if (!manager || !binding || !expected || !slots || !count || count>cmeContextRegistryMaxEntries ||
        role<1 || role>5 || cmeManagerName(resource,1)) return(1);
    for (i=0;i<count;i++)
        if (cmeManagerName(slots[i].lookup,1) || cmeManagerName(slots[i].table,0) ||
            cmeManagerName(slots[i].field,0)) return(1);
    pthread_mutex_lock(&manager->mutex);
    if (cmeManagerPrivate(manager) || sqlite3_exec(manager->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeManagerLoad(manager,&state)) goto done;
    result=cmeManagerCurrentMatch(&state,expected);
    if (result) goto done;
    result=1;
    if (cmeContextRegistryOpen(state.body,state.length,state.tag,32,manager->key,32,
        manager->deployment,manager->organization,cmeManagerAnchorFetch,&state.anchor,&registry) ||
        cmeContextRegistryLookup(registry,resource,&seed,&floor) || seed.role!=role) goto done;
    candidate=calloc(1,sizeof(*candidate));
    records=calloc(count,sizeof(*records));
    if (!candidate || !records) goto done;
    candidate->slots=calloc(count,sizeof(*candidate->slots));
    if (!candidate->slots) goto done;
    candidate->anchor=state.anchor; candidate->count=count;
    for (i=0;i<count;i++)
    {
        cmeStorageContext *context=&candidate->slots[i].context;
        if (cmeContextRegistryLookup(registry,slots[i].lookup,context,&floor) || context->role!=role ||
            memcmp(context->ids,seed.ids,4*16) || strcmp(context->table,slots[i].table) ||
            strcmp(context->field,slots[i].field)) goto done;
        candidate->slots[i].row=slots[i].row;
    }
    /* Two sorted indexes reject ambiguous physical slots and split record IDs
       without trusting candidate row metadata or quadratic map scans. */
    qsort(candidate->slots,count,sizeof(*candidate->slots),cmeBindingSlotCompare);
    for (i=0;i<count;i++)
    {
        const cmeBoundSlot *slot=&candidate->slots[i];
        records[i]=&candidate->slots[i];
        if (i)
        {
            const cmeBoundSlot *previous=&candidate->slots[i-1];
            if (!strcmp(slot->context.table,previous->context.table) && slot->row==previous->row &&
                (!strcmp(slot->context.field,previous->context.field) ||
                memcmp(slot->context.ids[4],previous->context.ids[4],16))) goto done;
        }
    }
    qsort(records,count,sizeof(*records),cmeBindingRecordCompare);
    for (i=1;i<count;i++)
        if (!cmeBindingRecordCompare(&records[i-1],&records[i]) && records[i-1]->row!=records[i]->row) goto done;
    if (sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    *binding=candidate; candidate=NULL; result=0;
done:
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); cmeContextRegistryFree(&registry);
    cmeContextBindingFree(&candidate); free(records);
    pthread_mutex_unlock(&manager->mutex);
    return(result);
}

int cmeContextBindingLookup(const cmeContextBinding *binding, const char *table,
                            int64_t row, const char *field, cmeStorageContext *context,
                            unsigned int *minimumFormat)
{
    cmeBoundSlot wanted={0};
    size_t low=0,high;
    if (context) memset(context,0,sizeof(*context));
    if (minimumFormat) *minimumFormat=0;
    if (!binding || !context || !minimumFormat || cmeManagerName(table,0) || cmeManagerName(field,0)) return(1);
    wanted.row=row; strcpy(wanted.context.table,table); strcpy(wanted.context.field,field);
    high=binding->count;
    while (low<high)
    {
        size_t middle=low+(high-low)/2;
        int comparison=cmeBindingSlotCompare(&wanted,&binding->slots[middle]);
        if (comparison<0) high=middle;
        else if (comparison>0) low=middle+1;
        else
        {
            *context=binding->slots[middle].context; *minimumFormat=binding->anchor.minimumFormat;
            return(0);
        }
    }
    return(1);
}

static int cmeManagerBindingCurrent(cmeContextManager *manager, const cmeContextBinding *binding);

int cmeContextBindingCheck(cmeContextManager *manager, const cmeContextBinding *binding)
{
    if (!manager || !binding || memcmp(manager->deployment,binding->anchor.deployment,16) ||
        memcmp(manager->organization,binding->anchor.organization,16)) return(1);
    return(cmeManagerBindingCurrent(manager,binding));
}

typedef struct
{
    unsigned char *bytes;
    size_t length;
} cmeMapEncoding;

static int cmeMapAppend(cmeMapEncoding *encoding, const void *bytes, size_t length)
{
    if (length>cmeContextRegistryMaxBytes-encoding->length) return(1);
    memcpy(encoding->bytes+encoding->length,bytes,length); encoding->length+=length;
    return(0);
}

static int cmeMapNumber(cmeMapEncoding *encoding, uint64_t value, unsigned int length)
{
    unsigned char bytes[8];
    unsigned int i;
    for (i=0;i<length;i++) bytes[i]=(unsigned char)(value>>(8*(length-i-1)));
    return(cmeMapAppend(encoding,bytes,length));
}

static int cmeMapText(cmeMapEncoding *encoding, sqlite3_stmt *stmt, int column, int lookup)
{
    const char *value;
    size_t length;
    if (sqlite3_column_type(stmt,column)!=SQLITE_TEXT) return(1);
    value=(const char *)sqlite3_column_text(stmt,column);
    if (!value || cmeManagerName(value,lookup)) return(1);
    length=strlen(value);
    if ((size_t)sqlite3_column_bytes(stmt,column)!=length) return(1);
    return(cmeMapNumber(encoding,length,1) || cmeMapAppend(encoding,value,length));
}

static int cmeShuffleVersion(cmeContextManager *manager, int *enabled)
{
    sqlite3_stmt *stmt=NULL;
    int result=1;
    *enabled=0;
    if (sqlite3_prepare_v2(manager->db,"SELECT count(*) FROM pragma_table_info('registry_meta') "
        "WHERE name='shuffle_version'",-1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW) goto done;
    if (!sqlite3_column_int(stmt,0)) { result=0; goto done; }
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(manager->db,"SELECT shuffle_version FROM registry_meta WHERE singleton=1",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
        sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || sqlite3_column_int64(stmt,0)!=1 ||
        sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    *enabled=1; result=0;
done:
    sqlite3_finalize(stmt); return(result);
}

static int cmePairVersion(cmeContextManager *manager, int *enabled)
{
    sqlite3_stmt *stmt=NULL;
    int result=1;
    *enabled=0;
    if (sqlite3_prepare_v2(manager->db,"SELECT count(*) FROM pragma_table_info('registry_meta') "
        "WHERE name='pair_version'",-1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW) goto done;
    if (!sqlite3_column_int(stmt,0)) { result=0; goto done; }
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(manager->db,"SELECT pair_version FROM registry_meta WHERE singleton=1",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
        sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || sqlite3_column_int64(stmt,0)!=1 ||
        sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    *enabled=1; result=0;
done:
    sqlite3_finalize(stmt); return(result);
}

static int cmeShufflePending(cmeContextManager *manager, const char *name, int *pending)
{
    sqlite3_stmt *stmt=NULL;
    int enabled,paired,step,result=1;
    *pending=0;
    if (cmeShuffleVersion(manager,&enabled)) return(1);
    if (!enabled) return(0);
    if (cmePairVersion(manager,&paired)) return(1);
    if (paired)
    {
        if (sqlite3_prepare_v2(manager->db,"SELECT 1 FROM context_shuffle_pairs p JOIN context_shuffles j "
            "ON p.map_name=j.map_name WHERE j.state=1 LIMIT 1",-1,&stmt,NULL)!=SQLITE_OK) goto done;
        step=sqlite3_step(stmt);
        if (step==SQLITE_ROW) { *pending=1; result=0; goto done; }
        if (step!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
    }
    if (sqlite3_prepare_v2(manager->db,"SELECT state FROM context_shuffles WHERE map_name=?1",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
    step=sqlite3_step(stmt);
    if (step==SQLITE_DONE) { result=0; goto done; }
    if (step!=SQLITE_ROW || sqlite3_column_type(stmt,0)!=SQLITE_INTEGER ||
        sqlite3_column_int64(stmt,0)<1 || sqlite3_column_int64(stmt,0)>3) goto done;
    *pending=sqlite3_column_int(stmt,0)==1; result=0;
done:
    sqlite3_finalize(stmt); return(result);
}

static int cmeShuffleEncode(cmeContextManager *manager, uint64_t revision, cmeMapEncoding *encoding)
{
    sqlite3_stmt *jobs=NULL,*slots=NULL;
    sqlite3_int64 names,total,seen=0;
    int result=1,step,slotStep;
    if (sqlite3_prepare_v2(manager->db,"SELECT (SELECT count(*) FROM context_shuffles),"
        "(SELECT count(*) FROM context_shuffle_slots)",-1,&jobs,NULL)!=SQLITE_OK || sqlite3_step(jobs)!=SQLITE_ROW) goto done;
    names=sqlite3_column_int64(jobs,0); total=sqlite3_column_int64(jobs,1);
    if (names<0 || names>cmeContextRegistryMaxEntries || total<0 || total>cmeContextRegistryMaxEntries ||
        cmeMapNumber(encoding,(uint64_t)names,4)) goto done;
    sqlite3_finalize(jobs); jobs=NULL;
    if (sqlite3_prepare_v2(manager->db,
        "SELECT j.map_name,j.job,j.state,j.finished,j.active_path,j.staged_path,j.source,j.target,m.active,m.role,"
        "(SELECT count(*) FROM context_shuffle_slots WHERE map_name=j.map_name) "
        "FROM context_shuffles j JOIN context_maps m ON j.map_name=m.name ORDER BY j.map_name COLLATE BINARY",
        -1,&jobs,NULL)!=SQLITE_OK || sqlite3_prepare_v2(manager->db,
        "SELECT table_name,slot,field_name,lookup FROM context_shuffle_slots WHERE map_name=?1 "
        "ORDER BY table_name COLLATE BINARY,slot,field_name COLLATE BINARY",-1,&slots,NULL)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(jobs))==SQLITE_ROW)
    {
        uint64_t finished=0;
        sqlite3_int64 count;
        unsigned int i,nonzero=0;
        int state,column;
        sqlite3_int64 storedState;
        if (--names<0 || cmeMapText(encoding,jobs,0,1) || sqlite3_column_type(jobs,2)!=SQLITE_INTEGER) goto done;
        storedState=sqlite3_column_int64(jobs,2);
        if (storedState<1 || storedState>3) goto done;
        state=(int)storedState;
        if (sqlite3_column_int(jobs,9)!=4 ||
            (state==1 && sqlite3_column_int(jobs,8)!=1)) goto done;
        for (column=1;column<=7;column++)
        {
            if (column==2)
            {
                if (cmeMapNumber(encoding,(uint64_t)state,1)) goto done;
            }
            else if (column==4 || column==5)
            {
                const char *path;
                size_t length;
                if (sqlite3_column_type(jobs,column)!=SQLITE_TEXT) goto done;
                path=(const char *)sqlite3_column_text(jobs,column);
                if (!path || *path!='/' || !(length=strlen(path)) || length>=PATH_MAX ||
                    length!=(size_t)sqlite3_column_bytes(jobs,column) ||
                    cmeMapNumber(encoding,length,2) || cmeMapAppend(encoding,path,length)) goto done;
            }
            else
            {
                size_t length=column==3 ? 8 : 32;
                const unsigned char *bytes;
                if (sqlite3_column_type(jobs,column)!=SQLITE_BLOB ||
                    sqlite3_column_bytes(jobs,column)!=(int)length || !(bytes=sqlite3_column_blob(jobs,column)) ||
                    cmeMapAppend(encoding,bytes,length)) goto done;
                if (column==1) for (i=0;i<32;i++) nonzero|=bytes[i];
                if (column==3) for (i=0;i<8;i++) finished=(finished<<8)|bytes[i];
            }
        }
        count=sqlite3_column_int64(jobs,10);
        if (!nonzero || (state==1 ? finished!=0 : (!finished || finished>revision)) ||
            !strcmp((const char *)sqlite3_column_text(jobs,4),(const char *)sqlite3_column_text(jobs,5)) ||
            !memcmp(sqlite3_column_blob(jobs,6),sqlite3_column_blob(jobs,7),32) ||
            count<1 || count>cmeContextRegistryMaxEntries || cmeMapNumber(encoding,(uint64_t)count,4) ||
            sqlite3_bind_text(slots,1,(const char *)sqlite3_column_text(jobs,0),-1,SQLITE_TRANSIENT)!=SQLITE_OK) goto done;
        while ((slotStep=sqlite3_step(slots))==SQLITE_ROW)
            if (--count<0 || ++seen>total || sqlite3_column_type(slots,1)!=SQLITE_INTEGER ||
                cmeMapText(encoding,slots,0,0) || cmeMapNumber(encoding,(uint64_t)sqlite3_column_int64(slots,1),8) ||
                cmeMapText(encoding,slots,2,0) || cmeMapText(encoding,slots,3,1)) goto done;
        if (slotStep!=SQLITE_DONE || count || sqlite3_reset(slots)!=SQLITE_OK) goto done;
    }
    if (step!=SQLITE_DONE || names || total!=seen) goto done;
    result=0;
done:
    sqlite3_finalize(jobs); sqlite3_finalize(slots); return(result);
}

static int cmePairPaths(const char *column, const char *resources);

/* Pair metadata follows the entire v2 encoding under a distinct v3 domain. */
static int cmePairEncode(cmeContextManager *manager, cmeMapEncoding *encoding)
{
    sqlite3_stmt *stmt=NULL;
    sqlite3_int64 count;
    int result=1,step,column;
    if (sqlite3_prepare_v2(manager->db,"SELECT count(*) FROM context_shuffle_pairs",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_ROW || (count=sqlite3_column_int64(stmt,0))<0 ||
        count>cmeContextRegistryMaxEntries || cmeMapNumber(encoding,(uint64_t)count,4)) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(manager->db,"SELECT p.map_name,p.active_path,p.staged_path,p.source,p.target,p.selection,j.active_path,j.staged_path "
        "FROM context_shuffle_pairs p JOIN context_shuffles j ON p.map_name=j.map_name "
        "ORDER BY p.map_name COLLATE BINARY",-1,&stmt,NULL)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        unsigned int nonzero=0,i;
        if (--count<0 || cmeMapText(encoding,stmt,0,1)) goto done;
        for (column=1;column<=5;column++)
        {
            if (column<3)
            {
                const char *path;
                size_t length;
                if (sqlite3_column_type(stmt,column)!=SQLITE_TEXT) goto done;
                path=(const char *)sqlite3_column_text(stmt,column);
                if (!path || *path!='/' ||
                    !(length=strlen(path)) || length>=PATH_MAX || length!=(size_t)sqlite3_column_bytes(stmt,column) ||
                    cmeMapNumber(encoding,length,2) || cmeMapAppend(encoding,path,length)) goto done;
            }
            else if (sqlite3_column_type(stmt,column)!=SQLITE_BLOB || sqlite3_column_bytes(stmt,column)!=32 ||
                !sqlite3_column_blob(stmt,column) || cmeMapAppend(encoding,sqlite3_column_blob(stmt,column),32)) goto done;
        }
        for (i=0;i<32;i++) nonzero|=((const unsigned char *)sqlite3_column_blob(stmt,5))[i];
        if (!nonzero || !strcmp((const char *)sqlite3_column_text(stmt,1),(const char *)sqlite3_column_text(stmt,2)) ||
            !memcmp(sqlite3_column_blob(stmt,3),sqlite3_column_blob(stmt,4),32) ||
            cmePairPaths((const char *)sqlite3_column_text(stmt,6),(const char *)sqlite3_column_text(stmt,1)) ||
            cmePairPaths((const char *)sqlite3_column_text(stmt,7),(const char *)sqlite3_column_text(stmt,2))) goto done;
    }
    if (step==SQLITE_DONE && !count) result=0;
done:
    sqlite3_finalize(stmt); return(result);
}

/* Canonical typed encoding of protected SQL rows, including tombstones. The
   namespace and separate HMAC domain prevent cross-scope/protocol substitution. */
static int cmeMapSign(cmeContextManager *manager, uint64_t revision,
                       cmeContextMapAnchor *anchor, unsigned char tag[32])
{
    static const unsigned char domain[]="CDSE-HKX-MAP-v1";
    static const unsigned char extendedDomain[]="CDSE-HKX-MAP-v2";
    static const unsigned char pairDomain[]="CDSE-HKX-MAP-v3";
    cmeMapEncoding encoding={0};
    sqlite3_stmt *maps=NULL,*slots=NULL;
    sqlite3_int64 names,total,seen=0;
    unsigned int written;
    int result=1,step,slotStep,extended,paired;
    encoding.bytes=malloc(cmeContextRegistryMaxBytes);
    if (!encoding.bytes || !revision || cmeShuffleVersion(manager,&extended) || cmePairVersion(manager,&paired) ||
        (paired && !extended) || sqlite3_prepare_v2(manager->db,
        "SELECT (SELECT count(*) FROM context_maps),(SELECT count(*) FROM context_map_slots)",
        -1,&maps,NULL)!=SQLITE_OK || sqlite3_step(maps)!=SQLITE_ROW) goto done;
    names=sqlite3_column_int64(maps,0); total=sqlite3_column_int64(maps,1);
    if (names<0 || names>cmeContextRegistryMaxEntries || total<0 || total>cmeContextRegistryMaxEntries ||
        cmeMapAppend(&encoding,paired ? pairDomain : (extended ? extendedDomain : domain),sizeof(domain)) || cmeMapAppend(&encoding,manager->deployment,16) ||
        cmeMapAppend(&encoding,manager->organization,16) || cmeMapNumber(&encoding,revision,8) ||
        cmeMapNumber(&encoding,(uint64_t)names,4)) goto done;
    sqlite3_finalize(maps); maps=NULL;
    if (sqlite3_prepare_v2(manager->db,
        "SELECT name,resource,role,active,(SELECT count(*) FROM context_map_slots WHERE map_name=name) "
        "FROM context_maps ORDER BY name COLLATE BINARY",-1,&maps,NULL)!=SQLITE_OK ||
        sqlite3_prepare_v2(manager->db,
        "SELECT table_name,slot,field_name,lookup FROM context_map_slots WHERE map_name=?1 "
        "ORDER BY table_name COLLATE BINARY,slot,field_name COLLATE BINARY",-1,&slots,NULL)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(maps))==SQLITE_ROW)
    {
        sqlite3_int64 count,role,active;
        if (sqlite3_column_type(maps,2)!=SQLITE_INTEGER || sqlite3_column_type(maps,3)!=SQLITE_INTEGER) goto done;
        count=sqlite3_column_int64(maps,4); role=sqlite3_column_int64(maps,2); active=sqlite3_column_int64(maps,3);
        if (--names<0 || role<1 || role>5 || (active!=0 && active!=1) ||
            count<0 || count>cmeContextRegistryMaxEntries || (active ? !count : count!=0) ||
            cmeMapText(&encoding,maps,0,1) || cmeMapText(&encoding,maps,1,1) ||
            cmeMapNumber(&encoding,(uint64_t)role,1) || cmeMapNumber(&encoding,(uint64_t)active,1) ||
            cmeMapNumber(&encoding,(uint64_t)count,4) || sqlite3_bind_text(slots,1,
            (const char *)sqlite3_column_text(maps,0),-1,SQLITE_TRANSIENT)!=SQLITE_OK) goto done;
        while ((slotStep=sqlite3_step(slots))==SQLITE_ROW)
        {
            if (--count<0 || ++seen>total || sqlite3_column_type(slots,1)!=SQLITE_INTEGER ||
                cmeMapText(&encoding,slots,0,0) ||
                cmeMapNumber(&encoding,(uint64_t)sqlite3_column_int64(slots,1),8) ||
                cmeMapText(&encoding,slots,2,0) || cmeMapText(&encoding,slots,3,1)) goto done;
        }
        if (slotStep!=SQLITE_DONE || count || sqlite3_reset(slots)!=SQLITE_OK) goto done;
    }
    if (step!=SQLITE_DONE || names || seen!=total || (extended && cmeShuffleEncode(manager,revision,&encoding)) ||
        (paired && cmePairEncode(manager,&encoding)) ||
        !HMAC(EVP_sha256(),manager->key,32,encoding.bytes,encoding.length,tag,&written) || written!=32 ||
        !EVP_Digest(encoding.bytes,encoding.length,anchor->digest,&written,EVP_sha256(),NULL) || written!=32) goto done;
    anchor->revision=revision; result=0;
done:
    sqlite3_finalize(maps); sqlite3_finalize(slots); free(encoding.bytes);
    return(result);
}

static int cmeMapLoad(cmeContextManager *manager, cmeContextMapAnchor *anchor)
{
    sqlite3_stmt *stmt=NULL;
    unsigned char saved[32],tag[32];
    uint64_t revision=0;
    unsigned int i;
    int result=1;
    if (sqlite3_prepare_v2(manager->db,"SELECT mapping_version FROM registry_meta WHERE singleton=1",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
        sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || sqlite3_column_int64(stmt,0)!=1 ||
        sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(manager->db,"SELECT revision,tag FROM context_map_head",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_ROW || sqlite3_column_type(stmt,0)!=SQLITE_BLOB ||
        sqlite3_column_bytes(stmt,0)!=8 || !sqlite3_column_blob(stmt,0) ||
        sqlite3_column_type(stmt,1)!=SQLITE_BLOB || sqlite3_column_bytes(stmt,1)!=32 || !sqlite3_column_blob(stmt,1)) goto done;
    for (i=0;i<8;i++) revision=(revision<<8)|((const unsigned char *)sqlite3_column_blob(stmt,0))[i];
    memcpy(saved,sqlite3_column_blob(stmt,1),32);
    if (sqlite3_step(stmt)!=SQLITE_DONE || cmeMapSign(manager,revision,anchor,tag) || CRYPTO_memcmp(saved,tag,32)) goto done;
    result=0;
done:
    sqlite3_finalize(stmt);
    return(result);
}

static int cmeMapMatch(const cmeContextMapAnchor *actual, const cmeContextMapAnchor *expected)
{
    if (!expected || !expected->revision) return(1);
    return(actual->revision!=expected->revision || CRYPTO_memcmp(actual->digest,expected->digest,32) ? 2 : 0);
}

static int cmeMapHead(cmeContextManager *manager, const cmeContextMapAnchor *anchor, const unsigned char tag[32])
{
    sqlite3_stmt *stmt=NULL;
    unsigned char revision[8];
    unsigned int i;
    int result=1;
    for (i=0;i<8;i++) revision[i]=(unsigned char)(anchor->revision>>(56-8*i));
    if (sqlite3_prepare_v2(manager->db,"INSERT INTO context_map_head VALUES(1,?1,?2) "
        "ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,tag=excluded.tag",-1,&stmt,NULL)==SQLITE_OK &&
        sqlite3_bind_blob(stmt,1,revision,8,SQLITE_STATIC)==SQLITE_OK &&
        sqlite3_bind_blob(stmt,2,tag,32,SQLITE_STATIC)==SQLITE_OK && sqlite3_step(stmt)==SQLITE_DONE) result=0;
    sqlite3_finalize(stmt); return(result);
}

int cmeContextManagerMapInit(cmeContextManager *manager, const cmeContextAnchor *expected,
                             cmeContextMapAnchor *published)
{
    cmeManagerState state={0};
    cmeContextMapAnchor next={0};
    sqlite3_stmt *stmt=NULL;
    unsigned char tag[32];
    int result=1;
    if (published) memset(published,0,sizeof(*published));
    if (!manager || !expected || !published) return(1);
    pthread_mutex_lock(&manager->mutex);
    if (cmeManagerPrivate(manager) || sqlite3_exec(manager->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeManagerLoad(manager,&state)) goto done;
    result=cmeManagerCurrentMatch(&state,expected); if (result) goto done;
    result=1; cmeManagerCheckpoint("after-begin");
    if (sqlite3_prepare_v2(manager->db,"SELECT count(*) FROM pragma_table_info('registry_meta') "
        "WHERE name='mapping_version'",-1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
        sqlite3_column_int(stmt,0)!=0) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_exec(manager->db,
        "ALTER TABLE registry_meta ADD COLUMN mapping_version INTEGER NOT NULL DEFAULT 1 CHECK(mapping_version=1);"
        "CREATE TABLE context_map_head(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision BLOB NOT NULL CHECK(length(revision)=8),tag BLOB NOT NULL CHECK(length(tag)=32));"
        "CREATE TABLE context_maps(name TEXT PRIMARY KEY,resource TEXT NOT NULL,role INTEGER NOT NULL,active INTEGER NOT NULL CHECK(active IN(0,1)));"
        "CREATE TABLE context_map_slots(map_name TEXT NOT NULL,table_name TEXT NOT NULL,slot INTEGER NOT NULL,field_name TEXT NOT NULL,lookup TEXT NOT NULL,PRIMARY KEY(map_name,table_name,slot,field_name));",
        NULL,NULL,NULL)!=SQLITE_OK || cmeMapSign(manager,1,&next,tag) || cmeMapHead(manager,&next,tag)) goto done;
    cmeManagerCheckpoint("after-write");
    if (sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    cmeManagerCheckpoint("after-commit"); *published=next; result=0;
done:
    sqlite3_finalize(stmt);
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex); return(result);
}

int cmeContextManagerMapFetch(cmeContextManager *manager, cmeContextMapAnchor *anchor)
{
    cmeManagerState state={0};
    cmeContextMapAnchor current={0};
    int result=1;
    if (anchor) memset(anchor,0,sizeof(*anchor));
    if (!manager || !anchor) return(1);
    pthread_mutex_lock(&manager->mutex);
    if (cmeManagerPrivate(manager) || sqlite3_exec(manager->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeManagerLoad(manager,&state) || !state.initialized || cmeMapLoad(manager,&current) ||
        sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    *anchor=current; result=0;
done:
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex); return(result);
}

static int cmeManagerBindingCurrent(cmeContextManager *manager, const cmeContextBinding *binding)
{
    cmeManagerState state={0};
    cmeContextMapAnchor map={0};
    int result=1;
    pthread_mutex_lock(&manager->mutex);
    if (cmeManagerPrivate(manager) || sqlite3_exec(manager->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeManagerLoad(manager,&state)) goto done;
    result=cmeManagerCurrentMatch(&state,&binding->anchor); if (result) goto done;
    if (binding->mapped)
    {
        result=1; if (cmeMapLoad(manager,&map)) goto done;
        result=cmeMapMatch(&map,&binding->mapAnchor); if (result) goto done;
    }
    result=sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)==SQLITE_OK ? 0 : 1;
done:
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex); return(result);
}

static int cmeManagerMapWrite(cmeContextManager *manager, const char *name, const char *resource,
                              unsigned int role, const cmeContextSlot *slots, size_t count,
                              const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                              cmeContextMapAnchor *published, int remove)
{
    cmeManagerState state={0};
    cmeContextMapAnchor current={0},next={0},copy;
    cmeContextBinding *verified=NULL;
    sqlite3_stmt *stmt=NULL;
    unsigned char tag[32];
    size_t i;
    int result=1,step,pending;
    if (mapExpected) { copy=*mapExpected; mapExpected=&copy; }
    if (published) memset(published,0,sizeof(*published));
    if (!manager || !published || !expected || !mapExpected || cmeManagerName(name,1)) return(1);
    if (!remove)
    {
        result=cmeContextManagerBind(manager,resource,role,slots,count,expected,&verified);
        cmeContextBindingFree(&verified); if (result) return(result);
    }
    result=1; pthread_mutex_lock(&manager->mutex);
    if (cmeManagerPrivate(manager) || sqlite3_exec(manager->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeManagerLoad(manager,&state)) goto done;
    result=cmeManagerCurrentMatch(&state,expected); if (result) goto done;
    result=1; if (cmeMapLoad(manager,&current)) goto done;
    result=cmeMapMatch(&current,mapExpected); if (result) goto done;
    result=1; if (current.revision==UINT64_MAX || cmeShufflePending(manager,name,&pending) || pending) goto done;
    cmeManagerCheckpoint("after-begin");
    if (sqlite3_prepare_v2(manager->db,"SELECT resource,role,active FROM context_maps WHERE name=?1",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
    step=sqlite3_step(stmt);
    if (step==SQLITE_ROW)
    {
        if (!sqlite3_column_int(stmt,2) || (!remove && (strcmp(resource,(const char *)sqlite3_column_text(stmt,0)) ||
            role!=(unsigned int)sqlite3_column_int(stmt,1)))) goto done;
    }
    else if (step!=SQLITE_DONE || remove) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(manager->db,remove ? "UPDATE context_maps SET active=0 WHERE name=?1" :
        "INSERT INTO context_maps VALUES(?1,?2,?3,1) ON CONFLICT(name) DO NOTHING",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK || (!remove &&
        (sqlite3_bind_text(stmt,2,resource,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_bind_int(stmt,3,(int)role)!=SQLITE_OK)) ||
        sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(manager->db,"DELETE FROM context_map_slots WHERE map_name=?1",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (!remove)
    {
        if (sqlite3_prepare_v2(manager->db,"INSERT INTO context_map_slots VALUES(?1,?2,?3,?4,?5)",-1,&stmt,NULL)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
        for (i=0;i<count;i++)
            if (sqlite3_bind_text(stmt,2,slots[i].table,-1,SQLITE_STATIC)!=SQLITE_OK ||
                sqlite3_bind_int64(stmt,3,slots[i].row)!=SQLITE_OK ||
                sqlite3_bind_text(stmt,4,slots[i].field,-1,SQLITE_STATIC)!=SQLITE_OK ||
                sqlite3_bind_text(stmt,5,slots[i].lookup,-1,SQLITE_STATIC)!=SQLITE_OK ||
                sqlite3_step(stmt)!=SQLITE_DONE || sqlite3_reset(stmt)!=SQLITE_OK) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
    }
    if (cmeMapSign(manager,current.revision+1,&next,tag) || cmeMapHead(manager,&next,tag)) goto done;
    cmeManagerCheckpoint("after-write");
    if (sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    cmeManagerCheckpoint("after-commit"); *published=next; result=0;
done:
    sqlite3_finalize(stmt);
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex); return(result);
}

int cmeContextManagerMapStore(cmeContextManager *manager, const char *name, const char *resource,
                              unsigned int role, const cmeContextSlot *slots, size_t count,
                              const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                              cmeContextMapAnchor *published)
{
    return(cmeManagerMapWrite(manager,name,resource,role,slots,count,expected,mapExpected,published,0));
}

int cmeContextManagerMapRemove(cmeContextManager *manager, const char *name,
                               const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                               cmeContextMapAnchor *published)
{
    return(cmeManagerMapWrite(manager,name,NULL,0,NULL,0,expected,mapExpected,published,1));
}

void cmeContextMapFree(cmeContextMap **map)
{
    size_t i;
    if (!map || !*map) return;
    for (i=0;i<(*map)->count;i++)
    {
        free((void *)(*map)->slots[i].lookup); free((void *)(*map)->slots[i].table);
        free((void *)(*map)->slots[i].field);
    }
    free((*map)->slots); free((*map)->resource); free(*map); *map=NULL;
}

int cmeContextManagerMapRead(cmeContextManager *manager, const char *name,
                             const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                             cmeContextMap **output)
{
    cmeManagerState state={0};
    cmeContextMapAnchor map={0};
    cmeContextMap *candidate=NULL;
    sqlite3_stmt *stmt=NULL;
    int result=1,step;
    if (output) *output=NULL;
    if (!manager || !output || !expected || !mapExpected || cmeManagerName(name,1)) return(1);
    pthread_mutex_lock(&manager->mutex);
    if (cmeManagerPrivate(manager) || sqlite3_exec(manager->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeManagerLoad(manager,&state)) goto done;
    result=cmeManagerCurrentMatch(&state,expected); if (result) goto done;
    result=1; if (cmeMapLoad(manager,&map)) goto done;
    result=cmeMapMatch(&map,mapExpected); if (result) goto done;
    result=1;
    if (sqlite3_prepare_v2(manager->db,"SELECT resource,role,active FROM context_maps WHERE name=?1",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_ROW) goto done;
    candidate=calloc(1,sizeof(*candidate));
    if (!candidate) goto done;
    candidate->resource=strdup((const char *)sqlite3_column_text(stmt,0));
    candidate->role=(unsigned int)sqlite3_column_int(stmt,1); candidate->active=sqlite3_column_int(stmt,2);
    if (cmeShufflePending(manager,name,&candidate->blocked)) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    candidate->slots=calloc(cmeContextRegistryMaxEntries,sizeof(*candidate->slots));
    if (!candidate->resource || !candidate->slots || sqlite3_prepare_v2(manager->db,
        "SELECT lookup,table_name,slot,field_name FROM context_map_slots WHERE map_name=?1 "
        "ORDER BY table_name COLLATE BINARY,slot,field_name COLLATE BINARY",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        cmeContextSlot *slot;
        if (candidate->count==cmeContextRegistryMaxEntries) goto done;
        slot=&candidate->slots[candidate->count++];
        slot->lookup=strdup((const char *)sqlite3_column_text(stmt,0));
        slot->table=strdup((const char *)sqlite3_column_text(stmt,1));
        slot->row=sqlite3_column_int64(stmt,2); slot->field=strdup((const char *)sqlite3_column_text(stmt,3));
        if (!slot->lookup || !slot->table || !slot->field) goto done;
    }
    if (step!=SQLITE_DONE || sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    *output=candidate; candidate=NULL; result=0;
done:
    sqlite3_finalize(stmt);
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex);
    cmeContextMapFree(&candidate); return(result);
}

int cmeContextManagerMapBind(cmeContextManager *manager, const char *name,
                             const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                             cmeContextBinding **binding)
{
    cmeContextMap *map=NULL;
    int result;
    if (binding) *binding=NULL;
    if (!binding) return(1);
    result=cmeContextManagerMapRead(manager,name,expected,mapExpected,&map);
    if (!result && (!map->active || map->blocked)) result=1;
    if (!result) result=cmeContextManagerBind(manager,map->resource,map->role,map->slots,map->count,expected,binding);
    if (!result)
    {
        (*binding)->mapped=1; (*binding)->mapAnchor=*mapExpected;
        result=cmeContextBindingCheck(manager,*binding);
        if (result) cmeContextBindingFree(binding);
    }
    cmeContextMapFree(&map); return(result);
}

static int cmeShuffleCurrent(cmeContextManager *manager, const cmeContextAnchor *expected,
                             const cmeContextMapAnchor *mapExpected, cmeManagerState *state,
                             cmeContextMapAnchor *map)
{
    int result;
    if (cmeManagerPrivate(manager) || cmeManagerLoad(manager,state)) return(1);
    result=cmeManagerCurrentMatch(state,expected); if (result) return(result);
    if (cmeMapLoad(manager,map)) return(1);
    return(cmeMapMatch(map,mapExpected));
}

int cmeContextManagerCheckAnchors(cmeContextManager *manager, const cmeContextAnchor *registry,
                                  const cmeContextMapAnchor *catalog)
{
    cmeManagerState state={0};
    cmeContextMapAnchor current={0};
    int result=1;
    if (!manager || !registry || !catalog) return(1);
    pthread_mutex_lock(&manager->mutex);
    if (sqlite3_exec(manager->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    result=cmeShuffleCurrent(manager,registry,catalog,&state,&current);
    if (!result && sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) result=1;
done:
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex); return(result);
}

static int cmeCopyPrepare(cmeContextManager *manager, const char *sourceName,
    const char *const *lookups, size_t count, const cmeContextAnchor *expected,
    const cmeContextMapAnchor *catalog, cmeContextMap **copy, cmeContextAnchor *published,
    unsigned char **snapshot, size_t *snapshotLength, unsigned char snapshotTag[32])
{
    cmeManagerState state={0};
    cmeContextMapAnchor current={0};
    cmeContextAnchor next={0},expectedCopy;
    cmeContextMap *source=NULL,*candidate=NULL;
    cmeContextBinding *binding=NULL;
    cmeStorageContext *allocated=NULL;
    sqlite3_stmt *stmt=NULL;
    unsigned char *body=NULL,*added=NULL,tag[32];
    size_t length=0,addedLength=0,i,j;
    int result=1;
    if (expected) { expectedCopy=*expected; expected=&expectedCopy; }
    if (copy) *copy=NULL;
    if (published) memset(published,0,sizeof(*published));
    if (!manager || !copy || !published || !expected || !catalog || !lookups ||
        !count || count>cmeContextRegistryMaxEntries || cmeManagerName(sourceName,1)) return(1);
    for (i=0;i<count;i++)
    {
        if (cmeManagerName(lookups[i],1)) return(1);
        for (j=0;j<i;j++) if (!strcmp(lookups[i],lookups[j])) return(1);
    }
    result=cmeContextManagerMapRead(manager,sourceName,expected,catalog,&source); if (result) goto before;
    result=1;
    if (!source->active || source->blocked || source->role!=4 || source->count!=count) goto before;
    result=cmeContextManagerMapBind(manager,sourceName,expected,catalog,&binding); if (result) goto before;
    result=1;
    candidate=calloc(1,sizeof(*candidate)); allocated=calloc(count,sizeof(*allocated));
    if (!candidate || !allocated) goto before;
    candidate->slots=calloc(count,sizeof(*candidate->slots));
    if (!candidate->slots) goto before;
    candidate->count=count; candidate->role=4; candidate->active=1;
    candidate->resource=strdup(lookups[0]);
    if (!candidate->resource) goto before;
    pthread_mutex_lock(&manager->mutex);
    if (sqlite3_exec(manager->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    result=cmeShuffleCurrent(manager,expected,catalog,&state,&current); if (result) goto done;
    result=1;
    if (state.anchor.minimumFormat!=1 || state.anchor.generation==UINT64_MAX ||
        sqlite3_prepare_v2(manager->db,"SELECT json_array_length(?1,'$.entries')",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,(const char *)state.body,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
        sqlite3_column_int64(stmt,0)>(sqlite3_int64)(cmeContextRegistryMaxEntries-count)) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    for (i=0;i<count;i++)
    {
        cmeContextSlot *slot=&candidate->slots[i];
        cmeStorageContext *context=&allocated[i];
        unsigned int floor=0;
        char *json=NULL;
        if (sqlite3_prepare_v2(manager->db,"SELECT 1 FROM json_each(?1,'$.entries') "
            "WHERE json_extract(value,'$.lookup')=?2 LIMIT 1",-1,&stmt,NULL)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,1,(const char *)state.body,-1,SQLITE_STATIC)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,2,lookups[i],-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
        if (cmeContextBindingLookup(binding,source->slots[i].table,source->slots[i].row,
            source->slots[i].field,context,&floor) || floor!=1) goto done;
        if (!i)
        { if (cmeManagerUUID(manager,&state,context,3)) goto done; }
        else memcpy(context->ids[3],allocated[0].ids[3],16);
        /* Authenticated binding guarantees one record per table/physical slot.
           Multiple fields of that record must retain a single new record UUID. */
        for (j=0;j<i;j++) if (!strcmp(source->slots[i].table,source->slots[j].table) &&
            source->slots[i].row==source->slots[j].row) break;
        if (j<i) memcpy(context->ids[4],allocated[j].ids[4],16);
        else if (cmeManagerUUID(manager,&state,context,4)) goto done;
        slot->lookup=strdup(lookups[i]); slot->table=strdup(source->slots[i].table);
        slot->field=strdup(source->slots[i].field); slot->row=source->slots[i].row;
        if (!slot->lookup || !slot->table || !slot->field) goto done;
        json=cmeManagerContextJSON(manager->db,context);
        if (!json) goto done;
        result=cmeManagerIssue(manager,&state,lookups[i],json,0,NULL,&added,&addedLength,tag,&next);
        sqlite3_free(json);
        if (result) goto done;
        result=1;
        free(state.body); state.body=added; added=NULL; state.length=addedLength;
        /* Keep the original generation in state: all additions form ONE next
           snapshot, and the UUID collision search sees earlier additions. */
        cmeManagerCheckpoint("after-copy-entry");
    }
    if (sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    body=state.body; state.body=NULL; length=state.length; result=0;
done:
    sqlite3_finalize(stmt);
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex);
    if (!result)
    {
        *published=next; *copy=candidate; candidate=NULL;
        *snapshot=body; body=NULL; *snapshotLength=length; memcpy(snapshotTag,tag,32);
    }
before:
    free(body); free(added); free(allocated);
    cmeContextMapFree(&source); cmeContextMapFree(&candidate); cmeContextBindingFree(&binding); return(result);
}

int cmeContextManagerCopyProvision(cmeContextManager *manager, const char *sourceName,
    const char *const *lookups, size_t count, const cmeContextAnchor *expected,
    const cmeContextMapAnchor *catalog, cmeContextMap **copy, cmeContextAnchor *published)
{
    cmeContextAnchor original,next={0};
    cmeContextMap *candidate=NULL;
    unsigned char *body=NULL,tag[32];
    size_t length=0;
    int result;
    if (expected) { original=*expected; expected=&original; }
    if (copy) *copy=NULL;
    if (published) memset(published,0,sizeof(*published));
    if (!copy || !published) return(1);
    result=cmeCopyPrepare(manager,sourceName,lookups,count,expected,catalog,&candidate,&next,&body,&length,tag);
    if (!result)
    {
        cmeManagerCheckpoint("copy-before-publish");
        result=cmeManagerPublishPinned(manager,body,length,tag,&next,expected,catalog,sourceName,0);
        if (!result) { *published=next; *copy=candidate; candidate=NULL; }
    }
    free(body); cmeContextMapFree(&candidate); return(result);
}

static const unsigned char cmeCopyDomain[]="CDSE-HKX-COPY-v1";

static int cmeCopyText(cmeMapEncoding *encoding, const char *text)
{
    size_t length=strlen(text);
    return(cmeMapNumber(encoding,length,1) || cmeMapAppend(encoding,text,length));
}

int cmeContextManagerCopyPlanPrepare(cmeContextManager *manager, const char *sourceName,
    const char *const *lookups, size_t count, const cmeContextAnchor *expected,
    const cmeContextMapAnchor *catalog, unsigned char **plan, size_t *length, unsigned char digest[32])
{
    cmeContextMap *copy=NULL;
    cmeContextAnchor next={0};
    cmeMapEncoding encoding={0};
    unsigned char beforeBytes[73],nextBytes[73],*snapshot=NULL,*candidate=NULL,tag[32];
    size_t snapshotLength=0,total=0,i;
    unsigned int written;
    int result=1;
    if (plan) *plan=NULL;
    if (length) *length=0;
    if (digest) memset(digest,0,32);
    if (!plan || !length || !digest || !expected || !catalog || cmeManagerAnchorPack(expected,beforeBytes)) return(1);
    result=cmeCopyPrepare(manager,sourceName,lookups,count,expected,catalog,&copy,&next,&snapshot,&snapshotLength,tag);
    if (result) goto done;
    result=1; encoding.bytes=malloc(cmeContextRegistryMaxBytes);
    if (!encoding.bytes || cmeManagerAnchorPack(&next,nextBytes) ||
        cmeMapAppend(&encoding,cmeCopyDomain,sizeof(cmeCopyDomain)) ||
        cmeMapAppend(&encoding,beforeBytes,73) || cmeMapNumber(&encoding,catalog->revision,8) ||
        cmeMapAppend(&encoding,catalog->digest,32) || cmeMapAppend(&encoding,nextBytes,73) ||
        cmeMapAppend(&encoding,tag,32) || cmeCopyText(&encoding,sourceName) || cmeMapNumber(&encoding,count,4)) goto done;
    for (i=0;i<count;i++)
        if (cmeCopyText(&encoding,copy->slots[i].lookup) || cmeCopyText(&encoding,copy->slots[i].table) ||
            cmeMapNumber(&encoding,(uint64_t)copy->slots[i].row,8) || cmeCopyText(&encoding,copy->slots[i].field)) goto done;
    if (cmeMapNumber(&encoding,snapshotLength,4)) goto done;
    total=encoding.length+snapshotLength+32;
    candidate=malloc(total);
    if (!candidate) goto done;
    memcpy(candidate,encoding.bytes,encoding.length); memcpy(candidate+encoding.length,snapshot,snapshotLength);
    if (!HMAC(EVP_sha256(),manager->key,32,candidate,total-32,candidate+total-32,&written) || written!=32 ||
        !EVP_Digest(candidate,total,digest,&written,EVP_sha256(),NULL) || written!=32) goto done;
    *plan=candidate; candidate=NULL; *length=total; result=0;
done:
    if (result) memset(digest,0,32);
    free(candidate); free(encoding.bytes); free(snapshot); cmeContextMapFree(&copy); return(result);
}

typedef struct
{
    const unsigned char *bytes;
    size_t remaining;
} cmeCopyCursor;

static int cmeCopyTake(cmeCopyCursor *cursor, void *output, size_t length)
{
    if (length>cursor->remaining) return(1);
    if (output) memcpy(output,cursor->bytes,length);
    cursor->bytes+=length; cursor->remaining-=length; return(0);
}

static int cmeCopyNumber(cmeCopyCursor *cursor, unsigned int length, uint64_t *value)
{
    unsigned int i;
    *value=0;
    if (length>cursor->remaining) return(1);
    for (i=0;i<length;i++) *value=(*value<<8)|cursor->bytes[i];
    return(cmeCopyTake(cursor,NULL,length));
}

static int cmeCopyName(cmeCopyCursor *cursor, char **name, int lookup)
{
    uint64_t length;
    if (cmeCopyNumber(cursor,1,&length) || !length || length>cursor->remaining ||
        length>(lookup ? 128U : 64U)) return(1);
    *name=malloc((size_t)length+1);
    if (!*name) return(1);
    memcpy(*name,cursor->bytes,(size_t)length); (*name)[length]=0;
    if (memchr(*name,0,(size_t)length) || cmeManagerName(*name,lookup)) return(1);
    return(cmeCopyTake(cursor,NULL,(size_t)length));
}

/* Authenticate all bytes and the independently retained digest BEFORE parsing.
   Signed plans are trusted issuer artifacts, not allocation provenance against
   an owner holding the registry key. No file paths or keys are encoded. */
static int cmeCopyDecode(cmeContextManager *manager, const unsigned char *plan, size_t length,
    const unsigned char digest[32], const cmeContextAnchor *expected, const cmeContextMapAnchor *catalog,
    cmeContextMap **copy, cmeContextAnchor *next, char **source,
    const unsigned char **snapshot, size_t *snapshotLength, unsigned char snapshotTag[32])
{
    cmeCopyCursor cursor={plan,length>=32 ? length-32 : 0};
    cmeContextMap *candidate=NULL;
    cmeContextRegistry *registry=NULL;
    unsigned char actual[32],tag[32],before[73],encoded[73],after[73];
    uint64_t number;
    size_t i,j;
    unsigned int written;
    int result=1;
    if (!manager || !plan || !digest || !expected || !catalog || !catalog->revision ||
        length<sizeof(cmeCopyDomain)+73+40+73+32+1+4+4+32 || length>cmeContextCopyPlanMaxBytes ||
        cmeManagerAnchorPack(expected,before) ||
        !EVP_Digest(plan,length,actual,&written,EVP_sha256(),NULL) || written!=32 || CRYPTO_memcmp(actual,digest,32) ||
        !HMAC(EVP_sha256(),manager->key,32,plan,length-32,tag,&written) || written!=32 ||
        CRYPTO_memcmp(tag,plan+length-32,32) || memcmp(plan,cmeCopyDomain,sizeof(cmeCopyDomain))) return(1);
    if (cmeCopyTake(&cursor,NULL,sizeof(cmeCopyDomain)) || cmeCopyTake(&cursor,encoded,73) ||
        CRYPTO_memcmp(before,encoded,73) || cmeCopyNumber(&cursor,8,&number) || number!=catalog->revision ||
        cmeCopyTake(&cursor,actual,32) || CRYPTO_memcmp(actual,catalog->digest,32) ||
        cmeCopyTake(&cursor,after,73) || cmeManagerAnchorUnpack(after,next) ||
        expected->generation==UINT64_MAX || next->generation!=expected->generation+1 ||
        expected->minimumFormat!=1 || next->minimumFormat!=1 || memcmp(before,after,32) ||
        cmeCopyTake(&cursor,snapshotTag,32) || cmeCopyName(&cursor,source,1) ||
        cmeCopyNumber(&cursor,4,&number) || !number || number>cmeContextRegistryMaxEntries) goto done;
    candidate=calloc(1,sizeof(*candidate));
    if (!candidate) goto done;
    candidate->slots=calloc((size_t)number,sizeof(*candidate->slots));
    if (!candidate->slots) goto done;
    candidate->count=(size_t)number; candidate->active=1; candidate->role=4;
    for (i=0;i<candidate->count;i++)
    {
        cmeContextSlot *slot=&candidate->slots[i];
        char *lookup=NULL,*table=NULL,*field=NULL;
        int failed=cmeCopyName(&cursor,&lookup,1) || cmeCopyName(&cursor,&table,0) ||
            cmeCopyNumber(&cursor,8,&number) || cmeCopyName(&cursor,&field,0);
        slot->lookup=lookup; slot->table=table; slot->field=field;
        if (failed) goto done;
        slot->row=number<=INT64_MAX ? (int64_t)number : -1-(int64_t)(UINT64_MAX-number);
        for (j=0;j<i;j++) if (!strcmp(slot->lookup,candidate->slots[j].lookup)) goto done;
        if (i)
        {
            const cmeContextSlot *previous=&candidate->slots[i-1];
            int order=strcmp(previous->table,slot->table);
            if (order>0 || (!order && (previous->row>slot->row ||
                (previous->row==slot->row && strcmp(previous->field,slot->field)>=0)))) goto done;
        }
    }
    if (cmeCopyNumber(&cursor,4,&number) || length-32-cursor.remaining>cmeContextRegistryMaxBytes ||
        !number || number>cmeContextRegistryMaxBytes ||
        cursor.remaining!=(size_t)number ||
        cmeContextRegistryOpen(cursor.bytes,(size_t)number,snapshotTag,32,manager->key,32,
            manager->deployment,manager->organization,cmeManagerAnchorFetch,next,&registry)) goto done;
    candidate->resource=strdup(candidate->slots[0].lookup);
    if (!candidate->resource) goto done;
    *snapshot=cursor.bytes; *snapshotLength=(size_t)number; *copy=candidate; candidate=NULL; result=0;
done:
    cmeContextRegistryFree(&registry); cmeContextMapFree(&candidate); return(result);
}

int cmeContextManagerCopyPlanMatch(cmeContextManager *manager, const unsigned char *plan,
    size_t length, const unsigned char digest[32], const cmeContextAnchor *expected,
    const cmeContextMapAnchor *catalog, const char *sourceName, const char *const *lookups, size_t count)
{
    cmeContextMap *copy=NULL;
    cmeContextAnchor next={0};
    char *source=NULL;
    const unsigned char *snapshot=NULL;
    unsigned char tag[32];
    size_t snapshotLength=0,i;
    int result=1;
    if (!sourceName || !lookups || !count || count>cmeContextRegistryMaxEntries ||
        cmeCopyDecode(manager,plan,length,digest,expected,catalog,&copy,&next,&source,&snapshot,&snapshotLength,tag)) goto done;
    if (strcmp(sourceName,source) || count!=copy->count) goto done;
    for (i=0;i<count;i++) if (!lookups[i] || strcmp(lookups[i],copy->slots[i].lookup)) goto done;
    result=0;
done:
    free(source); cmeContextMapFree(&copy); return(result);
}

static int cmeCopyPlanAction(cmeContextManager *manager, const unsigned char *plan, size_t length,
    const unsigned char digest[32], const cmeContextAnchor *expected, const cmeContextMapAnchor *catalog,
    int *status, cmeContextMap **copy, cmeContextAnchor *published, int commit)
{
    cmeContextAnchor original,next={0};
    cmeContextMapAnchor current={0};
    cmeContextMap *candidate=NULL;
    cmeManagerState state={0};
    char *source=NULL;
    const unsigned char *snapshot=NULL;
    unsigned char snapshotTag[32];
    size_t snapshotLength=0;
    int result=1,pending=0,classification=0;
    if (expected) { original=*expected; expected=&original; }
    if (status) *status=0;
    if (copy) *copy=NULL;
    if (published) memset(published,0,sizeof(*published));
    if (!copy || !published || !status ||
        cmeCopyDecode(manager,plan,length,digest,expected,catalog,&candidate,&next,&source,
            &snapshot,&snapshotLength,snapshotTag)) goto done;
    if (commit)
    {
        result=cmeManagerPublishPinned(manager,snapshot,snapshotLength,snapshotTag,&next,expected,catalog,source,1);
        classification=2;
    }
    else
    {
        pthread_mutex_lock(&manager->mutex);
        if (cmeManagerPrivate(manager) || sqlite3_exec(manager->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK ||
            cmeManagerLoad(manager,&state) || cmeMapLoad(manager,&current)) goto unlock;
        result=cmeMapMatch(&current,catalog); if (result) goto unlock;
        result=1;
        if (cmeShufflePending(manager,source,&pending) || pending) goto unlock;
        if (!cmeManagerCurrentMatch(&state,expected)) classification=1;
        else if (!cmeManagerCurrentMatch(&state,&next)) classification=2;
        else { result=2; goto unlock; }
        if (sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto unlock;
        result=0;
unlock:
        if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
        cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex);
    }
    if (!result) { *status=classification; *copy=candidate; candidate=NULL; *published=next; }
done:
    free(source); cmeContextMapFree(&candidate); return(result);
}

int cmeContextManagerCopyPlanStatus(cmeContextManager *manager, const unsigned char *plan,
    size_t length, const unsigned char digest[32], const cmeContextAnchor *expected,
    const cmeContextMapAnchor *catalog, int *state, cmeContextMap **copy, cmeContextAnchor *next)
{
    return(cmeCopyPlanAction(manager,plan,length,digest,expected,catalog,state,copy,next,0));
}

int cmeContextManagerCopyPlanCommit(cmeContextManager *manager, const unsigned char *plan,
    size_t length, const unsigned char digest[32], const cmeContextAnchor *expected,
    const cmeContextMapAnchor *catalog, cmeContextMap **copy, cmeContextAnchor *published)
{
    int state=0;
    return(cmeCopyPlanAction(manager,plan,length,digest,expected,catalog,&state,copy,published,1));
}

int cmeContextManagerShuffleInit(cmeContextManager *manager, const cmeContextAnchor *expected,
                                 const cmeContextMapAnchor *mapExpected, cmeContextMapAnchor *published)
{
    cmeManagerState state={0};
    cmeContextMapAnchor current={0},next={0},copy;
    unsigned char tag[32];
    int result=1,enabled;
    if (mapExpected) { copy=*mapExpected; mapExpected=&copy; }
    if (published) memset(published,0,sizeof(*published));
    if (!manager || !expected || !mapExpected || !published) return(1);
    pthread_mutex_lock(&manager->mutex);
    if (sqlite3_exec(manager->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    result=cmeShuffleCurrent(manager,expected,mapExpected,&state,&current); if (result) goto done;
    result=1;
    if (current.revision==UINT64_MAX || cmeShuffleVersion(manager,&enabled) || enabled) goto done;
    cmeManagerCheckpoint("after-begin");
    if (sqlite3_exec(manager->db,
        "ALTER TABLE registry_meta ADD COLUMN shuffle_version INTEGER NOT NULL DEFAULT 1 CHECK(shuffle_version=1);"
        "CREATE TABLE context_shuffles(map_name TEXT PRIMARY KEY NOT NULL,job BLOB UNIQUE NOT NULL CHECK(length(job)=32),state INTEGER NOT NULL CHECK(state IN(1,2,3)),finished BLOB NOT NULL CHECK(length(finished)=8),active_path TEXT NOT NULL,staged_path TEXT NOT NULL,source BLOB NOT NULL CHECK(length(source)=32),target BLOB NOT NULL CHECK(length(target)=32));"
        "CREATE TABLE context_shuffle_slots(map_name TEXT NOT NULL,table_name TEXT NOT NULL,slot INTEGER NOT NULL,field_name TEXT NOT NULL,lookup TEXT NOT NULL,PRIMARY KEY(map_name,table_name,slot,field_name));",
        NULL,NULL,NULL)!=SQLITE_OK || cmeMapSign(manager,current.revision+1,&next,tag) || cmeMapHead(manager,&next,tag)) goto done;
    cmeManagerCheckpoint("after-write");
    if (sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    cmeManagerCheckpoint("after-commit"); *published=next; result=0;
done:
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex); return(result);
}

int cmeContextManagerShufflePairInit(cmeContextManager *manager, const cmeContextAnchor *expected,
                                     const cmeContextMapAnchor *mapExpected, cmeContextMapAnchor *published)
{
    cmeManagerState state={0};
    cmeContextMapAnchor current={0},next={0},copy;
    sqlite3_stmt *stmt=NULL;
    unsigned char tag[32];
    int result=1,enabled,paired;
    if (mapExpected) { copy=*mapExpected; mapExpected=&copy; }
    if (published) memset(published,0,sizeof(*published));
    if (!manager || !expected || !mapExpected || !published) return(1);
    pthread_mutex_lock(&manager->mutex);
    if (sqlite3_exec(manager->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    result=cmeShuffleCurrent(manager,expected,mapExpected,&state,&current); if (result) goto done;
    result=1;
    if (current.revision==UINT64_MAX || cmeShuffleVersion(manager,&enabled) || !enabled ||
        cmePairVersion(manager,&paired) || paired || sqlite3_prepare_v2(manager->db,
        "SELECT 1 FROM context_shuffles WHERE state=1 LIMIT 1",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    cmeManagerCheckpoint("after-begin");
    if (sqlite3_exec(manager->db,
        "ALTER TABLE registry_meta ADD COLUMN pair_version INTEGER NOT NULL DEFAULT 1 CHECK(pair_version=1);"
        "CREATE TABLE context_shuffle_pairs(map_name TEXT PRIMARY KEY NOT NULL,active_path TEXT NOT NULL,"
        "staged_path TEXT NOT NULL,source BLOB NOT NULL CHECK(length(source)=32),target BLOB NOT NULL "
        "CHECK(length(target)=32),selection BLOB NOT NULL CHECK(length(selection)=32));",
        NULL,NULL,NULL)!=SQLITE_OK || cmeMapSign(manager,current.revision+1,&next,tag) || cmeMapHead(manager,&next,tag)) goto done;
    cmeManagerCheckpoint("after-write");
    if (sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    cmeManagerCheckpoint("after-commit"); *published=next; result=0;
done:
    sqlite3_finalize(stmt);
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex); return(result);
}

void cmeContextShuffleFree(cmeContextShuffle **shuffle)
{
    if (!shuffle || !*shuffle) return;
    free((*shuffle)->activePath); free((*shuffle)->stagedPath);
    if ((*shuffle)->pair)
    {
        free((*shuffle)->pair->activePath); free((*shuffle)->pair->stagedPath); free((*shuffle)->pair);
    }
    cmeContextMapFree(&(*shuffle)->target); free(*shuffle); *shuffle=NULL;
}

int cmeContextManagerShuffleRead(cmeContextManager *manager, const char *name,
                                 const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                                 cmeContextShuffle **shuffle)
{
    cmeManagerState state={0};
    cmeContextMapAnchor current={0};
    cmeContextShuffle *candidate=NULL;
    sqlite3_stmt *stmt=NULL;
    unsigned int i;
    int result=1,enabled,paired,step;
    if (shuffle) *shuffle=NULL;
    if (!manager || !expected || !mapExpected || !shuffle || cmeManagerName(name,1)) return(1);
    pthread_mutex_lock(&manager->mutex);
    if (sqlite3_exec(manager->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    result=cmeShuffleCurrent(manager,expected,mapExpected,&state,&current); if (result) goto done;
    result=1; if (cmeShuffleVersion(manager,&enabled) || !enabled) goto done;
    if (sqlite3_prepare_v2(manager->db,"SELECT j.job,j.state,j.finished,j.active_path,j.staged_path,j.source,j.target,m.resource,m.role "
        "FROM context_shuffles j JOIN context_maps m ON j.map_name=m.name WHERE j.map_name=?1",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_ROW) goto done;
    candidate=calloc(1,sizeof(*candidate));
    if (!candidate) goto done;
    candidate->target=calloc(1,sizeof(*candidate->target));
    if (!candidate->target) goto done;
    memcpy(candidate->job,sqlite3_column_blob(stmt,0),32); candidate->state=sqlite3_column_int(stmt,1);
    for (i=0;i<8;i++) candidate->finishedRevision=(candidate->finishedRevision<<8)|((const unsigned char *)sqlite3_column_blob(stmt,2))[i];
    candidate->activePath=strdup((const char *)sqlite3_column_text(stmt,3));
    candidate->stagedPath=strdup((const char *)sqlite3_column_text(stmt,4));
    memcpy(candidate->sourceDigest,sqlite3_column_blob(stmt,5),32); memcpy(candidate->targetDigest,sqlite3_column_blob(stmt,6),32);
    candidate->target->resource=strdup((const char *)sqlite3_column_text(stmt,7));
    candidate->target->role=(unsigned int)sqlite3_column_int(stmt,8); candidate->target->active=1;
    candidate->target->slots=calloc(cmeContextRegistryMaxEntries,sizeof(*candidate->target->slots));
    if (!candidate->activePath || !candidate->stagedPath || !candidate->target->resource || !candidate->target->slots) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(manager->db,"SELECT lookup,table_name,slot,field_name FROM context_shuffle_slots WHERE map_name=?1 "
        "ORDER BY table_name COLLATE BINARY,slot,field_name COLLATE BINARY",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        cmeContextSlot *slot;
        if (candidate->target->count==cmeContextRegistryMaxEntries) goto done;
        slot=&candidate->target->slots[candidate->target->count++];
        slot->lookup=strdup((const char *)sqlite3_column_text(stmt,0));
        slot->table=strdup((const char *)sqlite3_column_text(stmt,1)); slot->row=sqlite3_column_int64(stmt,2);
        slot->field=strdup((const char *)sqlite3_column_text(stmt,3));
        if (!slot->lookup || !slot->table || !slot->field) goto done;
    }
    if (step!=SQLITE_DONE || cmePairVersion(manager,&paired)) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (paired)
    {
        if (sqlite3_prepare_v2(manager->db,"SELECT active_path,staged_path,source,target,selection "
            "FROM context_shuffle_pairs WHERE map_name=?1",-1,&stmt,NULL)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
        step=sqlite3_step(stmt);
        if (step==SQLITE_ROW)
        {
            candidate->pair=calloc(1,sizeof(*candidate->pair));
            if (!candidate->pair) goto done;
            candidate->pair->activePath=strdup((const char *)sqlite3_column_text(stmt,0));
            candidate->pair->stagedPath=strdup((const char *)sqlite3_column_text(stmt,1));
            memcpy(candidate->pair->sourceDigest,sqlite3_column_blob(stmt,2),32);
            memcpy(candidate->pair->targetDigest,sqlite3_column_blob(stmt,3),32);
            memcpy(candidate->pair->selectionDigest,sqlite3_column_blob(stmt,4),32);
            if (!candidate->pair->activePath || !candidate->pair->stagedPath || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
        }
        else if (step!=SQLITE_DONE) goto done;
    }
    if (sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    *shuffle=candidate; candidate=NULL; result=0;
done:
    sqlite3_finalize(stmt);
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); cmeContextShuffleFree(&candidate);
    pthread_mutex_unlock(&manager->mutex); return(result);
}

static int cmeShuffleSlotCompare(const void *left, const void *right)
{
    const cmeContextSlot *a=*(const cmeContextSlot *const *)left,*b=*(const cmeContextSlot *const *)right;
    int result=strcmp(a->lookup,b->lookup);
    if (!result) result=strcmp(a->table,b->table);
    return(result ? result : strcmp(a->field,b->field));
}

static int cmeShufflePermutation(const cmeContextMap *source, const cmeContextSlot *target, size_t count)
{
    const cmeContextSlot **a=NULL,**b=NULL;
    size_t i;
    int result=1;
    if (!count || count!=source->count || count>cmeContextRegistryMaxEntries) return(1);
    a=calloc(count,sizeof(*a)); b=calloc(count,sizeof(*b));
    if (!a || !b) goto done;
    for (i=0;i<count;i++) { a[i]=&source->slots[i]; b[i]=&target[i]; }
    qsort(a,count,sizeof(*a),cmeShuffleSlotCompare); qsort(b,count,sizeof(*b),cmeShuffleSlotCompare);
    for (i=0;i<count;i++) if (cmeShuffleSlotCompare(&a[i],&b[i])) goto done;
    result=0;
done:
    free(a); free(b); return(result);
}

static int cmeShuffleFilesSafe(cmeContextManager *manager, const cmeOfflineArtifact *active,
                               const cmeOfflineArtifact *staged)
{
    struct stat authority;
    if (fstat(manager->directory,&authority)) return(1);
    return((active->status.st_dev==manager->device && active->status.st_ino==manager->inode) ||
        (staged->file>=0 && staged->status.st_dev==manager->device && staged->status.st_ino==manager->inode) ||
        (active->parent.st_dev==authority.st_dev && active->parent.st_ino==authority.st_ino) ||
        (staged->parent.st_dev==authority.st_dev && staged->parent.st_ino==authority.st_ino) ||
        (active->parent.st_dev==staged->parent.st_dev && active->parent.st_ino==staged->parent.st_ino) ||
        active->parent.st_dev!=staged->parent.st_dev ||
        (staged->file>=0 && active->status.st_dev!=staged->status.st_dev));
}

/* Companions must be distinct ResourcesDB siblings, not arbitrary destinations. */
static int cmePairPaths(const char *column, const char *resources)
{
    const char *a,*b;
    if (!column || !resources || !(a=strrchr(column,'/')) || !(b=strrchr(resources,'/')) ||
        strcmp(b+1,"ResourcesDB") || a-column!=b-resources || !strcmp(column,resources)) return(1);
    return(memcmp(column,resources,(size_t)(a-column))!=0);
}

static int cmePairFiles(cmeContextManager *manager, const char *column, const char *stagedColumn,
                        const cmeContextShufflePair *pair, int content,
                        cmeOfflineArtifact *active, cmeOfflineArtifact *staged)
{
    unsigned int i,nonzero=0;
    if (!pair || cmePairPaths(column,pair->activePath) || cmePairPaths(stagedColumn,pair->stagedPath) ||
        !memcmp(pair->sourceDigest,pair->targetDigest,32)) return(1);
    for (i=0;i<32;i++) nonzero|=pair->selectionDigest[i];
    return(!nonzero || cmeOfflineOpen(pair->activePath,1,active) ||
        cmeOfflineOpen(pair->stagedPath,content,staged) || cmeShuffleFilesSafe(manager,active,staged));
}

static int cmeShufflePrepare(cmeContextManager *manager, const char *name,
                                    const char *activePath, const char *stagedPath,
                                    const unsigned char sourceDigest[32], const unsigned char targetDigest[32],
                                    const cmeContextSlot *slots, size_t count,
                                    const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                                    unsigned char job[32], cmeContextMapAnchor *published,
                                    const cmeContextShufflePair *pair)
{
    cmeManagerState state={0};
    cmeContextMapAnchor current={0},next={0},copy;
    cmeContextMap *source=NULL;
    cmeContextBinding *verified=NULL;
    cmeOfflineArtifact active={.file=-1,.directory=-1},staged={.file=-1,.directory=-1};
    cmeOfflineArtifact resources={.file=-1,.directory=-1},stagedResources={.file=-1,.directory=-1};
    sqlite3_stmt *stmt=NULL;
    unsigned char nonce[32],tag[32];
    size_t i;
    unsigned int nonzero=0;
    int result=1,enabled,paired;
    if (mapExpected) { copy=*mapExpected; mapExpected=&copy; }
    if (published) memset(published,0,sizeof(*published));
    if (job) memset(job,0,32);
    if (!manager || !job || !published || !expected || !mapExpected || !sourceDigest || !targetDigest ||
        !slots || !count || count>cmeContextRegistryMaxEntries || !memcmp(sourceDigest,targetDigest,32)) return(1);
    result=cmeContextManagerMapRead(manager,name,expected,mapExpected,&source); if (result) return(result);
    result=1;
    if (!source->active || source->blocked || source->role!=4) goto before;
    result=cmeContextManagerBind(manager,source->resource,4,slots,count,expected,&verified); if (result) goto before;
    result=1;
    if (cmeShufflePermutation(source,slots,count) || cmeOfflineOpen(activePath,1,&active) ||
        cmeOfflineOpen(stagedPath,1,&staged) || cmeShuffleFilesSafe(manager,&active,&staged) ||
        CRYPTO_memcmp(active.digest,sourceDigest,32) || CRYPTO_memcmp(staged.digest,targetDigest,32)) goto before;
    if (pair && (cmePairFiles(manager,activePath,stagedPath,pair,1,&resources,&stagedResources) ||
        CRYPTO_memcmp(resources.digest,pair->sourceDigest,32) ||
        CRYPTO_memcmp(stagedResources.digest,pair->targetDigest,32))) goto before;
    pthread_mutex_lock(&manager->mutex);
    if (sqlite3_exec(manager->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    result=cmeShuffleCurrent(manager,expected,mapExpected,&state,&current); if (result) goto done;
    result=1;
    if (current.revision==UINT64_MAX || cmeShuffleVersion(manager,&enabled) || !enabled ||
        cmePairVersion(manager,&paired) || (pair && !paired) ||
        cmeOfflineVerify(&active) || cmeOfflineVerify(&staged) || cmeOfflineSync(&active,&staged)) goto done;
    if (pair)
    {
        if (cmeOfflineVerify(&resources) || cmeOfflineVerify(&stagedResources) ||
            cmeOfflineSync(&resources,&stagedResources) || sqlite3_prepare_v2(manager->db,
            "SELECT 1 FROM context_shuffles WHERE state=1 LIMIT 1",-1,&stmt,NULL)!=SQLITE_OK ||
            sqlite3_step(stmt)!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
    }
    cmeManagerCheckpoint("after-begin");
    if (sqlite3_prepare_v2(manager->db,"SELECT 1 FROM context_shuffles WHERE state=1 AND "
        "(active_path IN(?1,?2) OR staged_path IN(?1,?2)) LIMIT 1",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,activePath,-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,2,stagedPath,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (paired)
    {
        if (sqlite3_prepare_v2(manager->db,"DELETE FROM context_shuffle_pairs WHERE map_name=?1",-1,&stmt,NULL)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
        if (pair)
        {
            if (sqlite3_prepare_v2(manager->db,"INSERT INTO context_shuffle_pairs VALUES(?1,?2,?3,?4,?5,?6)",-1,&stmt,NULL)!=SQLITE_OK ||
                sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK ||
                sqlite3_bind_text(stmt,2,pair->activePath,-1,SQLITE_STATIC)!=SQLITE_OK ||
                sqlite3_bind_text(stmt,3,pair->stagedPath,-1,SQLITE_STATIC)!=SQLITE_OK ||
                sqlite3_bind_blob(stmt,4,pair->sourceDigest,32,SQLITE_STATIC)!=SQLITE_OK ||
                sqlite3_bind_blob(stmt,5,pair->targetDigest,32,SQLITE_STATIC)!=SQLITE_OK ||
                sqlite3_bind_blob(stmt,6,pair->selectionDigest,32,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
            sqlite3_finalize(stmt); stmt=NULL;
        }
    }
#ifdef CDSE_CONTEXT_MANAGER_TESTING
    if (getenv("CDSE_CONTEXT_MANAGER_RANDOM") && !strcmp(getenv("CDSE_CONTEXT_MANAGER_RANDOM"),"fail")) goto done;
#endif
    if (RAND_bytes(nonce,32)!=1) goto done;
    for (i=0;i<32;i++) nonzero|=nonce[i];
    if (!nonzero || sqlite3_prepare_v2(manager->db,"INSERT INTO context_shuffles VALUES(?1,?2,1,zeroblob(8),?3,?4,?5,?6) "
        "ON CONFLICT(map_name) DO UPDATE SET job=excluded.job,state=1,finished=excluded.finished,active_path=excluded.active_path,"
        "staged_path=excluded.staged_path,source=excluded.source,target=excluded.target",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_bind_blob(stmt,2,nonce,32,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,3,activePath,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_bind_text(stmt,4,stagedPath,-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,5,sourceDigest,32,SQLITE_STATIC)!=SQLITE_OK || sqlite3_bind_blob(stmt,6,targetDigest,32,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(manager->db,"DELETE FROM context_shuffle_slots WHERE map_name=?1",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(manager->db,"INSERT INTO context_shuffle_slots VALUES(?1,?2,?3,?4,?5)",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
    for (i=0;i<count;i++)
        if (sqlite3_bind_text(stmt,2,slots[i].table,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_bind_int64(stmt,3,slots[i].row)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,4,slots[i].field,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_bind_text(stmt,5,slots[i].lookup,-1,SQLITE_STATIC)!=SQLITE_OK ||
            sqlite3_step(stmt)!=SQLITE_DONE || sqlite3_reset(stmt)!=SQLITE_OK) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (cmeMapSign(manager,current.revision+1,&next,tag) || cmeMapHead(manager,&next,tag)) goto done;
    cmeManagerCheckpoint("after-write");
    if (sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    cmeManagerCheckpoint("after-commit"); memcpy(job,nonce,32); *published=next; result=0;
done:
    sqlite3_finalize(stmt);
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex);
before:
    cmeOfflineClose(&active); cmeOfflineClose(&staged);
    cmeOfflineClose(&resources); cmeOfflineClose(&stagedResources);
    cmeContextMapFree(&source); cmeContextBindingFree(&verified); return(result);
}

int cmeContextManagerShufflePrepare(cmeContextManager *manager, const char *name,
    const char *activePath, const char *stagedPath,
    const unsigned char sourceDigest[32], const unsigned char targetDigest[32],
    const cmeContextSlot *slots, size_t count, const cmeContextAnchor *expected,
    const cmeContextMapAnchor *mapExpected, unsigned char job[32], cmeContextMapAnchor *published)
{
    return(cmeShufflePrepare(manager,name,activePath,stagedPath,sourceDigest,targetDigest,
        slots,count,expected,mapExpected,job,published,NULL));
}

int cmeContextManagerShufflePairPrepare(cmeContextManager *manager, const char *name,
    const char *activePath, const char *stagedPath,
    const unsigned char sourceDigest[32], const unsigned char targetDigest[32],
    const cmeContextSlot *slots, size_t count, const cmeContextShufflePair *pair,
    const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
    unsigned char job[32], cmeContextMapAnchor *published)
{
    if (!pair)
    {
        if (job) memset(job,0,32);
        if (published) memset(published,0,sizeof(*published));
        return(1);
    }
    return(cmeShufflePrepare(manager,name,activePath,stagedPath,sourceDigest,targetDigest,
        slots,count,expected,mapExpected,job,published,pair));
}

static int cmeShuffleRecover(cmeContextManager *manager, const char *name,
                                    const unsigned char job[32], int complete,
                                    const cmeContextAnchor *expected, const cmeContextMapAnchor *mapExpected,
                                    cmeContextMapAnchor *published, int paired)
{
    cmeManagerState state={0};
    cmeContextMapAnchor current={0},next={0},copy;
    cmeContextShuffle *shuffle=NULL;
    cmeContextBinding *verified=NULL;
    cmeOfflineArtifact active={.file=-1,.directory=-1},staged={.file=-1,.directory=-1};
    cmeOfflineArtifact resources={.file=-1,.directory=-1},stagedResources={.file=-1,.directory=-1};
    sqlite3_stmt *stmt=NULL;
    unsigned char tag[32],finished[8];
    unsigned int i;
    int result=1,isTarget,resourcesTarget=0;
    if (mapExpected) { copy=*mapExpected; mapExpected=&copy; }
    if (published) memset(published,0,sizeof(*published));
    if (!manager || !job || !expected || !mapExpected || !published || (complete!=0 && complete!=1)) return(1);
    result=cmeContextManagerShuffleRead(manager,name,expected,mapExpected,&shuffle); if (result) return(result);
    result=1;
    if (paired!=(shuffle->pair!=NULL) || CRYPTO_memcmp(shuffle->job,job,32) ||
        (shuffle->state!=1 && shuffle->state!=(complete ? 2 : 3))) goto before;
    if (complete)
    {
        result=cmeContextManagerBind(manager,shuffle->target->resource,4,shuffle->target->slots,shuffle->target->count,expected,&verified);
        if (result) goto before;
    }
    result=1; pthread_mutex_lock(&manager->mutex);
    if (sqlite3_exec(manager->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    result=cmeShuffleCurrent(manager,expected,mapExpected,&state,&current); if (result) goto done;
    result=1;
    if (shuffle->state!=1 && shuffle->finishedRevision!=current.revision) { result=2; goto done; }
    if (shuffle->state==1 && current.revision==UINT64_MAX) goto done;
    cmeManagerCheckpoint("after-begin");
    if (cmeOfflineOpen(shuffle->activePath,1,&active) || cmeOfflineOpen(shuffle->stagedPath,0,&staged) ||
        cmeShuffleFilesSafe(manager,&active,&staged)) goto done;
    isTarget=!CRYPTO_memcmp(active.digest,shuffle->targetDigest,32);
    if (!isTarget && CRYPTO_memcmp(active.digest,shuffle->sourceDigest,32)) goto done;
    if (!complete && isTarget) goto done;
    if (paired)
    {
        if (cmePairFiles(manager,shuffle->activePath,shuffle->stagedPath,shuffle->pair,0,&resources,&stagedResources)) goto done;
        resourcesTarget=!CRYPTO_memcmp(resources.digest,shuffle->pair->targetDigest,32);
        if ((!resourcesTarget && CRYPTO_memcmp(resources.digest,shuffle->pair->sourceDigest,32)) ||
            (resourcesTarget && (!isTarget || !complete))) goto done;
        /* Validate both remaining candidates BEFORE the first irreversible rename. */
        if (complete && !resourcesTarget)
        {
            cmeOfflineClose(&stagedResources);
            if (cmeOfflineOpen(shuffle->pair->stagedPath,1,&stagedResources) ||
                cmeShuffleFilesSafe(manager,&resources,&stagedResources) ||
                CRYPTO_memcmp(stagedResources.digest,shuffle->pair->targetDigest,32)) goto done;
        }
    }
    if (shuffle->state!=1)
    {
        if (complete!=isTarget || (paired && (complete!=resourcesTarget ||
            cmeOfflineSync(&resources,&stagedResources))) || cmeOfflineSync(&active,&staged) ||
            sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
        *published=current; result=0; goto done;
    }
    if (complete && !isTarget)
    {
        cmeOfflineClose(&staged);
        if (cmeOfflineOpen(shuffle->stagedPath,1,&staged) || cmeShuffleFilesSafe(manager,&active,&staged) ||
            CRYPTO_memcmp(staged.digest,shuffle->targetDigest,32) || cmeOfflineInstall(&active,&staged)) goto done;
    }
    else if (cmeOfflineSync(&active,&staged)) goto done;
    if (paired)
    {
        cmeManagerCheckpoint("after-column-install");
        if (complete && !resourcesTarget)
        {
            if (cmeOfflineInstall(&resources,&stagedResources)) goto done;
        }
        else if (cmeOfflineSync(&resources,&stagedResources)) goto done;
        cmeManagerCheckpoint("after-resources-install");
    }
    cmeManagerCheckpoint("after-artifact-sync");
    if (complete)
    {
        if (sqlite3_prepare_v2(manager->db,"DELETE FROM context_map_slots WHERE map_name=?1",-1,&stmt,NULL)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
        if (sqlite3_prepare_v2(manager->db,"INSERT INTO context_map_slots SELECT map_name,table_name,slot,field_name,lookup "
            "FROM context_shuffle_slots WHERE map_name=?1",-1,&stmt,NULL)!=SQLITE_OK ||
            sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
    }
    for (i=0;i<8;i++) finished[i]=(unsigned char)((current.revision+1)>>(56-8*i));
    if (sqlite3_prepare_v2(manager->db,"UPDATE context_shuffles SET state=?2,finished=?3 WHERE map_name=?1 AND job=?4",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_bind_text(stmt,1,name,-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_int(stmt,2,complete ? 2 : 3)!=SQLITE_OK || sqlite3_bind_blob(stmt,3,finished,8,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,4,job,32,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE || sqlite3_changes(manager->db)!=1) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (cmeMapSign(manager,current.revision+1,&next,tag) || cmeMapHead(manager,&next,tag)) goto done;
    cmeManagerCheckpoint("after-write");
    if (sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    cmeManagerCheckpoint("after-commit"); *published=next; result=0;
done:
    sqlite3_finalize(stmt);
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); pthread_mutex_unlock(&manager->mutex);
before:
    cmeOfflineClose(&active); cmeOfflineClose(&staged);
    cmeOfflineClose(&resources); cmeOfflineClose(&stagedResources);
    cmeContextShuffleFree(&shuffle); cmeContextBindingFree(&verified); return(result);
}

int cmeContextManagerShuffleRecover(cmeContextManager *manager, const char *name,
    const unsigned char job[32], int complete, const cmeContextAnchor *expected,
    const cmeContextMapAnchor *mapExpected, cmeContextMapAnchor *published)
{
    return(cmeShuffleRecover(manager,name,job,complete,expected,mapExpected,published,0));
}

int cmeContextManagerShufflePairRecover(cmeContextManager *manager, const char *name,
    const unsigned char job[32], int complete, const cmeContextAnchor *expected,
    const cmeContextMapAnchor *mapExpected, cmeContextMapAnchor *published)
{
    return(cmeShuffleRecover(manager,name,job,complete,expected,mapExpected,published,1));
}
