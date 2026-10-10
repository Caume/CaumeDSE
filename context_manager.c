#include "common.h"
#include "context_manager.h"
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
#else
    (void)point;
#endif
}

int cmeContextManagerPublish(cmeContextManager *manager, const unsigned char *body, size_t length,
                             const unsigned char tag[32], const cmeContextAnchor *next,
                             const cmeContextAnchor *expected)
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
    cmeManagerCheckpoint("after-begin");
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
        "SELECT json_group_array(json(CASE WHEN json_extract(value,'$.lookup')=?2 "
        "THEN json_set(value,'$.state','revoked') ELSE value END)) FROM json_each(?1,'$.entries')";
    if (state->initialized && state->anchor.generation==UINT64_MAX) return(1);
    memcpy(next->deployment,manager->deployment,16); memcpy(next->organization,manager->organization,16);
    next->generation=state->initialized ? state->anchor.generation+1 : 1;
    next->minimumFormat=state->initialized ? state->anchor.minimumFormat : 1;
    if (sqlite3_prepare_v2(manager->db,query,-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,1,state->body ? (const char *)state->body : "{\"entries\":[]}",-1,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_text(stmt,2,lookup,-1,SQLITE_STATIC)!=SQLITE_OK ||
        (contextJSON && sqlite3_bind_text(stmt,3,contextJSON,-1,SQLITE_STATIC)!=SQLITE_OK) ||
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
    char *contextJSON=NULL;
    unsigned char *body=NULL,tag[32];
    unsigned int floor=0,i,start;
    size_t length=0;
    int result=1;
    if (expected) { expectedCopy=*expected; expected=&expectedCopy; }
    if (context) memset(context,0,sizeof(*context));
    if (published) memset(published,0,sizeof(*published));
    if (!manager || !published || cmeManagerName(lookup,1) ||
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
    if (cmeManagerIssue(manager,&state,lookup,contextJSON,&body,&length,tag,&next) ||
        sqlite3_exec(manager->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    result=0;
done:
    sqlite3_finalize(stmt);
    if (!sqlite3_get_autocommit(manager->db)) sqlite3_exec(manager->db,"ROLLBACK",NULL,NULL,NULL);
    cmeManagerStateFree(&state); cmeContextRegistryFree(&registry); sqlite3_free(contextJSON);
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
