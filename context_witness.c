#include "common.h"
#include "context_witness.h"

struct cmeContextWitness
{
    sqlite3 *db;
    int directory;
    dev_t device;
    ino_t inode;
    pthread_mutex_t mutex;
    unsigned char key[32],deployment[16],organization[16];
};

typedef struct
{
    cmeContextWitnessState state;
    unsigned char previous[40];
} cmeWitnessRecord;

static void cmeWitnessNumber(uint64_t value, unsigned char bytes[8])
{
    unsigned int i;
    for (i=0;i<8;i++) bytes[i]=(unsigned char)(value>>(56-8*i));
}

static uint64_t cmeWitnessDecode(const unsigned char bytes[8])
{
    unsigned int i;
    uint64_t value=0;
    for (i=0;i<8;i++) value=(value<<8)|bytes[i];
    return(value);
}

static int cmeWitnessPair(cmeContextWitness *witness, const cmeContextAnchor *registry,
                          const cmeContextMapAnchor *catalog, unsigned char bytes[113])
{
    if (!registry || !catalog || !registry->generation || !catalog->revision ||
        (registry->minimumFormat!=1 && registry->minimumFormat!=2) ||
        memcmp(registry->deployment,witness->deployment,16) || memcmp(registry->organization,witness->organization,16)) return(1);
    memcpy(bytes,registry->deployment,16); memcpy(bytes+16,registry->organization,16);
    cmeWitnessNumber(registry->generation,bytes+32); bytes[40]=(unsigned char)registry->minimumFormat;
    memcpy(bytes+41,registry->digest,32); cmeWitnessNumber(catalog->revision,bytes+73);
    memcpy(bytes+81,catalog->digest,32); return(0);
}

static int cmeWitnessSign(cmeContextWitness *witness, cmeWitnessRecord *record, unsigned char tag[32])
{
    static const unsigned char domain[]="CDSE-HKX-WITNESS-v1";
    unsigned char body[sizeof(domain)+32+8+113+40];
    size_t offset=sizeof(domain);
    unsigned int size;
    uint64_t revision=record->state.anchor.revision;
    if (!revision || cmeWitnessDecode(record->previous)!=(revision==1 ? 0 : revision-1)) return(1);
    if (revision==1)
    {
        unsigned int i,any=0;
        for (i=0;i<40;i++) any|=record->previous[i];
        if (any) return(1);
    }
    memcpy(body,domain,offset); memcpy(body+offset,witness->deployment,16); offset+=16;
    memcpy(body+offset,witness->organization,16); offset+=16;
    cmeWitnessNumber(revision,body+offset); offset+=8;
    if (cmeWitnessPair(witness,&record->state.registry,&record->state.catalog,body+offset)) return(1);
    offset+=113; memcpy(body+offset,record->previous,40);
    return(!HMAC(EVP_sha256(),witness->key,32,body,sizeof(body),tag,&size) || size!=32 ||
        !EVP_Digest(body,sizeof(body),record->state.anchor.digest,&size,EVP_sha256(),NULL) || size!=32);
}

static int cmeWitnessPrivate(cmeContextWitness *witness)
{
    struct stat parent,file,marker;
    return(fstat(witness->directory,&parent) || !S_ISDIR(parent.st_mode) || parent.st_uid!=geteuid() ||
        (parent.st_mode&07777)!=0700 || !parent.st_nlink ||
        fstatat(witness->directory,"witness.sqlite",&file,AT_SYMLINK_NOFOLLOW) || !S_ISREG(file.st_mode) ||
        file.st_uid!=geteuid() || (file.st_mode&07777)!=0600 || file.st_nlink!=1 ||
        file.st_dev!=witness->device || file.st_ino!=witness->inode ||
        fstatat(witness->directory,"witness.initialized",&marker,AT_SYMLINK_NOFOLLOW) ||
        !S_ISREG(marker.st_mode) || marker.st_uid!=geteuid() || (marker.st_mode&07777)!=0600 ||
        marker.st_nlink!=1 || marker.st_size!=0);
}

static void cmeWitnessCheckpoint(const char *point)
{
#ifdef CDSE_CONTEXT_MANAGER_TESTING
    const char *requested=getenv("CDSE_CONTEXT_WITNESS_CRASH");
    if (requested && !strcmp(requested,point)) _exit(86);
#else
    (void)point;
#endif
}

/* Caller holds mutex/transaction. Authenticate typed rows before interpreting
   pins; a missing publication never becomes a fresh initialization. */
static int cmeWitnessLoad(cmeContextWitness *witness, cmeWitnessRecord *record)
{
    sqlite3_stmt *stmt=NULL;
    unsigned char saved[32],tag[32];
    const unsigned char *bytes;
    int result=1,i;
    memset(record,0,sizeof(*record));
    if (cmeWitnessPrivate(witness) || sqlite3_prepare_v2(witness->db,
        "SELECT version,revision,registry,catalog,previous,tag,(SELECT count(*) FROM witness_current) FROM witness_current WHERE singleton=1",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
        sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || sqlite3_column_int64(stmt,0)!=1 || sqlite3_column_int64(stmt,6)!=1) goto done;
    for (i=1;i<6;i++)
        if (sqlite3_column_type(stmt,i)!=SQLITE_BLOB || sqlite3_column_bytes(stmt,i)!=(i==1 ? 8 : (i==2 ? 73 : (i==5 ? 32 : 40))) ||
            !sqlite3_column_blob(stmt,i)) goto done;
    record->state.anchor.revision=cmeWitnessDecode(sqlite3_column_blob(stmt,1));
    bytes=sqlite3_column_blob(stmt,2);
    memcpy(record->state.registry.deployment,bytes,16); memcpy(record->state.registry.organization,bytes+16,16);
    record->state.registry.generation=cmeWitnessDecode(bytes+32); record->state.registry.minimumFormat=bytes[40];
    memcpy(record->state.registry.digest,bytes+41,32);
    bytes=sqlite3_column_blob(stmt,3); record->state.catalog.revision=cmeWitnessDecode(bytes);
    memcpy(record->state.catalog.digest,bytes+8,32); memcpy(record->previous,sqlite3_column_blob(stmt,4),40);
    memcpy(saved,sqlite3_column_blob(stmt,5),32);
    if (sqlite3_step(stmt)!=SQLITE_DONE || cmeWitnessSign(witness,record,tag) || CRYPTO_memcmp(saved,tag,32)) goto done;
    result=0;
done:
    sqlite3_finalize(stmt); return(result);
}

static int cmeWitnessStore(cmeContextWitness *witness, cmeWitnessRecord *record)
{
    sqlite3_stmt *stmt=NULL;
    unsigned char pins[113],revision[8],tag[32];
    int result=1;
    if (cmeWitnessSign(witness,record,tag) || cmeWitnessPair(witness,&record->state.registry,&record->state.catalog,pins)) goto done;
    cmeWitnessNumber(record->state.anchor.revision,revision);
    if (sqlite3_prepare_v2(witness->db,"INSERT INTO witness_current VALUES(1,1,?1,?2,?3,?4,?5) "
        "ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,registry=excluded.registry,catalog=excluded.catalog,"
        "previous=excluded.previous,tag=excluded.tag",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,1,revision,8,SQLITE_STATIC)!=SQLITE_OK || sqlite3_bind_blob(stmt,2,pins,73,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,3,pins+73,40,SQLITE_STATIC)!=SQLITE_OK || sqlite3_bind_blob(stmt,4,record->previous,40,SQLITE_STATIC)!=SQLITE_OK ||
        sqlite3_bind_blob(stmt,5,tag,32,SQLITE_STATIC)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    result=0;
done:
    sqlite3_finalize(stmt); return(result);
}

void cmeContextWitnessClose(cmeContextWitness **witness)
{
    if (!witness || !*witness) return;
    sqlite3_close((*witness)->db);
    if ((*witness)->directory>=0) close((*witness)->directory);
    pthread_mutex_destroy(&(*witness)->mutex); OPENSSL_cleanse((*witness)->key,32);
    free(*witness); *witness=NULL;
}

int cmeContextWitnessOpen(const char *directory, int create, const unsigned char key[32],
                          const unsigned char deployment[16], const unsigned char organization[16],
                          const cmeContextAnchor *registry, const cmeContextMapAnchor *catalog,
                          cmeContextWitness **witness)
{
    cmeContextWitness *candidate=NULL;
    cmeWitnessRecord record={0};
    char canonical[PATH_MAX],path[PATH_MAX];
    struct stat parent,opened,file;
    sqlite3_stmt *stmt=NULL;
    unsigned int i,dep=0,org=0;
    int result=1,fd=-1;
    if (witness) *witness=NULL;
    if (!witness || !directory || !key || !deployment || !organization || (create!=0 && create!=1) ||
        !realpath(directory,canonical) || strcmp(directory,canonical) || lstat(directory,&parent) || !S_ISDIR(parent.st_mode) ||
        parent.st_uid!=geteuid() || (parent.st_mode&07777)!=0700 ||
        snprintf(path,sizeof(path),"%s/witness.sqlite",directory)>=(int)sizeof(path)) return(1);
    for (i=0;i<16;i++) { dep|=deployment[i]; org|=organization[i]; }
    if (!dep || !org) return(1);
    candidate=calloc(1,sizeof(*candidate)); if (!candidate) return(1);
    candidate->directory=-1;
    if (pthread_mutex_init(&candidate->mutex,NULL)) { free(candidate); return(1); }
    memcpy(candidate->key,key,32); memcpy(candidate->deployment,deployment,16); memcpy(candidate->organization,organization,16);
    candidate->directory=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if (candidate->directory<0 || fstat(candidate->directory,&opened) || parent.st_dev!=opened.st_dev || parent.st_ino!=opened.st_ino) goto done;
    if (create)
    {
        unsigned char pins[113];
        if (cmeWitnessPair(candidate,registry,catalog,pins)) goto done;
        if (!fstatat(candidate->directory,"witness.sqlite",&file,AT_SYMLINK_NOFOLLOW) || errno!=ENOENT) goto done;
        fd=openat(candidate->directory,"witness.initialized",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK,0600);
        if (fd<0 || fsync(fd)) goto done;
        close(fd); fd=-1;
        if (fsync(candidate->directory)) goto done;
        fd=openat(candidate->directory,"witness.sqlite",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK,0600);
        if (fd<0 || fstat(fd,&file)) goto done;
        close(fd); fd=-1;
    }
    else if (fstatat(candidate->directory,"witness.sqlite",&file,AT_SYMLINK_NOFOLLOW)) goto done;
    candidate->device=file.st_dev; candidate->inode=file.st_ino;
    /* Do not open/close an extra existing-DB fd: it can drop SQLite POSIX locks. */
    if (cmeWitnessPrivate(candidate) || sqlite3_open_v2(path,&candidate->db,
        SQLITE_OPEN_READWRITE|SQLITE_OPEN_FULLMUTEX|SQLITE_OPEN_NOFOLLOW,NULL)!=SQLITE_OK || cmeWitnessPrivate(candidate) ||
        sqlite3_busy_timeout(candidate->db,5000)!=SQLITE_OK || sqlite3_exec(candidate->db,
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA trusted_schema=OFF;",
        NULL,NULL,NULL)!=SQLITE_OK) goto done;
    if (sqlite3_prepare_v2(candidate->db,
        "SELECT (SELECT synchronous FROM pragma_synchronous),(SELECT journal_mode FROM pragma_journal_mode)",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW || sqlite3_column_int(stmt,0)!=3 ||
        !sqlite3_column_text(stmt,1) || strcmp((const char *)sqlite3_column_text(stmt,1),"delete")) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (create)
    {
        if (sqlite3_exec(candidate->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK) goto done;
        cmeWitnessCheckpoint("after-begin");
        if (sqlite3_exec(candidate->db,"CREATE TABLE witness_current(singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
            "version INTEGER NOT NULL CHECK(version=1),revision BLOB NOT NULL CHECK(length(revision)=8),"
            "registry BLOB NOT NULL CHECK(length(registry)=73),catalog BLOB NOT NULL CHECK(length(catalog)=40),"
            "previous BLOB NOT NULL CHECK(length(previous)=40),tag BLOB NOT NULL CHECK(length(tag)=32));",
            NULL,NULL,NULL)!=SQLITE_OK) goto done;
        record.state.anchor.revision=1; record.state.registry=*registry; record.state.catalog=*catalog;
        if (cmeWitnessStore(candidate,&record)) goto done;
        cmeWitnessCheckpoint("after-write");
        if (sqlite3_exec(candidate->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK || fsync(candidate->directory)) goto done;
        cmeWitnessCheckpoint("after-commit");
    }
    if (sqlite3_exec(candidate->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK || cmeWitnessLoad(candidate,&record) ||
        sqlite3_exec(candidate->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    *witness=candidate; candidate=NULL; result=0;
done:
    sqlite3_finalize(stmt);
    if (fd>=0) close(fd);
    if (candidate && candidate->db && !sqlite3_get_autocommit(candidate->db)) sqlite3_exec(candidate->db,"ROLLBACK",NULL,NULL,NULL);
    cmeContextWitnessClose(&candidate); return(result);
}

int cmeContextWitnessFetch(cmeContextWitness *witness, cmeContextWitnessState *state)
{
    cmeWitnessRecord record={0};
    int result=1;
    if (state) memset(state,0,sizeof(*state));
    if (!witness || !state) return(1);
    pthread_mutex_lock(&witness->mutex);
    if (sqlite3_exec(witness->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK || cmeWitnessLoad(witness,&record) ||
        sqlite3_exec(witness->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    *state=record.state; result=0;
done:
    if (!sqlite3_get_autocommit(witness->db)) sqlite3_exec(witness->db,"ROLLBACK",NULL,NULL,NULL);
    pthread_mutex_unlock(&witness->mutex); return(result);
}

int cmeContextWitnessCheck(cmeContextWitness *witness, const cmeContextAnchor *registry,
                           const cmeContextMapAnchor *catalog)
{
    cmeContextWitnessState state;
    unsigned char actual[113],expected[113];
    if (!witness || cmeWitnessPair(witness,registry,catalog,expected) || cmeContextWitnessFetch(witness,&state) ||
        cmeWitnessPair(witness,&state.registry,&state.catalog,actual)) return(1);
    return(CRYPTO_memcmp(actual,expected,sizeof(actual)) ? 2 : 0);
}

static int cmeWitnessStep(const cmeWitnessRecord *current, const cmeContextAnchor *registry,
                          const cmeContextMapAnchor *catalog, const unsigned char before[113],
                          const unsigned char after[113])
{
    return(current->state.anchor.revision!=UINT64_MAX &&
        ((current->state.registry.generation!=UINT64_MAX && registry->generation==current->state.registry.generation+1 &&
          registry->minimumFormat>=current->state.registry.minimumFormat && !CRYPTO_memcmp(before+73,after+73,40)) ||
         (current->state.catalog.revision!=UINT64_MAX && catalog->revision==current->state.catalog.revision+1 &&
          !CRYPTO_memcmp(before,after,73))));
}

int cmeContextWitnessReconcile(cmeContextWitness *witness, const cmeContextWitnessAnchor *expected,
                               const cmeContextAnchor *registry, const cmeContextMapAnchor *catalog,
                               cmeContextWitnessRecovery *recovery, cmeContextWitnessAnchor *current)
{
    cmeWitnessRecord record={0};
    cmeContextWitnessAnchor copy;
    cmeContextWitnessRecovery classification=cmeWitnessRecoveryInvalid;
    unsigned char before[113],after[113],token[40];
    int result=1;
    if (expected) { copy=*expected; expected=&copy; }
    if (current) memset(current,0,sizeof(*current));
    if (recovery) *recovery=cmeWitnessRecoveryInvalid;
    if (!witness || !expected || !expected->revision || !current || !recovery ||
        cmeWitnessPair(witness,registry,catalog,after)) return(1);
    cmeWitnessNumber(expected->revision,token); memcpy(token+8,expected->digest,32);
    pthread_mutex_lock(&witness->mutex);
    if (sqlite3_exec(witness->db,"BEGIN",NULL,NULL,NULL)!=SQLITE_OK || cmeWitnessLoad(witness,&record) ||
        cmeWitnessPair(witness,&record.state.registry,&record.state.catalog,before)) goto done;
    result=2;
    if (record.state.anchor.revision==expected->revision && !CRYPTO_memcmp(record.state.anchor.digest,expected->digest,32))
    {
        if (!CRYPTO_memcmp(before,after,113)) classification=cmeWitnessRecoveryCurrent;
        else if (cmeWitnessStep(&record,registry,catalog,before,after)) classification=cmeWitnessRecoveryAdvanceRequired;
    }
    else if (!CRYPTO_memcmp(record.previous,token,40) && !CRYPTO_memcmp(before,after,113))
        classification=cmeWitnessRecoveryAlreadyAdvanced;
    if (classification==cmeWitnessRecoveryInvalid) goto done;
    result=1;
    if (sqlite3_exec(witness->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    *current=record.state.anchor; *recovery=classification; result=0;
done:
    if (!sqlite3_get_autocommit(witness->db)) sqlite3_exec(witness->db,"ROLLBACK",NULL,NULL,NULL);
    pthread_mutex_unlock(&witness->mutex); return(result);
}

int cmeContextWitnessAdvance(cmeContextWitness *witness, const cmeContextWitnessAnchor *expected,
                             const cmeContextAnchor *registry, const cmeContextMapAnchor *catalog,
                             cmeContextWitnessAnchor *published)
{
    cmeWitnessRecord current={0},next={0};
    cmeContextWitnessAnchor copy;
    unsigned char before[113],after[113],token[40];
    int result=1;
    if (expected) { copy=*expected; expected=&copy; }
    if (published) memset(published,0,sizeof(*published));
    if (!witness || !expected || !expected->revision || !published || cmeWitnessPair(witness,registry,catalog,after)) return(1);
    cmeWitnessNumber(expected->revision,token); memcpy(token+8,expected->digest,32);
    pthread_mutex_lock(&witness->mutex);
    if (sqlite3_exec(witness->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK || cmeWitnessLoad(witness,&current) ||
        cmeWitnessPair(witness,&current.state.registry,&current.state.catalog,before)) goto done;
    if (current.state.anchor.revision!=expected->revision || CRYPTO_memcmp(current.state.anchor.digest,expected->digest,32))
    {
        result=2;
        if (!CRYPTO_memcmp(current.previous,token,40) && !CRYPTO_memcmp(before,after,113)) result=0;
        if (result || sqlite3_exec(witness->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) { if (!result) result=1; goto done; }
        *published=current.state.anchor; goto done;
    }
    if (!cmeWitnessStep(&current,registry,catalog,before,after)) goto done;
    cmeWitnessCheckpoint("after-begin");
    next.state.anchor.revision=current.state.anchor.revision+1; next.state.registry=*registry; next.state.catalog=*catalog;
    memcpy(next.previous,token,40);
    if (cmeWitnessStore(witness,&next)) goto done;
    cmeWitnessCheckpoint("after-write");
    if (sqlite3_exec(witness->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    cmeWitnessCheckpoint("after-commit"); *published=next.state.anchor; result=0;
done:
    if (!sqlite3_get_autocommit(witness->db)) sqlite3_exec(witness->db,"ROLLBACK",NULL,NULL,NULL);
    pthread_mutex_unlock(&witness->mutex); return(result);
}
