/* Offline ColumnFile staging; never modifies registered storage. */
#include "common.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>

static int cmeAdminCopy(sqlite3 *to, sqlite3 *from)
{
    sqlite3_backup *backup=sqlite3_backup_init(to,"main",from,"main");
    int result;
    if (!backup) return(1);
    result=sqlite3_backup_step(backup,-1);
    return(sqlite3_backup_finish(backup)!=SQLITE_OK || result!=SQLITE_DONE);
}

static int cmeAdminKey(const char *path, char key[257])
{
    struct stat st;
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
    ssize_t count;
    if (fd<0) return(1);
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() ||
        (st.st_mode&077) || st.st_size<1 || st.st_size>256)
    {
        close(fd);
        return(1);
    }
    count=read(fd,key,257);
    close(fd);
    if (count!=st.st_size || memchr(key,0,count)) return(1);
    if (key[count-1]=='\n') count--;
    if (!count) return(1);
    key[count]=0;
    return(0);
}

static int cmeAdminSchema(sqlite3 *db)
{
    const char *queries[]={"SELECT * FROM data LIMIT 0;","SELECT * FROM meta LIMIT 0;"};
    const char *names[]={"id","userId","orgId","salt","value","rowOrder","MAC","sign","MACProtected","signProtected","otphDKey",
                         "id","userId","orgId","salt","attribute","attributeData"};
    sqlite3_stmt *stmt=NULL;
    int table,column,offset=0,result=0;
    for (table=0;table<2;table++)
    {
        int columns=table ? 6 : 11;
        if (sqlite3_prepare_v2(db,queries[table],-1,&stmt,NULL)!=SQLITE_OK) return(1);
        if (sqlite3_column_count(stmt)!=columns) result=1;
        for (column=0;column<columns && !result;column++)
            if (strcmp(sqlite3_column_name(stmt,column),names[offset+column])) result=1;
        sqlite3_finalize(stmt);
        if (result) return(1);
        offset+=columns;
        if (sqlite3_prepare_v2(db,table ? "PRAGMA table_info(meta);" : "PRAGMA table_info(data);",
                               -1,&stmt,NULL)!=SQLITE_OK) return(1);
        if (sqlite3_step(stmt)!=SQLITE_ROW || strcmp((const char *)sqlite3_column_text(stmt,2),"INTEGER") ||
            sqlite3_column_int(stmt,5)!=1) result=1;
        sqlite3_finalize(stmt);
        if (result) return(1);
    }
    /* Reject extra objects, triggers, integrity fields, and unsafe helper IDs. */
    if (sqlite3_prepare_v2(db,
        "SELECT 1 FROM sqlite_master WHERE (name IN ('data','meta') AND type!='table') "
        "OR (name NOT IN ('data','meta') AND name NOT LIKE 'sqlite_%') UNION ALL "
        "SELECT 1 FROM data WHERE typeof(id)!='integer' OR id<1 OR id>2147483647 "
        "OR coalesce(MAC,'x')!='' OR coalesce(sign,'x')!='' OR coalesce(MACProtected,'x')!='' "
        "OR coalesce(signProtected,'x')!='' OR coalesce(otphDKey,'x')!='' UNION ALL "
        "SELECT 1 FROM meta WHERE typeof(id)!='integer' OR id<1 OR id>2147483647;",
        -1,&stmt,NULL)!=SQLITE_OK) return(1);
    result=sqlite3_step(stmt)!=SQLITE_DONE;
    sqlite3_finalize(stmt);
    return(result);
}

static int cmeAdminVerify(sqlite3 *db, const char *key, const char *profile)
{
    sqlite3_stmt *stmt=NULL;
    const char *queries[]={"SELECT salt,value,userId,orgId FROM data;",
                          "SELECT salt,attribute,attributeData,userId,orgId FROM meta;"};
    int table,column,result=0,step,written;
    for (table=0;table<2;table++)
    {
        if (sqlite3_prepare_v2(db,queries[table],-1,&stmt,NULL)!=SQLITE_OK) return(1);
        while ((step=sqlite3_step(stmt))==SQLITE_ROW && !result)
        {
            const char *alg=table ? cmeDefaultEncAlg : profile;
            for (column=1;column<sqlite3_column_count(stmt) && !result;column++)
            {
                char *salt=NULL;
                char *decoded=NULL;
                const char *value=(const char *)sqlite3_column_text(stmt,column);
                const char *saltText=(const char *)sqlite3_column_text(stmt,0);
                if (!value || !saltText || strlen(saltText)!=2*cmeDefaultSecureDBSaltLen ||
                    strspn(saltText,"0123456789abcdefABCDEF")!=strlen(saltText)) { result=1; break; }
                cmeStrConstrAppend(&salt,"%s",saltText);
                written=0;
                result=cmeUnprotectByteString(value,&decoded,alg,&salt,key,&written,strlen(value));
                if (!result && (written<=cmeDefaultValueSaltCharLen || memchr(decoded,0,written))) result=1;
                if (decoded) OPENSSL_cleanse(decoded,written>0 ? written : 1);
                cmeFree(decoded);
                if (!result && table && column==1)
                {
                    char *attribute=NULL;
                    result=cmeUnprotectDBSaltedValue(value,&attribute,alg,&salt,key,&written);
                    if (!result && strcmp(attribute,"protect") && strcmp(attribute,"name")) result=1;
                    cmeFree(attribute);
                }
                cmeFree(salt);
            }
        }
        if (step!=SQLITE_DONE) result=1;
        sqlite3_finalize(stmt);
        if (result) return(1);
    }
    return(0);
}

static int cmeAdminCompare(sqlite3 *before, sqlite3 *after)
{
    const char *queries[]={"SELECT id,userId,orgId,value,rowOrder,MAC,sign,MACProtected,signProtected,otphDKey FROM data ORDER BY id;",
        "SELECT id,userId,orgId,attribute,CASE WHEN attribute='protect' THEN '' ELSE attributeData END FROM meta ORDER BY id;"};
    sqlite3_stmt *a=NULL,*b=NULL;
    int table,column,sa,sb,result=0;
    for (table=0;table<2;table++)
    {
        if (sqlite3_prepare_v2(before,queries[table],-1,&a,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(after,queries[table],-1,&b,NULL)!=SQLITE_OK) result=1;
        while (!result)
        {
            sa=sqlite3_step(a); sb=sqlite3_step(b);
            if (sa!=sb || (sa!=SQLITE_ROW && sa!=SQLITE_DONE)) { result=1; break; }
            if (sa==SQLITE_DONE) break;
            for (column=0;column<sqlite3_column_count(a);column++)
            {
                const char *av=(const char *)sqlite3_column_text(a,column);
                const char *bv=(const char *)sqlite3_column_text(b,column);
                if (!av || !bv || strcmp(av,bv)) { result=1; break; }
            }
        }
        sqlite3_finalize(a); sqlite3_finalize(b); a=NULL; b=NULL;
        if (result) break;
    }
    return(result);
}

static int cmeAdminPlain(sqlite3 *db, const char *key, const char *profile)
{
    const char *reads[]={"SELECT id,salt,value,userId,orgId FROM data;",
                         "SELECT id,salt,attribute,attributeData,userId,orgId FROM meta;"};
    const char *writes[]={"UPDATE data SET value=?,userId=?,orgId=? WHERE id=?;",
                          "UPDATE meta SET attribute=?,attributeData=?,userId=?,orgId=? WHERE id=?;"};
    sqlite3_stmt *read=NULL,*write=NULL;
    int table,column,step,result=0,written;
    for (table=0;table<2;table++)
    {
        int fields=table ? 4 : 3;
        if (sqlite3_prepare_v2(db,reads[table],-1,&read,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(db,writes[table],-1,&write,NULL)!=SQLITE_OK) result=1;
        while (!result && (step=sqlite3_step(read))==SQLITE_ROW)
        {
            for (column=0;column<fields && !result;column++)
            {
                char *salt=NULL,*value=NULL;
                cmeStrConstrAppend(&salt,"%s",sqlite3_column_text(read,1));
                result=cmeUnprotectDBSaltedValue((const char *)sqlite3_column_text(read,column+2),
                    &value,table ? cmeDefaultEncAlg : profile,&salt,key,&written);
                if (!result) result=sqlite3_bind_text(write,column+1,value,-1,SQLITE_TRANSIENT)!=SQLITE_OK;
                if (value) OPENSSL_cleanse(value,strlen(value));
                cmeFree(value); cmeFree(salt);
            }
            if (!result) result=sqlite3_bind_int(write,fields+1,sqlite3_column_int(read,0))!=SQLITE_OK;
            if (!result) result=sqlite3_step(write)!=SQLITE_DONE;
            sqlite3_reset(write); sqlite3_clear_bindings(write);
        }
        if (!result && step!=SQLITE_DONE) result=1;
        sqlite3_finalize(read); sqlite3_finalize(write); read=NULL; write=NULL;
        if (result) break;
    }
    return(result);
}

static int cmeAdminSave(sqlite3 *db, const char *directory, const char *name)
{
    char path[PATH_MAX];
    sqlite3 *disk=NULL;
    int fd,result;
    if (snprintf(path,sizeof(path),"%s/%s",directory,name)>=(int)sizeof(path)) return(1);
    fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if (fd<0) return(1);
    close(fd);
    result=sqlite3_open(path,&disk)!=SQLITE_OK || cmeAdminCopy(disk,db);
    if (sqlite3_close(disk)!=SQLITE_OK) result=1;
    fd=open(path,O_RDONLY|O_NOFOLLOW);
    if (fd<0 || fsync(fd)) result=1;
    if (fd>=0) close(fd);
    fd=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if (fd<0 || fsync(fd)) result=1;
    if (fd>=0) close(fd);
    /* Persist the new checkpoint directory's entry in its parent as well. */
    if (!realpath(directory,path)) return(1);
    {
        char *separator=strrchr(path,'/');
        if (!separator) return(1);
        if (separator==path) separator[1]=0;
        else *separator=0;
    }
    fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if (fd<0 || fsync(fd)) result=1;
    if (fd>=0) close(fd);
    return(result);
}

int main(int argc, char **argv)
{
    const char *database=NULL,*scope=NULL,*sourceFile=NULL,*targetFile=NULL,*profile=NULL,*directory=NULL;
    const char *error="invalid arguments; run caumedse-admin --help";
    char sourceKey[257]={0},targetKey[257]={0},canonical[PATH_MAX],path[PATH_MAX];
    sqlite3 *source=NULL,*work=NULL,*plain=NULL,*readback=NULL;
    cmeReprotectDBReport report;
    cmeReprotectDBInventory inventory;
    int i,mode=0,result=1,fd;
    FILE *output;
    if (argc==2 && !strcmp(argv[1],"--help"))
    {
        puts("Usage: caumedse-admin reprotect-columnfile --database PATH --confirmed-scope REALPATH\n"
             "  --source-key-file PATH --target-key-file PATH --target-profile PROFILE\n"
             "  (--dry-run | --commit --output-dir NEW_DIRECTORY)\n"
             "Offline staging only. Source is never changed. Stop writers before export.\n"
             "Key files: owned regular files, mode 0600 or stricter, 1-256 bytes.\n"
             "Commit writes before.sqlite, after.sqlite, and verified checkpoint status.\n"
             "MAC/sign, shuffle, extra schemas and registered-resource updates are unsupported.");
        return(0);
    }
    if (argc<2 || strcmp(argv[1],"reprotect-columnfile")) goto arguments;
    for (i=2;i<argc;i++)
    {
        const char **option=NULL;
        if (!strcmp(argv[i],"--dry-run") || !strcmp(argv[i],"--commit"))
        {
            if (mode) goto arguments;
            mode=!strcmp(argv[i],"--dry-run") ? 1 : 2;
            continue;
        }
        if (!strcmp(argv[i],"--database")) option=&database;
        else if (!strcmp(argv[i],"--confirmed-scope")) option=&scope;
        else if (!strcmp(argv[i],"--source-key-file")) option=&sourceFile;
        else if (!strcmp(argv[i],"--target-key-file")) option=&targetFile;
        else if (!strcmp(argv[i],"--target-profile")) option=&profile;
        else if (!strcmp(argv[i],"--output-dir")) option=&directory;
        if (!option || *option || ++i>=argc || !argv[i][0]) goto arguments;
        *option=argv[i];
    }
    if (!database || !scope || !sourceFile || !targetFile || !profile || !mode ||
        (mode==2 && !directory) || (mode==1 && directory)) goto arguments;
    if (!realpath(database,canonical) || strcmp(scope,canonical))
    { error="confirmed scope must exactly equal the existing database realpath"; goto arguments; }
    if (cmeAdminKey(sourceFile,sourceKey) || cmeAdminKey(targetFile,targetKey))
    { error="unsafe or unreadable key file: require owner-only regular file, 1-256 bytes"; goto arguments; }
    /* Legacy DEBUG helpers log plaintext. Silence both streams before invoking them. */
    output=fdopen(dup(STDOUT_FILENO),"w");
    if (!output) goto arguments;
    if (!freopen("/dev/null","w",stdout) || !freopen("/dev/null","w",stderr))
    { error="cannot isolate helper diagnostics"; goto done; }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms();
#else
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ADD_ALL_CIPHERS |
                        OPENSSL_INIT_ADD_ALL_DIGESTS,NULL);
#endif
    error="random number generator initialization failed";
    if (cmeSeedPrng()) goto done;
    error="cannot load source snapshot; provide an offline exported SQLite ColumnFile";
    if (sqlite3_open_v2(canonical,&source,SQLITE_OPEN_READONLY,NULL)!=SQLITE_OK ||
        sqlite3_open(":memory:",&work)!=SQLITE_OK || cmeAdminCopy(work,source)) goto done;
    error="unsupported ColumnFile schema, IDs or integrity fields";
    if (cmeAdminSchema(work)) goto done;
    error="inventory failed: wrong source key or unavailable target profile";
    if (cmeInventoryMemSecureDBReprotect(work,sourceKey,profile,&inventory)) goto done;
    error="unsupported metadata or corrupt protected values; MAC/sign and shuffle require a dedicated migration";
    if (inventory.protectMetaRows!=1 || cmeAdminVerify(work,sourceKey,inventory.sourceProfile)) goto done;
    if (sqlite3_open(":memory:",&plain)!=SQLITE_OK || cmeAdminCopy(plain,work)) goto done;
    error="source plaintext verification failed";
    if (cmeAdminPlain(plain,sourceKey,inventory.sourceProfile)) goto done;
    if (mode==2)
    {
        error="output directory must not exist; use a private trusted parent directory";
        if (mkdir(directory,0700)) goto done;
        error="pre-mutation checkpoint failed; source unchanged, inspect output directory";
        if (cmeAdminSave(work,directory,"before.sqlite")) goto done;
    }
    error="migration failed; source unchanged, retain before.sqlite and retry in a new directory";
    if (cmeReprotectMemSecureDB(work,sourceKey,targetKey,profile,&report,0)) goto done;
    if (mode==2)
    {
        error="post-transaction checkpoint failed; source unchanged, do not use staged output";
        if (cmeAdminSave(work,directory,"after.sqlite")) goto done;
        snprintf(path,sizeof(path),"%s/after.sqlite",directory);
        if (sqlite3_open_v2(path,&readback,SQLITE_OPEN_READONLY,NULL)!=SQLITE_OK) goto done;
        sqlite3_close(work); work=NULL;
        if (sqlite3_open(":memory:",&work)!=SQLITE_OK || cmeAdminCopy(work,readback)) goto done;
    }
    error="target readback mismatch; source unchanged, do not use staged output";
    if (cmeAdminVerify(work,targetKey,profile) || cmeAdminPlain(work,targetKey,profile) ||
        cmeAdminCompare(plain,work)) goto done;
    if (mode==2)
    {
        const char *status="verified\nsource-unchanged\noffline-staging-only\n";
        snprintf(path,sizeof(path),"%s/status",directory);
        fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
        error="checkpoint status sync failed; source unchanged, repeat readback before using output";
        if (fd<0) goto done;
        i=write(fd,status,strlen(status))!=(ssize_t)strlen(status) || fsync(fd);
        close(fd);
        if (i) { unlink(path); goto done; }
        fd=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
        if (fd<0) { unlink(path); goto done; }
        i=fsync(fd); close(fd);
        if (i) { unlink(path); goto done; }
    }
    fprintf(output,"%s verified: dataRows=%d metaRows=%d protectedValueRows=%d; source unchanged\n",
            mode==1 ? "dry-run" : "staged commit",inventory.dataRows,inventory.metaRows,inventory.protectedValueRows);
    result=0;
done:
    if (result) fprintf(output,"Migration refused: %s.\n",error);
    fclose(output);
    sqlite3_close(source); sqlite3_close(work); sqlite3_close(plain); sqlite3_close(readback);
    OPENSSL_cleanse(sourceKey,sizeof(sourceKey)); OPENSSL_cleanse(targetKey,sizeof(targetKey));
    return(result ? 1 : 0);
arguments:
    fprintf(stderr,"Migration refused: %s.\n",error);
    OPENSSL_cleanse(sourceKey,sizeof(sourceKey)); OPENSSL_cleanse(targetKey,sizeof(targetKey));
    return(2);
}
