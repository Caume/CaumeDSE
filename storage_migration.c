/* Offline, single-key export migration. No live files are replaced. */
#include "admin.h"
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#if defined(HAVE_SQLITE3_SERIALIZE) && defined(HAVE_SQLITE3_DESERIALIZE)

static const char *cmeStorageDBs[]={"ResourcesDB","RolesDB","LogsDB"};
static const char *cmeStorageClasses[]={"ResourcesDB","RolesDB","LogsDB"};
static const char *cmeStorageTables[]={
    "documents users organizations storage filterWhitelist filterBlacklist",
    "documents users roleTables parserScripts outputDocuments content contentRows contentColumns dbNames dbTables tableRows tableColumns organizations storage documentTypes engineCommands transactions meta filterWhitelist filterBlacklist",
    "transactions meta"};
static unsigned long cmeStorageProfiles[4];
static int cmeStorageTargetReadback;

static int cmeStorageProfile(const char *cipher, const char *fallback, int count, int target)
{
    unsigned char *bytes=NULL;
    int length=0,index=-1;
    if (cmeB64ToStr((unsigned char *)cipher,&bytes,strlen(cipher),&length)) return(1);
    if (length>=9 && !memcmp(bytes,cmeHerraduraKExFrameMagic,8))
        index=bytes[8]==1 ? 2 : bytes[8]==2 ? 3 : -1;
    else index=(!strcmp(fallback,"aes-256-gcm") || !strcmp(fallback,"herradura-hske-nla1-aead-256")) ? 0 :
        !strcmp(fallback,"aes-256-cbc") ? 1 : -1;
    free(bytes);
    if (index<0) return(1);
    if (target && ((!strcmp(fallback,"herradura-hske-nla1-aead-256") && index!=2) ||
        (!strcmp(fallback,"aes-256-gcm") && index!=0) || (!strcmp(fallback,"aes-256-cbc") && index!=1))) return(1);
    if (count) cmeStorageProfiles[index]++;
    return(0);
}

static int cmeStorageName(const char *name)
{
    return(!name || !*name || strlen(name)>255 || strchr(name,'/') ||
        !strcmp(name,".") || !strcmp(name,"..") || strchr(name,'\n'));
}

static int cmeStorageRead(const char *root, const char *name, char **bytes, int *length)
{
    char path[PATH_MAX];
    struct stat st;
    int fd,result=1;
    ssize_t got,offset=0;
    *bytes=NULL;
    if (cmeStorageName(name) || snprintf(path,sizeof(path),"%s/%s",root,name)>=(int)sizeof(path)) return(1);
    fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
    if (fd<0) return(1);
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || st.st_nlink!=1 ||
        st.st_size<1 || st.st_size>64*1024*1024) goto done;
    *bytes=malloc(st.st_size+1);
    if (!*bytes) goto done;
    while (offset<st.st_size)
    {
        got=read(fd,*bytes+offset,st.st_size-offset);
        if (got<0 && errno==EINTR) continue;
        if (got<=0) goto done;
        offset+=got;
    }
    (*bytes)[offset]=0;
    *length=offset;
    result=0;
done:
    close(fd);
    if (result) { cmeFree(*bytes); }
    return(result);
}

static int cmeStorageSync(const char *path)
{
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW),result;
    if (fd<0) return(1);
    result=fsync(fd); close(fd);
    return(result!=0);
}

static int cmeStorageWrite(const char *root, const char *name, const char *bytes, int length)
{
    char path[PATH_MAX];
    struct stat st;
    int fd,result=1;
    ssize_t count,offset=0;
    if (cmeStorageName(name) || snprintf(path,sizeof(path),"%s/%s",root,name)>=(int)sizeof(path)) return(1);
    fd=open(path,O_WRONLY|O_CREAT|O_NOFOLLOW|O_NONBLOCK,0600);
    if (fd<0) return(1);
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || st.st_nlink!=1 ||
        (st.st_mode&077) || ftruncate(fd,0)) goto done;
    while (offset<length)
    {
        count=write(fd,bytes+offset,length-offset);
        if (count<0 && errno==EINTR) continue;
        if (count<=0) goto done;
        offset+=count;
    }
    result=fsync(fd)!=0;
done:
    close(fd);
    return(result || cmeStorageSync(root));
}

static int cmeStorageLoad(const char *root, const char *name, sqlite3 **db)
{
    char *bytes=NULL;
    int length,result=1;
    unsigned char *owned=NULL;
    if (cmeStorageRead(root,name,&bytes,&length)) return(1);
    if (length<100 || memcmp(bytes,"SQLite format 3",16) || sqlite3_open(":memory:",db)!=SQLITE_OK) goto done;
    owned=sqlite3_malloc64(length);
    if (!owned) goto done;
    memcpy(owned,bytes,length);
    /* Closed/checkpointed WAL exports need rollback-format headers in memory. */
    if ((owned[18]!=1 && owned[18]!=2) || (owned[19]!=1 && owned[19]!=2)) goto done;
    owned[18]=1; owned[19]=1;
    result=sqlite3_deserialize(*db,"main",owned,length,length,SQLITE_DESERIALIZE_FREEONCLOSE|SQLITE_DESERIALIZE_RESIZEABLE)!=SQLITE_OK;
    /* FREEONCLOSE transfers ownership even when deserialization fails. */
    owned=NULL;
    if (!result)
    {
        sqlite3_stmt *check=NULL;
        result=sqlite3_prepare_v2(*db,"PRAGMA quick_check;",-1,&check,NULL)!=SQLITE_OK ||
            sqlite3_step(check)!=SQLITE_ROW || !sqlite3_column_text(check,0) ||
            strcmp((const char *)sqlite3_column_text(check,0),"ok") || sqlite3_step(check)!=SQLITE_DONE;
        sqlite3_finalize(check);
    }
done:
    sqlite3_free(owned); cmeFree(bytes);
    return(result);
}

static int cmeStorageSave(sqlite3 *db, const char *root, const char *name)
{
    sqlite3_int64 length=0;
    if (sqlite3_exec(db,"VACUUM;",NULL,NULL,NULL)!=SQLITE_OK) return(1);
    unsigned char *bytes=sqlite3_serialize(db,"main",&length,0);
    int result=!bytes || length>64*1024*1024 || cmeStorageWrite(root,name,(const char *)bytes,length);
    sqlite3_free(bytes);
    return(result);
}

static int cmeStorageText(sqlite3_stmt *stmt, int column, const char **text)
{
    *text=(const char *)sqlite3_column_text(stmt,column);
    return(!*text || sqlite3_column_type(stmt,column)!=SQLITE_TEXT ||
        sqlite3_column_bytes(stmt,column)!=(int)strlen(*text));
}

static int cmeStorageSalt(const char *salt)
{
    return(!salt || strlen(salt)!=32 || strspn(salt,"0123456789abcdefABCDEF")!=32);
}

static int cmeStorageValue(const char *cipher, const char *saltText, const char *key,
                           const char *profile, char **plain, int prefixed)
{
    char *salt=NULL,*tag=NULL,*decoded=NULL;
    int written=0,result=1,length;
    *plain=NULL;
    if (!cipher || cmeStorageSalt(saltText)) return(1);
    cmeStrConstrAppend(&salt,"%s",saltText);
    if (prefixed)
    {
        if (strlen(cipher)<=64 || cmeHMACByteString((const unsigned char *)cipher+64,
            (unsigned char **)&tag,strlen(cipher+64),&written,cmeDefaultMACAlg,&salt,key) ||
            written!=64 || CRYPTO_memcmp(tag,cipher,64)) goto done;
        cipher+=64;
    }
    if (cmeStorageProfile(cipher,profile,0,cmeStorageTargetReadback)) goto done;
    if (cmeUnprotectByteString(cipher,&decoded,profile,&salt,key,&written,strlen(cipher))) goto done;
    length=written;
    if (length<32 || memchr(decoded,0,length) || strspn(decoded,"0123456789abcdefABCDEF")<32) goto done;
    *plain=strdup(decoded+32);
    if (!*plain) goto done;
    result=0;
done:
    if (decoded) OPENSSL_cleanse(decoded,written>0 ? written : 1);
    cmeFree(decoded); cmeFree(salt); cmeFree(tag);
    return(result);
}

static int cmeStorageTableAllowed(int kind, const char *table)
{
    char *list=strdup(cmeStorageTables[kind]),*save=NULL,*name;
    int found=0;
    for (name=strtok_r(list," ",&save);name;name=strtok_r(NULL," ",&save))
        if (!strcmp(table,name)) found=1;
    free(list);
    return(found);
}

/* Decode/encode every protected field, including NULL-preserving legacy records. */
static int cmeStorageInternal(sqlite3 *db, int kind, const char *key, const char *profile, int encode)
{
    sqlite3_stmt *tables=NULL,*read=NULL,*write=NULL;
    int result=1,step,column,columns,written,tableCount=0;
    char *query=NULL,*update=NULL;
    if (cmeCheckInternalDBSchema(db,cmeStorageClasses[kind],1)) return(1);
    if (kind==0 && cmeEnsureResourcesDBDocumentLookups(db)) return(1);
    if (sqlite3_prepare_v2(db,"SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%';",-1,&tables,NULL)!=SQLITE_OK) return(1);
    while ((step=sqlite3_step(tables))==SQLITE_ROW)
    {
        const char *type=(const char *)sqlite3_column_text(tables,0);
        const char *table=(const char *)sqlite3_column_text(tables,1);
        if (!strcmp(type,"index")) continue;
        if (strcmp(type,"table") || (strcmp(table,"schema_meta") && !cmeStorageTableAllowed(kind,table))) goto done;
        if (!strcmp(table,"schema_meta"))
        {
            if (sqlite3_prepare_v2(db,"SELECT count(*) FROM schema_meta WHERE key NOT IN ('schemaClass','schemaVersion','definitionsVersion','migrationState');",-1,&read,NULL)!=SQLITE_OK ||
                sqlite3_step(read)!=SQLITE_ROW || sqlite3_column_int(read,0)!=0) goto done;
            sqlite3_finalize(read); read=NULL;
            continue;
        }
        tableCount++;
        query=sqlite3_mprintf("SELECT * FROM \"%w\" ORDER BY id;",table);
        if (sqlite3_prepare_v2(db,query,-1,&read,NULL)!=SQLITE_OK) goto done;
        sqlite3_free(query); query=NULL;
        columns=sqlite3_column_count(read);
        int expected=kind==1 ? 12 : kind==2 ? (!strcmp(table,"transactions") ? 16 : 10) :
            !strcmp(table,"documents") ? 18 : !strcmp(table,"organizations") ? 8 : 12;
        if (columns!=expected) goto done;
        if (columns<5 || strcmp(sqlite3_column_name(read,0),"id") || strcmp(sqlite3_column_name(read,1),"userId") ||
            strcmp(sqlite3_column_name(read,2),"orgId") || strcmp(sqlite3_column_name(read,3),"salt")) goto done;
        cmeStrConstrAppend(&update,"UPDATE \"%s\" SET salt=?",table);
        for (column=1;column<columns;column++) if (column!=3)
        {
            query=sqlite3_mprintf(",\"%w\"=?",sqlite3_column_name(read,column));
            cmeStrConstrAppend(&update,"%s",query); sqlite3_free(query); query=NULL;
        }
        cmeStrConstrAppend(&update," WHERE id=?;");
        if (sqlite3_prepare_v2(db,update,-1,&write,NULL)!=SQLITE_OK) goto done;
        cmeFree(update);
        while ((step=sqlite3_step(read))==SQLITE_ROW)
        {
            const char *saltText=NULL;
            char *salt=NULL;
            int bind=2;
            if (sqlite3_column_type(read,0)!=SQLITE_INTEGER || sqlite3_column_int64(read,0)<1 ||
                cmeStorageText(read,3,&saltText) || cmeStorageSalt(saltText)) goto done;
            /* Document salts were assigned while recomputing payload MACs. */
            if (encode && (kind!=0 || strcmp(table,"documents"))) cmeGetRndSaltAnySize(&salt,16);
            else salt=strdup(saltText);
            if (!salt || sqlite3_bind_text(write,1,salt,-1,SQLITE_TRANSIENT)!=SQLITE_OK) { free(salt); goto done; }
            for (column=1;column<columns;column++) if (column!=3)
            {
                const char *name=sqlite3_column_name(read,column),*text=NULL;
                char *value=NULL,*tag=NULL,*combined=NULL;
                int bad=0;
                if (strstr(name,"Lookup"))
                {
                    char base[64]; int sourceColumn;
                    size_t length=strlen(name)-6;
                    if (kind!=0 || strcmp(table,"documents") || length>=sizeof(base)) { free(salt); goto done; }
                    memcpy(base,name,length); base[length]=0;
                    if (strcmp(base,"documentId") && strcmp(base,"storageId") && strcmp(base,"orgResourceId")) { free(salt); goto done; }
                    for (sourceColumn=0;sourceColumn<columns;sourceColumn++) if (!strcmp(sqlite3_column_name(read,sourceColumn),base)) break;
                    if (sourceColumn==columns || cmeStorageText(read,sourceColumn,&text)) { free(salt); goto done; }
                    if (encode) bad=cmeGetProtectDBLookupValue(base,text,key,&value);
                    else
                    {
                        bad=cmeStorageValue(text,saltText,key,profile,&value,1);
                        if (!bad) bad=cmeGetProtectDBLookupValue(base,value,key,&tag);
                        if (!bad && sqlite3_column_type(read,column)!=SQLITE_NULL)
                        {
                            const char *stored=NULL;
                            bad=cmeStorageText(read,column,&stored) || strlen(stored)!=strlen(tag) || CRYPTO_memcmp(stored,tag,strlen(tag));
                        }
                        cmeFree(value); value=tag; tag=NULL;
                    }
                }
                else if (sqlite3_column_type(read,column)==SQLITE_NULL)
                {
                    if (column<3) bad=1;
                }
                else
                {
                    bad=cmeStorageText(read,column,&text);
                    if (!bad && !encode)
                    {
                        bad=cmeStorageValue(text,saltText,key,profile,&value,1);
                        if (!bad && !cmeStorageTargetReadback) bad=cmeStorageProfile(text+64,profile,1,0);
                    }
                    if (!bad && encode)
                    {
                        bad=cmeProtectDBSaltedValue(text,&value,profile,&salt,key,&written);
                        if (!bad) bad=cmeHMACByteString((const unsigned char *)value,(unsigned char **)&tag,strlen(value),&written,cmeDefaultMACAlg,&salt,key);
                        if (!bad) { cmeStrConstrAppend(&combined,"%s%s",tag,value); cmeFree(value); value=combined; combined=NULL; }
                    }
                }
                if (!bad) bad=value ? sqlite3_bind_text(write,bind++,value,-1,SQLITE_TRANSIENT)!=SQLITE_OK : sqlite3_bind_null(write,bind++)!=SQLITE_OK;
                if (value) OPENSSL_cleanse(value,strlen(value));
                cmeFree(value); cmeFree(tag); cmeFree(combined);
                if (bad) { free(salt); goto done; }
            }
            free(salt);
            if (sqlite3_bind_int64(write,bind,sqlite3_column_int64(read,0))!=SQLITE_OK || sqlite3_step(write)!=SQLITE_DONE) goto done;
            sqlite3_reset(write); sqlite3_clear_bindings(write);
        }
        if (step!=SQLITE_DONE) goto done;
        sqlite3_finalize(read); read=NULL; sqlite3_finalize(write); write=NULL;
    }
    if (step!=SQLITE_DONE || tableCount!=(kind==0 ? 6 : kind==1 ? 20 : 2)) goto done;
    result=0;
done:
    sqlite3_finalize(tables); sqlite3_finalize(read); sqlite3_finalize(write);
    sqlite3_free(query); cmeFree(update);
    return(result);
}

static int cmeStorageCompare(sqlite3 *a, sqlite3 *b, int kind)
{
    sqlite3_stmt *tables=NULL,*left=NULL,*right=NULL;
    char *query=NULL;
    int result=1,step,sa,sb,i;
    if (sqlite3_prepare_v2(a,"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_meta';",-1,&tables,NULL)!=SQLITE_OK) return(1);
    while ((step=sqlite3_step(tables))==SQLITE_ROW)
    {
        const char *table=(const char *)sqlite3_column_text(tables,0);
        if (!cmeStorageTableAllowed(kind,table)) goto done;
        query=sqlite3_mprintf("SELECT * FROM \"%w\" ORDER BY id;",table);
        if (sqlite3_prepare_v2(a,query,-1,&left,NULL)!=SQLITE_OK || sqlite3_prepare_v2(b,query,-1,&right,NULL)!=SQLITE_OK) goto done;
        sqlite3_free(query); query=NULL;
        while ((sa=sqlite3_step(left))==SQLITE_ROW)
        {
            sb=sqlite3_step(right);
            if (sb!=sa || sqlite3_column_count(left)!=sqlite3_column_count(right)) goto done;
            for (i=0;i<sqlite3_column_count(left);i++)
            {
                const char *name=sqlite3_column_name(left,i);
                if (!strcmp(name,"salt") || strstr(name,"Lookup")) continue;
                if (sqlite3_column_type(left,i)!=sqlite3_column_type(right,i) ||
                    sqlite3_column_bytes(left,i)!=sqlite3_column_bytes(right,i)) goto done;
                if (sqlite3_column_bytes(left,i)>0 &&
                    memcmp(sqlite3_column_blob(left,i),sqlite3_column_blob(right,i),sqlite3_column_bytes(left,i))) goto done;
            }
        }
        if (sa!=SQLITE_DONE || sqlite3_step(right)!=SQLITE_DONE) goto done;
        sqlite3_finalize(left); left=NULL; sqlite3_finalize(right); right=NULL;
    }
    if (step==SQLITE_DONE) result=0;
done:
    sqlite3_finalize(tables); sqlite3_finalize(left); sqlite3_finalize(right); sqlite3_free(query);
    return(result);
}

static int cmeStorageColumnPlain(sqlite3 *db, const char *key, const char *dataProfile)
{
    sqlite3_stmt *meta=NULL,*data=NULL,*update=NULL;
    char shuffle[64]={0};
    int step,result=1,written;
    /* Strict verification before the existing plaintext comparison helper. */
    const char *queries[]={"SELECT salt,value,userId,orgId FROM data;","SELECT salt,attribute,attributeData,userId,orgId FROM meta;"};
    int table,column;
    for (table=0;table<2;table++)
    {
        if (sqlite3_prepare_v2(db,queries[table],-1,&data,NULL)!=SQLITE_OK) goto done;
        while ((step=sqlite3_step(data))==SQLITE_ROW)
            for (column=1;column<sqlite3_column_count(data);column++)
            {
                const char *salt=NULL,*value=NULL; char *plain=NULL;
                if (cmeStorageText(data,0,&salt) || cmeStorageText(data,column,&value) ||
                    cmeStorageValue(value,salt,key,table ? cmeDefaultEncAlg : dataProfile,&plain,0)) goto done;
                if (!cmeStorageTargetReadback && cmeStorageProfile(value,table ? cmeDefaultEncAlg : dataProfile,1,0)) { free(plain); goto done; }
                OPENSSL_cleanse(plain,strlen(plain)); free(plain);
            }
        if (step!=SQLITE_DONE) goto done;
        sqlite3_finalize(data); data=NULL;
    }
    if (cmeVerifyMemSecureDBIntegrity(db,key,dataProfile,0) || cmeAdminPlain(db,key,dataProfile)) goto done;
    if (sqlite3_prepare_v2(db,"SELECT attributeData FROM meta WHERE attribute='shuffle';",-1,&meta,NULL)!=SQLITE_OK) goto done;
    step=sqlite3_step(meta);
    if (step==SQLITE_ROW)
    {
        const char *profile=NULL;
        if (cmeStorageText(meta,0,&profile) || strlen(profile)>=sizeof(shuffle)) goto done;
        strcpy(shuffle,profile);
        if (sqlite3_step(meta)!=SQLITE_DONE) goto done;
    }
    else if (step!=SQLITE_DONE) goto done;
    if (*shuffle)
    {
        if (sqlite3_prepare_v2(db,"SELECT id,salt,rowOrder FROM data;",-1,&data,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(db,"UPDATE data SET rowOrder=? WHERE id=?;",-1,&update,NULL)!=SQLITE_OK) goto done;
        while ((step=sqlite3_step(data))==SQLITE_ROW)
        {
            const char *salt=NULL,*value=NULL; char *plain=NULL;
            if (cmeStorageText(data,1,&salt) || cmeStorageText(data,2,&value) ||
                cmeStorageValue(value,salt,key,shuffle,&plain,0)) goto done;
            if (!cmeStorageTargetReadback && cmeStorageProfile(value,shuffle,1,0)) { free(plain); goto done; }
            written=sqlite3_bind_text(update,1,plain,-1,SQLITE_TRANSIENT);
            free(plain);
            if (written!=SQLITE_OK || sqlite3_bind_int64(update,2,sqlite3_column_int64(data,0))!=SQLITE_OK || sqlite3_step(update)!=SQLITE_DONE) goto done;
            sqlite3_reset(update); sqlite3_clear_bindings(update);
        }
        if (step!=SQLITE_DONE) goto done;
        sqlite3_finalize(data); data=NULL;
        if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM data WHERE rowOrder='' OR rowOrder GLOB '*[^0-9]*' OR cast(rowOrder AS INTEGER)<1 "
            "OR cast(rowOrder AS INTEGER)>(SELECT count(*) FROM data) UNION ALL "
            "SELECT 1 FROM data GROUP BY cast(rowOrder AS INTEGER) HAVING count(*)!=1;",
            -1,&data,NULL)!=SQLITE_OK || sqlite3_step(data)!=SQLITE_DONE) goto done;
    }
    result=0;
done:
    sqlite3_finalize(meta); sqlite3_finalize(data); sqlite3_finalize(update);
    return(result);
}

static int cmeStorageColumn(sqlite3 *db, const char *sourceKey, const char *targetKey,
                             const char *sourceProfile, const char *targetProfile)
{
    sqlite3 *plain=NULL,*check=NULL;
    sqlite3_stmt *read=NULL,*write=NULL;
    cmeReprotectDBInventory inventory;
    cmeReprotectDBReport report;
    int result=1,step,column,written;
    /* Schema metadata is unencrypted; preserve only a validated known schema. */
    if (cmeCheckInternalDBSchema(db,"ColumnFile",1) || sqlite3_exec(db,"DROP TABLE IF EXISTS schema_meta;",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeAdminSchema(db) || cmeInventoryMemSecureDBReprotect(db,sourceKey,targetProfile,&inventory) || inventory.protectMetaRows!=1) goto done;
    if (sqlite3_open(":memory:",&plain)!=SQLITE_OK || cmeAdminCopy(plain,db) ||
        cmeStorageColumnPlain(plain,sourceKey,inventory.sourceProfile) ||
        cmeReprotectMemSecureDB(db,sourceKey,targetKey,targetProfile,&report,0)) goto done;
    /* The core helper rotates metadata keys; now rotate its storage profile. */
    if (sqlite3_prepare_v2(db,"SELECT id,salt,userId,orgId,attribute,attributeData FROM meta;",-1,&read,NULL)!=SQLITE_OK ||
        sqlite3_prepare_v2(db,"UPDATE meta SET salt=?,userId=?,orgId=?,attribute=?,attributeData=? WHERE id=?;",-1,&write,NULL)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(read))==SQLITE_ROW)
    {
        char *newSalt=NULL;
        const char *oldSalt=(const char *)sqlite3_column_text(read,1);
        for (column=2;column<6;column++)
        {
            char *value=NULL,*salt=strdup(oldSalt);
            int bad=cmeReprotectDBSaltedValue((const char *)sqlite3_column_text(read,column),&value,
                sourceProfile,targetProfile,&salt,&newSalt,targetKey,targetKey,&written,0);
            free(salt);
            if (!bad) bad=sqlite3_bind_text(write,column,value,-1,SQLITE_TRANSIENT)!=SQLITE_OK;
            cmeFree(value);
            if (bad) { cmeFree(newSalt); goto done; }
        }
        if (sqlite3_bind_text(write,1,newSalt,-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
            sqlite3_bind_int64(write,6,sqlite3_column_int64(read,0))!=SQLITE_OK || sqlite3_step(write)!=SQLITE_DONE) { cmeFree(newSalt); goto done; }
        cmeFree(newSalt); sqlite3_reset(write); sqlite3_clear_bindings(write);
    }
    if (step!=SQLITE_DONE) goto done;
    sqlite3_finalize(read); read=NULL; sqlite3_finalize(write); write=NULL;
    strcpy(cmeDefaultEncAlg,targetProfile);
    cmeStorageTargetReadback=1;
    if (sqlite3_open(":memory:",&check)!=SQLITE_OK || cmeAdminCopy(check,db) ||
        cmeStorageColumnPlain(check,targetKey,targetProfile) || cmeAdminCompare(plain,check) ||
        cmeSetInternalDBSchemaVersion(db,"ColumnFile") || sqlite3_exec(db,"VACUUM;",NULL,NULL,NULL)!=SQLITE_OK) goto done;
    result=0;
done:
    cmeStorageTargetReadback=0;
    strcpy(cmeDefaultEncAlg,sourceProfile);
    sqlite3_finalize(read); sqlite3_finalize(write); sqlite3_close(plain); sqlite3_close(check);
    return(result);
}

static int cmeStorageInventoryFiles(const char *root, sqlite3 *resources)
{
    DIR *directory=opendir(root);
    struct dirent *entry;
    sqlite3_stmt *find=NULL;
    int result=1,count=0;
    if (!directory || sqlite3_prepare_v2(resources,"SELECT count(*) FROM documents WHERE columnFile=?;",-1,&find,NULL)!=SQLITE_OK) goto done;
    while ((entry=readdir(directory)))
    {
        char *bytes=NULL; int length,i,known=0;
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if (++count>10000 || cmeStorageRead(root,entry->d_name,&bytes,&length)) goto done;
        free(bytes);
        for (i=0;i<3;i++) if (!strcmp(entry->d_name,cmeStorageDBs[i])) known=1;
        if (!known)
        {
            sqlite3_bind_text(find,1,entry->d_name,-1,SQLITE_TRANSIENT);
            if (sqlite3_step(find)!=SQLITE_ROW || sqlite3_column_int(find,0)!=1) goto done;
            sqlite3_reset(find); sqlite3_clear_bindings(find);
        }
    }
    sqlite3_finalize(find); find=NULL;
    if (sqlite3_prepare_v2(resources,"SELECT count(*)+3 FROM documents;",-1,&find,NULL)!=SQLITE_OK ||
        sqlite3_step(find)!=SQLITE_ROW || sqlite3_column_int(find,0)!=count) goto done;
    sqlite3_finalize(find); find=NULL;
    if (sqlite3_prepare_v2(resources,
        "SELECT 1 FROM documents d WHERE totalParts='' OR totalParts GLOB '*[^0-9]*' OR cast(totalParts AS INTEGER)<1 OR cast(totalParts AS INTEGER)>10000 "
        "OR partId='' OR partId GLOB '*[^0-9]*' OR cast(partId AS INTEGER)<1 OR cast(partId AS INTEGER)>cast(totalParts AS INTEGER) "
        "OR (SELECT count(*) FROM storage s WHERE s.storageId=d.storageId AND s.orgResourceId=d.orgResourceId)!=1 "
        "UNION ALL SELECT 1 FROM storage WHERE coalesce(type,'')!='local' "
        "UNION ALL SELECT 1 FROM documents GROUP BY documentId,storageId,orgResourceId,type,columnId "
        "HAVING count(*)!=max(cast(totalParts AS INTEGER)) OR count(DISTINCT cast(partId AS INTEGER))!=count(*) "
        "OR min(cast(totalParts AS INTEGER))!=max(cast(totalParts AS INTEGER));",
        -1,&find,NULL)!=SQLITE_OK || sqlite3_step(find)!=SQLITE_DONE) goto done;
    result=0;
done:
    if (directory) closedir(directory);
    sqlite3_finalize(find);
    return(result);
}

static int cmeStoragePayloads(sqlite3 *resources, const char *source, const char *after,
                               const char *sourceKey, const char *targetKey, const char *sourceProfile,
                               const char *targetProfile, int writeFiles, int *parts)
{
    sqlite3_stmt *read=NULL,*update=NULL;
    int result=1,step,length,written,plainLength;
    if (sqlite3_prepare_v2(resources,"SELECT id,salt,columnFile,partMAC,type FROM documents ORDER BY id;",-1,&read,NULL)!=SQLITE_OK ||
        sqlite3_prepare_v2(resources,"UPDATE documents SET salt=?,partMAC=? WHERE id=?;",-1,&update,NULL)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(read))==SQLITE_ROW)
    {
        const char *name=NULL,*oldSalt=NULL,*stored=NULL,*type=NULL;
        char *bytes=NULL,*salt=NULL,*tag=NULL,*targetSalt=NULL,*target=NULL,*plain=NULL,*check=NULL;
        sqlite3 *column=NULL,*readback=NULL;
        int bad=1,checkLength;
        if (cmeStorageText(read,1,&oldSalt) || cmeStorageText(read,2,&name) || cmeStorageText(read,3,&stored) ||
            cmeStorageText(read,4,&type) || cmeStorageSalt(oldSalt) || cmeStorageName(name)) goto partDone;
        for (int i=0;i<3;i++) if (!strcmp(name,cmeStorageDBs[i])) goto partDone;
        if (cmeStorageRead(source,name,&bytes,&length)) goto partDone;
        salt=strdup(oldSalt);
        if (cmeHMACByteString((const unsigned char *)bytes,(unsigned char **)&tag,length,&written,cmeDefaultMACAlg,&salt,sourceKey) ||
            strlen(stored)!=(size_t)written || CRYPTO_memcmp(tag,stored,written)) goto partDone;
        cmeFree(tag);
        cmeGetRndSaltAnySize(&targetSalt,16);
        if (!targetSalt) goto partDone;
        if (!strcmp(type,"file.csv"))
        {
            if (cmeStorageLoad(source,name,&column) || cmeStorageColumn(column,sourceKey,targetKey,sourceProfile,targetProfile)) goto partDone;
            sqlite3_int64 size=0;
            unsigned char *serialized=sqlite3_serialize(column,"main",&size,0);
            if (!serialized || size>64*1024*1024) { sqlite3_free(serialized); goto partDone; }
            target=malloc(size+1);
            if (!target) { sqlite3_free(serialized); goto partDone; }
            memcpy(target,serialized,size); target[size]=0; written=size; sqlite3_free(serialized);
        }
        else
        {
            if (memchr(bytes,0,length) || cmeStorageProfile(bytes,sourceProfile,1,0) ||
                cmeUnprotectByteString(bytes,&plain,sourceProfile,&salt,sourceKey,&plainLength,length) || plainLength<=0 ||
                cmeProtectByteString(plain,&target,targetProfile,&targetSalt,targetKey,&written,plainLength) ||
                cmeStorageProfile(target,targetProfile,0,1) ||
                cmeUnprotectByteString(target,&check,targetProfile,&targetSalt,targetKey,&checkLength,written) ||
                checkLength!=plainLength || (plainLength>0 && memcmp(plain,check,plainLength))) goto partDone;
        }
        strcpy(cmeDefaultEncAlg,targetProfile);
        if (writeFiles)
        {
            if (cmeStorageWrite(after,name,target,written)) goto partDone;
            char *persisted=NULL; int size;
            if (cmeStorageRead(after,name,&persisted,&size)) goto partDone;
            int mismatch=size!=written || memcmp(persisted,target,written);
            free(persisted);
            if (mismatch) goto partDone;
        }
        if (cmeHMACByteString((const unsigned char *)target,(unsigned char **)&tag,written,&length,cmeDefaultMACAlg,&targetSalt,targetKey) ||
            sqlite3_bind_text(update,1,targetSalt,-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
            sqlite3_bind_text(update,2,tag,-1,SQLITE_TRANSIENT)!=SQLITE_OK || sqlite3_bind_int64(update,3,sqlite3_column_int64(read,0))!=SQLITE_OK ||
            sqlite3_step(update)!=SQLITE_DONE) goto partDone;
        sqlite3_reset(update); sqlite3_clear_bindings(update);
        (*parts)++;
        bad=0;
partDone:
        strcpy(cmeDefaultEncAlg,sourceProfile);
        if (plain) OPENSSL_cleanse(plain,plainLength>0 ? plainLength : 1);
        if (check) OPENSSL_cleanse(check,checkLength>0 ? checkLength : 1);
        cmeFree(bytes); cmeFree(salt); cmeFree(tag); cmeFree(targetSalt); cmeFree(target); cmeFree(plain); cmeFree(check);
        sqlite3_close(column); sqlite3_close(readback);
        if (bad) goto done;
    }
    if (step==SQLITE_DONE) result=0;
done:
    sqlite3_finalize(read); sqlite3_finalize(update);
    return(result);
}

static int cmeStorageSnapshot(const char *source, const char *before, int resume)
{
    DIR *directory=opendir(source);
    struct dirent *entry;
    int result=1;
    if (!directory) return(1);
    while ((entry=readdir(directory)))
    {
        char *bytes=NULL,*previous=NULL; int length,oldLength,bad;
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if (cmeStorageRead(source,entry->d_name,&bytes,&length)) goto done;
        if (resume)
        {
            bad=cmeStorageRead(before,entry->d_name,&previous,&oldLength) || oldLength!=length || memcmp(bytes,previous,length);
            free(previous);
        }
        else bad=cmeStorageWrite(before,entry->d_name,bytes,length);
        free(bytes);
        if (bad) goto done;
    }
    result=0;
done:
    closedir(directory);
    return(result);
}

static int cmeStorageHash(const char *root, char **hash)
{
    struct dirent **entries=NULL;
    EVP_MD_CTX *context=EVP_MD_CTX_new();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size;
    int count=scandir(root,&entries,NULL,alphasort),i,result=1;
    if (count<0 || !context || EVP_DigestInit_ex(context,EVP_sha256(),NULL)!=1) goto done;
    for (i=0;i<count;i++)
    {
        char *bytes=NULL; int length;
        const char *name=entries[i]->d_name;
        if (!strcmp(name,".") || !strcmp(name,"..")) continue;
        if (cmeStorageRead(root,name,&bytes,&length)) goto done;
        char framing[64];
        int framingLength=snprintf(framing,sizeof(framing),"%zu:%d:",strlen(name),length);
        int bad=framingLength<0 || framingLength>=(int)sizeof(framing) ||
            EVP_DigestUpdate(context,framing,framingLength)!=1 ||
            EVP_DigestUpdate(context,name,strlen(name))!=1 || EVP_DigestUpdate(context,bytes,length)!=1;
        free(bytes);
        if (bad) goto done;
    }
    if (EVP_DigestFinal_ex(context,digest,&size)!=1 || cmeBytesToHexstr(digest,(unsigned char **)hash,size)) goto done;
    result=0;
done:
    if (entries) { for (i=0;i<count;i++) free(entries[i]); free(entries); }
    EVP_MD_CTX_free(context);
    return(result);
}

static int cmeStorageInvalidate(const char *root)
{
    char path[PATH_MAX];
    if (snprintf(path,sizeof(path),"%s/status",root)>=(int)sizeof(path) ||
        (unlink(path) && errno!=ENOENT)) return(1);
    return(cmeStorageSync(root));
}

int cmeStorageMain(int argc, char **argv)
{
    const char *root=NULL,*scope=NULL,*sourceFile=NULL,*targetFile=NULL,*sourceProfile=NULL,*targetProfile=NULL,*outputRoot=NULL;
    const char *error="invalid arguments; run caumedse-admin reprotect-storage --help";
    char canonical[PATH_MAX],before[PATH_MAX],after[PATH_MAX],parent[PATH_MAX],sourceKey[257]={0},targetKey[257]={0};
    char *binding=NULL,*bindingSalt=NULL,*bindingInput=NULL,*savedBinding=NULL,*sourceHash=NULL,*finalHash=NULL;
    sqlite3 *plain[3]={0},*encoded=NULL,*check=NULL;
    cmeCryptoProfile profile;
    struct stat st;
    FILE *output=NULL;
    int mode=0,resume=0,result=1,i,parts=0,written;
    if (argc==3 && !strcmp(argv[2],"--help"))
    {
        puts("Usage: caumedse-admin reprotect-storage --storage-root PATH --confirmed-scope REALPATH\n"
             "  --source-key-file PATH --target-key-file PATH --source-profile PROFILE --target-profile PROFILE\n"
             "  (--dry-run | --commit --output-dir NEW_DIRECTORY | --resume --output-dir DIRECTORY)\n"
             "Offline flat export: ResourcesDB, RolesDB, LogsDB and every registered payload.\n"
             "One source key must verify every record; stop all writers. No source files are changed.\n"
             "Resume restarts from verified protected before snapshots; publish only after verified status.");
        return(0);
    }
    for (i=2;i<argc;i++)
    {
        const char **option=NULL;
        if (!strcmp(argv[i],"--dry-run") || !strcmp(argv[i],"--commit") || !strcmp(argv[i],"--resume"))
        {
            if (mode) goto done;
            resume=!strcmp(argv[i],"--resume"); mode=!strcmp(argv[i],"--dry-run") ? 1 : 2; continue;
        }
        if (!strcmp(argv[i],"--storage-root")) option=&root;
        else if (!strcmp(argv[i],"--confirmed-scope")) option=&scope;
        else if (!strcmp(argv[i],"--source-key-file")) option=&sourceFile;
        else if (!strcmp(argv[i],"--target-key-file")) option=&targetFile;
        else if (!strcmp(argv[i],"--source-profile")) option=&sourceProfile;
        else if (!strcmp(argv[i],"--target-profile")) option=&targetProfile;
        else if (!strcmp(argv[i],"--output-dir")) option=&outputRoot;
        if (!option || *option || ++i>=argc || !*argv[i]) goto done;
        *option=argv[i];
    }
    if (!root || !scope || !sourceFile || !targetFile || !sourceProfile || !targetProfile || !mode ||
        (mode==2 && !outputRoot) || (mode==1 && outputRoot)) goto done;
    error="unsafe scope, key files or profile";
    if (!realpath(root,canonical) || strcmp(canonical,scope) || lstat(root,&st) || !S_ISDIR(st.st_mode) ||
        st.st_uid!=geteuid() || (st.st_mode&077) || cmeAdminKey(sourceFile,sourceKey) || cmeAdminKey(targetFile,targetKey) ||
        strlen(sourceProfile)>=64 || strlen(targetProfile)>=64 || cmeGetCryptoProfile(&profile,sourceProfile) ||
        !profile.implemented || !profile.allowedAsDefault || cmeGetCryptoProfile(&profile,targetProfile) || !profile.implemented || !profile.allowedAsDefault) goto done;
    output=fdopen(dup(STDOUT_FILENO),"w");
    if (!output || !freopen("/dev/null","w",stdout) || !freopen("/dev/null","w",stderr)) goto done;
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG|OPENSSL_INIT_ADD_ALL_CIPHERS|OPENSSL_INIT_ADD_ALL_DIGESTS,NULL);
    if (cmeSeedPrng()) goto done;
    strcpy(cmeDefaultEncAlg,sourceProfile);
    memset(cmeStorageProfiles,0,sizeof(cmeStorageProfiles));
    error="incomplete scope, unsupported schema, corrupt field/MAC/lookup or wrong source key";
    if (cmeStorageHash(canonical,&sourceHash)) goto done;
    for (i=0;i<3;i++) if (cmeStorageLoad(canonical,cmeStorageDBs[i],&plain[i]) ||
        cmeStorageInternal(plain[i],i,sourceKey,sourceProfile,0)) goto done;
    if (cmeStorageInventoryFiles(canonical,plain[0])) goto done;
    /* Checkpoint bindings authenticate parameters and target-key identity, not keys themselves. */
    if (mode==2)
    {
        error="unsafe checkpoint path or mismatched resume binding";
        char requested[PATH_MAX],proposed[PATH_MAX];
        if (strlen(outputRoot)>=sizeof(requested)) goto done;
        strcpy(requested,outputRoot);
        size_t size=strlen(requested);
        while (size>1 && requested[size-1]=='/') requested[--size]=0;
        char *leaf=strrchr(requested,'/');
        const char *name=leaf ? leaf+1 : requested;
        char basename[256];
        if (cmeStorageName(name)) goto done;
        strcpy(basename,name);
        if (leaf) { if (leaf==requested) leaf[1]=0; else *leaf=0; }
        else strcpy(requested,".");
        if (!realpath(requested,parent) || stat(parent,&st) || !S_ISDIR(st.st_mode) ||
            st.st_uid!=geteuid() || (st.st_mode&077) ||
            snprintf(proposed,sizeof(proposed),"%s/%s",parent,basename)>=(int)sizeof(proposed) ||
            (!strncmp(proposed,canonical,strlen(canonical)) &&
             (proposed[strlen(canonical)]=='/' || proposed[strlen(canonical)]==0))) goto done;
        if (!resume && mkdir(outputRoot,0700)) goto done;
        if (!realpath(outputRoot,parent) || lstat(outputRoot,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&077) ||
            snprintf(before,sizeof(before),"%s/before",parent)>=(int)sizeof(before) ||
            snprintf(after,sizeof(after),"%s/after",parent)>=(int)sizeof(after)) goto done;
        cmeStrConstrAppend(&bindingInput,"CaumeDSE:storageMigration:v1:%zu:%s:%zu:%s:%zu:%s:%zu:%s:%s",strlen(canonical),canonical,
            strlen(parent),parent,strlen(sourceProfile),sourceProfile,strlen(targetProfile),targetProfile,sourceHash);
        cmeStrConstrAppend(&bindingSalt,"%s",cmeDefaultLookupSalt);
        strcpy(cmeDefaultEncAlg,targetProfile);
        if (cmeHMACByteString((const unsigned char *)bindingInput,(unsigned char **)&binding,strlen(bindingInput),&written,cmeDefaultMACAlg,&bindingSalt,targetKey)) goto done;
        strcpy(cmeDefaultEncAlg,sourceProfile);
        if (resume)
        {
            int length;
            if (cmeStorageRead(parent,"binding",&savedBinding,&length) || length!=written || CRYPTO_memcmp(binding,savedBinding,written)) goto done;
            if (cmeStorageInvalidate(parent)) goto done;
            if (lstat(before,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&077) ||
                lstat(after,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&077) ||
                cmeStorageInventoryFiles(before,plain[0])) goto done;
        }
        else if (mkdir(before,0700) || mkdir(after,0700) || cmeStorageWrite(parent,"binding",binding,written)) goto done;
        if (cmeStorageSnapshot(canonical,before,resume) || cmeStorageSync(parent)) goto done;
        /* An interrupted retry must not retain a stale verified marker. */
        if (cmeStorageInvalidate(parent)) goto done;
    }
    else strcpy(after,"/offline-dry-run");
    error="payload integrity/migration/readback failed; source unchanged; checkpoint incomplete";
    if (cmeStoragePayloads(plain[0],mode==2 ? before : canonical,after,sourceKey,targetKey,sourceProfile,targetProfile,mode==2,&parts)) goto done;
    /* Exported storage paths become the immutable staged destination path. */
    sqlite3_stmt *pathUpdate=NULL;
    if (sqlite3_prepare_v2(plain[0],"UPDATE storage SET accessPath=?;",-1,&pathUpdate,NULL)!=SQLITE_OK) goto done;
    char access[PATH_MAX];
    if (snprintf(access,sizeof(access),"%s/",after)>=(int)sizeof(access)) { sqlite3_finalize(pathUpdate); goto done; }
    sqlite3_bind_text(pathUpdate,1,access,-1,SQLITE_TRANSIENT);
    i=sqlite3_step(pathUpdate); sqlite3_finalize(pathUpdate);
    if (i!=SQLITE_DONE) goto done;
    strcpy(cmeDefaultEncAlg,targetProfile);
    error="internal DB target integrity/lookup/plaintext readback failed; checkpoint incomplete";
    for (i=0;i<3;i++)
    {
        if (sqlite3_open(":memory:",&encoded)!=SQLITE_OK || cmeAdminCopy(encoded,plain[i]) ||
            cmeStorageInternal(encoded,i,targetKey,targetProfile,1) || cmeSetInternalDBSchemaVersion(encoded,cmeStorageClasses[i])) goto done;
        if (mode==2)
        {
            if (cmeStorageSave(encoded,after,cmeStorageDBs[i]) || cmeStorageLoad(after,cmeStorageDBs[i],&check)) goto done;
        }
        else if (sqlite3_open(":memory:",&check)!=SQLITE_OK || cmeAdminCopy(check,encoded)) goto done;
        cmeStorageTargetReadback=1;
        if (cmeStorageInternal(check,i,targetKey,targetProfile,0) || cmeStorageCompare(plain[i],check,i)) goto done;
        cmeStorageTargetReadback=0;
        sqlite3_close(encoded); encoded=NULL; sqlite3_close(check); check=NULL;
    }
    if (mode==2)
    {
        error="final scope/source verification or status sync failed; checkpoint incomplete";
        if (cmeStorageInventoryFiles(after,plain[0]) || cmeStorageSnapshot(canonical,before,1)) goto done;
        /* Ensure the checkpoint's directory entry is durable in its parent. */
        char outer[PATH_MAX]; strcpy(outer,parent);
        char *separator=strrchr(outer,'/');
        if (!separator) goto done;
        if (separator==outer) separator[1]=0; else *separator=0;
        if (cmeStorageHash(canonical,&finalHash) || strcmp(sourceHash,finalHash) || cmeStorageSync(outer)) goto done;
        const char *status="verified\nsource-unchanged\nwhole-export-verified\n";
        if (cmeStorageWrite(parent,"status",status,strlen(status)))
        {
            cmeStorageInvalidate(parent);
            goto done;
        }
    }
    else if (cmeStorageHash(canonical,&finalHash) || strcmp(sourceHash,finalHash)) goto done;
    fprintf(output,"%s verified: internalDBs=3 payloadParts=%d; source unchanged; runtime default=%s\n",
        mode==1 ? "dry-run" : "staged storage",parts,targetProfile);
    fprintf(output,"Source profiles: aes-256-gcm=%lu aes-256-cbc=%lu herradura-hske-nla1-aead-256=%lu herradura-hske-duplex-256=%lu\n",
        cmeStorageProfiles[0],cmeStorageProfiles[1],cmeStorageProfiles[2],cmeStorageProfiles[3]);
    result=0;
done:
    if (result) fprintf(output ? output : stderr,"Storage migration refused: %s.\n",error);
    if (output) fclose(output);
    for (i=0;i<3;i++) sqlite3_close(plain[i]);
    sqlite3_close(encoded); sqlite3_close(check);
    cmeFree(binding); cmeFree(bindingSalt); cmeFree(bindingInput); cmeFree(savedBinding);
    cmeFree(sourceHash); cmeFree(finalHash);
    OPENSSL_cleanse(sourceKey,sizeof(sourceKey)); OPENSSL_cleanse(targetKey,sizeof(targetKey));
    return(result);
}
#else
int cmeStorageMain(int argc, char **argv)
{
    (void)argc; (void)argv;
    fprintf(stderr,"Storage migration unavailable: SQLite serialization support is required.\n");
    return(1);
}
#endif
