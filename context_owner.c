/* Explicit local owner approval for offline, byte-preserving ColumnFile moves. */
#include "admin.h"
#include "context_manager.h"
#include "context_offline.h"
#include "context_witness.h"
#include <dirent.h>

typedef struct
{
    char *values[22],*registration[4];
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
static int cmeOwnerOutside(const char *export, const char *path);
static int cmeCopyOwnerPreflight(const cmeOwnerApproval *approval, const cmeContextMap *source,
    const cmeContextMap *destination, const char *key);
static int cmeCopyOwnerRegistration(sqlite3 *db, const cmeOwnerApproval *approval,
    const cmeOfflineArtifact *column, const char *key);
static int cmeCopyOwnerExport(sqlite3 *db, const cmeOwnerApproval *approval,
    const cmeOfflineArtifact *resources, const char *key);

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

static void cmeOwnerWriteHex(FILE *output, const unsigned char *bytes, size_t length)
{
    size_t i;
    for (i=0;i<length;i++) fprintf(output,"%02x",bytes[i]);
}

static void cmeOwnerPrint(const unsigned char *bytes, size_t length)
{
    cmeOwnerWriteHex(stdout,bytes,length);
}

static void cmeOwnerFree(cmeOwnerApproval *approval)
{
    size_t i;
    for (i=0;i<22;i++) free(approval->values[i]);
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

static int cmeOwnerRead(const char *path, size_t maximum, char **body, size_t *length, int binary)
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
    if ((binary && (fsync(fd) || fsync(parent.directory))) ||
        fstat(fd,&after) || before.st_size!=after.st_size || before.st_mtim.tv_sec!=after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec || before.st_ctim.tv_sec!=after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec || before.st_mode!=after.st_mode ||
        before.st_uid!=after.st_uid || before.st_nlink!=after.st_nlink || (!binary && memchr(candidate,0,offset)) ||
        fstatat(parent.directory,parent.name,&after,AT_SYMLINK_NOFOLLOW) ||
        before.st_dev!=after.st_dev || before.st_ino!=after.st_ino) goto done;
    candidate[offset]=0; *body=candidate; candidate=NULL;
    if (length) *length=offset;
    result=0;
done:
    if (candidate) { OPENSSL_cleanse(candidate,offset); free(candidate); }
    if (fd>=0) close(fd);
    cmeOfflineClose(&parent); return(result);
}

static int cmeOwnerFile(const char *path, size_t maximum, char **body)
{
    return(cmeOwnerRead(path,maximum,body,NULL,0));
}

static int cmeCopyOwnerParse(const char *body, cmeOwnerApproval *approval)
{
    static const char *names[]={"schema","manager","deployment","organization","map","registry",
        "catalog","witness","export","plan","lookups","source","candidate","sourceDigest","candidateDigest","profile",
        "resources","resourcesDigest","registration","storageAccessPath"};
    static const int columns[]={0,1,2,3,4,5,6,12,7,8,11,13,14,15,16,18,19,20,17,21};
    sqlite3 *db=NULL;
    sqlite3_stmt *stmt=NULL;
    unsigned char bytes[73];
    size_t i,seen=0;
    int result=1,step;
    if (sqlite3_open(":memory:",&db)!=SQLITE_OK || sqlite3_prepare_v2(db,
        "SELECT key,type,value FROM json_each(?1) WHERE json_valid(?1) AND json_type(?1)='object'",
        -1,&stmt,NULL)!=SQLITE_OK || sqlite3_bind_text(stmt,1,body,-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        const char *key=(const char *)sqlite3_column_text(stmt,0),*type=(const char *)sqlite3_column_text(stmt,1);
        int column;
        if (!key || !type || strlen(key)!=(size_t)sqlite3_column_bytes(stmt,0)) goto done;
        for (i=0;i<20;i++) if (!strcmp(key,names[i])) break;
        if (i==20) goto done;
        column=columns[i];
        if (approval->values[column] || strcmp(type,!i ? "integer" : ((i==10 || i==18) ? "array" : "text"))) goto done;
        if (!i)
        {
            if (sqlite3_column_type(stmt,2)!=SQLITE_INTEGER ||
                (sqlite3_column_int64(stmt,2)<1 || sqlite3_column_int64(stmt,2)>4)) goto done;
            approval->schema=(int)sqlite3_column_int64(stmt,2);
            approval->values[column]=strdup("1");
        }
        else approval->values[column]=cmeOwnerText(stmt,2,i==10 ? cmeContextRegistryMaxBytes : PATH_MAX-1);
        if (!approval->values[column]) goto done;
        seen++;
    }
    if (step!=SQLITE_DONE || seen!=(approval->schema==1 ? 11U : (approval->schema==2 ? 16U : 20U))) goto done;
    for (i=0;i<(approval->schema==1 ? 11U : (approval->schema==2 ? 16U : 20U));i++) if (!approval->values[columns[i]]) goto done;
    if (cmeOwnerHex(approval->values[2],approval->deployment,16) ||
        cmeOwnerHex(approval->values[3],approval->organization,16) || cmeOwnerHex(approval->values[5],bytes,73)) goto done;
    memcpy(approval->registry.deployment,bytes,16); memcpy(approval->registry.organization,bytes+16,16);
    for (i=0;i<8;i++) approval->registry.generation=(approval->registry.generation<<8)|bytes[32+i];
    approval->registry.minimumFormat=bytes[40]; memcpy(approval->registry.digest,bytes+41,32);
    if (memcmp(approval->deployment,bytes,16) || memcmp(approval->organization,bytes+16,16) ||
        approval->registry.minimumFormat!=1 || cmeOwnerHex(approval->values[6],bytes,40)) goto done;
    for (i=0;i<8;i++) approval->catalog.revision=(approval->catalog.revision<<8)|bytes[i];
    memcpy(approval->catalog.digest,bytes+8,32);
    if (approval->schema>=2 && (cmeOwnerHex(approval->values[15],approval->source,32) ||
        cmeOwnerHex(approval->values[16],approval->target,32))) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (approval->schema>=3)
    {
        if (cmeOwnerHex(approval->values[20],approval->resourcesSource,32) || *approval->values[21]!='/' ||
            sqlite3_prepare_v2(db,"SELECT json_extract(?1,'$[0]'),json_extract(?1,'$[1]'),json_extract(?1,'$[2]'),"
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
        sqlite3_bind_text(stmt,1,approval->values[11],-1,SQLITE_STATIC)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        if (approval->count==cmeContextRegistryMaxEntries || strcmp((const char *)sqlite3_column_text(stmt,0),"text")) goto done;
        approval->slots[approval->count].lookup=cmeOwnerText(stmt,1,128);
        if (!approval->slots[approval->count++].lookup) goto done;
    }
    if (step==SQLITE_DONE && approval->count) result=0;
done:
    sqlite3_finalize(stmt); sqlite3_close(db); return(result);
}

static int cmeCopyOwnerPaths(const cmeOwnerApproval *approval, const char *manifest,
    const char *key, const char *witnessKey, cmeOfflineArtifact *plan)
{
    const char *directories[]={approval->values[1],approval->values[12],approval->values[7]};
    const char *files[]={manifest,key,witnessKey};
    char parent[PATH_MAX],canonical[PATH_MAX],*slash;
    struct stat status,seen[3];
    size_t i,j;
    if (strlen(approval->values[8])>=sizeof(parent) || cmeOfflineOpen(approval->values[8],0,plan)) return(1);
    strcpy(parent,approval->values[8]); slash=strrchr(parent,'/');
    if (!slash || slash==parent) return(1);
    *slash=0;
    for (i=0;i<3;i++)
    {
        if (!realpath(directories[i],canonical) || strcmp(directories[i],canonical) ||
            lstat(directories[i],&status) || !S_ISDIR(status.st_mode) || status.st_uid!=geteuid() ||
            (status.st_mode&07777)!=0700 || !status.st_nlink ||
            !cmeOwnerOutside(directories[i],parent) || !cmeOwnerOutside(parent,directories[i])) return(1);
        if (status.st_dev==plan->parent.st_dev && status.st_ino==plan->parent.st_ino) return(1);
        for (j=0;j<i;j++) if (status.st_dev==seen[j].st_dev && status.st_ino==seen[j].st_ino) return(1);
        seen[i]=status;
        for (j=0;j<3;j++)
        {
            if (!files[j] || !cmeOwnerOutside(directories[i],files[j])) return(1);
            if (i!=j && !cmeOwnerOutside(directories[i],directories[j])) return(1);
        }
    }
    for (i=0;i<3;i++) if (!strcmp(files[i],approval->values[8])) return(1);
    return(0);
}

/* Leave even partial/uncertain files in place: never replace an owner receipt.
   A subsequent prepare refuses the name; no registry IDs are published here. */
static int cmeCopyOwnerSave(cmeOfflineArtifact *parent, const char *path, const unsigned char *bytes, size_t length)
{
    struct stat file,entry,directory;
    char directoryPath[PATH_MAX],*slash;
    size_t offset=0;
    int fd=-1,result=1;
    fd=openat(parent->directory,parent->name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK,0600);
    if (fd<0 || fchmod(fd,0600)) goto done;
    while (offset<length)
    {
        ssize_t written=write(fd,bytes+offset,length-offset);
        if (written<0 && errno==EINTR) continue;
        if (written<=0) goto done;
        offset+=(size_t)written;
    }
    strcpy(directoryPath,path); slash=strrchr(directoryPath,'/');
    if (!slash) goto done;
    *slash=0;
    if (fsync(fd) || fstat(fd,&file) || !S_ISREG(file.st_mode) || file.st_uid!=geteuid() ||
        (file.st_mode&07777)!=0600 || file.st_nlink!=1 || file.st_size!=(off_t)length ||
        fstatat(parent->directory,parent->name,&entry,AT_SYMLINK_NOFOLLOW) ||
        file.st_dev!=entry.st_dev || file.st_ino!=entry.st_ino || file.st_size!=entry.st_size ||
        fstat(parent->directory,&directory) || directory.st_uid!=geteuid() ||
        (directory.st_mode&07777)!=0700 || !directory.st_nlink || fsync(parent->directory) ||
        lstat(directoryPath,&entry) || entry.st_dev!=directory.st_dev || entry.st_ino!=directory.st_ino) goto done;
    result=0;
done:
    if (fd>=0 && close(fd)) result=1;
    return(result);
}

static void cmeCopyOwnerRegistry(const cmeContextAnchor *anchor, unsigned char bytes[73])
{
    size_t i;
    memcpy(bytes,anchor->deployment,16); memcpy(bytes+16,anchor->organization,16);
    for (i=0;i<8;i++) bytes[32+i]=(unsigned char)(anchor->generation>>(56-8*i));
    bytes[40]=(unsigned char)anchor->minimumFormat; memcpy(bytes+41,anchor->digest,32);
}

static int cmeCopyOwnerCandidatePaths(const cmeOwnerApproval *approval, const cmeOfflineArtifact *plan,
    const char *manifest, const char *key, const char *witnessKey, const char *orgKey)
{
    const char *directories[]={approval->values[1],approval->values[12],approval->values[7]};
    const char *controls[]={manifest,key,witnessKey,orgKey};
    cmeOfflineArtifact source={.file=-1,.directory=-1},candidate={.file=-1,.directory=-1};
    char parent[PATH_MAX],*slash;
    struct stat status;
    size_t i;
    int result=1;
    if (!orgKey || !strcmp(orgKey,key) || !strcmp(orgKey,witnessKey) || !strcmp(orgKey,approval->values[8]) ||
        cmeOfflineOpen(approval->values[13],0,&source) || cmeOfflineOpen(approval->values[14],0,&candidate)) goto done;
    strcpy(parent,approval->values[13]); slash=strrchr(parent,'/'); if (!slash) goto done; *slash=0;
    if (strcmp(parent,approval->values[7])) goto done;
    if (approval->schema>=3)
    {
        char expected[PATH_MAX];
        if (snprintf(expected,sizeof(expected),"%s/ResourcesDB",approval->values[7])>=(int)sizeof(expected) ||
            strcmp(expected,approval->values[19])) goto done;
    }
    strcpy(parent,approval->values[14]); slash=strrchr(parent,'/'); if (!slash) goto done; *slash=0;
    if (candidate.parent.st_dev==plan->parent.st_dev && candidate.parent.st_ino==plan->parent.st_ino) goto done;
    {
        char custody[PATH_MAX];
        strcpy(custody,approval->values[8]); slash=strrchr(custody,'/'); if (!slash) goto done; *slash=0;
        if (!cmeOwnerOutside(custody,parent) || !cmeOwnerOutside(parent,custody)) goto done;
    }
    for (i=0;i<3;i++)
        if (!cmeOwnerOutside(directories[i],parent) || !cmeOwnerOutside(parent,directories[i]) ||
            !cmeOwnerOutside(directories[i],orgKey) || lstat(directories[i],&status) ||
            (status.st_dev==candidate.parent.st_dev && status.st_ino==candidate.parent.st_ino)) goto done;
    for (i=0;i<4;i++) if (!cmeOwnerOutside(parent,controls[i])) goto done;
    result=0;
done:
    cmeOfflineClose(&source); cmeOfflineClose(&candidate); return(result);
}

static int cmeCopyOwnerMain(int argc, char **argv)
{
    cmeOwnerApproval approval={0};
    cmeContextManager *manager=NULL;
    cmeContextWitness *witness=NULL;
    cmeContextWitnessAnchor retained={0},current={0};
    cmeContextWitnessRecovery recovery=cmeWitnessRecoveryInvalid;
    cmeContextAnchor next={0};
    cmeContextMap *copy=NULL;
    cmeContextMap *source=NULL;
    cmeContextBinding *binding=NULL,*destinationBinding=NULL;
    cmeOfflineArtifact parent={.file=-1,.directory=-1};
    const char *manifest=NULL,*keyFile=NULL,*witnessFile=NULL,*witnessDirectory=NULL,*confirmation=NULL;
    const char *token=NULL,*digestText=NULL,*approvedRegistry=NULL,*action=NULL;
    const char *orgFile=NULL;
    const char **lookups=NULL;
    char *body=NULL,*keyText=NULL,*witnessText=NULL,*planText=NULL,*orgText=NULL;
    FILE *output=NULL,*diagnostics=NULL;
    unsigned char key[32]={0},witnessKey[32]={0},digest[32],bytes[73],approved[73],*prepared=NULL;
    size_t length=0,i;
    int result=1,state=0,prepare=0,advance=0,check=0,registered=0,export=0;
    if (argc==3 && !strcmp(argv[2],"--help"))
    {
        puts("Usage: caumedse-admin context-copy-plan --approval FILE --confirmed-offline APPROVAL_REALPATH\n"
             "  --registry-key-file FILE --witness-directory DIRECTORY --witness-key-file FILE\n"
             "  --retained-witness-token TOKEN (--prepare | --status | --commit | --advance-witness)\n"
             "  Status/commit/advance: --plan-digest SHA256\n"
             "  Advance only: --approved-registry PLANNED_NEXT_REGISTRY_TOKEN\n"
             "  Schema 2 only: --check-candidate --plan-digest SHA256 --org-key-file FILE\n"
             "  Schema 3 only: --check-registration --plan-digest SHA256 --org-key-file FILE\n"
             "  Schema 4 only: --check-export --plan-digest SHA256 --org-key-file FILE\n"
             "Private schema-1 approval, original pins, independently retained digest/token.\n"
             "Prepare exclusively creates and syncs the plan, never overwrites or allocates IDs.\n"
             "Stop all readers/writers. Retain uncertain files; never reset/blindly regenerate.\n"
             "Candidate check verifies complete selected ColumnFile cells and a byte-exact legacy clone.\n"
             "Registration check also verifies the selected source ResourcesDB association.\n"
             "Export check also accounts for all registered payloads, part groups and local storage.\n"
             "Neither check is destination registration acceptance or V2 context authentication.\n"
             "Witness advancement is separate. No physical copy, catalog publication or V2 writes.");
        return(0);
    }
    for (i=2;i<(size_t)argc;i++)
    {
        const char **option=NULL;
        if (!strcmp(argv[i],"--prepare") || !strcmp(argv[i],"--status") ||
            !strcmp(argv[i],"--commit") || !strcmp(argv[i],"--advance-witness") || !strcmp(argv[i],"--check-candidate") ||
            !strcmp(argv[i],"--check-registration") || !strcmp(argv[i],"--check-export"))
        { if (action) goto done; action=argv[i]; continue; }
        if (!strcmp(argv[i],"--approval")) option=&manifest;
        else if (!strcmp(argv[i],"--registry-key-file")) option=&keyFile;
        else if (!strcmp(argv[i],"--witness-key-file")) option=&witnessFile;
        else if (!strcmp(argv[i],"--witness-directory")) option=&witnessDirectory;
        else if (!strcmp(argv[i],"--confirmed-offline")) option=&confirmation;
        else if (!strcmp(argv[i],"--retained-witness-token")) option=&token;
        else if (!strcmp(argv[i],"--plan-digest")) option=&digestText;
        else if (!strcmp(argv[i],"--approved-registry")) option=&approvedRegistry;
        else if (!strcmp(argv[i],"--org-key-file")) option=&orgFile;
        if (!option || *option || ++i>=(size_t)argc || !*argv[i]) goto done;
        *option=argv[i];
    }
    if (!manifest || !keyFile || !witnessFile || !witnessDirectory || !confirmation || !token || !action ||
        strcmp(manifest,confirmation) || cmeOwnerFile(manifest,cmeContextRegistryMaxBytes,&body) ||
        cmeCopyOwnerParse(body,&approval) || strcmp(witnessDirectory,approval.values[12]) ||
        cmeCopyOwnerPaths(&approval,manifest,keyFile,witnessFile,&parent) ||
        cmeOwnerFile(keyFile,65,&keyText) || cmeOwnerFile(witnessFile,65,&witnessText)) goto done;
    prepare=!strcmp(action,"--prepare"); advance=!strcmp(action,"--advance-witness");
    export=!strcmp(action,"--check-export");
    registered=export || !strcmp(action,"--check-registration"); check=registered || !strcmp(action,"--check-candidate");
    if (check ? (approval.schema!=(export ? 4 : (registered ? 3 : 2)) || !orgFile) : (approval.schema!=1 || orgFile)) goto done;
    if ((prepare ? digestText!=NULL : (!digestText || cmeOwnerHex(digestText,digest,32))) ||
        (advance ? (!approvedRegistry || cmeOwnerHex(approvedRegistry,approved,73)) : approvedRegistry!=NULL)) goto done;
    if (strlen(keyText)==65 && keyText[64]=='\n') keyText[64]=0;
    if (strlen(witnessText)==65 && witnessText[64]=='\n') witnessText[64]=0;
    if (cmeOwnerHex(keyText,key,32) || cmeOwnerHex(witnessText,witnessKey,32) || !CRYPTO_memcmp(key,witnessKey,32) ||
        cmeOwnerHex(token,bytes,40)) goto done;
    for (i=0;i<8;i++) retained.revision=(retained.revision<<8)|bytes[i];
    memcpy(retained.digest,bytes+8,32);
    if (cmeContextManagerOpen(approval.values[1],0,key,approval.deployment,approval.organization,&manager) ||
        cmeContextWitnessOpen(approval.values[12],0,witnessKey,approval.deployment,approval.organization,
            &approval.registry,&approval.catalog,&witness)) goto done;
    lookups=calloc(approval.count,sizeof(*lookups));
    if (!lookups) goto done;
    for (i=0;i<approval.count;i++) lookups[i]=approval.slots[i].lookup;
    if (prepare)
    {
        result=cmeContextManagerCheckAnchors(manager,&approval.registry,&approval.catalog); if (result) goto done;
        result=cmeContextWitnessReconcile(witness,&retained,&approval.registry,&approval.catalog,&recovery,&current);
        if (result) goto done;
        if (recovery!=cmeWitnessRecoveryCurrent) { result=2; goto done; }
        result=cmeContextManagerCopyPlanPrepare(manager,approval.values[4],lookups,approval.count,
            &approval.registry,&approval.catalog,&prepared,&length,digest);
        if (result) goto done;
        planText=(char *)prepared; prepared=NULL;
    }
    else if (cmeOwnerRead(approval.values[8],cmeContextCopyPlanMaxBytes,&planText,&length,1)) goto done;
    result=1;
    if (cmeContextManagerCopyPlanMatch(manager,(unsigned char *)planText,length,digest,&approval.registry,
        &approval.catalog,approval.values[4],lookups,approval.count)) goto done;
    result=cmeContextManagerCopyPlanStatus(manager,(unsigned char *)planText,length,digest,&approval.registry,
        &approval.catalog,&state,&copy,&next);
    if (result) goto done;
    if (!check) cmeContextMapFree(&copy);
    result=cmeContextWitnessReconcile(witness,&retained,state==1 ? &approval.registry : &next,
        &approval.catalog,&recovery,&current);
    if (result) goto done;
    if (state==1 && recovery!=cmeWitnessRecoveryCurrent) { result=2; goto done; }
    if (state==2 && recovery==cmeWitnessRecoveryAdvanceRequired)
    { result=cmeContextWitnessCheck(witness,&approval.registry,&approval.catalog); if (result) goto done; }
    if (check)
    {
        cmeContextAnchor currentRegistry=state==1 ? approval.registry : next;
        result=1;
        if (cmeCopyOwnerCandidatePaths(&approval,&parent,manifest,keyFile,witnessFile,orgFile) ||
            cmeOwnerFile(orgFile,257,&orgText)) goto done;
        if (orgText[strlen(orgText)-1]=='\n') orgText[strlen(orgText)-1]=0;
        if (!*orgText || strlen(orgText)>256) goto done;
        output=fdopen(dup(STDOUT_FILENO),"w"); diagnostics=fdopen(dup(STDERR_FILENO),"w");
        if (!output || !diagnostics || fflush(NULL) || !freopen("/dev/null","w",stdout) || !freopen("/dev/null","w",stderr)) goto done;
        result=cmeContextManagerMapRead(manager,approval.values[4],&currentRegistry,&approval.catalog,&source);
        if (result) goto done;
        result=cmeContextManagerMapBind(manager,approval.values[4],&currentRegistry,&approval.catalog,&binding);
        if (result) goto done;
        if (state==2)
        {
            result=cmeContextManagerBind(manager,copy->resource,copy->role,copy->slots,copy->count,&currentRegistry,&destinationBinding);
            if (result) goto done;
        }
        result=1;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        OpenSSL_add_all_algorithms();
#else
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS,NULL);
#endif
        if (cmeCopyOwnerPreflight(&approval,source,copy,orgText)) goto done;
        result=cmeContextBindingCheck(manager,binding); if (result) goto done;
        if (destinationBinding) { result=cmeContextBindingCheck(manager,destinationBinding); if (result) goto done; }
        result=cmeContextWitnessReconcile(witness,&retained,&currentRegistry,&approval.catalog,&recovery,&current);
        if (result) goto done;
        if (state==1 && recovery!=cmeWitnessRecoveryCurrent) { result=2; goto done; }
        if (state==2 && recovery==cmeWitnessRecoveryAdvanceRequired)
        { result=cmeContextWitnessCheck(witness,&approval.registry,&approval.catalog); if (result) goto done; }
        fprintf(output,"state=%s\npublication=disabled\ninventory=complete-columnfile-cells\ncontext-authentication=absent\nplan-digest=",
            export ? "verified-legacy-export" : (registered ? "verified-legacy-registration" : "verified-legacy-candidate"));
        cmeOwnerWriteHex(output,digest,32); fputc('\n',output);
        if (registered)
        {
            fprintf(output,"registration=selected-source-columnfile\nresources-digest=");
            cmeOwnerWriteHex(output,approval.resourcesSource,32); fputc('\n',output);
        }
        if (export) fprintf(output,"export-inventory=complete-registered-payloads\npayload-authentication=registered-file-macs\n");
        goto done;
    }
    if (prepare)
    {
        if (state!=1) { result=2; goto done; }
        result=cmeCopyOwnerSave(&parent,approval.values[8],(unsigned char *)planText,length); if (result) goto done;
    }
    else if (!strcmp(action,"--commit") || advance)
    {
        if (advance)
        {
            cmeCopyOwnerRegistry(&next,bytes);
            if (state!=2 || CRYPTO_memcmp(bytes,approved,73)) { result=1; goto done; }
        }
        result=cmeContextWitnessCopyCommit(manager,witness,&retained,(unsigned char *)planText,length,digest,
            &approval.registry,&approval.catalog,&copy,&next);
        if (result) goto done;
        state=2;
        result=cmeContextWitnessReconcile(witness,&retained,&next,&approval.catalog,&recovery,&current);
        if (result) goto done;
        if (advance && recovery==cmeWitnessRecoveryAdvanceRequired)
        {
            result=cmeContextManagerCheckAnchors(manager,&next,&approval.catalog); if (result) goto done;
            result=cmeContextWitnessAdvance(witness,&retained,&next,&approval.catalog,&current); if (result) goto done;
            recovery=cmeWitnessRecoveryCurrent;
        }
    }
    printf("state=%s\nplan-digest=",prepare ? "prepared" : (advance ? "witness-advanced" : (state==1 ? "ready" : "committed")));
    cmeOwnerPrint(digest,32); cmeCopyOwnerRegistry(&next,bytes);
    printf("\nregistry="); cmeOwnerPrint(bytes,73);
    for (i=0;i<8;i++) bytes[i]=(unsigned char)(approval.catalog.revision>>(56-8*i));
    memcpy(bytes+8,approval.catalog.digest,32); printf("\ncatalog="); cmeOwnerPrint(bytes,40);
    printf("\nwitness-state=%s\n",recovery==cmeWitnessRecoveryAdvanceRequired ? "advance-required" :
        (recovery==cmeWitnessRecoveryAlreadyAdvanced ? "already-advanced" : "current"));
    if (advance)
    {
        for (i=0;i<8;i++) bytes[i]=(unsigned char)(current.revision>>(56-8*i));
        memcpy(bytes+8,current.digest,32); printf("witness-token="); cmeOwnerPrint(bytes,40); putchar('\n');
    }
    result=0;
done:
    if (result) fprintf(diagnostics ? diagnostics : stderr,"context-copy-plan: %s; retain existing plans, never reset blindly\n",
        result==2 ? "stale approval; reconcile owner pins" : "invalid approval or unavailable state");
    if (keyText) { OPENSSL_cleanse(keyText,strlen(keyText)); free(keyText); }
    if (witnessText) { OPENSSL_cleanse(witnessText,strlen(witnessText)); free(witnessText); }
    if (orgText) { OPENSSL_cleanse(orgText,strlen(orgText)); free(orgText); }
    OPENSSL_cleanse(key,sizeof(key)); OPENSSL_cleanse(witnessKey,sizeof(witnessKey));
    free(body); free(planText); free(prepared); free(lookups); cmeOfflineClose(&parent);
    cmeOwnerFree(&approval); cmeContextMapFree(&copy);
    cmeContextMapFree(&source); cmeContextBindingFree(&binding); cmeContextBindingFree(&destinationBinding);
    if (output) fclose(output);
    if (diagnostics) fclose(diagnostics);
    cmeContextWitnessClose(&witness); cmeContextManagerClose(&manager); return(result);
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

/* Coverage is every identity-bearing cell, not merely one handle per row.
   Salt, integer IDs and integrity/helper columns are checked by legacy schema/
   crypto verification; they are not independently allocated cell identities. */
static int cmeCopyOwnerInventory(sqlite3 *db, const cmeContextMap *source, const cmeContextMap *destination)
{
    static const char *tables[]={"data","meta"};
    static const char *fields[2][4]={{"value","userId","orgId","rowOrder"},
                                   {"attribute","attributeData","userId","orgId"}};
    sqlite3_stmt *stmt=NULL;
    size_t table,field,i,cells=0;
    int result=1,step;
    if (!source->active || source->blocked || source->role!=4 || source->count!=destination->count) return(1);
    for (i=0;i<source->count;i++)
        if (strcmp(source->slots[i].table,destination->slots[i].table) ||
            source->slots[i].row!=destination->slots[i].row || strcmp(source->slots[i].field,destination->slots[i].field)) return(1);
    for (table=0;table<2;table++)
    {
        if (sqlite3_prepare_v2(db,table ? "SELECT id FROM meta ORDER BY id" : "SELECT id FROM data ORDER BY id",
            -1,&stmt,NULL)!=SQLITE_OK) goto done;
        while ((step=sqlite3_step(stmt))==SQLITE_ROW)
        {
            int64_t row=sqlite3_column_int64(stmt,0);
            if (sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || row<1) goto done;
            for (field=0;field<4;field++)
            {
                size_t matches=0;
                if (++cells>cmeContextRegistryMaxEntries) goto done;
                for (i=0;i<source->count;i++)
                    if (!strcmp(source->slots[i].table,tables[table]) && source->slots[i].row==row &&
                        !strcmp(source->slots[i].field,fields[table][field])) matches++;
                if (matches!=1) goto done;
            }
        }
        if (step!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
    }
    if (cells && cells==source->count) result=0;
done:
    sqlite3_finalize(stmt); return(result);
}

static int cmeCopyOwnerPreflight(const cmeOwnerApproval *approval, const cmeContextMap *source,
    const cmeContextMap *destination, const char *key)
{
    cmeOfflineArtifact files[3];
    const char *paths[]={approval->values[13],approval->values[14]};
    sqlite3 *db[3]={NULL,NULL,NULL};
    sqlite3_stmt *stmt=NULL;
    unsigned int budgets[3]={20000,20000,20000};
    cmeCryptoProfile profile;
    char savedProfile[64];
    int i,j,result=1,count=approval->schema>=3 ? 3 : 2;
    strcpy(savedProfile,cmeDefaultEncAlg);
    for (i=0;i<3;i++) { memset(&files[i],0,sizeof(files[i])); files[i].file=-1; files[i].directory=-1; }
    if ((strcmp(approval->values[18],"aes-256-gcm") && strcmp(approval->values[18],"aes-256-cbc")) ||
        cmeGetCryptoProfile(&profile,approval->values[18]) || !profile.implemented || !profile.allowedAsDefault ||
        CRYPTO_memcmp(approval->source,approval->target,32)) goto done;
    strcpy(cmeDefaultEncAlg,approval->values[18]);
    for (i=0;i<2;i++)
    {
        if (cmeOfflineOpen(paths[i],1,&files[i]) || CRYPTO_memcmp(files[i].digest,approval->source,32) ||
            sqlite3_open_v2(paths[i],&db[i],SQLITE_OPEN_READONLY|SQLITE_OPEN_NOFOLLOW,NULL)!=SQLITE_OK) goto done;
        sqlite3_limit(db[i],SQLITE_LIMIT_LENGTH,cmeContextRegistryMaxBytes);
        sqlite3_limit(db[i],SQLITE_LIMIT_SQL_LENGTH,65536);
        sqlite3_progress_handler(db[i],1000,cmeOwnerBudget,&budgets[i]);
        if (sqlite3_exec(db[i],"PRAGMA trusted_schema=OFF; BEGIN",NULL,NULL,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(db[i],"SELECT 1 FROM pragma_table_list WHERE schema='main' AND type IN ('virtual','shadow')",
                -1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
        if (sqlite3_prepare_v2(db[i],"PRAGMA integrity_check",-1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
            !sqlite3_column_text(stmt,0) || strcmp((const char *)sqlite3_column_text(stmt,0),"ok") || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
        sqlite3_finalize(stmt); stmt=NULL;
        if (cmeOwnerRegisteredColumn(db[i],key,approval->values[18]) || cmeCopyOwnerInventory(db[i],source,destination)) goto done;
    }
    if ((files[0].status.st_dev==files[1].status.st_dev && files[0].status.st_ino==files[1].status.st_ino) ||
        (files[0].parent.st_dev==files[1].parent.st_dev && files[0].parent.st_ino==files[1].parent.st_ino)) goto done;
    if (count==3)
    {
        if (cmeOfflineOpen(approval->values[19],1,&files[2]) || CRYPTO_memcmp(files[2].digest,approval->resourcesSource,32) ||
            sqlite3_open_v2(approval->values[19],&db[2],SQLITE_OPEN_READONLY|SQLITE_OPEN_NOFOLLOW,NULL)!=SQLITE_OK) goto done;
        sqlite3_limit(db[2],SQLITE_LIMIT_LENGTH,cmeContextRegistryMaxBytes);
        sqlite3_limit(db[2],SQLITE_LIMIT_SQL_LENGTH,65536);
        sqlite3_progress_handler(db[2],1000,cmeOwnerBudget,&budgets[2]);
        if (sqlite3_exec(db[2],"PRAGMA trusted_schema=OFF; BEGIN",NULL,NULL,NULL)!=SQLITE_OK ||
            cmeCopyOwnerRegistration(db[2],approval,&files[0],key) ||
            (approval->schema==4 && cmeCopyOwnerExport(db[2],approval,&files[2],key))) goto done;
    }
    for (i=0;i<count;i++) for (j=0;j<i;j++)
        if (files[i].status.st_dev==files[j].status.st_dev && files[i].status.st_ino==files[j].status.st_ino) goto done;
    for (i=0;i<count;i++)
    {
        if (sqlite3_exec(db[i],"COMMIT",NULL,NULL,NULL)!=SQLITE_OK || sqlite3_close(db[i])!=SQLITE_OK) goto done;
        db[i]=NULL;
        if (cmeOfflineVerify(&files[i])) goto done;
    }
    result=0;
done:
    strcpy(cmeDefaultEncAlg,savedProfile); sqlite3_finalize(stmt);
    for (i=0;i<3;i++) { sqlite3_close(db[i]); cmeOfflineClose(&files[i]); }
    return(result);
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
                                 const cmeOfflineArtifact *column, const char *key, const char *columnPath)
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
    if (strcmp(plain[5],strrchr(columnPath,'/')+1) || strcmp(plain[6],"file.csv") ||
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
static int cmeOwnerRegisteredMetadata(sqlite3 *a, sqlite3 *b, const cmeOwnerApproval *approval,
                                      const char *key, const char *columnPath)
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
                if (!strcmp(value,strrchr(columnPath,'/')+1) && sqlite3_column_int64(left,0)!=approval->documentRow) goto done;
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

/* Source association only: same-handle comparison reuses the bounded schema,
   duplicate-filename and unique-local-storage checks without inventing a target
   ResourcesDB. Selected selectors/partMAC are authenticated separately. */
static int cmeCopyOwnerRegistration(sqlite3 *db, const cmeOwnerApproval *approval,
    const cmeOfflineArtifact *column, const char *key)
{
    static const int identity[]={7,8,9,14};
    sqlite3_stmt *stmt=NULL;
    char *plain[4]={0},*path=NULL;
    size_t i,rows=0,matches=0;
    int result=1,step;
    if (cmeOwnerRegisteredMetadata(db,db,approval,key,approval->values[13]) ||
        cmeOwnerRegisteredRow(db,approval,column,key,approval->values[13]) ||
        sqlite3_prepare_v2(db,"SELECT * FROM documents ORDER BY id",-1,&stmt,NULL)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        int same=1;
        if (++rows>cmeContextRegistryMaxEntries) goto done;
        for (i=0;i<4;i++)
        {
            if (cmeOwnerRegisteredValue(stmt,identity[i],key,approval->values[18],&plain[i])) goto done;
            if (strcmp(plain[i],approval->registration[i])) same=0;
        }
        if (same && sqlite3_column_int64(stmt,0)!=approval->documentRow) goto done;
        for (i=0;i<4;i++) { OPENSSL_cleanse(plain[i],strlen(plain[i])); free(plain[i]); plain[i]=NULL; }
    }
    if (step!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(db,"SELECT * FROM storage ORDER BY id",-1,&stmt,NULL)!=SQLITE_OK) goto done;
    rows=0;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        if (++rows>cmeContextRegistryMaxEntries ||
            cmeOwnerRegisteredValue(stmt,7,key,approval->values[18],&plain[0]) ||
            cmeOwnerRegisteredValue(stmt,11,key,approval->values[18],&plain[1])) goto done;
        if (!strcmp(plain[0],approval->registration[1]) && !strcmp(plain[1],approval->registration[2]))
        {
            if (++matches!=1 || cmeOwnerRegisteredValue(stmt,8,key,approval->values[18],&path) ||
                strcmp(path,approval->values[21])) goto done;
            OPENSSL_cleanse(path,strlen(path)); free(path); path=NULL;
        }
        for (i=0;i<2;i++) { OPENSSL_cleanse(plain[i],strlen(plain[i])); free(plain[i]); plain[i]=NULL; }
    }
    if (step==SQLITE_DONE && matches==1) result=0;
done:
    for (i=0;i<4;i++) if (plain[i]) { OPENSSL_cleanse(plain[i],strlen(plain[i])); free(plain[i]); }
    if (path) { OPENSSL_cleanse(path,strlen(path)); free(path); }
    sqlite3_finalize(stmt); return(result);
}

/* Enumerate twice against authenticated names. Never interpret a registered name
   as a path, or follow a protected historical storage accessPath. */
static int cmeCopyOwnerExportNames(sqlite3 *inventory, const char *root, size_t expected)
{
    DIR *directory=opendir(root);
    struct dirent *entry;
    sqlite3_stmt *stmt=NULL;
    size_t count=0;
    int result=1;
    if (!directory || sqlite3_prepare_v2(inventory,
        "SELECT 1 FROM parts WHERE name=?1 UNION ALL SELECT 1 WHERE ?1 IN ('ResourcesDB','RolesDB','LogsDB')",
        -1,&stmt,NULL)!=SQLITE_OK) goto done;
    for (;;)
    {
        errno=0; entry=readdir(directory);
        if (!entry) { if (errno) goto done; break; }
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if (++count>expected || sqlite3_bind_text(stmt,1,entry->d_name,-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
            sqlite3_step(stmt)!=SQLITE_ROW || sqlite3_step(stmt)!=SQLITE_DONE || sqlite3_reset(stmt)!=SQLITE_OK) goto done;
    }
    if (count==expected) result=0;
done:
    sqlite3_finalize(stmt); if (directory) closedir(directory); return(result);
}

static int cmeCopyOwnerExport(sqlite3 *db, const cmeOwnerApproval *approval,
    const cmeOfflineArtifact *resources, const char *key)
{
    static const int fields[]={5,7,8,9,6,14,11,12};
    static const char *lookupNames[]={"documentId","storageId","orgResourceId"};
    static const char *internal[]={"RolesDB","LogsDB"};
    sqlite3 *inventory=NULL;
    sqlite3_stmt *read=NULL,*insert=NULL,*check=NULL;
    cmeOfflineArtifact *artifacts=NULL,current={.file=-1,.directory=-1};
    char *plain[15]={0},*lookup=NULL,path[PATH_MAX];
    struct stat directory;
    size_t count=0,rows=0,i,j;
    unsigned int budget=20000;
    int result=1,step;
    artifacts=calloc(cmeContextRegistryMaxEntries+2,sizeof(*artifacts));
    if (!artifacts || sqlite3_open(":memory:",&inventory)!=SQLITE_OK) goto done;
    sqlite3_limit(inventory,SQLITE_LIMIT_LENGTH,cmeContextRegistryMaxBytes);
    sqlite3_progress_handler(inventory,1000,cmeOwnerBudget,&budget);
    if (sqlite3_exec(inventory,"PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;"
        "CREATE TABLE parts(name TEXT PRIMARY KEY,doc TEXT,storage TEXT,org TEXT,type TEXT,col TEXT,total INTEGER,part INTEGER);"
        "CREATE TABLE stores(storage TEXT,org TEXT,PRIMARY KEY(storage,org));",NULL,NULL,NULL)!=SQLITE_OK ||
        sqlite3_prepare_v2(db,"SELECT * FROM documents ORDER BY id",-1,&read,NULL)!=SQLITE_OK ||
        sqlite3_prepare_v2(inventory,"INSERT INTO parts VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",-1,&insert,NULL)!=SQLITE_OK) goto done;
    while ((step=sqlite3_step(read))==SQLITE_ROW)
    {
        if (++rows>cmeContextRegistryMaxEntries) goto done;
        for (i=1;i<15;i++)
            if (i!=3 && cmeOwnerRegisteredValue(read,(int)i,key,approval->values[18],&plain[i])) goto done;
        plain[3]=cmeOwnerText(read,3,32);
        if (!plain[3] || !*plain[5] || strlen(plain[5])>NAME_MAX || strchr(plain[5],'/') ||
            !strcmp(plain[5],".") || !strcmp(plain[5],"..") || !strcmp(plain[5],"ResourcesDB") ||
            !strcmp(plain[5],"RolesDB") || !strcmp(plain[5],"LogsDB")) goto done;
        for (i=6;i<=9;i++) if (!*plain[i] || strlen(plain[i])>128) goto done;
        if (!*plain[14] || strlen(plain[14])>128) goto done;
        for (i=11;i<=12;i++)
        {
            char *end=NULL;
            unsigned long value;
            errno=0; value=strtoul(plain[i],&end,10);
            if (!*plain[i] || strspn(plain[i],"0123456789")!=strlen(plain[i]) || errno || !end || *end ||
                !value || value>cmeContextRegistryMaxEntries) goto done;
        }
        for (i=0;i<3;i++)
        {
            char *stored=cmeOwnerText(read,15+(int)i,64);
            int bad=!stored || cmeGetProtectDBLookupValue(lookupNames[i],plain[7+i],key,&lookup) ||
                !lookup || strlen(stored)!=64 || strlen(lookup)!=64 || CRYPTO_memcmp(stored,lookup,64);
            free(stored); free(lookup); lookup=NULL;
            if (bad) goto done;
        }
        for (i=0;i<8;i++)
            if (sqlite3_bind_text(insert,(int)i+1,plain[fields[i]],-1,SQLITE_TRANSIENT)!=SQLITE_OK) goto done;
        if (sqlite3_step(insert)!=SQLITE_DONE || sqlite3_reset(insert)!=SQLITE_OK ||
            snprintf(path,sizeof(path),"%s/%s",approval->values[7],plain[5])>=(int)sizeof(path) ||
            cmeOfflineOpenPayload(path,&current) || cmeOwnerRegisteredMAC(&current,plain[3],key,plain[10])) goto done;
        /* Retain bounded metadata, not thousands of open descriptors. The final
           pass rechecks every entry through the held export directory. */
        artifacts[count++]=current; cmeOfflineClose(&current);
        for (i=1;i<15;i++) if (plain[i]) { OPENSSL_cleanse(plain[i],strlen(plain[i])); free(plain[i]); plain[i]=NULL; }
    }
    if (step!=SQLITE_DONE || !rows) goto done;
    sqlite3_finalize(read); read=NULL; sqlite3_finalize(insert); insert=NULL;
    if (sqlite3_prepare_v2(db,"SELECT * FROM storage ORDER BY id",-1,&read,NULL)!=SQLITE_OK ||
        sqlite3_prepare_v2(inventory,"INSERT INTO stores VALUES(?1,?2)",-1,&insert,NULL)!=SQLITE_OK) goto done;
    rows=0;
    while ((step=sqlite3_step(read))==SQLITE_ROW)
    {
        if (++rows>cmeContextRegistryMaxEntries) goto done;
        for (i=6;i<=11;i++) if ((i<=8 || i==11) &&
            cmeOwnerRegisteredValue(read,(int)i,key,approval->values[18],&plain[i])) goto done;
        if (strcmp(plain[6],"local") || strcmp(plain[8],approval->values[21]) ||
            !*plain[7] || strlen(plain[7])>128 || !*plain[11] || strlen(plain[11])>128 ||
            sqlite3_bind_text(insert,1,plain[7],-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
            sqlite3_bind_text(insert,2,plain[11],-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
            sqlite3_step(insert)!=SQLITE_DONE || sqlite3_reset(insert)!=SQLITE_OK) goto done;
        for (i=6;i<=11;i++) if (plain[i]) { OPENSSL_cleanse(plain[i],strlen(plain[i])); free(plain[i]); plain[i]=NULL; }
    }
    if (step!=SQLITE_DONE || sqlite3_prepare_v2(inventory,
        "SELECT 1 FROM parts p WHERE part>total OR NOT EXISTS (SELECT 1 FROM stores s WHERE s.storage=p.storage AND s.org=p.org) "
        "UNION ALL SELECT 1 FROM parts GROUP BY doc,storage,org,type,col "
        "HAVING count(*)!=max(total) OR count(DISTINCT part)!=count(*) OR min(total)!=max(total)",
        -1,&check,NULL)!=SQLITE_OK || sqlite3_step(check)!=SQLITE_DONE) goto done;
    for (i=0;i<2;i++)
    {
        if (snprintf(path,sizeof(path),"%s/%s",approval->values[7],internal[i])>=(int)sizeof(path) ||
            cmeOfflineOpen(path,1,&current)) goto done;
        artifacts[count++]=current; cmeOfflineClose(&current);
    }
    if (cmeCopyOwnerExportNames(inventory,approval->values[7],count+1)) goto done;
    for (i=0;i<count;i++)
    {
        artifacts[i].file=-1; artifacts[i].directory=resources->directory;
        j=cmeOfflineVerify(&artifacts[i]); artifacts[i].directory=-1;
        if (j) goto done;
    }
    if (cmeCopyOwnerExportNames(inventory,approval->values[7],count+1) ||
        fstat(resources->directory,&directory) ||
        directory.st_mtim.tv_sec!=resources->parent.st_mtim.tv_sec || directory.st_mtim.tv_nsec!=resources->parent.st_mtim.tv_nsec ||
        directory.st_ctim.tv_sec!=resources->parent.st_ctim.tv_sec || directory.st_ctim.tv_nsec!=resources->parent.st_ctim.tv_nsec ||
        lstat(approval->values[7],&directory) || directory.st_dev!=resources->parent.st_dev ||
        directory.st_ino!=resources->parent.st_ino || directory.st_uid!=geteuid() || (directory.st_mode&07777)!=0700) goto done;
    result=0;
done:
    for (i=0;i<15;i++) if (plain[i]) { OPENSSL_cleanse(plain[i],strlen(plain[i])); free(plain[i]); }
    free(lookup); free(artifacts); cmeOfflineClose(&current);
    sqlite3_finalize(read); sqlite3_finalize(insert); sqlite3_finalize(check); sqlite3_close(inventory); return(result);
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
        cmeOwnerRegisteredColumn(db[1],key,approval->values[18]) ||
        cmeOwnerRegisteredRow(db[2],approval,&files[0],key,approval->values[7]) ||
        cmeOwnerRegisteredRow(db[3],approval,&files[1],key,approval->values[7]) ||
        cmeOwnerRegisteredMetadata(db[2],db[3],approval,key,approval->values[7])) goto done;
    for (i=0;i<4;i++)
        if (sqlite3_exec(db[i],"COMMIT",NULL,NULL,NULL)!=SQLITE_OK || cmeOfflineVerify(&files[i])) goto done;
    result=0;
done:
    strcpy(cmeDefaultEncAlg,savedProfile);
    for (i=0;i<4;i++) { sqlite3_close(db[i]); cmeOfflineClose(&files[i]); }
    return(result);
}

/* Bind selectors/profile independently of reapproved manager and witness pins.
   Length-prefixed UTF-8 bytes prevent JSON spelling/order and delimiter aliases. */
static int cmeOwnerRegisteredPair(const cmeOwnerApproval *approval, cmeContextShufflePair *pair)
{
    static const unsigned char domain[]="CDSE-REGISTERED-SHUFFLE-v1";
    EVP_MD_CTX *hash=EVP_MD_CTX_new();
    unsigned char bytes[8];
    unsigned int written;
    int i,result=1;
    pair->activePath=approval->values[13]; pair->stagedPath=approval->values[14];
    memcpy(pair->sourceDigest,approval->resourcesSource,32); memcpy(pair->targetDigest,approval->resourcesTarget,32);
    if (!hash || !EVP_DigestInit_ex(hash,EVP_sha256(),NULL) ||
        !EVP_DigestUpdate(hash,domain,sizeof(domain))) goto done;
    for (i=0;i<8;i++) bytes[i]=(unsigned char)((uint64_t)approval->documentRow>>(56-8*i));
    if (!EVP_DigestUpdate(hash,bytes,8)) goto done;
    for (i=0;i<5;i++)
    {
        const char *value=i==4 ? approval->values[18] : approval->registration[i];
        size_t length=strlen(value);
        if (!length || length>65535) goto done;
        bytes[0]=(unsigned char)(length>>8); bytes[1]=(unsigned char)length;
        if (!EVP_DigestUpdate(hash,bytes,2) || !EVP_DigestUpdate(hash,value,length)) goto done;
    }
    if (EVP_DigestFinal_ex(hash,pair->selectionDigest,&written) && written==32) result=0;
done:
    EVP_MD_CTX_free(hash); return(result);
}

static int cmeOwnerRegisteredReceipt(const cmeOwnerApproval *approval, const cmeContextShufflePair *pair,
                                     const cmeContextShuffle *shuffle)
{
    return(!shuffle->pair || cmeOwnerReceipt(approval,shuffle) ||
        strcmp(pair->activePath,shuffle->pair->activePath) || strcmp(pair->stagedPath,shuffle->pair->stagedPath) ||
        CRYPTO_memcmp(pair->sourceDigest,shuffle->pair->sourceDigest,32) ||
        CRYPTO_memcmp(pair->targetDigest,shuffle->pair->targetDigest,32) ||
        CRYPTO_memcmp(pair->selectionDigest,shuffle->pair->selectionDigest,32));
}

static void cmeOwnerRegisteredOutput(FILE *output, const char *action, const cmeContextShuffle *shuffle,
                                     const cmeContextMapAnchor *catalog, const unsigned char job[32])
{
    unsigned char revision[8];
    int i;
    fprintf(output,"state=%s\n",!strcmp(action,"--status") ?
        (shuffle->state==1 ? "prepared" : (shuffle->state==2 ? "completed" : "aborted")) : action+2);
    if (!strcmp(action,"--prepare") || !strcmp(action,"--status"))
    {
        fprintf(output,"job="); cmeOwnerWriteHex(output,job,32); fputc('\n',output);
    }
    for (i=0;i<8;i++) revision[i]=(unsigned char)(catalog->revision>>(56-8*i));
    fprintf(output,"catalog="); cmeOwnerWriteHex(output,revision,8);
    cmeOwnerWriteHex(output,catalog->digest,32); fputc('\n',output);
}

int cmeContextOwnerMain(int argc, char **argv)
{
    if (argc>1 && !strcmp(argv[1],"context-copy-plan")) return(cmeCopyOwnerMain(argc,argv));
    cmeOwnerApproval approval={0};
    cmeContextManager *manager=NULL;
    cmeContextMap *source=NULL;
    cmeContextBinding *binding=NULL;
    cmeContextShuffle *shuffle=NULL;
    cmeContextMapAnchor published={0};
    cmeContextShufflePair pair={0};
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
             "  Registered schema 3: (--check | --init | --prepare | --status | --complete JOB_HEX | --abort JOB_HEX)\n"
             "    --org-key-file FILE --retained-witness-token TOKEN\n"
             "Registered actions are floor-1-only. Init upgrades shuffle catalog v2 to paired v3.\n"
             "Init/prepare verify both artifacts; recovery requires exact authenticated paired receipts.\n"
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
    if ((registeredCommand ? (approval.schema!=3 || !orgFile || !retainedToken ||
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
        if (cmeOwnerRegisteredPair(&approval,&pair)) goto done;
        output=fdopen(dup(STDOUT_FILENO),"w"); diagnostics=fdopen(dup(STDERR_FILENO),"w");
        if (!output || !diagnostics || fflush(NULL) || !freopen("/dev/null","w",stdout) || !freopen("/dev/null","w",stderr)) goto done;
        if (!strcmp(action,"--status") || !strcmp(action,"--complete") || !strcmp(action,"--abort"))
        {
            result=cmeContextManagerShuffleRead(manager,approval.values[4],&approval.registry,&approval.catalog,&shuffle);
            if (result) goto done;
            result=1;
            if (cmeOwnerRegisteredReceipt(&approval,&pair,shuffle)) goto done;
            /* Current guard was checked above; recheck immediately before any install. */
            result=cmeContextManagerCheckAnchors(manager,&approval.registry,&approval.catalog); if (result) goto done;
            result=cmeContextWitnessReconcile(witness,&witnessExpected,&approval.registry,&approval.catalog,&recovery,&witnessPublished);
            if (result) goto done;
            if (recovery!=cmeWitnessRecoveryCurrent) { result=2; goto done; }
            if (!strcmp(action,"--status"))
            { published=approval.catalog; memcpy(job,shuffle->job,32); result=0; }
            else result=cmeContextManagerShufflePairRecover(manager,approval.values[4],job,!strcmp(action,"--complete"),
                &approval.registry,&approval.catalog,&published);
            if (!result) cmeOwnerRegisteredOutput(output,action,shuffle,&published,job);
            goto done;
        }
        result=cmeContextManagerMapRead(manager,approval.values[4],&approval.registry,&approval.catalog,&source);
        if (result) goto done;
        result=1;
        if (!source->active || source->blocked || source->role!=4 || cmeOwnerPermutation(&approval,source)) goto done;
        result=cmeContextManagerMapBind(manager,approval.values[4],&approval.registry,&approval.catalog,&binding);
        if (result) goto done;
        result=1;
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
        if (!strcmp(action,"--check")) fprintf(output,"state=verified-pair\npublication=disabled\n");
        else
        {
            if (!strcmp(action,"--init"))
                result=cmeContextManagerShufflePairInit(manager,&approval.registry,&approval.catalog,&published);
            else result=cmeContextManagerShufflePairPrepare(manager,approval.values[4],approval.values[7],approval.values[8],
                approval.source,approval.target,approval.slots,approval.count,&pair,&approval.registry,&approval.catalog,job,&published);
            if (!result) cmeOwnerRegisteredOutput(output,action,NULL,&published,job);
        }
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
        result=1; if (shuffle->pair || cmeOwnerReceipt(&approval,shuffle)) goto done;
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
