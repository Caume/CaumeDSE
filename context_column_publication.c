/* Durable whole-export directory promotion; map publication remains separate. */
#include "common.h"
#include "context_column.h"
#include "context_column_internal.h"
#include <sys/file.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

typedef struct
{
    int directory,parent;
    struct stat control,destination;
    char name[129],temporary[134],done[134],doneTemporary[139],destinationName[NAME_MAX+1];
} cmePublicationSession;

static void cmePublicationCheckpoint(const char *stage)
{
#ifdef CDSE_CONTEXT_COLUMN_TESTING
    const char *crash=getenv("CDSE_CONTEXT_PUBLICATION_CRASH"),*pause=getenv("CDSE_CONTEXT_PUBLICATION_PAUSE");
    if (crash && !strcmp(crash,stage)) _exit(86);
    if (pause && !strcmp(pause,stage))
    {
        const char *ready=getenv("CDSE_CONTEXT_PUBLICATION_READY_FD"),*resume=getenv("CDSE_CONTEXT_PUBLICATION_RESUME_FD");
        char byte;
        if (!ready || !resume || atoi(ready)<3 || atoi(resume)<3 ||
            write(atoi(ready),"1",1)!=1 || read(atoi(resume),&byte,1)!=1) _exit(87);
    }
#else
    (void)stage;
#endif
}

static int cmePublicationRename(int source, const char *old, int destination, const char *next)
{
#if defined(__linux__) && defined(SYS_renameat2)
    if (!syscall(SYS_renameat2,source,old,destination,next,1U)) return(0);
    return(errno==ENOSYS ? 3 : 1);
#else
    (void)source; (void)old; (void)destination; (void)next; return(3);
#endif
}

static int cmePublicationPresent(int directory, const char *name)
{
    struct stat status;
    if (!fstatat(directory,name,&status,AT_SYMLINK_NOFOLLOW)) return(1);
    return(errno==ENOENT ? 0 : -1);
}

static int cmePublicationSessionCheck(const cmePublicationSession *session)
{
    struct stat control,parent;
    return(fstat(session->directory,&control) || cmeCustodyPrivate(&control) ||
        !cmeCustodyIdentity(&control,&session->control) || control.st_gid!=session->control.st_gid ||
        fstat(session->parent,&parent) || cmeCustodyPrivate(&parent) ||
        !cmeCustodyIdentity(&parent,&session->destination) || parent.st_gid!=session->destination.st_gid);
}

static int cmePublicationSessionOpen(const cmeContextColumnPublication *input, cmePublicationSession *session)
{
    if (!input || input->directory<0 || input->destination.parent<0 || cmeCustodyLeaf(input->name) ||
        strlen(input->name)>128 || cmeCustodyLeaf(input->destination.name)) return(1);
    strcpy(session->name,input->name); strcpy(session->destinationName,input->destination.name);
    snprintf(session->temporary,sizeof(session->temporary),"%s.tmp",input->name);
    snprintf(session->done,sizeof(session->done),"%s.done",input->name);
    snprintf(session->doneTemporary,sizeof(session->doneTemporary),"%s.done.tmp",input->name);
    /* Independent open description: dup would share flock ownership. */
    session->directory=openat(input->directory,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    session->parent=fcntl(input->destination.parent,F_DUPFD_CLOEXEC,3);
    if (session->directory<0 || session->parent<0 || fstat(session->directory,&session->control) ||
        fstat(session->parent,&session->destination) || cmeCustodyPrivate(&session->control) ||
        cmeCustodyPrivate(&session->destination) || flock(session->directory,LOCK_EX|LOCK_NB)) return(1);
    if (cmeCustodyIdentity(&session->control,&session->destination) &&
        (!strcmp(session->name,session->destinationName) || !strcmp(session->temporary,session->destinationName) ||
         !strcmp(session->done,session->destinationName) || !strcmp(session->doneTemporary,session->destinationName))) return(1);
    return(0);
}

static void cmePublicationSessionClose(cmePublicationSession *session)
{
    if (session->directory>=0) close(session->directory);
    if (session->parent>=0) close(session->parent);
}

static int cmePublicationNumber(EVP_MD_CTX *hash, uint64_t value)
{
    unsigned char bytes[8]; size_t i;
    for (i=0;i<8;i++) bytes[i]=(unsigned char)(value>>(8*(7-i)));
    return(!EVP_DigestUpdate(hash,bytes,8));
}

static int cmePublicationText(EVP_MD_CTX *hash, const char *text)
{
    unsigned char length[2]; size_t n=strlen(text);
    if (n>NAME_MAX) return(1);
    length[0]=(unsigned char)(n>>8); length[1]=(unsigned char)n;
    return(!EVP_DigestUpdate(hash,length,2) || !EVP_DigestUpdate(hash,text,n));
}

static int cmePublicationStat(EVP_MD_CTX *hash, const struct stat *status, int level)
{
    uint64_t values[]={status->st_dev,status->st_ino,status->st_mode,status->st_uid,status->st_gid,
        status->st_nlink,status->st_size,status->st_mtim.tv_sec,status->st_mtim.tv_nsec,
        status->st_ctim.tv_sec,status->st_ctim.tv_nsec};
    size_t i,count=level==0 ? 5 : (level==1 ? 9 : 11);
    if (level && (status->st_size<0 || status->st_mtim.tv_sec<0 || status->st_mtim.tv_nsec<0 ||
        status->st_mtim.tv_nsec>=1000000000L || (level==2 && (status->st_ctim.tv_sec<0 ||
        status->st_ctim.tv_nsec<0 || status->st_ctim.tv_nsec>=1000000000L)))) return(1);
    for (i=0;i<count;i++) if (cmePublicationNumber(hash,values[i])) return(1);
    return(0);
}

static int cmePublicationIntent(cmeContextColumnCustody *custody, const char *staging,
    const cmePublicationSession *session, unsigned char body[cmeContextColumnPublicationMaxBytes], size_t *length,
    unsigned char digest[32])
{
    static const unsigned char domain[]="CDSE-HKX-COLUMN-PUBLICATION-v1";
    static const unsigned char manifestDomain[]="CDSE-HKX-COLUMN-PUBLICATION-MANIFEST-v1";
    EVP_MD_CTX *hash=NULL;
    cmeContextCopyEvidence evidence={0};
    unsigned char manifest[32],request[32],signature[32];
    unsigned int written=0;
    size_t root,i;
    int result=1;
    *length=0;
    if (!custody || cmeCustodyLeaf(staging) || cmePublicationSessionCheck(session) ||
        !cmeCustodyIdentity(&custody->roots[1].anchor,&session->destination) ||
        !strcmp(staging,session->destinationName) ||
        (cmeCustodyIdentity(&custody->roots[0].anchor,&session->destination) &&
         !strcmp(custody->roots[0].name,session->destinationName)) ||
        cmeCustodyNested(session->directory,&custody->roots[0].status) ||
        cmeCustodyNested(session->directory,&custody->roots[1].status)) goto done;
    result=cmeContextCopyTargetEvidence(custody->manager,custody->target,&evidence); if (result) goto done;
    result=1; hash=EVP_MD_CTX_new();
    if (!hash || !EVP_DigestInit_ex(hash,EVP_sha256(),NULL) ||
        !EVP_DigestUpdate(hash,manifestDomain,sizeof(manifestDomain)) ||
        !EVP_DigestUpdate(hash,custody->acceptanceDigest,32) ||
        !EVP_DigestUpdate(hash,evidence.allocationDigest,32) ||
        !EVP_DigestUpdate(hash,evidence.registry.deployment,16) || !EVP_DigestUpdate(hash,evidence.registry.organization,16) ||
        cmePublicationNumber(hash,evidence.registry.generation) || cmePublicationNumber(hash,evidence.registry.minimumFormat) ||
        !EVP_DigestUpdate(hash,evidence.registry.digest,32) || cmePublicationNumber(hash,evidence.catalog.revision) ||
        !EVP_DigestUpdate(hash,evidence.catalog.digest,32) || cmePublicationNumber(hash,evidence.witness.revision) ||
        !EVP_DigestUpdate(hash,evidence.witness.digest,32) || cmePublicationText(hash,custody->destinationMap) ||
        cmePublicationStat(hash,&session->control,0) || cmePublicationText(hash,session->name) ||
        cmePublicationStat(hash,&session->destination,0) || cmePublicationText(hash,session->destinationName)) goto done;
    for (root=0;root<2;root++)
    {
        if (cmePublicationStat(hash,&custody->roots[root].anchor,0) ||
            cmePublicationText(hash,root ? staging : custody->roots[root].name) ||
            cmePublicationStat(hash,&custody->roots[root].status,1) || cmePublicationNumber(hash,custody->count[root])) goto done;
        for (i=0;i<custody->count[root];i++)
        {
            const cmeCustodyFile *file=&custody->files[root][i];
            if (cmePublicationText(hash,file->name) || cmePublicationStat(hash,&file->status,2) ||
                !EVP_DigestUpdate(hash,file->digest,32)) goto done;
        }
    }
    if (!EVP_DigestFinal_ex(hash,manifest,&written) || written!=32) goto done;
    _Static_assert(sizeof(domain)+96<=cmeContextColumnPublicationMaxBytes,"publication intent bound");
    memcpy(body,domain,sizeof(domain)); memcpy(body+sizeof(domain),manifest,32);
    memcpy(body+sizeof(domain)+32,custody->acceptanceDigest,32); *length=sizeof(domain)+64;
    if (!EVP_Digest(body,*length,request,&written,EVP_sha256(),NULL) || written!=32) goto done;
    result=cmeContextManagerColumnPublicationSign(custody->manager,&evidence.registry,&evidence.catalog,
        custody->destinationMap,request,signature); if (result) goto done;
    result=1; memcpy(body+*length,signature,32); *length+=32;
    if (!EVP_Digest(body,*length,digest,&written,EVP_sha256(),NULL) || written!=32) goto done;
    result=cmeContextCopyTargetCheck(custody->manager,custody->target);
done:
    EVP_MD_CTX_free(hash); OPENSSL_cleanse(manifest,sizeof(manifest)); OPENSSL_cleanse(request,sizeof(request));
    OPENSSL_cleanse(signature,sizeof(signature)); return(result);
}

/* Exact canonical bytes, with a matching prefix allowed only for reserved temps. */
static int cmePublicationRead(int directory, const char *name, const unsigned char *expected, size_t length, int prefix)
{
    unsigned char bytes[cmeContextColumnPublicationMaxBytes];
    struct stat before,after,named;
    int fd=-1,result=1; size_t offset=0;
    fd=openat(directory,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if (fd<0 || fstat(fd,&before) || !S_ISREG(before.st_mode) || before.st_uid!=geteuid() ||
        (before.st_mode&07777)!=0600 || before.st_nlink!=1 || before.st_size<0 || (uint64_t)before.st_size>length ||
        (!prefix && (uint64_t)before.st_size!=length)) goto done;
    while (offset<(size_t)before.st_size)
    {
        ssize_t got=pread(fd,bytes+offset,(size_t)before.st_size-offset,(off_t)offset);
        if (got<0 && errno==EINTR) continue;
        if (got<=0) goto done;
        offset+=(size_t)got;
    }
    if ((offset && CRYPTO_memcmp(bytes,expected,offset)) || fstat(fd,&after) || !cmeCustodySame(&before,&after) ||
        fstatat(directory,name,&named,AT_SYMLINK_NOFOLLOW) || !cmeCustodySame(&before,&named)) goto done;
    result=0;
done:
    if (fd>=0) close(fd);
    OPENSSL_cleanse(bytes,sizeof(bytes)); return(result);
}

static int cmePublicationWrite(const cmePublicationSession *session, const char *name, const char *temporary,
    const unsigned char *bytes, size_t length, const char *checkpoint)
{
    int fd=-1,result=1,present=cmePublicationPresent(session->directory,name);
    size_t offset=0;
    struct stat status,after,named;
    int pending=cmePublicationPresent(session->directory,temporary);
    if (present<0 || pending<0 || cmePublicationSessionCheck(session) ||
        (pending && cmePublicationRead(session->directory,temporary,bytes,length,1))) return(1);
    if (present) return(cmePublicationRead(session->directory,name,bytes,length,0) || fsync(session->directory));
    if (pending && unlinkat(session->directory,temporary,0)) return(1);
    fd=openat(session->directory,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
    if (fd<0 || fstat(fd,&status) || !S_ISREG(status.st_mode) || status.st_uid!=geteuid() ||
        (status.st_mode&07777)!=0600 || status.st_nlink!=1) goto done;
    cmePublicationCheckpoint(checkpoint);
    while (offset<length)
    {
        ssize_t count=write(fd,bytes+offset,length-offset);
        if (count<0 && errno==EINTR) continue;
        if (count<=0) goto done;
        offset+=(size_t)count;
    }
    if (fsync(fd) || fstat(fd,&after) || !cmeCustodyIdentity(&status,&after) ||
        after.st_uid!=status.st_uid || after.st_gid!=status.st_gid || after.st_mode!=status.st_mode || after.st_nlink!=1 ||
        (uint64_t)after.st_size!=length || fstatat(session->directory,temporary,&named,AT_SYMLINK_NOFOLLOW) ||
        !cmeCustodySame(&after,&named) || cmePublicationSessionCheck(session) ||
        cmePublicationRead(session->directory,temporary,bytes,length,0)) goto done;
    close(fd); fd=-1;
    result=cmePublicationRename(session->directory,temporary,session->directory,name); if (result) goto done;
    result=fsync(session->directory) ? 1 : 0;
done:
    if (fd>=0) close(fd);
    return(result);
}

static int cmePublicationSync(cmeContextColumnCustody *custody)
{
    size_t i;
    int fd=-1,result=1;
    struct stat status;
    for (i=0;i<custody->count[1];i++)
    {
        cmeCustodyFile *entry=&custody->files[1][i];
        fd=openat(custody->roots[1].directory,entry->name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        if (fd<0 || fstat(fd,&status) || !cmeCustodySame(&status,&entry->status) || fsync(fd)) goto done;
        close(fd); fd=-1;
    }
    result=(fsync(custody->roots[1].directory) || fsync(custody->roots[1].parent)) ? 1 : 0;
done:
    if (fd>=0) close(fd);
    return(result);
}

static int cmePublicationPromoted(cmeContextColumnCustody *custody, const cmePublicationSession *session)
{
    cmeContextColumnCustody view=*custody;
    struct stat status,comparison;
    if (fstat(view.roots[1].directory,&status)) return(1);
    comparison=status; comparison.st_ctim=view.roots[1].status.st_ctim;
    if (!cmeCustodySame(&comparison,&view.roots[1].status)) return(1);
    view.roots[1].status=status; strcpy(view.roots[1].name,session->destinationName); view.failed=0;
    return(cmeContextColumnCustodyCheck(&view));
}

static int cmePublicationFinish(cmeContextColumnCustody *custody, cmePublicationSession *session,
    const unsigned char *body, size_t length, int *state)
{
    int result=cmePublicationPromoted(custody,session); if (result) return(result);
    if (cmePublicationSync(custody) || fsync(session->parent) || cmePublicationSessionCheck(session)) return(1);
    cmePublicationCheckpoint("after-parent-sync");
    result=cmePublicationPromoted(custody,session); if (result) return(result);
    result=cmePublicationWrite(session,session->done,session->doneTemporary,body,length,"marker-temp"); if (result) return(result);
    cmePublicationCheckpoint("after-marker");
    result=cmePublicationPromoted(custody,session); if (result) return(result);
    if (cmePublicationSessionCheck(session) || cmePublicationRead(session->directory,session->name,body,length,0) ||
        cmePublicationRead(session->directory,session->done,body,length,0)) return(1);
    *state=2; return(0);
}

int cmeContextColumnPublicationPrepare(cmeContextColumnCustody *custody,
    const cmeContextColumnPublication *publication, unsigned char intentDigest[32])
{
    cmePublicationSession session={.directory=-1,.parent=-1};
    unsigned char body[cmeContextColumnPublicationMaxBytes],digest[32];
    size_t length=0;
    int result=1;
    if (intentDigest) memset(intentDigest,0,32);
    if (!custody || !intentDigest || cmePublicationSessionOpen(publication,&session)) goto done;
    result=cmeContextColumnCustodyCheck(custody); if (result) goto done;
    result=1;
    if (cmePublicationPresent(session.parent,session.destinationName)!=0 ||
        cmePublicationPresent(session.directory,session.done)!=0 || cmePublicationSync(custody)) goto done;
    result=cmePublicationIntent(custody,custody->roots[1].name,&session,body,&length,digest); if (result) goto done;
    result=cmeContextColumnCustodyCheck(custody); if (result) goto done;
    result=cmePublicationWrite(&session,session.name,session.temporary,body,length,"intent-temp"); if (result) goto done;
    cmePublicationCheckpoint("after-intent");
    result=cmeContextColumnCustodyCheck(custody); if (result) goto done;
    result=1;
    if (cmePublicationSessionCheck(&session) || cmePublicationRead(session.directory,session.name,body,length,0) ||
        cmePublicationPresent(session.parent,session.destinationName)!=0 || cmePublicationPresent(session.directory,session.done)!=0) goto done;
    memcpy(intentDigest,digest,32); result=0;
done:
    cmePublicationSessionClose(&session); OPENSSL_cleanse(body,sizeof(body)); OPENSSL_cleanse(digest,sizeof(digest)); return(result);
}

static int cmePublicationPublish(cmeContextColumnCustody *custody, cmePublicationSession *session,
    const unsigned char intentDigest[32], int *state)
{
    unsigned char body[cmeContextColumnPublicationMaxBytes],digest[32];
    size_t length=0;
    int result=cmeContextColumnCustodyCheck(custody); if (result) goto done;
    result=cmePublicationIntent(custody,custody->roots[1].name,session,body,&length,digest); if (result) goto done;
    result=1;
    if (CRYPTO_memcmp(digest,intentDigest,32) || cmePublicationRead(session->directory,session->name,body,length,0) ||
        cmePublicationPresent(session->directory,session->done)!=0 ||
        cmePublicationPresent(session->parent,session->destinationName)!=0 || cmePublicationSync(custody)) goto done;
    cmePublicationCheckpoint("before-rename");
    result=cmeContextColumnCustodyCheck(custody); if (result) goto done;
    result=1;
    if (cmePublicationSessionCheck(session) || cmePublicationRead(session->directory,session->name,body,length,0)) goto done;
    result=cmePublicationRename(custody->roots[1].parent,custody->roots[1].name,session->parent,session->destinationName);
    if (result) goto done;
    custody->failed=1;
    cmePublicationCheckpoint("after-rename");
    result=cmePublicationFinish(custody,session,body,length,state);
done:
    OPENSSL_cleanse(body,sizeof(body)); OPENSSL_cleanse(digest,sizeof(digest)); return(result);
}

int cmeContextColumnPublicationPublish(cmeContextColumnCustody *custody,
    const cmeContextColumnPublication *publication, const unsigned char intentDigest[32], int *state)
{
    cmePublicationSession session={.directory=-1,.parent=-1};
    int result=1;
    if (state) *state=0;
    if (!custody || !state || !intentDigest || cmePublicationSessionOpen(publication,&session)) goto done;
    result=cmePublicationPublish(custody,&session,intentDigest,state);
done:
    cmePublicationSessionClose(&session); return(result);
}

int cmeContextColumnPublicationRecover(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnRegistrationInputs *credentials, const cmeContextColumnExportInputs *export,
    const cmeContextColumnCustodyRoot *source, const cmeContextColumnCustodyRoot *staging,
    const unsigned char *acceptance, size_t acceptanceLength, const unsigned char acceptanceDigest[32],
    const cmeContextColumnPublication *publication, const unsigned char intentDigest[32], int *state)
{
    cmePublicationSession session={.directory=-1,.parent=-1};
    cmeContextColumnCustodyRoot actual;
    cmeContextColumnCustody *custody=NULL;
    struct stat parent;
    unsigned char body[cmeContextColumnPublicationMaxBytes],digest[32];
    size_t length=0;
    int staged,published,result=1;
    if (state) *state=0;
    if (!state || !staging || staging->parent<0 || cmeCustodyLeaf(staging->name) || !intentDigest ||
        cmePublicationSessionOpen(publication,&session) || fstat(staging->parent,&parent) ||
        !cmeCustodyIdentity(&parent,&session.destination) || !strcmp(staging->name,session.destinationName)) goto done;
    staged=cmePublicationPresent(staging->parent,staging->name);
    published=cmePublicationPresent(session.parent,session.destinationName);
    if (staged<0 || published<0 || staged+published!=1 ||
        (staged && cmePublicationPresent(session.directory,session.done)!=0)) goto done;
    actual=*staging;
    if (published) { actual.parent=session.parent; actual.name=session.destinationName; }
    result=cmeContextColumnCustodyOpen(manager,target,transform,registration,credentials,export,source,&actual,
        acceptance,acceptanceLength,acceptanceDigest,&custody); if (result) goto done;
    result=cmePublicationIntent(custody,staging->name,&session,body,&length,digest); if (result) goto done;
    result=1;
    if (CRYPTO_memcmp(digest,intentDigest,32) || cmePublicationRead(session.directory,session.name,body,length,0)) goto done;
    if (staged) result=cmePublicationPublish(custody,&session,intentDigest,state);
    else result=cmePublicationFinish(custody,&session,body,length,state);
done:
    cmeContextColumnCustodyFree(&custody); cmePublicationSessionClose(&session);
    OPENSSL_cleanse(body,sizeof(body)); OPENSSL_cleanse(digest,sizeof(digest)); return(result);
}

/* Read-only admission handoff over a freshly verified PUBLISHED custody root. */
int cmeColumnPublicationCompleted(cmeContextColumnCustody *custody,
    const cmeContextColumnPublication *publication, const char *staging, const unsigned char pin[32])
{
    cmePublicationSession session={.directory=-1,.parent=-1};
    unsigned char body[cmeContextColumnPublicationMaxBytes],digest[32];
    size_t length=0;
    int result=1;
    if (!custody || !pin || cmeCustodyLeaf(staging) || cmePublicationSessionOpen(publication,&session)) goto done;
    result=cmeContextColumnCustodyCheck(custody); if (result) goto done;
    result=1;
    if (strcmp(custody->roots[1].name,session.destinationName) ||
        cmePublicationPresent(session.parent,staging)!=0 ||
        cmePublicationPresent(session.directory,session.temporary)!=0 ||
        cmePublicationPresent(session.directory,session.doneTemporary)!=0) goto done;
    result=cmePublicationIntent(custody,staging,&session,body,&length,digest); if (result) goto done;
    result=1;
    if (CRYPTO_memcmp(digest,pin,32) || cmePublicationRead(session.directory,session.name,body,length,0) ||
        cmePublicationRead(session.directory,session.done,body,length,0) || cmePublicationSessionCheck(&session)) goto done;
    result=cmeContextColumnCustodyCheck(custody);
done:
    cmePublicationSessionClose(&session); return(result);
}
