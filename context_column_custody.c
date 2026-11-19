/* Descriptor-anchored export custody. No artifact or authority publication. */
#include "common.h"
#include "context_column.h"
#include <dirent.h>

typedef struct
{
    int parent,directory;
    char name[NAME_MAX+1];
    struct stat anchor,status;
} cmeCustodyDirectory;
typedef struct
{
    char name[NAME_MAX+1];
    size_t length,maximum;
    unsigned char digest[32];
    struct stat status;
} cmeCustodyFile;
struct cmeContextColumnCustody
{
    cmeContextManager *manager;
    const cmeContextCopyTarget *target;
    cmeCustodyDirectory roots[2];
    cmeCustodyFile *files[2];
    size_t count[2];
    int failed;
};

static void cmeCustodyCheckpoint(const char *stage)
{
#ifdef CDSE_CONTEXT_COLUMN_TESTING
    static int used=0;
    const char *pause=getenv("CDSE_CONTEXT_CUSTODY_PAUSE");
    if (!used && pause && !strcmp(pause,stage))
    {
        used=1;
        const char *ready=getenv("CDSE_CONTEXT_CUSTODY_READY_FD"),*resume=getenv("CDSE_CONTEXT_CUSTODY_RESUME_FD");
        char byte;
        if (!ready || !resume || atoi(ready)<3 || atoi(resume)<3 ||
            write(atoi(ready),"1",1)!=1 || read(atoi(resume),&byte,1)!=1) _exit(87);
    }
#else
    (void)stage;
#endif
}

static int cmeCustodyLeaf(const char *name)
{
    static const char *suffix[]={"-wal","-shm","-journal"};
    size_t i,n;
    if (!name || !(n=strnlen(name,NAME_MAX+1)) || n>NAME_MAX || name[0]=='.') return(1);
    for (i=0;i<n;i++)
        if (!((name[i]>='a' && name[i]<='z') || (name[i]>='A' && name[i]<='Z') ||
            (name[i]>='0' && name[i]<='9') || name[i]=='_' || name[i]=='-' || name[i]=='.')) return(1);
    for (i=0;i<3;i++) if (n>=strlen(suffix[i]) && !strcmp(name+n-strlen(suffix[i]),suffix[i])) return(1);
    return(0);
}

static int cmeCustodyIdentity(const struct stat *a, const struct stat *b)
{
    return(a->st_dev==b->st_dev && a->st_ino==b->st_ino);
}

static int cmeCustodySame(const struct stat *a, const struct stat *b)
{
    return(cmeCustodyIdentity(a,b) && a->st_mode==b->st_mode && a->st_uid==b->st_uid && a->st_gid==b->st_gid &&
        a->st_nlink==b->st_nlink && a->st_size==b->st_size &&
        a->st_mtim.tv_sec==b->st_mtim.tv_sec && a->st_mtim.tv_nsec==b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec && a->st_ctim.tv_nsec==b->st_ctim.tv_nsec);
}

static int cmeCustodyPrivate(const struct stat *status)
{
    return(!S_ISDIR(status->st_mode) || status->st_uid!=geteuid() || (status->st_mode&07777)!=0700 || !status->st_nlink);
}

static int cmeCustodyRootOpen(const cmeContextColumnCustodyRoot *input, cmeCustodyDirectory *root)
{
    struct stat named;
    if (!input || input->parent<0 || cmeCustodyLeaf(input->name)) return(1);
    strcpy(root->name,input->name);
    root->parent=fcntl(input->parent,F_DUPFD_CLOEXEC,3);
    if (root->parent<0 || fstat(root->parent,&root->anchor) || cmeCustodyPrivate(&root->anchor)) return(1);
    root->directory=openat(root->parent,root->name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    return(root->directory<0 || fstat(root->directory,&root->status) || cmeCustodyPrivate(&root->status) ||
        fstatat(root->parent,root->name,&named,AT_SYMLINK_NOFOLLOW) || !cmeCustodySame(&root->status,&named));
}

static int cmeCustodyRootCheck(const cmeCustodyDirectory *root)
{
    struct stat parent,status,named;
    return(fstat(root->parent,&parent) || cmeCustodyPrivate(&parent) || !cmeCustodyIdentity(&parent,&root->anchor) ||
        parent.st_gid!=root->anchor.st_gid || fstat(root->directory,&status) || !cmeCustodySame(&status,&root->status) ||
        fstatat(root->parent,root->name,&named,AT_SYMLINK_NOFOLLOW) || !cmeCustodySame(&named,&root->status));
}

/* Fail closed on inaccessible or excessively deep ancestry. Namespace anchor
   pathnames remain the caller's responsibility; only object ancestry is tested. */
static int cmeCustodyNested(int directory, const struct stat *other)
{
    int current=fcntl(directory,F_DUPFD_CLOEXEC,3),parent=-1,result=1;
    struct stat here,above;
    size_t depth;
    if (current<0) return(1);
    for (depth=0;depth<256;depth++)
    {
        if (fstat(current,&here) || cmeCustodyIdentity(&here,other)) goto done;
        parent=openat(current,"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (parent<0 || fstat(parent,&above)) goto done;
        if (cmeCustodyIdentity(&here,&above)) { result=0; goto done; }
        close(current); current=parent; parent=-1;
    }
done:
    if (parent>=0) close(parent);
    close(current); return(result);
}

static int cmeCustodyOrder(const void *a, const void *b)
{
    return(strcmp(((const cmeCustodyFile *)a)->name,((const cmeCustodyFile *)b)->name));
}

static cmeCustodyFile *cmeCustodyFind(cmeCustodyFile *files, size_t count, const char *name)
{
    size_t left=0,right=count;
    while (left<right)
    {
        size_t middle=left+(right-left)/2;
        int order=strcmp(files[middle].name,name);
        if (!order) return(&files[middle]);
        if (order<0) left=middle+1; else right=middle;
    }
    return(NULL);
}

static int cmeCustodyEnumerate(const cmeCustodyDirectory *root, cmeCustodyFile *files, size_t count)
{
    int fd=openat(root->directory,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),result=1;
    DIR *directory=NULL;
    struct dirent *entry;
    size_t seen=0;
    if (fd<0 || !(directory=fdopendir(fd))) { if (fd>=0) close(fd); return(1); }
    for (;;)
    {
        errno=0; entry=readdir(directory);
        if (!entry) { if (errno) goto done; break; }
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if (++seen>count || !cmeCustodyFind(files,count,entry->d_name)) goto done;
    }
    if (seen==count) result=0;
done:
    closedir(directory); return(result);
}

static int cmeCustodyRead(const cmeCustodyDirectory *root, cmeCustodyFile *entry, unsigned char **output, int initial)
{
    unsigned char buffer[16384],digest[32],*copy=NULL;
    EVP_MD_CTX *hash=NULL;
    struct stat before,after,named;
    size_t offset=0;
    unsigned int written=0;
    int file=-1,result=1;
    if (output) *output=NULL;
    file=openat(root->directory,entry->name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if (file<0 || fstat(file,&before) || !S_ISREG(before.st_mode) || before.st_uid!=geteuid() ||
        (before.st_mode&07777)!=0600 || before.st_nlink!=1 || before.st_size<100 ||
        (uint64_t)before.st_size>entry->maximum || (entry->length && (uint64_t)before.st_size!=entry->length) ||
        (!initial && !cmeCustodySame(&before,&entry->status))) goto done;
    if (output && !(copy=malloc((size_t)before.st_size))) goto done;
    hash=EVP_MD_CTX_new();
    if (!hash || !EVP_DigestInit_ex(hash,EVP_sha256(),NULL)) goto done;
    while (offset<(size_t)before.st_size)
    {
        size_t wanted=(size_t)before.st_size-offset;
        ssize_t got;
        if (wanted>sizeof(buffer)) wanted=sizeof(buffer);
        got=pread(file,buffer,wanted,(off_t)offset);
        if (got<0 && errno==EINTR) continue;
        if (got<=0 || (!offset && (got<20 || memcmp(buffer,"SQLite format 3",16) || buffer[18]!=1 || buffer[19]!=1)) ||
            !EVP_DigestUpdate(hash,buffer,(size_t)got)) goto done;
        if (copy) memcpy(copy+offset,buffer,(size_t)got);
        offset+=(size_t)got;
    }
    if (!EVP_DigestFinal_ex(hash,digest,&written) || written!=32 || CRYPTO_memcmp(digest,entry->digest,32) ||
        fstat(file,&after) || !cmeCustodySame(&before,&after) ||
        fstatat(root->directory,entry->name,&named,AT_SYMLINK_NOFOLLOW) || !cmeCustodySame(&before,&named)) goto done;
    if (initial) { entry->status=before; entry->length=(size_t)before.st_size; }
    if (output) { *output=copy; copy=NULL; }
    result=0;
done:
    if (copy) { OPENSSL_cleanse(copy,(size_t)before.st_size); free(copy); }
    OPENSSL_cleanse(buffer,sizeof(buffer)); OPENSSL_cleanse(digest,sizeof(digest)); EVP_MD_CTX_free(hash);
    if (file>=0) close(file);
    return(result);
}

void cmeContextColumnCustodyFree(cmeContextColumnCustody **custody)
{
    size_t root;
    if (!custody || !*custody) return;
    for (root=0;root<2;root++)
    {
        if ((*custody)->roots[root].parent>=0) close((*custody)->roots[root].parent);
        if ((*custody)->roots[root].directory>=0) close((*custody)->roots[root].directory);
        free((*custody)->files[root]);
    }
    OPENSSL_cleanse(*custody,sizeof(**custody)); free(*custody); *custody=NULL;
}

int cmeContextColumnCustodyCheck(cmeContextColumnCustody *custody)
{
    size_t root,i;
    struct stat status;
    int result=1;
    if (!custody) return(1);
    if (custody->failed) return(custody->failed);
    result=cmeContextCopyTargetCheck(custody->manager,custody->target); if (result) goto done;
    result=1;
    for (root=0;root<2;root++)
    {
        if (cmeCustodyRootCheck(&custody->roots[root]) ||
            cmeCustodyEnumerate(&custody->roots[root],custody->files[root],custody->count[root])) goto done;
        for (i=0;i<custody->count[root];i++)
            if (cmeCustodyRead(&custody->roots[root],&custody->files[root][i],NULL,0)) goto done;
    }
    cmeCustodyCheckpoint("after-files");
    for (root=0;root<2;root++)
    {
        for (i=0;i<custody->count[root];i++)
            if (fstatat(custody->roots[root].directory,custody->files[root][i].name,&status,AT_SYMLINK_NOFOLLOW) ||
                !cmeCustodySame(&status,&custody->files[root][i].status)) goto done;
        if (cmeCustodyEnumerate(&custody->roots[root],custody->files[root],custody->count[root]) ||
            cmeCustodyRootCheck(&custody->roots[root])) goto done;
    }
    result=cmeContextCopyTargetCheck(custody->manager,custody->target);
done:
    if (result) custody->failed=result;
    return(result);
}

int cmeContextColumnCustodyOpen(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnRegistrationInputs *credentials, const cmeContextColumnExportInputs *export,
    const cmeContextColumnCustodyRoot *source, const cmeContextColumnCustodyRoot *candidate,
    const unsigned char *acceptance, size_t acceptanceLength, const unsigned char acceptanceDigest[32],
    cmeContextColumnCustody **custody)
{
    cmeContextColumnCustody *next=NULL;
    cmeContextColumnRegistrationInputs inputs={0};
    cmeContextColumnExportInputs actual={0};
    cmeContextColumnExportArtifact *companions=NULL;
    unsigned char **bytes[2]={NULL,NULL},pin[32];
    size_t root,i;
    int result=1;
    if (custody) *custody=NULL;
    if (!custody || !manager || !target || !credentials || !export || !acceptance ||
        acceptanceLength<32 || acceptanceLength>cmeContextColumnAcceptanceMaxBytes || !acceptanceDigest ||
        cmeContextColumnExportDigest(transform,registration,export->companions,export->count,pin) ||
        CRYPTO_memcmp(pin,export->approvalDigest,32)) goto done;
    next=calloc(1,sizeof(*next)); if (!next) goto done;
    next->roots[0].parent=next->roots[0].directory=next->roots[1].parent=next->roots[1].directory=-1;
    next->manager=manager; next->target=target;
    companions=calloc(export->count,sizeof(*companions)); if (!companions) goto done;
    memcpy(companions,export->companions,export->count*sizeof(*companions));
    /* Replace caller buffers before use; the manifest supplies only approved pins. */
    for (i=0;i<export->count;i++) companions[i].source=companions[i].candidate=NULL;
    if (cmeCustodyRootOpen(source,&next->roots[0]) || cmeCustodyRootOpen(candidate,&next->roots[1]) ||
        cmeCustodyNested(next->roots[0].directory,&next->roots[1].status) ||
        cmeCustodyNested(next->roots[1].directory,&next->roots[0].status)) goto done;
    for (root=0;root<2;root++)
    {
        next->count[root]=export->count+1+root;
        next->files[root]=calloc(next->count[root],sizeof(*next->files[root]));
        bytes[root]=calloc(next->count[root],sizeof(*bytes[root]));
        if (!next->files[root] || !bytes[root]) goto done;
        for (i=0;i<next->count[root];i++)
        {
            cmeCustodyFile *entry=&next->files[root][i];
            const char *name=i<export->count ? companions[i].name : (i==export->count ? "ResourcesDB" : registration->destinationFile);
            if (cmeCustodyLeaf(name)) goto done;
            strcpy(entry->name,name);
            entry->maximum=i<export->count ? cmeContextColumnMaxImageBytes : (i==export->count ? cmeContextColumnMaxBytes : cmeContextColumnMaxImageBytes);
            entry->length=i<export->count ? companions[i].length : 0;
            memcpy(entry->digest,i<export->count ? companions[i].digest : (i==export->count ?
                (root ? registration->candidateResourcesDigest : registration->sourceResourcesDigest) : transform->candidateDigest),32);
        }
        qsort(next->files[root],next->count[root],sizeof(*next->files[root]),cmeCustodyOrder);
        for (i=1;i<next->count[root];i++) if (!strcmp(next->files[root][i-1].name,next->files[root][i].name)) goto done;
        if (cmeCustodyEnumerate(&next->roots[root],next->files[root],next->count[root])) goto done;
        for (i=0;i<next->count[root];i++)
            if (cmeCustodyRead(&next->roots[root],&next->files[root][i],&bytes[root][i],1)) goto done;
    }
    actual=*export; actual.companions=companions;
    inputs=*credentials; inputs.source=inputs.candidate=inputs.sourceResources=inputs.candidateResources=NULL;
    inputs.sourceLength=inputs.candidateLength=inputs.sourceResourcesLength=inputs.candidateResourcesLength=0;
    for (root=0;root<2;root++)
        for (i=0;i<next->count[root];i++)
        {
            cmeCustodyFile *entry=&next->files[root][i];
            size_t j;
            if (!strcmp(entry->name,"ResourcesDB"))
            {
                if (root) { inputs.candidateResources=bytes[root][i]; inputs.candidateResourcesLength=entry->length; }
                else { inputs.sourceResources=bytes[root][i]; inputs.sourceResourcesLength=entry->length; }
            }
            else if (root && !strcmp(entry->name,registration->destinationFile))
            { inputs.candidate=bytes[root][i]; inputs.candidateLength=entry->length; }
            else
            {
                /* The manifest is sorted, so use a bounded binary lookup. */
                size_t left=0,right=export->count;
                while (left<right)
                {
                    j=left+(right-left)/2;
                    if (strcmp(companions[j].name,entry->name)<0) left=j+1; else right=j;
                }
                if (left==export->count || strcmp(companions[left].name,entry->name)) goto done;
                if (root) companions[left].candidate=bytes[root][i]; else companions[left].source=bytes[root][i];
                if (!root && !strcmp(entry->name,registration->sourceFile))
                { inputs.source=bytes[root][i]; inputs.sourceLength=entry->length; }
            }
        }
    cmeCustodyCheckpoint("after-read");
    result=cmeContextColumnExportVerify(manager,target,transform,registration,&inputs,&actual,acceptance,acceptanceLength,acceptanceDigest);
    if (result) goto done;
    cmeCustodyCheckpoint("after-acceptance");
    result=cmeContextColumnCustodyCheck(next); if (result) goto done;
    *custody=next; next=NULL;
done:
    for (root=0;root<2;root++)
    {
        if (bytes[root])
        {
            size_t count=export ? export->count+1+root : 0;
            for (i=0;i<count;i++) if (bytes[root][i])
            {
                /* Successful reads retain their exact bounded length. */
                cmeContextColumnCustody *owner=next ? next : (custody ? *custody : NULL);
                if (owner) OPENSSL_cleanse(bytes[root][i],owner->files[root][i].length);
                free(bytes[root][i]);
            }
            free(bytes[root]);
        }
    }
    free(companions); cmeContextColumnCustodyFree(&next); return(result);
}
