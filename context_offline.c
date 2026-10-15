#include "common.h"
#include "context_offline.h"

static int cmeOfflineSame(const struct stat *a, const struct stat *b)
{
    return(a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_size==b->st_size &&
        a->st_mode==b->st_mode && a->st_uid==b->st_uid && a->st_nlink==b->st_nlink &&
        a->st_mtim.tv_sec==b->st_mtim.tv_sec && a->st_mtim.tv_nsec==b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec && a->st_ctim.tv_nsec==b->st_ctim.tv_nsec);
}

static int cmeOfflineSidecars(const cmeOfflineArtifact *artifact)
{
    static const char *suffixes[]={"-journal","-wal","-shm"};
    char name[NAME_MAX+9];
    struct stat status;
    size_t i;
    for (i=0;i<3;i++)
    {
        if (snprintf(name,sizeof(name),"%s%s",artifact->name,suffixes[i])>=(int)sizeof(name)) return(1);
        if (!fstatat(artifact->directory,name,&status,AT_SYMLINK_NOFOLLOW) || errno!=ENOENT) return(1);
    }
    return(0);
}

void cmeOfflineClose(cmeOfflineArtifact *artifact)
{
    if (artifact->file>=0) close(artifact->file);
    if (artifact->directory>=0) close(artifact->directory);
    artifact->file=-1; artifact->directory=-1;
}

int cmeOfflineOpen(const char *path, int content, cmeOfflineArtifact *artifact)
{
    char parent[PATH_MAX],canonical[PATH_MAX],*slash;
    unsigned char buffer[16384];
    struct stat after;
    EVP_MD_CTX *hash=NULL;
    off_t offset=0;
    unsigned int written;
    int result=1;
    memset(artifact,0,sizeof(*artifact)); artifact->file=-1; artifact->directory=-1;
    if (!path || *path!='/' || strlen(path)>=sizeof(parent)) goto done;
    strcpy(parent,path); slash=strrchr(parent,'/');
    if (!slash || slash==parent || !slash[1] || strlen(slash+1)>NAME_MAX) goto done;
    strcpy(artifact->name,slash+1); *slash=0;
    if (!strcmp(artifact->name,".") || !strcmp(artifact->name,"..") ||
        !realpath(parent,canonical) || strcmp(parent,canonical)) goto done;
    artifact->directory=open(parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
    if (artifact->directory<0 || fstat(artifact->directory,&artifact->parent) ||
        artifact->parent.st_uid!=geteuid() || (artifact->parent.st_mode&07777)!=0700 ||
        !artifact->parent.st_nlink) goto done;
    if (!content) { result=0; goto done; }
    if (!realpath(path,canonical) || strcmp(path,canonical) || cmeOfflineSidecars(artifact)) goto done;
    artifact->file=openat(artifact->directory,artifact->name,O_RDWR|O_NOFOLLOW|O_NONBLOCK);
    if (artifact->file<0 || fstat(artifact->file,&artifact->status) || !S_ISREG(artifact->status.st_mode) ||
        artifact->status.st_uid!=geteuid() || (artifact->status.st_mode&07777)!=0600 ||
        artifact->status.st_nlink!=1 || artifact->status.st_size<100 ||
        artifact->status.st_size>cmeOfflineMaxBytes || fsync(artifact->file)) goto done;
    hash=EVP_MD_CTX_new();
    if (!hash || !EVP_DigestInit_ex(hash,EVP_sha256(),NULL)) goto done;
    while (offset<artifact->status.st_size)
    {
        size_t wanted=(size_t)(artifact->status.st_size-offset);
        ssize_t got;
        if (wanted>sizeof(buffer)) wanted=sizeof(buffer);
        got=pread(artifact->file,buffer,wanted,offset);
        if (got<0 && errno==EINTR) continue;
        if (got<=0) goto done;
        if (!offset && (got<20 || memcmp(buffer,"SQLite format 3\0",16) || buffer[18]!=1 || buffer[19]!=1)) goto done;
        if (!EVP_DigestUpdate(hash,buffer,(size_t)got)) goto done;
        offset+=got;
    }
    if (!EVP_DigestFinal_ex(hash,artifact->digest,&written) || written!=32 ||
        fstat(artifact->file,&after) || !cmeOfflineSame(&artifact->status,&after) ||
        fstatat(artifact->directory,artifact->name,&after,AT_SYMLINK_NOFOLLOW) ||
        !cmeOfflineSame(&artifact->status,&after) || cmeOfflineSidecars(artifact)) goto done;
    result=0;
done:
    EVP_MD_CTX_free(hash);
    if (result) cmeOfflineClose(artifact);
    return(result);
}

int cmeOfflineSync(cmeOfflineArtifact *active, cmeOfflineArtifact *staged)
{
    return(fsync(active->directory) || fsync(staged->directory));
}

int cmeOfflineVerify(const cmeOfflineArtifact *artifact)
{
    struct stat status;
    return(fstatat(artifact->directory,artifact->name,&status,AT_SYMLINK_NOFOLLOW) ||
        !cmeOfflineSame(&artifact->status,&status) || cmeOfflineSidecars(artifact));
}

int cmeOfflineInstall(cmeOfflineArtifact *active, cmeOfflineArtifact *staged)
{
    struct stat status;
    if (active->status.st_dev!=staged->status.st_dev ||
        fstatat(active->directory,active->name,&status,AT_SYMLINK_NOFOLLOW) ||
        !cmeOfflineSame(&active->status,&status) || cmeOfflineSidecars(active) ||
        fstatat(staged->directory,staged->name,&status,AT_SYMLINK_NOFOLLOW) ||
        !cmeOfflineSame(&staged->status,&status) || cmeOfflineSidecars(staged) ||
        renameat(staged->directory,staged->name,active->directory,active->name)) return(1);
#ifdef CDSE_CONTEXT_MANAGER_TESTING
    if (getenv("CDSE_CONTEXT_OFFLINE_CRASH") &&
        (!strcmp(getenv("CDSE_CONTEXT_OFFLINE_CRASH"),"after-rename") ||
         (!strcmp(getenv("CDSE_CONTEXT_OFFLINE_CRASH"),"after-resources-rename") &&
          !strcmp(active->name,"ResourcesDB")))) _exit(86);
#endif
    return(cmeOfflineSync(active,staged));
}
