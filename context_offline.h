#ifndef CME_CONTEXT_OFFLINE_H
#define CME_CONTEXT_OFFLINE_H

#include <sys/stat.h>
#include <limits.h>

#define cmeOfflineMaxBytes (256U*1024U*1024U)

/* Internal file primitives only; authority/ordering belongs to the manager. */
typedef struct
{
    int file, directory;
    struct stat status, parent;
    char name[NAME_MAX+1];
    unsigned char digest[32];
} cmeOfflineArtifact;

int cmeOfflineOpen(const char *path, int content, cmeOfflineArtifact *artifact);
void cmeOfflineClose(cmeOfflineArtifact *artifact);
int cmeOfflineSync(cmeOfflineArtifact *active, cmeOfflineArtifact *staged);
int cmeOfflineInstall(cmeOfflineArtifact *active, cmeOfflineArtifact *staged);
int cmeOfflineVerify(const cmeOfflineArtifact *artifact);

#endif
