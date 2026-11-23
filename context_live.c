#include "common.h"
#include "context_column.h"
#include "context_live.h"
#include "context_offline.h"

/* A read verifies the entire release. Bound this work to one request at a time. */
static pthread_mutex_t cmeContextLiveLock=PTHREAD_MUTEX_INITIALIZER;

int cmeContextLiveRead(const char *org, const char *storage, const char *document,
    int64_t row, cmeContextV2Buffer *value)
{
    const char *enabled=getenv("CDSE_V2_READ_ENABLED");
    const char *routeOrg=getenv("CDSE_V2_READ_ORG");
    const char *routeStorage=getenv("CDSE_V2_READ_STORAGE");
    const char *routeDocument=getenv("CDSE_V2_READ_DOCUMENT");
    const char *sourcePath=getenv("CDSE_V2_READ_SOURCE_EXPORT");
    const char *publishedPath=getenv("CDSE_V2_READ_PUBLISHED_EXPORT");
    cmeOfflineArtifact source={.file=-1,.directory=-1};
    cmeOfflineArtifact published={.file=-1,.directory=-1};
    cmeContextColumnCustodyRoot roots[2];
    cmeContextManager *manager=NULL;
    cmeContextWitness *witness=NULL;
    cmeContextColumnReadRelease *release=NULL;
    cmeContextWitnessAnchor acknowledged={0};
    unsigned char deployment[16],organization[16],digest[32],token[40];
    unsigned char registryKey[32],witnessKey[32];
    char *envelope=NULL,*password=NULL;
    size_t envelopeLength=0,passwordLength=0,i;
    int status=503;

    if (!enabled || strcmp(enabled,"1") || !routeOrg || strcmp(routeOrg,org) ||
        !routeStorage || strcmp(routeStorage,storage) || !routeDocument || strcmp(routeDocument,document))
        return(404);
    if (pthread_mutex_trylock(&cmeContextLiveLock)) return(503);

    if (!sourcePath || !publishedPath ||
        cmeOfflineDecodeHex(getenv("CDSE_V2_READ_DEPLOYMENT"),deployment,sizeof(deployment)) ||
        cmeOfflineDecodeHex(getenv("CDSE_V2_READ_ORGANIZATION"),organization,sizeof(organization)) ||
        cmeOfflineDecodeHex(getenv("CDSE_V2_READ_RELEASE_DIGEST"),digest,sizeof(digest)) ||
        cmeOfflineDecodeHex(getenv("CDSE_V2_READ_WITNESS_TOKEN"),token,sizeof(token))) goto done;
    for (i=0;i<8;i++) acknowledged.revision=(acknowledged.revision<<8)|token[i];
    memcpy(acknowledged.digest,token+8,sizeof(acknowledged.digest));
    if (!acknowledged.revision ||
        cmeOfflineOpen(sourcePath,0,&source) || cmeOfflineOpen(publishedPath,0,&published) ||
        cmeOfflineReadPrivate(getenv("CDSE_V2_READ_RELEASE_ENVELOPE"),cmeContextColumnGlobalMaxBytes,
            &envelope,&envelopeLength,cmeOfflineBinaryFile) ||
        cmeOfflineReadKey(getenv("CDSE_V2_READ_REGISTRY_KEY_FILE"),registryKey) ||
        cmeOfflineReadKey(getenv("CDSE_V2_READ_WITNESS_KEY_FILE"),witnessKey) ||
        !CRYPTO_memcmp(registryKey,witnessKey,sizeof(registryKey)) ||
        cmeContextManagerOpen(getenv("CDSE_V2_READ_REGISTRY_DIRECTORY"),0,registryKey,deployment,organization,&manager) ||
        cmeContextWitnessOpen(getenv("CDSE_V2_READ_WITNESS_DIRECTORY"),0,witnessKey,deployment,organization,
            NULL,NULL,&witness)) goto done;

    roots[0]=(cmeContextColumnCustodyRoot){.parent=source.directory,.name=source.name};
    roots[1]=(cmeContextColumnCustodyRoot){.parent=published.directory,.name=published.name};
    if (cmeContextColumnGlobalReadOpen(manager,witness,&roots[0],&roots[1],(const unsigned char *)envelope,
            envelopeLength,digest,&acknowledged,&release) ||
        cmeOfflineReadPrivate(getenv("CDSE_V2_READ_PASSWORD_FILE"),256,&password,&passwordLength,cmeOfflineBinaryFile) ||
        cmeContextColumnRead(release,"data",row,"value",(const unsigned char *)password,passwordLength,value)) goto done;
    status=200;

done:
    if (password) OPENSSL_cleanse(password,passwordLength);
    free(password);
    free(envelope);
    OPENSSL_cleanse(registryKey,sizeof(registryKey));
    OPENSSL_cleanse(witnessKey,sizeof(witnessKey));
    cmeContextColumnReadReleaseFree(&release);
    cmeContextWitnessClose(&witness);
    cmeContextManagerClose(&manager);
    cmeOfflineClose(&source);
    cmeOfflineClose(&published);
    pthread_mutex_unlock(&cmeContextLiveLock);
    return(status);
}
