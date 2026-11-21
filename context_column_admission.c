/* Retained physical proof and blocked catalog/witness admission. */
#include "common.h"
#include "context_column.h"
#include "context_column_internal.h"

#define CME_PROOF_MAX (4U*1024U*1024U)
#define CME_PROOF_FILES 4100U
static const unsigned char cmeProofDomain[]="CDSE-HKX-COLUMN-ADMISSION-FILES-v1";
static const unsigned char cmeAdmissionJournalDomain[]="CDSE-HKX-COLUMN-ADMISSION-v1";
typedef struct { unsigned char *bytes; size_t length,maximum; } cmeAdmissionWriter;
typedef struct { const unsigned char *bytes; size_t length; } cmeAdmissionReader;

static void cmeAdmissionCheckpoint(const char *stage)
{
#ifdef CDSE_CONTEXT_COLUMN_TESTING
    const char *crash=getenv("CDSE_CONTEXT_ADMISSION_CRASH"),*pause=getenv("CDSE_CONTEXT_ADMISSION_PAUSE");
    if (crash && !strcmp(crash,stage)) _exit(86);
    if (pause && !strcmp(pause,stage))
    {
        const char *ready=getenv("CDSE_CONTEXT_ADMISSION_READY_FD"),*resume=getenv("CDSE_CONTEXT_ADMISSION_RESUME_FD");
        char byte;
        if (!ready || !resume || atoi(ready)<3 || atoi(resume)<3 ||
            write(atoi(ready),"1",1)!=1 || read(atoi(resume),&byte,1)!=1) _exit(87);
    }
#else
    (void)stage;
#endif
}

static int cmeAdmissionHash(const unsigned char *bytes, size_t length, unsigned char digest[32])
{
    unsigned int written=0;
    return(!EVP_Digest(bytes,length,digest,&written,EVP_sha256(),NULL) || written!=32);
}

static int cmeAdmissionAppend(cmeAdmissionWriter *writer, const void *bytes, size_t length)
{
    if (length>writer->maximum-writer->length) return(1);
    memcpy(writer->bytes+writer->length,bytes,length); writer->length+=length; return(0);
}

static int cmeAdmissionNumber(cmeAdmissionWriter *writer, uint64_t value, size_t width)
{
    unsigned char bytes[8]; size_t i;
    for (i=0;i<width;i++) bytes[i]=(unsigned char)(value>>(8*(width-i-1)));
    return(cmeAdmissionAppend(writer,bytes,width));
}

static int cmeAdmissionTake(cmeAdmissionReader *reader, void *bytes, size_t length)
{
    if (length>reader->length) return(1);
    if (bytes) memcpy(bytes,reader->bytes,length);
    reader->bytes+=length; reader->length-=length; return(0);
}

static int cmeAdmissionReadNumber(cmeAdmissionReader *reader, uint64_t *value, size_t width)
{
    size_t i; *value=0;
    if (width>reader->length) return(1);
    for (i=0;i<width;i++) *value=(*value<<8)|reader->bytes[i];
    return(cmeAdmissionTake(reader,NULL,width));
}

static int cmeAdmissionText(cmeAdmissionWriter *writer, const char *text)
{
    size_t length=strlen(text);
    return(length>NAME_MAX || cmeAdmissionNumber(writer,length,2) || cmeAdmissionAppend(writer,text,length));
}

static int cmeAdmissionReadText(cmeAdmissionReader *reader, char *text, size_t maximum, int leaf)
{
    uint64_t length;
    if (cmeAdmissionReadNumber(reader,&length,2) || !length || length>maximum || length>reader->length ||
        memchr(reader->bytes,0,(size_t)length) || cmeAdmissionTake(reader,text,(size_t)length)) return(1);
    text[length]=0; return(leaf ? cmeCustodyLeaf(text) : 0);
}

static int cmeAdmissionStat(cmeAdmissionWriter *writer, const struct stat *status, int full)
{
    uint64_t values[]={status->st_dev,status->st_ino,status->st_mode,status->st_uid,status->st_gid,
        status->st_nlink,status->st_size,status->st_mtim.tv_sec,status->st_mtim.tv_nsec,
        status->st_ctim.tv_sec,status->st_ctim.tv_nsec};
    size_t i;
    if (full && (status->st_size<0 || status->st_mtim.tv_sec<0 || status->st_ctim.tv_sec<0 ||
        status->st_mtim.tv_nsec<0 || status->st_mtim.tv_nsec>=1000000000L ||
        status->st_ctim.tv_nsec<0 || status->st_ctim.tv_nsec>=1000000000L)) return(1);
    for (i=0;i<(full ? 11U : 5U);i++) if (cmeAdmissionNumber(writer,values[i],8)) return(1);
    return(0);
}

static int cmeAdmissionStatMatch(cmeAdmissionReader *reader, const struct stat *status, int full)
{
    unsigned char bytes[88];
    cmeAdmissionWriter encoded={bytes,0,sizeof(bytes)};
    if (cmeAdmissionStat(&encoded,status,full) || encoded.length>reader->length ||
        CRYPTO_memcmp(reader->bytes,bytes,encoded.length)) return(1);
    return(cmeAdmissionTake(reader,NULL,encoded.length));
}

static int cmeAdmissionSnapshot(cmeContextColumnCustody *custody, const unsigned char publication[32],
    const unsigned char allocation[32], cmeAdmissionWriter *proof)
{
    size_t root,i;
    if (cmeAdmissionAppend(proof,cmeProofDomain,sizeof(cmeProofDomain)) ||
        cmeAdmissionAppend(proof,custody->acceptanceDigest,32) || cmeAdmissionAppend(proof,publication,32) ||
        cmeAdmissionAppend(proof,allocation,32)) return(1);
    for (root=0;root<2;root++)
    {
        if (!custody->count[root] || custody->count[root]>CME_PROOF_FILES ||
            cmeAdmissionStat(proof,&custody->roots[root].anchor,0) || cmeAdmissionText(proof,custody->roots[root].name) ||
            cmeAdmissionStat(proof,&custody->roots[root].status,1) || cmeAdmissionNumber(proof,custody->count[root],4)) return(1);
        for (i=0;i<custody->count[root];i++)
            if (cmeAdmissionText(proof,custody->files[root][i].name) ||
                cmeAdmissionStat(proof,&custody->files[root][i].status,1) ||
                cmeAdmissionAppend(proof,custody->files[root][i].digest,32)) return(1);
    }
    return(0);
}

/* No target capability or credentials: the manager ticket authenticates this
   exact retained snapshot, originally constructed from complete fresh custody. */
static int cmeAdmissionSnapshotLoad(const cmeContextColumnCustodyRoot *source,
    const cmeContextColumnCustodyRoot *published, const unsigned char *bytes, size_t length, cmeContextV2Buffer *image, unsigned char imageDigest[32])
{
    cmeAdmissionReader reader={bytes,length};
    cmeContextColumnCustody *view=NULL;
    char name[NAME_MAX+1];
    size_t root,i;
    uint64_t count;
    int result=1;
    unsigned char *raw=NULL;
    size_t selected=SIZE_MAX,missing=0;
    if (!bytes || length> CME_PROOF_MAX || length<sizeof(cmeProofDomain)+96 ||
        memcmp(bytes,cmeProofDomain,sizeof(cmeProofDomain)) ||
        cmeAdmissionTake(&reader,NULL,sizeof(cmeProofDomain)+96)) goto done;
    view=calloc(1,sizeof(*view)); if (!view) goto done;
    view->roots[0].parent=view->roots[0].directory=view->roots[1].parent=view->roots[1].directory=-1;
    if (cmeCustodyRootOpen(source,&view->roots[0]) || cmeCustodyRootOpen(published,&view->roots[1]) ||
        cmeCustodyNested(view->roots[0].directory,&view->roots[1].status) ||
        cmeCustodyNested(view->roots[1].directory,&view->roots[0].status)) goto done;
    for (root=0;root<2;root++)
    {
        cmeCustodyDirectory *directory=&view->roots[root];
        if (cmeAdmissionStatMatch(&reader,&directory->anchor,0) || cmeAdmissionReadText(&reader,name,NAME_MAX,1) ||
            strcmp(name,directory->name) || cmeAdmissionStatMatch(&reader,&directory->status,1) ||
            cmeAdmissionReadNumber(&reader,&count,4) || !count || count>CME_PROOF_FILES) goto done;
        view->files[root]=calloc((size_t)count,sizeof(*view->files[root]));
        if (!view->files[root]) goto done;
        view->count[root]=(size_t)count;
        for (i=0;i<view->count[root];i++)
        {
            cmeCustodyFile *file=&view->files[root][i];
            if (cmeAdmissionReadText(&reader,file->name,NAME_MAX,1) ||
                (i && strcmp(view->files[root][i-1].name,file->name)>=0) ||
                fstatat(directory->directory,file->name,&file->status,AT_SYMLINK_NOFOLLOW) ||
                cmeAdmissionStatMatch(&reader,&file->status,1) || cmeAdmissionTake(&reader,file->digest,32)) goto done;
            file->maximum=!strcmp(file->name,"ResourcesDB") ? cmeContextColumnMaxBytes : cmeContextColumnMaxImageBytes;
            if (file->status.st_size<100 || (uint64_t)file->status.st_size>file->maximum) goto done;
            file->length=(size_t)file->status.st_size;
        }
    }
    if (reader.length) goto done;
    result=cmeCustodyPhysicalCheck(view); if (result) goto done;
    if (image)
    {
        size_t j;
        result=1;
        if (!imageDigest || view->count[1]!=view->count[0]+1) goto done;
        j=0;
        for (i=0;i<view->count[1];i++)
        {
            if (j<view->count[0] && !strcmp(view->files[1][i].name,view->files[0][j].name)) j++;
            else { selected=i; missing++; }
        }
        if (j!=view->count[0] || missing!=1 || !strcmp(view->files[1][selected].name,"ResourcesDB") ||
            cmeCustodyRead(&view->roots[1],&view->files[1][selected],&raw,0)) goto done;
        image->length=view->files[1][selected].length;
        image->bytes=malloc(image->length+1); if (!image->bytes) { image->length=0; goto done; }
        memcpy(image->bytes,raw,image->length); image->bytes[image->length]=0;
        memcpy(imageDigest,view->files[1][selected].digest,32);
        result=cmeCustodyPhysicalCheck(view);
    }
    else result=0;
done:
    free(raw);
    if (result && image) { cmeContextV2BufferFree(image); if (imageDigest) memset(imageDigest,0,32); }
    cmeContextColumnCustodyFree(&view); return(result);
}

static int cmeAdmissionSnapshotCheck(const cmeContextColumnCustodyRoot *source,
    const cmeContextColumnCustodyRoot *published, const unsigned char *bytes, size_t length)
{
    return(cmeAdmissionSnapshotLoad(source,published,bytes,length,NULL,NULL));
}

int cmeContextColumnAdmissionPrepare(cmeContextColumnCustody *custody,
    const cmeContextColumnPublication *publication, const char *staging, const unsigned char publicationDigest[32],
    const unsigned char *allocation, size_t allocationLength, const unsigned char allocationDigest[32],
    const cmeContextAnchor *originalRegistry, cmeContextV2Buffer *journal, unsigned char journalDigest[32])
{
    cmeContextCopyEvidence evidence={0};
    cmeContextMapAnchor next={0};
    cmeAdmissionWriter proof={NULL,0,CME_PROOF_MAX},encoded={NULL,0,cmeContextColumnAdmissionMaxBytes};
    unsigned char *ticket=NULL,proofDigest[32],ticketDigest[32],digest[32];
    size_t ticketLength=0;
    int result=1;
    if (journal) { journal->bytes=NULL; journal->length=0; }
    if (journalDigest) memset(journalDigest,0,32);
    if (!custody || !journal || !journalDigest || !allocationDigest || !originalRegistry) goto done;
    result=cmeColumnPublicationCompleted(custody,publication,staging,publicationDigest); if (result) goto done;
    result=cmeContextCopyTargetEvidence(custody->manager,custody->target,&evidence); if (result) goto done;
    result=1;
    if (CRYPTO_memcmp(evidence.allocationDigest,allocationDigest,32) || !(proof.bytes=malloc(proof.maximum)) ||
        cmeAdmissionSnapshot(custody,publicationDigest,allocationDigest,&proof) ||
        cmeAdmissionHash(proof.bytes,proof.length,proofDigest)) goto done;
    result=cmeContextManagerColumnAdmissionPlan(custody->manager,allocation,allocationLength,allocationDigest,
        originalRegistry,&evidence.registry,&evidence.catalog,custody->destinationMap,proofDigest,
        &ticket,&ticketLength,ticketDigest,&next); if (result) goto done;
    result=1; encoded.bytes=malloc(encoded.maximum);
    if (!encoded.bytes || cmeAdmissionAppend(&encoded,cmeAdmissionJournalDomain,sizeof(cmeAdmissionJournalDomain)) ||
        cmeAdmissionAppend(&encoded,evidence.registry.deployment,16) || cmeAdmissionAppend(&encoded,evidence.registry.organization,16) ||
        cmeAdmissionNumber(&encoded,evidence.registry.generation,8) || cmeAdmissionNumber(&encoded,evidence.registry.minimumFormat,1) ||
        cmeAdmissionAppend(&encoded,evidence.registry.digest,32) || cmeAdmissionNumber(&encoded,evidence.catalog.revision,8) ||
        cmeAdmissionAppend(&encoded,evidence.catalog.digest,32) || cmeAdmissionNumber(&encoded,evidence.witness.revision,8) ||
        cmeAdmissionAppend(&encoded,evidence.witness.digest,32) || cmeAdmissionNumber(&encoded,next.revision,8) ||
        cmeAdmissionAppend(&encoded,next.digest,32) || cmeAdmissionText(&encoded,custody->destinationMap) ||
        cmeAdmissionNumber(&encoded,ticketLength,4) || cmeAdmissionAppend(&encoded,ticket,ticketLength) ||
        cmeAdmissionNumber(&encoded,proof.length,4) || cmeAdmissionAppend(&encoded,proof.bytes,proof.length) ||
        cmeAdmissionHash(encoded.bytes,encoded.length,digest)) goto done;
    result=cmeColumnPublicationCompleted(custody,publication,staging,publicationDigest); if (result) goto done;
    journal->bytes=encoded.bytes; journal->length=encoded.length; encoded.bytes=NULL;
    memcpy(journalDigest,digest,32); result=0;
done:
    free(ticket); free(proof.bytes); free(encoded.bytes); return(result);
}

typedef struct
{
    cmeContextColumnAdmissionResult completed;
    cmeContextMapAnchor original;
    cmeContextWitnessAnchor retained;
    unsigned char proofDigest[32],ticketDigest[32];
    const unsigned char *ticket,*proof;
    size_t ticketLength,proofLength;
    char name[129];
} cmeAdmissionPlan;

static int cmeAdmissionDecodeJournal(const unsigned char *journal, size_t length,
    const unsigned char journalDigest[32], cmeAdmissionPlan *plan)
{
    cmeAdmissionReader reader={journal,length};
    cmeContextColumnAdmissionResult completed={0};
    cmeContextMapAnchor original={0};
    cmeContextWitnessAnchor retained={0};
    unsigned char digest[32],proofDigest[32],ticketDigest[32];
    const unsigned char *ticket=NULL,*proof=NULL;
    size_t ticketLength=0,proofLength=0;
    uint64_t number;
    char name[129];
    if (!plan || !journal || !journalDigest || length>cmeContextColumnAdmissionMaxBytes ||
        length<sizeof(cmeAdmissionJournalDomain)+73+120+10 || cmeAdmissionHash(journal,length,digest) ||
        CRYPTO_memcmp(digest,journalDigest,32) || memcmp(journal,cmeAdmissionJournalDomain,sizeof(cmeAdmissionJournalDomain)) ||
        cmeAdmissionTake(&reader,NULL,sizeof(cmeAdmissionJournalDomain)) ||
        cmeAdmissionTake(&reader,completed.registry.deployment,16) || cmeAdmissionTake(&reader,completed.registry.organization,16) ||
        cmeAdmissionReadNumber(&reader,&completed.registry.generation,8) || cmeAdmissionReadNumber(&reader,&number,1)) return(1);
    completed.registry.minimumFormat=(unsigned int)number;
    if (cmeAdmissionTake(&reader,completed.registry.digest,32) || cmeAdmissionReadNumber(&reader,&original.revision,8) ||
        cmeAdmissionTake(&reader,original.digest,32) || cmeAdmissionReadNumber(&reader,&retained.revision,8) ||
        cmeAdmissionTake(&reader,retained.digest,32) || cmeAdmissionReadNumber(&reader,&completed.catalog.revision,8) ||
        cmeAdmissionTake(&reader,completed.catalog.digest,32) || cmeAdmissionReadText(&reader,name,128,0) ||
        cmeAdmissionReadNumber(&reader,&number,4) || !number || number>cmeContextRegistryMaxBytes || number>reader.length) return(1);
    ticket=reader.bytes; ticketLength=(size_t)number;
    if (cmeAdmissionTake(&reader,NULL,ticketLength) || cmeAdmissionReadNumber(&reader,&number,4) ||
        !number || number>CME_PROOF_MAX || number!=reader.length) return(1);
    proof=reader.bytes; proofLength=(size_t)number;
    if (cmeAdmissionHash(proof,proofLength,proofDigest) || cmeAdmissionHash(ticket,ticketLength,ticketDigest)) return(1);
    plan->completed=completed; plan->original=original; plan->retained=retained;
    memcpy(plan->proofDigest,proofDigest,32); memcpy(plan->ticketDigest,ticketDigest,32);
    plan->ticket=ticket; plan->ticketLength=ticketLength; plan->proof=proof; plan->proofLength=proofLength;
    strcpy(plan->name,name); return(0);
}

int cmeContextColumnAdmissionRun(cmeContextManager *manager, cmeContextWitness *witness,
    const cmeContextColumnCustodyRoot *source, const cmeContextColumnCustodyRoot *published,
    const unsigned char *journal, size_t length, const unsigned char journalDigest[32],
    cmeContextColumnAdmissionResult *output)
{
    cmeAdmissionPlan plan={0};
    cmeContextColumnAdmissionResult completed={0};
    cmeContextMapAnchor original={0};
    cmeContextWitnessAnchor retained={0},current={0};
    cmeContextWitnessRecovery recovery=cmeWitnessRecoveryInvalid;
    unsigned char proofDigest[32],ticketDigest[32];
    const unsigned char *ticket=NULL,*proof=NULL;
    size_t ticketLength=0,proofLength=0;
    char name[129];
    int result=1,state=0;
    if (output) memset(output,0,sizeof(*output));
    if (!output || !manager || !witness) goto done;
    if (cmeAdmissionDecodeJournal(journal,length,journalDigest,&plan)) goto done;
    completed=plan.completed; original=plan.original; retained=plan.retained;
    memcpy(proofDigest,plan.proofDigest,32); memcpy(ticketDigest,plan.ticketDigest,32);
    ticket=plan.ticket; ticketLength=plan.ticketLength; proof=plan.proof; proofLength=plan.proofLength;
    strcpy(name,plan.name);
    result=cmeContextManagerColumnAdmissionStep(manager,&completed.registry,&original,&completed.catalog,name,
        proofDigest,ticket,ticketLength,ticketDigest,0,&state); if (result) goto done;
    result=1;
    if (cmeAdmissionSnapshotCheck(source,published,proof,proofLength)) goto done;
    cmeAdmissionCheckpoint("before-catalog");
    if (cmeAdmissionSnapshotCheck(source,published,proof,proofLength)) goto done;
    result=cmeContextWitnessColumnAdmissionCommit(manager,witness,&retained,&completed.registry,&original,&completed.catalog,
        name,proofDigest,ticket,ticketLength,ticketDigest,&state); if (result) goto done;
    if (state!=2) { result=1; goto done; }
    cmeAdmissionCheckpoint("after-catalog");
    result=1;
    if (cmeAdmissionSnapshotCheck(source,published,proof,proofLength)) goto done;
    result=cmeContextWitnessReconcile(witness,&retained,&completed.registry,&completed.catalog,&recovery,&current);
    if (result) goto done;
    if (recovery==cmeWitnessRecoveryAdvanceRequired)
    {
        result=cmeContextWitnessCheck(witness,&completed.registry,&original); if (result) goto done;
        result=1; if (cmeAdmissionSnapshotCheck(source,published,proof,proofLength)) goto done;
        result=cmeContextManagerColumnAdmissionStep(manager,&completed.registry,&original,&completed.catalog,name,
            proofDigest,ticket,ticketLength,ticketDigest,0,&state); if (result) goto done;
        if (state!=2) { result=2; goto done; }
        result=cmeContextWitnessAdvance(witness,&retained,&completed.registry,&completed.catalog,&current); if (result) goto done;
    }
    else if (recovery!=cmeWitnessRecoveryAlreadyAdvanced) { result=2; goto done; }
    completed.witness=current;
    cmeAdmissionCheckpoint("after-witness");
    result=1; if (cmeAdmissionSnapshotCheck(source,published,proof,proofLength)) goto done;
    result=cmeContextManagerColumnAdmissionStep(manager,&completed.registry,&original,&completed.catalog,name,
        proofDigest,ticket,ticketLength,ticketDigest,0,&state); if (result) goto done;
    if (state!=2) { result=2; goto done; }
    result=cmeContextWitnessReconcile(witness,&retained,&completed.registry,&completed.catalog,&recovery,&current);
    if (result) goto done;
    if (recovery!=cmeWitnessRecoveryAlreadyAdvanced || current.revision!=completed.witness.revision ||
        CRYPTO_memcmp(current.digest,completed.witness.digest,32)) { result=2; goto done; }
    completed.state=2; *output=completed;
done:
    return(result);
}

struct cmeContextColumnReadRelease
{
    cmeContextManager *manager;
    cmeContextWitness *witness;
    cmeContextWitnessAnchor acknowledged;
    cmeContextColumnCustodyRoot roots[2];
    char names[2][NAME_MAX+1];
    unsigned char *journal,digest[32];
    size_t length;
    int failed;
};

void cmeContextColumnReadReleaseFree(cmeContextColumnReadRelease **release)
{
    size_t i;
    if (!release || !*release) return;
    for (i=0;i<2;i++) if ((*release)->roots[i].parent>=0) close((*release)->roots[i].parent);
    free((*release)->journal); OPENSSL_cleanse(*release,sizeof(**release)); free(*release); *release=NULL;
}

int cmeContextColumnReadReleaseCheck(cmeContextColumnReadRelease *release)
{
    cmeAdmissionPlan plan={0};
    cmeContextWitnessAnchor current={0};
    cmeContextWitnessRecovery recovery=cmeWitnessRecoveryInvalid;
    int result=1,state=0;
    if (!release) return(1);
    if (release->failed) return(release->failed);
    if (cmeAdmissionDecodeJournal(release->journal,release->length,release->digest,&plan)) goto done;
    result=cmeContextManagerColumnAdmissionStep(release->manager,&plan.completed.registry,&plan.original,
        &plan.completed.catalog,plan.name,plan.proofDigest,plan.ticket,plan.ticketLength,plan.ticketDigest,0,&state);
    if (result) goto done;
    if (state!=2) { result=2; goto done; }
    result=cmeContextWitnessReconcile(release->witness,&plan.retained,&plan.completed.registry,&plan.completed.catalog,
        &recovery,&current); if (result) goto done;
    if (recovery!=cmeWitnessRecoveryAlreadyAdvanced || current.revision!=release->acknowledged.revision ||
        CRYPTO_memcmp(current.digest,release->acknowledged.digest,32)) { result=2; goto done; }
    result=1;
    if (cmeAdmissionSnapshotCheck(&release->roots[0],&release->roots[1],plan.proof,plan.proofLength)) goto done;
    result=cmeContextManagerCheckAnchors(release->manager,&plan.completed.registry,&plan.completed.catalog);
    if (result) goto done;
    result=cmeContextWitnessReconcile(release->witness,&release->acknowledged,&plan.completed.registry,&plan.completed.catalog,
        &recovery,&current);
    if (!result && recovery!=cmeWitnessRecoveryCurrent) result=2;
done:
    if (result) release->failed=result;
    return(result);
}

int cmeContextColumnReadReleaseOpen(cmeContextManager *manager, cmeContextWitness *witness,
    const cmeContextColumnCustodyRoot *source, const cmeContextColumnCustodyRoot *published,
    const unsigned char *journal, size_t length, const unsigned char journalDigest[32],
    const cmeContextWitnessAnchor *acknowledged, cmeContextColumnReadRelease **release)
{
    cmeContextColumnReadRelease *candidate=NULL;
    const cmeContextColumnCustodyRoot *roots[2]={source,published};
    size_t i;
    int result=1;
    if (release) *release=NULL;
    if (!release || !manager || !witness || !journal || !journalDigest || !acknowledged || !acknowledged->revision ||
        !length || length>cmeContextColumnAdmissionMaxBytes) return(1);
    candidate=calloc(1,sizeof(*candidate)); if (!candidate) goto done;
    candidate->roots[0].parent=candidate->roots[1].parent=-1;
    candidate->manager=manager; candidate->witness=witness; candidate->acknowledged=*acknowledged;
    candidate->journal=malloc(length); if (!candidate->journal) goto done;
    memcpy(candidate->journal,journal,length); candidate->length=length; memcpy(candidate->digest,journalDigest,32);
    for (i=0;i<2;i++)
    {
        if (!roots[i] || roots[i]->parent<0 || cmeCustodyLeaf(roots[i]->name)) goto done;
        strcpy(candidate->names[i],roots[i]->name); candidate->roots[i].name=candidate->names[i];
        candidate->roots[i].parent=fcntl(roots[i]->parent,F_DUPFD_CLOEXEC,3);
        if (candidate->roots[i].parent<0) goto done;
    }
    result=cmeContextColumnReadReleaseCheck(candidate); if (result) goto done;
    cmeAdmissionCheckpoint("before-read-release");
    result=cmeContextColumnReadReleaseCheck(candidate); if (result) goto done;
    *release=candidate; candidate=NULL;
done:
    cmeContextColumnReadReleaseFree(&candidate); return(result);
}

int cmeContextColumnRead(cmeContextColumnReadRelease *release, const char *table, int64_t row, const char *field,
    const unsigned char *password, size_t passwordLength, cmeContextV2Buffer *plaintext)
{
    cmeAdmissionPlan plan={0};
    cmeContextMap *map=NULL;
    cmeContextBinding *binding=NULL;
    cmeContextColumnStage *stage=NULL;
    cmeContextV2Buffer image={0},candidate={0};
    unsigned char imageDigest[32];
    size_t i;
    int result=1;
    if (plaintext) { plaintext->bytes=NULL; plaintext->length=0; }
    if (!plaintext || !release || !table || !field || row<1 || !password || !passwordLength || passwordLength>256) goto done;
    result=cmeContextColumnReadReleaseCheck(release); if (result) goto done;
    result=1;
    if (cmeAdmissionDecodeJournal(release->journal,release->length,release->digest,&plan) ||
        cmeAdmissionSnapshotLoad(&release->roots[0],&release->roots[1],plan.proof,plan.proofLength,&image,imageDigest)) goto done;
    result=cmeContextManagerColumnAdmissionBind(release->manager,&plan.completed.registry,&plan.original,&plan.completed.catalog,
        plan.name,plan.proofDigest,plan.ticket,plan.ticketLength,plan.ticketDigest,&map,&binding); if (result) goto done;
    result=cmeColumnStageDeserializeAdmission(release->manager,binding,map,image.bytes,image.length,imageDigest,
        password,passwordLength,&stage); if (result) goto done;
    result=1;
    for (i=0;i<stage->count;i++)
    {
        const cmeContextColumnCell *cell=&stage->cells[i];
        if (!strcmp(cell->table,table) && cell->row==row && !strcmp(cell->field,field))
        {
            result=cmeContextV2OpenAdmissionBinding(release->manager,binding,table,row,field,password,passwordLength,
                cell->salt,cell->frame.bytes,cell->frame.length,&candidate);
            break;
        }
    }
    if (result) goto done;
    cmeAdmissionCheckpoint("after-read");
    result=cmeContextColumnReadReleaseCheck(release); if (result) goto done;
    *plaintext=candidate; memset(&candidate,0,sizeof(candidate));
done:
    cmeContextV2BufferFree(&image); cmeContextV2BufferFree(&candidate); cmeContextColumnStageFree(&stage);
    cmeContextBindingFree(&binding); cmeContextMapFree(&map); return(result);
}
