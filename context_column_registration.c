/* Verified offline registration snapshots; no physical publication. */
#include "common.h"
#include "context_column.h"
#include "context_column_internal.h"

static int cmeRegText(const char *value, size_t maximum, int leaf)
{
    size_t i,n;
    if (!value || !(n=strnlen(value,maximum+1)) || n>maximum) return(1);
    for (i=0;i<n;i++)
    {
        unsigned char c=value[i];
        if (c<32 || c==127 || (leaf && !((c>='a' && c<='z') || (c>='A' && c<='Z') ||
            (c>='0' && c<='9') || c=='_' || c=='-' || c=='.'))) return(1);
    }
    return(leaf && (value[0]=='.' || !strcmp(value,"ResourcesDB") || !strcmp(value,"RolesDB") || !strcmp(value,"LogsDB")));
}

int cmeContextColumnRegistrationDigest(const cmeContextColumnTransformApproval *transform,
    const cmeContextColumnRegistrationApproval *approval, unsigned char digest[32])
{
    static const unsigned char domain[]="CDSE-HKX-COLUMN-REGISTRATION-v1";
    unsigned char body[4096],profile;
    unsigned int written=0;
    const char *text[9];
    size_t i,j,n,offset=0;
    int result;
    if (digest) memset(digest,0,32);
    if (!digest || !transform || !approval || !approval->metadataProfile || !transform->sourceProfile ||
        approval->sourceRow<1 || approval->sourceRow>INT_MAX || approval->destinationRow<1 ||
        approval->destinationRow>INT_MAX || approval->sourceRow==approval->destinationRow) return(1);
    if (!strcmp(approval->metadataProfile,"aes-256-gcm")) profile=1;
    else if (!strcmp(approval->metadataProfile,"aes-256-cbc")) profile=2;
    else return(1);
    text[0]=approval->sourceFile; text[1]=approval->destinationFile; text[2]=approval->sourceDocument;
    text[3]=approval->destinationDocument; text[4]=approval->storageId; text[5]=approval->organizationResource;
    text[6]=approval->columnId; text[7]=approval->storagePath; text[8]=transform->destinationMap;
    for (i=0;i<9;i++) if (cmeRegText(text[i],i<2 ? 255 : (i==7 ? 1024 : 128),i<2)) return(1);
    if (text[7][0]!='/' || !strcmp(text[0],text[1]) || !strcmp(text[2],text[3]) ||
        (strcmp(transform->sourceProfile,"aes-256-gcm") && strcmp(transform->sourceProfile,"aes-256-cbc"))) return(1);
#define CME_REG_APPEND(p,n) do { memcpy(body+offset,p,n); offset+=(n); } while (0)
    CME_REG_APPEND(domain,sizeof(domain)); body[offset++]=profile;
    body[offset++]=!strcmp(transform->sourceProfile,"aes-256-gcm") ? 1 : 2;
    CME_REG_APPEND(approval->sourceResourcesDigest,32); CME_REG_APPEND(approval->candidateResourcesDigest,32);
    CME_REG_APPEND(transform->sourceDigest,32); CME_REG_APPEND(transform->candidateDigest,32);
    for (i=0;i<2;i++)
    {
        uint64_t row=i ? approval->destinationRow : approval->sourceRow;
        for (j=0;j<8;j++) body[offset++]=(unsigned char)(row>>(8*(7-j)));
    }
    for (i=0;i<9;i++)
    {
        n=strlen(text[i]); body[offset++]=(unsigned char)(n>>8); body[offset++]=(unsigned char)n;
        CME_REG_APPEND(text[i],n);
    }
#undef CME_REG_APPEND
    _Static_assert(sizeof(domain)+2+128+16+18+2*255+6*128+1024<=sizeof(body),"registration approval bound");
    result=!EVP_Digest(body,offset,digest,&written,EVP_sha256(),NULL) || written!=32;
    OPENSSL_cleanse(body,sizeof(body));
    if (result) memset(digest,0,32);
    return(result);
}

#if defined(HAVE_SQLITE3_DESERIALIZE)
static const char *cmeRegSQLText(sqlite3_stmt *stmt, int column)
{
    const char *text;
    if (sqlite3_column_type(stmt,column)!=SQLITE_TEXT || sqlite3_column_bytes(stmt,column)>(int)cmeContextColumnMaxCellBytes) return(NULL);
    text=(const char *)sqlite3_column_text(stmt,column);
    return(text && strlen(text)==(size_t)sqlite3_column_bytes(stmt,column) ? text : NULL);
}

static int cmeRegBudget(void *context)
{
    unsigned int *budget=context;
    if (!*budget) return(1);
    --*budget; return(0);
}

static int cmeRegHash(const unsigned char *bytes, size_t length, const unsigned char expected[32])
{
    unsigned char digest[32]; unsigned int written=0;
    return(!EVP_Digest(bytes,length,digest,&written,EVP_sha256(),NULL) || written!=32 || CRYPTO_memcmp(digest,expected,32));
}

static int cmeRegOpen(const unsigned char *bytes, size_t length, const unsigned char digest[32],
    sqlite3 **db, unsigned char **copy, unsigned int *budget)
{
    sqlite3_stmt *stmt=NULL;
    int result=1;
    if (!bytes || length<100 || length>cmeContextColumnMaxBytes || !(*copy=sqlite3_malloc64(length))) return(1);
    memcpy(*copy,bytes,length);
    if (cmeRegHash(*copy,length,digest) || memcmp(*copy,"SQLite format 3",16) || (*copy)[18]!=1 || (*copy)[19]!=1 ||
        sqlite3_open(":memory:",db)!=SQLITE_OK || sqlite3_deserialize(*db,"main",*copy,length,length,SQLITE_DESERIALIZE_READONLY)!=SQLITE_OK) goto done;
    sqlite3_limit(*db,SQLITE_LIMIT_LENGTH,cmeContextColumnMaxCellBytes); sqlite3_limit(*db,SQLITE_LIMIT_COLUMN,24);
    sqlite3_limit(*db,SQLITE_LIMIT_SQL_LENGTH,65536); sqlite3_progress_handler(*db,1000,cmeRegBudget,budget);
    if (sqlite3_db_config(*db,SQLITE_DBCONFIG_DEFENSIVE,1,NULL)!=SQLITE_OK ||
        sqlite3_exec(*db,"PRAGMA trusted_schema=OFF; PRAGMA query_only=ON",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeCheckInternalDBSchema(*db,"ResourcesDB",0) || sqlite3_prepare_v2(*db,
        "SELECT 1 FROM sqlite_master WHERE type NOT IN ('table','index') OR tbl_name NOT IN "
        "('documents','users','organizations','storage','filterWhitelist','filterBlacklist','schema_meta') UNION ALL "
        "SELECT 1 FROM pragma_table_list WHERE schema='main' AND type IN ('virtual','shadow')",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    {
        static const char *tables[]={"documents","users","organizations","storage","filterWhitelist","filterBlacklist","schema_meta"};
        static const int columns[]={18,12,8,12,12,12,2};
        size_t i;
        for (i=0;i<7;i++)
        {
            char *sql=sqlite3_mprintf("PRAGMA table_xinfo(\"%w\")",tables[i]);
            int column=0,step;
            if (!sql) goto done;
            result=sqlite3_prepare_v2(*db,sql,-1,&stmt,NULL)!=SQLITE_OK; sqlite3_free(sql);
            if (result) { result=1; goto done; }
            result=1;
            while ((step=sqlite3_step(stmt))==SQLITE_ROW)
            {
                if (sqlite3_column_int(stmt,6) || (!column &&
                    (!sqlite3_column_text(stmt,1) || strcmp((const char *)sqlite3_column_text(stmt,1),i==6 ? "key" : "id") ||
                    !sqlite3_column_text(stmt,2) || strcmp((const char *)sqlite3_column_text(stmt,2),i==6 ? "TEXT" : "INTEGER") ||
                    sqlite3_column_int(stmt,5)!=1))) goto done;
                column++;
            }
            if (step!=SQLITE_DONE || column!=columns[i]) goto done;
            sqlite3_finalize(stmt); stmt=NULL;
        }
    }
    if (sqlite3_prepare_v2(*db,"PRAGMA integrity_check",-1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
        !sqlite3_column_text(stmt,0) || strcmp((const char *)sqlite3_column_text(stmt,0),"ok") || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    result=0;
done:
    sqlite3_finalize(stmt); return(result);
}

static int cmeRegDecode(sqlite3_stmt *stmt, int column, const char *key, const char *profile, char **plain)
{
    const char *value=cmeRegSQLText(stmt,column),*saltText=cmeRegSQLText(stmt,3);
    char *salt=NULL,*tag=NULL;
    int written=0,result=1;
    *plain=NULL;
    if (!value || strlen(value)<=64 || !saltText || strlen(saltText)!=32 || strspn(saltText,"0123456789abcdefABCDEF")!=32 ||
        !(salt=strdup(saltText)) || cmeHMACByteString((const unsigned char *)value+64,(unsigned char **)&tag,strlen(value+64),
        &written,"sha256",&salt,key) || written!=64 || CRYPTO_memcmp(value,tag,64)) goto done;
    result=cmeContextColumnLegacyDecode(value+64,saltText,key,profile,plain);
done:
    free(salt); free(tag); return(result);
}

static void cmeRegPlainFree(char **plain)
{
    size_t i;
    for (i=0;i<18;i++) if (plain[i]) { OPENSSL_cleanse(plain[i],strlen(plain[i])); free(plain[i]); plain[i]=NULL; }
}

static int cmeRegLookup(sqlite3_stmt *stmt, const char *key, char **plain)
{
    static const char *fields[]={"documentId","storageId","orgResourceId"};
    char *expected=NULL;
    const char *stored;
    int i,result=1;
    for (i=0;i<3;i++)
    {
        stored=cmeRegSQLText(stmt,15+i);
        if (!stored || strlen(stored)!=64 || cmeGetProtectDBLookupValue(fields[i],plain[7+i],key,&expected) ||
            !expected || strlen(expected)!=64 || CRYPTO_memcmp(stored,expected,64)) goto done;
        free(expected); expected=NULL;
    }
    result=0;
done:
    free(expected); return(result);
}

static int cmeRegRow(sqlite3 *db, int destination, const cmeContextColumnRegistrationApproval *a,
    const cmeContextColumnRegistrationInputs *in, char **plain)
{
    static const char *names[]={"id","userId","orgId","salt","resourceInfo","columnFile","type","documentId",
        "storageId","orgResourceId","partMAC","totalParts","partId","lastModified","columnId",
        "documentIdLookup","storageIdLookup","orgResourceIdLookup"};
    sqlite3_stmt *stmt=NULL;
    char *salt=NULL,*tag=NULL;
    const char *saltText;
    int result=1,i,written=0;
    int64_t row=destination ? a->destinationRow : a->sourceRow;
    if (sqlite3_prepare_v2(db,"SELECT * FROM documents WHERE id=?1",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_column_count(stmt)!=18 || sqlite3_bind_int64(stmt,1,row)!=SQLITE_OK) goto done;
    for (i=0;i<18;i++) if (strcmp(sqlite3_column_name(stmt,i),names[i])) goto done;
    if (sqlite3_step(stmt)!=SQLITE_ROW || sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || sqlite3_column_int64(stmt,0)!=row) goto done;
    for (i=1;i<15;i++) if (i!=3 && cmeRegDecode(stmt,i,in->registrationKey,a->metadataProfile,&plain[i])) goto done;
    if (strcmp(plain[5],destination ? a->destinationFile : a->sourceFile) ||
        strcmp(plain[6],destination ? cmeContextColumnRegistrationType : "file.csv") ||
        strcmp(plain[7],destination ? a->destinationDocument : a->sourceDocument) ||
        strcmp(plain[8],a->storageId) || strcmp(plain[9],a->organizationResource) || strcmp(plain[14],a->columnId) ||
        strcmp(plain[11],"1") || strcmp(plain[12],"1") || cmeRegLookup(stmt,in->registrationKey,plain)) goto done;
    saltText=cmeRegSQLText(stmt,3);
    if (!saltText || !(plain[3]=strdup(saltText)) || !(salt=strdup(plain[3])) ||
        cmeHMACByteString(destination ? in->candidate : in->source,(unsigned char **)&tag,
        destination ? in->candidateLength : in->sourceLength,&written,"sha256",&salt,in->registrationKey) ||
        written!=64 || strlen(plain[10])!=64 || CRYPTO_memcmp(tag,plain[10],64) || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    result=0;
done:
    free(salt); free(tag); sqlite3_finalize(stmt); return(result);
}

static int cmeRegCell(sqlite3_stmt *a, sqlite3_stmt *b, int column)
{
    int type=sqlite3_column_type(a,column),n;
    const void *left,*right;
    if (type!=sqlite3_column_type(b,column)) return(1);
    if (type==SQLITE_NULL) return(0);
    if (type==SQLITE_INTEGER) return(sqlite3_column_int64(a,column)!=sqlite3_column_int64(b,column));
    if (type!=SQLITE_TEXT && type!=SQLITE_BLOB) return(1);
    left=sqlite3_column_blob(a,column); right=sqlite3_column_blob(b,column); n=sqlite3_column_bytes(a,column);
    return(n!=sqlite3_column_bytes(b,column) || (n && (!left || !right || memcmp(left,right,n))));
}

static int cmeRegClone(sqlite3 *source, sqlite3 *candidate, int64_t destinationRow)
{
    static const char *tables[]={"documents","users","organizations","storage","filterWhitelist","filterBlacklist","schema_meta"};
    static const int counts[]={18,12,8,12,12,12,2,4};
    sqlite3_stmt *a=NULL,*b=NULL;
    char *sql=NULL;
    size_t table,rows=0;
    int result=1,step,column;
    for (table=0;table<8;table++)
    {
        sql=table==7 ? sqlite3_mprintf("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name COLLATE BINARY") :
            sqlite3_mprintf("SELECT * FROM \"%w\" ORDER BY %s",tables[table],table==6 ? "key COLLATE BINARY" : "id");
        if (!sql || sqlite3_prepare_v2(source,sql,-1,&a,NULL)!=SQLITE_OK) goto done;
        if (!table) { sqlite3_free(sql); sql=sqlite3_mprintf("SELECT * FROM documents WHERE id!=?1 ORDER BY id"); }
        if (!sql || sqlite3_prepare_v2(candidate,sql,-1,&b,NULL)!=SQLITE_OK ||
            (!table && sqlite3_bind_int64(b,1,destinationRow)!=SQLITE_OK) || sqlite3_column_count(a)!=counts[table] ||
            sqlite3_column_count(b)!=counts[table]) goto done;
        sqlite3_free(sql); sql=NULL;
        for (column=0;column<counts[table];column++) if (strcmp(sqlite3_column_name(a,column),sqlite3_column_name(b,column))) goto done;
        while ((step=sqlite3_step(a))==SQLITE_ROW)
        {
            if (++rows>cmeContextRegistryMaxEntries || sqlite3_step(b)!=SQLITE_ROW ||
                (!table && sqlite3_column_int64(a,0)==destinationRow) ||
                (table<6 && (sqlite3_column_type(a,0)!=SQLITE_INTEGER || sqlite3_column_int64(a,0)<1))) goto done;
            for (column=0;column<counts[table];column++) if (cmeRegCell(a,b,column)) goto done;
        }
        if (step!=SQLITE_DONE || sqlite3_step(b)!=SQLITE_DONE) goto done;
        sqlite3_finalize(a); a=NULL; sqlite3_finalize(b); b=NULL;
    }
    result=0;
done:
    sqlite3_free(sql); sqlite3_finalize(a); sqlite3_finalize(b); return(result);
}

static int cmeRegAssociations(sqlite3 *db, int destination, const cmeContextColumnRegistrationApproval *a, const char *key)
{
    sqlite3_stmt *stmt=NULL;
    char *plain[18]={0};
    static const int fields[]={5,7,8,9,14};
    size_t i,rows=0,source=0,target=0;
    int result=1,step;
    if (sqlite3_prepare_v2(db,"SELECT * FROM documents ORDER BY id",-1,&stmt,NULL)!=SQLITE_OK || sqlite3_column_count(stmt)!=18) goto done;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        int64_t row=sqlite3_column_int64(stmt,0);
        if (sqlite3_column_type(stmt,0)!=SQLITE_INTEGER || row<1 || ++rows>cmeContextRegistryMaxEntries+1) goto done;
        for (i=0;i<5;i++) if (cmeRegDecode(stmt,fields[i],key,a->metadataProfile,&plain[fields[i]])) goto done;
        if (cmeRegLookup(stmt,key,plain)) goto done;
        if (!strcmp(plain[5],a->sourceFile) && row!=a->sourceRow) goto done;
        if (!strcmp(plain[7],a->sourceDocument) && !strcmp(plain[8],a->storageId) &&
            !strcmp(plain[9],a->organizationResource) && !strcmp(plain[14],a->columnId))
        { if (row!=a->sourceRow || ++source!=1) goto done; }
        if (!strcmp(plain[5],a->destinationFile) || !strcmp(plain[7],a->destinationDocument))
        { if (!destination || row!=a->destinationRow || ++target!=1) goto done; }
        cmeRegPlainFree(plain);
    }
    if (step!=SQLITE_DONE || source!=1 || target!=(destination ? 1U : 0U)) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(db,"SELECT * FROM storage ORDER BY id",-1,&stmt,NULL)!=SQLITE_OK || sqlite3_column_count(stmt)!=12) goto done;
    rows=0; target=0;
    while ((step=sqlite3_step(stmt))==SQLITE_ROW)
    {
        if (++rows>cmeContextRegistryMaxEntries || cmeRegDecode(stmt,7,key,a->metadataProfile,&plain[7]) ||
            cmeRegDecode(stmt,11,key,a->metadataProfile,&plain[11])) goto done;
        if (!strcmp(plain[7],a->storageId) && !strcmp(plain[11],a->organizationResource))
        {
            if (++target!=1 || cmeRegDecode(stmt,6,key,a->metadataProfile,&plain[6]) || strcmp(plain[6],"local") ||
                cmeRegDecode(stmt,8,key,a->metadataProfile,&plain[8]) || strcmp(plain[8],a->storagePath)) goto done;
        }
        cmeRegPlainFree(plain);
    }
    if (step==SQLITE_DONE && target==1) result=0;
done:
    cmeRegPlainFree(plain); sqlite3_finalize(stmt); return(result);
}
#endif

static int cmeRegCheck(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *approval,
    const cmeContextColumnRegistrationInputs *in)
{
    unsigned char digest[32];
    int result=1;
    if (!in || !in->source || in->sourceLength<100 || in->sourceLength>cmeContextColumnMaxBytes || !in->candidate ||
        in->candidateLength<4096 || in->candidateLength>cmeContextColumnMaxImageBytes || !in->registrationKey ||
        !*in->registrationKey || strnlen(in->registrationKey,257)>256 ||
        cmeContextColumnRegistrationDigest(transform,approval,digest) || CRYPTO_memcmp(digest,transform->registrationEvidenceDigest,32)) return(1);
    result=cmeContextCopyTargetCheck(manager,target); if (result) return(result);
#if defined(HAVE_SQLITE3_DESERIALIZE)
    {
        sqlite3 *db[2]={NULL,NULL}; unsigned char *copy[2]={NULL,NULL};
        unsigned int budgets[2]={20000,20000};
        char *source[18]={0},*destination[18]={0};
        static const int preserved[]={1,2,4,8,9,11,12,13,14};
        size_t i;
        result=1;
        if (cmeRegHash(in->source,in->sourceLength,transform->sourceDigest) || cmeRegHash(in->candidate,in->candidateLength,transform->candidateDigest) ||
            cmeRegOpen(in->sourceResources,in->sourceResourcesLength,approval->sourceResourcesDigest,&db[0],&copy[0],&budgets[0]) ||
            cmeRegOpen(in->candidateResources,in->candidateResourcesLength,approval->candidateResourcesDigest,&db[1],&copy[1],&budgets[1]) ||
            cmeRegClone(db[0],db[1],approval->destinationRow) || cmeRegRow(db[0],0,approval,in,source) ||
            cmeRegRow(db[1],1,approval,in,destination) || cmeRegAssociations(db[0],0,approval,in->registrationKey) ||
            cmeRegAssociations(db[1],1,approval,in->registrationKey)) goto done;
        for (i=0;i<sizeof(preserved)/sizeof(*preserved);i++) if (strcmp(source[preserved[i]],destination[preserved[i]])) goto done;
        result=cmeContextCopyTargetCheck(manager,target);
done:
        cmeRegPlainFree(source); cmeRegPlainFree(destination);
        for (i=0;i<2;i++)
        {
            sqlite3_close(db[i]);
            if (copy[i]) OPENSSL_cleanse(copy[i],i ? in->candidateResourcesLength : in->sourceResourcesLength);
            sqlite3_free(copy[i]);
        }
    }
#else
    result=3;
#endif
    return(result);
}

int cmeContextColumnRegisteredPrepare(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *approval,
    const cmeContextColumnRegistrationInputs *inputs, cmeContextV2Buffer *receipt, unsigned char receiptDigest[32])
{
    int result;
    if (receipt) memset(receipt,0,sizeof(*receipt));
    if (receiptDigest) memset(receiptDigest,0,32);
    if (!receipt || !receiptDigest) return(1);
    result=cmeRegCheck(manager,target,transform,approval,inputs); if (result) return(result);
    result=cmeContextColumnTransformPrepare(manager,target,transform,inputs->source,inputs->sourceLength,inputs->sourceKey,
        inputs->candidate,inputs->candidateLength,inputs->password,inputs->passwordLength,receipt,receiptDigest);
    if (!result) result=cmeContextCopyTargetCheck(manager,target);
    if (result) { cmeContextV2BufferFree(receipt); memset(receiptDigest,0,32); }
    return(result);
}

int cmeContextColumnRegisteredVerify(cmeContextManager *manager, const cmeContextCopyTarget *target,
    const cmeContextColumnTransformApproval *transform, const cmeContextColumnRegistrationApproval *approval,
    const cmeContextColumnRegistrationInputs *inputs,
    const unsigned char *receipt, size_t receiptLength, const unsigned char receiptDigest[32])
{
    int result=cmeRegCheck(manager,target,transform,approval,inputs);
    if (!result) result=cmeContextColumnTransformVerify(manager,target,transform,inputs->source,inputs->sourceLength,inputs->sourceKey,
        inputs->candidate,inputs->candidateLength,inputs->password,inputs->passwordLength,receipt,receiptLength,receiptDigest);
    if (!result) result=cmeContextCopyTargetCheck(manager,target);
    return(result);
}

int cmeContextColumnExportDigest(const cmeContextColumnTransformApproval *transform,
    const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnExportArtifact *companions, size_t count, unsigned char digest[32])
{
    static const unsigned char domain[]="CDSE-HKX-COLUMN-EXPORT-v1";
    EVP_MD_CTX *hash=NULL;
    unsigned char pin[32],number[8];
    unsigned int written=0;
    size_t i,j,n,total=0,roles=0,logs=0;
    int result=1;
    if (digest) memset(digest,0,32);
    if (!digest || !companions || count<3 || count>cmeContextRegistryMaxEntries+2 ||
        cmeContextColumnRegistrationDigest(transform,registration,pin)) goto done;
    hash=EVP_MD_CTX_new();
    if (!hash || !EVP_DigestInit_ex(hash,EVP_sha256(),NULL) || !EVP_DigestUpdate(hash,domain,sizeof(domain)) ||
        !EVP_DigestUpdate(hash,pin,32)) goto done;
    for (j=0;j<8;j++) number[j]=(unsigned char)((uint64_t)count>>(8*(7-j)));
    if (!EVP_DigestUpdate(hash,number,8)) goto done;
    for (i=0;i<count;i++)
    {
        const cmeContextColumnExportArtifact *entry=&companions[i];
        int internal=entry->name && (!strcmp(entry->name,"RolesDB") || !strcmp(entry->name,"LogsDB"));
        if (!entry->name || (!internal && cmeRegText(entry->name,255,1)) ||
            (i && strcmp(companions[i-1].name,entry->name)>=0) ||
            entry->length>cmeContextColumnMaxImageBytes || (internal && entry->length>cmeContextColumnMaxBytes) ||
            entry->length>cmeContextColumnExportMaxBytes-total) goto done;
        total+=entry->length; n=strlen(entry->name);
        roles+=!strcmp(entry->name,"RolesDB"); logs+=!strcmp(entry->name,"LogsDB");
        number[0]=(unsigned char)(n>>8); number[1]=(unsigned char)n;
        if (!EVP_DigestUpdate(hash,number,2) || !EVP_DigestUpdate(hash,entry->name,n)) goto done;
        for (j=0;j<8;j++) number[j]=(unsigned char)((uint64_t)entry->length>>(8*(7-j)));
        if (!EVP_DigestUpdate(hash,number,8) || !EVP_DigestUpdate(hash,entry->digest,32)) goto done;
    }
    if (roles!=1 || logs!=1 || !EVP_DigestFinal_ex(hash,pin,&written) || written!=32) goto done;
    memcpy(digest,pin,32); result=0;
done:
    EVP_MD_CTX_free(hash); OPENSSL_cleanse(pin,sizeof(pin)); return(result);
}

#if defined(HAVE_SQLITE3_DESERIALIZE)
static const cmeContextColumnExportArtifact *cmeExportFind(const cmeContextColumnExportInputs *export, const char *name)
{
    size_t left=0,right=export->count;
    while (left<right)
    {
        size_t middle=left+(right-left)/2;
        int order=strcmp(export->companions[middle].name,name);
        if (!order) return(&export->companions[middle]);
        if (order<0) left=middle+1; else right=middle;
    }
    return(NULL);
}

static int cmeExportInternal(const cmeContextColumnExportArtifact *entry)
{
    sqlite3 *db=NULL;
    sqlite3_stmt *stmt=NULL;
    unsigned char *copy=NULL;
    unsigned int budget=20000;
    int result=1;
    if (entry->length<100 || !entry->source || !(copy=sqlite3_malloc64(entry->length))) goto done;
    memcpy(copy,entry->source,entry->length);
    if (memcmp(copy,"SQLite format 3",16) || copy[18]!=1 || copy[19]!=1 || sqlite3_open(":memory:",&db)!=SQLITE_OK ||
        sqlite3_deserialize(db,"main",copy,entry->length,entry->length,SQLITE_DESERIALIZE_READONLY)!=SQLITE_OK) goto done;
    sqlite3_limit(db,SQLITE_LIMIT_LENGTH,cmeContextColumnMaxCellBytes); sqlite3_limit(db,SQLITE_LIMIT_COLUMN,32);
    sqlite3_limit(db,SQLITE_LIMIT_SQL_LENGTH,65536); sqlite3_progress_handler(db,1000,cmeRegBudget,&budget);
    if (sqlite3_db_config(db,SQLITE_DBCONFIG_DEFENSIVE,1,NULL)!=SQLITE_OK ||
        sqlite3_exec(db,"PRAGMA trusted_schema=OFF; PRAGMA query_only=ON",NULL,NULL,NULL)!=SQLITE_OK ||
        cmeCheckInternalDBSchema(db,entry->name,0) || sqlite3_prepare_v2(db,
        "SELECT 1 FROM sqlite_master WHERE type NOT IN ('table','index') UNION ALL "
        "SELECT 1 FROM pragma_table_list WHERE schema='main' AND type IN ('virtual','shadow')",-1,&stmt,NULL)!=SQLITE_OK ||
        sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    sqlite3_finalize(stmt); stmt=NULL;
    if (sqlite3_prepare_v2(db,"PRAGMA integrity_check",-1,&stmt,NULL)!=SQLITE_OK || sqlite3_step(stmt)!=SQLITE_ROW ||
        !sqlite3_column_text(stmt,0) || strcmp((const char *)sqlite3_column_text(stmt,0),"ok") || sqlite3_step(stmt)!=SQLITE_DONE) goto done;
    result=0;
done:
    sqlite3_finalize(stmt); sqlite3_close(db);
    if (copy) OPENSSL_cleanse(copy,entry->length);
    sqlite3_free(copy); return(result);
}
#endif

int cmeContextColumnExportCheck(const cmeContextColumnTransformApproval *transform,
    const cmeContextColumnRegistrationApproval *registration,
    const cmeContextColumnRegistrationInputs *inputs, const cmeContextColumnExportInputs *export)
{
    unsigned char digest[32];
    size_t i;
    if (!inputs || !inputs->registrationKey || !*inputs->registrationKey || strnlen(inputs->registrationKey,257)>256 ||
        !export || cmeContextColumnExportDigest(transform,registration,export->companions,export->count,digest) ||
        CRYPTO_memcmp(digest,export->approvalDigest,32)) return(1);
#if defined(HAVE_SQLITE3_DESERIALIZE)
    {
        sqlite3 *db=NULL,*inventory=NULL;
        sqlite3_stmt *read=NULL,*insert=NULL,*check=NULL;
        unsigned char *copy=NULL;
        char *plain[18]={0},*salt=NULL,*tag=NULL;
        unsigned int budget=20000,inventoryBudget=20000;
        size_t rows=0;
        int result=1,step,written=0;
        for (i=0;i<export->count;i++)
        {
            const cmeContextColumnExportArtifact *entry=&export->companions[i];
            if (!entry->source || !entry->candidate || cmeRegHash(entry->source,entry->length,entry->digest) ||
                cmeRegHash(entry->candidate,entry->length,entry->digest) ||
                ((!strcmp(entry->name,"RolesDB") || !strcmp(entry->name,"LogsDB")) && cmeExportInternal(entry))) goto done;
        }
        if (cmeRegOpen(inputs->sourceResources,inputs->sourceResourcesLength,registration->sourceResourcesDigest,&db,&copy,&budget) ||
            sqlite3_open(":memory:",&inventory)!=SQLITE_OK) goto done;
        sqlite3_limit(inventory,SQLITE_LIMIT_LENGTH,cmeContextColumnMaxCellBytes);
        sqlite3_progress_handler(inventory,1000,cmeRegBudget,&inventoryBudget);
        if (sqlite3_exec(inventory,"PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;"
            "CREATE TABLE parts(name TEXT PRIMARY KEY,doc TEXT,storage TEXT,org TEXT,col TEXT,UNIQUE(doc,storage,org,col));"
            "CREATE TABLE stores(storage TEXT,org TEXT,PRIMARY KEY(storage,org));",NULL,NULL,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(db,"SELECT * FROM documents ORDER BY id",-1,&read,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(inventory,"INSERT INTO parts VALUES(?1,?2,?3,?4,?5)",-1,&insert,NULL)!=SQLITE_OK) goto done;
        while ((step=sqlite3_step(read))==SQLITE_ROW)
        {
            static const int fields[]={5,7,8,9,14};
            const cmeContextColumnExportArtifact *entry;
            const char *saltText;
            if (++rows>cmeContextRegistryMaxEntries) goto done;
            for (i=1;i<15;i++) if (i!=3 && cmeRegDecode(read,(int)i,inputs->registrationKey,registration->metadataProfile,&plain[i])) goto done;
            if (cmeRegText(plain[5],255,1) || strcmp(plain[6],"file.csv") || strcmp(plain[11],"1") || strcmp(plain[12],"1") ||
                cmeRegLookup(read,inputs->registrationKey,plain) || !(entry=cmeExportFind(export,plain[5]))) goto done;
            for (i=1;i<5;i++) if (cmeRegText(plain[fields[i]],128,0)) goto done;
            saltText=cmeRegSQLText(read,3);
            if (!saltText || !(salt=strdup(saltText)) || cmeHMACByteString(entry->source,(unsigned char **)&tag,entry->length,
                &written,"sha256",&salt,inputs->registrationKey) || written!=64 || strlen(plain[10])!=64 ||
                CRYPTO_memcmp(tag,plain[10],64)) goto done;
            free(salt); salt=NULL; free(tag); tag=NULL;
            for (i=0;i<5;i++) if (sqlite3_bind_text(insert,(int)i+1,plain[fields[i]],-1,SQLITE_TRANSIENT)!=SQLITE_OK) goto done;
            if (sqlite3_step(insert)!=SQLITE_DONE || sqlite3_reset(insert)!=SQLITE_OK) goto done;
            cmeRegPlainFree(plain);
        }
        if (step!=SQLITE_DONE || rows+2!=export->count) goto done;
        sqlite3_finalize(read); read=NULL; sqlite3_finalize(insert); insert=NULL;
        if (sqlite3_prepare_v2(db,"SELECT * FROM storage ORDER BY id",-1,&read,NULL)!=SQLITE_OK ||
            sqlite3_prepare_v2(inventory,"INSERT INTO stores VALUES(?1,?2)",-1,&insert,NULL)!=SQLITE_OK) goto done;
        rows=0;
        while ((step=sqlite3_step(read))==SQLITE_ROW)
        {
            static const int fields[]={6,7,8,11};
            if (++rows>cmeContextRegistryMaxEntries) goto done;
            for (i=0;i<4;i++) if (cmeRegDecode(read,fields[i],inputs->registrationKey,registration->metadataProfile,&plain[fields[i]])) goto done;
            if (strcmp(plain[6],"local") || strcmp(plain[8],registration->storagePath) ||
                cmeRegText(plain[7],128,0) || cmeRegText(plain[11],128,0) ||
                sqlite3_bind_text(insert,1,plain[7],-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
                sqlite3_bind_text(insert,2,plain[11],-1,SQLITE_TRANSIENT)!=SQLITE_OK ||
                sqlite3_step(insert)!=SQLITE_DONE || sqlite3_reset(insert)!=SQLITE_OK) goto done;
            cmeRegPlainFree(plain);
        }
        if (step!=SQLITE_DONE || sqlite3_prepare_v2(inventory,
            "SELECT 1 FROM parts p WHERE NOT EXISTS (SELECT 1 FROM stores s WHERE s.storage=p.storage AND s.org=p.org)",
            -1,&check,NULL)!=SQLITE_OK || sqlite3_step(check)!=SQLITE_DONE) goto done;
        result=0;
    done:
        free(salt); free(tag); cmeRegPlainFree(plain);
        sqlite3_finalize(read); sqlite3_finalize(insert); sqlite3_finalize(check);
        sqlite3_close(inventory); sqlite3_close(db);
        if (copy) OPENSSL_cleanse(copy,inputs->sourceResourcesLength);
        sqlite3_free(copy); return(result);
    }
#else
    (void)i; return(3);
#endif
}
