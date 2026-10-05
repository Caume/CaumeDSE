/* Synthetic keys/data only; invoked by the command contract tests. */
#include "common.h"

static const char *cmeFixtureKey(void)
{
    return(getenv("CDSE_FIXTURE_LEGACY_RAW") ? "Password" : "fixture-source-key");
}

static int cmeFixtureCancel(void *context)
{
    (void)context;
    return(1);
}

static void cmeFixtureInterrupt(sqlite3_context *context, int argc, sqlite3_value **argv)
{
    (void)argc; (void)argv;
    sqlite3_progress_handler(sqlite3_context_db_handle(context),1,cmeFixtureCancel,NULL);
    sqlite3_result_int(context,0);
}

static int cmeFixtureRollback(sqlite3 *db, const char *mode)
{
    char **before=NULL,**after=NULL;
    int rows=0,cols=0,afterRows=0,afterCols=0,i,result=1;
    cmeReprotectDBReport report;
    const char *trigger=!strcmp(mode,"rollback-data") ?
        "CREATE TRIGGER fail BEFORE UPDATE OF value ON data WHEN old.id=2 BEGIN SELECT RAISE(ABORT,'test'); END;" :
        !strcmp(mode,"rollback-tags") ?
        "CREATE TRIGGER fail BEFORE UPDATE OF MAC ON data WHEN old.id=2 BEGIN SELECT RAISE(ABORT,'test'); END;" :
        !strcmp(mode,"interrupt") ?
        "CREATE TRIGGER fail BEFORE UPDATE ON meta WHEN old.id=2 BEGIN SELECT interrupt_migration(); END;" :
        "CREATE TRIGGER fail BEFORE UPDATE ON meta WHEN old.id=2 BEGIN SELECT RAISE(ABORT,'test'); END;";
    sqlite3_create_function(db,"interrupt_migration",0,SQLITE_UTF8,NULL,cmeFixtureInterrupt,NULL,NULL);
    if (cmeSQLRows(db,trigger,NULL,NULL) ||
        cmeMemTable(db,"SELECT * FROM data UNION ALL SELECT id,userId,orgId,salt,attribute,attributeData,'','','','','' FROM meta;",&before,&rows,&cols)) goto done;
    i=cmeReprotectMemSecureDB(db,"fixture-source-key","fixture-target-key","aes-256-cbc",&report,0);
    sqlite3_progress_handler(db,0,NULL,NULL);
    if (!i) goto done;
    if (!sqlite3_get_autocommit(db) ||
        cmeMemTable(db,"SELECT * FROM data UNION ALL SELECT id,userId,orgId,salt,attribute,attributeData,'','','','','' FROM meta;",&after,&afterRows,&afterCols) ||
        rows!=afterRows || cols!=afterCols) goto done;
    for (i=0;i<(rows+1)*cols;i++) if (strcmp(before[i],after[i])) goto done;
    result=cmeVerifyMemSecureDBIntegrity(db,"fixture-source-key","aes-256-gcm",0);
done:
    if (before) cmeMemTableFinal(before);
    if (after) cmeMemTableFinal(after);
    return(result);
}

static int cmeFixtureBundle(const char *root)
{
    const char *names[]={"ResourcesDB","RolesDB","LogsDB"};
    int kind,result=1,step,column,written;
    sqlite3 *db=NULL;
    sqlite3_stmt *tables=NULL,*read=NULL,*update=NULL;
    char path[4096],*query=NULL,*sql=NULL;
    for (kind=0;kind<3;kind++)
    {
        snprintf(path,sizeof(path),"%s/%s",root,names[kind]);
        if (sqlite3_open(path,&db)!=SQLITE_OK ||
            sqlite3_prepare_v2(db,"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_meta';",-1,&tables,NULL)!=SQLITE_OK) goto done;
        while ((step=sqlite3_step(tables))==SQLITE_ROW)
        {
            const char *table=(const char *)sqlite3_column_text(tables,0);
            query=sqlite3_mprintf("SELECT * FROM \"%w\" ORDER BY id;",table);
            if (sqlite3_prepare_v2(db,query,-1,&read,NULL)!=SQLITE_OK) goto done;
            sqlite3_free(query); query=NULL;
            cmeStrConstrAppend(&sql,"UPDATE \"%s\" SET salt=?",table);
            for (column=1;column<sqlite3_column_count(read);column++) if (column!=3 && !strstr(sqlite3_column_name(read,column),"Lookup"))
                cmeStrConstrAppend(&sql,",\"%s\"=?",sqlite3_column_name(read,column));
            cmeStrConstrAppend(&sql," WHERE id=?;");
            if (sqlite3_prepare_v2(db,sql,-1,&update,NULL)!=SQLITE_OK) goto done;
            cmeFree(sql);
            while ((step=sqlite3_step(read))==SQLITE_ROW)
            {
                char *salt=NULL,*partMAC=NULL;
                int bind=2;
                cmeGetRndSaltAnySize(&salt,16);
                if (!salt) goto done;
                if (kind==0 && !strcmp(table,"documents"))
                {
                    char *bytes=NULL,*protected=NULL; int length;
                    snprintf(path,sizeof(path),"%s/%s",root,sqlite3_column_text(read,5));
                    if (cmeLoadStrFromFile(&bytes,path,&length)) { free(salt); goto done; }
                    int raw=strcmp((const char *)sqlite3_column_text(read,6),"file.csv")!=0;
                    if (raw && getenv("CDSE_FIXTURE_LEGACY_RAW")) { free(salt); salt=strdup("00000000000000000000000000000000"); }
                    if (raw && !getenv("CDSE_FIXTURE_LEGACY_RAW"))
                    {
                        if (cmeProtectByteString(bytes,&protected,cmeDefaultEncAlg,&salt,cmeFixtureKey(),&written,length) ||
                            cmeWriteStrToFile(protected,path,written)) { free(bytes); free(salt); cmeFree(protected); goto done; }
                        free(bytes); bytes=protected; protected=NULL; length=written;
                    }
                    if (cmeHMACByteString((const unsigned char *)bytes,(unsigned char **)&partMAC,length,&written,cmeDefaultMACAlg,&salt,cmeFixtureKey()))
                    { free(bytes); free(salt); goto done; }
                    free(bytes);
                }
                sqlite3_bind_text(update,1,salt,-1,SQLITE_TRANSIENT);
                for (column=1;column<sqlite3_column_count(read);column++) if (column!=3 && !strstr(sqlite3_column_name(read,column),"Lookup"))
                {
                    const char *value=(const char *)sqlite3_column_text(read,column);
                    char *cipher=NULL,*tag=NULL,*combined=NULL;
                    if (partMAC && !strcmp(sqlite3_column_name(read,column),"partMAC")) value=partMAC;
                    int bad=0;
                    if (value)
                    {
                        bad=cmeProtectDBSaltedValue(value,&cipher,cmeDefaultEncAlg,&salt,cmeFixtureKey(),&written);
                        if (!bad) bad=cmeHMACByteString((const unsigned char *)cipher,(unsigned char **)&tag,strlen(cipher),&written,cmeDefaultMACAlg,&salt,cmeFixtureKey());
                        if (!bad) { cmeStrConstrAppend(&combined,"%s%s",tag,cipher); sqlite3_bind_text(update,bind++,combined,-1,SQLITE_TRANSIENT); }
                    }
                    else sqlite3_bind_null(update,bind++);
                    cmeFree(cipher); cmeFree(tag); cmeFree(combined);
                    if (bad) { free(salt); cmeFree(partMAC); goto done; }
                }
                free(salt); cmeFree(partMAC);
                sqlite3_bind_int64(update,bind,sqlite3_column_int64(read,0));
                if (sqlite3_step(update)!=SQLITE_DONE) goto done;
                sqlite3_reset(update); sqlite3_clear_bindings(update);
            }
            if (step!=SQLITE_DONE) goto done;
            sqlite3_finalize(read); read=NULL; sqlite3_finalize(update); update=NULL;
        }
        if (step!=SQLITE_DONE || cmeSetInternalDBSchemaVersion(db,names[kind]) ||
            cmeSQLRows(db,"PRAGMA journal_mode=WAL; PRAGMA wal_checkpoint(TRUNCATE);",NULL,NULL)) goto done;
        sqlite3_finalize(tables); tables=NULL; sqlite3_close(db); db=NULL;
    }
    result=0;
done:
    sqlite3_finalize(tables); sqlite3_finalize(read); sqlite3_finalize(update); sqlite3_close(db);
    sqlite3_free(query); cmeFree(sql);
    return(result);
}

static int cmeFixtureReadBundle(const char *root)
{
    sqlite3 *resources=NULL,*column=NULL;
    char path[4096],storage[4096],*temporary=NULL,*bytes=NULL;
    char **rows=NULL;
    int length,numRows=0,numCols=0,result=1;
    const char expected[]="raw\0binary\xff" "fixture\n";
    snprintf(path,sizeof(path),"%s/ResourcesDB",root);
    snprintf(storage,sizeof(storage),"%s/",root);
    if (sqlite3_open_v2(path,&resources,SQLITE_OPEN_READONLY,NULL)!=SQLITE_OK ||
        cmeSecureFileToTmpRAWFileInDir(&temporary,resources,"rawpart","file.raw",storage,
            "fixtureOrg","fixtureStorage","fixture-target-key",root) ||
        cmeLoadStrFromFile(&bytes,temporary,&length) || length!=sizeof(expected)-1 || memcmp(bytes,expected,length)) goto done;
    snprintf(path,sizeof(path),"%s/column",root);
    if (sqlite3_open(":memory:",&column)!=SQLITE_OK || cmeMemDBLoadOrSave(column,path,0) ||
        cmeMemSecureDBUnprotect(column,"fixture-target-key") ||
        cmeMemTable(column,"SELECT value FROM data ORDER BY id;",&rows,&numRows,&numCols) ||
        numRows!=2 || numCols!=1 || strcmp(rows[1],"fixture-alpha") || strcmp(rows[2],"fixture-beta")) goto done;
    result=0;
done:
    if (temporary) unlink(temporary);
    cmeFree(temporary); cmeFree(bytes);
    if (rows) cmeMemTableFinal(rows);
    sqlite3_close(resources); sqlite3_close(column);
    return(result);
}

int main(int argc, char **argv)
{
    sqlite3 *db=NULL;
    int result;
    if (argc!=3) return(2);
    cmeInitDefaultEncAlg();
    if (!strcmp(argv[2],"nla1-provider"))
    {
        cmeCryptoProfile profile;
        if (cmeGetCryptoProfile(&profile,"herradura-hske-nla1-aead-256")) return(1);
        printf("%d\n",profile.implemented && profile.allowedAsDefault);
        return(0);
    }
    if (!strcmp(argv[2],"legacy-provider")) { printf("%d\n",CDSE_HERRADURAKEX_LEGACY_DUPLEX); return(0); }
    if (!strcmp(argv[2],"verify-bundle")) return(cmeFixtureReadBundle(argv[1]));
    if (!strcmp(argv[2],"bundle")) return(cmeFixtureBundle(argv[1]));
    if (sqlite3_open(argv[1],&db)!=SQLITE_OK) return(1);
    result=cmeSQLRows(db,
        "CREATE TABLE data (id INTEGER PRIMARY KEY,userId TEXT,orgId TEXT,salt TEXT,value TEXT,rowOrder TEXT,MAC TEXT,sign TEXT,MACProtected TEXT,signProtected TEXT,otphDKey TEXT);"
        "CREATE TABLE meta (id INTEGER PRIMARY KEY,userId TEXT,orgId TEXT,salt TEXT,attribute TEXT,attributeData TEXT);"
        "INSERT INTO data VALUES (1,'fixtureUser','fixtureOrg','','fixture-alpha','1','','','','','');"
        "INSERT INTO data VALUES (2,'fixtureUser','fixtureOrg','','fixture-beta','2','','','','','');"
        "INSERT INTO meta VALUES (1,'fixtureUser','fixtureOrg','','protect','aes-256-gcm');"
        "INSERT INTO meta VALUES (2,'fixtureUser','fixtureOrg','','name','fixture-column');",NULL,NULL);
    if (!result && !strcmp(argv[2],"mac"))
        result=cmeSQLRows(db,"INSERT INTO meta VALUES (3,'fixtureUser','fixtureOrg','','MAC','sha256');",NULL,NULL);
    if (!result && (!strcmp(argv[2],"integrity") || !strcmp(argv[2],"empty") || !strncmp(argv[2],"rollback-",9) || !strcmp(argv[2],"interrupt")))
        result=cmeSQLRows(db,
            "INSERT INTO meta VALUES (3,'fixtureUser','fixtureOrg','','MAC','sha256');"
            "INSERT INTO meta VALUES (4,'fixtureUser','fixtureOrg','','sign','sha256');"
            "INSERT INTO meta VALUES (5,'fixtureUser','fixtureOrg','','MACProtected','sha256');"
            "INSERT INTO meta VALUES (6,'fixtureUser','fixtureOrg','','signProtected','sha256');",NULL,NULL);
    if (!result && !strcmp(argv[2],"shuffle"))
        result=cmeSQLRows(db,
            "INSERT INTO meta VALUES (3,'fixtureUser','fixtureOrg','','shuffle','aes-256-gcm');"
            "UPDATE meta SET id=4 WHERE id=1; UPDATE meta SET id=1 WHERE id=3; UPDATE meta SET id=3 WHERE id=4;",NULL,NULL);
    if (!result && !strcmp(argv[2],"empty")) result=cmeSQLRows(db,"UPDATE data SET value='' WHERE id=2;",NULL,NULL);
    if (!result) result=cmeMemSecureDBProtect(db,cmeFixtureKey());
    if (!result && (!strncmp(argv[2],"rollback-",9) || !strcmp(argv[2],"interrupt")))
        result=cmeFixtureRollback(db,argv[2]);
    if (sqlite3_close(db)!=SQLITE_OK) result=1;
    return(result ? 1 : 0);
}
