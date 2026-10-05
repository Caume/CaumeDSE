/* Synthetic keys/data only; invoked by the command contract tests. */
#include "common.h"

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

int main(int argc, char **argv)
{
    sqlite3 *db=NULL;
    int result;
    if (argc!=3) return(2);
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
    if (!result && (!strcmp(argv[2],"integrity") || !strncmp(argv[2],"rollback-",9) || !strcmp(argv[2],"interrupt")))
        result=cmeSQLRows(db,
            "INSERT INTO meta VALUES (3,'fixtureUser','fixtureOrg','','MAC','sha256');"
            "INSERT INTO meta VALUES (4,'fixtureUser','fixtureOrg','','sign','sha256');"
            "INSERT INTO meta VALUES (5,'fixtureUser','fixtureOrg','','MACProtected','sha256');"
            "INSERT INTO meta VALUES (6,'fixtureUser','fixtureOrg','','signProtected','sha256');",NULL,NULL);
    if (!result && !strcmp(argv[2],"shuffle"))
        result=cmeSQLRows(db,"INSERT INTO meta VALUES (3,'fixtureUser','fixtureOrg','','shuffle','aes-256-gcm');",NULL,NULL);
    if (!result) result=cmeMemSecureDBProtect(db,"fixture-source-key");
    if (!result && (!strncmp(argv[2],"rollback-",9) || !strcmp(argv[2],"interrupt")))
        result=cmeFixtureRollback(db,argv[2]);
    if (sqlite3_close(db)!=SQLITE_OK) result=1;
    return(result ? 1 : 0);
}
