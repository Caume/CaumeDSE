/* Synthetic keys/data only; invoked by the command contract tests. */
#include "common.h"

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
    if (!result && !strcmp(argv[2],"shuffle"))
        result=cmeSQLRows(db,"INSERT INTO meta VALUES (3,'fixtureUser','fixtureOrg','','shuffle','aes-256-gcm');",NULL,NULL);
    if (!result) result=cmeMemSecureDBProtect(db,"fixture-source-key");
    if (sqlite3_close(db)!=SQLITE_OK) result=1;
    return(result ? 1 : 0);
}
