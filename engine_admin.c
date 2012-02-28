/***
Copyright 2010-2012 by Omar Alejandro Herrera Reyna

    Caume Data Security Engine, also known as CaumeDSE is released under the
    GNU General Public License by the Copyright holder, with the additional
    exemption that compiling, linking, and/or using OpenSSL is allowed.

    LICENSE

    This file is part of Caume Data Security Engine, also called CaumeDSE.

    CaumeDSE is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CaumeDSE is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with CaumeDSE.  If not, see <http://www.gnu.org/licenses/>.

    INCLUDED SOFTWARE

    This product includes software developed by the OpenSSL Project
    for use in the OpenSSL Toolkit (http://www.openssl.org/).
    This product includes cryptographic software written by
    Eric Young (eay@cryptsoft.com).
    This product includes software written by
    Tim Hudson (tjh@cryptsoft.com).

    This product includes software from the SQLite library that is in
    the public domain (http://www.sqlite.org/copyright.html).

    This product includes software from the GNU Libmicrohttpd project, Copyright
    © 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
    2008, 2009, 2010 , 2011, 2012 Free Software Foundation, Inc.

    This product includes software from Perl5, which is Copyright (C) 1993-2005,
    by Larry Wall and others.

***/
#include "common.h"

int cmeSetupEngineAdminDBs ()
{   //IDD ver. 1.0.19 15nov2011
    int result;
    int createAdmin=0;
    char readChar;
    const char dbFName1 []="ResourcesDB";
    const char dbFName2 []="RolesDB";
    const char dbFName3 []="LogsDB";
    char *currentDBName=NULL;
    char *sqlQuery=NULL;
    char *rndAdminOrgPwd=NULL;
    sqlite3 *currentDB=NULL;
    #define cmeSetupEngineAdminDBsFree() \
        do { \
            cmeFree(rndAdminOrgPwd); \
            cmeFree(currentDBName); \
            cmeFree(sqlQuery); \
            if (currentDB) \
            { \
                cmeDBClose(currentDB); \
                currentDB=NULL; \
            } \
        } while (0) //Local free() macro

    //Prepare: ResourcesDB
    cmeStrConstrAppend(&currentDBName,"%s%s",cmeDefaultFilePath,dbFName1); //Create full path
    result=cmeDBOpen(currentDBName,&currentDB);
    if (!result)
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeSetupEngineAdminDBs(), DB file %s already exists;"
                " skipping.\n",currentDBName);
#endif
        cmeSetupEngineAdminDBsFree();
    }
    else
    {
        result=cmeDBCreateOpen (currentDBName,&currentDB);       //Create Database
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeDBCreateOpen() failed "
                    "with Engine Admin. DB file: %s!\n",currentDBName);
#endif
            cmeSetupEngineAdminDBsFree();
            return(1);
        }
        result=cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; "
                                    "CREATE TABLE documents (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT, resourceInfo TEXT,"
                                    " columnFile TEXT, type TEXT, documentId TEXT, storageId TEXT, orgResourceId TEXT,"
                                    " partHash	TEXT, totalParts TEXT, partId TEXT, lastModified TEXT, columnId TEXT); "
                                    "CREATE TABLE users (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT, resourceInfo TEXT,"
                                    " certificate TEXT, publicKey TEXT, userResourceId TEXT, basicAuthPwdHash TEXT,"
                                    " oauthConsumerKey TEXT, oauthConsumerSecret TEXT, orgResourceId TEXT); "
                                    "CREATE TABLE organizations (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT, resourceInfo TEXT,"
                                    " certificate TEXT, publicKey TEXT, orgResourceId TEXT); "
                                    "CREATE TABLE storage (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT, resourceInfo TEXT,"
                                    " location TEXT, type TEXT, storageId TEXT, accessPath TEXT,"
                                    " accessUser TEXT, accessPassword TEXT, orgResourceId TEXT); "
                                    "CREATE TABLE filterWhitelist (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE filterBlacklist (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "COMMIT;");
        if (result) //If error then exit.
        {
            cmeSetupEngineAdminDBsFree();
            return(2);
        }
        if (cmeSQLRows(currentDB,sqlQuery,NULL,NULL)) //Create a tables.
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeSQLRows() Error, can't "
                    "create tables in DB file: %s!\n",currentDBName);
#endif
            cmeSetupEngineAdminDBsFree();
            return(3);
        }
        createAdmin=1; //We set flag to create default admin userId, userId's roles, orgId and storageId.
        cmeSetupEngineAdminDBsFree();
    }
    // Prepare: RolesDB
    cmeStrConstrAppend(&currentDBName,"%s%s",cmeDefaultFilePath,dbFName2);  //Create full path.
    result=cmeDBOpen(currentDBName,&currentDB);
    if (!result)
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeSetupEngineAdminDBs(), DB file %s already exists;"
                " skipping.\n",currentDBName);
#endif
        cmeSetupEngineAdminDBsFree();
    }
    else
    {
        result=cmeDBCreateOpen (currentDBName,&currentDB);       //Create Database.
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeDBCreateOpen() failed "
                    "with Engine Admin. DB file: %s!\n",currentDBName);
#endif
            cmeSetupEngineAdminDBsFree();
            return(4);
        }
        result=cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; "
                                    "CREATE TABLE documents (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE users (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE roleTables (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE parserScripts (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE outputDocuments (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE content (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE contentRows (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE contentColumns (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE dbNames (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE dbTables (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE tableRows (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE tableColumns (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE organizations (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE storage (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE documentTypes (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE engineCommands (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE transactions (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE meta (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE filterWhitelist (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "CREATE TABLE filterBlacklist (id INTEGER PRIMARY KEY,"
                                    " userId TEXT, orgId TEXT, salt TEXT,"
                                    " _get TEXT, _post TEXT, _put TEXT, _delete TEXT,"
                                    " _head TEXT, _options TEXT, userResourceId TEXT, orgResourceId TEXT);"
                                    "COMMIT;");
        if (result) //If error then exit.
        {
            cmeSetupEngineAdminDBsFree();
            return(5);
        }
        if (cmeSQLRows(currentDB,sqlQuery,NULL,NULL)) //Create a tables.
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeSQLRows() Error, can't "
                    "create tables in DB file: %s!\n",currentDBName);
#endif
            cmeSetupEngineAdminDBsFree();
            return(6);
        }
        createAdmin=1; //We set flag to create default admin userId, userId's roles, orgId and storageId.
        cmeSetupEngineAdminDBsFree();
    }
    // Prepare: LogsDB
    cmeStrConstrAppend(&currentDBName,"%s%s",cmeDefaultFilePath,dbFName3);  //Create full path.
    result=cmeDBOpen(currentDBName,&currentDB);
    if (!result)
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeSetupEngineAdminDBs(), DB file %s already exists;"
                " skipping.\n",currentDBName);
#endif
        cmeSetupEngineAdminDBsFree();
    }
    else
    {
        result=cmeDBCreateOpen (currentDBName,&currentDB);       //Create Database.
        if (result) //Error
        {
    #ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeDBCreateOpen() failed "
                    "with Engine Admin. DB file: %s!\n",currentDBName);
    #endif
            cmeSetupEngineAdminDBsFree();
            return(7);
        }
        result=cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; "
                            "CREATE TABLE transactions (id INTEGER PRIMARY KEY,"
                            " userId TEXT, orgId TEXT, salt TEXT,"
                            " timestamp TEXT, uri TEXT, headers	TEXT, startTimestamp TEXT, stopTimestamp TEXT,"
                            " dataMBIn TEXT, dataMBOut TEXT, orgResourceId TEXT);"
                            "CREATE TABLE meta (id INTEGER PRIMARY KEY,"
                            " userId TEXT, orgId TEXT, salt TEXT,"
                            " initTimestamp TEXT, memoryMB TEXT, operatingSystem TEXT, localStorageMB TEXT,"
                            " cloudStorageMB TEXT, bandwidthMbIn TEXT, bandwidthMbOut TEXT, ipAddress TEXT);"
                            "COMMIT;");
        if (result) //If error then exit.
        {
            cmeSetupEngineAdminDBsFree();
            return(8);
        }
        if (cmeSQLRows(currentDB,sqlQuery,NULL,NULL)) //Create a tables.
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeSQLRows() Error, can't "
                    "create tables in DB file: %s!\n",currentDBName);
#endif
            cmeSetupEngineAdminDBsFree();
            return(9);
        }
        cmeSetupEngineAdminDBsFree();
    }
    if (createAdmin) //ResourcesDB and/or RolesDB did not existe and was(were) created; we need a new default admin's user, roles, organization and storage.
    {
        cmeGetRndSaltAnySize(&rndAdminOrgPwd,16); //Generate a random key of 16 bytes as HexStr.
        result=cmeWebServiceInitAdminIdSetup(rndAdminOrgPwd); //Create User.
        if (result) //Error.
        {
    #ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeWebServiceInitAdminSetup() Error, can't "
                    "create user for default admin in new DB setup: Error: %d!\n",result);
    #endif
            cmeSetupEngineAdminDBsFree();
            return(10);
        }
        result=cmeWebServiceInitAdminSetup(rndAdminOrgPwd);  //Create user's roles.
        if (result) //Error.
        {
    #ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeWebServiceInitAdminSetup() Error, can't "
                    "create default roles for default admin in new DB setup: Error: %d!\n",result);
    #endif
            cmeSetupEngineAdminDBsFree();
            return(10);
        }
        result=cmeWebServiceInitOrgSetup(rndAdminOrgPwd);  //Create organization.
        if (result) //Error.
        {
    #ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeWebServiceInitOrgSetup() Error, can't "
                    "create default organization fin new DB setup: Error: %d!\n",result);
    #endif
            cmeSetupEngineAdminDBsFree();
            return(11);
        }
        result=cmeWebServiceInitStorageSetup(rndAdminOrgPwd);  //Create storage.
        if (result) //Error.
        {
    #ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeWebServiceInitStorageSetup() Error, can't "
                    "create default storage fin new DB setup: Error: %d!\n",result);
    #endif
            cmeSetupEngineAdminDBsFree();
            return(12);
        }
        printf("*** WARNING - READ CAREFULLY ***\nThe engine didn't find all required system databases. This is normal if this is "
               "the first time that the engine is executed. The engine has generated the corresponding system databases and "
               "created a new administration account with full privileges, along with a default organization and a default storage "
               "resource (which defaults to the same location of the engine's databases).\n""This is the ONLY time that the "
               "randomly generated key for the default Admin organization will be displayed (the engine does not store any organization "
               "keys). Make sure that you take note of it and store it in a safe place.\nOnce you are done please type 'Y' plus [Enter] "
               "to continue.\n");
        printf("Default Admin userId      : %s \n"
               "Default Admin organization: %s \n"
               "Default Admin storageId   : %s \n"
               "Default Admin storagePath : %s \n"
               "Default Admin orgKey      : %s \n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,cmeAdminDefaultStorageId,cmeAdminDefaultStoragePath,
               rndAdminOrgPwd);
        do
        {
            readChar=getchar();
        } while (readChar != 'Y');
        putchar (readChar);
        do
        {
            readChar=getchar();
        } while (readChar != '\n');
        // TODO (OHR#2#): Implement, if possible, screen deletion of the administrator key (e.g. by printing control characters). Alternatively consider printing sensitive info. with a special library that allows this (curses?).
        memset(rndAdminOrgPwd,0,strlen(rndAdminOrgPwd)); //Overwrite default admin. key in memory.
    }
    cmeSetupEngineAdminDBsFree();
    return(0);
}

int cmeRegisterSecureDBorFile (const char **SQLDBfNames, const int numSQLDBfNames, const char **SQLDBfSalts, const char **SQLDBpartHash,
                               const int numSQLDBparts, const char *orgKey, const char *userId, const char *orgId, const char *resourceInfo,
                               const char *type, const char *documentId, const char *storageId, const char *orgResourceId)
{   //IDD ver. 1.0.19 15nov2011
    int cont,cont2,result;
    int written=0;
    int numRows=0;
    int numColumns=0;
    time_t timeStamp=0;
    const int numDocumentDBCols=cmeIDDResourcesDBDocumentsNumCols-2;          //Number of columns to handle in the documents DB table, except ID and salt;
    const char dbFName[]="ResourcesDB";
    sqlite3 *currentDB=NULL;
    sqlite3 *saveDB=NULL;
    char *currentDBName=NULL;
    char *sqlQuery=NULL;
    char *partId=NULL;              //Will contain the text equivalent of the part number of each column file
    char *totalParts=NULL;          //Will contain the text equivalent total parts per column of each column file
    char *lastModified=NULL;        //Will contain the text equivalent of current date (timestamp)
    char *columnId=NULL;            //Will contain the text equivalent of the column number, so that each part can be reassembled within the corresponding column.
    char **sqlTable=NULL;
    unsigned char **currentSaltProtectedData=NULL;
    unsigned char *hexStrSalt=NULL;
    #define cmeRegisterSecureDBFree() \
        do { \
            cmeFree(currentDBName); \
            cmeFree(sqlQuery); \
            cmeFree(partId); \
            cmeFree(totalParts); \
            cmeFree(lastModified); \
            cmeFree(columnId); \
            cmeFree(hexStrSalt); \
            if (currentSaltProtectedData) \
            { \
                for (cont2=0;cont2<numDocumentDBCols;cont2++) \
                { \
                    cmeFree(currentSaltProtectedData[cont2]); \
                } \
                cmeFree(currentSaltProtectedData); \
            } \
            if (sqlTable) \
            { \
                cmeMemTableFinal(sqlTable); \
            } \
            if (currentDB) \
            { \
                cmeDBClose(currentDB); \
                currentDB=NULL; \
            } \
            if (saveDB) \
            { \
                cmeDBClose(saveDB); \
                saveDB=NULL; \
            } \
        } while (0) //Local free() macro

    currentSaltProtectedData=(unsigned char **)malloc((sizeof(unsigned char *))*numDocumentDBCols);
    for (cont=0;cont<numDocumentDBCols;cont++) //Initialize pointers.
    {
        currentSaltProtectedData[cont]=NULL;
    }
    cmeStrConstrAppend(&currentDBName,"%s%s",cmeDefaultFilePath,dbFName);
    result=cmeDBOpen(currentDBName,&currentDB);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeDBOpen() failed "
                "with Engine Admin. DB file: %s!\n",currentDBName);
#endif
        cmeRegisterSecureDBFree();
        return(1);
    }
    else  //Register rows
    {
        cmeStrConstrAppend(&totalParts,"%d",numSQLDBparts); //Set text variable with total number of parts (i.e. column fragments)
        timeStamp=time(NULL);
        cmeStrConstrAppend(&lastModified,"%ld",timeStamp);  //Set text of current timestamp (unix time_t format).
        for (cont=0; cont<numSQLDBfNames; cont++) //process column values and insert them into ResourcesDB
        {
            cmeFree(hexStrSalt);
            if (SQLDBfSalts) //Salts were provided (e.g. for raw files)
            {
                cmeStrConstrAppend((char **)&hexStrSalt,"%s",SQLDBfSalts[cont]); //Use corresponding salt.
            }
            cmeFree(columnId);
            cmeStrConstrAppend(&columnId,"%d",(cont%(numSQLDBfNames/numSQLDBparts))+1);
            cmeProtectDBSaltedValue(userId,(char **)&currentSaltProtectedData[0],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //userId.
            cmeProtectDBSaltedValue(orgId,(char **)&currentSaltProtectedData[1],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //orgId.
            cmeProtectDBSaltedValue(resourceInfo,(char **)&currentSaltProtectedData[2],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //resourceInfo.
            cmeProtectDBSaltedValue(type,(char **)&currentSaltProtectedData[3],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //type.
            cmeProtectDBSaltedValue(documentId,(char **)&currentSaltProtectedData[4],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //documentId.
            cmeProtectDBSaltedValue(storageId,(char **)&currentSaltProtectedData[5],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //storageId.
            cmeProtectDBSaltedValue(orgResourceId,(char **)&currentSaltProtectedData[6],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //orgResourceId.
            cmeProtectDBSaltedValue(lastModified,(char **)&currentSaltProtectedData[7],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //lastModified.
            cmeProtectDBSaltedValue(columnId,(char **)&currentSaltProtectedData[8],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //columnId.
            cmeProtectDBSaltedValue(totalParts,(char **)&currentSaltProtectedData[9],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //totalParts.
            cmeFree(partId);
            cmeStrConstrAppend(&partId,"%d",(cont/(numSQLDBfNames/numSQLDBparts))+1);
            cmeProtectDBSaltedValue(SQLDBfNames[cont],(char **)&currentSaltProtectedData[10],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //columnFile.
            cmeProtectDBSaltedValue(SQLDBpartHash[cont],(char **)&currentSaltProtectedData[11],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //partHash.

            cmeProtectDBSaltedValue(partId,(char **)&currentSaltProtectedData[12],cmeDefaultEncAlg,(char **)&hexStrSalt,orgKey,&written); //partId.
            // Insert row in database.
            cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; "
                                "INSERT INTO documents (id, userId, orgId, salt, resourceInfo,"
                                " columnFile, type, documentId, storageId, orgResourceId, partHash,"
                                " totalParts, partId, lastModified, columnId)"
                                "VALUES (NULL,'%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s');"
                                "COMMIT;",currentSaltProtectedData[0],currentSaltProtectedData[1],hexStrSalt,
                                currentSaltProtectedData[2],currentSaltProtectedData[10],currentSaltProtectedData[3],
                                currentSaltProtectedData[4],currentSaltProtectedData[5],currentSaltProtectedData[6],
                                currentSaltProtectedData[11],currentSaltProtectedData[9],currentSaltProtectedData[12],
                                currentSaltProtectedData[7],currentSaltProtectedData[8]);
            if (cmeSQLRows(currentDB,sqlQuery,NULL,NULL)) //insert row.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeRegisterSecureDB(), cmeSQLRows() Error, can't "
                        "insert row in DB file %s!\n",currentDBName);
#endif
                cmeRegisterSecureDBFree();
                return(2);
            }
            cmeFree(sqlQuery);
        //    }
        }
    }
    result=cmeDBCreateOpen(":memory:",&saveDB);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSetupEngineAdminDBs(), cmeDBCreateOpen() failed "
                "with Engine Admin. DB file: %s!\n",currentDBName);
#endif
        cmeRegisterSecureDBFree();
        return(3);
    }
    result=cmeMemTable(currentDB,"PRAGMA empty_result_callbacks = ON; " //TODO (OHR#4#): Make sure we include this at least once to receive empty databases w/ column names.
                       "SELECT userId, orgId, salt, resourceInfo, columnFile, type, documentId, storageId,"
                       " orgResourceId, partHash, totalParts, partId, lastModified, columnId FROM documents;",
                       &sqlTable,&numRows,&numColumns); //We need to skip id, as it will be inserted by cmeMemTableToMemDB()
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeRegisterSecureDB(), cmeMemTable() Error, can't "
                "'select * from documents' in resourceDB:%s!\n",currentDBName);
#endif
        cmeRegisterSecureDBFree();
        return(4);
    }
    else //Call Shuffling algorithm; ignore first row (headers); first column (id) has already been ignored in SELECT FROM documents.
    {
        cmeMemTableShuffle(sqlTable,numRows,numColumns,1,0);
    }
    result=cmeMemTableToMemDB(saveDB,(const char **)sqlTable,numRows,numColumns,"documents");
    cmeMemTableFinal(sqlTable);
    result=cmeMemTable(currentDB,"SELECT userId, orgId, salt, resourceInfo, certificate, publicKey,"
                       "userResourceId, basicAuthPwdHash, oauthConsumerKey, oauthConsumerSecret, orgResourceId FROM users;",
                       &sqlTable,&numRows,&numColumns); //We need to skip id, as it will be inserted by cmeMemTableToMemDB()
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeRegisterSecureDB(), cmeMemTable() Error, can't "
                "'select * from users' in resourceDB:%s!\n",currentDBName);
#endif
        cmeRegisterSecureDBFree();
        return(5);
    }
    result=cmeMemTableToMemDB(saveDB,(const char **)sqlTable,numRows,numColumns,"users");
    cmeMemTableFinal(sqlTable);
    result=cmeMemTable(currentDB,"SELECT userId, orgId, salt, resourceInfo, certificate,"
                       "publicKey, orgResourceId FROM organizations;",
                       &sqlTable,&numRows,&numColumns); //We need to skip id, as it will be inserted by cmeMemTableToMemDB()
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeRegisterSecureDB(), cmeMemTable() Error, can't "
                "'select * from organizations' in resourceDB:%s!\n",currentDBName);
#endif
        cmeRegisterSecureDBFree();
        return(6);
    }
    result=cmeMemTableToMemDB(saveDB,(const char **)sqlTable,numRows,numColumns,"organizations");
    cmeMemTableFinal(sqlTable);
    result=cmeMemTable(currentDB,"SELECT userId, orgId, salt, resourceInfo, location, type, storageId, "
                       "accessPath, accessUser, accessPassword, orgResourceId FROM storage;",
                       &sqlTable,&numRows,&numColumns); //We need to skip id, as it will be inserted by cmeMemTableToMemDB()
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeRegisterSecureDB(), cmeMemTable() Error, can't "
                "'select * from storage' in resourceDB:%s!\n",currentDBName);
#endif
        cmeRegisterSecureDBFree();
        return(7);
    }
    result=cmeMemTableToMemDB(saveDB,(const char **)sqlTable,numRows,numColumns,"storage");
    cmeMemDBLoadOrSave(saveDB,currentDBName,1);
    cmeRegisterSecureDBFree();
    return(0);
}

int cmeWebServiceSetup (unsigned short port, int useSSL, const char *sslKeyFile, const char *sslCertFile, const char *caCertFile)
{
    int readFileLen;
    struct MHD_Daemon *webServiceDaemon=NULL;
    char *key_pem=NULL;
    char *cert_pem=NULL;
    char *ca_pem=NULL;
    #define cmeWebServiceSetupFree() \
        do { \
            cmeFree(key_pem); \
            cmeFree(cert_pem); \
            cmeFree(ca_pem); \
            if (webServiceDaemon) \
            { \
                MHD_stop_daemon (webServiceDaemon); \
            } \
        } while (0) //Local free() macro.

    if (useSSL) //HTTPS
    {
        // TODO (ANY#2#): Add basic error handling for loading cert. files (e.g. if file is not found, function will return an int > 0.
        cmeLoadStrFromFile(&key_pem,sslKeyFile,&readFileLen);
        cmeLoadStrFromFile(&cert_pem,sslCertFile,&readFileLen);
        cmeLoadStrFromFile(&ca_pem,caCertFile,&readFileLen);
        if ((key_pem == NULL)||(cert_pem == NULL)||(ca_pem == NULL)) //Error
        {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceSetup(), Error, can't "
                "read server key, server cert or ca cert files: %s %s %s\n",sslKeyFile,sslCertFile,caCertFile);
#endif
            cmeWebServiceSetupFree();
            return (1);
        }
        webServiceDaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_SSL,
                                            port,NULL,NULL,
                                            &cmeWebServiceAnswerConnection,NULL,
                                            MHD_OPTION_NOTIFY_COMPLETED,&cmeWebServiceRequestCompleted,NULL,
                                            MHD_OPTION_HTTPS_MEM_KEY,key_pem,
                                            MHD_OPTION_HTTPS_MEM_CERT,cert_pem,
                                            MHD_OPTION_HTTPS_MEM_TRUST,ca_pem,    //root CA certificate = engine certificate; CA certifies organization, and organization certifies user.
                                            MHD_OPTION_END);

        if (NULL == webServiceDaemon) //Error
        {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceSetup(), Error, can't "
                "start HTTPS server on port %d. Cert file: %s. Key file: %s.\n",port,cert_pem,key_pem);
#endif
            cmeWebServiceSetupFree();
            return (2);
        }
    }
    else  //HTTP
    {
        // We would use webServiceDaemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,  for multiple threads. But right now we use a single thread-
        webServiceDaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
                                            port, NULL, NULL,
                                            &cmeWebServiceAnswerConnection,NULL,
                                            MHD_OPTION_NOTIFY_COMPLETED,&cmeWebServiceRequestCompleted,NULL,
                                            MHD_OPTION_END);
        if (NULL == webServiceDaemon)
        {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceSetup(), Error, can't "
                "start HTTP server on port %d!\n",port);
#endif
            cmeWebServiceSetupFree();
            return (3);
        }
    }
    getchar ();                     //TODO (OHR#2#): Clear temporal "wait for enter"; create web service Exception Handler (stop) function.
    cmeWebServiceSetupFree();
    return(0);
}

int cmeWebServiceInitAdminSetup (const char *orgKey)
{   //IDD version 1.0.20
    int cont,result;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    const int numTables=20;                                             //Constant: number of tables in DB
    const int numColumns=cmeIDDRolesDBAnyTableNumCols-2;                  //Constant: number of columns in table, ignoring id & salt
    const char *tableNames[20]={"documents","users","roleTables","parserScripts","outputDocuments","content",
                                "contentRows","contentColumns","dbNames","dbTables","tableRows","tableColumns",
                                "organizations","storage","documentTypes","engineCommands","transactions","meta",
                                "filterWhitelist","filterBlacklist"}; //Note: also    const char *tableNames[]=...
    const char *columnNamesToMatch[2]={"userResourceId","orgResourceId"};
    const char *columnNames[10]={"_get","_post","_put","_delete","_head","_options","userResourceId","orgResourceId","userId","orgId"};
    char *columnValues[10]={"1","1","1","1","1","1",NULL,NULL,NULL,NULL};
    char *columnValuesFWL[10]={".*",".*",".*",".*",".*",".*",NULL,NULL,NULL,NULL};
    char *columnValuesFBL[10]={"","","","","","",NULL,NULL,NULL,NULL};
    char *columnValuesToMatch[2]={NULL,NULL};
    sqlite3 *pDB=NULL;
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    #define cmeWebServiceInitAdminSetupFree() \
        do { \
            cmeFree(dbFilePath); \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
            if (resultRegisterCols) \
            { \
               for (cont=0; cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            for (cont=6;cont<10;cont++) \
            { \
                cmeFree(columnValues[cont]); \
                cmeFree(columnValuesFWL[cont]); \
                cmeFree(columnValuesFBL[cont]); \
            } \
            for (cont=0;cont<2;cont++) \
            { \
                cmeFree(columnValuesToMatch[cont]); \
            } \
        } while (0) //Local free() macro.

    cmeStrConstrAppend(&(columnValues[6]),"%s",cmeAdminDefaultUserId);
    cmeStrConstrAppend(&(columnValues[7]),"%s",cmeAdminDefaultOrgId);
    cmeStrConstrAppend(&(columnValues[8]),"%s",cmeAdminDefaultUserId);
    cmeStrConstrAppend(&(columnValues[9]),"%s",cmeAdminDefaultOrgId);
    cmeStrConstrAppend(&(columnValuesFWL[6]),"%s",cmeAdminDefaultUserId);  //Filter Whitelist values
    cmeStrConstrAppend(&(columnValuesFWL[7]),"%s",cmeAdminDefaultOrgId);
    cmeStrConstrAppend(&(columnValuesFWL[8]),"%s",cmeAdminDefaultUserId);
    cmeStrConstrAppend(&(columnValuesFWL[9]),"%s",cmeAdminDefaultOrgId);
    cmeStrConstrAppend(&(columnValuesFBL[6]),"%s",cmeAdminDefaultUserId);  //Filter Blacklist values
    cmeStrConstrAppend(&(columnValuesFBL[7]),"%s",cmeAdminDefaultOrgId);
    cmeStrConstrAppend(&(columnValuesFBL[8]),"%s",cmeAdminDefaultUserId);
    cmeStrConstrAppend(&(columnValuesFBL[9]),"%s",cmeAdminDefaultOrgId);
    cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",cmeAdminDefaultUserId);
    cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",cmeAdminDefaultOrgId);
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultRolesDBName);
    result=cmeDBOpen(dbFilePath,&pDB);
    if (result) //Error
    {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceInitAdminSetup(), can't open RolesDB!"
                    " File: '%s'!\n",dbFilePath);
#endif
                return(1);
    }
    for (cont=0;cont<numTables;cont++) //No error -> process all tableNames in RolesDB
    {
        result=cmeGetUnprotectDBRegisters(pDB,tableNames[cont],columnNamesToMatch,(const char **)columnValuesToMatch,
                                          2,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey); //Check if role doesn't exist.
        if(numResultRegisters>0) //Role is already in DB -> Warning
        {
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceInitAdminSetup(), Warning, role already exists!"
                    " User: '%s', Organization: '%s', TableName: '%s'!\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,tableNames[cont]);
#endif
        }
        else
        { //Add role to DB
            if (strcmp(tableNames[cont],"filterWhitelist")==0) //Process filterWhitelist
            {
                result=cmePostProtectDBRegister(pDB,tableNames[cont],columnNames,(const char **)columnValuesFWL,
                                                numColumns,orgKey);
            }
            else if (strcmp(tableNames[cont],"filterBlacklist")==0) //Process filterWhitelist
            {
                result=cmePostProtectDBRegister(pDB,tableNames[cont],columnNames,(const char **)columnValuesFBL,
                                                numColumns,orgKey);
            }
            else //Process all other tables
            {
                result=cmePostProtectDBRegister(pDB,tableNames[cont],columnNames,(const char **)columnValues,
                                                numColumns,orgKey);
            }
            if (result) //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceInitAdminSetup(), Error, Can't create new role!"
                        " User: '%s', Organization: '%s', TableName: '%s'.\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,tableNames[cont]);
#endif
                cmeWebServiceInitAdminSetupFree();
                return(2);
            }
            else //Ok
            {
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceInitAdminSetup(), POST of new role successful."
                        " User: '%s', Organization: '%s', TableName: '%s'.\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,tableNames[cont]);
#endif
            }
        }
    }
    cmeWebServiceInitAdminSetupFree();
    return(0);
}

int cmeWebServiceCheckPermissions (const char *method, const char *url, const char **urlElements, const int numUrlElements,
                                   char **responseText, int *responseCode, const char *userId, const char *orgId, const char *orgKey)
{// IDD ver. 1.0.20
    int result,cont,cont2;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    int numColumnValues=0;
    const int numValidRoleTables=20;     // # of roleTable names to be parsed.
    char *ptrStrChar=NULL;
    char *lcaseMethod=NULL;
    sqlite3 *pDB=NULL;
    char *dbFilePath=NULL;
    char **columnNames=NULL;
    char **columnValues=NULL;
    char *currentTableName=NULL;
    char **resultRegisterCols=NULL;
    const char *validRoleTableNames[20]={"documents","users","roleTables","parserScripts","outputDocuments","content",
                                         "contentRows","contentColumns","dbNames","dbTables","tableRows","tableColumns",
                                         "organizations","storage","documentTypes","engineCommands","transactions","meta",
                                         "filterWhitelist","filterBlacklist"};
    #define cmeWebServiceCheckPermissionsFree() \
        do { \
            cmeFree(dbFilePath); \
            cmeFree(currentTableName); \
            cmeFree(lcaseMethod); \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
            if (numColumnValues) \
            { \
                for (cont=0;cont<numColumnValues;cont++) \
                { \
                    cmeFree(columnNames[cont]); \
                    cmeFree(columnValues[cont]); \
                } \
                cmeFree(columnNames); \
                cmeFree(columnValues); \
            } \
            if (numResultRegisterCols) \
            { \
                for (cont=0;cont<(numResultRegisters+1)*numResultRegisterCols;cont++) \
                { \
                    cmeFree(resultRegisterCols[cont]); \
                } \
                cmeFree(resultRegisterCols); \
            } \
        } while (0) //Local free() macro.

    *responseCode=0;
    //Check that all resource classes listed in the URL are valid:
    for (cont=0; cont<numUrlElements; cont++) //Process all URL elements starting from level 0 (organizations, dbNames...). Note that Web site is not included in URL.
    {
        cmeFree(currentTableName);
        if (!(cont&1)) //Even #; means that the urlElement at this position is a classname that can be looked used as a roleTableName.
        {
            cmeStrConstrAppend(&currentTableName,"%s",urlElements[cont]);
            result=1;
            for(cont2=0;cont2<numValidRoleTables;cont2++) //Verify that the roleTableName is valid
            {
                if (!strcmp(validRoleTableNames[cont2],currentTableName)) //Match!
                {
                    result=0;
                    break;
                }
            }
            if (result) //Error; tableName not found.
            {
                cmeStrConstrAppend(responseText,"<b>404 ERROR Resource class %s not found!</b><br>"
                                   "METHOD: '%s' URL: '%s'."
                                   " Latest IDD version: <code>%s</code>",currentTableName,method,url,
                                   cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceCheckPermissions(), Resource class '%s' "
                        "not found!. Method: '%s', URL: '%s'!\n",currentTableName,method,url);
#endif
                cmeWebServiceCheckPermissionsFree();
                *responseCode=404;
                return(1);
            }
        }
    }
    cmeFree(currentTableName);
    if (!((numUrlElements-1)&1)) //Even #; means that the urlElement at this position is a classname that can be looked up as a roleTableName.
    {
        cmeStrConstrAppend(&currentTableName,"%s",urlElements[numUrlElements-1]);
    }
    else //Odd #; means that we should use the previous position to use the corresponding classname as a roleTableName.
    {
        cmeStrConstrAppend(&currentTableName,"%s",urlElements[numUrlElements-2]);
    }
    cmeStrConstrAppend(&lcaseMethod,"%s",method);
    ptrStrChar=lcaseMethod;
    while (*ptrStrChar) //Convert to lowercase the method string to get an appropriate column.
    {
        *ptrStrChar=tolower(*ptrStrChar);
        ptrStrChar++;
    }
    ptrStrChar=NULL;
    //Reserve memory:
    columnNames=(char **)malloc(sizeof(char *)*3);
    columnValues=(char **)malloc(sizeof(char *)*3);
    for (cont=0;cont<3;cont++) //reset pointers. Needed by cmeStrConstrAppend().
    {
        columnNames[cont]=NULL;
        columnValues[cont]=NULL;
    }
    cmeStrConstrAppend(&(columnNames[0]),"_%s",lcaseMethod);
    cmeStrConstrAppend(&(columnValues[0]),"1");
    cmeStrConstrAppend(&(columnNames[1]),"userResourceId");
    cmeStrConstrAppend(&(columnValues[1]),"%s",userId);
    cmeStrConstrAppend(&(columnNames[2]),"orgResourceId");
    cmeStrConstrAppend(&(columnValues[2]),"%s",orgId);
    numColumnValues=3;
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultRolesDBName);
    result=cmeDBOpen(dbFilePath,&pDB);
    if (!result) //if OK
    {   //Verify that the user (userId+orgId) has permissions for the requested action (roleTable + method) with the current orgKey:
        result=cmeGetUnprotectDBRegisters(pDB,currentTableName,(const char **)columnNames,(const char **)columnValues,
                                          numColumnValues,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
        if (!result) //OK
        {
            if (numResultRegisters) // Found >0
            {
                // TODO (OHR#6#): Process White and Black regex filter lists in corresponding tables within ResourcesDB
                *responseCode=200;
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceCheckPermissions(), Permissions validated successfully!");
#endif
                cmeWebServiceCheckPermissionsFree();
                return(0);
            }
            else //Found 0
            {
                cmeStrConstrAppend(responseText,"<b>401 UNAUTHORIZED user doesn't have permission to perform request!</b><br>"
                                   "METHOD: '%s' URL: '%s'."
                                   " Latest IDD version: <code>%s</code>",method,url,
                                   cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceCheckPermissions(), Unauthorized; no roles records"
                    "found in roleTable: '%s' , Method: '%s', URL: '%s'!\n",currentTableName,method,url);
#endif
                *responseCode=401;
                cmeWebServiceCheckPermissionsFree();
                return(2);
            }
        }
        else //Error
        {

            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceCheckPermissions(), Error in cmeGetUnprotectDBRegisters() '%d'."
                    " Method: '%s', URL: '%s', can't process table: %s !\n",result,method,url,currentTableName);
#endif
            cmeWebServiceCheckPermissionsFree();
            *responseCode=500;
            return(3);
        }
    }
    else //DB Error
    {
        cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                           "Internal server error number '%d'."
                           "METHOD: '%s' URL: '%s'."
                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceCheckPermissions(), Error, internal server error '%d'."
                " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
        cmeWebServiceCheckPermissionsFree();
        *responseCode=500;
        return(4);
    }
}

int cmeWebServiceInitOrgSetup (const char *orgKey)
{   //IDD version 1.0.20
    int cont,result;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    const int numColumns=cmeIDDResourcesDBOrganizationsNumCols-2;       //Constant: number of columns in table, ignoring id & salt
    const char *tableName="organizations";
    const char *columnNamesToMatch[1]={"orgResourceId"};
    const char *columnNames[6]={"resourceInfo","certificate","publicKey","orgResourceId","userId","orgId"};
    char *columnValues[6]={NULL,NULL,NULL,NULL,NULL,NULL};
    char *columnValuesToMatch[1]={NULL};
    sqlite3 *pDB=NULL;
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    #define cmeWebServiceInitOrgSetupFree() \
        do { \
            cmeFree(dbFilePath); \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
            if (resultRegisterCols) \
            { \
               for (cont=0; cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            for (cont=0;cont<6;cont++) \
            { \
                cmeFree(columnValues[cont]); \
            } \
            for (cont=0;cont<1;cont++) \
            { \
                cmeFree(columnValuesToMatch[cont]); \
            } \
        } while (0) //Local free() macro.

    cmeStrConstrAppend(&(columnValues[0]),"Default DSE organization");
    cmeStrConstrAppend(&(columnValues[1]),"TBD");
    cmeStrConstrAppend(&(columnValues[2]),"TBD");
    cmeStrConstrAppend(&(columnValues[3]),"%s",cmeAdminDefaultOrgId);              //orgResourceId
    cmeStrConstrAppend(&(columnValues[4]),"%s",cmeAdminDefaultUserId);
    cmeStrConstrAppend(&(columnValues[5]),"%s",cmeAdminDefaultOrgId);              //orgId
    cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",cmeAdminDefaultOrgId);
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    result=cmeDBOpen(dbFilePath,&pDB);
    if (result) //Error
    {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceInitOrgSetup(), can't open ResourcesDB!"
                    " File: '%s'!\n",dbFilePath);
#endif
                return(1);
    }
    result=cmeGetUnprotectDBRegisters(pDB,tableName,columnNamesToMatch,(const char **)columnValuesToMatch,1,
                                      &resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey); //Check if organization doesn't exist.
    if(numResultRegisters>0) //organization (with same orgKey) is already in DB -> Error
    {
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceInitOrgSetup(), Error, organization already exists!"
                " User: '%s', Organization: '%s', TableName: '%s'!\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,tableName);
#endif
    }
    else
    { //Add organization to DB
        result=cmePostProtectDBRegister(pDB,tableName,columnNames,(const char **)columnValues,numColumns,orgKey);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceInitOrgSetup(), Error, Can't create new organization!"
                    " User: '%s', Organization: '%s', TableName: '%s'.\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,tableName);
#endif
            cmeWebServiceInitOrgSetupFree();
            return(2);
        }
        else //Ok
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceInitOrgSetup(), POST of new organization successful."
                    " User: '%s', Organization: '%s', TableName: '%s'.\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,tableName);
#endif
        }
    }
    cmeWebServiceInitOrgSetupFree();
    return(0);
}

int cmeWebServiceInitStorageSetup (const char *orgKey)
{   //IDD version 1.0.19 25Nov2011
    int cont,result;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    const int numColumns=cmeIDDResourcesDBStorageNumCols-2;       //Constant: number of columns in table, ignoring id & salt
    const char *tableName="storage";
    const char *columnNamesToMatch[2]={"storageId","orgResourceId"};
    const char *columnNames[10]={"resourceInfo","location","type","storageId","accessPath","accessUser","accessPassword","orgResourceId","userId","orgId"};
    char *columnValues[10]={NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
    char *columnValuesToMatch[2]={NULL,NULL};
    sqlite3 *pDB=NULL;
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    #define cmeWebServiceInitStorageSetupFree() \
        do { \
            cmeFree(dbFilePath); \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
            if (resultRegisterCols) \
            { \
               for (cont=0; cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            for (cont=0;cont<10;cont++) \
            { \
                cmeFree(columnValues[cont]); \
            } \
            for (cont=0;cont<2;cont++) \
            { \
                cmeFree(columnValuesToMatch[cont]); \
            } \
        } while (0) //Local free() macro.

    cmeStrConstrAppend(&(columnValues[0]),"Default DSE storage");
    cmeStrConstrAppend(&(columnValues[1]),"localhost");
    cmeStrConstrAppend(&(columnValues[2]),"local");
    cmeStrConstrAppend(&(columnValues[3]),"%s",cmeAdminDefaultStorageId);          //storageId
    cmeStrConstrAppend(&(columnValues[4]),"%s",cmeAdminDefaultStoragePath);
    cmeStrConstrAppend(&(columnValues[5]),"N/A");
    cmeStrConstrAppend(&(columnValues[6]),"N/A");
    cmeStrConstrAppend(&(columnValues[7]),"%s",cmeAdminDefaultOrgId);              //orgResourceId
    cmeStrConstrAppend(&(columnValues[8]),"%s",cmeAdminDefaultUserId);
    cmeStrConstrAppend(&(columnValues[9]),"%s",cmeAdminDefaultOrgId);              //orgId
    cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",cmeAdminDefaultStorageId);
    cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",cmeAdminDefaultOrgId);
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    result=cmeDBOpen(dbFilePath,&pDB);
    if (result) //Error
    {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceInitStorageSetup(), can't open ResourcesDB!"
                    " File: '%s'!\n",dbFilePath);
#endif
                return(1);
    }
    result=cmeGetUnprotectDBRegisters(pDB,tableName,columnNamesToMatch,(const char **)columnValuesToMatch,2,
                                      &resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey); //Check if storage doesn't exist.
    if(numResultRegisters>0) //organization (with same orgKey) is already in DB -> Error
    {
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceInitStorageSetup(), Error, storage already exists!"
                " User: '%s', Organization: '%s', Storage: '%s', TableName: '%s'!\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,cmeAdminDefaultStorageId,tableName);
#endif
    }
    else
    { //Add organization to DB
        result=cmePostProtectDBRegister(pDB,tableName,columnNames,(const char **)columnValues,numColumns,orgKey);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceInitStorageSetup(), Error, Can't create new storage!"
                    " User: '%s', Organization: '%s', Storage: '%s', TableName: '%s'!\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,cmeAdminDefaultStorageId,tableName);
#endif
            cmeWebServiceInitStorageSetupFree();
            return(2);
        }
        else //Ok
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceInitStorageSetup(), POST of new storage successful."
                    " User: '%s', Organization: '%s', Storage: '%s', TableName: '%s'!\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,cmeAdminDefaultStorageId,tableName);
#endif
        }
    }
    cmeWebServiceInitStorageSetupFree();
    return(0);
}


int cmeWebServiceInitAdminIdSetup (const char *orgKey)
{   //IDD version 1.0.19 25Nov2011
    int cont,result;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    const int numColumns=cmeIDDResourcesDBUsersNumCols-2;       //Constant: number of columns in table, ignoring id & salt
    const char *tableName="users";
    const char *columnNamesToMatch[2]={"userResourceId","orgResourceId"};
    const char *columnNames[10]={"resourceInfo","certificate","publicKey","userResourceId","basicAuthPwdHash","oauthConsumerKey","oauthConsumerSecret","orgResourceId","userId","orgId"};
    char *columnValues[10]={NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
    char *columnValuesToMatch[2]={NULL,NULL};
    sqlite3 *pDB=NULL;
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    #define cmeWebServiceInitAdminIdSetupFree() \
        do { \
            cmeFree(dbFilePath); \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
            if (resultRegisterCols) \
            { \
               for (cont=0; cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            for (cont=0;cont<10;cont++) \
            { \
                cmeFree(columnValues[cont]); \
            } \
            for (cont=0;cont<2;cont++) \
            { \
                cmeFree(columnValuesToMatch[cont]); \
            } \
        } while (0) //Local free() macro.

    cmeStrConstrAppend(&(columnValues[0]),"Default DSE storage");
    cmeStrConstrAppend(&(columnValues[1]),"TBD");
    cmeStrConstrAppend(&(columnValues[2]),"TBD");
    cmeStrConstrAppend(&(columnValues[3]),"%s",cmeAdminDefaultUserId);          //storageId
    cmeStrConstrAppend(&(columnValues[4]),"TBD");
    cmeStrConstrAppend(&(columnValues[5]),"TBD");
    cmeStrConstrAppend(&(columnValues[6]),"TBD");
    cmeStrConstrAppend(&(columnValues[7]),"%s",cmeAdminDefaultOrgId);              //orgResourceId
    cmeStrConstrAppend(&(columnValues[8]),"%s",cmeAdminDefaultUserId);
    cmeStrConstrAppend(&(columnValues[9]),"%s",cmeAdminDefaultOrgId);              //orgId
    cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",cmeAdminDefaultUserId);
    cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",cmeAdminDefaultOrgId);
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    result=cmeDBOpen(dbFilePath,&pDB);
    if (result) //Error
    {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceInitAdminIdSetup(), can't open ResourcesDB!"
                    " File: '%s'!\n",dbFilePath);
#endif
                return(1);
    }
    result=cmeGetUnprotectDBRegisters(pDB,tableName,columnNamesToMatch,(const char **)columnValuesToMatch,2,
                                      &resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey); //Check if storage doesn't exist.
    if(numResultRegisters>0) //organization (with same orgKey) is already in DB -> Error
    {
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceInitAdminIdSetup(), Error, user already exists!"
                " User: '%s', Organization: '%s', TableName: '%s'!\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,tableName);
#endif
    }
    else
    { //Add organization to DB
        result=cmePostProtectDBRegister(pDB,tableName,columnNames,(const char **)columnValues,numColumns,orgKey);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceInitAdminIdSetup(), Error, Can't create new user!"
                    " User: '%s', Organization: '%s', TableName: '%s'!\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,tableName);
#endif
            cmeWebServiceInitAdminIdSetupFree();
            return(2);
        }
        else //Ok
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceInitAdminIdSetup(), POST of new user successful."
                    " User: '%s', Organization: '%s', TableName: '%s'!\n",cmeAdminDefaultUserId,cmeAdminDefaultOrgId,tableName);
#endif
        }
    }
    cmeWebServiceInitAdminIdSetupFree();
    return(0);
}

void cmeWebServiceStart ()
{
    printf("--- Running Web server HTTPS, port %d\n",cmeDefaultWebServiceSSLPort);
    while (1)
    {
        cmeWebServiceSetup(cmeDefaultWebServiceSSLPort,1,cmeDefaultHTTPSKeyFile,cmeDefaultHTTPSCertFile,cmeDefaultCACertFile);
    }
}
