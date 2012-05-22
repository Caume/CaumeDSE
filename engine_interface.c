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

int cmeSecureDBToMemDB (sqlite3 **resultDB, sqlite3 *pResourcesDB,const char *documentId,
                        const char *orgKey, const char *storagePath)
{   //IDD v.1.0.21
    int cont,cont2,result,written,written2,MACLen;
    int readBytes=0;
    int partMACmismatch=0;
    int numRows=0;
    int numCols=0;
    int numRowsMeta=0;
    int numColsMeta=0;
    int dbNumCols=0;
    int dbNumReintegratedCols=0;
    int dbNumRows=0;
    char **queryResult=NULL;
    char ***memDBResultData=NULL;
    char ***memDBResultMeta=NULL;
    char **resultMemTable=NULL;
    char **colSQLDBfNames=NULL;
    char **colSQLDBfSalts=NULL;
    char **memFilePartsMACs=NULL;
    char *currentDocumentId=NULL;
    char *currentRawFileContent=NULL;
    char *protectedValueMAC=NULL;
    char *bkpFName=NULL;
    char *sqlTableName="data"; //default table name for memory databases
    unsigned char *decodedEncryptedString=NULL;
    sqlite3 **memDBcol=NULL;
    //MEMORY CLEANUP MACRO for local function.
    #define cmeSecureDBToMemDBFree() \
        do { \
            cmeFree(currentDocumentId); \
            cmeFree(currentRawFileContent); \
            cmeFree(protectedValueMAC); \
            cmeFree(resultMemTable); \
            cmeFree (bkpFName); \
            cmeFree (decodedEncryptedString); \
            if (memDBcol) \
            { \
                for(cont=0;cont<dbNumCols;cont++) \
                { \
                    if (memDBcol[cont]) \
                    { \
                        cmeDBClose(memDBcol[cont]); \
                        memDBcol[cont]=NULL; \
                    } \
                } \
                cmeFree(memDBcol); \
            } \
            for (cont=0;cont<dbNumReintegratedCols;cont++) \
            { \
                if (memDBResultData) \
                { \
                    if (memDBResultData[cont]) \
                    { \
                        cmeMemTableFinal(memDBResultData[cont]); \
                    } \
                } \
                if (memDBResultMeta) \
                { \
                    if (memDBResultMeta[cont]) \
                    { \
                        cmeMemTableFinal(memDBResultMeta[cont]); \
                    } \
                } \
            } \
            for (cont=0;cont<dbNumCols;cont++) \
            { \
                if (colSQLDBfNames) \
                { \
                    cmeFree(colSQLDBfNames[cont]); \
                } \
                if (memFilePartsMACs) \
                { \
                    cmeFree(memFilePartsMACs[cont]); \
                } \
                if (colSQLDBfSalts) \
                { \
                    cmeFree(colSQLDBfSalts[cont]); \
                } \
            } \
            cmeFree(memDBResultData); \
            cmeFree(memDBResultMeta); \
            cmeFree(colSQLDBfNames); \
            cmeFree(memFilePartsMACs); \
            cmeFree(colSQLDBfSalts); \
        } while (0); //Local free() macro.
                     /*NOTE: No need to free each element in resultMemTable, as they are just pointers to elements
                      from memDBResultData and memDBResultMeta.
                      //WIPING SENSITIVE DATA IN MEMORY AFTER USE in colSQLDBfNames!*/

    *resultDB=NULL;  //Pointer to results must not point to anything previously! (Caller responsibility).
    //Open empty result DB (we must return at least an empty database in case of error). Caller must close it.
    if (cmeDBCreateOpen(":memory:",resultDB))
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSecureSQLToMemDB(), cmeDBCreateOpen() Error, can't "
                "Create and Open memory DB to store unprotected DB created from colFiles!\n");
#endif
        cmeSecureDBToMemDBFree(); //CLEANUP.
        return(1);
    }
    result=cmeMemTable(pResourcesDB,"SELECT * FROM documents",&queryResult,&numRows,&numCols);
    if(result) // Error
    {
        cmeSecureDBToMemDBFree(); //CLEANUP.
        return(2);
    }
    //We reserve memory for the first file part (and will increment memory as needed):
    colSQLDBfNames=(char **)malloc(sizeof(char *));     //We reserve memory for the estimated max. number of column parts to handle.
    colSQLDBfSalts=(char **)malloc(sizeof(char *));     //We reserve memory for the estimated max. number of column parts to handle.
    memFilePartsMACs=(char **)malloc(sizeof(char *));   //We reserve memory for the estimated max. number of column parts to handle.
    memDBcol=(sqlite3 **)malloc(sizeof(sqlite3 *));       //We reserve memory for column sqlite3 structure.
    //Initialize first file part pointers:
    memDBcol[0]=NULL;
    colSQLDBfNames[0]=NULL;
    colSQLDBfSalts[0]=NULL;
    memFilePartsMACs[0]=NULL;
    //Get MAC length in chars:
    cmeDigestLen(cmeDefaultMACAlg,&MACLen); //Get length of the MAC value (bytes).
    MACLen*=2;                              //Convert byte length to HexStr length.
    //Get list of column files from ResourcesDB:
    for(cont=1;cont<=numRows;cont++) //First row in a cmeSQLTable contains the names of columns; we skip them.
    {
        //Unprotect documentId:
        cmeFree(protectedValueMAC);
        cmeHMACByteString((const unsigned char*)queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_documentId]+MACLen,
                          (unsigned char **)&protectedValueMAC,strlen(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_documentId]+MACLen),
                          &written,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
        if (!strncmp(protectedValueMAC,queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_documentId],MACLen)) //MAC is correct; proceed with decryption.
        {
            result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_documentId]+MACLen,
                                             &currentDocumentId,cmeDefaultEncAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),
                                             orgKey,&written);
            if (result)  //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeSecureSQLToMemDB(), cmeUnprotectDBSaltedValue() error, cannot "
                        "decrypt documentId!\n");
#endif
                cmeSecureDBToMemDBFree(); //CLEANUP.
                return(3);
            }
        }
        else //MAC is incorrect; skip decryption process.
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Warning: cmeSecureSQLToMemDB(), cmeHMACByteString() cannot "
                    "verify documentId MAC!\n");
#endif
            cmeStrConstrAppend(&currentDocumentId,""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
        }
        //Check if register is part of the requested file. If so continue processing it:
        if (!strcmp(currentDocumentId,documentId)) //This column is part of the table!
        {
            //Unprotect columnFile:
            cmeFree(protectedValueMAC);
            cmeHMACByteString((const unsigned char*)queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile]+MACLen,
                              (unsigned char **)&protectedValueMAC,strlen(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile]+MACLen),
                              &written2,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
            if (!strncmp(protectedValueMAC,queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile],MACLen)) //MAC is correct; proceed with decryption.
            {
                result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile]+MACLen,
                                     &(colSQLDBfNames[dbNumCols]),cmeDefaultEncAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),
                                     orgKey,&written2);
                if (result)  //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeSecureSQLToMemDB(), cmeUnprotectDBSaltedValue() error, cannot "
                            "decrypt columnFile!\n");
#endif
                    cmeSecureDBToMemDBFree(); //CLEANUP.
                    return(4);
                }
            }
            else //MAC is incorrect; skip decryption process.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeSecureSQLToMemDB(), cmeHMACByteString() error, cannot "
                        "verify columnFile MAC!\n");
#endif
                cmeStrConstrAppend(&(colSQLDBfNames[dbNumCols]),""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
            }
            //Unprotect partMAC:
            cmeFree(protectedValueMAC);
            cmeHMACByteString((const unsigned char*)queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partMAC]+MACLen,
                              (unsigned char **)&protectedValueMAC,strlen(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partMAC]+MACLen),
                              &written2,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
            if (!strncmp(protectedValueMAC,queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partMAC],MACLen)) //MAC is correct; proceed with decryption.
            {
                result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partMAC]+MACLen,
                                     &(memFilePartsMACs[dbNumCols]),cmeDefaultEncAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),
                                     orgKey,&written2);
                if (result)  //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeSecureSQLToMemDB(), cmeUnprotectDBSaltedValue() error, cannot "
                            "decrypt partMAC!\n");
#endif
                    cmeSecureDBToMemDBFree(); //CLEANUP.
                    return(5);
                }
            }
            else //MAC is incorrect; skip decryption process.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeSecureSQLToMemDB(), cmeHMACByteString() error, cannot "
                        "verify partMAC MAC!\n");
#endif
                cmeStrConstrAppend(&(memFilePartsMACs[dbNumCols]),""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
            }
            //Copy salt:
            cmeStrConstrAppend(&(colSQLDBfSalts[dbNumCols]),"%s",queryResult[(cont*numCols)+cmeIDDanydb_salt]);
            //Increment number of columns found:
            dbNumCols++;
            //Grow reserved memory to hold next column element:
            colSQLDBfNames=(char **)realloc(colSQLDBfNames,sizeof(char *)*(dbNumCols+1));
            colSQLDBfSalts=(char **)realloc(colSQLDBfSalts,sizeof(char *)*(dbNumCols+1));
            memFilePartsMACs=(char **)realloc(memFilePartsMACs,sizeof(char *)*(dbNumCols+1));
            memDBcol=(sqlite3 **)malloc(sizeof(sqlite3 *)*(dbNumCols+1));
            //Initialize recently allocated memory:
            memDBcol[dbNumCols]=NULL;
            colSQLDBfNames[dbNumCols]=NULL;
            colSQLDBfSalts[dbNumCols]=NULL;
            memFilePartsMACs[dbNumCols]=NULL;
        }
        //TODO (OHR#2#): EVERYWHERE - Research memset() replacement to ensure delete with volatile; assess mlock ().
        if (currentDocumentId)
        {
            memset(currentDocumentId,0,strlen(currentDocumentId));   //WIPING SENSITIVE DATA IN MEMORY AFTER USE!
        }
        cmeFree(currentDocumentId);
    }
    for (cont=0;cont<dbNumCols;cont++) //Load protected columns
    {
        cmeStrConstrAppend(&bkpFName,"%s%s",storagePath,colSQLDBfNames[cont]);
        //Verify MAC of raw column before unprotecting file:
        cmeFree(protectedValueMAC);
        cmeFree(currentRawFileContent);
        result=cmeLoadStrFromFile(&currentRawFileContent,bkpFName,&readBytes);
        if (result)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSecureSQLToMemDB(), cmeLoadStrFromFile() error cannot "
                    "load raw column file part: %s !\n",bkpFName);
#endif
            cmeSecureDBToMemDBFree();
            return(6);
        }
        result=cmeHMACByteString((const unsigned char *)currentRawFileContent,(unsigned char **)&protectedValueMAC,readBytes,&written,cmeDefaultMACAlg,&(colSQLDBfSalts[cont]),orgKey);
        if (strcmp(protectedValueMAC,memFilePartsMACs[cont])) //Error!, MAC mismatch
        {
            partMACmismatch++; //Flag MAC mismatch for file part.
        }
        else //MAC OK; load column file.
        {
            if (cmeDBCreateOpen(":memory:",&(memDBcol[cont])))
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeSecureSQLToMemDB(), cmeDBCreateOpen() Error, can't "
                        "Create and Open memory DB to import secure colFiles; colFile No. %d!\n",cont);
#endif
                cmeSecureDBToMemDBFree(); //CLEANUP.
                return(7);
            }
            result=cmeMemDBLoadOrSave(memDBcol[cont],bkpFName,0);
            if (result) //Error
            {
                cmeSecureDBToMemDBFree(); //CLEANUP.
                return(8);
            }
        }
        cmeFree(bkpFName);
    }
    if ((!dbNumCols)||partMACmismatch) //if file not found or file part MAC mismatch, exit.
    {
        cmeSecureDBToMemDBFree();
        return(0);
    }
    //Reintegrate columns:
    result=cmeMemSecureDBReintegrate(memDBcol,orgKey,dbNumCols,&dbNumReintegratedCols);
    //Generate result table from reintegrated columns:
    memDBResultMeta=(char ***)malloc(sizeof(char **)*dbNumReintegratedCols);    //We reserve memory for column meta attributes.
    memDBResultData=(char ***)malloc(sizeof(char **)*dbNumReintegratedCols);    //We reserve memory for column data fields.
    for (cont=0;cont<dbNumReintegratedCols;cont++)
    {
        memDBResultMeta[cont]=NULL;
        memDBResultData[cont]=NULL;
        result=cmeMemSecureDBUnprotect(memDBcol[cont],orgKey); //Unprotect secure column DB.
        if (result) //Error
        {
            cmeSecureDBToMemDBFree(); //CLEANUP.
            return(9);
        }
        result=cmeMemTable(memDBcol[cont],"SELECT * FROM meta",&(memDBResultMeta[cont]),
                           &numRowsMeta,&numColsMeta);
        if(result) // Error
        {
            cmeSecureDBToMemDBFree(); //CLEANUP.
            return(10);
        }
        result=cmeMemTable(memDBcol[cont],"SELECT * FROM data",&(memDBResultData[cont]),
                           &numRows,&numCols);
        if(result) // Error
        {
            cmeSecureDBToMemDBFree(); //CLEANUP.
            return(11);
        }
        cmeFree(bkpFName);
    }
    dbNumRows=numRows;
    resultMemTable=(char **)malloc(sizeof(char *)*dbNumReintegratedCols*(dbNumRows+1)); //Consider 1 extra row for column names!
    if (!resultMemTable) //Error
    {
        cmeSecureDBToMemDBFree(); //CLEANUP.
        return(12);
    }
    for (cont=0;cont<=dbNumRows;cont++) //Import all data into a single, memory based, database.
    {
        for (cont2=0;cont2<dbNumReintegratedCols;cont2++) //Create Table with enough column elements; consider row for column names
        {
            if (cont) //Import data
            {
                resultMemTable[(cont*dbNumReintegratedCols)+cont2]=memDBResultData[cont2][((cont)*11)+4]; //Col. names are skipped w/ (cont+1)*11)+4....
            }
            else //Import column names
            {
                resultMemTable[(cont*dbNumReintegratedCols)+cont2]=memDBResultMeta[cont2][5+6];
            }
        }
    }
    result=cmeMemTableToMemDB (*resultDB, (const char **)resultMemTable, dbNumRows, dbNumReintegratedCols,
                               sqlTableName);
    if (result) //Error
    {
        cmeSecureDBToMemDBFree(); //CLEANUP.
        return(13);
    }
    //Free the rest of dynamically allocated resources that are no longer needed.
    for (cont=0;cont<dbNumReintegratedCols;cont++) //Wipe sensitive data after use
    {
        if (colSQLDBfNames[cont])
        {
            memset(colSQLDBfNames[cont],0,strlen(colSQLDBfNames[cont]));
        }
    }
    cmeSecureDBToMemDBFree();
    return(0);
}

int cmeDeleteSecureDB (sqlite3 *pResourcesDB,const char *documentId, const char *orgKey, const char *storagePath)
{
    int cont,result,written,written2,MACLen;
    int numRows=0;
    int numCols=0;
    int dbNumCols=0;
    int *colsSQLDBIds=NULL;
    char *currentDocumentId=NULL;
    char *currentFName=NULL;
    char *sqlQuery=NULL;
    char *protectedValueMAC=NULL;
    char **colSQLDBfNames=NULL;
    char **queryResult=NULL;
    sqlite3_int64 existRows=0;
    sqlite3 *existsDB=NULL;
    #define cmeDeleteSecureDBFree() \
        do { \
            cmeFree(colsSQLDBIds); \
            cmeFree(currentDocumentId); \
            cmeFree(currentFName); \
            cmeFree(sqlQuery); \
            cmeFree(protectedValueMAC); \
            for (cont=0;cont<dbNumCols;cont++) \
            { \
                if (colSQLDBfNames) \
                { \
                    cmeFree(colSQLDBfNames[cont]); \
                } \
            } \
            cmeFree(colSQLDBfNames); \
        } while (0); //Local free() macro.

    result=cmeSecureDBToMemDB(&existsDB,pResourcesDB,documentId,orgKey,storagePath);
    existRows=sqlite3_last_insert_rowid(existsDB);
    cmeDBClose(existsDB);
    if (existRows>0) //We have the same documentId already in the database...
    {
        cmeDigestLen(cmeDefaultMACAlg,&MACLen); //Get length of the MAC value (bytes).
        MACLen*=2; //Convert byte length to HexStr length.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeDeleteSecureDB(), documentId %s already exists; "
                "proceeding to delete it.\n",documentId);
#endif
        result=cmeMemTable(pResourcesDB,"SELECT * FROM documents;",&queryResult,&numRows,&numCols);
        if(result) // Error
        {
            cmeDeleteSecureDBFree();
            return(1);
        }
        colSQLDBfNames=(char **)malloc(sizeof(char *)*cmeMaxCSVColumns);
        for (cont=0;cont<cmeMaxCSVColumns;cont++)
        {
            colSQLDBfNames[cont]=NULL;
        }
        colsSQLDBIds=(int *)malloc(sizeof(int)*numRows);
        for(cont=1;cont<=numRows;cont++) //First row in a cmeSQLTable contains the names of columns; we skip them.
        {
            //Unprotect documentId:
            cmeFree(protectedValueMAC);
            cmeHMACByteString((const unsigned char*)queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_documentId]+MACLen,
                              (unsigned char **)&protectedValueMAC,strlen(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_documentId]+MACLen),
                              &written,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
            if (!strncmp(protectedValueMAC,queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_documentId],MACLen)) //MAC is correct; proceed with decryption.
            {
                result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_documentId]+MACLen,
                                     &currentDocumentId,cmeDefaultEncAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),
                                     orgKey,&written);
                if (result)  //Error
                {
    #ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeDeleteSecureDB(), cmeUnprotectDBSaltedValue() error, cannot "
                            "decrypt documentId!\n");
    #endif
                    cmeDeleteSecureDBFree(); //CLEANUP.
                    return(2);
                }
                if (!strcmp(currentDocumentId,documentId))//This column is part of the table!
                {
                    //Unprotect columnFile:
                    cmeFree(protectedValueMAC);
                    cmeHMACByteString((const unsigned char*)queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile]+MACLen,
                                      (unsigned char **)&protectedValueMAC,strlen(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile]+MACLen),
                                      &written2,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
                    if (!strncmp(protectedValueMAC,queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile],MACLen)) //MAC is correct; proceed with decryption.
                    {
                        result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile]+MACLen,
                                             &(colSQLDBfNames[dbNumCols]),cmeDefaultEncAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),
                                             orgKey,&written2);
                        if (result)  //Error
                        {
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeDeleteSecureDB(), cmeUnprotectDBSaltedValue() error, cannot "
                                    "decrypt documentId!\n");
#endif
                            cmeDeleteSecureDBFree(); //CLEANUP.
                            return(3);
                        }
                    }
                    else //MAC is incorrect; skip decryption process.
                    {
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Warning: cmeDeleteSecureDB(), cmeHMACByteString() cannot "
                                "verify columnFile MAC!\n");
#endif
                        cmeStrConstrAppend(&(colSQLDBfNames[dbNumCols]),""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
                    }
                    colsSQLDBIds[dbNumCols]=atoi(queryResult[cont*numCols]+cmeIDDanydb_id);            //Store register ID; register will be deleted from resourcesDB index.
                    dbNumCols++;
                }
                memset(currentDocumentId,0,written);   //WIPING SENSITIVE DATA IN MEMORY AFTER USE!
                cmeFree(currentDocumentId);
            }
            else //MAC is incorrect; skip decryption process.
            {
    #ifdef DEBUG
                fprintf(stdout,"CaumeDSE Warning: cmeDeleteSecureDB(), cmeHMACByteString() cannot "
                        "verify documentId MAC!\n");
    #endif
                cmeStrConstrAppend(&currentDocumentId,""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
            }
        }
        for(cont=0; cont <dbNumCols; cont++)
        {
            //Delete from ResourcesDB.
            cmeStrConstrAppend(&sqlQuery,"BEGIN;"
                               "DELETE FROM documents WHERE id=%d;"
                               "COMMIT;",colsSQLDBIds[cont]);
            result=cmeSQLRows(pResourcesDB,sqlQuery,NULL,NULL);
            cmeFree(sqlQuery);
            if (result)
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeDeleteSecureDB(), cmeSQLRows() Error, can't "
                        "delete secureDB column, query: %s!\n",sqlQuery);
#endif
                cmeDeleteSecureDBFree();
                return(4);
            }
            //Delete Column Files.
            cmeStrConstrAppend(&currentFName,"%s%s",cmeDefaultFilePath,colSQLDBfNames[cont]);
            result=remove(currentFName);
            cmeFree(currentFName);
            if (result)
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeDeleteSecureDB(), remove() Error, can't "
                        "delete secureDB column file: %s\n",currentFName);
#endif
                cmeDeleteSecureDBFree();
                return(5);

            }
        }
        //Prepare to free the rest of dynamically allocated resources that are no longer needed.
        cmeMemTableFinal(queryResult);
        for (cont=0;cont<dbNumCols;cont++)
        {
            memset(colSQLDBfNames[cont],0,written2);    //WIPING SENSITIVE DATA IN MEMORY AFTER USE!
            colsSQLDBIds[cont]=0;                       //WIPING SENSITIVE DATA IN MEMORY AFTER USE!
        }
    }
    else //WARNING: document ID not found
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeDeleteSecureDB(), documentId %s not found! "
                "No document ID was deleted.\n",documentId);
#endif
    }
    cmeDeleteSecureDBFree();
    return(0);
}

int cmeGetUnprotectDBRegisters (sqlite3 *pDB, const char *tableName, const char **columnNames,
                                const char **columnValues,const int numColumnValues, char ***resultRegisterCols,
                                int *numResultRegisterCols, int *numResultRegisters, const char *orgKey)
{
    int result,cont,cont2,cont3,MACLen;
    int valueLen=0;
    int numMatch=0;
    int numRows=0;
    int numColumns=0;
    char *query=NULL;
    char *protectedValueMAC=NULL;
    char **resultsRegTmp=NULL;
    char **sqlTable=NULL;
    #define cmeGetUnprotectDBRegisterFree() \
        do { \
            cmeFree(query); \
            cmeFree(protectedValueMAC); \
            if (sqlTable) \
            { \
                cmeMemTableFinal(sqlTable); \
            } \
        } while (0); //Local free() macro.

    *numResultRegisters=1; //We will reserve memory for at least one result register.
    //1st Load all encrypted registers in a memTable.
    //TODO (OHR#3#): Check alternative for enabling tables with no results to return column names as 1st row;
    //               'PRAGMA empty_result_callbacks = ON' is deprecated according to SQLITE 3 docs!
    cmeStrConstrAppend(&query,"PRAGMA empty_result_callbacks = ON; SELECT * FROM %s;",
                       tableName);
    result=cmeMemTable(pDB,(const char *)query,&sqlTable,&numRows,&numColumns);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeGetUnprotectDBRegister(), cmeMemTable() Error, can't "
                "execute query %s in table:%s!\n",query,tableName);
#endif
        cmeGetUnprotectDBRegisterFree();
        return(1);
    }
    *numResultRegisterCols=numColumns;
    *resultRegisterCols=(char **)malloc(sizeof(char *)*numColumns*2);  //Allocate space for colum names and first row of result values.
    cmeDigestLen(cmeDefaultMACAlg,&MACLen); //Get length of the MAC value (bytes).
    MACLen*=2; //Convert byte length to HexStr length.
    for (cont=0;cont<numColumns;cont++) //First copy all column names in the first row and set to NULL the second row for result values.
    {
        (*resultRegisterCols)[cont]=NULL; //cmeStrContrAppend requires this for new strings.
        cmeStrConstrAppend(&((*resultRegisterCols)[cont]),"%s",sqlTable[cont]); //Add header names (row 0).
        (*resultRegisterCols)[(*numResultRegisters)*numColumns+cont]=NULL;
    }
    for (cont=1;cont<=numRows;cont++) //Process each row (ignore row 0 with column header names)
    {
        numMatch=0;
        for (cont2=0;cont2<numColumns;cont2++) //Process each column - first search for filter matches.
        {
            cmeFree((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]); //Clear memory space before use.
            if ((strcmp(sqlTable[cont2],"id")!=0)&&(strcmp(sqlTable[cont2],"salt")!=0)
                &&(sqlTable[cont*numColumns+cont2]!=NULL))  //We decrypt and compare, except if column name is 'id' or 'salt'.
            {
                if (strlen(sqlTable[cont*numColumns+cont2])>(size_t)MACLen) //Good, protected value is longer than MAC value.
                {
                    cmeHMACByteString((const unsigned char *)sqlTable[cont*numColumns+cont2]+MACLen,(unsigned char **)&protectedValueMAC,strlen(sqlTable[cont*numColumns+cont2]+MACLen),
                                      &valueLen,cmeDefaultMACAlg,&(sqlTable[cont*numColumns+cmeIDDanydb_salt]),orgKey);
                    if (!strncmp(protectedValueMAC,sqlTable[cont*numColumns+cont2],MACLen)) //MAC is correct; proceed with decryption.
                    {
                        //If cmeUnprotectDBSaltedValue() !=0, value can't be decrypted with the key provided (2) or is NULL (1)! No need to compare incorrectly decrypted values!
                        if(!cmeUnprotectDBSaltedValue(sqlTable[cont*numColumns+cont2]+MACLen,&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                                      cmeDefaultEncAlg,&(sqlTable[cont*numColumns+cmeIDDanydb_salt]),orgKey,&valueLen))
                        {
                            for (cont3=0;cont3<numColumnValues;cont3++) //Check each relevant column by name.
                            {
                                if ((strcmp(sqlTable[cont2],columnNames[cont3])==0) && //Matches column name.
                                    (strcmp((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2],columnValues[cont3])==0))  //And matches value filter.
                                {
                                    numMatch++;
                                }
                            }
                        }
                    }
                    cmeFree(protectedValueMAC);
                }
                else //Error: protectedValue length shouldn't be <= MACLen
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeGetUnprotectDBRegister(), Error, length "
                            "of protected value (%u) <= length of MAC (%d) for default HMAC alg. %s!\n",
                            (unsigned int)strlen(sqlTable[cont*numColumns+cont2]),MACLen,cmeDefaultMACAlg);
#endif
                }
            }
            else  //We just compare ('salt' and 'id' column names).
            {
                cmeStrConstrAppend(&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                   "%s",sqlTable[cont*numColumns+cont2]);
                for (cont3=0;cont3<numColumnValues;cont3++) //Check each relevant column by name.
                {
                    if ((strcmp(sqlTable[cont2],columnNames[cont3])==0) && //Matches column name.
                        (strcmp(sqlTable[cont*numColumns+cont2],columnValues[cont3])==0))  //And matches value filter.
                    {
                        numMatch++;
                    }
                }
            }
        }
        if ((numMatch==numColumnValues)||(numColumnValues==0)) //We found all matches in a register; add the results to the result array.
        {
            (*numResultRegisters)++;
            resultsRegTmp=(char **)realloc(*resultRegisterCols,sizeof(char *)*numColumns*((*numResultRegisters)+1));  //realocate space to allow one more register
            if (resultsRegTmp)
            {
                *resultRegisterCols=resultsRegTmp;
            }
            else // Realloc error!!!
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeGetUnprotectDBRegister(), realloc() Error, can't "
                        "allocate new memory block of size: %lu\n",sizeof(char *)*numColumns*((*numResultRegisters)+1));
#endif
                cmeGetUnprotectDBRegisterFree();
                return(2);
            }
            for (cont2=0;cont2<numColumns;cont2++) //Clear new value pointers.
            {
                (*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]=NULL; //cmeStrContrAppend requires this for new strings.
            }
        }
    }
    cmeGetUnprotectDBRegisterFree();
    (*numResultRegisters)--; //Adjust number of results by eliminating the last row which is a placeholder for the next "potential" match.
    return(0);
}

int cmeDeleteUnprotectDBRegisters (sqlite3 *pDB, const char *tableName, const char **columnNames,
                                const char **columnValues,const int numColumnValues, char ***resultRegisterCols,
                                int *numResultRegisterCols, int *numResultRegisters, const char *orgKey)
{
    int result,cont,cont2,cont3,MACLen;
    int valueLen=0;
    int numMatch=0;
    int numRows=0;
    int numColumns=0;
    char *protectedValueMAC=NULL;
    char *regId=NULL;
    char *query=NULL;
    char **sqlTable=NULL;
    #define cmeDeleteUnprotectDBRegisterFree() \
        do { \
            cmeFree(query); \
            cmeFree(regId); \
            cmeFree(protectedValueMAC); \
            if (sqlTable) \
            { \
                cmeMemTableFinal(sqlTable); \
            } \
        } while (0); //Local free() macro.

    *numResultRegisters=1; //We will reserve memory for at least one result register.
    //1st Load all encrypted registers in a memTable.
    //TODO (OHR#3#): Check alternative for enabling tables with no results to return column names as 1st row;
    //               'PRAGMA empty_result_callbacks = ON' is deprecated according to SQLITE 3 docs!
    cmeStrConstrAppend(&query,"PRAGMA empty_result_callbacks = ON; SELECT * FROM %s;",
                       tableName);
    result=cmeMemTable(pDB,(const char *)query,&sqlTable,&numRows,&numColumns);
    cmeFree(query);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeDeleteUnprotectDBRegister(), cmeMemTable() Error, can't "
                "execute query %s in table:%s!\n",query,tableName);
#endif
        cmeDeleteUnprotectDBRegisterFree();
        return(1);
    }
    *numResultRegisterCols=numColumns;
    *resultRegisterCols=(char **)malloc(sizeof(char *)*numColumns*2);  //Allocate space for colum names and first row of result values.
    cmeDigestLen(cmeDefaultMACAlg,&MACLen); //Get length of the MAC value (bytes).
    MACLen*=2; //Convert byte length to HexStr length.
    for (cont=0;cont<numColumns;cont++) //First copy all column names in the first row.
    {
        (*resultRegisterCols)[cont]=NULL; //cmeStrContrAppend requires this for new strings.
        cmeStrConstrAppend(&((*resultRegisterCols)[cont]),"%s",sqlTable[cont]); //Add header names (row 0).
        (*resultRegisterCols)[(*numResultRegisters)*numColumns+cont]=NULL;
    }
    for (cont=1;cont<=numRows;cont++) //Process each row (ignore row 0 with column header names)
    {
        numMatch=0; //Reset match counter.
        cmeFree(regId);
        for (cont2=0;cont2<numColumns;cont2++) //Process each column - first search for filter matches.
        {
            cmeFree((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]); //Clear memory space before use.
            if ((strcmp(sqlTable[cont2],"id")!=0)&&(strcmp(sqlTable[cont2],"salt")!=0)
                &&(sqlTable[cont*numColumns+cont2]!=NULL))  //We decrypt and compare, except if column name is 'id' or 'salt'.
            {
                if (strlen(sqlTable[cont*numColumns+cont2])>(size_t)MACLen) //Good, protected value is longer than MAC value.
                {
                    cmeHMACByteString((const unsigned char *)sqlTable[cont*numColumns+cont2]+MACLen,(unsigned char **)&protectedValueMAC,strlen(sqlTable[cont*numColumns+cont2]+MACLen),
                                      &valueLen,cmeDefaultMACAlg,&(sqlTable[cont*numColumns+cmeIDDanydb_salt]),orgKey);
                    if (!strncmp(protectedValueMAC,sqlTable[cont*numColumns+cont2],MACLen)) //MAC is correct; proceed with decryption.
                    {
                        //If cmeUnprotectDBSaltedValue() !=0, value can't be decrypted with the key provided (2) or is NULL (1)! No need to compare incorrectly decrypted values!
                        if(!cmeUnprotectDBSaltedValue(sqlTable[cont*numColumns+cont2]+MACLen,&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                                      cmeDefaultEncAlg,&(sqlTable[cont*numColumns+cmeIDDanydb_salt]),orgKey,&valueLen))
                        {
                            for (cont3=0;cont3<numColumnValues;cont3++) //Check each relevant column by name.
                            {
                                if ((strcmp(sqlTable[cont2],columnNames[cont3])==0) &&      //Matches column name.
                                    (strcmp((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2],columnValues[cont3])==0))  //And matches value filter.
                                {
                                    numMatch++;
                                }
                            }
                        }
                    }
                    cmeFree(protectedValueMAC);
                }
                else //Error: protectedValue length shouldn't be <= MACLen
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeGetUnprotectDBRegister(), Error, length "
                            "of protected value (%u) <= length of MAC (%d) for default HMAC alg. %s!\n",
                            (unsigned int)strlen(sqlTable[cont*numColumns+cont2]),MACLen,cmeDefaultMACAlg);
#endif
                }
            }
            else  //We just compare ('salt' and 'id' column names).
            {
                cmeStrConstrAppend(&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                   "%s",sqlTable[cont*numColumns+cont2]);
                for (cont3=0;cont3<numColumnValues;cont3++) //Check each relevant column by name.
                {
                    if ((strcmp(sqlTable[cont2],columnNames[cont3])==0) &&      //Matches column name.
                        (strcmp(sqlTable[cont*numColumns+cont2],columnValues[cont3])==0))  //And matches value filter.
                    {
                        numMatch++;
                    }
                }
                if (cont2==cmeIDDanydb_id)
                {
                    cmeStrConstrAppend(&regId,"%s",sqlTable[cont*numColumns+cont2]);
                }
            }
        }
        if ((numMatch==numColumnValues)||(numColumnValues==0)) //We found all matches in a register; process this row.
        {
            (*numResultRegisters)++;
            cmeStrConstrAppend(&query,"DELETE FROM %s WHERE id=%s;",tableName,regId);
            result=cmeSQLRows(pDB,(const char *)query,NULL,NULL);
            cmeFree(query);
            if (result) //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeDeleteUnprotectDBRegister(), sql Error, can't "
                        "DELETE, statement: %s\n",query);
#endif
                cmeDeleteUnprotectDBRegisterFree();
                return(2);
            }
        }
    }
    cmeDeleteUnprotectDBRegisterFree();
    (*numResultRegisters)--; //Adjust number of results by eliminating the last row which is a placeholder for the next "potential" match.
    return(0);
}

int cmePostProtectDBRegister (sqlite3 *pDB, const char *tableName, const char **columnNames,
                              const char **columnValues,const int numColumnValues, const char *orgKey)
{   //NOTE: Authorization and parameter validation takes place outside (at web interface level!).
    int cont,result,protectedValueLen,protectedValueMACLen;
    char *sqlStatement=NULL;
    char *protectedValue=NULL;
    char *protectedValueMAC=NULL;
    char *salt=NULL;
    #define cmePostProtectDBRegisterFree() \
        do { \
            cmeFree(sqlStatement); \
            cmeFree(protectedValue); \
            cmeFree(protectedValueMAC); \
            cmeFree(salt); \
        } while (0); //Local free() macro.

    cmeStrConstrAppend (&sqlStatement,"BEGIN TRANSACTION; INSERT INTO %s (id,",tableName); //First part. id goes by default.
    for (cont=0; cont<numColumnValues; cont++)
    {
        if (!columnNames[cont]) //Error, colName is NULL!
        {
 #ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmePostProtectDBRegister(), Error,"
                    "NULL pointer at columnNames[%d]\n",cont);
#endif
            cmePostProtectDBRegisterFree();
            return(1);
        }
        if (strcmp(columnNames[cont],"salt")==0) //Salt provided? yes -> use it and append at the end.
        {
            if (columnValues[cont]) //user provided value; else use NULL
            {
                //TODO (OHR#3#): verify salt requirements. If bad, ERROR!
                cmeStrConstrAppend(&salt,"%s",columnValues[cont]);
            }
        }
        else
        {
            cmeStrConstrAppend(&sqlStatement,"%s",columnNames[cont]); //add column.
            if ((cont+1)<numColumnValues)  //Still one left...
            {
                cmeStrConstrAppend(&sqlStatement,","); //add comma.
            }
        }
    }
    cmeStrConstrAppend (&sqlStatement,",salt) VALUES (NULL,"); //Second part. id=NULL goes by default.
    for (cont=0; cont<numColumnValues; cont++)
    {
        if ((strcmp(columnNames[cont],"salt")!=0)&&(columnValues[cont]!=NULL)) //Skip salt, we will add it at the end.
        {
            cmeProtectDBSaltedValue(columnValues[cont],&protectedValue,cmeDefaultEncAlg,&salt,orgKey,&protectedValueLen);
            cmeHMACByteString((const unsigned char *)protectedValue,(unsigned char **)&protectedValueMAC,protectedValueLen,&protectedValueMACLen,cmeDefaultMACAlg,&salt,orgKey);
            cmeStrConstrAppend(&sqlStatement,"'%s%s'",protectedValueMAC,protectedValue); //add MAC+Encrypted(salted) column value to query.
            cmeFree(protectedValue);
            cmeFree(protectedValueMAC);
            if ((cont+1)<numColumnValues)  //Still one left...
            {
                cmeStrConstrAppend(&sqlStatement,","); //add comma.
            }
        }
    }
    cmeStrConstrAppend (&sqlStatement,",'%s'); COMMIT;",salt); //Last part.
    result=cmeSQLRows(pDB,sqlStatement,NULL,NULL);
    if (result) //Error.
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmePostProtectDBRegister(), cmeSQLRows() Error, can't "
                "create register in table: %s with sql statement %s!\n",tableName,sqlStatement);
#endif
        cmePostProtectDBRegisterFree();
        return(2);
    }
    cmePostProtectDBRegisterFree();
    return(0);
}

int cmePutProtectDBRegisters (sqlite3 *pDB, const char *tableName, const char **columnNames,
                                const char **columnValues,const int numColumnValues, const char **columnNamesUpdate,
                                const char **columnValuesUpdate,const int numColumnValuesUpdate, char ***resultRegisterCols,
                                int *numResultRegisterCols, int *numResultRegisters, const char *orgKey)
{
    int result,cont,cont2,cont3,MACLen,protectedValueMACLen;
    int valueLen=0;
    int numMatch=0;
    int numRows=0;
    int numColumns=0;
    int encryptedValueLen=0;
    char *regId=NULL;
    char *query=NULL;
    char *protectedValueMAC=NULL;
    char *encryptedValue=NULL;
    char **resultsRegTmp=NULL;
    char **sqlTable=NULL;
    #define cmePutProtectDBRegisterFree() \
        do { \
            cmeFree(query); \
            cmeFree(regId); \
            cmeFree(protectedValueMAC); \
            cmeFree(encryptedValue); \
            if (sqlTable) \
            { \
                cmeMemTableFinal(sqlTable); \
            } \
        } while (0); //Local free() macro.

    *numResultRegisters=1; //We will reserve memory for at least one result register.
    //1st Load all encrypted registers in a memTable.
    //TODO (OHR#3#): Check alternative for enabling tables with no results to return column names as 1st row;
    //               'PRAGMA empty_result_callbacks = ON' is deprecated according to SQLITE 3 docs!
    cmeStrConstrAppend(&query,"PRAGMA empty_result_callbacks = ON; SELECT * FROM %s;",
                       tableName);
    result=cmeMemTable(pDB,(const char *)query,&sqlTable,&numRows,&numColumns);
    cmeFree(query);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmePutProtectDBRegister(), cmeMemTable() Error, can't "
                "execute query %s in table:%s!\n",query,tableName);
#endif
        cmePutProtectDBRegisterFree();
        return(1);
    }
    *numResultRegisterCols=numColumns;
    *resultRegisterCols=(char **)malloc(sizeof(char *)*numColumns*2);  //Allocate space for colum names and first row of result values.
    cmeDigestLen(cmeDefaultMACAlg,&MACLen); //Get length of the MAC value.
    MACLen*=2; //Convert byte length to HexStr length.
    for (cont=0;cont<numColumns;cont++) //First copy all column names in the first row.
    {
        (*resultRegisterCols)[cont]=NULL; //cmeStrContrAppend requires this for new strings.
        cmeStrConstrAppend(&((*resultRegisterCols)[cont]),"%s",sqlTable[cont]); //Add header names (row 0).
        (*resultRegisterCols)[(*numResultRegisters)*numColumns+cont]=NULL;
    }
    for (cont=1;cont<=numRows;cont++) //Process each row (ignore row 0 with column header names)
    {
        numMatch=0;
        cmeFree(regId);
        for (cont2=0;cont2<numColumns;cont2++) //Process each column - first search for filter matches.
        {
            cmeFree((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]); //Clear memory space before use.
            if ((strcmp(sqlTable[cont2],"id")!=0)&&(strcmp(sqlTable[cont2],"salt")!=0)
                &&(sqlTable[cont*numColumns+cont2]!=NULL))  //We decrypt and compare, except if column name is 'id' or 'salt'.
            {
                if (strlen(sqlTable[cont*numColumns+cont2])>(size_t)MACLen) //Good, protected value is longer than MAC value.
                {
                    cmeHMACByteString((const unsigned char *)sqlTable[cont*numColumns+cont2]+MACLen,(unsigned char **)&protectedValueMAC,strlen(sqlTable[cont*numColumns+cont2]+MACLen),
                                      &valueLen,cmeDefaultMACAlg,&(sqlTable[cont*numColumns+cmeIDDanydb_salt]),orgKey);
                    if (!strncmp(protectedValueMAC,sqlTable[cont*numColumns+cont2],MACLen)) //MAC is correct; proceed with decryption.
                    {
                        //If cmeUnprotectDBSaltedValue() !=0, value can't be decrypted with the key provided (2) or is NULL (1)! No need to compare incorrectly decrypted values!
                        if(!cmeUnprotectDBSaltedValue(sqlTable[cont*numColumns+cont2]+MACLen,&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                                      cmeDefaultEncAlg,&(sqlTable[cont*numColumns+cmeIDDanydb_salt]),orgKey,&valueLen))
                        {
                            for (cont3=0;cont3<numColumnValues;cont3++) //Check each relevant column by name.
                            {
                                if ((strcmp(sqlTable[cont2],columnNames[cont3])==0) && //Matches column name.
                                    (strcmp((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2],columnValues[cont3])==0))  //And matches value filter.
                                {
                                    numMatch++;
                                }
                            }
                        }
                    }
                    cmeFree(protectedValueMAC);
                }
                else //Error: protectedValue length shouldn't be <= MACLen
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmePutProtectDBRegister(), Error, length "
                            "of protected value (%u) <= length of MAC (%d) for default HMAC alg. %s!\n",
                            (unsigned int)strlen(sqlTable[cont*numColumns+cont2]),MACLen,cmeDefaultMACAlg);
#endif
                }
            }
            else  //We just compare ('salt' and 'id' column names).
            {
                cmeStrConstrAppend(&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                   "%s",sqlTable[cont*numColumns+cont2]);
                for (cont3=0;cont3<numColumnValues;cont3++) //Check each relevant column by name.
                {
                    if ((strcmp(sqlTable[cont2],columnNames[cont3])==0) && //Matches column name.
                        (strcmp(sqlTable[cont*numColumns+cont2],columnValues[cont3])==0))  //And matches value filter.
                    {
                        numMatch++;
                    }
                }
                if (cont2==cmeIDDanydb_id)
                {
                    cmeStrConstrAppend(&regId,"%s",sqlTable[cont*numColumns+cont2]);
                }
            }
        }
        if ((numMatch==numColumnValues)||(numColumnValues==0)) //We found all matches in a register; add the results to the result array.
        {
            (*numResultRegisters)++;
            resultsRegTmp=(char **)realloc(*resultRegisterCols,sizeof(char *)*numColumns*((*numResultRegisters)+1));  //realocate space to allow one more register
            if (resultsRegTmp)
            {
                *resultRegisterCols=resultsRegTmp;
            }
            else // Realloc error!!!
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmePutProtectDBRegister(), realloc() Error, can't "
                        "allocate new memory block of size: %lu\n",sizeof(char *)*numColumns*((*numResultRegisters)+1));
#endif
                cmePutProtectDBRegisterFree();
                return(2);
            }
            for (cont2=0;cont2<numColumns;cont2++) //Clear new value pointers.
            {
                (*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]=NULL; //cmeStrContrAppend requires this for new strings.
            }
            cmeStrConstrAppend(&query,"UPDATE %s SET",tableName); //First part.
            for (cont2=0;cont2<numColumnValuesUpdate;cont2++)
            {
                if ((!strcmp(columnNamesUpdate[cont2],"id"))&&(!strcmp(columnNamesUpdate[cont2],"salt"))) // We don't encrypt if 'id' or 'salt'
                {
                    cmeStrConstrAppend(&query," %s='%s'",columnNamesUpdate[cont2],columnValuesUpdate[cont2]);
                    if ((cont2+1)<numColumnValuesUpdate) //Still another value left...
                    {
                        cmeStrConstrAppend(&query,",");
                    }
                }
                else //Encrypt then MAC
                {
                    cmeProtectDBSaltedValue(columnValuesUpdate[cont2],&encryptedValue,cmeDefaultEncAlg,
                                            &((*resultRegisterCols)[((*numResultRegisters)-1)*numColumns+cmeIDDanydb_salt]),
                                            orgKey,&encryptedValueLen); //Salt and encrypt value.
                    cmeHMACByteString((const unsigned char *)encryptedValue,(unsigned char **)&protectedValueMAC,encryptedValueLen,&protectedValueMACLen,cmeDefaultMACAlg,
                                      &((*resultRegisterCols)[((*numResultRegisters)-1)*numColumns+cmeIDDanydb_salt]),orgKey);
                    cmeStrConstrAppend(&query," %s='%s%s'",columnNamesUpdate[cont2],protectedValueMAC,encryptedValue);  //Add MAC+Encrypted(salted) column value to query.
                    cmeFree(encryptedValue);
                    cmeFree(protectedValueMAC);
                    if ((cont2+1)<numColumnValuesUpdate) //Still another value left...
                    {
                        cmeStrConstrAppend(&query,",");
                    }
                }
            }
            cmeStrConstrAppend(&query," WHERE id=%s;",regId); //Last part.
            result=cmeSQLRows(pDB,(const char *)query,NULL,NULL);
            cmeFree(query);
            if (result) //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmePutProtectDBRegister(), sql Error, can't "
                        "UPDATE, statement: %s\n",query);
#endif
                cmePutProtectDBRegisterFree();
                return(3);
            }
        }
    }
    cmePutProtectDBRegisterFree();
    (*numResultRegisters)--; //Adjust number of results by eliminating the last row which is a placeholder for the next "potential" match.
    return(0);
}

int cmeProcessURLMatchSaveParameters (const char *urlMethod, const char **argumentElements, const char **validNamesToMatch,
                                      const char **validNamesToSave, const int numValidMatch, const int numValidSaves,
                                      char **columnValuesToMatch, char **columnNamesToMatch, char **columnValuesToSave,
                                      char **columnNamesToSave, int *numMatchArgs, int *numSaveArgs, char **userId, char **orgId,
                                      char **orgKey, char **newOrgKey, int *usrArg, int *orgArg, int *keyArg, int *newKeyArg)
{
    //NOTE: Caller must reserve enough memory for each 'char **arrayOfStrings' and 'char *string', and free them after call!
    int cont,cont2;
    *usrArg=0;
    *orgArg=0;
    *keyArg=0;
    *newKeyArg=0;
    cont=0;
    while ((cont<cmeWSURIMaxArguments)&&(argumentElements[cont])&&(((*numMatchArgs)<cmeWSURIMaxMatchSaveArguments)||
           ((*numSaveArgs)<cmeWSURIMaxMatchSaveArguments)||(!keyArg)||(!usrArg)||(!orgArg))) //Check for parameters (userId,orgKey,orgId).
    {
        if (!strcmp(argumentElements[cont],"userId")) //parameter userId found!.
        {
            cmeStrConstrAppend(userId,"%s",argumentElements[cont+1]); //special case; we pass it as a function parameter; not in columnValues.
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeProcessURLMatchSaveParameters(), %s, parameter userId: '%s'.\n",
                    urlMethod, argumentElements[cont+1]);
#endif
            *usrArg=1;
        }
        else if (!strcmp(argumentElements[cont],"orgId")) //parameter orgId found!.
        {
            cmeStrConstrAppend(orgId,"%s",argumentElements[cont+1]); //special case; we pass it as a function parameter; not in columnValues.
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeProcessURLMatchSaveParameters(), %s, parameter orgId: '%s'.\n",
                    urlMethod, argumentElements[cont+1]);
#endif
            *orgArg=1;
        }
        else if (!strcmp(argumentElements[cont],"orgKey")) //parameter orgKey found!.
        {
            cmeStrConstrAppend(orgKey,"%s",argumentElements[cont+1]); //special case; we pass it as a function parameter; not in columnValues.
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeProcessURLMatchSaveParameters(), %s, parameter orgKey: '%s'.\n",
                    urlMethod, argumentElements[cont+1]);
#endif
            *keyArg=1;
        }
        else if (!strcmp(argumentElements[cont],"newOrgKey")) //parameter newOrgKey found!.
        {
            cmeStrConstrAppend(newOrgKey,"%s",argumentElements[cont+1]); //special case; we pass it as a function parameter; not in columnValues.
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeProcessURLMatchSaveParameters(), %s, parameter newOrgKey: '%s'.\n",
                    urlMethod, argumentElements[cont+1]);
#endif
            *newKeyArg=1;
        }
        cont2=0; //Process match parameters:
        while ((cont2<numValidMatch)&&(validNamesToMatch[cont2]!=NULL))
        {
            if (!strcmp(argumentElements[cont],validNamesToMatch[cont2])) // MATCH parameter found!.
            {
                cmeStrConstrAppend(&(columnValuesToMatch[*numMatchArgs]),"%s",argumentElements[cont+1]);
                cmeStrConstrAppend(&(columnNamesToMatch[*numMatchArgs]),"%s",(argumentElements[cont])+1); //Add column name without the preceeding '_' character.
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeProcessURLMatchSaveParameters(), %s, MATCH parameter '%s': '%s'.\n",
                        urlMethod, argumentElements[cont], argumentElements[cont+1]);
#endif
                (*numMatchArgs)++;
            }
            cont2++;
        }
        cont2=0; //Process save parameters:
        while ((cont2<numValidSaves)&&(validNamesToSave[cont2]!=NULL))
        {
            if (!strcmp(argumentElements[cont],validNamesToSave[cont2])) // SAVE parameter found!.
            {
                cmeStrConstrAppend(&(columnValuesToSave[*numSaveArgs]),"%s",argumentElements[cont+1]);
                if ((char)argumentElements[cont][0]=='*') //Regular Save paramenter
                {
                    cmeStrConstrAppend(&(columnNamesToSave[*numSaveArgs]),"%s",(argumentElements[cont])+1); //Add column name without the preceeding '*' character.
                }
                else //Other parameter, such as userId or orgId
                {
                    cmeStrConstrAppend(&(columnNamesToSave[*numSaveArgs]),"%s",(argumentElements[cont])); //Add column name as it is.
                }
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeProcessURLMatchSaveParameters(), %s, SAVE parameter '%s': '%s'.\n",
                        urlMethod, argumentElements[cont], argumentElements[cont+1]);
#endif
                (*numSaveArgs)++;
            }
            cont2++;
        }
        cont+=2;
    }
    return (0);
}

int cmeConstructContentRow (const char **argumentElements, const char **columnNames, const int numColumns,
                            const char *registerId, char ***newContentRow)
{
    int cont,cont2;
    char *nameNoBrackets=NULL;
    #define cmeConstructContentRowFree() \
        do { \
            cmeFree(nameNoBrackets); \
        } while (0); //Local free() macro.

    *newContentRow=(char **)malloc(sizeof(char*)*numColumns); //Reserve memory for new contentRow (size=numColumns). Note that caller must free it.
    for (cont=0;cont<numColumns;cont++) //Clear newContentRow data.
    {
        (*newContentRow)[cont]=NULL;
    }
    cmeStrConstrAppend(&(*newContentRow[0]),"%s",registerId); //Set id=registerId in new contentRow.
    cont=0;
    while ((cont<cmeWSURIMaxArguments)&&(argumentElements[cont])) //Check for contentRow parameters [<number>] or [<name>].
    {
        if ((argumentElements[cont][0]!='[')||(argumentElements[cont][strlen(argumentElements[cont])-1]!=']')) //argument name is not contained within brackets.
        {
            cont+=2;
            continue; //Not a contentRow parameter; check next argument name.
        }
        cmeFree(nameNoBrackets);
        cmeStrConstrAppend(&nameNoBrackets,"%.*s",strlen(argumentElements[cont])-2,argumentElements[cont]+1); //Copy substring (all except start and en brackets).
        for(cont2=1;cont2<numColumns;cont2++) //Compare against each column name; we skip first column, which is always the register's id.
        {
            if(!strcmp(columnNames[cont2],nameNoBrackets)) //found match.
            {
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeConstructContentRow(), contentRow parameter found by name: '%s', value: '%s'.\n",
                        argumentElements[cont],argumentElements[cont+1]);
#endif
                cmeStrConstrAppend(&((*newContentRow)[cont2]),"%s",argumentElements[cont+1]);
                break;
            }
        }
        cont+=2;
    }
    //Replace any NULL fields with empty strings.
    for (cont=0;cont<numColumns;cont++)
    {
        if(!((*newContentRow)[cont]))
        {
            cmeStrConstrAppend(&((*newContentRow)[cont]),"");
        }
    }
    cmeConstructContentRowFree();
    return (0);
}
