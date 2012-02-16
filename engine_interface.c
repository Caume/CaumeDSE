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
{
    int cont,cont2,result,written,written2;
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
    char *errMsg=NULL;
    char *currentDocumentId=NULL;
    char *bkpFName=NULL;
    char *sqlTableName="data"; //default table name for memory databases
    unsigned char *decodedEncryptedString=NULL;
    sqlite3 **memDBcol=NULL;
    //TODO (OHR#2#): EVERYWHERE - Change breaks for returns(), In all functions! Use the following multiline macro template.
    //MEMORY CLEANUP MACRO for local function.
    #define cmeSecureDBToMemDBFree() \
        do { \
            cmeFree(currentDocumentId); \
            cmeFree(resultMemTable); \
            cmeFree (bkpFName); \
            cmeFree (decodedEncryptedString); \
            for (cont=0;cont<dbNumCols;cont++) \
            { \
                if (memDBResultData) \
                { \
                    cmeMemTableFinal(memDBResultData[cont]); \
                } \
                if (memDBResultMeta) \
                { \
                    cmeMemTableFinal(memDBResultMeta[cont]); \
                } \
                if (colSQLDBfNames) \
                { \
                    cmeFree(colSQLDBfNames[cont]); \
                } \
            } \
            cmeFree(colSQLDBfNames); \
        } while (0) /*NOTE: No need to free each element in resultMemTable, as they are just pointers to elements
                      from memDBResultData and memDBResultMeta.
                      //WIPING SENSITIVE DATA IN MEMORY AFTER USE in colSQLDBfNames!*/

    result=cmeMemTable(pResourcesDB,"SELECT * FROM documents",&queryResult,&numRows,&numCols,
                       &errMsg);
    if(result) // Error
    {
        cmeSecureDBToMemDBFree(); //CLEANUP.
        return(1);
    }
    //Get list of column files from ResourcesDB
    colSQLDBfNames=(char **)malloc(sizeof(char *)*cmeMaxCSVColumns*cmeMaxCSVPartsPerColumn); //We reserve memory for the estimated max. number of column parts to handle.
    for (cont=0;cont<cmeMaxCSVColumns*cmeMaxCSVPartsPerColumn;cont++) // TODO (ANY#2#): Replace MAX method with a more efficient way to allocate memory!
    {
        colSQLDBfNames[cont]=NULL; //Initialize pointers to column names.
    }
    for(cont=1;cont<=numRows;cont++) //First row in a cmeSQLTable contains the names of columns; we skip them.
    {
        result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_documentId],     //Protected value (B64+encrypted+salted)
                                         &currentDocumentId,                //Unencrypted result (documentId)
                                         cmeDefaultEncAlg,
                                         &(queryResult[(cont*numCols)+cmeIDDanydb_salt]),  //Salt used to protect value
                                         orgKey,&written);
        if (result)  //Error
        {
            cmeSecureDBToMemDBFree(); //CLEANUP.
            return(2);
        }
        if ((!(strncmp(currentDocumentId,documentId,strlen(currentDocumentId))))&&
            (strlen(currentDocumentId)==strlen(documentId)))  //This column is part of the table!
        {
            result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile],     //Protected value (B64+encrypted+salted)
                                             &(colSQLDBfNames[dbNumCols]),       //Unencrypted result (columnFile)
                                             cmeDefaultEncAlg,
                                             &(queryResult[(cont*numCols)+cmeIDDanydb_salt]),  //Salt used to protect value
                                             orgKey,&written2);
            if (result)  //Error
            {
                cmeSecureDBToMemDBFree(); //CLEANUP.
                return(3);
            }
            else
            {
                dbNumCols++;
            }
        }
        //TODO (OHR#2#): EVERYWHERE - Research memset() replacement to ensure delete with volatile; assess mlock ().
        memset(currentDocumentId,0,written);   //WIPING SENSITIVE DATA IN MEMORY AFTER USE!
        cmeFree(currentDocumentId);
    }
    memDBcol=(sqlite3 **)malloc(sizeof(sqlite3 *)*dbNumCols);
    memDBResultMeta=(char ***)malloc(sizeof(char **)*dbNumCols);
    memDBResultData=(char ***)malloc(sizeof(char **)*dbNumCols);
    for (cont=0;cont<dbNumCols;cont++)
    {
        memDBcol[cont]=NULL;
        memDBResultMeta[cont]=NULL;
        memDBResultData[cont]=NULL;
    }
    for (cont=0;cont<dbNumCols;cont++) //Load protected columns
    {
        cmeStrConstrAppend(&bkpFName,"%s%s",storagePath,colSQLDBfNames[cont]);
        if (cmeDBCreateOpen(":memory:",&(memDBcol[cont])))
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSecureSQLToMemDB(), cmeDBCreateOpen() Error, can't "
                    "Create and Open memory DB to import secure colFiles; colFile No. %d!\n",cont);
#endif
            cmeDBClose(*resultDB);
            cmeSecureDBToMemDBFree(); //CLEANUP.
            return(4);
        }
        result=cmeMemDBLoadOrSave(memDBcol[cont],bkpFName,0);
        if (result) //Error
        {
            cmeFree(bkpFName);
            cmeSecureDBToMemDBFree(); //CLEANUP.
            return(5);
        }
        cmeFree(bkpFName);
    }
    result=cmeMemSecureDBReintegrate(memDBcol,orgKey,dbNumCols,&dbNumReintegratedCols);
    for (cont=0;cont<dbNumReintegratedCols;cont++)
    {
        result=cmeMemSecureDBUnprotect(memDBcol[cont],orgKey); //Unprotect secure column DB.
        if (result) //Error
        {
            cmeSecureDBToMemDBFree(); //CLEANUP.
            return(6);
        }
        result=cmeMemTable(memDBcol[cont],"SELECT * FROM meta",&(memDBResultMeta[cont]),
                           &numRowsMeta,&numColsMeta,&errMsg);
        if(result) // Error
        {
            cmeSecureDBToMemDBFree(); //CLEANUP.
            return(7);
        }
        result=cmeMemTable(memDBcol[cont],"SELECT * FROM data",&(memDBResultData[cont]),
                           &numRows,&numCols,&errMsg);
        if(result) // Error
        {
            cmeSecureDBToMemDBFree(); //CLEANUP.
            return(8);
        }
        cmeFree(bkpFName);
    }
    dbNumRows=numRows;
    for (cont=0;cont<dbNumReintegratedCols;cont++) //Free stuff.
    {
        cmeDBClose(memDBcol[cont]);
    }
    cmeFree(memDBcol);
    *resultDB=NULL;
    if (cmeDBCreateOpen(":memory:",resultDB))
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSecureSQLToMemDB(), cmeDBCreateOpen() Error, can't "
                "Create and Open memory DB to store unprotected DB created from colFiles!\n");
#endif
        cmeDBClose(*resultDB);
        cmeSecureDBToMemDBFree(); //CLEANUP.
        return(9);
    }
    resultMemTable=(char **)malloc(sizeof(char *)*dbNumReintegratedCols*(dbNumRows+1)); //Consider 1 extra row for column names!
    if (!resultMemTable) //Error
    {
        cmeSecureDBToMemDBFree(); //CLEANUP.
        return(10);
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
        return(11);
    }
    //Free the rest of dynamically allocated resources that are no longer needed.
    for (cont=0;cont<dbNumReintegratedCols;cont++) //Wipe sensitive data after use
    {
        memset(colSQLDBfNames[cont],0,written2);
    }
    cmeSecureDBToMemDBFree();
    return(0);
}

int cmeDeleteSecureDB (sqlite3 *pResourcesDB,const char *documentId, const char *orgKey, const char *storagePath)
{
    int cont,result,written,written2;
    int numRows=0;
    int numCols=0;
    int dbNumCols=0;
    int *colsSQLDBIds=NULL;
    char *errMsg=NULL;
    char *currentDocumentId=NULL;
    char *currentFName=NULL;
    char *sqlQuery=NULL;
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
            for (cont=0;cont<dbNumCols;cont++) \
            { \
                if (colSQLDBfNames) \
                { \
                    cmeFree(colSQLDBfNames[cont]); \
                } \
            } \
            cmeFree(colSQLDBfNames); \
        } while (0) //Local free() macro.

    result=cmeSecureDBToMemDB(&existsDB,pResourcesDB,documentId,orgKey,storagePath);
    existRows=sqlite3_last_insert_rowid(existsDB);
    cmeDBClose(existsDB);
    if (existRows>0) //We have the same documentId already in the database...
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeDeleteSecureDB(), documentId %s already exists; "
                "proceeding to delete it.\n",documentId);
#endif
        result=cmeMemTable(pResourcesDB,"SELECT * FROM documents;",&queryResult,&numRows,&numCols,
                           &errMsg);
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
            result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+7],     //Protected value (B64+encrypted+salted)
                                         &currentDocumentId,                //Unencrypted result (documentId)
                                         cmeDefaultEncAlg,
                                         &(queryResult[(cont*numCols)+3]),  //Salt used to protect value
                                         orgKey,&written);
            if (result)  //Error
            {
                cmeDeleteSecureDBFree();
                return(2);
            }
            if ((!(strncmp(currentDocumentId,documentId,strlen(currentDocumentId))))&&
                (strlen(currentDocumentId)==strlen(documentId)))  //This column is part of the table!
            {
                result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+5],     //Protected value (B64+encrypted+salted)
                                                 &(colSQLDBfNames[dbNumCols]),       //Unencrypted result (columnFile)
                                                 cmeDefaultEncAlg,
                                                 &(queryResult[(cont*numCols)+3]),  //Salt used to protect value
                                                 orgKey,&written2);
                colsSQLDBIds[dbNumCols]=atoi(queryResult[cont*numCols]);            //Store register ID; register will be deleted from resourcesDB index.
                if (result)  //Error
                {
                    cmeDeleteSecureDBFree();
                    return(3);
                }
                dbNumCols++;
            }
            memset(currentDocumentId,0,written);   //WIPING SENSITIVE DATA IN MEMORY AFTER USE!
            cmeFree(currentDocumentId);
        }
        for(cont=0; cont <dbNumCols; cont++)
        {
            //Delete from ResourcesDB.
            cmeStrConstrAppend(&sqlQuery,"BEGIN;"
                               "DELETE FROM documents WHERE id=%d;"
                               "COMMIT;",colsSQLDBIds[cont]);
            result=cmeSQLRows(pResourcesDB,sqlQuery,NULL,NULL,&errMsg);
            cmeFree(sqlQuery);
            if (result)
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeDeleteSecureDB(), cmeSQLRows() Error, can't "
                        "delete secureDB column, query: %s; Error: %s!\n",sqlQuery,errMsg);
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
    int result,cont,cont2,cont3;
    int valueLen=0;
    int numMatch=0;
    int numRows=0;
    int numColumns=0;
    char *query=NULL;
    char *errMsg=NULL;
    char *decryptedValue=NULL;
    char **resultsRegTmp=NULL;
    char **sqlTable=NULL;
    #define cmeGetUnprotectDBRegisterFree() \
        do { \
            cmeFree(query); \
            cmeFree(decryptedValue); \
            if (sqlTable) \
            { \
                cmeMemTableFinal(sqlTable); \
            } \
        } while (0) //Local free() macro.

    *numResultRegisters=0;
    //1st Load all encrypted registers in a memTable.
    //TODO (OHR#3#): Check alternative for enabling tables with no results to return column names as 1st row;
    //               'PRAGMA empty_result_callbacks = ON' is deprecated according to SQLITE 3 docs!
    cmeStrConstrAppend(&query,"PRAGMA empty_result_callbacks = ON; SELECT * FROM %s;",
                       tableName);
    result=cmeMemTable(pDB,(const char *)query,&sqlTable,&numRows,&numColumns,&errMsg);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeGetUnprotectDBRegister(), cmeMemTable() Error, can't "
                "execute query %s in table:%s; Error: %s\n",query,tableName,errMsg);
#endif
        cmeGetUnprotectDBRegisterFree();
        return(1);
    }
    *numResultRegisterCols=numColumns;
    *resultRegisterCols=(char **)malloc(sizeof(char *)*numColumns);  //Allocate space for columNames.
    for (cont=0;cont<numColumns;cont++) //First copy all column names in the first row.
    {
        (*resultRegisterCols)[cont]=NULL; //cmeStrContrAppend requires this for new strings.
        cmeStrConstrAppend(&((*resultRegisterCols)[cont]),"%s",sqlTable[cont]); //Add header names (row 0).
    }
    for (cont=1;cont<=numRows;cont++) //Process each row (ignore row 0 with column header names)
    {
        numMatch=0;
        if (numColumnValues!=0) //If ==0, we process all rows (e.g. GET user class).
        {
            for (cont2=0;cont2<numColumns;cont2++) //Process each column - first search for filter matches.
            {
                for (cont3=0;cont3<numColumnValues;cont3++) //Check each relevant column by name.
                {
                    if(strcmp(sqlTable[cont2],columnNames[cont3])==0) //Matches column name.
                    {
                        if ((strcmp(sqlTable[cont2],"id")!=0)&&(strcmp(sqlTable[cont2],"salt")!=0)
                            &&(sqlTable[cont*numColumns+cont2]!=NULL))  //We decrypt and compare, except if column name is 'id' or 'salt'.
                        {   //If cmeUnprotectDBValue() !=0, value can't be decrypted with the key provided (2) or is NULL (1)! No need to compare incorrectly decrypted values!
                            if(!cmeUnprotectDBValue(sqlTable[cont*numColumns+cont2],&decryptedValue,cmeDefaultEncAlg,
                                                    &(sqlTable[cont*numColumns+cmeIDDanydb_salt]),orgKey,&valueLen))
                            {
                                if (strlen(decryptedValue)>=cmeDefaultValueSaltCharLen) //Double check that we have the right length.
                                {   //We skip the first 16 characters of the 8 byte hexstr salt that is included at the beginning.
                                    if (strcmp(&(decryptedValue[cmeDefaultValueSaltCharLen]),columnValues[cont3])==0)  //Matches value filter.
                                    {
                                        numMatch++;
                                    }
                                }
                                else
                                {   //We don't skip the first 16 characters of the 8 byte hexstr salt that is included at the beginning.
                                    if (strcmp(decryptedValue,columnValues[cont3])==0)  //Matches value filter.
                                    {
                                        numMatch++;
                                    }
#ifdef DEBUG
                                    fprintf(stderr,"CaumeDSE Debug: cmeGetUnprotectDBRegister(), cmeUnprotectDBValue() Warning, value '%s' "
                                            "of column name '%s' has incorrect valuesalt size!\n",decryptedValue,sqlTable[cont2]);
#endif
                                }
                            }
                            cmeFree(decryptedValue);
                        }
                        else  //We just compare ('salt' and 'id' column names).
                        {
                            if (strcmp(sqlTable[cont*numColumns+cont2],columnValues[cont3])==0)  //Matches value filter.
                            {
                                numMatch++;
                            }
                        }
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
            for (cont2=0;cont2<numColumns;cont2++) //Copy all values (unencrypted)
            {
                (*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]=NULL; //cmeStrContrAppend requires this for new strings.
                if ((cont2 !=cmeIDDanydb_salt)&&(cont2!=cmeIDDanydb_id))
                {   //If SALT or id, we just copy, everything else gets decrypted
                    result=cmeUnprotectDBValue(sqlTable[cont*numColumns+cont2],&decryptedValue,
                                            cmeDefaultEncAlg,&(sqlTable[cont*numColumns+cmeIDDanydb_salt]),
                                            orgKey,&valueLen);
                    if (result)
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeGetUnprotectDBRegister(), cmeUnprotectDBValue() Error, "
                                "decrypting value! Errorcode %d, valueLen %d.\n",result,valueLen);
#endif
                    }
                    if (strlen(decryptedValue)>=cmeDefaultValueSaltCharLen) //Double check that we have the right length
                    {
                        cmeStrConstrAppend(&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                        "%s",&(decryptedValue[cmeDefaultValueSaltCharLen])); //We skip the first 16 characters of the 8 byte hexstr salt that is included at the beginning.
                    }
                    else
                    {
                        cmeStrConstrAppend(&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                        "%s",decryptedValue); //We don't skip the first 16 characters of the 8 byte hexstr salt that is included at the beginning.
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeGetUnprotectDBRegister(), cmeUnprotectDBValue() Error, value '%s' "
                                "of column name '%s' has incorrect valuesalt size!\n",decryptedValue,sqlTable[cont2]);
#endif
                    }
                    cmeFree(decryptedValue);
                }
                else // Salt,id -> only copy value (nothing to decrypt).
                {
                    cmeStrConstrAppend(&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                       "%s",sqlTable[cont*numColumns+cont2]);
                }
            }
        }
    }

    return(0);
}

int cmeDeleteUnprotectDBRegisters (sqlite3 *pDB, const char *tableName, const char **columnNames,
                                const char **columnValues,const int numColumnValues, char ***resultRegisterCols,
                                int *numResultRegisterCols, int *numResultRegisters, const char *orgKey)
{
    int result,cont,cont2,cont3;
    int valueLen=0;
    int numMatch=0;
    int numRows=0;
    int numColumns=0;
    char *regId=NULL;
    char *query=NULL;
    char *errMsg=NULL;
    char *decryptedValue=NULL;
    char **resultsRegTmp=NULL;
    char **sqlTable=NULL;
    #define cmeDeleteUnprotectDBRegisterFree() \
        do { \
            cmeFree(query); \
            cmeFree(decryptedValue); \
            cmeFree(regId); \
            if (sqlTable) \
            { \
                cmeMemTableFinal(sqlTable); \
            } \
        } while (0) //Local free() macro.

    *numResultRegisters=0;
    //1st Load all encrypted registers in a memTable.
    //TODO (OHR#3#): Check alternative for enabling tables with no results to return column names as 1st row;
    //               'PRAGMA empty_result_callbacks = ON' is deprecated according to SQLITE 3 docs!
    cmeStrConstrAppend(&query,"PRAGMA empty_result_callbacks = ON; SELECT * FROM %s;",
                       tableName);
    result=cmeMemTable(pDB,(const char *)query,&sqlTable,&numRows,&numColumns,&errMsg);
    cmeFree(query);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeDeleteUnprotectDBRegister(), cmeMemTable() Error, can't "
                "execute query %s in table:%s; Error: %s\n",query,tableName,errMsg);
#endif
        cmeDeleteUnprotectDBRegisterFree();
        return(1);
    }
    *numResultRegisterCols=numColumns;
    *resultRegisterCols=(char **)malloc(sizeof(char *)*numColumns);  //Allocate space for columNames.
    for (cont=0;cont<numColumns;cont++) //First copy all column names in the first row.
    {
        (*resultRegisterCols)[cont]=NULL; //cmeStrContrAppend requires this for new strings.
        cmeStrConstrAppend(&((*resultRegisterCols)[cont]),"%s",sqlTable[cont]); //Add header names (row 0).
    }
    for (cont=1;cont<=numRows;cont++) //Process each row (ignore row 0 with column header names)
    {
        numMatch=0; //Reset match counter.
        if (numColumnValues!=0) //If ==0, we process all rows (e.g. GET user class).
        {
            for (cont2=0;cont2<numColumns;cont2++) //Process each column - first search for filter matches.
            {
                for (cont3=0;cont3<numColumnValues;cont3++) //Check each relevant column by name.
                {
                    if(strcmp(sqlTable[cont2],columnNames[cont3])==0) //Matches column name.
                    {
                        if ((strcmp(sqlTable[cont2],"id")!=0)&&(strcmp(sqlTable[cont2],"salt")!=0)
                            &&(sqlTable[cont*numColumns+cont2]!=NULL))  //We decrypt and compare, except if column name is 'id' or 'salt'.
                        {
                            cmeUnprotectDBSaltedValue(sqlTable[cont*numColumns+cont2],&decryptedValue,cmeDefaultEncAlg,
                                                &(sqlTable[cont*numColumns+cmeIDDanydb_salt]),orgKey,&valueLen);
                            if (strcmp(decryptedValue,columnValues[cont3])==0)  //Matches value filter.
                            {
                                numMatch++;
                            }
                            cmeFree(decryptedValue);
                        }
                        else  //We just compare ('salt' and 'id' column names).
                        {
                            if (strcmp(sqlTable[cont*numColumns+cont2],columnValues[cont3])==0)  //Matches value filter.
                            {
                                numMatch++;
                            }
                        }
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
                fprintf(stderr,"CaumeDSE Error: cmeDeleteUnprotectDBRegister(), realloc() Error, can't "
                        "allocate new memory block of size: %lu\n",sizeof(char *)*numColumns*((*numResultRegisters)+1));
#endif
                cmeDeleteUnprotectDBRegisterFree();
                return(2);
            }

            for (cont2=0;cont2<numColumns;cont2++) //Copy all values (unencrypted)
            {
                (*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]=NULL; //cmeStrContrAppend requires this for new strings.
                if ((cont2 !=cmeIDDanydb_salt)&&(cont2!=cmeIDDanydb_id))
                {   //Decrypt saltes value (if value is not salted cmeUnprotectDBSaltedValue() will take care of it).
                    cmeUnprotectDBSaltedValue(sqlTable[cont*numColumns+cont2],&decryptedValue,
                                              cmeDefaultEncAlg,&(sqlTable[cont*numColumns+cmeIDDanydb_salt]),
                                              orgKey,&valueLen);
                    cmeStrConstrAppend(&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                        "%s",decryptedValue);
                    cmeFree(decryptedValue);
                }
                else // Salt,id -> only copy value (nothing to decrypt).
                {
                    cmeStrConstrAppend(&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                       "%s",sqlTable[cont*numColumns+cont2]);
                    if (cont2==cmeIDDanydb_id)
                    {
                        cmeStrConstrAppend(&regId,"%s",sqlTable[cont*numColumns+cont2]);
                    }
                }
            }
            cmeStrConstrAppend(&query,"DELETE FROM %s WHERE id=%s;",tableName,regId);
            cmeFree(regId);
            result=cmeSQLRows(pDB,(const char *)query,NULL,NULL,&errMsg);
            cmeFree(query);
            if (result) //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeDeleteUnprotectDBRegister(), sql Error, can't "
                        "DELETE, statement: %s\n",query);
#endif
                cmeDeleteUnprotectDBRegisterFree();
                return(3);
            }
        }
    }
    cmeDeleteUnprotectDBRegisterFree();
    return(0);
}

int cmePostProtectDBRegister (sqlite3 *pDB, const char *tableName, const char **columnNames,
                              const char **columnValues,const int numColumnValues, const char *orgKey)
{   //NOTE: Authorization and parameter validation takes place outside (at web interface level!).
    int cont,result,protectedValueLen;
    char *sqlStatement=NULL;
    char *protectedValue=NULL;
    char *salt=NULL;
    char *errMsg=NULL;
    #define cmePostProtectDBRegisterFree() \
        do { \
            cmeFree(sqlStatement); \
            cmeFree(protectedValue); \
            cmeFree(salt); \
        } while (0) //Local free() macro.

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
            cmeStrConstrAppend(&sqlStatement,"'%s'",protectedValue); //add encrypted (salted) column value to query.
            cmeFree(protectedValue);
            if ((cont+1)<numColumnValues)  //Still one left...
            {
                cmeStrConstrAppend(&sqlStatement,","); //add comma.
            }
        }
    }
    cmeStrConstrAppend (&sqlStatement,",'%s'); COMMIT;",salt); //Last part.
    result=cmeSQLRows(pDB,sqlStatement,NULL,NULL,&errMsg);
    if (result) //Error.
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmePostProtectDBRegister(), cmeSQLRows() Error, can't "
                "create register in table: %s with sql statement %s! Error: %s\n",tableName,sqlStatement,errMsg);
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
    int result,cont,cont2,cont3;
    int valueLen=0;
    int numMatch=0;
    int numRows=0;
    int numColumns=0;
    int encryptedValueLen=0;
    char *regId=NULL;
    char *query=NULL;
    char *errMsg=NULL;
    char *decryptedValue=NULL;
    char *encryptedValue=NULL;
    char *valueSalt=NULL;
    char *saltedValue=NULL;
    char **resultsRegTmp=NULL;
    char **sqlTable=NULL;
    #define cmePutProtectDBRegisterFree() \
        do { \
            cmeFree(query); \
            cmeFree(regId); \
            cmeFree(decryptedValue); \
            cmeFree(encryptedValue); \
            cmeFree(valueSalt); \
            cmeFree(saltedValue); \
            if (sqlTable) \
            { \
                cmeMemTableFinal(sqlTable); \
            } \
        } while (0) //Local free() macro.

    *numResultRegisters=0;
    //1st Load all encrypted registers in a memTable.
    //TODO (OHR#3#): Check alternative for enabling tables with no results to return column names as 1st row;
    //               'PRAGMA empty_result_callbacks = ON' is deprecated according to SQLITE 3 docs!
    cmeStrConstrAppend(&query,"PRAGMA empty_result_callbacks = ON; SELECT * FROM %s;",
                       tableName);
    result=cmeMemTable(pDB,(const char *)query,&sqlTable,&numRows,&numColumns,&errMsg);
    cmeFree(query);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmePutProtectDBRegister(), cmeMemTable() Error, can't "
                "execute query %s in table:%s; Error: %s\n",query,tableName,errMsg);
#endif
        cmePutProtectDBRegisterFree();
        return(1);
    }
    *numResultRegisterCols=numColumns;
    *resultRegisterCols=(char **)malloc(sizeof(char *)*numColumns);  //Allocate space for columNames.
    for (cont=0;cont<numColumns;cont++) //First copy all column names in the first row.
    {
        (*resultRegisterCols)[cont]=NULL; //cmeStrContrAppend requires this for new strings.
        cmeStrConstrAppend(&((*resultRegisterCols)[cont]),"%s",sqlTable[cont]); //Add header names (row 0).
    }
    for (cont=1;cont<=numRows;cont++) //Process each row (ignore row 0 with column header names)
    {
        numMatch=0;
        if (numColumnValues!=0) //If ==0, we process all rows (e.g. PUT user class).
        {
            for (cont2=0;cont2<numColumns;cont2++) //Process each column - first search for filter matches.
            {
                for (cont3=0;cont3<numColumnValues;cont3++) //Check each relevant column by name.
                {
                    if(strcmp(sqlTable[cont2],columnNames[cont3])==0) //Matches column name.
                    {
                        if ((strcmp(sqlTable[cont2],"id")!=0)&&(strcmp(sqlTable[cont2],"salt")!=0)
                            &&(sqlTable[cont*numColumns+cont2]!=NULL))  //We decrypt and compare, except if column name is 'id' or 'salt'.
                        {
                            cmeUnprotectDBValue(sqlTable[cont*numColumns+cont2],&decryptedValue,cmeDefaultEncAlg,
                                                &(sqlTable[cont*numColumns+cmeIDDanydb_salt]),orgKey,&valueLen);
                            if (strlen(decryptedValue)>=cmeDefaultValueSaltCharLen) //Double check that we have the right length.
                            {   //We skip the first 16 characters of the 8 byte hexstr salt that is included at the beginning.
                                if (strcmp(&(decryptedValue[cmeDefaultValueSaltCharLen]),columnValues[cont3])==0)  //Matches value filter.
                                {
                                    numMatch++;
                                }
                            }
                            else
                            {   //We don't skip the first 16 characters of the 8 byte hexstr salt that is included at the beginning.
                                if (strcmp(decryptedValue,columnValues[cont3])==0)  //Matches value filter.
                                {
                                    numMatch++;
                                }
#ifdef ERROR_LOG
                                fprintf(stderr,"CaumeDSE Error: cmePutProtectDBRegister(), cmeUnprotectDBValue() Error, value '%s' "
                                        "of column name '%s' has incorrect valuesalt size!\n",decryptedValue,sqlTable[cont2]);
#endif
                            }
                            cmeFree(decryptedValue);
                        }
                        else  //We just compare ('salt' and 'id' column names).
                        {
                            if (strcmp(sqlTable[cont*numColumns+cont2],columnValues[cont3])==0)  //Matches value filter.
                            {
                                numMatch++;
                            }
                        }
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
                fprintf(stderr,"CaumeDSE Error: cmePutProtectDBRegister(), realloc() Error, can't "
                        "allocate new memory block of size: %lu\n",sizeof(char *)*numColumns*((*numResultRegisters)+1));
#endif
                cmePutProtectDBRegisterFree();
                return(2);
            }
            for (cont2=0;cont2<numColumns;cont2++) //Copy all values (unencrypted)
            {
                (*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]=NULL; //cmeStrContrAppend requires this for new strings.
                if ((cont2 !=cmeIDDanydb_salt)&&(cont2!=cmeIDDanydb_id))
                {   //If SALT or id, we just copy, everything else gets decrypted
                    cmeUnprotectDBValue(sqlTable[cont*numColumns+cont2],&decryptedValue,
                                        cmeDefaultEncAlg,&(sqlTable[cont*numColumns+cmeIDDanydb_salt]),
                                        orgKey,&valueLen);
                    if (strlen(decryptedValue)>=cmeDefaultValueSaltCharLen) //Double check that we have the right length
                    {
                        cmeStrConstrAppend(&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                        "%s",&(decryptedValue[cmeDefaultValueSaltCharLen])); //We skip the first 16 characters of the 8 byte hexstr salt that is included at the beginning.
                    }
                    else
                    {
                        cmeStrConstrAppend(&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                        "%s",decryptedValue); //We don't skip the first 16 characters of the 8 byte hexstr salt that is included at the beginning.
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmePutProtectDBRegister(), cmeUnprotectDBValue() Error, value '%s' "
                                "of column name '%s' has incorrect valuesalt size!\n",decryptedValue,sqlTable[cont2]);
#endif
                    }
                    cmeFree(decryptedValue);
                }
                else // Salt,id -> only copy value (nothing to decrypt).
                {
                    cmeStrConstrAppend(&((*resultRegisterCols)[(*numResultRegisters)*numColumns+cont2]),
                                       "%s",sqlTable[cont*numColumns+cont2]);
                    if (cont2==cmeIDDanydb_id)
                    {
                        cmeStrConstrAppend(&regId,"%s",sqlTable[cont*numColumns+cont2]);
                    }
                }
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
                else //Encrypt first
                {
                    cmeGetRndSaltAnySize(&valueSalt,cmeDefaultValueSaltLen);    //Get random salt (16 character 8 byte hexstring).
                    cmeStrConstrAppend(&saltedValue,"%s%s",valueSalt,columnValuesUpdate[cont2]);  //Append unencrypted value to random salt.
                    cmeFree(valueSalt);
                    cmeProtectDBValue(saltedValue,&encryptedValue,cmeDefaultEncAlg,
                                      &((*resultRegisterCols)[(*numResultRegisters)*numColumns+cmeIDDanydb_salt]),
                                      orgKey,&encryptedValueLen);   //Encrypt salted value.
                    cmeFree(saltedValue);
                    cmeStrConstrAppend(&query," %s='%s'",columnNamesUpdate[cont2],encryptedValue);  //Add encrypted (salted) value to query.
                    cmeFree(encryptedValue);
                    if ((cont2+1)<numColumnValuesUpdate) //Still another value left...
                    {
                        cmeStrConstrAppend(&query,",");
                    }
                }
            }
            cmeStrConstrAppend(&query," WHERE id=%s;",regId); //Last part.
            cmeFree(regId);
            result=cmeSQLRows(pDB,(const char *)query,NULL,NULL,&errMsg);
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

