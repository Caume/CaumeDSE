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

//TODO (OHR#5#):create and call function to sanitize all input that will be included in DB queries!
int cmeDBCreateOpen (const char *filename, sqlite3 **ppDB)
{
    int result;

    result = sqlite3_open_v2(filename, ppDB,SQLITE_OPEN_READWRITE|
                             SQLITE_OPEN_CREATE|SQLITE_OPEN_FULLMUTEX, NULL);
    if (result!=SQLITE_OK)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeDBCreateOpen(), sqlite_open_v2() error: %s\n",
                sqlite3_errmsg(*ppDB));
#endif
        sqlite3_close(*ppDB);
        return(1);
    }
    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeDBCreateOpen(), Created/opened sqlite3 database file: %s.\n",filename);
#endif
        return(0);
    }
}

int cmeDBOpen (const char *filename, sqlite3 **ppDB)
{
    int result;

    result = sqlite3_open_v2(filename, ppDB,SQLITE_OPEN_READWRITE|
                             SQLITE_OPEN_FULLMUTEX, NULL);
    if (result!=SQLITE_OK)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeDBOpen(), sqlite_open_v2() error: %s\n",
                sqlite3_errmsg(*ppDB));
#endif
        sqlite3_close(*ppDB);
        return(1);
    }
    else
    {
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeDBOpen(), Opened sqlite3 database file: %s.\n",filename);
#endif
        return(0);
    }
}

int cmeDBClose (sqlite3 *ppDB)
{
    int  result=0;
    result=sqlite3_close(ppDB);
    if (result!=SQLITE_OK)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeDBClose(), sqlite_close() error: %s\n",
                sqlite3_errmsg(ppDB));
#endif
        return(1);
    }
    else
    {
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeDBClose(), Closed sqlite3 database file.\n");
#endif
        return(0);
    }
}

//Based on code from: http://www.sqlite.org/backup.html
int cmeMemDBLoadOrSave(sqlite3 *pInMemory, const char *zFilename, int isSave)
{
    int result=0;
    sqlite3 *pFile=NULL;
    sqlite3_backup *pBackup=NULL;
    sqlite3 *pTo=NULL;
    sqlite3 *pFrom=NULL;

    if(isSave) // we save
    {
        result=cmeDBCreateOpen(zFilename,&pFile);
    }
    else //we load
    {
        result=cmeDBOpen(zFilename,&pFile);
    }
    if (result) //Error Opening or creating file.
    {
        return(1);
    }
    else //Everything is ok now.
    {
        // If this is a 'load' operation (isSave==0), then data is copied
        // from the database file to database pInMemory.
        // Otherwise, data is copied from pInMemory to pFile.
        // TODO (ANY#8#): if isSave, Vacuum mem first, then save!
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeDBMemLoadOrSave(), Opened DB file %s for "
                "R/W successfuly. isSave: %d \n",zFilename, isSave);
#endif
        pFrom = (isSave ? pInMemory : pFile);
        pTo   = (isSave ? pFile     : pInMemory);
        // Set up the backup procedure to copy from the "main" database of
        // connection pFile to the main database of connection pInMemory.
        pBackup = sqlite3_backup_init(pTo, "main", pFrom, "main");
        if( pBackup )
        {
          (void)sqlite3_backup_step(pBackup, -1);  //Copy full database at once.
          (void)sqlite3_backup_finish(pBackup);
        }
        result = sqlite3_errcode(pTo);
    }
    cmeDBClose(pFile); // Close the database connection opened on database file zFilename
    return (result);
}

int cmeSQLIterate (const char *args,int numCols,char **pStrResults,char **pColNames)
{
    int cont,cont2,result;
    int maxResults=0;
    int returnedResults=0;
    char **perlResults=NULL;
    char *fName=NULL;
    char *sqlStatemnt=NULL;
    #define cmeSQLIterateFree() \
        do { \
            cmeFree(fName); \
            cmeFree(sqlStatemnt); \
            if (perlResults) \
            { \
               for (cont=0; cont<returnedResults;cont++) \
               { \
                   cmeFree(perlResults[cont]); \
               } \
               cmeFree(perlResults); \
            } \
        } while (0) //Local free() macro.

    cmeStrConstrAppend(&fName,"%s",(char *)args);
    maxResults=numCols;
    perlResults=(char **)malloc((sizeof(char *))*numCols);
    if (!cmeResultMemTable)//If this is the first iteration (i.e. cmeResultMemTable==NULL).
    {
        cmeResultMemTableCols=numCols; //Set column names of Tmp MemTable.
        cmeResultMemTable=(char **)malloc(sizeof(char*)*numCols); //There can't be more results than there are columns (as of this version).

        result=cmePerlParserScriptFunction(cmeDefaultPerlColNameSetupFunction,cdsePerl,pColNames,numCols,     //Send column names on first iteration to special subroutine "cmePERLProcessColumnNames"
                                           perlResults,maxResults,&returnedResults);
        if (result)  //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSQLIterate(), Error in cmePerlParserScriptFunction()"
                    ": %d.\n",result);
#endif
            cmeSQLIterateFree();
            return(result);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeSQLIterate(), Prepared %d results"
                " from perl function %s (first iteration).\n",returnedResults,cmeDefaultPerlColNameSetupFunction);
#endif
        for(cont=0;cont<numCols;cont++) //Copy column names
        {
            cmeResultMemTable[cont]=NULL;
            if (returnedResults==numCols) // If script returned column names (modified?) then use them
            {
                cmeStrConstrAppend(&(cmeResultMemTable[cont]),"%s",perlResults[numCols -1 -cont]);
            }
            else //Otherwise use the column names provided to this function
            {
                cmeStrConstrAppend(&(cmeResultMemTable[cont]),"%s",pColNames[cont]);
            }
        }
        cmeResultMemTableRows=0; //Column names are always included (row 0), even if row count ignores them.
    }
    for (cont=0; cont<returnedResults;cont++) //Free results from first iteration (columns), if any...
    {
       cmeFree(perlResults[cont]);
    }
    cmeResultMemTableRows++; //Increase the number of rows included in the Tmp MemTable.
    cmeResultMemTable=(char **)realloc(cmeResultMemTable,sizeof(char*)*(cmeResultMemTableCols*cmeResultMemTableRows+numCols)); //Add space for one additional row
    if (!cmeResultMemTable) //Realloc error.
    {
        return(1);
    }
    for (cont=(cmeResultMemTableCols*cmeResultMemTableRows);cont<(cmeResultMemTableCols*cmeResultMemTableRows+numCols);cont++)
    {
        cmeResultMemTable[cont]=NULL; //initialize new row pointers.
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeSQLIterate(), Prepared to iterate on a row with"
            " the following %d columns and values:\n",numCols);
    for (cont=0; cont<numCols; cont++)
    {
        fprintf(stdout,"\t\t%d) col.name:%s value:%s\n",cont+1,pColNames[cont],pStrResults[cont]);
    }
#endif
    result=cmePerlParserScriptFunction(fName,cdsePerl,pStrResults,numCols,
                                        perlResults,maxResults,&returnedResults);
    if (result)  //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSQLIterate(), Error in cmePerlParserScriptFunction()"
                ": %d.\n",result);
#endif
        cmeSQLIterateFree();
        return(result);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeSQLIterate(), Prepared %d results"
            " from perl function %s.\n",returnedResults,fName);
#endif
    cont2=cmeResultMemTableCols*cmeResultMemTableRows;
    for (cont=returnedResults-1; cont>=0; cont--)         //pop results from the stack in reverse (correct) order
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeSQLIterate(), cmePerlParserScriptFunction() result %d:"
                " %s.\n",cont+1,perlResults[cont]);
#endif
        cmeStrConstrAppend(&(cmeResultMemTable[cont2]),"%s",perlResults[cont]);
        cont2++;
    }
    cmeSQLIterateFree();
    return(0);
}

int cmeSQLRows (sqlite3 *db, const char *sqlQuery, char *perlScriptName,
                PerlInterpreter *myPerl)
{
    int result,cont,cont2,numCols;
    int regCount=0;
    sqlite3_stmt *sqlStatemnt=NULL;
    char **columnNames=NULL;
    char **columnValues=NULL;
    const char *pSqlInstruction=NULL;
    const char *tail;
    const char *errMsg;
    #define cmeSQLRowsFree() \
        do { \
            cmeFree(columnNames); \
            cmeFree(columnValues); \
        } while (0) //Local free() macro.

    if (myPerl==NULL) //No Callback function defined
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeSQLRows(), sqlite3_exec() to be called with "
                "no Callback function. Query:\n%s\n",sqlQuery);
#endif
        //0) Open connection to Database; this is done outside of this function (DB is assumed to be open).
        //1) Prepare SQL statement:
        pSqlInstruction=sqlQuery;
        do
        {
            numCols=-1; //Reset column counter for each SQL instruction.
            result = sqlite3_prepare_v2(db,pSqlInstruction,-1,&sqlStatemnt,&tail);
            if (result) // Error
            {
    #ifdef ERROR_LOG
                errMsg=sqlite3_errmsg(db);
                fprintf(stderr,"CaumeDSE Error: cmeSQLRows(), sqlite3_prepare_v2() error: %s\n",
                        errMsg);
    #endif
                cmeSQLRowsFree();
                return(2);
            }
            //2) Execute statement and get each result row:
            while (sqlite3_step(sqlStatemnt) == SQLITE_ROW)
            {
                if (numCols==-1) //First cycle.
                {
                    numCols=sqlite3_data_count(sqlStatemnt);                //Get number of columns in row.
                    columnNames=(char **)malloc(sizeof(char *)*numCols);    //Reserve memory for column names' string pointers.
                    columnValues=(char **)malloc(sizeof(char *)*numCols);   //Reserve memory for column values' string pointers.
                    for (cont=0;cont<numCols;cont++) //Point to column names.
                    {
                        columnNames[cont]=(char *)sqlite3_column_name(sqlStatemnt,cont);
                    }
                    if (cmeResultMemTable)//cmeResultMemTable is not empty, free all variables.
                    {
                        for (cont2=0;cont2<=cmeResultMemTableRows;cont2++) //Process each row. (Note that column names are put in row 0; we need to include this row).
                        {
                            for(cont=0;cont<cmeResultMemTableCols;cont++) //Process each column.
                            {
                                memset(cmeResultMemTable[cont2*cmeResultMemTableCols+cont],0,strlen(cmeResultMemTable[cont2*cmeResultMemTableCols+cont])); //Wipe sensitive data.
                                cmeFree(cmeResultMemTable[cont2*cmeResultMemTableCols+cont]);
                            }
                        }
                        cmeFree(cmeResultMemTable);
                        cmeResultMemTableCols=0;
                        cmeResultMemTableRows=0;
                    }
                    //Insert column names into new table:
                    cmeResultMemTableCols=numCols; //Set column names of Tmp MemTable.
                    cmeResultMemTable=(char **)malloc(sizeof(char*)*numCols); //There can't be more results than there are columns (for now).
                    for(cont=0;cont<numCols;cont++) //Copy column names.
                    {
                        cmeResultMemTable[cont]=NULL;
                        cmeStrConstrAppend(&(cmeResultMemTable[cont]),"%s",columnNames[cont]);
                    }
                    cmeResultMemTableRows=0; //Column names are always included (row 0), even if row count ignores them.
                }
                cmeResultMemTableRows++; //Increase the number of rows included in the Tmp MemTable.
                cmeResultMemTable=(char **)realloc(cmeResultMemTable,sizeof(char*)*(cmeResultMemTableCols*cmeResultMemTableRows+numCols)); //Add space for one additional row
                if (!cmeResultMemTable) //Realloc error.
                {
                    return(1);
                }
                for (cont=(cmeResultMemTableCols*cmeResultMemTableRows);cont<(cmeResultMemTableCols*cmeResultMemTableRows+numCols);cont++)
                {
                    cmeResultMemTable[cont]=NULL; //initialize new row pointers.
                }
                for (cont=0;cont<numCols;cont++) //Point to column values; copy values to new row.
                {
                    columnValues[cont]=(char *)sqlite3_column_text(sqlStatemnt,cont);
                    cmeStrConstrAppend(&(cmeResultMemTable[cmeResultMemTableCols*cmeResultMemTableRows+cont]),"%s",columnValues[cont]);
                }
                regCount++;
            }
    #ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeSQLRows(), sqlite3_step() cycle finished; '%d' result rows were obtained.\n",
                    regCount);
    #endif
            //3) Finalize statement:
            sqlite3_finalize(sqlStatemnt);
            //3.5) Cycle for next SQL instruction. if available
            pSqlInstruction=tail;
        } while (sqlStatemnt);
        //4)  Close DB connection; this will be done outside of this function.
    }
    else //Callback function required
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeSQLRows(), sqlite3_exec() to be called with "
                "Callback Perl function: Script name: %s. Query:\n%s\n",
                perlScriptName,sqlQuery);
#endif
        //0) Open connection to Database; this is done outside of this function (DB is assumed to be open).
        //1) Prepare SQL statement:
        pSqlInstruction=sqlQuery;
        do
        {
            numCols=-1; //Reset column counter for each SQL instruction.
            result = sqlite3_prepare_v2(db,pSqlInstruction,-1,&sqlStatemnt,&tail);
            if (result) // Error
            {
    #ifdef ERROR_LOG
                errMsg=sqlite3_errmsg(db);
                fprintf(stderr,"CaumeDSE Error: cmeSQLRows(), sqlite3_prepare_v2() error: %s\n",
                        errMsg);
    #endif
                cmeSQLRowsFree();
                return(2);
            }
            //2) Execute statement and get each result row:
            while (sqlite3_step(sqlStatemnt) == SQLITE_ROW)
            {
                if (numCols==-1) //First cycle.
                {
                    numCols=sqlite3_data_count(sqlStatemnt);                //Get number of columns in row.
                    columnNames=(char **)malloc(sizeof(char *)*numCols);    //Reserve memory for column names' string pointers.
                    columnValues=(char **)malloc(sizeof(char *)*numCols);   //Reserve memory for column values' string pointers.
                    for (cont=0;cont<numCols;cont++) //Point to column names.
                    {
                        columnNames[cont]=(char *)sqlite3_column_name(sqlStatemnt,cont);
                    }
                    if (cmeResultMemTable)//cmeResultMemTable is not empty, free all variables.
                    {
                        for (cont2=0;cont2<=cmeResultMemTableRows;cont2++) //Process each row. (Note that column names are put in row 0; we need to include this row).
                        {
                            for(cont=0;cont<cmeResultMemTableCols;cont++) //Process each column.
                            {
                                memset(cmeResultMemTable[cont2*cmeResultMemTableCols+cont],0,strlen(cmeResultMemTable[cont2*cmeResultMemTableCols+cont])); //Wipe sensitive data.
                                cmeFree(cmeResultMemTable[cont2*cmeResultMemTableCols+cont]);
                            }
                        }
                        cmeFree(cmeResultMemTable);
                        cmeResultMemTableCols=0;
                        cmeResultMemTableRows=0;
                    }
                }
                for (cont=0;cont<numCols;cont++) //Point to column values.
                {
                    columnValues[cont]=(char *)sqlite3_column_text(sqlStatemnt,cont);
                }
                //Parse each row with the script iteration function:
                cmeSQLIterate(perlScriptName,numCols,columnValues,columnNames);
                regCount++;
            }
    #ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeSQLRows(), sqlite3_step() cycle finished; '%d' result rows were obtained.\n",
                    regCount);
    #endif
            //3) Finalize statement:
            sqlite3_finalize(sqlStatemnt);
            //3.5) Cycle for next SQL instruction. if available
            pSqlInstruction=tail;
        } while (sqlStatemnt);
        //4)  Close DB connection; this will be done outside of this function.
    }
    cmeSQLRowsFree();
    return(0);
}

int cmeResultMemTableClean ()
{
    int cont,cont2;

    if (cmeResultMemTable)//cmeResultMemTable is not empty, free all variables.
    {
        for (cont2=0;cont2<=cmeResultMemTableRows;cont2++) //Process each row. (Note that column names are put in row 0; we need to include this row).
        {
            for(cont=0;cont<cmeResultMemTableCols;cont++) //Process each column.
            {
                memset(cmeResultMemTable[cont2*cmeResultMemTableCols+cont],0,strlen(cmeResultMemTable[cont2*cmeResultMemTableCols+cont])); //Wipe sensitive data.
                cmeFree(cmeResultMemTable[cont2*cmeResultMemTableCols+cont]);
            }
        }
        cmeFree(cmeResultMemTable);
        cmeResultMemTableCols=0;
        cmeResultMemTableRows=0;
    }
    return(0);
}

int cmeMemTable (sqlite3 *db, const char *sqlQuery,char ***pQueryResult,
                 int *numRows, int *numColumns)
{
    int result;    char *pzErrmsg=NULL; // TODO (OHR#2#): Delete pErrmsg from parameters; passing back errors from sqlite3 is complicated since associated memory needs to be freed with sqlite3_free. We will deal with those errors only within functions that call sqlite functions directly!
    //TODO (ANY#8#): replace call to sqlite3_get_table() with calls to sqlite3_exec() and use PRAGMA table_info
    // This is because sqlite3_get_table is apparently obsolete (??) and should be avoided, according to docs.
    result=sqlite3_get_table(db, sqlQuery, pQueryResult, numRows, numColumns,
                             &pzErrmsg);
            //NOTE: numRows does not consider the header row at index 0.
            //sqlite3_get_table allways includes a header row; real number of rows= numRows+1 !
    if (pzErrmsg!=NULL) // Then we have a problem...
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSQLTable(), sqlite3_get_table() error: %s\n",
                pzErrmsg);
        sqlite3_free(pzErrmsg);
#endif
        return(1);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeSQLTable(), sqlite3_get_table() successful.\n");
#endif
    return(0);
}

int cmeMemTableFinal (char **QueryResult)
{
    sqlite3_free_table(QueryResult);
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeSQLTableFinal(), sqlite3_free_table() executed.\n");
#endif
    return(0);
}

int cmeMemTableToMemDB (sqlite3 *dstMemDB, const char **srcMemTable, const int numRows,
                        const int numCols, char *sqlTableName)
{
    int cont,cont2,cont3,result;
    int rowsBlocks;
    int rowsLastBlock;
    int exitcode=0;
    int currentRow=1;
    char *sqlInsertQuery=NULL;
    char *sqlCreateCols=NULL;
    char *sqlInsertCols=NULL;
    const char *defaultTableName="data";

    if (!numCols) //If MemTable is empty, we do nothing and exit
    {
        return(0);
    }
    if(!sqlTableName) //if table name is empty; assign a default name
    {
        sqlTableName=(char *)defaultTableName;
    }
    rowsBlocks=numRows / cmeDefaultInsertSqlRows;
    rowsLastBlock=numRows % cmeDefaultInsertSqlRows;
    cmeStrConstrAppend(&sqlCreateCols,"id INTEGER PRIMARY KEY,"); //First add the ID.
    cmeStrConstrAppend(&sqlInsertCols,"id,"); //First insert the ID autoincrement.
    for (cont=0;cont<numCols;cont++) //Create sqlCreateCols string.
    {
        cmeStrConstrAppend(&sqlCreateCols,"'%s' TEXT",srcMemTable[cont]);  //first row, contains the column name.
        cmeStrConstrAppend(&sqlInsertCols,"'%s'",srcMemTable[cont]);
        if ((cont+1) < numCols) //If there is still another element pending, add comma.
        {
           cmeStrConstrAppend(&sqlCreateCols,",");
           cmeStrConstrAppend(&sqlInsertCols,",");
        }
    }
    cmeStrConstrAppend(&sqlInsertQuery,"BEGIN TRANSACTION; CREATE TABLE %s (%s); COMMIT;",
                       sqlTableName,sqlCreateCols); // Create table 'memtable'
    result=cmeSQLRows(dstMemDB,sqlInsertQuery,NULL,NULL);
    if (result) //Check Error Type
    {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemTableToMemDB(), cmeSQLRows() Error, can't "
                    "create table: %s (%s) !\n",sqlTableName,sqlCreateCols);
#endif
            exitcode=1;
    }
    if (!exitcode)
    {
        for (cont=0; cont < rowsBlocks; cont++) //process all blocks of cmeDefaultInsertSqlRows rows.
        {
            cmeFree(sqlInsertQuery);
            result=cmeStrConstrAppend(&sqlInsertQuery,"BEGIN TRANSACTION;"); // First part of block
            for (cont2=0; cont2 < cmeDefaultInsertSqlRows; cont2++) //Process all rows.
            {
                result=cmeStrConstrAppend(&sqlInsertQuery," INSERT INTO %s (%s) VALUES (NULL", //Prepare INSERT statement.
                                          sqlTableName,sqlInsertCols);
                if (numCols)
                {
                    result=cmeStrConstrAppend(&sqlInsertQuery,",");
                }
                for (cont3=0; cont3<numCols; cont3++) //Process all fields in row.
                {
                    result=cmeStrConstrAppend(&sqlInsertQuery,"'%s'",srcMemTable[(currentRow*numCols)+cont3]);
                    if((cont3+1)<numCols)
                    {
                        result=cmeStrConstrAppend(&sqlInsertQuery,",");
                    }
                }
                currentRow++;
                result=cmeStrConstrAppend(&sqlInsertQuery,");"); //Finish INSERT statement.
            }
            result=cmeStrConstrAppend(&sqlInsertQuery,"COMMIT;"); // Last part of block
            if (cmeSQLRows(dstMemDB,sqlInsertQuery,NULL,NULL)) //insert row.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemTableToMemDB(), cmeSQLRows() Error, can't "
                        "insert values, sqlquery: %s in table: %s !\n",sqlInsertQuery,sqlTableName);
#endif
                exitcode=2;
                break;
            }
        }
    }
    if (!exitcode)
    {
        //Process last block.
        cmeFree(sqlInsertQuery);
        result=cmeStrConstrAppend(&sqlInsertQuery,"BEGIN TRANSACTION;"); // First part of block.
        for (cont2=0; cont2 < rowsLastBlock; cont2++) //process all columns in each row.
        {
            result=cmeStrConstrAppend(&sqlInsertQuery," INSERT INTO %s (%s) VALUES (NULL", //Prepare INSERT statement.
                                      sqlTableName,sqlInsertCols);
            if (numCols)
            {
                result=cmeStrConstrAppend(&sqlInsertQuery,",");
            }
            for (cont3=0; cont3<numCols; cont3++) //Add values
            {
                result=cmeStrConstrAppend(&sqlInsertQuery,"'%s'",srcMemTable[(currentRow*numCols)+cont3]);
                if((cont3+1)<numCols)
                {
                    result=cmeStrConstrAppend(&sqlInsertQuery,",");
                }
            }
            currentRow++;
            result=cmeStrConstrAppend(&sqlInsertQuery,");"); //Finish INSERT statement.
        }
        result=cmeStrConstrAppend(&sqlInsertQuery,"COMMIT;"); // Last part of block.
        if (cmeSQLRows(dstMemDB,sqlInsertQuery,NULL,NULL)) //insert row.
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemTableToMemDB(), cmeSQLRows() Error, can't "
                    "insert values, sqlquery: %s in table: %s !\n",sqlInsertQuery,sqlTableName);
#endif
            exitcode=3;
        }
    }
    cmeFree(sqlInsertQuery);
    cmeFree(sqlInsertCols);
    cmeFree(sqlCreateCols);
    return (exitcode);
}

int cmeMemTableShuffle(char **sqlTable, const int numRows, const int numCols, const int skipHeaderRows,
                       const int skipIdCols)    //Implements Durstenfeld's shuffling algorithm
                                                //http://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
{
    int cont, cont2, rndIdx;
    unsigned int randomInt=0;
    unsigned char *prngBuf=NULL;
    unsigned char *prngBufStr=NULL;
    char *valueTmp=NULL;
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeMemTableShuffle(), preparing to shuffle MemTable with %d rows (not counting header row)"
            " and %d columns; headers to skip: %d; columns to skip: %d.\n",numRows,numCols,skipHeaderRows,
            skipIdCols);
#endif
    for (cont=numRows;cont>=skipHeaderRows; cont--) //Not cont=numRows-1, since we need to consider the header row.
    {
        cmePrngGetBytes(&prngBuf,sizeof(int));
        cmeBytesToHexstr(prngBuf,&prngBufStr,sizeof(int));
        sscanf((char *)prngBufStr,"%X",&randomInt);
        cmeFree(prngBuf);
        cmeFree(prngBufStr);
        rndIdx=(int)(randomInt%numRows);
        if (rndIdx<=(skipHeaderRows-1)) //Hits a row we need to skip.
        {
            rndIdx=(numRows); //Then exchange with a row at the other end.
        }
        for (cont2=(numCols-1);cont2>=skipIdCols;cont2--)
        {
            valueTmp=sqlTable[(cont*numCols)+cont2];
            sqlTable[(cont*numCols)+cont2]=sqlTable[(rndIdx*numCols)+cont2];
            sqlTable[(rndIdx*numCols)+cont2]=valueTmp;
        }
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeMemTableShuffle(), finished shuffling MemTable with %d rows"
            " and %d columns; headers to skip: %d; columns to skip: %d.\n",numRows,numCols,skipHeaderRows,
            skipIdCols);
#endif
    return (0);
}

int cmeMemTableOrder(char **sqlTable, const int numRows, const int numCols, const int orderIdxCol, const int skipHeaderRows,
                       const int skipIdCols)
{
    int cont,cont2,cont3;
    char *valueTmp=NULL;
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeMemTableOrder(), preparing to reorder MemTable with %d rows (not counting header row)"
            " and %d columns; headers to skip: %d; columns to skip: %d.\n",numRows,numCols,skipHeaderRows,
            skipIdCols);
#endif
    for (cont=numRows;cont>=skipHeaderRows; cont--) //Not cont=numRows-1, since we need to consider the header row.
    {
        for (cont2=cont;cont2>=skipHeaderRows; cont2--) //Search every row <= current row for the one that belongs to this position, and swap them.
        {
            if (cont==atoi(sqlTable[(cont2*numCols)+orderIdxCol])) //We found the right row. Swap and break.
            {
                for (cont3=(numCols-1);cont3>=skipIdCols;cont3--)
                {
                    valueTmp=sqlTable[(cont*numCols)+cont3];
                    sqlTable[(cont*numCols)+cont3]=sqlTable[(cont2*numCols)+cont3];
                    sqlTable[(cont2*numCols)+cont3]=valueTmp;
                }
                break;
            }
        }

        ///orderIdx=atoi(sqlTable[(cont*numCols)+orderIdxCol]); //Get order Idx for current register.

        /**
        //While current reg. is not ordered...
        while (strcmp(sqlTable[(cont*numCols)+orderIdxCol],sqlTable[(cont*numCols)+cmeIDDanydb_id]))
        {
            if ((orderIdx<skipHeaderRows)||(orderIdx>numRows)) //Error, Idx is out of boundaries.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemTableOrder(), index for row: %d is %d "
                        "and is out of bounds, in a table with %d rows!",cont,orderIdx,numRows);
#endif
                return(1);
            }
            for (cont2=(numCols-1);cont2>=skipIdCols;cont2--)
            {
                //Swap with
                valueTmp=sqlTable[(cont*numCols)+cont2];
                sqlTable[(cont*numCols)+cont2]=sqlTable[(orderIdx*numCols)+cont2];
                sqlTable[(orderIdx*numCols)+cont2]=valueTmp;
            }
            orderIdx=atoi(sqlTable[(cont*numCols)+orderIdxCol]); //Get order Idx for new register.
        } **/
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeMemTableOrder(), finished ordering MemTable with %d rows"
            " and %d columns; headers to skip: %d; columns to skip: %d.\n",numRows,numCols,skipHeaderRows,
            skipIdCols);
#endif
    return (0);
}

int cmeMemSecureDBProtect (sqlite3 *memSecureDB, const char *orgKey)
{
    int cont,result,written;
    int cont2=0;
    int numColsData=0;
    int numRowsData=0;
    int numColsPMeta=0;
    int numRowsPMeta=0;
    char **memData=NULL;
    char **memProtectMetaData=NULL;
    char **currentDataSalt=NULL;
    char *currentEncB64Data=NULL;
    char *currentMetaAttribute=NULL;
    char *currentMetaAttributeData=NULL;
    char *currentMetaId=NULL;
    char *currentMetaSalt=NULL;
    char *currentMetaUserId=NULL;
    char *currentMetaOrgId=NULL;
    char *currentDataId=NULL;
    char *currentDataEncAlg=NULL;
    char *sqlQuery=NULL;
    unsigned char *rndBytes=NULL;
    const EVP_CIPHER *cipher=NULL;
    //MEMORY CLEANUP MACRO for local function.
    #define cmeMemSecureDBProtectFree() \
        do { \
            cmeFree(currentEncB64Data); \
            cmeFree(currentMetaAttribute); \
            cmeFree(currentMetaAttributeData); \
            cmeFree(currentMetaId); \
            cmeFree(currentMetaSalt); \
            cmeFree(currentMetaUserId); \
            cmeFree(currentMetaOrgId); \
            cmeFree(currentDataId); \
            cmeFree(currentDataEncAlg); \
            cmeFree(sqlQuery); \
            cmeFree(rndBytes); \
            if (memData) \
            { \
                cmeMemTableFinal(memData); \
                memData=NULL; \
            } \
            if (memProtectMetaData) \
            { \
                cmeMemTableFinal(memProtectMetaData); \
                memProtectMetaData=NULL; \
            } \
            if (currentDataSalt) \
            { \
                for (cont=0;cont<numRowsData;cont++) \
                { \
                    cmeFree(currentDataSalt[cont]); \
                } \
                cmeFree(currentDataSalt); \
            } \
        } while (0)

    //Get information from table meta (we assume tables meta and data have not been protected yet).
    result=cmeMemTable(memSecureDB,"SELECT * FROM meta;",&memProtectMetaData,&numRowsPMeta,&numColsPMeta);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeMemTable() Error"
                "can't execute 'SELECT * FROM meta;'!\n");
#endif
        cmeMemSecureDBProtectFree();
        return(1);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), cmeMemTable() loaded memSecureDB, table meta.\n");
#endif
    //Get information from table data (we assume tables meta and data have not been protected yet).
    result=cmeMemTable(memSecureDB,"SELECT * FROM data;",&memData,&numRowsData,&numColsData);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeMemTable() Error"
                "can't execute 'SELECT * FROM data;'!\n");
#endif
        cmeMemSecureDBProtectFree();
        return(2);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), cmeMemTable() loaded memSecureDB, table data.\n");
#endif
    //Create salt array for data and update in data table. We skip first row of headers.
    currentDataSalt=(char **)malloc(sizeof(char **)*(numRowsData));  //Salt array will be freed at the end of function.
    for (cont=1;cont<=numRowsData;cont++)
    {
        cmeGetRndSaltAnySize(&(currentDataSalt[cont-1]),cmeDefaultSecureDBSaltLen);
        //Update Salt info in data table.
        cmeFree(sqlQuery);
        cmeStrConstrAppend(&currentDataId,"%s",memData[cmeIDDColumnFileDataNumCols*cont+cmeIDDanydb_id]);
        cmeStrConstrAppend(&sqlQuery,"BEGIN;"
                           "UPDATE data SET salt='%s' WHERE id=%s; COMMIT;",currentDataSalt[cont-1],currentDataId);
        cmeFree(currentDataId);
        result=cmeSQLRows(memSecureDB,sqlQuery,NULL,NULL);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeSQLRows() Error"
                    "can't execute update query: %s !\n",sqlQuery);
#endif
            cmeMemSecureDBProtectFree();
            return(3);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), updated 'salt' in data table "
                " with query: %s.\n",sqlQuery);
#endif
        cmeFree(sqlQuery);
    }
    //Apply each protection mecanism on the whole table
    for (cont=1; cont<=numRowsPMeta; cont++) //Iterate on each protection row in meta.
    {
        cmeGetRndSaltAnySize(&currentMetaSalt,cmeDefaultSecureDBSaltLen);

        cmeStrConstrAppend(&currentMetaAttribute,"%s",memProtectMetaData[cont*              //Get meta.attribute
                           cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attribute]);
        cmeStrConstrAppend(&currentMetaAttributeData,"%s",memProtectMetaData[cont*          //Get meta.attributeData
                           cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attributeData]);
        cmeStrConstrAppend(&currentMetaUserId,"%s",memProtectMetaData[cont*
                           cmeIDDColumnFileMetaNumCols+cmeIDDanydb_userId]);                //Get meta.userId
        cmeStrConstrAppend(&currentMetaOrgId,"%s",memProtectMetaData[cont*
                           cmeIDDColumnFileMetaNumCols+cmeIDDanydb_orgId]);                 //Get meta.orgId
        cmeStrConstrAppend(&currentMetaId,"%s",memProtectMetaData[cont*
                           cmeIDDColumnFileMetaNumCols+cmeIDDanydb_id]);                    //Get meta.id
        // Check if protection attribute = "name".
        if (!strncmp(memProtectMetaData[cont*cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attribute],
                     cmeIDDColumnFileMeta_attribute_0, sizeof(cmeIDDColumnFileMeta_attribute_0)))
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(): 'name' will be protected by default in Meta.\n");
#endif
        }
        // Check if protection attribute = "shuffle".
        else if (!strncmp(memProtectMetaData[cont*cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attribute],
                     cmeIDDColumnFileMeta_attribute_1, sizeof(cmeIDDColumnFileMeta_attribute_1)))
        {
            cmeMemTableShuffle(memData,numRowsData,numColsData,1,1);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), shuffle protection applied to table Data.\n");
#endif
            for(cont2=1;cont2<=numRowsData;cont2++) //Updates all shuffled rows (leaves column 'id' untouched); protects 'rowOrder'.
            {
                cmeStrConstrAppend(&currentDataEncAlg,"%s",memProtectMetaData[cont*cmeIDDColumnFileMetaNumCols+
                               cmeIDDColumnFileMeta_attributeData]); //Get encryption algorithm.
                result=cmeGetCipher(&cipher,currentDataEncAlg);
                if (!result) //OK, supported algorithm
                {
                    //Encrypt rowOrder and update memSQL table Data:
                    cmeStrConstrAppend(&currentDataId,"%s",memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDanydb_id]);
                    //Protect 'rowOrder' (data table):
                    result=cmeProtectDBSaltedValue(memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDColumnFileData_rowOrder], &currentEncB64Data,
                                             currentDataEncAlg, &(currentDataSalt[cont2-1]), orgKey, &written);
                    if (result) //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeProtectDBSaltedValue() Error, can't "
                                "protect 'rowOrder' in data table: %s with algorithm %s!\n",
                                memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDColumnFileData_rowOrder],currentDataEncAlg);
#endif
                        cmeMemSecureDBProtectFree();
                        return(5);
                    }
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), protected"
                            " 'rowOrder'. Result: %s.\n",currentEncB64Data);
#endif
                    cmeStrConstrAppend(&sqlQuery,"BEGIN; UPDATE data SET"); //First part of query.
                    cmeStrConstrAppend(&sqlQuery," userId='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                       cmeIDDanydb_userId]);
                    cmeStrConstrAppend(&sqlQuery,",orgId='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                       cmeIDDanydb_orgId]);
                    cmeStrConstrAppend(&sqlQuery,",salt='%s'",currentDataSalt[cont2-1]); //Include new salts.
                    cmeStrConstrAppend(&sqlQuery,",value='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                       cmeIDDColumnFileData_value]);
                    cmeStrConstrAppend(&sqlQuery,",rowOrder='%s'",currentEncB64Data);
                    cmeStrConstrAppend(&sqlQuery,",MAC='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                       cmeIDDColumnFileData_MAC]);
                    cmeStrConstrAppend(&sqlQuery,",MACProtected='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                       cmeIDDColumnFileData_MACProtected]);
                    cmeStrConstrAppend(&sqlQuery,",sign='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                       cmeIDDColumnFileData_sign]);
                    cmeStrConstrAppend(&sqlQuery,",signProtected='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                       cmeIDDColumnFileData_signProtected]);
                    cmeStrConstrAppend(&sqlQuery,",otphDkey='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                       cmeIDDColumnFileData_otphDKey]);
                    cmeStrConstrAppend(&sqlQuery," WHERE id=%s; COMMIT;",currentDataId); //Last part of query.
                    result=cmeSQLRows(memSecureDB,sqlQuery,NULL,NULL);
                    cmeFree(currentEncB64Data);
                    if (result) //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeSQLRows() Error"
                                "can't execute update query: %s !\n",sqlQuery);
#endif
                        cmeMemSecureDBProtectFree();
                        return(6);
                    }
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), shuffle-protected row with id %s in table data.\n",
                            currentDataId);
#endif
                    cmeFree(sqlQuery);
                    cmeFree(currentDataId);
                    cmeFree(currentDataEncAlg);
                }
                else //Error: unsupported/unknown algorithm!
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), Error, can't "
                            "protect 'rowOrder' in data table: %s with algorithm %s!\n",
                            memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDColumnFileData_value],currentDataEncAlg);
#endif
                    cmeMemSecureDBProtectFree();
                    return(7);
                }
            }
        }
        // Check if protection attribute = "protect".
        else if (!strncmp(memProtectMetaData[cont*cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attribute],
                 cmeIDDColumnFileMeta_attribute_2, sizeof(cmeIDDColumnFileMeta_attribute_2)))
        {
            //Protect 'value' column in Data table, use random salt for each 'value' and store it as well:
            cmeStrConstrAppend(&currentDataEncAlg,"%s",memProtectMetaData[cont*cmeIDDColumnFileMetaNumCols+
                               cmeIDDColumnFileMeta_attributeData]); //Get encryption algorithm.
            result=cmeGetCipher(&cipher,currentDataEncAlg);
            if (!result) //OK, supported algorithm
            {
                for(cont2=1;cont2<=numRowsData;cont2++)  //We skip the header row.
                {
                    cmeStrConstrAppend(&currentDataId,"%s",memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDanydb_id]);
                    //Protect 'value' (data table):
                    result=cmeProtectDBSaltedValue(memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDColumnFileData_value], &currentEncB64Data,
                                             currentDataEncAlg, &(currentDataSalt[cont2-1]), orgKey, &written);
                    if (result) //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeProtectDBSaltedValue() Error, can't "
                                "protect 'value' in data table: %s with algorithm %s!\n",
                                memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDColumnFileData_value],currentDataEncAlg);
#endif
                        cmeMemSecureDBProtectFree();
                        return(8);
                    }
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), protected"
                            " 'value'. Result: %s.\n",currentEncB64Data);
#endif
                    cmeStrConstrAppend(&sqlQuery,"BEGIN; UPDATE data SET value='%s'",currentEncB64Data); //First part of query.
                    cmeFree(currentEncB64Data);
                    //Protect 'userId' (data table):
                    result=cmeProtectDBSaltedValue (memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDanydb_userId], &currentEncB64Data,
                                              currentDataEncAlg, &(currentDataSalt[cont2-1]), orgKey, &written);
                    if (result) //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeProtectDBSaltedValue() Error, can't "
                                "protect 'userId' in data table: %s with algorithm %s!\n",
                                memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDanydb_userId],currentDataEncAlg);
#endif
                        cmeMemSecureDBProtectFree();
                        return(9);
                    }
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), protected"
                            " 'userId'. Result: %s.\n",currentEncB64Data);
#endif
                    cmeStrConstrAppend(&sqlQuery,",userId='%s'",currentEncB64Data); //First part of query.
                    cmeFree(currentEncB64Data);
                    //Protect 'orgId' (data table):
                    result=cmeProtectDBSaltedValue(memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDanydb_orgId], &currentEncB64Data,
                                             currentDataEncAlg, &(currentDataSalt[cont2-1]), orgKey, &written);
                    if (result) //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeProtectDBSaltedValue() Error, can't "
                                "protect 'orgId' in data table: %s with algorithm %s!\n",
                                memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDanydb_orgId],currentDataEncAlg);
#endif
                        cmeMemSecureDBProtectFree();
                        return(10);
                    }
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), protected"
                            " 'orgId'. Result: %s.\n",currentEncB64Data);
#endif
                    cmeStrConstrAppend(&sqlQuery,",orgId='%s'",currentEncB64Data); //First part of query.
                    cmeFree(currentEncB64Data);
                    //Last part of query; Execute query.
                    cmeStrConstrAppend(&sqlQuery," WHERE id=%s; COMMIT;",
                                       currentDataId); //Last part of query. Overwrite salt if necessary (other protections overwrite it as well).
                    result=cmeSQLRows(memSecureDB,sqlQuery,NULL,NULL);
                    cmeFree(sqlQuery);
                    if (result) //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeSQLRows() Error"
                                "can't execute update query: %s !\n",sqlQuery);
#endif
                        cmeMemSecureDBProtectFree();
                        return(11);
                    }
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), protected row with id %s in table data.\n",
                            currentDataId);
#endif
                    cmeFree(currentDataId);
                }
                cmeFree(currentDataEncAlg);
            }
            else //Error: unsupported/unknown algorithm!
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), Error, can't "
                        "protect 'value' in data table: %s with algorithm %s!\n",
                        memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDColumnFileData_value],currentDataEncAlg);
#endif
                cmeMemSecureDBProtectFree();
                return(12);
            }

        }
        // Check if protection attribute = "sign".
        else if (!strncmp(memProtectMetaData[cont*cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attribute],
                 cmeIDDColumnFileMeta_attribute_3, sizeof(cmeIDDColumnFileMeta_attribute_3)))
        {
            //TODO (OHR#5#): sign; requires userId to get certificate/private key (check issues with private key)
        }
        // Check if protection attribute = "signProtected".
        else if (!strncmp(memProtectMetaData[cont*cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attribute],
                     cmeIDDColumnFileMeta_attribute_4, sizeof(cmeIDDColumnFileMeta_attribute_4)))
        {
            //TODO (OHR#5#): signProtected; requires userId to get certificate/private key (check issues with private key)
        }
        // Check if protection attribute = "MAC".
        else if (!strncmp(memProtectMetaData[cont*cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attribute],
                     cmeIDDColumnFileMeta_attribute_5, sizeof(cmeIDDColumnFileMeta_attribute_5)))
        {
            //TODO (OHR#3#): MAC
        }
        // Check if protection attribute = "MACProtected".
        else if (!strncmp(memProtectMetaData[cont*cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attribute],
                     cmeIDDColumnFileMeta_attribute_6, sizeof(cmeIDDColumnFileMeta_attribute_6)))
        {
            //TODO (OHR#3#): MACProtected
        }
        //Finally, protect columnFile.Meta attribute, attributeData, userId and orgId in each row in meta table.
        //Protect Meta "attribute":
        result=cmeProtectDBSaltedValue(currentMetaAttribute, &currentEncB64Data,
                                 cmeDefaultEncAlg, &currentMetaSalt, orgKey, &written);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeProtectDBSaltedValue() Error, can't "
                    "protect Meta attribute: %s with algorithm %s!\n",currentMetaAttribute,cmeDefaultEncAlg);
#endif
            cmeMemSecureDBProtectFree();
            return(13);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), protected"
                " Meta attribute. Result: %s.\n",currentEncB64Data);
#endif
        //cmeFree(sqlQuery);  //First part of query
        cmeStrConstrAppend(&sqlQuery,"BEGIN; UPDATE meta SET attribute='%s'",currentEncB64Data);
        cmeFree(currentEncB64Data);
        //Protect Meta "attributeData":
        result=cmeProtectDBSaltedValue(currentMetaAttributeData, &currentEncB64Data,
                                cmeDefaultEncAlg, &currentMetaSalt, orgKey, &written);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeProtectDBSaltedValue() Error, can't "
                    "protect Meta attributeData: %s with algorithm %s!\n",currentMetaAttributeData,cmeDefaultEncAlg);
#endif
            cmeMemSecureDBProtectFree();
            return(14);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), protected"
                " Meta attributeData. Result: %s.\n",currentEncB64Data);
#endif
        cmeStrConstrAppend(&sqlQuery,",attributeData='%s'",currentEncB64Data);
        cmeFree(currentEncB64Data);
        //Protect Meta "userId":
        result=cmeProtectDBSaltedValue(currentMetaUserId, &currentEncB64Data,
                                cmeDefaultEncAlg, &currentMetaSalt, orgKey, &written);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeProtectDBSaltedValue() Error, can't "
                    "protect Meta userId: %s with algorithm %s!\n",currentMetaUserId,cmeDefaultEncAlg);
#endif
            cmeMemSecureDBProtectFree();
            return(15);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), protected"
                " Meta userId. Result: %s.\n",currentEncB64Data);
#endif
        cmeStrConstrAppend(&sqlQuery,",userId='%s'",currentEncB64Data);
        cmeFree(currentEncB64Data);
        //Protect Meta "orgId":
        result=cmeProtectDBSaltedValue(currentMetaOrgId, &currentEncB64Data,
                                cmeDefaultEncAlg, &currentMetaSalt, orgKey, &written);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeProtectDBSaltedValue() Error, can't "
                    "protect Meta orgId: %s with algorithm %s!\n",currentMetaOrgId,cmeDefaultEncAlg);
#endif
            cmeMemSecureDBProtectFree();
            return(16);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), protected"
                " Meta orgId. Result: %s.\n",currentEncB64Data);
#endif
        cmeStrConstrAppend(&sqlQuery,",orgId='%s'",currentEncB64Data);
        cmeFree(currentEncB64Data);
        //Last part of query
        cmeStrConstrAppend(&sqlQuery,",salt='%s' WHERE id=%s; COMMIT;",currentMetaSalt,currentMetaId);
        result=cmeSQLRows(memSecureDB,sqlQuery,NULL,NULL);
        cmeFree(sqlQuery);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBProtect(), cmeSQLRows() Error"
                    "can't execute update query: %s !\n",sqlQuery);
#endif
            cmeMemSecureDBProtectFree();
            return(17);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBProtect(), protected row with id %s in table meta.\n",
                currentMetaId);
#endif
        //Free stuff in this FOR loop
        cmeFree(currentMetaAttribute);
        cmeFree(currentMetaAttributeData);
        cmeFree(currentMetaId);
        cmeFree(currentMetaSalt);
        cmeFree(currentMetaUserId);
        cmeFree(currentMetaOrgId);
    }
    cmeMemSecureDBProtectFree();
    return (0);
}

int cmeMemSecureDBUnprotect (sqlite3 *memSecureDB, const char *orgKey)
{
    int cont,cont2,result,written;
    int numColsData=0;
    int numRowsData=0;
    int numColsPMeta=0;
    int numRowsPMeta=0;
    char **memData=NULL;
    char **memProtectMetaData=NULL;
    char *currentData=NULL;
    char *currentEncB64Data=NULL;
    char *currentMetaAttribute=NULL;
    char *currentMetaAttributeData=NULL;
    char *currentMetaId=NULL;
    char *currentMetaSalt=NULL;
    char *currentMetaUserId=NULL;
    char *currentMetaOrgId=NULL;
    char *currentDataUserId=NULL;
    char *currentDataOrgId=NULL;
    char *currentDataId=NULL;
    char *currentDataSalt=NULL;
    char *currentDataEncAlg=NULL;
    char *sqlQuery=NULL;
    const EVP_CIPHER *cipher=NULL;
    //MEMORY CLEANUP MACRO for local function.
    #define cmeMemSecureDBUnprotectFree() \
        do { \
            cmeFree(currentData); \
            cmeFree(currentEncB64Data); \
            cmeFree(currentMetaAttribute); \
            cmeFree(currentMetaAttributeData); \
            cmeFree(currentMetaId); \
            cmeFree(currentMetaSalt); \
            cmeFree(currentMetaUserId); \
            cmeFree(currentMetaOrgId); \
            cmeFree(currentDataUserId); \
            cmeFree(currentDataOrgId); \
            cmeFree(currentDataSalt); \
            cmeFree(currentDataEncAlg); \
            cmeFree(sqlQuery); \
            if (memData) \
            { \
                cmeMemTableFinal(memData); \
                memData=NULL; \
            } \
            if (memProtectMetaData) \
            { \
                cmeMemTableFinal(memProtectMetaData); \
                memProtectMetaData=NULL; \
            } \
        } while (0)

    //Get information from table meta (we assume tables meta and data are protected).
    result=cmeMemTable(memSecureDB,"SELECT * FROM meta;",&memProtectMetaData,&numRowsPMeta,&numColsPMeta);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeMemTable() Error"
                "can't execute 'SELECT * FROM meta;'!\n");
#endif
        cmeMemSecureDBUnprotectFree();
        return(1);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBUnprotect(), cmeMemTable() loaded memSecureDB, table meta.\n");
#endif
    //Get information from table data (we assume tables meta and data are protected).
    result=cmeMemTable(memSecureDB,"SELECT * FROM data;",&memData,&numRowsData,&numColsData);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeMemTable() Error"
                "can't execute 'SELECT * FROM data;'!\n");
#endif
        cmeMemSecureDBUnprotectFree();
        return(2);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBUnprotect(), cmeMemTable() loaded memSecureDB, table data.\n");
#endif
    //Unprotect and reverse on table data, each protection mechanism defined in table meta.
    for (cont=1; cont<=numRowsPMeta; cont++) //Iterate on each protection row in meta.
    {
        cmeStrConstrAppend(&currentMetaSalt,"%s",memProtectMetaData[cont*              //Get meta.salt
                           cmeIDDColumnFileMetaNumCols+cmeIDDanydb_salt]);
        cmeStrConstrAppend(&currentEncB64Data,"%s",memProtectMetaData[cont*            //Get prot. meta.attribute
                           cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attribute]);
        result=cmeUnprotectDBSaltedValue(currentEncB64Data,&currentMetaAttribute,cmeDefaultEncAlg,&currentMetaSalt,orgKey,&written);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeUnprotectDBSaltedValue() Error, can't "
                    "decrypt 'attribute' in meta table, B64str: %s with algorithm %s!\n",
                    currentEncB64Data,cmeDefaultEncAlg);
#endif
            cmeMemSecureDBUnprotectFree();
            return(3);
        }
        cmeFree(currentEncB64Data);
        cmeStrConstrAppend(&currentEncB64Data,"%s",memProtectMetaData[cont*            //Get prot. meta.attributeData
                           cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attributeData]);
        result=cmeUnprotectDBSaltedValue(currentEncB64Data,&currentMetaAttributeData,cmeDefaultEncAlg,&currentMetaSalt,orgKey,&written);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeUnprotectDBSaltedValue() Error, can't "
                    "decrypt 'attributeData' in meta table, B64str: %s with algorithm %s!\n",
                    currentEncB64Data,cmeDefaultEncAlg);
#endif
            cmeMemSecureDBUnprotectFree();
            return(4);
        }
        cmeFree(currentEncB64Data);
        cmeStrConstrAppend(&currentEncB64Data,"%s",memProtectMetaData[cont*            //Get prot. meta.userId
                           cmeIDDColumnFileMetaNumCols+cmeIDDanydb_userId]);
        result=cmeUnprotectDBSaltedValue(currentEncB64Data,&currentMetaUserId,cmeDefaultEncAlg,&currentMetaSalt,orgKey,&written);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeUnprotectDBSaltedValue() Error, can't "
                    "decrypt 'userId' in meta table, B64str: %s with algorithm %s!\n",
                    currentEncB64Data,cmeDefaultEncAlg);
#endif
            cmeMemSecureDBUnprotectFree();
            return(5);
        }
        cmeFree(currentEncB64Data);
        cmeStrConstrAppend(&currentEncB64Data,"%s",memProtectMetaData[cont*            //Get prot. meta.orgId
                           cmeIDDColumnFileMetaNumCols+cmeIDDanydb_orgId]);
        result=cmeUnprotectDBSaltedValue(currentEncB64Data,&currentMetaOrgId,cmeDefaultEncAlg,&currentMetaSalt,orgKey,&written);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeUnprotectDBSaltedValue() Error, can't "
                    "decrypt 'orgId' in meta table, B64str: %s with algorithm %s!\n",
                    currentEncB64Data,cmeDefaultEncAlg);
#endif
            cmeMemSecureDBUnprotectFree();
            return(6);
        }
        cmeFree(currentEncB64Data);
        cmeStrConstrAppend(&currentMetaId,"%s",memProtectMetaData[cont*            //Get prot. meta.id
                           cmeIDDColumnFileMetaNumCols+cmeIDDanydb_id]);
        //First part of query
        cmeStrConstrAppend(&sqlQuery,"BEGIN; UPDATE meta SET attribute='%s'",currentMetaAttribute);
        cmeStrConstrAppend(&sqlQuery,",attributeData='%s'",currentMetaAttributeData);
        cmeStrConstrAppend(&sqlQuery,",userId='%s'",currentMetaUserId);
        cmeStrConstrAppend(&sqlQuery,",orgId='%s'",currentMetaOrgId);
        cmeStrConstrAppend(&sqlQuery,",salt='%s' WHERE id=%s; COMMIT;",currentMetaSalt,currentMetaId);
        result=cmeSQLRows(memSecureDB,sqlQuery,NULL,NULL);
        if (result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeSQLRows() Error"
                    "can't execute update query: %s !\n",sqlQuery);
#endif
            cmeMemSecureDBUnprotectFree();
            return(7);
        }
        cmeFree(sqlQuery);
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBUnprotect(), unprotected row with id %s in table meta.\n",
                currentMetaId);
#endif
        // Check if protection attribute = "name".
        if (!strncmp(currentMetaAttribute,cmeIDDColumnFileMeta_attribute_0,
                     sizeof(cmeIDDColumnFileMeta_attribute_0)))
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBUnprotect(): 'name' will be unprotected by default in Meta.\n");
#endif
        }
        // Check if protection attribute = "shuffle".
        else if (!strncmp(currentMetaAttribute,cmeIDDColumnFileMeta_attribute_1,
                          sizeof(cmeIDDColumnFileMeta_attribute_1)))
        {
            cmeStrConstrAppend(&currentDataEncAlg,"%s",currentMetaAttributeData); //Get encryption algorithm.
            result=cmeGetCipher(&cipher,currentDataEncAlg);
            if (result) //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), Error, "
                        "unsupported / unknown encryption algorithm: %s!\n",currentDataEncAlg);
#endif
                cmeMemSecureDBUnprotectFree();
                return(8);
            }
            for(cont2=1;cont2<=numRowsData;cont2++) //Updates all shuffled rows (leaves column 'id' untouched); unprotects 'rowOrder'.
            {
                //Decrypt rowOrder and update memSQL table Data.
                cmeStrConstrAppend(&currentDataId,"%s",memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDanydb_id]);
                cmeStrConstrAppend(&currentEncB64Data,"%s",memData[cmeIDDColumnFileDataNumCols*cont2+
                                     cmeIDDColumnFileData_rowOrder]); //Get encrypted B64str.
                //Unprotect 'rowOrder' (data table).

                result=cmeUnprotectDBSaltedValue(currentEncB64Data,&currentData,currentDataEncAlg,&(memData[cmeIDDColumnFileDataNumCols*cont2+
                                           cmeIDDanydb_salt]),orgKey,&written);
                cmeFree(currentEncB64Data);
                if (result) //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeUnprotectDBSaltedValue() Error, can't "
                            "decrypt 'rowOrder' in data table with algorithm %s!\n",currentDataEncAlg);
#endif
                    cmeMemSecureDBUnprotectFree();
                    return(9);
                }
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBUnprotect(), decrypted 'rowOrder' in data table row: "
                        "%s, with algorithm: %s.\n",currentData,currentDataEncAlg);
#endif
                cmeStrConstrAppend(&sqlQuery,"BEGIN; UPDATE data SET"); //First part of query.
                cmeStrConstrAppend(&sqlQuery," rowOrder='%s'",currentData);
                cmeStrConstrAppend(&sqlQuery," WHERE id=%s; COMMIT;",currentDataId); //Last part of query.
                result=cmeSQLRows(memSecureDB,sqlQuery,NULL,NULL);
                cmeFree(currentData);
                if (result) //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeSQLRows() Error"
                            " can't execute update query: %s !\n",sqlQuery);
#endif
                    cmeMemSecureDBUnprotectFree();
                    return(10);
                }
                cmeFree(sqlQuery);
                cmeFree(currentDataId);
            }
            cmeFree(currentDataEncAlg);
            cmeMemTableFinal(memData); //Free current table and reload.
            //Get shuffled (rowOrder unprotected) information from table data (we assume rowOrder has been unprotected).
            result=cmeMemTable(memSecureDB,"SELECT * FROM data;",&memData,&numRowsData,&numColsData);
            if (result) //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeMemTable() Error"
                        "can't execute 'SELECT * FROM data;' for shuffled data!\n");
#endif
                cmeMemSecureDBUnprotectFree();
                return(11);
            }
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBUnprotect(), cmeMemTable() loaded memSecureDB,"
                    " shuffled, table data.\n");
#endif
            //Unshuffle memory table
            result=cmeMemTableOrder(memData,numRowsData,numColsData,cmeIDDColumnFileData_rowOrder,1,1);
            if (result) //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Debug: cmeMemSecureDBUnprotect(), cmeMemTableOrder() Error."
                        "Can't reorder shuffled data table; error # %d!\n",result);
#endif
                cmeMemSecureDBUnprotectFree();
                return(12);
            }
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBUnprotect(), shuffle protection removed from table Data.\n");
#endif
            for (cont2=1;cont2<=numRowsData;cont2++) //Save reordered table back to DB.
            {
                cmeStrConstrAppend(&sqlQuery,"BEGIN; UPDATE data SET"); //First part of query.
                cmeStrConstrAppend(&sqlQuery," userId='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                   cmeIDDanydb_userId]);
                cmeStrConstrAppend(&sqlQuery,",orgId='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                   cmeIDDanydb_orgId]);
                cmeStrConstrAppend(&sqlQuery,",salt='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                   cmeIDDanydb_salt]);
                cmeStrConstrAppend(&sqlQuery,",value='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                   cmeIDDColumnFileData_value]);
                cmeStrConstrAppend(&sqlQuery,",rowOrder='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                   cmeIDDColumnFileData_rowOrder]);
                cmeStrConstrAppend(&sqlQuery,",MAC='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                   cmeIDDColumnFileData_MAC]);
                cmeStrConstrAppend(&sqlQuery,",MACProtected='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                   cmeIDDColumnFileData_MACProtected]);
                cmeStrConstrAppend(&sqlQuery,",sign='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                   cmeIDDColumnFileData_sign]);
                cmeStrConstrAppend(&sqlQuery,",signProtected='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                   cmeIDDColumnFileData_signProtected]);
                cmeStrConstrAppend(&sqlQuery,",otphDkey='%s'",memData[cmeIDDColumnFileDataNumCols*cont2+
                                   cmeIDDColumnFileData_otphDKey]);
                cmeStrConstrAppend(&sqlQuery," WHERE id=%s; COMMIT;",memData[cmeIDDColumnFileDataNumCols*cont2+
                                   cmeIDDanydb_id]); //Last part of query.
                result=cmeSQLRows(memSecureDB,sqlQuery,NULL,NULL);
                if (result) //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeSQLRows() Error"
                            "can't execute update query: %s !\n",sqlQuery);
#endif
                    cmeMemSecureDBUnprotectFree();
                    return(13);
                }
                cmeFree(sqlQuery);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBUnprotect(), unshuffled row with id %s, in table data.\n",
                        memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDanydb_id]);
#endif
            }
        }
        // Check if protection attribute = "protect".
        else if (!strncmp(currentMetaAttribute,cmeIDDColumnFileMeta_attribute_2,
                          sizeof(cmeIDDColumnFileMeta_attribute_2)))
        {
            //Unprotect userId,orgId in each row in tabla data.
            for(cont2=1;cont2<=numRowsData;cont2++)
            {
                cmeStrConstrAppend(&currentDataSalt,"%s",memData[cont2*              //Get data.salt
                                   cmeIDDColumnFileDataNumCols+cmeIDDanydb_salt]);
                cmeStrConstrAppend(&currentEncB64Data,"%s",memData[cont2*            //Get prot. data.userId
                                   cmeIDDColumnFileDataNumCols+cmeIDDanydb_userId]);

                result=cmeUnprotectDBSaltedValue(currentEncB64Data,&currentDataUserId,cmeDefaultEncAlg,&currentDataSalt,orgKey,&written);
                if (result) //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeUnprotectDBSaltedValue() Error, can't "
                            "decrypt 'userId' in data table, B64str: %s with algorithm %s!\n",
                            currentEncB64Data,cmeDefaultEncAlg);
#endif
                    cmeMemSecureDBUnprotectFree();
                    return(14);
                }
                cmeFree(currentEncB64Data);
                cmeStrConstrAppend(&currentEncB64Data,"%s",memData[cont2*            //Get prot. data.orgId
                                   cmeIDDColumnFileDataNumCols+cmeIDDanydb_orgId]);
                result=cmeUnprotectDBSaltedValue(currentEncB64Data,&currentDataOrgId,cmeDefaultEncAlg,&currentDataSalt,orgKey,&written);
                if (result) //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeUnprotectDBSaltedValue() Error, can't "
                            "decrypt 'orgId' in data table, B64str: %s with algorithm %s!\n",
                            currentEncB64Data,cmeDefaultEncAlg);
#endif
                    cmeMemSecureDBUnprotectFree();
                    return(15);
                }
                cmeFree(currentEncB64Data);
                cmeStrConstrAppend(&currentDataId,"%s",memData[cont2*            //Get prot. data.id
                                   cmeIDDColumnFileDataNumCols+cmeIDDanydb_id]);
                //First part of query
                cmeStrConstrAppend(&sqlQuery,"BEGIN; UPDATE data SET");
                cmeStrConstrAppend(&sqlQuery," userId='%s'",currentDataUserId);
                cmeStrConstrAppend(&sqlQuery,",orgId='%s'",currentDataOrgId);
                cmeStrConstrAppend(&sqlQuery,",salt='%s' WHERE id=%s; COMMIT;",currentDataSalt,currentDataId);
                result=cmeSQLRows(memSecureDB,sqlQuery,NULL,NULL);
                if (result) //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeSQLRows() Error"
                            "can't execute update query: %s !\n",sqlQuery);
#endif
                    cmeMemSecureDBUnprotectFree();
                    return(16);
                }
                cmeFree(sqlQuery);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBUnprotect(), unprotected userId & orgId in row with id %s, in table data.\n",
                        currentDataId);
#endif
                cmeFree(currentDataId);
                cmeFree(currentDataSalt);
                cmeFree(currentDataUserId);
                cmeFree(currentDataOrgId);
            }
            //Unprotect 'value' in data table with corresponding encryption algorithm.
            cmeStrConstrAppend(&currentEncB64Data,"%s",memProtectMetaData[cont*cmeIDDColumnFileMetaNumCols+
                               cmeIDDColumnFileMeta_attributeData]); // Get encrypted, B64 str representation of encr. alg.
            result=cmeUnprotectDBSaltedValue(currentEncB64Data,&currentDataEncAlg,cmeDefaultEncAlg,&(memProtectMetaData[cont*
                                        cmeIDDColumnFileMetaNumCols+cmeIDDanydb_salt]),orgKey,&written);
            if (result) //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeUnprotectDBSaltedValue() Error, can't "
                        "decrypt encryption algorithm in meta table: %s with algorithm %s!\n",
                        currentEncB64Data,cmeDefaultEncAlg);
#endif
                cmeMemSecureDBUnprotectFree();
                return(17);
            }
            cmeFree(currentEncB64Data);
            //Unprotect 'value' column in Data table, using corresponding salt.
            result=cmeGetCipher(&cipher,currentDataEncAlg);
            if (!result) //OK, supported algorithm
            {
                for(cont2=1;cont2<=numRowsData;cont2++)  //We skip the header row.
                {
                    cmeStrConstrAppend(&currentDataId,"%s",memData[cmeIDDColumnFileDataNumCols*cont2+cmeIDDanydb_id]);
                    //Protect 'value (data table).
                    cmeStrConstrAppend(&currentEncB64Data,"%s",memData[cmeIDDColumnFileDataNumCols*cont2+
                                       cmeIDDColumnFileData_value]); // Get encrypted, B64 str representation of encr. alg.
                    result=cmeUnprotectDBSaltedValue(currentEncB64Data,&currentData,currentDataEncAlg,&(memData[cmeIDDColumnFileDataNumCols*
                                               cont2+cmeIDDanydb_salt]),orgKey,&written);
                    if (result) //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeUnprotectDBSaltedValue() Error, can't "
                                "decrypt 'value' in data table: %s with algorithm %s!\n",
                                currentEncB64Data,currentDataEncAlg);
#endif
                        cmeMemSecureDBUnprotectFree();
                        return(18);
                    }
                    cmeFree(currentEncB64Data);
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBUnprotect(), decrypted 'value' in data table: "
                            "%s with algorithm %s.\n",currentData,currentDataEncAlg);
#endif
                    cmeStrConstrAppend(&sqlQuery,"BEGIN; UPDATE data SET value='%s' WHERE id=%s; COMMIT;",
                                       currentData,currentDataId);  //Update query.
                    memset(currentData,0,strlen(currentData));      // Clear sensitive data
                    cmeFree(currentData);
                    result=cmeSQLRows(memSecureDB,sqlQuery,NULL,NULL);
                    if (result) //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), cmeSQLRows() Error"
                                "can't execute update query: %s !\n",sqlQuery);
#endif
                        cmeMemSecureDBUnprotectFree();
                        return(19);
                    }
                    memset(sqlQuery,0,sizeof(char)*strlen(sqlQuery)); //Clean sensitive data.
                    cmeFree(sqlQuery);
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBUnprotect(), unprotected 'value' in row with id %s, in table data.\n",
                            currentDataId);
#endif
                    cmeFree(currentDataId);
                }
            }
            else //Error: unsupported/unknown algorithm!
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBUnprotect(), Error, "
                        "unsupported / unknown encryption algorithm: %s!\n",currentDataEncAlg);
#endif
                cmeMemSecureDBUnprotectFree();
                return(20);
            }
            cmeFree(currentDataEncAlg);
        }
        // Check if protection attribute = "sign".
        else if (!strncmp(currentMetaAttribute,cmeIDDColumnFileMeta_attribute_3,
                          sizeof(cmeIDDColumnFileMeta_attribute_3)))
        {
            //TODO (OHR#5#): sign; requires userId to get certificate/private key (check issues with private key)
        }
        // Check if protection attribute = "signProtected".
        else if (!strncmp(currentMetaAttribute,cmeIDDColumnFileMeta_attribute_4,
                          sizeof(cmeIDDColumnFileMeta_attribute_4)))
        {
            //TODO (OHR#5#): signProtected; requires userId to get certificate/private key (check issues with private key)
        }
        // Check if protection attribute = "MAC".
        else if (!strncmp(currentMetaAttribute,cmeIDDColumnFileMeta_attribute_5,
                          sizeof(cmeIDDColumnFileMeta_attribute_5)))
        {
            //TODO (OHR#3#): MAC
        }
        // Check if protection attribute = "MACProtected".
        else if (!strncmp(currentMetaAttribute,cmeIDDColumnFileMeta_attribute_6,
                          sizeof(cmeIDDColumnFileMeta_attribute_6)))
        {
            //TODO (OHR#3#): MACProtected
        }
        //Free stuff in this FOR loop
        cmeFree(currentMetaAttribute);
        cmeFree(currentMetaAttributeData);
        cmeFree(currentMetaId);
        cmeFree(currentMetaSalt);
        cmeFree(currentMetaUserId);
        cmeFree(currentMetaOrgId);
    }
    //Free remaining stuff.
    cmeMemSecureDBUnprotectFree();
    return (0);
}

int cmeProtectDBValue (const char *value, char **protectedValue, const char *encAlg, char **salt,
                       const char *orgKey, int *protectedValueLen)
{   //TODO (OHR#2#): Replace everywhere to protect a DB value with a call to this function.
    int result;
    if (value==NULL) //Error: no value to encrypt
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeProtectDBValue(), Error, can't "
                "encrypt NULL value with algorithm %s!\n",encAlg);
#endif
        return(1);
    }
    result=cmeProtectByteString (value, protectedValue, encAlg, salt, orgKey, protectedValueLen, strlen(value));
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeProtectDBValue(), cmeProtectByteString() Error, can't "
                "protect 'value' %s with algorithm %s!\n",value,encAlg);
#endif
        return(2);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeProtectDBValue(), protected 'value': "
            "%s with algorithm %s.\n",value,encAlg);
#endif
    return (0);
}

int cmeUnprotectDBValue (const char *protectedValue, char **value, const char *encAlg, char **salt,
                         const char *orgKey, int *valueLen)
{   //TODO (OHR#2#): Replace everywhere to unprotect a DB value with a call to this function.
    int result;

    *value=NULL;
    if (!protectedValue) //WARNING: null input!
    {
        *valueLen=0;
        cmeStrConstrAppend(value,"");
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeUnprotectDBValue(), Warning, can't "
                "decrypt 'protectedValue'=NULL with algorithm %s and key %s!\n",encAlg,orgKey);
#endif
        return(0); //Not an error, just a warning!
    }
    result=cmeUnprotectByteString(protectedValue,value,encAlg,salt,orgKey,valueLen,strlen(protectedValue));
    if (result) //Unprotect failed. Return empty string.
    {
        cmeFree(*value); //Clean value; we will return an empty string.
        *valueLen=0;
        cmeStrConstrAppend(value,"");
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeUnprotectDBValue(), cmeUnprotectByteString() Warning, can't "
                "unprotect 'protectedValue' %s with algorithm %s and the key %s!\n",protectedValue,encAlg,orgKey);
#endif
    }
    else //Unprotect successful.
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeUnprotectDBValue(), unprotected 'protectedValue': "
                "%s with algorithm %s -> %s.\n",protectedValue,encAlg,*value);
#endif
    }
    return (0);
}

int cmeProtectDBSaltedValue (const char *value, char **protectedValue, const char *encAlg, char **salt,
                             const char *orgKey, int *protectedValueLen)
{   // TODO (OHR#5#): Replace everywhere to salt+protect a DB value with a call to this function. Also replace unsalted versions of this function!
    int result;
    char *valueSalt=NULL;
    char *saltedValue=NULL;
    #define cmeProtectDBSaltedValueFree() \
        do { \
            cmeFree(valueSalt); \
            cmeFree(saltedValue); \
        } while (0) //Local free() macro

    if (value==NULL) //Error: no value to encrypt
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeProtectDBSaltedValue(), Error, can't "
                "protect NULL value with algorithm %s!\n",encAlg);
#endif
        cmeProtectDBSaltedValueFree();
        return(1);
    }
    cmeGetRndSaltAnySize(&valueSalt,cmeDefaultValueSaltLen);  //Get random valueSalt (16 chars, 8 byte hexstring).
    cmeStrConstrAppend(&saltedValue,"%s%s",valueSalt,value);  // Append unencrypted value to valueSalt.
    result=cmeProtectByteString(saltedValue, protectedValue, encAlg, salt,orgKey, protectedValueLen, strlen(saltedValue));
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeProtectDBSaltedValue(), cmeProtectByteString() Error, can't "
                "protect 'salted value' %s with algorithm %s!\n",saltedValue,encAlg);
#endif
        cmeProtectDBSaltedValueFree();
        return(2);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeProtectDBSaltedValue(), protected 'salted value': "
            "%s with algorithm %s.\n",saltedValue,encAlg);
#endif
    cmeProtectDBSaltedValueFree();
    return (0);
}

int cmeUnprotectDBSaltedValue (const char *protectedValue, char **value, const char *encAlg, char **salt,
                               const char *orgKey, int *valueLen)
{   // TODO (OHR#5#): Replace everywhere to unprotect+unsalt a DB value with a call to this function. Also replace unsalted versions of this function!
    int result;
    char *saltedValue=NULL;
    #define cmeUnProtectDBSaltedValueFree() \
        do { \
            cmeFree(saltedValue); \
        } while (0) //Local free() macro

    *value=NULL;
    if (!protectedValue) //WARNING: null input!
    {
        *valueLen=0;
        cmeStrConstrAppend(value,"");
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeUnprotectDBSaltedValue(), Warning, can't unprotect 'protectedValue'=NULL "
                "with algorithm %s and key %s!\n",encAlg,orgKey);
#endif
        cmeUnProtectDBSaltedValueFree();
        return(0); //No error, just a warning.
    }
    result=cmeUnprotectByteString(protectedValue, &saltedValue, encAlg, salt, orgKey, valueLen, strlen(protectedValue));
    if (result) //Unprotect failed. Return empty string.
    {
        *valueLen=0;
        cmeStrConstrAppend(value,"");
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeUnprotectDBSaltedValue(), cmeUnprotectByteString() Warning, can't "
                "unprotect 'protectedValue' %s with algorithm %s and the key %s!\n",protectedValue,encAlg,orgKey);
#endif
    }
    else //Unprotect successful.
    {
        if (*valueLen>=cmeDefaultValueSaltCharLen) //Double check that we have the right length
        {
            cmeStrConstrAppend(value,"%s",&(saltedValue[cmeDefaultValueSaltCharLen])); //We skip the first 16 characters of the 8 byte hexstr salt that is included at the beginning.
            *valueLen-=cmeDefaultValueSaltCharLen;
        }
        else
        {
            cmeStrConstrAppend(value,"%s",saltedValue); //We don't skip the first 16 characters of the 8 byte hexstr salt that is included at the beginning.
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeUnprotectDBSaltedValue() Warning, value '%s' "
                    "has incorrect valuesalt size!. Unprotected it assuming it wasn't valueSalted\n",saltedValue);
#endif
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeUnprotectDBSaltedValue(), unprotected 'protectedValue': "
                "%s with algorithm %s -> %s.\n",protectedValue,encAlg,*value);
#endif
    }
    cmeUnProtectDBSaltedValueFree();
    return (0);
}

int cmeMemSecureDBReintegrate (sqlite3 **memSecureDB, const char *orgKey,
                               const int dbNumCols, int *dbNumReintegratedCols)
{
    int cont,cont2,cont3,cont4,result,written;
    int numColsData=0;
    int numColsPMeta=0;
    int numRowsPMeta=0;
    int *numRowsData=NULL;
    char ***memData=NULL;
    char ***memProtectMetaData=NULL;
    char **memColumnName=NULL;
    char *currentEncData=NULL;
    char *currentEncB64Data=NULL;
    char *currentMetaAttribute=NULL;
    char *currentMetaAttributeData=NULL;
    char *currentMetaId=NULL;
    char *currentMetaSalt=NULL;
    char *currentMetaUserId=NULL;
    char *currentMetaOrgId=NULL;
    char *sqlQuery=NULL;
    sqlite3 *tmpPtr=NULL;       //Just a tmp pointer; no need for cmeFree().
    //MEMORY CLEANUP MACRO for local function.
    #define cmeMemSecureDBReintegrateFree() \
        do { \
            cmeFree(numRowsData); \
            cmeFree(currentEncData); \
            cmeFree(currentEncB64Data); \
            cmeFree(currentMetaAttribute); \
            cmeFree(currentMetaAttributeData); \
            cmeFree(currentMetaId); \
            cmeFree(currentMetaSalt); \
            cmeFree(currentMetaUserId); \
            cmeFree(currentMetaOrgId); \
            cmeFree(sqlQuery); \
            if (memColumnName) \
            { \
                for (cont=0;cont<dbNumCols;cont++) \
                { \
                    cmeFree(memColumnName[cont]); \
                } \
                cmeFree(memColumnName); \
            } \
            if (memData) \
            { \
                for (cont=0;cont<dbNumCols;cont++) \
                { \
                    if (memData[cont]) \
                    { \
                        cmeMemTableFinal(memData[cont]); \
                    } \
                } \
                cmeFree(memData); \
            } \
            if (memProtectMetaData) \
            { \
                for (cont=0;cont<dbNumCols;cont++) \
                { \
                    if (memProtectMetaData[cont]) \
                    { \
                        cmeMemTableFinal(memProtectMetaData[cont]); \
                    } \
                } \
                cmeFree(memProtectMetaData); \
            } \
        } while (0)

    *dbNumReintegratedCols=dbNumCols;
    numRowsData=(int *)malloc(sizeof(int)*dbNumCols);
    memData=(char ***)malloc(sizeof(char **)*dbNumCols);
    memProtectMetaData=(char ***)malloc(sizeof(char **)*dbNumCols);
    memColumnName=(char **)malloc(sizeof(char *)*dbNumCols);
    for (cont=0;cont<dbNumCols;cont++)
    {
        numRowsData[cont]=0;
        memData[cont]=NULL;
        memProtectMetaData[cont]=NULL;
        memColumnName[cont]=NULL;
    }

    for (cont=0;cont<dbNumCols;cont++)
    {
        //Get information from table meta (we assume tables meta and data are protected).
        result=cmeMemTable(memSecureDB[cont],"SELECT * FROM meta;",&(memProtectMetaData[cont]),&numRowsPMeta,&numColsPMeta);
        if (result) //Error
        {
    #ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBReintegrate(), cmeMemTable() Error"
                    "can't execute 'SELECT * FROM meta;'!\n");
    #endif
            cmeMemSecureDBReintegrateFree();
            return(1);
        }
    #ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBReintegrate(), cmeMemTable() loaded memSecureDB, table meta.\n");
    #endif
        //Get information from table data (we assume tables meta and data are protected).
        result=cmeMemTable(memSecureDB[cont],"SELECT * FROM data;",&(memData[cont]),&(numRowsData[cont]),&numColsData);
        if (result) //Error
        {
    #ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBReintegrate(), cmeMemTable() Error"
                    "can't execute 'SELECT * FROM data;'!\n");
    #endif
            cmeMemSecureDBReintegrateFree();
            return(2);
        }
    #ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBReintegrate(), cmeMemTable() loaded memSecureDB, table data.\n");
    #endif
        //Unprotect and reverse on table data, each protection mechanism defined in table meta.
        for (cont2=1; cont2<=numRowsPMeta; cont2++) //Iterate on each protection row in meta.
        {
            cmeStrConstrAppend(&currentMetaSalt,"%s",memProtectMetaData[cont][cont2*              //Get meta.salt
                               cmeIDDColumnFileMetaNumCols+cmeIDDanydb_salt]);
            cmeStrConstrAppend(&currentEncB64Data,"%s",memProtectMetaData[cont][cont2*            //Get prot. meta.attribute
                               cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attribute]);
            result=cmeUnprotectDBSaltedValue(currentEncB64Data,&currentMetaAttribute,cmeDefaultEncAlg,&currentMetaSalt,orgKey,&written);
            if (result) //Error
            {
    #ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBReintegrate(), cmeUnprotectDBSaltedValue() Error, can't "
                        "unprotect 'attribute' in meta table, B64str: %s with algorithm %s!\n",
                        currentEncB64Data,cmeDefaultEncAlg);
    #endif
                cmeMemSecureDBReintegrateFree();
                return(3);
            }
            cmeFree(currentEncB64Data);
            cmeStrConstrAppend(&currentEncB64Data,"%s",memProtectMetaData[cont][cont2*            //Get prot. meta.attributeData
                               cmeIDDColumnFileMetaNumCols+cmeIDDColumnFileMeta_attributeData]);
            result=cmeUnprotectDBSaltedValue(currentEncB64Data,&currentMetaAttributeData,cmeDefaultEncAlg,&currentMetaSalt,orgKey,&written);
            if (result) //Error
            {
    #ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBReintegrate(), cmeUnprotectDBSaltedValue() Error, can't "
                        "decrypt 'attributeData' in meta table, B64str: %s with algorithm %s!\n",
                        currentEncB64Data,cmeDefaultEncAlg);
    #endif
                cmeMemSecureDBReintegrateFree();
                return(4);
            }
            cmeFree(currentEncB64Data);
            // Check for name duplicates protection attribute = "name".
            if (!strncmp(currentMetaAttribute,cmeIDDColumnFileMeta_attribute_0,
                         sizeof(cmeIDDColumnFileMeta_attribute_0)))
            {
    #ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeMemSecureDBReintegrate(): 'name' checking name column duplicates to reintegrate.\n");
    #endif
                cmeStrConstrAppend(&(memColumnName[cont]),"%s",currentMetaAttributeData); //Save column Name.
                for (cont3=0;cont3<cont;cont3++) //check for duplicates with previous column names
                {
                    if ((memColumnName[cont3])&&(memColumnName[cont]))
                    {
                        if (!strcmp(memColumnName[cont3],memColumnName[cont])) //We have a duplicate!, insert data rows into first duplicate column and clear this column name.
                        {
                            for (cont4=1;cont4<=numRowsData[cont];cont4++) //Insert rows, skipping column names
                            {
                                cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION;"
                                                   " INSERT INTO data (id,userId,orgId,salt,value,rowOrder,MAC,sign,MACProtected,signProtected,otphDkey)"
                                                   " VALUES (NULL,'%s','%s','%s','%s','%s','%s','%s','%s','%s','%s');"
                                                   "COMMIT;",
                                                   memData[cont][cmeIDDColumnFileDataNumCols*cont4+cmeIDDanydb_userId],
                                                   memData[cont][cmeIDDColumnFileDataNumCols*cont4+cmeIDDanydb_orgId],
                                                   memData[cont][cmeIDDColumnFileDataNumCols*cont4+cmeIDDanydb_salt],
                                                   memData[cont][cmeIDDColumnFileDataNumCols*cont4+cmeIDDColumnFileData_value],
                                                   memData[cont][cmeIDDColumnFileDataNumCols*cont4+cmeIDDColumnFileData_rowOrder],
                                                   memData[cont][cmeIDDColumnFileDataNumCols*cont4+cmeIDDColumnFileData_MAC],
                                                   memData[cont][cmeIDDColumnFileDataNumCols*cont4+cmeIDDColumnFileData_sign],
                                                   memData[cont][cmeIDDColumnFileDataNumCols*cont4+cmeIDDColumnFileData_MACProtected],
                                                   memData[cont][cmeIDDColumnFileDataNumCols*cont4+cmeIDDColumnFileData_signProtected],
                                                   memData[cont][cmeIDDColumnFileDataNumCols*cont4+cmeIDDColumnFileData_otphDKey]);
                                if (cmeSQLRows(memSecureDB[cont3],sqlQuery,NULL,NULL)) //insert row.
                                {
#ifdef ERROR_LOG
                                    fprintf(stderr,"CaumeDSE Error: cmeMemSecureDBReintegrate(), cmeSQLRows() Error, can't "
                                            "insert row in secured DB data table!\n");
#endif
                                    cmeFree(sqlQuery);
                                    return(5);
                                }
                                cmeFree(sqlQuery);
                            }
                            (*dbNumReintegratedCols)--;
                            cmeFree(memColumnName[cont]); //clear current column name, since it was a duplicate (we copy all rows to the first col. name duplicate only)
                            //cmeStrConstrAppend(&(memColumnName[cont]),"*%d",cont); //Mark current column name, since it was a duplicate (we copy all rows to the first col. name duplicate only)
                        }
                    }
                }
            }
            //Free stuff in this FOR loop:
            cmeFree(currentEncB64Data);
            cmeFree(currentMetaAttribute);
            cmeFree(currentMetaAttributeData);
            cmeFree(currentMetaSalt);
        }
    }
    //Final packing of pointers (all integrated columns are moved to the first pointers).
    for (cont=0;cont<(*dbNumReintegratedCols);cont++)
    {
        if (!memColumnName[cont])//Empty column; we must move the first reintegrated column pointer to here
        {
            cont2=cont;
            while ((!memColumnName[cont2])&&(cont2<(dbNumCols-1)))
            {
                cont2++;
            }
            if (memColumnName[cont2])
            {
                cmeStrConstrAppend(&(memColumnName[cont]),"%s",memColumnName[cont2]); //copy column name (just to see where it will be moved in debugger.
                cmeFree(memColumnName[cont2]); //free moved column name.
                tmpPtr=memSecureDB[cont2]; //Now exchange pointers to column databases.
                memSecureDB[cont2]=memSecureDB[cont];
                memSecureDB[cont]=tmpPtr;
            }
        }
    }
    cmeMemSecureDBReintegrateFree();
    return (0);
}
