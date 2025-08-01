/***
Copyright 2010-2021 by Omar Alejandro Herrera Reyna

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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "common.h"

int cmeDirectoryExists (const char *dirPath)
{
    DIR *dp;
    /**TODO (ANY#6#): Add wrappers for corresponding Cloud Storage.
       0=local filesystem, 1=GoGrid, 2=RackSpace, 3=AmazonS3,...
    **/
    if (cmeStorageProvider==0)  //Handle common
    {
        if ((dp = opendir(dirPath)) == NULL)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeDirectoryExists(), Error, directory %s doesn't exist,"
                    "used %d cloud storage definition!\n",dirPath,cmeStorageProvider);
#endif
            return(1);
        }
    }
    return(0);
}

int cmeCSVFileRowsToMemTable (const char *fName, char ***elements, int *numCols,
                              int *processedRows, int hasColNames, int rowStart, int rowEnd)
{
    int cont,cont2,cont3;
    int elemCont=0;
    int rowCont=0;
    int flag=0;
    int fpEOF=0;
    FILE *fp=NULL;
    ssize_t lineLen=0;
    char **colNames=NULL;
    char *resStr=NULL;
    char defaultColName []="Column_";
    char curElement[cmeMaxCSVElemSize];
    char *curRow=NULL;                   // Buffer for current row, allocated dynamically
    size_t curRowSize=0;                 // Current size of curRow buffer

    if(rowEnd<rowStart) //Error, incorrect start/end row; Rows are inclusive, starting from row 0
                        //i.e., if rowEnd==rowStart, then that row (one only) is read.
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeCSVFileRowsToMem(), Error end row to be read"
                " %d, is smaller than starting row %d !\n",rowEnd,rowStart);
#endif
        return(1);
    }
    fp=fopen(fName,"r");
    if(!fp)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeCSVFileRowsToMem(), fopen() Error, can't "
                "open CSV file: %s !\n",fName);
#endif
        return(2);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeCSVFileRowsToMem(), fopen(), CSV file "
            "%s opened for reading.\n",fName);
#endif
    lineLen = getline(&curRow,&curRowSize,fp);
    resStr=(lineLen==-1)?NULL:curRow;
    cont=0;
    cont2=1;
    do          //Get # of columns
    {
        if (curRow[cont]==',')
        {
            cont2++;
        }
        else if (curRow[cont]=='\"')
        {
            do
            {
                cont++;
            }while ((cont<(int)strlen(curRow))&&(curRow[cont]!='\"'));
            if (cont>=(int)strlen(curRow)) //Error, quoted element not closed
            {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeCSVFileRowsToMem(), Error, quoted "
                "element not closed at first row, in CSV file: %s !\n",fName);
#endif
                fclose(fp);
                return (3);
            }
        }
        cont++;
    }while (cont<(int)strlen(curRow));
    *numCols=cont2;
    colNames=(char **)malloc(sizeof(char **) * (*numCols));  //reserve memory for column name pointers
    *elements=(char **)malloc(sizeof(char **) * (*numCols) *
              (rowEnd-rowStart+2));  //reserve memory for element pointers
    rowEnd++;       //increment to include header row.
    rowStart++;
    if (hasColNames)    //get Column names from first row first if CSV contains headers in 1st row.
    {

        if (resStr==NULL)  //Error or EOF
        {
            if (feof(fp)==0) // Error
            {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeCSVFileRowsToMem(), fgets() Error, can't "
                "read CSV file: %s!\n",fName);
#endif
                fclose(fp);
                return (4);
            }
            else    //EOF
            {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeCSVFileRowsToMem(), fgets() Error, reached "
                "EOF prematurely (before getting # of columns), in CSV file: %s!\n",fName);
#endif
                fclose(fp);
                return(5);
            }
        }
        else //No error, then process column names
        {
            flag=1;
            cont=0;
            cont2=0;
            cont3=0;
            while(flag)
            {
                cont2=0;
                if (curRow[cont]=='\"')   //parse quoted element
                {
                    cont++;
                    while ((curRow[cont]!='\"')&&(cont<(int)strlen(curRow)))
                    {
                        curElement[cont2]=curRow[cont];
                        cont2++;
                        cont++;
                    }
                    if (curRow[cont]!='\"') //error, quoted element not closed
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeCSVFileToMem(), Error, quoted "
                                "element not closed at first row (column names), in CSV file: "
                                " %s !\n",fName);
#endif
                        fclose(fp);
                        return(6);
                    }
                    else
                    {
                        curElement[cont2]='\0';
                        colNames[cont3]=(char *)malloc(sizeof(char) * (cont2+1));  //reserve memory for column name
                        memcpy(colNames[cont3],curElement,cont2+1);
                        cont3++;
                        while ((curRow[cont]!=',')&&(cont<(int)strlen(curRow))) //Skip to next element
                        {
                            cont++;
                        }
                        cont++; //go one character after the comma.
                    }
                }
                else            //parse normal element
                {
                    while ((curRow[cont]!=',')&&(cont<(int)strlen(curRow))&&
                           (curRow[cont]!='\n')&&(curRow[cont]!='\r'))
                    {
                        curElement[cont2]=curRow[cont];
                        cont2++;
                        cont++;
                    }
                    curElement[cont2]='\0';
                    colNames[cont3]=(char *)malloc(sizeof(char) * (cont2+1));  //reserve memory for column name
                    memcpy(colNames[cont3],curElement,cont2+1);
                    cont3++;
                    while ((curRow[cont]!=',')&&(cont<(int)strlen(curRow))) //Skip to next element
                    {
                        cont++;
                    }
                    cont++; //go one character after the comma.
                }
                if (cont>=(int)strlen(curRow))  //End cycle if end of string has been reached
                {
                    flag=0;
                }
            }
        }
    }
    else    //If CSV file has NO column headers at first row...
    {
        fseek(fp,0,SEEK_SET);  //Rewind to start of file first.
        for (cont3=0;cont3<*numCols;cont3++) //Fill in generic names.
        {
            colNames[cont3]=(char *)malloc(sizeof(char) * cmeMaxCSVDefaultColNameSize);  //reserve memory for column name
            /* Use snprintf to avoid potential buffer overflows when generating
             * generic column names.  The buffer has space for up to
             * cmeMaxCSVDefaultColNameSize bytes including the terminating null
             * byte.
             */
            snprintf(colNames[cont3], cmeMaxCSVDefaultColNameSize,
                     "%s%d", defaultColName, cont3);
        }
    }
    for (rowCont=1;rowCont<rowStart;rowCont++) //Skip to starting row.
    {
        lineLen = getline(&curRow,&curRowSize,fp);
        resStr=(lineLen==-1)?NULL:curRow;
        if (feof(fp)) //End of File
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeCSVFileToMem(), fgets() Error, reached "
                    "EOF prematurely (before getting to starting row), in CSV file: %s!\n",fName);
#endif
            fclose(fp);
            return(7);
        }
    }
    *processedRows=0;       //Reset counter for number of processed rows.
    elemCont=0;             //Reset element counter
    for (cont=0;cont<*numCols; cont++) //Add column names to table of elements (1st row).
    {
        (*elements)[cont]=NULL;
        cmeStrConstrAppend(&((*elements)[cont]),"%s",colNames[cont]);
        //memcpy((*elements)[elemCont],colNames[cont],strlen(colNames[cont]));
        elemCont++;
    }
    for (cont=0; cont<*numCols; cont++) //Free column names.
    {
        cmeFree(colNames[cont]);
    }
    cmeFree(colNames);
    fpEOF=0;
    while ((rowCont<=rowEnd)&&(!fpEOF)) //Process each row.
    {
        cont=0;
        cont2=0;
        lineLen = getline(&curRow,&curRowSize,fp);  //Read one row.
        resStr=(lineLen==-1)?NULL:curRow;
        rowCont++;
        if (resStr==NULL)  //Error or EOF
        {
            if (feof(fp)==0) // Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeCSVFileToMem(), fgets() Error, can't "
                        "read CSV file: %s!\n",fName);
#endif
                fclose(fp);
                return (8);
            }
            else    //EOF
            {
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeCSVFileToMem(), fgets() EOF reached "
                        "prematurely (before getting to end Row), in CSV file: %s!\n",fName);
#endif
                fpEOF=1;
            }
        }
        else
        {
            flag=1;
            while(flag) //Process current row
            {
                cont2=0;
                if (curRow[cont]=='\"')   //parse quoted element
                {
                    cont++;
                    while ((curRow[cont]!='\"')&&(cont<(int)strlen(curRow)))
                    {
                        curElement[cont2]=curRow[cont];
                        cont2++;
                        cont++;
                    }
                    if (curRow[cont]!='\"') //error, quoted element not closed
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeCSVFileToMem(), Error, quoted "
                                "element not closed at processed row %d, in CSV file: "
                                "%s !\n",*processedRows,fName);
#endif
                        fclose(fp);
                        return(9);
                    }
                    else
                    {
                        curElement[cont2]='\0';
                        (*elements)[elemCont]=(char *)malloc(sizeof(char) *
                                              (cont2+1));  //reserve memory for element
                        memcpy((*elements)[elemCont],curElement,cont2+1);
                        elemCont++;
                        while ((curRow[cont]!=',')&&(cont<(int)strlen(curRow))) //Skip to next element
                        {
                            cont++;
                        }
                        cont++; //go one character after the comma.
                    }
                }
                else            //parse normal element
                {
                    while ((curRow[cont]!=',')&&(cont<(int)strlen(curRow))&&
                           (curRow[cont]!='\n')&&(curRow[cont]!='\r'))
                    {
                        curElement[cont2]=curRow[cont];
                        cont2++;
                        cont++;
                    }
                    curElement[cont2]='\0';
                    (*elements)[elemCont]=(char *)malloc(sizeof(char) * (cont2+1));  //reserve memory for element
                    memcpy((*elements)[elemCont],curElement,cont2+1);
                    elemCont++;
                    while ((curRow[cont]!=',')&&(cont<(int)strlen(curRow))) //Skip to next element
                    {
                        cont++;
                    }
                    cont++; //go one character after the comma.
                }
                if (cont>=(int)strlen(curRow))  //End cycle, if end of string has been reached
                {
                    flag=0;
                }
            }
            (*processedRows)++;
        }
    }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeCSVFileToMem(), processed %d rows "
                "(not counting header row, if required), from CSV file: %s!\n",*processedRows,fName);
#endif
    fclose(fp);
    cmeFree(curRow);
    return (0);
}

int cmeCSVFileRowsToMemTableFinal (char ***elements, int numCols,int processedRows)
{
    int cont,cont2;
    for (cont2=0; cont2<processedRows; cont2++) //Free elements.
    {
        for (cont=0; cont<numCols; cont++)
        {
            cmeFree ((*elements)[cont+(cont2*numCols)]);
        }
    }
    cmeFree(*elements);
    return(0);
}

int cmeLoadStrFromFile (char **pDstStr, const char *filePath, int *dstStrLen)
{
    int fileLen,readBytes;
    FILE *fp=NULL;

    fp=fopen(filePath,"r");
    if(!fp) //Error
    {
#ifdef ERROR_LOG
        fprintf(stdout,"CaumeDSE Error: cmeLoadStrFromFile(), can't open file %s for reading!\n",filePath);
#endif
        return(1);
    }
    fseek(fp,0L,SEEK_END);
    fileLen=ftell(fp);
    rewind(fp);
    *pDstStr=(char *)malloc(sizeof(char)*(fileLen+1));  //Note that caller must free *pDstStr!
    if (!pDstStr) //Error
    {
#ifdef ERROR_LOG
        fprintf(stdout,"CaumeDSE Error: cmeLoadStrFromFile(), can't malloc() memory to read file %s, of length %d !\n",
                filePath,fileLen);
#endif
        fclose(fp);
        return(2);
    }
    readBytes=fread(*pDstStr,1,fileLen,fp);
    fclose(fp);
    *dstStrLen=readBytes;
    if (fileLen!=readBytes) //Error
    {
#ifdef ERROR_LOG
        fprintf(stdout,"CaumeDSE Error: cmeLoadStrFromFile(), read only %d bytes of %d from file %s!\n",
                readBytes,fileLen,filePath);
#endif
        return(3);
    }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeLoadStrFromFile(), read %d bytes from file %s, of length %d.\n",
                readBytes,filePath,fileLen);
#endif
    return(0);
}

int cmeWriteStrToFile (char *pSrcStr, const char *filePath, int srcStrLen)
{
    int written;
    FILE *fp=NULL;

    fp=fopen(filePath,"w");
    if(!fp) //Error
    {
#ifdef ERROR_LOG
        fprintf(stdout,"CaumeDSE Error: cmeWriteStrToFile(), can't open file %s for writing!\n",filePath);
#endif
        return(1);
    }
    if (!pSrcStr) //Error
    {
#ifdef ERROR_LOG
        fprintf(stdout,"CaumeDSE Error: cmeWriteStrToFile(), pointer to src string is NULL!\n");
#endif
        fclose(fp);
        return(2);
    }
    written=fwrite (pSrcStr,1,srcStrLen,fp);
    fclose(fp);
    if (srcStrLen!=written) //Error
    {
#ifdef ERROR_LOG
        fprintf(stdout,"CaumeDSE Error: cmeWriteStrToFile(), wrote only %d bytes of %d to file %s!\n",
                written,srcStrLen,filePath);
#endif
        return(3);
    }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWriteStrToFile(), wrote %d bytes to file %s, from srcStr of length %d.\n",
                written,filePath,srcStrLen);
#endif
    return(0);
}

int cmeCSVFileToSecureDB (const char *CSVfName,const int hasColNames,int *numCols,int *processedRows,
                          const char *userId,const char *orgId,const char *orgKey, const char **attribute,
                          const char **attributeData, const int numAttribute,const int replaceDB,
                          const char *resourceInfo, const char *documentType, const char *documentId,
                          const char *storageId, const char *storagePath)
{
    int cont,cont2,cont3,rContLimit,result,readBytes,written;
    int numEntries=0;
    int totalParts=0;
    int rowStart=0;
    int numSQLDBfNames=0;               //with column slicing this will be (*numcols)*((((*processedRows)/cmeMaxCSVRowsInPart))+(((*processedRows)%cmeMaxCSVRowsInPart > 0)? 1 : 0 ))
    int cycleProcessedRows=0;
    int rowEnd=cmeCSVRowBuffer-1;
    sqlite3 **ppDB=NULL;
    sqlite3 *resourcesDB=NULL;
    char **elements=NULL;               //Note: elements will be freed via the special function cmeCSVFileRowsToMemTableFinal() within the corresponding loop; it is not included in cmeCSVFileToSecureDBFree()
    char **SQLDBfNames=NULL;            //Will hold the name of each file part.
    char **SQLDBfMACs=NULL;             //Will hold the MAC of each file part.
    char **SQLDBfSalts=NULL;            //Will hold the salt of each file part.
    char **colNames=NULL;
    char *currentRawFileContent=NULL;   //Will hold the binary contents of each created file part during the hashing process.
    char *resourcesDBName=NULL;
    char *sqlQuery=NULL;
    char *value=NULL;                   //Just a pointer to elements within elements[]. No need to free.
    char *bkpFName=NULL;
    char *securedRowOrder=NULL;
    char *securedValue=NULL;
    char *MAC=NULL;                    //'data' table values depending on attributes selected.
    char *salt=NULL;
    char *MACProtected=NULL;
    char *sign=NULL;
    char *signProtected=NULL;
    char *otphDkey=NULL;
    char *sanitizedStr=NULL;
    const char *nullParam="";
    const char resourcesDBFName[]="ResourcesDB";
    #define cmeCSVFileToSecureDBFree() \
        do { \
            cmeFree(resourcesDBName); \
            cmeFree(sqlQuery); \
            cmeFree(bkpFName); \
            cmeFree(securedRowOrder); \
            cmeFree(securedValue); \
            cmeFree(MAC); \
            cmeFree(salt); \
            cmeFree(MACProtected); \
            cmeFree(sign); \
            cmeFree(signProtected); \
            cmeFree(otphDkey); \
            cmeFree(currentRawFileContent); \
            cmeFree(sanitizedStr); \
            if (resourcesDB) \
            { \
                cmeDBClose(resourcesDB); \
                resourcesDB=NULL; \
            } \
            if (ppDB) \
            { \
                for (cont=0;cont<(*numCols);cont++) \
                { \
                    cmeDBClose(ppDB[cont]); \
                    ppDB[cont]=NULL; \
                } \
                cmeFree(ppDB); \
            } \
            if (SQLDBfNames) \
            { \
                for (cont=0;cont<numSQLDBfNames;cont++) \
                { \
                    cmeFree(SQLDBfNames[cont]); \
                } \
                cmeFree(SQLDBfNames); \
            } \
            if (SQLDBfMACs) \
            { \
                for (cont=0;cont<numSQLDBfNames;cont++) \
                { \
                    cmeFree(SQLDBfMACs[cont]); \
                } \
                cmeFree(SQLDBfMACs); \
            } \
            if (SQLDBfSalts) \
            { \
                for (cont=0;cont<numSQLDBfNames;cont++) \
                { \
                    cmeFree(SQLDBfSalts[cont]); \
                } \
                cmeFree(SQLDBfSalts); \
            } \
            if (colNames) \
            { \
                for (cont=0;cont<(*numCols);cont++) \
                { \
                    cmeFree(colNames[cont]); \
                } \
                cmeFree(colNames); \
            } \
        } while (0); //Local free() macro.

    cmeStrConstrAppend(&resourcesDBName,"%s%s",cmeDefaultFilePath,resourcesDBFName);
    result=cmeDBOpen(resourcesDBName,&resourcesDB);
    if (result) //Error
    {
        cmeCSVFileToSecureDBFree();
        return(1);
    }
    result=cmeExistsDocumentId(resourcesDB,documentId,orgKey,&numEntries);
    if (numEntries>0) //We have the same documentId already in the database...
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeCVSFileToSecureDB(), documentId %s already exists; "
                "replace instruction: %d\n",documentId,replaceDB);
#endif
        if (!replaceDB)
        {
            cmeCSVFileToSecureDBFree();
            return(3);
        }
        else //delete old secureDB first, and then replace
        {
            result=cmeDeleteSecureDB(resourcesDB,documentId,orgKey,storagePath);
        }
    }
    cmeDBClose(resourcesDB);
    resourcesDB=NULL;
    *numCols=0;         //Set default results
    *processedRows=0;
    do
    {
        result=cmeCSVFileRowsToMemTable(CSVfName, &elements, numCols, &cycleProcessedRows, hasColNames, rowStart, rowEnd);
        if(result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeCVSFileToSecureDB(), cmeCSVFileRowsToMem() Error, can't "
                    "open CSV file: %s !\n",CSVfName);
#endif
            cmeCSVFileToSecureDBFree();
            return(4);
        }
        if (colNames) //If not the first cycle, free colNames (which will also set to NULL all ptrs.)
        {
            for (cont=0;cont<(*numCols);cont++)
            {
                cmeFree(colNames[cont]);
            }
            cmeFree(colNames);
        }
        colNames=(char **)malloc((sizeof(char *)) * (*numCols)); //Reserve space and copy column names.
        for (cont=0;cont<(*numCols);cont++)
        {
            colNames[cont]=NULL;    //Set all ptrs. to NULL as required by cmeStrConstrAppend().
            if(!strcmp(elements[cont],"id")) //Found column named "id"!
            {
                cmeStrConstrAppend(&(colNames[cont]),"_id"); //"id" name is reserved for internal databases; so we change it!
            }
            else //Otherwise, just copy the column name provided.
            {
                cmeStrConstrAppend(&(colNames[cont]),"%s",elements[cont]);
            }
        }
        // TODO (OHR#6#): Create & call function to create DB files in memory for CSV column imports.
        if (!(SQLDBfNames)) //Create (and open) DB files in memory if they have not been created.
        {
            totalParts=((cycleProcessedRows/cmeMaxCSVRowsInPart)+((cycleProcessedRows%cmeMaxCSVRowsInPart > 0)? 1 : 0 ));
            numSQLDBfNames=(*numCols)*totalParts;
            ppDB=(sqlite3 **)malloc(sizeof(sqlite3 *)*numSQLDBfNames);
            if (!ppDB)
            {
                cmeCSVFileToSecureDBFree();
                return(5);
            }
            SQLDBfNames=(char **)malloc(sizeof(char *)*numSQLDBfNames);
            SQLDBfMACs=(char **)malloc(sizeof(char *)*numSQLDBfNames);
            SQLDBfSalts=(char **)malloc(sizeof(char *)*numSQLDBfNames);
            if ((!SQLDBfNames)||(!SQLDBfMACs)||(!SQLDBfSalts))
            {
                cmeCSVFileToSecureDBFree();
                return(6);
            }
            for(cont=0;cont<numSQLDBfNames;cont++) //Reset memory pointers
            {
                SQLDBfNames[cont]=NULL;
                SQLDBfMACs[cont]=NULL;
                SQLDBfSalts[cont]=NULL;
                cmeGetRndSaltAnySize(&(SQLDBfSalts[cont]),cmeDefaultValueSaltLen); //Get current salt for encryption (random hexstr).
            }
            for (cont=0;cont<numSQLDBfNames;cont++) //Create random filenames for column parts.
            {
                cmeGetRndSalt(&(SQLDBfNames[cont]));
                //TODO (OHR#8#): Create SQLDBfNames collision handling routine. Just in case.
                if (cmeDBCreateOpen(":memory:",&(ppDB[cont])))
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeCVSFileToSecureSQL(), cmeDBCreateOpen() Error, can't "
                            "Create and Open memory DB corresponding to DB file: %s !\n",SQLDBfNames[cont]);
#endif
                    cmeCSVFileToSecureDBFree();
                    return(7);
                }
                cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; CREATE TABLE data "
                                    "(id INTEGER PRIMARY KEY, userId TEXT, orgId TEXT, salt TEXT,"
                                    " value TEXT, rowOrder TEXT, MAC TEXT, sign TEXT, MACProtected TEXT,"
                                    " signProtected TEXT, otphDkey TEXT);"
                                    "COMMIT;");
                if (cmeSQLRows((ppDB[cont]),sqlQuery,NULL,NULL)) //Create a table 'data'.
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeCVSFileToSecureSQL(), cmeSQLRows() Error, can't "
                            "create table 'data' in DB file %d: %s!\n",cont,SQLDBfNames[cont]);
#endif
                    cmeCSVFileToSecureDBFree();
                    return(9);
                }
                cmeFree(sqlQuery);  //Free memory that was used for queries.
                cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; CREATE TABLE meta "
                                    "(id INTEGER PRIMARY KEY, userId TEXT, orgID TEXT, salt TEXT,"
                                    " attribute TEXT, attributeData TEXT); COMMIT;");
                if (cmeSQLRows((ppDB[cont]),sqlQuery,NULL,NULL)) //Create a table 'meta'.
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeCVSFileToSecureSQL(), cmeSQLRows() Error, can't "
                            "create table 'meta' in DB file %d: %s!\n",cont,SQLDBfNames[cont]);
#endif
                    cmeCSVFileToSecureDBFree();
                    return(11);
                }
                cmeFree(sqlQuery);  //Free memory that was used for queries.
            }
            for (cont=0;cont<numSQLDBfNames;cont++) //Insert data into meta table.
            {   //Insert 'name' attribute.
                cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; "
                                    "INSERT INTO meta (id, userId, orgId, attribute, attributeData) "
                                    "VALUES (NULL");
                cmeFree(sanitizedStr);
                cmeSanitizeStrForSQL(userId,&sanitizedStr);   //Sanitize parameter userId for use in SQL statement.
                cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                cmeFree(sanitizedStr);
                cmeSanitizeStrForSQL(orgId,&sanitizedStr);   //Sanitize parameter orgId for use in SQL statement.
                cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                cmeStrConstrAppend(&sqlQuery,",'name'");    //Add literal 'name' for attribute.
                cmeFree(sanitizedStr);
                cmeSanitizeStrForSQL(colNames[cont%(*numCols)],&sanitizedStr);  //Sanitize parameter attributeData for use in SQL statement.
                cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                cmeStrConstrAppend(&sqlQuery,");");    //End sql statement string.
                cmeStrConstrAppend(&salt,"%s",nullParam);   //Salt will be calculated and included in cmeMemSecureDBProtect()
                for (cont2=0; cont2<numAttribute; cont2++) //Append other security attributes.
                {
                    cmeStrConstrAppend(&sqlQuery,"INSERT INTO meta (id, userId, orgId, salt, attribute, attributeData) "
                                    "VALUES (NULL");
                    cmeFree(sanitizedStr);
                    cmeSanitizeStrForSQL(userId,&sanitizedStr);   //Sanitize parameter userId for use in SQL statement.
                    cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                    cmeFree(sanitizedStr);
                    cmeSanitizeStrForSQL(orgId,&sanitizedStr);   //Sanitize parameter orgId for use in SQL statement.
                    cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                    cmeStrConstrAppend(&sqlQuery,",'%s'",salt);    //Add literal salt.
                    cmeFree(sanitizedStr);
                    cmeSanitizeStrForSQL(attribute[cont2],&sanitizedStr);   //Sanitize parameter attribute for use in SQL statement.
                    cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                    cmeFree(sanitizedStr);
                    cmeSanitizeStrForSQL(attributeData[cont2],&sanitizedStr);  //Sanitize parameter attributeData for use in SQL statement.
                    cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                    cmeStrConstrAppend(&sqlQuery,");");    //End sql statement string.
                }
                cmeFree(salt);
                cmeStrConstrAppend(&sqlQuery,"COMMIT;");
                if (cmeSQLRows((ppDB[cont]),sqlQuery,NULL,NULL)) //Insert row.
                {
    #ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeCVSFileToSecureSQL(), cmeSQLRows() Error, can't "
                            "insert row in DB file %d: %s!\n",cont,SQLDBfNames[cont]);
    #endif
                    cmeCSVFileToSecureDBFree();
                    return(17);
                }
                cmeFree(sqlQuery); //Free memory that was used for queries.
            }
        }
        //TODO (OHR#6#): Create and call function to insert data into tables (move code there).
        for (cont=0;cont<totalParts;cont++) //Process each column part.
        {
            for (cont2=0;cont2<(*numCols);cont2++) //Process each column.
            {
                if ((cont+1)*cmeMaxCSVRowsInPart>cycleProcessedRows) // Last part? yes-> then set rContLimit to the remaining rows.
                {
                    rContLimit=cycleProcessedRows-(cont*cmeMaxCSVRowsInPart);
                }
                else
                {
                    rContLimit=(cycleProcessedRows>cmeMaxCSVRowsInPart)?cmeMaxCSVRowsInPart:cycleProcessedRows;
                }
                for(cont3=1;cont3<=rContLimit;cont3++) //Skip header row in elements[]; process each row.
                {
                    value=elements[cont2+((*numCols)*(cont3+cont*cmeMaxCSVRowsInPart))];
                    //Setup attribute defaults.
                    cmeStrConstrAppend(&securedRowOrder,"%d",cont3+rowStart+cont*cmeMaxCSVRowsInPart);
                    cmeStrConstrAppend(&MAC,"%s",nullParam); // TODO (OHR#2#): Calculate MAC, MAC protected and stuff. Probably outside this function.
                    cmeStrConstrAppend(&MACProtected,"%s",nullParam);
                    cmeStrConstrAppend(&sign,"%s",nullParam);
                    cmeStrConstrAppend(&signProtected,"%s",nullParam);
                    cmeStrConstrAppend(&otphDkey,"%s",nullParam);
                    cmeStrConstrAppend(&salt,"%s",nullParam);   //Salt wil be included in cmeMemSecureDBProtect().
                    cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; INSERT INTO data "
                                                "(id,userId,orgId,salt,value,rowOrder,MAC,sign,MACProtected,signProtected,otphDkey)"
                                                " VALUES (NULL");
                    cmeFree(sanitizedStr);
                    cmeSanitizeStrForSQL(userId,&sanitizedStr);   //Sanitize parameter userId for use in SQL statement.
                    cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                    cmeFree(sanitizedStr);
                    cmeSanitizeStrForSQL(orgId,&sanitizedStr);   //Sanitize parameter orgId for use in SQL statement.
                    cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                    cmeStrConstrAppend(&sqlQuery,",'%s'",salt);    //Add literal salt.
                    cmeFree(sanitizedStr);
                    cmeSanitizeStrForSQL(value,&sanitizedStr);   //Sanitize parameter value for use in SQL statement.
                    cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                    cmeStrConstrAppend(&sqlQuery,",'%s','%s','%s','%s','%s','%s');" //Add remaining parameters.
                                                "COMMIT;",securedRowOrder,MAC,sign,
                                                MACProtected,signProtected,otphDkey);
                    //Free stuff;
                    cmeFree(salt);
                    cmeFree(otphDkey);
                    cmeFree(signProtected);
                    cmeFree(sign);
                    cmeFree(MACProtected);
                    cmeFree(MAC);
                    cmeFree(securedRowOrder);
                    if (cmeSQLRows((ppDB[(*numCols)*cont+cont2]),sqlQuery,NULL,NULL)) //Insert row.
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeCVSFileToSecureSQL(), cmeSQLRows() Error, can't "
                                "insert row in DB file %d: %s!\n",cont,SQLDBfNames[cont]);
#endif
                        cmeCSVFileToSecureDBFree();
                        return(13);
                    }
                    cmeFree(sqlQuery);  //Free memory that was used for queries.
                }
            }
        }
        rowStart+=cmeCSVRowBuffer; //Process next block of rows.
        rowEnd+=cmeCSVRowBuffer;
        cmeCSVFileRowsToMemTableFinal(&elements,*numCols,cycleProcessedRows); //Free element table
        *processedRows+=cycleProcessedRows;
    } while (cycleProcessedRows==cmeCSVRowBuffer);

    for (cont=0; cont<numSQLDBfNames; cont++)  //Create backup DB files; copy Memory DBs there.
    {
        if (numAttribute)  //If security attributes are defined, override corresponding defaults.
        {
            result=cmeMemSecureDBProtect(ppDB[cont],orgKey);
            cmeStrConstrAppend(&sqlQuery,"VACUUM;"); //Reconstruct DB without slack space w/ unprotected data!
            if (cmeSQLRows((ppDB[cont]),sqlQuery,NULL,NULL)) //Vacuum DB col.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeCVSFileToSecureSQL(), cmeSQLRows() Error, can't "
                        "VACUUM DB file %d: %s!\n",cont,SQLDBfNames[cont]);
#endif
                cmeCSVFileToSecureDBFree();
                return(14);
            }
            cmeFree(sqlQuery);  //Free memory that was used for queries.
        }
        cmeFree(bkpFName);
        cmeStrConstrAppend(&bkpFName,"%s%s",storagePath,SQLDBfNames[cont]);
        result=cmeMemDBLoadOrSave(ppDB[cont],bkpFName,1);
        if (result)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeCVSFileToSecureSQL(), cmeMemDBLoadOrSave() error cannot "
                    "load/save file: %s; Save: %d!\n",bkpFName,1);
#endif
            cmeCSVFileToSecureDBFree();
            return(15);
        }
        //Get MAC of recently created file:
        result=cmeLoadStrFromFile(&currentRawFileContent,bkpFName,&readBytes);
        if (result)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeCVSFileToSecureSQL(), cmeLoadStrFromFile() error cannot "
                    "load recently created file part: %s !\n",bkpFName);
#endif
            cmeCSVFileToSecureDBFree();
            return(16);
        }
        result=cmeHMACByteString((const unsigned char *)currentRawFileContent,(unsigned char **)&(SQLDBfMACs[cont]),readBytes,&written,cmeDefaultMACAlg,&(SQLDBfSalts[cont]),orgKey);
        cmeFree(currentRawFileContent);
        cmeFree(bkpFName);
    }
    result=cmeRegisterSecureDBorFile ((const char **)SQLDBfNames, numSQLDBfNames,(const char **)SQLDBfSalts, (const char **)SQLDBfMACs,totalParts,orgKey, userId, orgId, resourceInfo,
                                       documentType,documentId,storageId,orgId);
    if (result) //error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeCVSFileToSecureSQL(), cmeRegisterSecureDB() error cannot "
                "register documentId %s with documentType %s; Error#: %d!\n",documentId,documentType,result);
#endif
        cmeCSVFileToSecureDBFree();
        return(17);
    }
    cmeCSVFileToSecureDBFree();
    return (0);
}

int cmeRAWFileToSecureFile (const char *rawFileName, const char *userId,const char *orgId,const char *orgKey,
                            const char *resourceInfo, const char *documentType, const char *documentId,
                            const char *storageId, const char *storagePath)
{   //IDD v.1.0.21
    int cont,result,written,written2,lastPartSize;
    int bufferLen=0;
    int numParts=0;
    int tmpMemDataLen=0;            //This will contain the size in bytes of the data read in memory from file.
    char *tmpMemDataBuffer=NULL;    //This will point to reserved memory that will hold the file data.
    char *tmpMemCiphertext=NULL;    //This will hold the encrypted data.
    char *tmpMemB64Ciphertext=NULL; //This will hold the B64 encoded version of the encrypted data.
    char *currentFilePartPath=NULL; //This will hold the whole file path for the current file part.
    const char *pFilePartStart=NULL;      //This will point to the start of each file slice (no need to free this ptr).
    char **filePartNames=NULL;      //This will hold the random file part names.
    char **filePartMACs=NULL;       //This will hold the MACs for all file parts.
    char **filePartSalts=NULL;      //This will hold the salts for all file parts.
    #define cmeRAWFileToSecureFileFree() \
        do { \
            cmeFree(tmpMemDataBuffer); \
            cmeFree(tmpMemCiphertext); \
            cmeFree(tmpMemB64Ciphertext); \
            cmeFree(currentFilePartPath); \
            if (filePartNames) \
            { \
                for (cont=0;cont<numParts;cont++) \
                { \
                    cmeFree(filePartNames[cont]); \
                } \
                cmeFree(filePartNames); \
            } \
            if (filePartMACs) \
            { \
                for (cont=0;cont<numParts;cont++) \
                { \
                    cmeFree(filePartMACs[cont]); \
                } \
                cmeFree(filePartMACs); \
            } \
            if (filePartSalts) \
            { \
                for (cont=0;cont<numParts;cont++) \
                { \
                    cmeFree(filePartSalts[cont]); \
                } \
                cmeFree(filePartSalts); \
            } \
        } while (0); //Local free() macro.

    result=cmeLoadStrFromFile(&tmpMemDataBuffer,rawFileName,&tmpMemDataLen); //Read file into memory
    if (result) //Error reading file into memory.
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeRAWFileToSecureFile(), cmeLoadStrFromFile() error cannot "
                "read raw file: %s !\n",rawFileName);
#endif
        cmeRAWFileToSecureFileFree();
        return(1);
    }

    numParts=tmpMemDataLen/cmeMaxRAWDataInPart;
    lastPartSize=tmpMemDataLen%cmeMaxRAWDataInPart;
    if (lastPartSize) // We have a remainder
    {
        numParts++;
    }
    filePartNames=(char **)malloc(sizeof(char *)*numParts); //Reserve memory for file part name pointers.
    filePartMACs=(char **)malloc(sizeof(char *)*numParts); //Reserve memory for file part MAC pointers.
    filePartSalts=(char **)malloc(sizeof(char *)*numParts); //Reserve memory for file part salt pointers.
    for(cont=0;cont<numParts; cont++) // Initialize pointers.
    {
        filePartMACs[cont]=NULL;
        filePartNames[cont]=NULL;
        filePartSalts[cont]=NULL;
        cmeGetRndSalt(&(filePartNames[cont]));  //Get current file name (random hexstr).
        cmeGetRndSaltAnySize(&(filePartSalts[cont]),cmeDefaultValueSaltLen); //Get current salt for encryption (random hexstr).
    }
    for (cont=0;cont<numParts;cont++)// Slice file in parts - analogous to column parts in secureDB for CSVs.
    {
        cmeStrConstrAppend(&currentFilePartPath,"%s%s",storagePath,filePartNames[cont]);
        pFilePartStart=&(tmpMemDataBuffer[cont*cmeMaxRAWDataInPart]); //Point to beginning of file part.

        if ((cont+1)==numParts) //If this is the last part.
        {
            bufferLen=lastPartSize;
        }
        else //Not the last part.
        {
            bufferLen=cmeMaxRAWDataInPart;
        }
        //Protect memory data with orgKey and default encryption algorithm:
        result=cmeProtectByteString(pFilePartStart,&tmpMemB64Ciphertext,cmeDefaultEncAlg,&(filePartSalts[cont]),orgKey,
                                    &written,bufferLen);
        if (result) //Error protecting data in memory
        {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeRAWFileToSecureFile(), cmeProtectByteString() error cannot "
                "protect file part number %d, with algorithm %s !\n",cont,cmeDefaultEncAlg);
#endif
            cmeRAWFileToSecureFileFree();
            return(2);
        }
        cmeWriteStrToFile(tmpMemB64Ciphertext,currentFilePartPath,written);  //Write encrypted data to currentFilePartPath file.
        cmeHMACByteString((const unsigned char *)tmpMemB64Ciphertext,(unsigned char **)&(filePartMACs[cont]),written,&written2,
                          cmeDefaultHshAlg,&(filePartSalts[cont]),orgKey); //Calculate MAC on file part in memory.
        cmeFree(tmpMemB64Ciphertext); //Free B64 encoded, encryptede data; we don't need it any more.
        cmeFree(currentFilePartPath);
    }
    //Register parts as a secure file in engine DBs
    result=cmeRegisterSecureDBorFile ((const char **)filePartNames,numParts,(const char **)filePartSalts,(const char **)filePartMACs,
                                      numParts,orgKey,userId,orgId,resourceInfo,documentType,documentId,storageId,orgId);
    if (result)//Error
    {
        cmeRAWFileToSecureFileFree();
        return(4);
    }
    cmeRAWFileToSecureFileFree();
    return (0);
}

int cmeSecureFileToTmpRAWFile (char **tmpRAWFile, sqlite3 *pResourcesDB,const char *documentId,
                               const char *documentType, const char *documentPath, const char *orgId,
                               const char *storageId, const char *orgKey)
{   //IDD v.1.0.21
    int cont,cont2,result,written,written2,MACLen;
    int numRows=0;
    int numCols=0;
    int dbNumCols=0;
    int partMACmismatch=0;
    FILE *fpTmpRAWFile=NULL;
    int *memFilePartsOrder=NULL;        //Dynamic array to store the corresponding order of the file part.
    int *memFilePartsDataSize=NULL;     //Dynamic array to store the corresponding size in bytes, of the file part.
    char **memFilePartsData=NULL;       //Dynamic array to store unencrypted data of each part of the protected file.
    char **queryResult=NULL;
    char **colSQLDBfNames=NULL;         //Dynamic array to store part filenames of the protected RAWFile.
    char **memFilePartsMACs=NULL;
    char *currentDocumentId=NULL;
    char *currentDocumentType=NULL;
    char *currentOrgResourceId=NULL;
    char *currentStorageId=NULL;
    char *currentPartId=NULL;
    char *currentEncryptedData=NULL;
    char *protectedValueMAC=NULL;
    char *bkpFName=NULL;
    unsigned char *decodedEncryptedString=NULL;
    //MEMORY CLEANUP MACRO for local function.
    #define cmeSecureFileToTmpRAWFileFree() \
        do { \
            cmeFree(currentDocumentId); \
            cmeFree(currentPartId); \
            cmeFree(currentDocumentType); \
            cmeFree(currentOrgResourceId); \
            cmeFree(currentStorageId); \
            cmeFree(currentEncryptedData); \
            cmeFree(bkpFName); \
            cmeFree(decodedEncryptedString); \
            cmeFree(memFilePartsOrder); \
            cmeFree(memFilePartsDataSize); \
            cmeFree(protectedValueMAC); \
            for (cont=0;cont<dbNumCols;cont++) \
            { \
                if (colSQLDBfNames) \
                { \
                    cmeFree(colSQLDBfNames[cont]); \
                } \
                if (memFilePartsData) \
                { \
                    cmeFree(memFilePartsData[cont]); \
                } \
                if (memFilePartsMACs) \
                { \
                    cmeFree(memFilePartsMACs[cont]); \
                } \
            } \
            cmeFree(colSQLDBfNames); \
            cmeFree(memFilePartsData); \
            cmeFree(memFilePartsMACs); \
            if (fpTmpRAWFile) \
            { \
                fclose(fpTmpRAWFile); \
                fpTmpRAWFile=NULL; \
            } \
        } while (0); //Local free() macro.

    result=cmeMemTable(pResourcesDB,"SELECT * FROM documents",&queryResult,&numRows,&numCols);
    if(result) // Error
    {
        cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
        return(1);
    }
    //We reserve memory for the first file part (and will increment memory as needed):
    colSQLDBfNames=(char **)malloc(sizeof(char *));
    memFilePartsOrder=(int *)malloc(sizeof(int));
    memFilePartsDataSize=(int *)malloc(sizeof(int));
    memFilePartsData=(char **)malloc(sizeof(char *));
    memFilePartsMACs=(char **)malloc(sizeof(char *));
    *colSQLDBfNames=NULL; //Initialize pointer to first column name.
    *memFilePartsOrder=0; //Initialize pointer to first part order number.
    *memFilePartsDataSize=0;
    *memFilePartsData=NULL; //Initialize pointer to first part data byte string (unencrypted data).
    *memFilePartsMACs=NULL; //Initialize pointer to first part data MAC of encrypted data.
    cmeDigestLen(cmeDefaultMACAlg,&MACLen); //Get length of the MAC value (bytes).
    MACLen*=2; //Convert byte length to HexStr length.
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
                fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeUnprotectDBSaltedValue() error, cannot "
                        "decrypt documentId!\n");
#endif
                cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
                return(2);
            }
        }
        else //MAC is incorrect; skip decryption process.
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Warning: cmeSecureFileToTmpRAWFile(), cmeHMACByteString() cannot "
                    "verify documentId MAC!\n");
#endif
            cmeStrConstrAppend(&currentDocumentId,""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
        }
        //Unprotect documentType:
        cmeFree(protectedValueMAC);
        cmeHMACByteString((const unsigned char*)queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_type]+MACLen,
                          (unsigned char **)&protectedValueMAC,strlen(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_type]+MACLen),
                          &written,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
        if (!strncmp(protectedValueMAC,queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_type],MACLen)) //MAC is correct; proceed with decryption.
        {
            result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_type]+MACLen,
                                 &currentDocumentType,cmeDefaultEncAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),
                                 orgKey,&written);
            if (result)  //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeUnprotectDBSaltedValue() error, cannot "
                        "decrypt documentType!\n");
#endif
                cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
                return(3);
            }
        }
        else //MAC is incorrect; skip decryption process.
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Warning: cmeSecureFileToTmpRAWFile(), cmeHMACByteString() cannot "
                    "verify documentType MAC!\n");
#endif
            cmeStrConstrAppend(&currentDocumentType,""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
        }
        //Unprotect orgResourceId:
        cmeFree(protectedValueMAC);
        cmeHMACByteString((const unsigned char*)queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_orgResourceId]+MACLen,
                          (unsigned char **)&protectedValueMAC,strlen(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_orgResourceId]+MACLen),
                          &written,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
        if (!strncmp(protectedValueMAC,queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_orgResourceId],MACLen)) //MAC is correct; proceed with decryption.
        {
            result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_orgResourceId]+MACLen,
                                 &currentOrgResourceId,cmeDefaultEncAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),
                                 orgKey,&written);
            if (result)  //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeUnprotectDBSaltedValue() error, cannot "
                        "decrypt orgResourceId!\n");
#endif
                cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
                return(4);
            }
        }
        else //MAC is incorrect; skip decryption process.
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Warning: cmeSecureFileToTmpRAWFile(), cmeHMACByteString() cannot "
                    "verify orgResourceId MAC!\n");
#endif
            cmeStrConstrAppend(&currentOrgResourceId,""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
        }
        //Unprotect storageId:
        cmeFree(protectedValueMAC);
        cmeHMACByteString((const unsigned char*)queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_storageId]+MACLen,
                          (unsigned char **)&protectedValueMAC,strlen(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_storageId]+MACLen),
                          &written,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
        if (!strncmp(protectedValueMAC,queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_storageId],MACLen)) //MAC is correct; proceed with decryption.
        {
            result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_storageId]+MACLen,
                                 &currentStorageId,cmeDefaultEncAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),
                                 orgKey,&written);
            if (result)  //Error
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeUnprotectDBSaltedValue() error, cannot "
                        "decrypt storageId!\n");
#endif
                cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
                return(5);
            }
        }
        else //MAC is incorrect; skip decryption process.
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Warning: cmeSecureFileToTmpRAWFile(), cmeHMACByteString() cannot "
                    "verify storageId MAC!\n");
#endif
            cmeStrConstrAppend(&currentStorageId,""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
        }
        //Verify that this part belongs to the requested document. If so continue processing it:
        if ((!(strcmp(currentDocumentId,documentId)))&&(!(strcmp(currentDocumentType,documentType)))
            &&(!(strcmp(currentOrgResourceId,orgId)))&&(!(strcmp(currentStorageId,storageId))))  //This part belongs to the protected RAWFile -> process!
        {
            //Unprotect columnFile:
            cmeFree(protectedValueMAC);
            cmeHMACByteString((const unsigned char*)queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile]+MACLen,
                              (unsigned char **)&protectedValueMAC,strlen(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile]+MACLen),
                              &written,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
            if (!strncmp(protectedValueMAC,queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile],MACLen)) //MAC is correct; proceed with decryption.
            {
                result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_columnFile]+MACLen,
                                     &(colSQLDBfNames[dbNumCols]),cmeDefaultEncAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),
                                     orgKey,&written);
                if (result)  //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeUnprotectDBSaltedValue() error, cannot "
                            "decrypt columnFile!\n");
#endif
                    cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
                    return(6);
                }
            }
            else //MAC is incorrect; skip decryption process.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeHMACByteString() error, cannot "
                        "verify columnFile MAC!\n");
#endif
                cmeStrConstrAppend(&(colSQLDBfNames[dbNumCols]),""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
            }
            //Unprotect partId:
            cmeFree(protectedValueMAC);
            cmeHMACByteString((const unsigned char*)queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partId]+MACLen,
                              (unsigned char **)&protectedValueMAC,strlen(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partId]+MACLen),
                              &written,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
            if (!strncmp(protectedValueMAC,queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partId],MACLen)) //MAC is correct; proceed with decryption.
            {
                result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partId]+MACLen,
                                     &currentPartId,cmeDefaultEncAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),
                                     orgKey,&written);
                if (result)  //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeUnprotectDBSaltedValue() error, cannot "
                            "decrypt partId!\n");
#endif
                    cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
                    return(7);
                }
            }
            else //MAC is incorrect; skip decryption process.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeHMACByteString() error, cannot "
                        "verify partId MAC!\n");
#endif
                cmeStrConstrAppend(&currentPartId,""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
            }
            memFilePartsOrder[dbNumCols]=atoi(currentPartId);   //Set order number.
            if (currentPartId)
            {
                memset(currentPartId,0,written);                    //WIPING SENSITIVE DATA IN MEMORY AFTER USE!
            }
            cmeFree(currentPartId);                             //Free currentPartId for next cycle.
            //Unprotect partMAC:
            cmeFree(protectedValueMAC);
            cmeHMACByteString((const unsigned char*)queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partMAC]+MACLen,
                              (unsigned char **)&protectedValueMAC,strlen(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partMAC]+MACLen),
                              &written,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
            if (!strncmp(protectedValueMAC,queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partMAC],MACLen)) //MAC is correct; proceed with decryption.
            {
                result=cmeUnprotectDBSaltedValue(queryResult[(cont*numCols)+cmeIDDResourcesDBDocuments_partMAC]+MACLen,
                                     &(memFilePartsMACs[dbNumCols]),cmeDefaultEncAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),
                                     orgKey,&written);
                if (result)  //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeUnprotectDBSaltedValue() error, cannot "
                            "decrypt partMAC!\n");
#endif
                    cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
                    return(8);
                }
            }
            else //MAC is incorrect; skip decryption process.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeHMACByteString() error, cannot "
                        "verify partMAC MAC!\n");
#endif
                cmeStrConstrAppend(&(memFilePartsMACs[dbNumCols]),""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
            }
            //Read and unprotect each RAWFile part:
            if(!documentPath) //If path is NULL, use default path.
            {
                cmeStrConstrAppend(&bkpFName,"%s%s",cmeDefaultFilePath,colSQLDBfNames[dbNumCols]); //Set full path for the encrypted RAWFile part.
            }
            else //Otherwise use provided path.
            {
                cmeStrConstrAppend(&bkpFName,"%s%s",documentPath,colSQLDBfNames[dbNumCols]); //Set full path for the encrypted RAWFile part.
            }
            result=cmeLoadStrFromFile(&currentEncryptedData,bkpFName,&written); //Load encrypted RAWFile part.
            if (result)  //Error
            {
                cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
                return(9);
            }
            //Unprotect currentEncryptedData (current encrypted part file):
            cmeFree(protectedValueMAC);
            cmeHMACByteString((const unsigned char*)currentEncryptedData,(unsigned char **)&protectedValueMAC,written,
                              &written2,cmeDefaultMACAlg,&(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey);
            if (!strncmp(protectedValueMAC,memFilePartsMACs[dbNumCols],MACLen)) //MAC is correct; proceed with decryption.
            {
                result=cmeUnprotectByteString(currentEncryptedData,&(memFilePartsData[dbNumCols]),cmeDefaultEncAlg,
                                              &(queryResult[(cont*numCols)+cmeIDDanydb_salt]),orgKey,
                                              &(memFilePartsDataSize[dbNumCols]),written);
                if (result)  //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeUnprotectDBSaltedValue() error, cannot "
                            "decrypt current encrypted part file!\n");
#endif
                    cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
                    return(10);
                }
            }
            else //MAC is incorrect; skip decryption process.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), cmeHMACByteString() error, cannot "
                        "verify MAC of current encrypted part file!\n");
#endif
                cmeStrConstrAppend(&(memFilePartsData[dbNumCols]),""); //This pointer can't be null (strcmp() will segfault), so we point it to an empty string.
                partMACmismatch++; //Flag MAC mismatch for file part.
            }
            memset(bkpFName,0,strlen(bkpFName));    //WIPING SENSITIVE DATA IN MEMORY AFTER USE!
            cmeFree(bkpFName);                      //Free bkpFName for next cycle.
            cmeFree(currentEncryptedData);          //Free currentEncryptedData for the next cycle.
            dbNumCols++;
            //Grow Arrays to hold next element:
            colSQLDBfNames=(char **)realloc(colSQLDBfNames,sizeof(char *)*(dbNumCols+1));
            memFilePartsOrder=(int *)realloc(memFilePartsOrder,sizeof(int)*(dbNumCols+1));
            memFilePartsDataSize=(int *)realloc(memFilePartsDataSize,sizeof(int)*(dbNumCols+1));
            memFilePartsData=(char **)realloc(memFilePartsData,sizeof(char *)*(dbNumCols+1));
            memFilePartsMACs=(char **)realloc(memFilePartsMACs,sizeof(char *)*(dbNumCols+1));
            //Initialize new allocated memory:
            colSQLDBfNames[dbNumCols]=NULL;
            memFilePartsOrder[dbNumCols]=0;
            memFilePartsDataSize[dbNumCols]=0;
            memFilePartsData[dbNumCols]=NULL;
            memFilePartsMACs[dbNumCols]=NULL;
        }
        memset(currentDocumentId,0,strlen(currentDocumentId));   //WIPING SENSITIVE DATA IN MEMORY AFTER USE!
        cmeFree(currentDocumentId);
    }
    *tmpRAWFile=NULL;
    if(dbNumCols && (!partMACmismatch)) //If we found at least 1 column part and no MAC mismatch, process the file...
    {
        cmeGetRndSalt(tmpRAWFile); //Get random HEX byte string for temporary file. Note that caller is responsible for freeing *tmpRAWFile
        cmeStrConstrAppend(&bkpFName,"%s%s",cmeDefaultSecureTmpFilePath,*tmpRAWFile); //Set full path for temporal, unencrypted RAWFile.
        cmeFree(*tmpRAWFile);
        cmeStrConstrAppend(tmpRAWFile,"%s",bkpFName); //Set tmpRAWFile to the full path of the file.
        fpTmpRAWFile=fopen(bkpFName,"wb");
        memset(bkpFName,0,strlen(bkpFName));   //WIPING SENSITIVE DATA IN MEMORY AFTER USE!
        cmeFree(bkpFName);  //Free bkpFName for next cycle.
        if (!fpTmpRAWFile)  //Error
        {
            cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
            return(10);
        }
        for (cont=1;cont<=dbNumCols;cont++) //Go through each part number in order
        {
            for (cont2=0;cont2<dbNumCols;cont2++) //Look for the file part that corresponds to the current order number
                if ((memFilePartsOrder[cont2])==(cont)) //Found it! Write its data to the tmpRAWFile.
                {
                    result=fwrite(memFilePartsData[cont2],1,memFilePartsDataSize[cont2],fpTmpRAWFile);
                    if(!result) //Error writing to secure tmp file.
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeSecureFileToTmpRAWFile(), fwrite() error, cannot "
                                "write to secure tmp file!\n");
#endif
                    }
                }
        }
        fclose(fpTmpRAWFile);
        fpTmpRAWFile=NULL;
        cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
        return(0);
    }
    else  //Error, file not found
    {
        cmeSecureFileToTmpRAWFileFree(); //CLEANUP.
        return(11);
    }
}

int cmeFileOverwriteAndDelete (const char *filePath)
{
    int result;
    long int cont,fileLen;
    FILE *fp=NULL;

    fp=fopen(filePath,"w");
    if(!fp) //Error
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Warning: cmeFileOverwriteAndDelete(), can't open file %s for overwriting!\n",filePath);
#endif
        return(1);
    }
    result=fseek(fp,0,SEEK_END); //Go to EOF.
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeFileOverwriteAndDelete(), fseek() Error!\n");
#endif
        fclose(fp);
        return(2);
    }
    fileLen=ftell(fp);
    result=fseek(fp,0,SEEK_SET); //Go to Start of File
    for (cont=0; cont<fileLen; cont++)
    {
        result=fputc((int)'0',fp);
    }
    fclose(fp);
    result=remove(filePath);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeFileOverwriteAndDelete(), remove() error, cannot delete file '%s'!\n",
                filePath);
#endif
        return(3);
    }
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeFileOverwriteAndDelete(), file '%s' of length %ld overwritten and deleted.\n",
                filePath,fileLen);
#endif
    return(0);
}

ssize_t cmeContentReaderCallback (void *cls, uint64_t pos, char *buf, size_t max)
{
    FILE *file =((struct cmeWebServiceContentReaderStruct *)cls)->fpResponseFile;
    int readBytes=0;

    (void) fseek (file, pos, SEEK_SET);
    readBytes=fread (buf, 1, max, file);
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeContentReaderCallback(), read %d bytes in ContentReaderCallback iteration.\n",readBytes);
#endif
    return (readBytes);
}

void cmeContentReaderFreeCallback (void *cls)
{
    FILE *file =((struct cmeWebServiceContentReaderStruct *)cls)->fpResponseFile;
    char *fileName =((struct cmeWebServiceContentReaderStruct *)cls)->fileName;


    if(!strncmp(cmeDefaultSecureTmpFilePath,fileName,strlen(cmeDefaultSecureTmpFilePath))) //The file is located in the Secure Temporal repository.
    {
        cmeFileOverwriteAndDelete(fileName);
    }
    cmeFree(fileName);
    fclose(file);
    cmeFree(cls);
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeContentReaderFreeCallback(), file closed successfully; end of ContentReaderCallback.\n");
#endif
}
int cmeMemTableToSecureDB (const char **memTable, const int numCols,const int numRows,
                           const char *userId,const char *orgId,const char *orgKey, const char **attribute,
                           const char **attributeData, const int numAttribute, const int replaceDB,
                           const char *resourceInfo, const char *documentType, const char *documentId,
                           const char *storageId, const char *storagePath)
{
    int cont,cont2,cont3,rContLimit,result,readBytes,written;
    int numEntries=0;
    int skipIdColumn=0;
    int totalParts=0;
    int numSQLDBfNames=0;               //with column slicing this will be (*numcols)*(((numRows/cmeMaxCSVRowsInPart))+((numRows%cmeMaxCSVRowsInPart > 0)? 1 : 0 ))
    sqlite3 **ppDB=NULL;
    sqlite3 *resourcesDB=NULL;
    char **SQLDBfNames=NULL;            //Will hold the name of each file part.
    char **SQLDBfMACs=NULL;             //Will hold the MAC of each file part.
    char **SQLDBfSalts=NULL;            //Will hold the salt of each file part.
    char **colNames=NULL;
    char *currentRawFileContent=NULL;   //Will hold the binary contents of each created file part during the hashing process.
    char *resourcesDBName=NULL;
    char *sqlQuery=NULL;
    char *value=NULL;                  //just a pointer to data in memTable; no need to free.
    char *bkpFName=NULL;
    char *securedRowOrder=NULL;
    char *securedValue=NULL;
    char *MAC=NULL;                    //'data' table values depending on attributes selected.
    char *salt=NULL;
    char *MACProtected=NULL;
    char *sign=NULL;
    char *signProtected=NULL;
    char *otphDkey=NULL;
    char *sanitizedStr=NULL;
    const char *nullParam="";
    const char resourcesDBFName[]="ResourcesDB";
    #define cmeMemTableToSecureDBFree() \
        do { \
            cmeFree(resourcesDBName); \
            cmeFree(sqlQuery); \
            cmeFree(bkpFName); \
            cmeFree(securedRowOrder); \
            cmeFree(securedValue); \
            cmeFree(MAC); \
            cmeFree(salt); \
            cmeFree(MACProtected); \
            cmeFree(sign); \
            cmeFree(signProtected); \
            cmeFree(otphDkey); \
            cmeFree(sanitizedStr); \
            cmeFree(currentRawFileContent); \
            if (resourcesDB) \
            { \
                cmeDBClose(resourcesDB); \
                resourcesDB=NULL; \
            } \
            if (ppDB) \
            { \
                for (cont=0;cont<numSQLDBfNames;cont++) \
                { \
                    cmeDBClose(ppDB[cont]); \
                    ppDB[cont]=NULL; \
                } \
                cmeFree(ppDB); \
            } \
            if (SQLDBfNames) \
            { \
                for (cont=0;cont<numSQLDBfNames;cont++) \
                { \
                    cmeFree(SQLDBfNames[cont]); \
                } \
                cmeFree(SQLDBfNames); \
            } \
            if (SQLDBfMACs) \
            { \
                for (cont=0;cont<numSQLDBfNames;cont++) \
                { \
                    cmeFree(SQLDBfMACs[cont]); \
                } \
                cmeFree(SQLDBfMACs); \
            } \
            if (SQLDBfSalts) \
            { \
                for (cont=0;cont<numSQLDBfNames;cont++) \
                { \
                    cmeFree(SQLDBfSalts[cont]); \
                } \
                cmeFree(SQLDBfSalts); \
            } \
            if (colNames) \
            { \
                for (cont=0;cont<numCols;cont++) \
                { \
                    cmeFree(colNames[cont]); \
                } \
                cmeFree(colNames); \
            } \
        } while (0); //Local free() macro.

    cmeStrConstrAppend(&resourcesDBName,"%s%s",cmeDefaultFilePath,resourcesDBFName);
    result=cmeDBOpen(resourcesDBName,&resourcesDB);
    if (result) //Error
    {
        cmeMemTableToSecureDBFree();
        return(1);
    }
    result=cmeExistsDocumentId(resourcesDB,documentId,orgKey,&numEntries);
    if (numEntries>0) //We have the same documentId already in the database...
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeCVSFileToSecureDB(), documentId %s already exists; "
                "replace instruction: %d\n",documentId,replaceDB);
#endif
        if (!replaceDB)
        {
            cmeMemTableToSecureDBFree();
            return(3);
        }
        else //delete old secureDB first, and then replace
        {
            result=cmeDeleteSecureDB(resourcesDB,documentId,orgKey,storagePath);
        }
    }
    cmeDBClose(resourcesDB);
    resourcesDB=NULL;
    colNames=(char **)malloc((sizeof(char *))*numCols); //Reserve space and copy column names.
    for (cont=0;cont<numCols;cont++)
    {
        colNames[cont]=NULL;    //Set all ptrs. to NULL as required by cmeStrConstrAppend().
        cmeStrConstrAppend(&(colNames[cont]),"%s",memTable[cont]);
    }
    // TODO (OHR#6#): Create & call function to create DB files in memory for memTable column imports.
    if (!strcmp(colNames[0],"id")) //id column exists; we need to skip it.
    {
        skipIdColumn=1;
    }
    if (!(SQLDBfNames)) //Create (and open) DB files in memory if they have not been created.
    {
        if ((numRows==0)&&((numCols-skipIdColumn)>=1)) //We have a new table with column names and no rows.
        {
            totalParts=1;
        }
        else
        {
            totalParts=((numRows/cmeMaxCSVRowsInPart)+((numRows%cmeMaxCSVRowsInPart > 0)? 1 : 0 ));
        }
        numSQLDBfNames=(numCols-skipIdColumn)*totalParts;
        ppDB=(sqlite3 **)malloc(sizeof(sqlite3 *)*numSQLDBfNames);
        if (!ppDB)
        {
            cmeMemTableToSecureDBFree();
            return(4);
        }
        SQLDBfNames=(char **)malloc(sizeof(char *)*numSQLDBfNames);
        SQLDBfMACs=(char **)malloc(sizeof(char *)*numSQLDBfNames);
        SQLDBfSalts=(char **)malloc(sizeof(char *)*numSQLDBfNames);
        if ((!SQLDBfNames)||(!SQLDBfMACs)||(!SQLDBfSalts))
        {
            cmeMemTableToSecureDBFree();
            return(5);
        }
        for(cont=0;cont<numSQLDBfNames;cont++) //Reset memory pointers
        {
            SQLDBfNames[cont]=NULL;
            SQLDBfMACs[cont]=NULL;
            SQLDBfSalts[cont]=NULL;
            cmeGetRndSaltAnySize(&(SQLDBfSalts[cont]),cmeDefaultValueSaltLen); //Get current salt for encryption (random hexstr).
        }
        for (cont=0;cont<numSQLDBfNames;cont++) //Create random filenames for column parts.
        {
            cmeGetRndSalt(&(SQLDBfNames[cont]));
            //TODO (OHR#8#): Create SQLDBfNames collision handling routine. Just in case.
            if (cmeDBCreateOpen(":memory:",&(ppDB[cont])))
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemTableToSecureDB(), cmeDBCreateOpen() Error, can't "
                        "Create and Open memory DB corresponding to DB file: %s !\n",SQLDBfNames[cont]);
#endif
                cmeMemTableToSecureDBFree();
                return(6);
            }
            cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; CREATE TABLE data "
                                "(id INTEGER PRIMARY KEY, userId TEXT, orgId TEXT, salt TEXT,"
                                " value TEXT, rowOrder TEXT, MAC TEXT, sign TEXT, MACProtected TEXT,"
                                " signProtected TEXT, otphDkey TEXT);"
                                "COMMIT;");
            if (cmeSQLRows((ppDB[cont]),sqlQuery,NULL,NULL)) //Create a table 'data'.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemTableToSecureDB(), cmeSQLRows() Error, can't "
                        "create table 'data' in DB file %d: %s!\n",cont,SQLDBfNames[cont]);
#endif
                cmeMemTableToSecureDBFree();
                return(7);
            }
            cmeFree(sqlQuery);  //Free memory that was used for queries.
            cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; CREATE TABLE meta "
                                "(id INTEGER PRIMARY KEY, userId TEXT, orgID TEXT, salt TEXT,"
                                " attribute TEXT, attributeData TEXT); COMMIT;");
            if (cmeSQLRows((ppDB[cont]),sqlQuery,NULL,NULL)) //Create a table 'meta'.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemTableToSecureDB(), cmeSQLRows() Error, can't "
                        "create table 'meta' in DB file %d: %s!\n",cont,SQLDBfNames[cont]);
#endif
                cmeMemTableToSecureDBFree();
                return(8);
            }
            cmeFree(sqlQuery);  //Free memory that was used for queries.
        }
        for (cont=0;cont<numSQLDBfNames;cont++) //Insert data into meta table.
        {   //Insert 'name' attribute.
            cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; "
                                    "INSERT INTO meta (id, userId, orgId, attribute, attributeData) "
                                    "VALUES (NULL");
            cmeFree(sanitizedStr);
            cmeSanitizeStrForSQL(userId,&sanitizedStr);   //Sanitize parameter userId for use in SQL statement.
            cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
            cmeFree(sanitizedStr);
            cmeSanitizeStrForSQL(orgId,&sanitizedStr);   //Sanitize parameter orgId for use in SQL statement.
            cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
            cmeStrConstrAppend(&sqlQuery,",'name'");    //Add literal 'name' for attribute.
            cmeFree(sanitizedStr);
            cmeSanitizeStrForSQL(colNames[(cont%(numCols-skipIdColumn))+skipIdColumn],&sanitizedStr);  //Sanitize parameter attributeData for use in SQL statement.
            cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
            cmeStrConstrAppend(&sqlQuery,");");    //End sql statement string.
            cmeStrConstrAppend(&salt,"%s",nullParam);   //Salt wil be included in cmeMemSecureDBProtect()
            for (cont2=0; cont2<numAttribute; cont2++) //Append other security attributes.
            {
                cmeStrConstrAppend(&sqlQuery,"INSERT INTO meta (id, userId, orgId, salt, attribute, attributeData) "
                                    "VALUES (NULL");
                cmeFree(sanitizedStr);
                cmeSanitizeStrForSQL(userId,&sanitizedStr);   //Sanitize parameter userId for use in SQL statement.
                cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                cmeFree(sanitizedStr);
                cmeSanitizeStrForSQL(orgId,&sanitizedStr);   //Sanitize parameter orgId for use in SQL statement.
                cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                cmeStrConstrAppend(&sqlQuery,",'%s'",salt);    //Add literal salt.
                cmeFree(sanitizedStr);
                cmeSanitizeStrForSQL(attribute[cont2],&sanitizedStr);   //Sanitize parameter attribute for use in SQL statement.
                cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                cmeFree(sanitizedStr);
                cmeSanitizeStrForSQL(attributeData[cont2],&sanitizedStr);  //Sanitize parameter attributeData for use in SQL statement.
                cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                cmeStrConstrAppend(&sqlQuery,");");    //End sql statement string.
            }
            cmeFree(salt);
            cmeStrConstrAppend(&sqlQuery,"COMMIT;");
            if (cmeSQLRows((ppDB[cont]),sqlQuery,NULL,NULL)) //Insert row.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemTableToSecureDB(), cmeSQLRows() Error, can't "
                        "insert row in DB file %d: %s!\n",cont,SQLDBfNames[cont]);
#endif
                cmeMemTableToSecureDBFree();
                return(9);
            }
            cmeFree(sqlQuery); //Free memory that was used for queries.
        }
    }
    //TODO (OHR#6#): Create and call function to insert data into tables (move code there).
    for (cont=0;cont<totalParts;cont++) //Process each column part.
    {
        for (cont2=0+skipIdColumn;cont2<numCols;cont2++) //Process each column (we skip the first column if it is "id").
        {
            if ((cont+1)*cmeMaxCSVRowsInPart>numRows) // Last part? yes-> then set rContLimit to the remaining rows.
            {
                rContLimit=numRows-(cont*cmeMaxCSVRowsInPart);
            }
            else
            {
                rContLimit=(numRows>cmeMaxCSVRowsInPart)?cmeMaxCSVRowsInPart:numRows;
            }
            for(cont3=1;cont3<=rContLimit;cont3++) //Skip header row in memTable[]; process each row.
            {
                value=(char *)memTable[cont2+((numCols)*(cont3+cont*cmeMaxCSVRowsInPart))];
                //Setup attributes defaults:
                cmeStrConstrAppend(&securedRowOrder,"%d",cont3+cont*cmeMaxCSVRowsInPart);
                cmeStrConstrAppend(&MAC,"%s",nullParam); // TODO (OHR#2#): Calculate MAC, MAC protected and stuff. Probably outside this function.
                cmeStrConstrAppend(&MACProtected,"%s",nullParam);
                cmeStrConstrAppend(&sign,"%s",nullParam);
                cmeStrConstrAppend(&signProtected,"%s",nullParam);
                cmeStrConstrAppend(&otphDkey,"%s",nullParam);
                cmeStrConstrAppend(&salt,"%s",nullParam);   //Salt wil be included in cmeMemSecureDBProtect().
                cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; INSERT INTO data "
                                            "(id,userId,orgId,salt,value,rowOrder,MAC,sign,MACProtected,signProtected,otphDkey)"
                                            " VALUES (NULL");
                cmeFree(sanitizedStr);
                cmeSanitizeStrForSQL(userId,&sanitizedStr);   //Sanitize parameter userId for use in SQL statement.
                cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                cmeFree(sanitizedStr);
                cmeSanitizeStrForSQL(orgId,&sanitizedStr);   //Sanitize parameter orgId for use in SQL statement.
                cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                cmeStrConstrAppend(&sqlQuery,",'%s'",salt);    //Add literal salt.
                cmeFree(sanitizedStr);
                cmeSanitizeStrForSQL(value,&sanitizedStr);   //Sanitize parameter value for use in SQL statement.
                cmeStrConstrAppend(&sqlQuery,",'%s'",sanitizedStr);
                cmeStrConstrAppend(&sqlQuery,",'%s','%s','%s','%s','%s','%s');" //Add remaining parameters.
                                            "COMMIT;",securedRowOrder,MAC,sign,
                                            MACProtected,signProtected,otphDkey);
                //Free stuff:
                cmeFree(salt);
                cmeFree(otphDkey);
                cmeFree(signProtected);
                cmeFree(sign);
                cmeFree(MACProtected);
                cmeFree(MAC);
                cmeFree(securedRowOrder);
                if (cmeSQLRows((ppDB[(numCols-skipIdColumn)*cont+cont2-skipIdColumn]),sqlQuery,NULL,NULL)) //Insert row.
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeMemTableToSecureDB(), cmeSQLRows() Error, can't "
                            "insert row in DB file %d: %s!\n",cont,SQLDBfNames[cont]);
#endif
                    cmeMemTableToSecureDBFree();
                    return(10);
                }
                cmeFree(sqlQuery);  //Free memory that was used for queries.
            }
        }
    }
    for (cont=0;cont<numSQLDBfNames; cont++)  //Create backup DB files; copy Memory DBs there.
    {
        if (numAttribute)  //If security attributes are defined, override corresponding defaults.
        {
            result=cmeMemSecureDBProtect(ppDB[cont],orgKey);
            cmeStrConstrAppend(&sqlQuery,"VACUUM;"); //Reconstruct DB without slack space w/ unprotected data!
            if (cmeSQLRows((ppDB[cont]),sqlQuery,NULL,NULL)) //Vacuum DB col.
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeMemTableToSecureDB(), cmeSQLRows() Error, can't "
                        "VACUUM DB file %d: %s!\n",cont,SQLDBfNames[cont]);
#endif
                cmeMemTableToSecureDBFree();
                return(11);
            }
            cmeFree(sqlQuery);  //Free memory that was used for queries.
        }
        cmeFree(bkpFName);
        cmeStrConstrAppend(&bkpFName,"%s%s",storagePath,SQLDBfNames[cont]);
        result=cmeMemDBLoadOrSave(ppDB[cont],bkpFName,1);
        if (result)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemTableToSecureDB(), cmeMemDBLoadOrSave() error cannot "
                    "load/save file: %s; Save: %d!\n",bkpFName,1);
#endif
            cmeMemTableToSecureDBFree();
            return(12);
        }
        //Get MAC of recently created file:
        result=cmeLoadStrFromFile(&currentRawFileContent,bkpFName,&readBytes);
        if (result)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeMemTableToSecureDB(), cmeLoadStrFromFile() error cannot "
                    "load recently created file part: %s !\n",bkpFName);
#endif
            cmeMemTableToSecureDBFree();
            return(13);
        }
        result=cmeHMACByteString((const unsigned char *)currentRawFileContent,(unsigned char **)&(SQLDBfMACs[cont]),readBytes,&written,cmeDefaultMACAlg,&(SQLDBfSalts[cont]),orgKey);
        cmeFree(currentRawFileContent);
        cmeFree(bkpFName);
    }
    if (!resourceInfo) //ResourceInfo is null; use nullParam instead.
    {
        result=cmeRegisterSecureDBorFile((const char **)SQLDBfNames, numSQLDBfNames,(const char **)SQLDBfSalts, (const char **)SQLDBfMACs,totalParts,orgKey,userId,orgId,nullParam,
                                        documentType,documentId,storageId,orgId);
    }
    else //ResourceInfo exists; use it.
    {
        result=cmeRegisterSecureDBorFile((const char **)SQLDBfNames, numSQLDBfNames,(const char **)SQLDBfSalts, (const char **)SQLDBfMACs,totalParts,orgKey,userId,orgId,resourceInfo,
                                        documentType,documentId,storageId,orgId);
    }
    if (result) //error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeMemTableToSecureDB(), cmeRegisterSecureDB() error cannot "
                "register documentId %s with documentType %s; Error#: %d!\n",documentId,documentType,result);
#endif
        cmeMemTableToSecureDBFree();
        return(14);
    }
    cmeMemTableToSecureDBFree();
    return (0);
}
