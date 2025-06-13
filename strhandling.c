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
#include "common.h"

//Note: cmeHexstrToBytes and cmeBytesToHexstr are based on suggestions provided at http://stackoverflow.com/questions/5666900/ by
//      Nathan Moinvaziri (http://stackoverflow.com/users/610692/nathan-moinvaziri)
//      Stackoverflow licenses user contributions under CC BY-SA 3.0 (http://creativecommons.org/licenses/by-sa/3.0/)
int cmeHexstrToBytes (unsigned char **bytearray, unsigned const char *hexstr)
{
    unsigned char *pByt;
    if(strlen((char *)hexstr)%2)
    {
#ifdef ERROR_LOG
           fprintf(stderr,"CaumeDSE Error: cmeHexstrToBytes(), HexStr (%s) size (%d)"
                    "must be even!\n",hexstr,(int)strlen((char *)hexstr));
#endif
        return(1);
    }
    *bytearray=(unsigned char *)malloc(sizeof(unsigned char)*(strlen((char *)hexstr)/2)+1);
    pByt=*bytearray;                 //Note: Caller must free *bytearray after use!
    while (*hexstr != '\0')
    {
       if ((isxdigit((char)(hexstr[0])))&&(isxdigit((char)(hexstr[1]))))
       {
            pByt[0]  = BASE16_DECODELO(hexstr[0]);
            pByt[0] |= BASE16_DECODEHI(hexstr[1]);
            pByt += 1;
            hexstr += 2;
       }
       else
       {
#ifdef ERROR_LOG
           fprintf(stderr,"CaumeDSE Error: cmeHexstrToBytes(), non hex representation found: %c%c!\n",
                   hexstr[0],hexstr[1]);
#endif
            return (2);
       }
    }
    pByt[0] = '\0';
    return(0);
}

int cmeBytesToHexstr (unsigned const char *bytearray, unsigned char **hexstr, int len)
{
    int cont=0;
    unsigned char *pHxs;
    *hexstr=(unsigned char *)malloc((len*2)+1);  //Note that caller must free hexstr !!!
    pHxs=*hexstr;
    memset(pHxs,0,(len*2)+1);   //Important! otherwise garbage shows up in resulting string.
    while (cont<len)            //Important! hexstr must be twice as large as bytearray, +1 (for \0);
    {
        pHxs[0]  = BASE16_ENCODELO(*bytearray);
        pHxs[1] |= BASE16_ENCODEHI(*bytearray);
        bytearray += 1;
        pHxs += 2;
        cont++;
    }
    pHxs = '\0';
    return(0);
}

int cmeStrToB64(unsigned char *bufIn, unsigned char **bufOut, int biLen, int *written)
{
    int result __attribute__((unused));
    int inlen __attribute__((unused)) =0;
    BIO *bio=NULL;
    BIO *b64=NULL;
    BUF_MEM *bptr;
    #define cmeStrToB64Free() \
        do { \
            BIO_free_all(b64); \
        } while (0); //Local free() macro.


    bio = BIO_new(BIO_s_mem());
    b64 = BIO_new(BIO_f_base64());
    ///BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); //No PEM standard (i.e. avoid adding NL after 64 chars and to last line)
    b64 = BIO_push(b64, bio);
    inlen=BIO_write(b64, bufIn, biLen);
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeStrToB64(), Read %d bytes to be encoded in B64.\n",inlen);
#endif
    result=BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    *written=bptr->length;
    *bufOut=(unsigned char *)malloc((sizeof(unsigned char))*((*written)+1));
    memcpy(*bufOut, bptr->data,(*written));
    (*bufOut)[*written]='\0';
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeStrToB64(), Encoded bytes in B64 string (%d chars long).\n",*written);
#endif
    cmeStrToB64Free();
    return(0);
}

int cmeB64ToStr(unsigned char *bufIn, unsigned char **bufOut, int biLen, int *written)
{
    int inlen=0;
    BIO *bio=NULL;
    BIO *b64=NULL;
    #define cmeB64ToStrFree() \
        do { \
            BIO_free_all(bio); \
        } while (0); //Local free() macro.

#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeB64ToStr(), Read B64 string (%d chars long).\n",biLen);
#endif
    *bufOut=(unsigned char *)malloc((sizeof(unsigned char))*biLen); //Note that Caller is responsible for freeing *bufOut !
    b64 = BIO_new(BIO_f_base64());
    ///BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); //No PEM standard (i.e. avoid adding NL after 64 chars and to last line)
    bio = BIO_new_mem_buf(bufIn,biLen);
    bio = BIO_push(b64,bio);
    inlen=BIO_read(bio,*bufOut,biLen);
    (*bufOut)[inlen]='\0';
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeB64ToStr(), Decoded %d bytes from B64 string.\n",inlen);
#endif
    *written=inlen;
    cmeB64ToStrFree();
    return(0);
}

int cmeStrConstrAppend (char **resultStr, const char *addString, ...)
{
    int result=0;
    int flag=0;
    char *tmpAddString=NULL;
    int sqlBufLen=cmeDefaultSqlBufferLen;
    va_list ap;
    #define cmeStrConstrAppendFree() \
        do { \
            cmeFree(tmpAddString); \
        } while (0); //Local free() macro

    tmpAddString=(char *)malloc(sqlBufLen); //Create addString with parameters
    if(!tmpAddString) //Error in malloc
    {
        return(1);
    }
    do
    {
        va_start(ap, addString);
        result=vsnprintf(tmpAddString,sqlBufLen,addString,ap);
        if ((result>-1)&&(result<sqlBufLen)) //If result is OK, then move on.
        {
            flag=0;
        }
        else //If buffer is not big enough to hold the whole string...
        {
            if (result > -1)
            {
                sqlBufLen=result+1; //Exactly what is needed (e.g. glibc 2.1 and later).
            }
            else
            {
                sqlBufLen*=2; //Double buffer and try again (e.g. glibc 2.0.6 an previous).
            }
            if(!(tmpAddString=(char *)realloc(tmpAddString,sqlBufLen)))
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeStrConstrAppend(), Error in malloc(), "
                        "out of memory?\n");
#endif
                cmeStrConstrAppendFree();
                return(2);  //if error, exit.
            }
            flag=1;
        }
    } while (flag);
    if (!resultStr) //Error, pointer to result string is NULL
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeStrConstrAppend(), Error: pointer to resultStr"
                "is NULL! Did you forget to append '&' to the string variable?\n");
#endif
        cmeStrConstrAppendFree();
        return(3);
    }
    if (!(*resultStr)) //resultStr is initially empty
    {
        *resultStr=strndup(tmpAddString,sqlBufLen);
        if (!(*resultStr))//strdup/malloc error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeStrConstrAppend(), Error: "
                    "strdup/malloc error (resultStr was initially empty)!\n");
#endif
            cmeStrConstrAppendFree();
            return(4);
        }
    }
    else //resultStr is not empty, then just append the new string.
    {
        *resultStr=(char *)realloc(*resultStr,((strlen(*resultStr))+(strlen(tmpAddString))+1));  //Note that caller must free *resultStr !
        if (!(*resultStr)) //realloc error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeStrConstrAppend(), Error: "
                    "malloc error while creating new string (original+appended)!\n");
#endif
            cmeStrConstrAppendFree();
            return(5);
        }
        strcat(*resultStr,tmpAddString);
    }
    cmeStrConstrAppendFree();
    return (0);
}

int cmeStrSqlINSERTConstruct (char **resultQuery, const char *tableName, const char **colNamesValuesPairs,
                              const int numColumns)
{
    int cont;
    cmeStrConstrAppend(resultQuery,"BEGIN TRANSACTION; INSERT INTO %s (",tableName); //First part.
    for (cont=0;cont<numColumns;cont+=2)  //Add column names.
    {
        cmeStrConstrAppend(resultQuery,"%s",colNamesValuesPairs[cont]);
        if ((cont+2)<numColumns) //still another column pending.
        {
            cmeStrConstrAppend(resultQuery,",");
        }
    }
    cmeStrConstrAppend(resultQuery,") VALUES(",colNamesValuesPairs[cont]);
    for (cont=1;cont<numColumns;cont+=2)  //Add values.
    {
        cmeStrConstrAppend(resultQuery,"'%s'",colNamesValuesPairs[cont]);
        if ((cont+2)<numColumns) //still another column pending.
        {
            cmeStrConstrAppend(resultQuery,",");
        }
    }
    cmeStrConstrAppend(resultQuery,"); COMMIT;",colNamesValuesPairs[cont]); //Last part.
    //TODO (OHR#3#): Sanitize variables.
    return (0);  //Note that caller must free resultQuery!
}

int cmeStrSqlUPDATEConstruct (char **resultQuery, const char *tableName, const char **colNamesValuesPairs,
                            const int numColumns, const char *matchColumn, const char *matchValue)
{
    int cont;
    cmeStrConstrAppend(resultQuery,"BEGIN TRANSACTION; UPDATE %s SET ",tableName); //First part.
    for (cont=0;cont<numColumns;cont+=2)  //Add column names.
    {
        cmeStrConstrAppend(resultQuery,"%s = '%s'",colNamesValuesPairs[cont],colNamesValuesPairs[cont+1]);
        if ((cont+2)<numColumns) //still another column pending.
        {
            cmeStrConstrAppend(resultQuery,",");
        }
    } //TODO (OHR#2#): Check WHERE usage; not necesarily equal to userId !!!
    //TODO (OHR#3#): Sanitize variables.
    cmeStrConstrAppend(resultQuery," WHERE %s = '%s'; COMMIT;",matchColumn,matchValue); //Last part.
    return (0);  //Note that caller must free resultQuery!
}

int cmeMemTableToHTMLTableStr (const char** srcMemTable,char **resultHTMLTableStr,int numColumns,int numRows)
{
    int cont,cont2;

    cmeStrConstrAppend(resultHTMLTableStr,"<table border=\"1\">");
    for (cont=0;cont<=numRows;cont++) //We include header row.
    {
        cmeStrConstrAppend(resultHTMLTableStr,"<tr>");
        for(cont2=0;cont2<numColumns;cont2++)
        {
            cmeStrConstrAppend(resultHTMLTableStr,"<td>%s</td>",srcMemTable[numColumns*cont+cont2]);
        }
        cmeStrConstrAppend(resultHTMLTableStr,"</tr>");
    }
    cmeStrConstrAppend(resultHTMLTableStr,"</table>");
    return(0);
}

int cmeMemTableToCSVTableStr (const char** srcMemTable,char **resultCSVTableStr,int numColumns,int numRows)
{
    int cont,cont2;

    for (cont=0;cont<=numRows;cont++) //We include header row.
    {
        for(cont2=0;cont2<numColumns;cont2++)
        {
            cmeStrConstrAppend(resultCSVTableStr,"\"%s\"",srcMemTable[numColumns*cont+cont2]);
            if ((cont2+1)<numColumns) //If not the last value of the Row.
            {
                cmeStrConstrAppend(resultCSVTableStr,",",srcMemTable[numColumns*cont+cont2]);
            }
        }
        cmeStrConstrAppend(resultCSVTableStr,"\n");
    }
    return(0);
}

int cmeFindInArgPairList (const char** stringPairs, const char *key, const char **pValue)
{
    int cont=0;
    *pValue=NULL;
    while ((stringPairs[cont])&&(cont<(cmeWSURIMaxArguments*2))) //if still no NULL pointer
    {
        if(!strcmp(key,stringPairs[cont]))//found it!
        {
            *pValue=stringPairs[cont+1]; //return pointer to argument value for corresponding key.
            return(0);
        }
        cont+=2;
    }
    return(1); //key not found.
}

int cmeConstructWebServiceTableResponse (const char **resultTable, const int tableCols, const int tableRows,
                                         const char **argumentElements, const char *method, const char *url, const char *documentId,
                                         char ***responseHeaders, char **resultTableStr, int *responseCode)
{
    int result __attribute__((unused));
    const char *pOutputType=NULL;       //Ptr to outputType parameter withi argumentElements. No need to free.

    if (tableCols) // If column names, print them.
    {
        // TODO (OHR#2#): Check output type (HTML/CSV) and prepare response accordingly.
        if ((!cmeFindInArgPairList(argumentElements,"outputType",&pOutputType))&&(pOutputType))
        {
            if (!strcmp("csv",pOutputType)) // user request results in csv format.
            {
                result=cmeMemTableToCSVTableStr((const char **)resultTable,resultTableStr,tableCols,tableRows);
                cmeStrConstrAppend(&((*responseHeaders)[2]),"Content-Type");  //Note: fields 0 & 1 will be set with Engine-results later.
                cmeStrConstrAppend(&((*responseHeaders)[3]),"application/csv");
                cmeStrConstrAppend(&((*responseHeaders)[4]),"Content-Disposition");
                cmeStrConstrAppend(&((*responseHeaders)[5]),"attachment;filename=\"%s\"",documentId);
            }
            else if (!strcmp("html",pOutputType)) // user request results in clean html format (without additional html headers and footers).
            {
                result=cmeMemTableToHTMLTableStr((const char **)resultTable,resultTableStr,tableCols,tableRows);
                cmeStrConstrAppend(&((*responseHeaders)[2]),"Content-Type");  //Note: fields 0 & 1 will be set with Engine-results later.
                cmeStrConstrAppend(&((*responseHeaders)[3]),"text/html; charset=utf-8");
            }
            else //Error, unknown outputType.
            {
                cmeStrConstrAppend(resultTableStr,"<b>501 ERROR Not implemented.</b><br>"
                                   "The requested functionality has not been implemented."
                                   "METHOD: '%s' URL: '%s'."
                                    "Latest IDD version: <code>%s</code>",method,url,
                                    cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), Debug, support "
                        "for outputType '%s' has not been implemented. Method: '%s', URL: '%s'!\n",pOutputType,method,url);
#endif
                *responseCode=501;
                return(1);
            }
        }
        else //No specific output type requested; use default format. Note that by default a Content-type of text/html is added if no header Content-Type is specified.
        {
            result=cmeMemTableToHTMLTableStr((const char **)resultTable,resultTableStr,tableCols,tableRows);
        }
    }
    if (tableRows) // Found >0 rows
    {
        *responseCode=200;
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeConstructWebServiceTableResponse(), construction of table response for GET request successful.\n");
#endif
    }
    else //Found 0 rows
    {
        *responseCode=404;
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeConstructWebServiceTableResponse(), construction of table response for GET request successful but "
                "no records found.\n");
#endif
    }
    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",tableRows);
    return(0);
}

int cmex509GetElementFromDN (const char* DN, const char *elementId, char **element, int *elementLen)
{
    int cont,cont2,DNLen;
    if (!DN) //Error, x509 certificate DN can't be null!
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmex509GetElementFromDN(), Error: NULL DN!\n");
#endif
        *element=NULL;
        *elementLen=0;
        return (1);
    }
    if (!elementId) //Error, x509 certificate elementId can't be null!
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmex509GetElementFromDN(), Error: NULL elementId!\n");
#endif
        *element=NULL;
        *elementLen=0;
        return (2);
    }
    if ((strlen(elementId)>2)||(strlen(elementId)<1)) //Error, x509 certificate elementId can't >2 or <1!
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmex509GetElementFromDN(), Error: elementId has wrong length!\n");
#endif
        *element=NULL;
        *elementLen=0;
        return (3);
    }
    DNLen=strlen(DN);
    cont=0;
    // TODO (ANY#4#): Verify that elementId is one of the following valid x509 DN elements: C, ST, L, O, OU or CN
    if (strlen(elementId)==1)
    {
        while (((DN[cont]!=elementId[0])||(DN[cont+1]!='='))&&(cont<(DNLen-2))) //Find start of element.
        {
            cont++;
        }
        cont+=2; //Set cont2 to start of element.
    }
    else //elementId length == 2.
    {
        while (((DN[cont]!=elementId[0])||(DN[cont+1]!=elementId[1])||(DN[cont+2]!='='))&&(cont<(DNLen-3))) //Find start of element.
        {
            cont++;
        }
        cont+=3; //Set cont2 to start of element.
    }
    cont2=cont;
    while ((DN[cont2]!='\n')&&(DN[cont2]!='\0')&&(DN[cont2]!=',')&&(cont2<=(DNLen))) //Find end of element.
    {
        cont2++;
    }
    *elementLen=cont2-cont;
    if (!(elementLen)) // element nos found (elementLen==0)
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmex509GetElementFromDN(), Warning: element not found.\n");
#endif
        *element=NULL;
        *elementLen=0;
        return (4);
    }
    else
    {
        *element=(char *)malloc((*elementLen) + 1);     //Note that caller must free *element.
        strncpy(*element,&(DN[cont]),*elementLen);      //Copy element to destination char *.
        (*element)[*elementLen]='\0';                   //Add end of string char.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmex509GetElementFromDN(), %s element: %s , length: %d.\n",elementId,*element,*elementLen);
#endif
        return(0);
    }
}
