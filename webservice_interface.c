/***
Copyright 2010-2026 by Omar Alejandro Herrera Reyna

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
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

static void cmeWebServiceSetThreadStatus(struct cmeWebServiceConnectionInfoStruct *con_info, int threadStatus)
{
    pthread_mutex_lock(&(con_info->threadStatusMutex));
    con_info->threadStatus=threadStatus;
    pthread_cond_broadcast(&(con_info->threadStatusCond));
    pthread_mutex_unlock(&(con_info->threadStatusMutex));
}

static int cmeWebServiceGetThreadStatus(struct cmeWebServiceConnectionInfoStruct *con_info)
{
    int threadStatus;

    pthread_mutex_lock(&(con_info->threadStatusMutex));
    threadStatus=con_info->threadStatus;
    pthread_mutex_unlock(&(con_info->threadStatusMutex));
    return(threadStatus);
}

static void cmeWebServiceWaitThreadStatusNot(struct cmeWebServiceConnectionInfoStruct *con_info, int threadStatus)
{
    pthread_mutex_lock(&(con_info->threadStatusMutex));
    while (con_info->threadStatus==threadStatus)
    {
        pthread_cond_wait(&(con_info->threadStatusCond),&(con_info->threadStatusMutex));
    }
    pthread_mutex_unlock(&(con_info->threadStatusMutex));
}

static void cmeWebServiceWaitThreadStatus(struct cmeWebServiceConnectionInfoStruct *con_info, int threadStatus)
{
    pthread_mutex_lock(&(con_info->threadStatusMutex));
    while (con_info->threadStatus!=threadStatus)
    {
        pthread_cond_wait(&(con_info->threadStatusCond),&(con_info->threadStatusMutex));
    }
    pthread_mutex_unlock(&(con_info->threadStatusMutex));
}

static void cmeWebServiceAbortPOST(struct cmeWebServiceConnectionInfoStruct *con_info)
{
    if (con_info->filePointer)
    {
        fclose(con_info->filePointer);
        con_info->filePointer=NULL;
    }
    cmeWebServiceSetThreadStatus(con_info,2);
}

int cmeWebServiceAnswerConnection (void *cls, struct MHD_Connection *connection, const char *url,
                                   const char *method, const char *version, const char *upload_data,
                                   size_t *upload_data_size, void **con_cls)

{
    #define GET             0
    #define POST            1
    int cont,responseEncoding __attribute__((unused)),result;
    int exitcode=1;
    int numUrlElements=0;
    int responseCode=0;
    long int responseDataSize=0;
    char *page=NULL;
    const char *pOutputType=NULL;                         //Ptr to constant str. for output type. No need to free.
    char **urlElements=NULL;
    struct MHD_Response *response=NULL;
    struct MHD_Response *responseFile=NULL;
    char **headerElements=NULL;
    char **argumentElements=NULL;
    char **responseHeaders=NULL;
    char *responseText=NULL;
    char *responseFilePath=NULL;
    struct cmeWebServiceConnectionInfoStruct *con_info=NULL;    //We will free this struct in cmeWebServiceRequestCompleted().
    struct cmeWebServiceContentReaderStruct *cr_info=NULL;      //We will free this struct in cmeContentReaderFreeCallback();
    struct stat statResponseFile;
    #define cmeWebServiceAnswerConnectionFree() \
        do { \
            cmeFree(page); \
            cmeFree(responseText); \
            if (response) \
            { \
                MHD_destroy_response (response); \
            } \
            if (responseFile) \
            { \
                MHD_destroy_response (responseFile); \
            } \
            if (numUrlElements) \
            { \
                cont=0; \
                while (cont<numUrlElements) \
                { \
                    cmeFree(urlElements[cont]); \
                    cont++; \
                } \
                cmeFree(urlElements); \
            } \
            if (headerElements) \
            { \
                cont=0; \
                while (cont<(cmeWSHTTPMaxHeaders*2)) \
                { \
                    cmeFree(headerElements[cont]); \
                    cont++; \
                } \
                cmeFree(headerElements); \
            } \
            if (argumentElements) \
            { \
                cont=0; \
                while (cont<(cmeWSURIMaxArguments*2)) \
                { \
                    cmeFree(argumentElements[cont]); \
                    cont++; \
                } \
                cmeFree(argumentElements); \
            } \
            if (responseHeaders) \
            { \
                cont=0; \
                while (cont<(cmeWSHTTPMaxHeaders*2)) \
                { \
                    cmeFree(responseHeaders[cont]); \
                    cont++; \
                } \
                cmeFree(responseHeaders); \
            } \
            if (responseFilePath) \
            { \
               cmeFree(responseFilePath); \
            } \
        } while (0); //Local free() macro.

    responseEncoding=cmeWSEncoding_HTML; //by default we use HTML responses on new requests
    if (NULL == *con_cls) //New connection; set POST processor if needed.
    {
        con_info = (struct cmeWebServiceConnectionInfoStruct *) malloc (sizeof (struct cmeWebServiceConnectionInfoStruct));
        if (NULL == con_info) //Error.
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceAnswerConnection(), malloc() can't allocate memory for cmeWebServiceConnectionInfoStruct."
                    " Method: '%s', url: '%s'!\n",method,url);
#endif
            return MHD_NO;
        }
        con_info->connectionStartTime=time(NULL);
        con_info->requestDataSize=(long int)*upload_data_size;
        con_info->threadStatus=0;
        if (pthread_mutex_init(&(con_info->threadStatusMutex),NULL))
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceAnswerConnection(), pthread_mutex_init() failed."
                    " Method: '%s', url: '%s'!\n",method,url);
#endif
            cmeFree(con_info);
            return MHD_NO;
        }
        if (pthread_cond_init(&(con_info->threadStatusCond),NULL))
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceAnswerConnection(), pthread_cond_init() failed."
                    " Method: '%s', url: '%s'!\n",method,url);
#endif
            pthread_mutex_destroy(&(con_info->threadStatusMutex));
            cmeFree(con_info);
            return MHD_NO;
        }
        con_info->answerString=NULL;
        con_info->answerCode=0;
        con_info->filePointer=NULL;
        con_info->fileName=NULL;
        con_info->connectionType=0;
        con_info->connection=connection;
        con_info->postProcessor=NULL;
        con_info->postArglist=(char **)malloc((sizeof (char *))*cmeWSHTTPMaxHeaders*2); //*2 since Argument lists consist of argumentElements PAIRS.
        for (cont=0;cont<(cmeWSHTTPMaxHeaders*2);cont++) //Clear pointers.
        {
            con_info->postArglist[cont]=NULL;
        }
        con_info->postArgCont=0;
        if (0 == strcmp (method, "POST"))
        {   // NOTE (OHR#9#): For MHD_create_post_processor to work properly, encoding (form "enctype" / header "Content-Type") must be defined;
            //                otherwise NULL will be returned. It should be either "application/x-www-form-urlencoded", "text/plain" or "multipart/form-data".
            con_info->postProcessor=MHD_create_post_processor(connection,cmeWSPostBufferSize,(MHD_PostDataIterator)&cmeWebServicePOSTIteration,(void *) con_info);
            if (!con_info->postProcessor) //Warning, can't create post processor; we probably need an emulated POST with a GET style method (i.e. URL parameters).
            {
#ifdef DEBUG
                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceAnswerConnection(), MHD_create_post_processor() Failed."
                        " Method: '%s', url: '%s'!\n",method,url);
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceAnswerConnection(), new connectionType = GET (emulated GET for POST). "
                        "Method: %s, url: %s.\n", method, url);
#endif
                //cmeFree(con_info);
                con_info->connectionType=GET; //Don't reject a POST with parameters in the URI, process as a GET request
                cmeWebServiceSetThreadStatus(con_info,2);
                //return MHD_NO;
            }
            else
            {
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceAnswerConnection(), new connectionType = POST. "
                        "Method: %s, url: %s.\n", method, url);
#endif
                con_info->connectionType=POST;
            }
        }
        else
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceAnswerConnection(), new connectionType = GET. "
                    "Method: %s, url: %s.\n", method, url);
#endif
            con_info->connectionType=GET;
            cmeWebServiceSetThreadStatus(con_info,2);
        }
        *con_cls=(void *)con_info;
        return MHD_YES;
    }
    else
    {
        con_info=*con_cls;
        con_info->requestDataSize+=(long int)*upload_data_size;
    }
    if ((con_info->connectionType)==POST) //Iterate POST request.
    {
        if (*upload_data_size != 0) //If data is available, retrieve it and exit function for another iteration.
        {
            if (MHD_NO == MHD_post_process (con_info->postProcessor, upload_data,*upload_data_size))
            {
                *upload_data_size = 0;
                cmeWebServiceAbortPOST(con_info);
                return MHD_NO;
            }
            *upload_data_size = 0;
            return MHD_YES;
        }
        if (con_info->filePointer) //We need to close the file before cmeWebServiceRequestCompleted() is called, since cmeWebServiceProcessRequest() will use it.
        {
            fclose (con_info->filePointer);
            con_info->filePointer=NULL;
        }
        if (*upload_data_size == 0) //No more data is available; signal that POST parsing is done.
        {
            cmeWebServiceSetThreadStatus(con_info,1);
        }
    }
    cmeWebServiceWaitThreadStatusNot(con_info,0); //Wait until the POST processor has collected all data.
    //Allocate space for headers and response headers:
    headerElements=(char **)malloc((sizeof (char *))*cmeWSHTTPMaxHeaders*2); //*2 since headers consist of headerElements PAIRS.
    responseHeaders=(char **)malloc((sizeof (char *))*cmeWSHTTPMaxResponseHeaders*2); //*2 since headers consist of headerElements PAIRS.
    for (cont=0;cont<(cmeWSHTTPMaxHeaders*2);cont++) //Clear pointers.
    {
        headerElements[cont]=NULL;
        responseHeaders[cont]=NULL;
    }
    //Allocate space for arguments:
    argumentElements=(char **)malloc((sizeof (char *))*cmeWSURIMaxArguments*2); //*2 since elements consist of argumentElements PAIRS.
    for (cont=0;cont<(cmeWSURIMaxArguments*2);cont++) //Clear pointers.
    {
        argumentElements[cont]=NULL;
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeWebServiceAnswerConnection(), new %s request for %s using version %s\n", method, url, version);
#endif
    cmeWebServiceParseURL(url, &urlElements, &numUrlElements);  //Parse URL.
    MHD_get_connection_values (connection, MHD_GET_ARGUMENT_KIND, (MHD_KeyValueIterator)&cmeWebServiceParseKeys, argumentElements);   //Parse Headers.
    MHD_get_connection_values (connection, MHD_HEADER_KIND, (MHD_KeyValueIterator)&cmeWebServiceParseKeys, headerElements);   //Parse Arguments.
    result=cmeWebServiceProcessRequest (&responseText,&responseFilePath,&responseHeaders,&responseCode,
                                        url,(const char **)urlElements,numUrlElements,
                                        (const char **)headerElements,(const char **)argumentElements,method,connection);
    con_info->answerCode=responseCode;
    if (responseFilePath) //We have a response File.
    {
        cr_info=(struct cmeWebServiceContentReaderStruct *) malloc (sizeof (struct cmeWebServiceContentReaderStruct)); //Create structure to pass among ContentReader iterations.
        cr_info->fpResponseFile=NULL;
        cr_info->fileName=NULL;
        cmeStrConstrAppend(&(cr_info->fileName),"%s",responseFilePath); //Copy file path.
        result=stat(responseFilePath,&statResponseFile);
        if (!result) //OK, file exists and we got statistics
        {
            cr_info->fpResponseFile=fopen(responseFilePath,"rb");
            if (cr_info->fpResponseFile) //File opened correctly
            {
    #ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceAnswerConnection(), user request successful "
                        "Method: '%s'. Url: '%s'. responseFilePath: '%s'.\n",method,url,responseFilePath);
    #endif
                //Create response from file:
                responseDataSize=(long int)statResponseFile.st_size;
                responseFile=MHD_create_response_from_callback(statResponseFile.st_size,                //Size of file to read.
                                                               cmeDefaultContentReaderCallbackPageSize, //Page size for reading content.
                                                               &cmeContentReaderCallback,               //MHD_ContentReaderCallback function.
                                                               cr_info,                                 //void *crc_cls (i.e. ContentReaderCallback parameter).
                                                               &cmeContentReaderFreeCallback);          //MHD_ContentReaderFreeCallback function.
                if (!responseFile)//Error, could not create MHD_Response!
                {
                    fclose(cr_info->fpResponseFile);
                    exitcode=MHD_NO;
                }
                else //OK, proceed creating response and adding headers.
                {
                    if (responseHeaders[0] && responseHeaders[1]) //We got at least 1 response header. Process them
                    {
                        cont=0;
                        while ((responseHeaders[cont])&&(responseHeaders[cont+1])&&(cont<(cmeWSHTTPMaxHeaders*2)))
                        {
                            result=MHD_add_response_header(responseFile,responseHeaders[cont],responseHeaders[cont+1]);
                            cont+=2;
                        }
                    }

                    //Add default Headers:
                    result=MHD_add_response_header(responseFile,"Server","CaumeDSE " cmeEngineVersion);
                    exitcode=MHD_queue_response (connection, responseCode, responseFile); //Note that WebService processing function needs to define appropriate Content-Type headers
                }
            }
        }
    }
    else // responseText with content or empty
    {
        if (responseText)
        {
            //Add default Headers:
            if (cmeFindInArgPairList((const char **)responseHeaders,"Content-Type",&pOutputType)) //No Content-Type defined, so set one with the default: text/html.
            {
                cmeStrConstrAppend(&page,"%s%s%s",cmeWSHTMLPageStart,responseText,
                                   cmeWSHTMLPageEnd); //Add page opening/closing tags and (c) to response page.
                responseDataSize=(long int)strlen(page);
                //Create response body:
                response=MHD_create_response_from_buffer((size_t)responseDataSize,(void*) page, MHD_RESPMEM_MUST_COPY); //We have to create response body before adding headers.
                result=MHD_add_response_header(response,"Content-Type","text/html; charset=utf-8");
            }
            else
            {
                cmeStrConstrAppend(&page,"%s",responseText); //Add plain response to response page.
                responseDataSize=(long int)strlen(page);
                //Create response body:
                response=MHD_create_response_from_buffer((size_t)responseDataSize,(void*) page, MHD_RESPMEM_MUST_COPY);
            }
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceAnswerConnection(), user request successful "
                    "Method: '%s'. Url: '%s'.\n responseText: '%s'.\n",method,url,page);
#endif
            result=MHD_add_response_header(response,"Server","CaumeDSE " cmeEngineVersion);
        }
        else
        {
            //Create empty response body (e.g. for HEAD method):
            responseDataSize=0;
            response=MHD_create_response_from_buffer(0,NULL, MHD_RESPMEM_MUST_COPY);
            //Add default Headers:
            result=MHD_add_response_header(response,"Server","CaumeDSE " cmeEngineVersion);
        }
        if (responseHeaders[0] && responseHeaders[1]) //We got at least 1 response header. Process them
        {
            cont=0;
            while ((responseHeaders[cont])&&(responseHeaders[cont+1])&&(cont<(cmeWSHTTPMaxHeaders*2)))
            {
                result=MHD_add_response_header(response,responseHeaders[cont],responseHeaders[cont+1]);
                cont+=2;
            }
        }
        exitcode=MHD_queue_response (connection, responseCode, response);
    }
    cmeWebServiceSetThreadStatus(con_info,2); //Now the POST handling routing thread can free memory and finish.
    result=cmeWebServiceLogConnection (connection,con_info,con_info->connectionStartTime,method,url,con_info->requestDataSize,responseDataSize,
                                       (const char **)headerElements,(const char **)responseHeaders,(const char **)argumentElements,
                                       (const char **)urlElements,numUrlElements);
    cmeWebServiceAnswerConnectionFree();  //Free stuff
    return (exitcode);
}

int cmeWebServiceParseURL(const char *url, char ***urlElements, int *numUrlElements)
{
    int cont=0;
    char *urlCopy=NULL;
    char *token=NULL;

    *numUrlElements=0;
    *urlElements=(char **)malloc(sizeof(char *)*cmeIDDURIMaxDepth);
    cmeStrConstrAppend(&urlCopy,"%s",url);    //Because strtok() modifies parsed string.
    token=strtok(urlCopy,"/?");
    while ((cont<cmeIDDURIMaxDepth)&&(token))
    {
        (*numUrlElements)++;
        (*urlElements)[cont]=NULL;
        cmeStrConstrAppend(&((*urlElements)[cont]),"%s",token);
        token=strtok(NULL,"/?");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceParseURL(), element at level %d: '%s'.\n",
                *numUrlElements,(*urlElements)[cont]);
#endif
        cont++;
    }
    cmeFree(urlCopy);
    return (0);
}

int cmeWebServiceParseKeys(void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
    int cont=0;

    if (kind==MHD_GET_ARGUMENT_KIND)
    {
        //Jump to last free argumentElements space
        while ((((char **)cls)[cont])&&(cont<cmeWSURIMaxArguments)) //We iterate each time for thread safety. No static vars. then.
        {
            cont+=2;
        }
        if (cont<cmeWSURIMaxArguments)
        {
            cmeStrConstrAppend(&(((char **)cls)[cont]),"%s",key);
            cmeStrConstrAppend(&(((char **)cls)[cont+1]),"%s",value);
            //Note that caller must free each cls[cont]!
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceParseKeys(), ARGUMENT:, key:%s, value:%s\n", key, value);
#endif
    }
//MHD_RESPONSE_HEADER_KIND DEPRECATED in recent versions of libmicrohttpd:
/*    else if (kind==MHD_RESPONSE_HEADER_KIND)
    {
        //Jump to last free responseElements space
        while ((((char **)cls)[cont])&&(cont<cmeWSHTTPMaxResponseHeaders)) //We iterate each time for thread safety. No static vars. then.
        {
            cont+=2;
        }
        if (cont<cmeWSHTTPMaxResponseHeaders)
        {
            cmeStrConstrAppend(&(((char **)cls)[cont]),"%s",key);
            cmeStrConstrAppend(&(((char **)cls)[cont+1]),"%s",value);
            //Note that caller must free each cls[cont]!
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceParseKeys(), RESPONSE HEADER:, key:%s, value:%s\n", key, value);
#endif
    }
*/
    else if (kind==MHD_HEADER_KIND)
    {
        //Jump to last free headerElements space
        while ((((char **)cls)[cont])&&(cont<cmeWSHTTPMaxHeaders)) //We iterate each time for thread safety. No static vars. then.
        {
            cont+=2;
        }
        if (cont<cmeWSHTTPMaxHeaders)
        {
            cmeStrConstrAppend(&(((char **)cls)[cont]),"%s",key);
            cmeStrConstrAppend(&(((char **)cls)[cont+1]),"%s",value);
            //Note that caller must free each cls[cont]!
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceParseKeys(), HEADER:, key:%s, value:%s\n", key, value);
#endif
    }
    return MHD_YES;
}

static int cmeWebServiceHasUnsafeRequestInput(const char **urlElements, int numUrlElements,
                                              const char **argumentElements)
{
    int cont;

    for (cont=0;cont<numUrlElements;cont++)
    {
        if (cmeHasUnsafeSQLInputChars(urlElements[cont]))
        {
            return(1);
        }
    }
    if (!argumentElements)
    {
        return(1);
    }
    for (cont=0;((cont+1)<cmeWSURIMaxArguments)&&(argumentElements[cont]);cont+=2)
    {
        if (cmeHasUnsafeSQLInputChars(argumentElements[cont])||
            cmeHasUnsafeSQLInputChars(argumentElements[cont+1]))
        {
            return(1);
        }
    }
    return(0);
}

static int cmeWebServiceIsFalseValue(const char *value)
{
    return((value)&&((!strcmp(value,"0"))||(!strcasecmp(value,"false"))||
                     (!strcasecmp(value,"no"))||(!strcasecmp(value,"off"))||
                     (!strcasecmp(value,"none"))));
}

static int cmeWebServiceIsTrueValue(const char *value)
{
    return((value)&&((!strcmp(value,"1"))||(!strcasecmp(value,"true"))||
                     (!strcasecmp(value,"yes"))||(!strcasecmp(value,"on"))||
                     (!value[0])));
}

static int cmeWebServiceGetSecureDBAttributeParam(const char **argumentElements, const char *name,
                                                  const char **value)
{
    char *starName=NULL;
    int result;

    if ((!argumentElements)||(!name)||(!value))
    {
        return(1);
    }
    if (!cmeFindInArgPairList(argumentElements,name,value))
    {
        return(0);
    }
    cmeStrConstrAppend(&starName,"*%s",name);
    result=cmeFindInArgPairList(argumentElements,starName,value);
    cmeFree(starName);
    return(result);
}

static int cmeWebServiceGetBooleanParam(const char **argumentElements, const char *name,
                                        int defaultValue)
{
    const char *value=NULL;

    if ((cmeWebServiceGetSecureDBAttributeParam(argumentElements,name,&value))||
        (!value))
    {
        return(defaultValue);
    }
    if (cmeWebServiceIsFalseValue(value))
    {
        return(0);
    }
    if (cmeWebServiceIsTrueValue(value))
    {
        return(1);
    }
    return(defaultValue);
}

static const char *cmeWebServiceSupportedDocumentTypes[]={
    "file.csv",
    "file.raw",
    "file.txt",
    "file.json",
    "file.xml",
    "file.html",
    "file.pdf",
    "file.png",
    "file.jpg",
    "file.gif",
    "file.zip",
    "file.bin",
    "script.perl",
    "script.python"
};

static const int cmeWebServiceNumSupportedDocumentTypes=
    sizeof(cmeWebServiceSupportedDocumentTypes)/sizeof(cmeWebServiceSupportedDocumentTypes[0]);

static int cmeWebServiceIsSupportedDocumentType(const char *documentType)
{
    int cont;

    if (!documentType)
    {
        return(0);
    }
    for (cont=0;cont<cmeWebServiceNumSupportedDocumentTypes;cont++)
    {
        if (!strcmp(documentType,cmeWebServiceSupportedDocumentTypes[cont]))
        {
            return(1);
        }
    }
    return(0);
}

static int cmeWebServiceIsParserScriptDocumentType(const char *documentType)
{
    if (!documentType)
    {
        return(0);
    }
    return((!strcmp(documentType,"script.perl"))||
           (!strcmp(documentType,"script.python")));
}

static int cmeWebServiceIsRawFileDocumentType(const char *documentType)
{
    if (!documentType)
    {
        return(0);
    }
    return((!strcmp(documentType,"file.raw"))||
           (!strcmp(documentType,"file.txt"))||
           (!strcmp(documentType,"file.json"))||
           (!strcmp(documentType,"file.xml"))||
           (!strcmp(documentType,"file.html"))||
           (!strcmp(documentType,"file.pdf"))||
           (!strcmp(documentType,"file.png"))||
           (!strcmp(documentType,"file.jpg"))||
           (!strcmp(documentType,"file.gif"))||
           (!strcmp(documentType,"file.zip"))||
           (!strcmp(documentType,"file.bin")));
}

static int cmeWebServiceCreateSecureTmpPath(char **tmpPath)
{
    char *tmpName=NULL;

    if (!tmpPath)
    {
        return(1);
    }
    *tmpPath=NULL;
    if (cmeGetRndSalt(&tmpName))
    {
        return(2);
    }
    cmeStrConstrAppend(tmpPath,"%s%s",cmeDefaultSecureTmpFilePath,tmpName);
    cmeFree(tmpName);
    return((*tmpPath)?0:3);
}

static int cmeWebServiceWriteResultMemTableCSV(const char *filePath)
{
    int result;
    char *csvTable=NULL;

    if ((!filePath)||(!cmeResultMemTable)||(cmeResultMemTableCols<=0))
    {
        return(1);
    }
    result=cmeMemTableToCSVTableStr((const char **)cmeResultMemTable,&csvTable,
                                    cmeResultMemTableCols,cmeResultMemTableRows);
    if (result)
    {
        cmeFree(csvTable);
        return(2);
    }
    result=cmeWriteStrToFile(csvTable,filePath,(int)strlen(csvTable));
    cmeFree(csvTable);
    return(result?3:0);
}

static int cmeWebServiceLoadCSVToResultMemTable(const char *filePath)
{
    int cont,result;
    int numCols=0;
    int processedRows=0;
    char **elements=NULL;

    if (!filePath)
    {
        return(1);
    }
    result=cmeCSVFileRowsToMemTable(filePath,&elements,&numCols,&processedRows,1,0,
                                    cmeMaxCSVRowsInPart*cmeMaxCSVPartsPerColumn);
    if (result)
    {
        return(2);
    }
    cmeResultMemTableClean();
    cmeResultMemTableCols=numCols;
    cmeResultMemTableRows=processedRows;
    cmeResultMemTable=(char **)malloc(sizeof(char *)*numCols*(processedRows+1));
    if (!cmeResultMemTable)
    {
        cmeCSVFileRowsToMemTableFinal(&elements,numCols,processedRows+1);
        cmeResultMemTableCols=0;
        cmeResultMemTableRows=0;
        return(3);
    }
    for (cont=0;cont<numCols*(processedRows+1);cont++)
    {
        cmeResultMemTable[cont]=NULL;
        cmeStrConstrAppend(&(cmeResultMemTable[cont]),"%s",elements[cont]?elements[cont]:"");
    }
    cmeCSVFileRowsToMemTableFinal(&elements,numCols,processedRows+1);
    return(0);
}

static int cmeWebServiceValidateParserResultSize(const char *context)
{
    long long cells;

    if ((cmeResultMemTableCols<0)||(cmeResultMemTableRows<0))
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: %s(), invalid parser result dimensions cols=%d rows=%d.\n",
                context?context:"cmeWebServiceValidateParserResultSize",
                cmeResultMemTableCols,cmeResultMemTableRows);
#endif
        return(1);
    }
    cells=(long long)cmeResultMemTableCols*(long long)(cmeResultMemTableRows+1);
    if (cells>CDSE_PARSER_SCRIPT_MAX_RESULT_CELLS)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: %s(), parser result has %lld cells; limit is %d.\n",
                context?context:"cmeWebServiceValidateParserResultSize",
                cells,CDSE_PARSER_SCRIPT_MAX_RESULT_CELLS);
#endif
        return(2);
    }
    return(0);
}

static int cmeWebServiceValidateParserOutputFileSize(const char *filePath)
{
    struct stat st;

    if (!filePath)
    {
        return(1);
    }
    if (stat(filePath,&st))
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceValidateParserOutputFileSize(), stat() failed for '%s': %s.\n",
                filePath,strerror(errno));
#endif
        return(2);
    }
    if (st.st_size>CDSE_PARSER_SCRIPT_MAX_OUTPUT_BYTES)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceValidateParserOutputFileSize(), parser output '%s' is %lld bytes; limit is %d.\n",
                filePath,(long long)st.st_size,CDSE_PARSER_SCRIPT_MAX_OUTPUT_BYTES);
#endif
        return(3);
    }
    return(0);
}

static int cmeWebServiceWaitForParserChild(pid_t pid, const char *context)
{
    int result=0;
    int status=0;
    int waited=0;

    while (1)
    {
        result=waitpid(pid,&status,WNOHANG);
        if (result==pid)
        {
            break;
        }
        if ((result<0)&&(errno==EINTR))
        {
            continue;
        }
        if (result<0)
        {
            break;
        }
        if (waited>=CDSE_PARSER_SCRIPT_TIMEOUT_SECONDS)
        {
            kill(pid,SIGTERM);
            sleep(1);
            if (waitpid(pid,&status,WNOHANG)==0)
            {
                kill(pid,SIGKILL);
            }
            while ((waitpid(pid,&status,0)<0)&&(errno==EINTR))
            {
            }
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: %s(), parser timed out after %d seconds.\n",
                    context?context:"cmeWebServiceWaitForParserChild",
                    CDSE_PARSER_SCRIPT_TIMEOUT_SECONDS);
#endif
            return(6);
        }
        sleep(1);
        waited++;
    }
    if ((result<0)||(!WIFEXITED(status))||(WEXITSTATUS(status)!=0))
    {
        return(5);
    }
    return(0);
}

static int cmeWebServiceRunPythonParserScript(const char *scriptPath)
{
    int result=0;
    char *inputPath=NULL;
    char *outputPath=NULL;
    pid_t pid;

    if (!scriptPath)
    {
        return(1);
    }
    result=cmeWebServiceCreateSecureTmpPath(&inputPath);
    if (!result)
    {
        result=cmeWebServiceCreateSecureTmpPath(&outputPath);
    }
    if (!result)
    {
        result=cmeWebServiceWriteResultMemTableCSV(inputPath);
    }
    if (!result)
    {
        pid=fork();
        if (pid<0)
        {
            result=4;
        }
        else if (pid==0)
        {
            execlp("python3","python3",scriptPath,inputPath,outputPath,(char *)NULL);
            _exit(127);
        }
        else
        {
            result=cmeWebServiceWaitForParserChild(pid,"cmeWebServiceRunPythonParserScript");
        }
    }
    if (!result)
    {
        result=cmeWebServiceValidateParserOutputFileSize(outputPath);
        if (result)
        {
            result=7;
        }
    }
    if (!result)
    {
        result=cmeWebServiceLoadCSVToResultMemTable(outputPath);
    }
    if (!result)
    {
        result=cmeWebServiceValidateParserResultSize("cmeWebServiceRunPythonParserScript");
        if (result)
        {
            result=8;
        }
    }
    if (inputPath)
    {
        cmeFileOverwriteAndDelete(inputPath);
    }
    if (outputPath)
    {
        cmeFileOverwriteAndDelete(outputPath);
    }
    cmeFree(inputPath);
    cmeFree(outputPath);
    return(result);
}

static const char *cmePerlParserChildRunner =
"my ($script_path,$input_path,$output_path)=@ARGV;\n"
"exit 2 unless defined $script_path && defined $input_path && defined $output_path;\n"
"sub cdse_load_script {\n"
"    my ($path)=@_;\n"
"    my $result=do $path;\n"
"    if (!defined $result) {\n"
"        print STDERR \"CaumeDSE Perl parser load failed: \",($@ || $! || 'unknown'),\"\\n\";\n"
"        exit 3;\n"
"    }\n"
"}\n"
"sub cdse_parse_csv_line {\n"
"    my ($line)=@_;\n"
"    $line='' unless defined $line;\n"
"    chomp $line;\n"
"    $line =~ s/\\r\\z//;\n"
"    my @fields=();\n"
"    my $field='';\n"
"    my $quoted=0;\n"
"    my @chars=split //,$line;\n"
"    while (@chars) {\n"
"        my $ch=shift @chars;\n"
"        if ($quoted) {\n"
"            if ($ch eq '\"') {\n"
"                if (@chars && $chars[0] eq '\"') { $field.=shift @chars; }\n"
"                else { $quoted=0; }\n"
"            }\n"
"            else { $field.=$ch; }\n"
"        }\n"
"        else {\n"
"            if ($ch eq ',') { push @fields,$field; $field=''; }\n"
"            elsif (($ch eq '\"') && ($field eq '')) { $quoted=1; }\n"
"            else { $field.=$ch; }\n"
"        }\n"
"    }\n"
"    push @fields,$field;\n"
"    return @fields;\n"
"}\n"
"sub cdse_write_csv_line {\n"
"    my ($fh,@fields)=@_;\n"
"    for (my $idx=0; $idx<@fields; $idx++) {\n"
"        my $field=defined $fields[$idx] ? $fields[$idx] : '';\n"
"        $field =~ s/\"/\"\"/g;\n"
"        if ($field =~ /[\",\\r\\n]/) { $field='\"'.$field.'\"'; }\n"
"        print $fh ',' if $idx;\n"
"        print $fh $field;\n"
"    }\n"
"    print $fh \"\\n\";\n"
"}\n"
"open my $in,'<',$input_path or exit 4;\n"
"open my $out,'>',$output_path or exit 5;\n"
"my $header=<$in>;\n"
"if (defined $header) {\n"
"    cdse_load_script($script_path);\n"
"    my @cols=cdse_parse_csv_line($header);\n"
"    my @out_cols=@cols;\n"
"    if (defined &cmePERLProcessColumnNames) {\n"
"        my @candidate=cmePERLProcessColumnNames(@cols);\n"
"        @out_cols=@candidate if @candidate==@cols;\n"
"    }\n"
"    cdse_write_csv_line($out,@out_cols);\n"
"    while (my $line=<$in>) {\n"
"        cdse_load_script($script_path);\n"
"        my @row=cdse_parse_csv_line($line);\n"
"        my @out_row=@row;\n"
"        if (defined &cmePERLProcessRow) {\n"
"            my @candidate=cmePERLProcessRow(@row);\n"
"            @out_row=@candidate if @candidate==@row;\n"
"        }\n"
"        cdse_write_csv_line($out,@out_row);\n"
"    }\n"
"}\n"
"close $out or exit 6;\n"
"close $in or exit 7;\n"
"exit 0;\n";

static int cmeWebServiceRunPerlParserScript(const char *scriptPath)
{
    int result=0;
    char *inputPath=NULL;
    char *outputPath=NULL;
    char *runnerPath=NULL;
    pid_t pid;

    if (!scriptPath)
    {
        return(1);
    }
    result=cmeWebServiceCreateSecureTmpPath(&inputPath);
    if (!result)
    {
        result=cmeWebServiceCreateSecureTmpPath(&outputPath);
    }
    if (!result)
    {
        result=cmeWebServiceCreateSecureTmpPath(&runnerPath);
    }
    if (!result)
    {
        result=cmeWebServiceWriteResultMemTableCSV(inputPath);
    }
    if (!result)
    {
        result=cmeWriteStrToFile((char *)cmePerlParserChildRunner,runnerPath,
                                 (int)strlen(cmePerlParserChildRunner));
        if (result)
        {
            result=3;
        }
    }
    if (!result)
    {
        pid=fork();
        if (pid<0)
        {
            result=4;
        }
        else if (pid==0)
        {
            execlp("perl","perl",runnerPath,scriptPath,inputPath,outputPath,(char *)NULL);
            _exit(127);
        }
        else
        {
            result=cmeWebServiceWaitForParserChild(pid,"cmeWebServiceRunPerlParserScript");
        }
    }
    if (!result)
    {
        result=cmeWebServiceValidateParserOutputFileSize(outputPath);
        if (result)
        {
            result=7;
        }
    }
    if (!result)
    {
        result=cmeWebServiceLoadCSVToResultMemTable(outputPath);
    }
    if (!result)
    {
        result=cmeWebServiceValidateParserResultSize("cmeWebServiceRunPerlParserScript");
        if (result)
        {
            result=8;
        }
    }
    if (inputPath)
    {
        cmeFileOverwriteAndDelete(inputPath);
    }
    if (outputPath)
    {
        cmeFileOverwriteAndDelete(outputPath);
    }
    if (runnerPath)
    {
        cmeFileOverwriteAndDelete(runnerPath);
    }
    cmeFree(inputPath);
    cmeFree(outputPath);
    cmeFree(runnerPath);
    return(result);
}

static int cmeWebServiceBuildSecureDBAttributes(const char **argumentElements,
                                                const char **attributes, const char **attributeData,
                                                int maxAttributes)
{
    int numAttributes=0;
    const char *shuffleValue=NULL;
    const char *protectValue=NULL;

    if ((!attributes)||(!attributeData)||(maxAttributes<2))
    {
        return(0);
    }
    if ((cmeWebServiceGetSecureDBAttributeParam(argumentElements,"shuffle",&shuffleValue))||
        (!shuffleValue))
    {
        shuffleValue=cmeDefaultEncAlg;
    }
    if ((cmeWebServiceGetSecureDBAttributeParam(argumentElements,"protect",&protectValue))||
        (!protectValue))
    {
        protectValue=cmeDefaultEncAlg;
    }
    if (!cmeWebServiceIsFalseValue(shuffleValue))
    {
        attributes[numAttributes]="shuffle";
        if (cmeWebServiceIsTrueValue(shuffleValue))
        {
            attributeData[numAttributes]=cmeDefaultEncAlg;
        }
        else
        {
            attributeData[numAttributes]=shuffleValue;
        }
        numAttributes++;
    }
    if (!cmeWebServiceIsFalseValue(protectValue))
    {
        attributes[numAttributes]="protect";
        if (cmeWebServiceIsTrueValue(protectValue))
        {
            attributeData[numAttributes]=cmeDefaultEncAlg;
        }
        else
        {
            attributeData[numAttributes]=protectValue;
        }
        numAttributes++;
    }
    return(numAttributes);
}

// File-scope engine power status flag.  Access is serialised with cmePowerMutex so that
// concurrent requests see a consistent value when the operator toggles the engine on/off.
static int cmeEnginePowerStatus=1;
static pthread_mutex_t cmeLogsSchemaMutex=PTHREAD_MUTEX_INITIALIZER;
static int cmeLogsSchemaReady=0;

static int cmeWebServiceEnsureLogsTransactionsTable(sqlite3 *pDB)
{
    int cont,result=0,found=0;
    char *sqlCreate=NULL;
    const char *tableName=cmeIDDLogsDBTransactionsTableName;
    #define cmeWebServiceEnsureLogsTransactionsTableFree() \
        do { \
            cmeFree(sqlCreate); \
            cmeResultMemTableClean(); \
        } while (0); //Local free() macro.

    pthread_mutex_lock(&cmeLogsSchemaMutex);
    if (cmeLogsSchemaReady)
    {
        pthread_mutex_unlock(&cmeLogsSchemaMutex);
        return(0);
    }
    result=cmeMemTableWithTableColumnNames(pDB,tableName);
    if (!result)
    {
        for (cont=0; cont<cmeResultMemTableCols; cont++)
        {
            if (!strcmp(cmeResultMemTable[cont],cmeIDDLogsDBTransactions_requestMethod_name))
            {
                found=1;
                break;
            }
        }
        cmeResultMemTableClean();
    }
    if (result || !found)
    {
        cmeStrConstrAppend(&sqlCreate,
                           "BEGIN TRANSACTION; DROP TABLE IF EXISTS \"%s\"; ",
                           tableName);
        cmeStrConstrAppend(&sqlCreate,
                           "CREATE TABLE \"%s\" (" cmeIDDanydb_id_name " INTEGER PRIMARY KEY, "
                           cmeIDDanydb_userId_name " TEXT, " cmeIDDanydb_orgId_name " TEXT, "
                           cmeIDDanydb_salt_name " TEXT, " cmeIDDLogsDBTransactions_requestMethod_name " TEXT, "
                           cmeIDDLogsDBTransactions_requestUrl_name " TEXT, "
                           cmeIDDLogsDBTransactions_requestHeaders_name " TEXT, "
                           cmeIDDLogsDBTransactions_startTimestamp_name " TEXT, "
                           cmeIDDLogsDBTransactions_endTimestamp_name " TEXT, "
                           cmeIDDLogsDBTransactions_requestDataSize_name " TEXT, "
                           cmeIDDLogsDBTransactions_responseDataSize_name " TEXT, "
                           cmeIDDLogsDBTransactions_orgResourceId_name " TEXT, "
                           cmeIDDLogsDBTransactions_requestIPAddress_name " TEXT, "
                           cmeIDDLogsDBTransactions_responseCode_name " TEXT, "
                           cmeIDDLogsDBTransactions_responseHeaders_name " TEXT, "
                           cmeIDDLogsDBTransactions_authenticated_name " TEXT); "
                           "CREATE INDEX \"idx_log_%s_uo\" ON \"%s\"("
                           cmeIDDanydb_orgId_name "," cmeIDDanydb_userId_name "); COMMIT;",
                           tableName,tableName,tableName);
        result=cmeSQLRows(pDB,sqlCreate,NULL,NULL);
        if (result)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceEnsureLogsTransactionsTable(), can't create table %s!\n",
                    tableName);
#endif
            cmeWebServiceEnsureLogsTransactionsTableFree();
            pthread_mutex_unlock(&cmeLogsSchemaMutex);
            return(1);
        }
    }
    cmeLogsSchemaReady=1;
    cmeWebServiceEnsureLogsTransactionsTableFree();
    pthread_mutex_unlock(&cmeLogsSchemaMutex);
    return(0);
}

int cmeWebServiceProcessRequest (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                 const char *url, const char **urlElements, int numUrlElements,
                                 const char **headerElements,const char **argumentElements, const char *method,
                                 struct MHD_Connection *connection)
{   //IDD 1.0.21
    int cont,result;
    int authentication=0;
    int powerStatus;  //Local snapshot of cmeEnginePowerStatus, read under cmePowerMutex.
    char *userId=NULL;
    char *orgId=NULL;
    char *orgKey=NULL;
    char *newOrgKey=NULL;
    char *storagePath=NULL;
    const union MHD_ConnectionInfo *connectionInfo=NULL;
#ifdef DEBUG
    int debugSkipAuthz=0;
    const char *debugSkipAuthzEnv=NULL;
#endif
    #define cmeWebServiceProcessRequestFree() \
        do { \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(storagePath); \
            if(orgKey) \
            { \
                memset(orgKey,0,strlen(orgKey)); \
                cmeFree(orgKey); \
            } \
            if(newOrgKey) \
            { \
                memset(newOrgKey,0,strlen(newOrgKey)); \
                cmeFree(newOrgKey); \
            } \
            cmeResultMemTableClean(); \
        } while (0); //Local free() macro.

    // Read the shared engine power status once, under the mutex.
    pthread_mutex_lock(&cmePowerMutex);
    powerStatus=cmeEnginePowerStatus;
    pthread_mutex_unlock(&cmePowerMutex);

    if (cmeWebServiceHasUnsafeRequestInput(urlElements,numUrlElements,argumentElements))
    {
        cmeStrConstrAppend(responseText,"<b>400 ERROR Bad request.</b><br><br>"
                           "Request contains unsupported input characters.");
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(), Error, request contains unsupported input characters.\n");
#endif
        *responseCode=400;
        cmeWebServiceProcessRequestFree();
        return(1);
    }
    if ((numUrlElements==1)&&(strcmp("favicon.ico",urlElements[0])==0)&&(strcmp("GET",method)==0)) //Process favicon.ico; powerStatus='on' not required.
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                    "favicon.ico.\n");
#endif
        cmeWebServiceProcessRequestFree();
        cmeStrConstrAppend (responseFilePath,"%sfavicon.ico",cmeDefaultFilePath);
        cmeStrConstrAppend(&((*responseHeaders)[0]),"Content-Type");
        cmeStrConstrAppend(&((*responseHeaders)[1]),"image/x-icon");
        *responseCode=200; //Response: OK
        cmeWebServiceProcessRequestFree();
        return (0);
    }
    if (numUrlElements==0) //Error; depth does not match a valid value
    {
        cmeStrConstrAppend(responseText,"<b>404 ERROR Resource not found.</b><br><br>"
                   "Resource depth %d. method: '%s', url: '%s'",numUrlElements,method,url);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(). Error, Resource not found."
                "Resource depth %d. method: '%s', url: '%s'\n",numUrlElements,method,url);
#endif
        cmeWebServiceProcessRequestFree();
        *responseCode=404; //Response: Error 404 (resource not found).
        return(1);
    }
    //Get user credentials (parameters userId, orgId, orgKey and newOrgKey).
    cont=0;
    while ((cont<cmeWSURIMaxArguments)&&(argumentElements[cont]))
    {
        if (!strcmp(argumentElements[cont],"userId")) //Copy userId.
        {
            cmeStrConstrAppend(&userId,"%s",argumentElements[cont+1]);
        }
        else if (!strcmp(argumentElements[cont],"orgId")) //Copy orgId.
        {
            cmeStrConstrAppend(&orgId,"%s",argumentElements[cont+1]);
        }
        else if (!strcmp(argumentElements[cont],"orgKey")) //Copy orgKey.
        {
            cmeStrConstrAppend(&orgKey,"%s",argumentElements[cont+1]);
        }
        else if (!strcmp(argumentElements[cont],"newOrgKey")) //Copy newOrgKey (this is an optional parameter for POST requests).
        {
            cmeStrConstrAppend(&newOrgKey,"%s",argumentElements[cont+1]);
        }
        cont+=2;
    }

    if ((!userId)||(!orgId)||(!orgKey)) //Error, some essential parameters for the next functions are not included!
    {
        result=1;
        cmeStrConstrAppend(responseText,"<b>401 ERROR Unauthorized. Parameter userId|orgId|orgKey is missing.</b><br>"
                           "Internal server error number '%d'."
                           "METHOD: '%s' URL: '%s'."
                            "Latest IDD version: <code>%s</code>",result,method,url,
                            cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), Warning, unauthorized '%d'."
                " Method: '%s', URL: '%s' userId, orgId and/or orgKey parameter(s) missing!\n",result,method,url);
#endif
        cmeWebServiceProcessRequestFree();
        *responseCode=401;
        return(2);
    }
    else //Authenticate and authorize (roles) for requesting user.
    {
        //AUTHENTICATION PHASE:
        if (cmeUseOAUTHAuthentication) //Try OAUTH client authentication.
        {
            /*
             * OAuth delegation is handled by an external engine manager.  The
             * manager validates OAuth credentials, creates a delegated
             * organization/user/role/resource scope with its own orgKey, sends
             * normal CaumeDSE requests with that delegated identity, and
             * removes the delegated scope when the OAuth grant expires.  The
             * engine never stores organization keys or OAuth tokens, so it
             * cannot validate OAuth grants directly.
             */
            result=1;
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), OAuth authentication is delegated "
                    "to an external engine manager and is not performed internally.\n");
#endif
            if (!result) //OAUTH Authentication Successful.
            {
                authentication+=1;
            }
        }
        connectionInfo=connection?MHD_get_connection_info(connection, MHD_CONNECTION_INFO_PROTOCOL):NULL; //Get gnutls connection protocol information.
        if ((cmeUseTLSAuthentication)&&(connectionInfo)) //Try TLS client certificate authentication.
        {   //NOTE: CA (ca.pem) signs org certificate; org certificate signs user certificate. Client certificate chain must include both org and user certificates!
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), will try TLS authentication; GnuTLS reports protocol version: %d.\n",
                    connectionInfo->protocol);
#endif
            result=cmeWebServiceClientCertAuth(userId, orgId, connection);
            if (!result) //TLS Authentication Successful.
            {
                authentication+=2;
            }
        }
        else
        {
            if ((cmeBypassTLSAuthenticationInHTTP)&&(cmeUseTLSAuthentication))
            {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), WARNING: bypassing TLS authentication in an HTTP session.\n");
#endif
                authentication+=4; //If TLS authentication is required but session is not HTTPS/TLS, assume authentication is correct. (For testing purposes only, e.g. HTTP in DEBUG mode)
            }
#ifdef DEBUG
            else if ((!connection)&&(getenv("CDSE_DEBUG_TESTS_NONINTERACTIVE")))
            {
                authentication+=4;
            }
#endif
        }
        if (!authentication) //Error, all authentication methods failed!
        {
            cmeStrConstrAppend(responseText,"<b>401 User authentication failed!</b><br>"
                   "METHOD: '%s' URL: '%s'."
                   " Latest IDD version: <code>%s</code>",method,url,
                   cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), User authentication failed."
                " Method: '%s', URL: '%s'.\n",method,url);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=401;
            return(3);
        }
#ifdef DEBUG
        debugSkipAuthzEnv=getenv("CDSE_DEBUG_TEST_SKIP_AUTHZ");
        debugSkipAuthz=((!connection)&&(getenv("CDSE_DEBUG_TESTS_NONINTERACTIVE")))||
                       ((debugSkipAuthzEnv)&&(*debugSkipAuthzEnv)&&
                        (strcmp(debugSkipAuthzEnv,"0")));
        if (!debugSkipAuthz)
#endif
        {
        //AUTHORIZATION PHASE:
        result=cmeWebServiceConfirmUserId(userId,orgKey);
        if (result==1) //System Error, can't open ResourceDB to check userId.
        {
            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(), Error, internal server error '%d'."
                    " Method: '%s', URL: '%s', can't open ResourceDB to check userId: %s !\n",result,method,url,userId);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=500;
            return(4);
        }
        else if (result==2) //Error, invalid userId.
        {
            cmeStrConstrAppend(responseText,"<b>403 ERROR request forbidden for the specified userResourceId</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), Warning, '%d'."
                    " Method: '%s', URL: '%s', can't find userResourceId for userId %s!\n",result,method,url,userId);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=403;
            return(5);
        }
        result=cmeWebServiceConfirmOrgId(orgId,orgKey);
        if (result==1) //System Error, can't open ResourceDB to check orgId.
        {
            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(), Error, internal server error '%d'."
                    " Method: '%s', URL: '%s', can't open ResourceDB to check orgId: %s !\n",result,method,url,orgId);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=500;
            return(6);
        }
        else if (result==2) //Error, invalid orgId.
        {
            cmeStrConstrAppend(responseText,"<b>403 ERROR request forbidden for the specified orgResourceId.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), Warning, '%d'."
                    " Method: '%s', URL: '%s', can't find userResourceId for orgId %s!\n",result,method,url,orgId);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=403;
            return(7);
        }
        result=cmeWebServiceCheckPermissions (method, url, urlElements, numUrlElements,
                                              responseText, responseCode, userId, orgId, orgKey);
        if (result) //System Error or authorization error. cmeWebServiceCheckPermissions() already filled in the response text and code.
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), Warning, '%s'."
                    " Method: '%s', URL: '%s' invalid credentials!\n",*responseText,method,url);
#endif
            cmeWebServiceProcessRequestFree();
            return(8);
        }
        }
    }
    //Check URL resource parameters:
#ifdef DEBUG
    if ((!connection)&&(getenv("CDSE_DEBUG_TESTS_NONINTERACTIVE")))
    {
        if ((numUrlElements>4)&&(strcmp(urlElements[2],"storage")==0))
        {
            cmeStrConstrAppend(&storagePath,"%s",cmeDefaultFilePath);
        }
    }
    else
#endif
    {
    if ((numUrlElements>2)&&(strcmp(urlElements[0],"organizations")==0)) //We have an organization resource in the URL. Check that it is valid.
    {
        if (newOrgKey) //check using newOrgKey
        {
            result=cmeWebServiceConfirmOrgId(urlElements[1],newOrgKey);
        }
        else //check using orgKey
        {
            result=cmeWebServiceConfirmOrgId(urlElements[1],orgKey);
        }
        if (result==1) //System Error, can't open ResourceDB to check orgId.
        {
            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(), Error, internal server error '%d'."
                    " Method: '%s', URL: '%s', can't open ResourceDB to check orgResourceId: %s !\n",result,method,url,urlElements[1]);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=500;
            return(9);
        }
        else if (result==2) //Error, invalid organization in URL.
        {
            cmeStrConstrAppend(responseText,"<b>404 ERROR The organization resource specified in the URL was not found. Check parameters.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Error: cmeWebServiceProcessRequest(), Warning, '%d'."
                    " Method: '%s', URL: '%s', can't find orgResourceId: %s!\n",result,method,url,urlElements[1]);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=404;
            return(10);
        }
    }
    if ((numUrlElements>4)&&(strcmp(urlElements[2],"storage")==0))// We have a storage resource in the URL. Check it is valid and get the corresponding storage path.
    {
        //Get storage path:
        if (newOrgKey) //check using newOrgKey
        {
            result=cmeWebServiceGetStoragePath(&storagePath,urlElements[3],urlElements[1],newOrgKey);
        }
        else //check using orgKey
        {
            result=cmeWebServiceGetStoragePath(&storagePath,urlElements[3],urlElements[1],orgKey);
        }
        if (result==1) //System Error, can't open ResourceDB to check storageId and storagePath.
        {
            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(), Error, internal server error '%d'."
                    " Method: '%s', URL: '%s', can't find storageId: %s !\n",result,method,url,urlElements[3]);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=500;
            return(11);
        }
        else if (result==2) //Error, invalid storageId, can't get path.
        {
            cmeStrConstrAppend(responseText,"<b>404 ERROR The storage resource specified in the URL was not found. Check parameters.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Error: cmeWebServiceProcessRequest(), Warning, '%d'."
                    " Method: '%s', URL: '%s', can't find storageId; can't get storage path of storageId: %s !\n",result,method,url,urlElements[3]);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=404;
            return(12);
        }
    }
    if ((numUrlElements>4)&&(strcmp(urlElements[2],"users")==0))// We have a users resource in the URL. Check it is valid.
    {
        if (newOrgKey) //check using newOrgKey
        {
            result=cmeWebServiceConfirmUserId(urlElements[3],newOrgKey);
        }
        else //check using orgKey
        {
            result=cmeWebServiceConfirmUserId(urlElements[3],orgKey);
        }
        if (result==1) //System Error, can't open ResourceDB to check userId.
        {
            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(), Error, internal server error '%d'."
                    " Method: '%s', URL: '%s', can't open ResourceDB to check userId: %s !\n",result,method,url,urlElements[3]);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=500;
            return(13);
        }
        else if (result==2) //Error, invalid userId.
        {
            cmeStrConstrAppend(responseText,"<b>404 ERROR The userId specified in the URL was not found. Check parameters.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), Warning, '%d'."
                    " Method: '%s', URL: '%s', can't the userId specified in the URL: %s!\n",result,method,url,urlElements[3]);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=404;
            return(14);
        }
    }
    }
    //Process web service requests:
    if ((numUrlElements==1)&&(strcmp(urlElements[0],"engineCommands")==0)) // engine command resource (ignore powerStatus)
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                    "engine command resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
        pthread_mutex_lock(&cmePowerMutex);
        result=cmeWebServiceProcessEngineResource(responseText, responseCode, url, argumentElements, method, &cmeEnginePowerStatus);
        pthread_mutex_unlock(&cmePowerMutex);
        if (result) //Error, return error code + 100.
        {
            return(result+100);
        }
        else
        {
            return(0);
        }
    }
    //Check engine power status:
    else if (!powerStatus)  //powerStatus is off
    {
        cmeStrConstrAppend(responseText,"<b>503 ERROR Engine is off.</b><br><br>Turn engine on "
                           "using administrator credentials with PUT request: <code>https://{engine}"
                           "?userId=&lt;admin_userid&gt;&amp;orgId=&lt;admin_orgid&gt;&amp;"
                           "orgKey=&lt;admin_orgpwd&gt;&amp;setEnginePower=on </code>");
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(), Error, Web Services are off; "
                "no access to admin. databases for method: %s, url: %s!\n",method,url);
#endif
        cmeWebServiceProcessRequestFree();
        *responseCode=503; //Response: Error 503 service unavailable.
        return(15);
    }
    //Process trasactions (logs) requests:
    else if ((numUrlElements==1)&&(strcmp(urlElements[0],"transactions")==0)) //transaction class resource.
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                    "engine command resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
        result=cmeWebServiceProcessTransactionClass(responseText,responseHeaders,responseCode,
                                                    url,argumentElements,method);
        if (result) //Error, return error code + 100.
        {
            return(result+100);
        }
        else
        {
            return(0);
        }
    }
    //Good so far, now process the URL according to the resource depth level:
    else if ((numUrlElements>=1)&&(numUrlElements<=cmeIDDURIMaxDepth)&&(powerStatus)) //organization resource tree.
    {   //Check URL depth level an process response accordingly (CME Web Services Definition)
        if ((numUrlElements==1)&&(strcmp(urlElements[0],"organizations")==0)) // organization class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "organization class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessOrgClass (responseText, responseFilePath, responseHeaders, responseCode,
                                                 url, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==2)&&(strcmp(urlElements[0],"organizations")==0))// organization resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "organization resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessOrgResource(responseText, responseHeaders, responseCode,
                                                   url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==3)&&(strcmp(urlElements[2],"users")==0))// user class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "user class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessUserClass(responseText, responseHeaders, responseCode,
                                                 url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==4)&&(strcmp(urlElements[2],"users")==0))// user resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "user resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessUserResource(responseText, responseFilePath, responseHeaders, responseCode,
                                                    url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==5)&&(strcmp(urlElements[4],"roleTables")==0))// roleTable class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "roleTable class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessRoleTableClass(responseText, responseHeaders, responseCode,
                                                     url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==6)&&(strcmp(urlElements[4],"roleTables")==0))// roleTable resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "roleTable resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessRoleTableResource(responseText, responseFilePath, responseHeaders, responseCode,
                                                         url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==5)&&(strcmp(urlElements[4],"filterWhitelist")==0))// filterWhitelist class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "filterWhitelist class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessFilterWhitelistClass(responseText, responseHeaders, responseCode,
                                                     url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==6)&&(strcmp(urlElements[4],"filterWhitelist")==0))// filterWhitelist resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "filterWhitelist resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessFilterWhitelistResource(responseText, responseFilePath, responseHeaders, responseCode,
                                                         url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==5)&&(strcmp(urlElements[4],"filterBlacklist")==0))// filterBlacklist class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "filterBlacklist class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessFilterBlacklistClass(responseText, responseHeaders, responseCode,
                                                     url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==6)&&(strcmp(urlElements[4],"filterBlacklist")==0))// filterBlacklist resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "filterBlacklist resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessFilterBlacklistResource(responseText, responseFilePath, responseHeaders, responseCode,
                                                         url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==3)&&(strcmp(urlElements[2],"storage")==0)) //storage class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "storage class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessStorageClass (responseText, responseHeaders, responseCode,
                                                 url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==4)&&(strcmp(urlElements[2],"storage")==0))// storage resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "storage resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessStorageResource(responseText, responseFilePath, responseHeaders, responseCode,
                                                   url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements>=5)&&(numUrlElements<=10)&&(strcmp(urlElements[2],"storage")==0)&&
                 (strcmp(urlElements[4],"dbNames")==0))
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "DB browsing resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessDBBrowseResource(responseText,responseHeaders,responseCode,url,
                                                        urlElements,numUrlElements,argumentElements,
                                                        method,storagePath);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==5)&&(strcmp(urlElements[4],"documentTypes")==0))// documentTypes class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "documentType class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessDocumentTypeClass(responseText, responseHeaders, responseCode,
                                                         url, urlElements, argumentElements, method);
            if (result)
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==6)&&(strcmp(urlElements[4],"documentTypes")==0)) //documentType resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "documentType resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessDocumentTypeResource(responseText, responseFilePath, responseCode,
                                                            url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==7)&&(strcmp(urlElements[6],"documents")==0))// documents class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                           "document class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessDocumentClass (responseText, responseHeaders, responseCode,
                                                      url, urlElements, argumentElements, method, storagePath);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==8)&&(strcmp(urlElements[6],"documents")==0)) //document resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                           "document resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessDocumentResource(responseText, responseHeaders, responseCode,
                                                        url, urlElements, argumentElements, method, storagePath, connection);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==9)&&(strcmp(urlElements[8],"parserScripts")==0))// parserScripts class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "parserScript class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessParserScriptClass(responseText, responseHeaders, responseCode,
                                                         url, urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==10)&&(strcmp(urlElements[8],"parserScripts")==0))// parserScripts resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                           "parserScript resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessParserScriptResource(responseText, responseHeaders, responseCode,
                                                            url, urlElements, argumentElements, method, storagePath);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==9)&&(strcmp(urlElements[8],"content")==0))// content class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                           "content class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessContentClass (responseText, responseFilePath, responseHeaders, responseCode,
                                                     url, urlElements, argumentElements, method, storagePath);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==9)&&(strcmp(urlElements[8],"contentRows")==0))// contentRows class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "contentRows class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessContentRowClass (responseText, responseHeaders, responseCode, url,
                                                        urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==10)&&(strcmp(urlElements[8],"contentRows")==0))// contentRow resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "contentRow resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessContentRowResource (responseText, responseHeaders, responseCode, url,
                                                           urlElements, argumentElements, method, storagePath);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==9)&&(strcmp(urlElements[8],"contentColumns")==0))// contentColumns class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "contentColumns class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessContentColumnClass (responseText, responseHeaders, responseCode, url,
                                                           urlElements, argumentElements, method);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else if ((numUrlElements==10)&&(strcmp(urlElements[8],"contentColumns")==0))// contentColumn resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "contentColumn resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            result=cmeWebServiceProcessContentColumnResource (responseText, responseHeaders, responseCode, url,
                                                              urlElements, argumentElements, method, storagePath);
            if (result) //Error, return error code + 100.
            {
                return(result+100);
            }
            else
            {
                return(0);
            }
        }
        else //ERROR: unknown resource type
        {
            cmeStrConstrAppend(responseText,"<b>404 ERROR Resource not found.</b><br><br>"
               "Unknown resource: '%s'. method: '%s', url: '%s'",urlElements[numUrlElements-1],method,url);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(). Error, resource not found."
                    "Unknown resource: '%s'. Method: '%s', url: '%s'\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=404; //Response: Error 404 (resource not found).
            return (22);
        }
    }
    else //Error; depth does not match a valid value
    {
        cmeStrConstrAppend(responseText,"<b>404 ERROR Resource not found.</b><br><br>"
                   "Resource depth %d. method: '%s', url: '%s'",numUrlElements,method,url);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(). Error, Resource not found."
                "Resource depth %d. method: '%s', url: '%s'\n",numUrlElements,method,url);
#endif
        cmeWebServiceProcessRequestFree();
        *responseCode=404; //Response: Error 404 (resource not found).
        return(24);
    }
}

int cmeWebServiceProcessEngineResource (char **responseText, int *responseCode, const char *url,
                                        const char **argumentElements, const char *method, int *powerStatus)
{   //IDD v.1.0.20 definitions
    int cont, numCorrectArgs;
    int tmpPowerStatus=1;
    char *userId=NULL;
    char *orgId=NULL;
    char *orgKey=NULL;
    char *engineCommand=NULL;
    #define cmeWebServiceProcessEngineResourceFree() \
        do { \
            cmeFree(userId) \
            cmeFree(orgId) \
            cmeFree(orgKey) \
            cmeFree(engineCommand) \
        } while (0); //Local free() macro.

    if(!strcmp(method,"PUT")) //Method = PUT is ok, process:
    {
        numCorrectArgs=0;
        cont=0;
        while ((cont<cmeWSURIMaxArguments)&&(argumentElements[cont])&&(numCorrectArgs<4)) //Check for parameters
        {
            if (!strcmp(argumentElements[cont],"*setEnginePower")) //parameter setEnginePower found!.
            {
                cmeStrConstrAppend(&engineCommand,"setEnginePower");
                if (!strcmp(argumentElements[cont+1],"on")) // Power on.
                {
                    cmeStrConstrAppend(responseText,"engine power status changed to on.<br>");
                    tmpPowerStatus=1;
                    numCorrectArgs++;
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessEngineResource(), engine command successful: "
                                "engine on.\n");
#endif
                }
                else if (!strcmp(argumentElements[cont+1],"off")) // Power off.
                {
                    cmeStrConstrAppend(responseText,"engine power status changed to off.<br>");
                    tmpPowerStatus=0;
                    numCorrectArgs++;
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessEngineResource(), engine command successful: "
                                "engine off.\n");
#endif
                }
                else //Error, unknown setEnginePower command.
                {
                    cmeStrConstrAppend(responseText,"<b>503 ERROR unknown setEnginePower value '%s'.<br>",argumentElements[cont+1]);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessEngineResource(), Error, unknown setEnginePower value. "
                            "Method: %s, url: %s!\n",method,url);
#endif
                    *responseCode=503;
                    cmeWebServiceProcessEngineResourceFree();
                    return(0);
                }
            }
            cont+=2;
        }
        if ((numCorrectArgs==1)&&(strcmp(engineCommand,"setEnginePower")==0)) //Command 'setEnginePower' successful
        {
            *powerStatus=tmpPowerStatus;
            *responseCode=200;
            cmeWebServiceProcessEngineResourceFree();
            return(0);
        }
        else //Error, invalid number of arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Conflicting number of arguments."
                               "</b><br><br>The provided number of arguments is incorrect. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgEngineOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessEngineResource(), Error, incorrect number of arguments"
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessEngineResourceFree();
            *responseCode=409;
            return(1);
        }
    }
    else if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        if (*powerStatus)
        {
            cmeStrConstrAppend(responseText,"<b>200 Engine power status is 'on'.<br");
        }
        else
        {
            cmeStrConstrAppend(responseText,"<b>200 Engine power status is 'off'.<br");
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessEngineResource(), engine command successful: "
                    " 'GET'; engine is %d.\n",*powerStatus);
#endif
        cmeWebServiceProcessEngineResourceFree();
        *responseCode=200;
        return(0);
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        cmeStrConstrAppend(responseText,"<b>200 OK - Options for engine resources:</b><br>"
                           "%sLatest IDD version: <code>%s</code>",cmeWSMsgEngineOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessEngineResource(), OPTIONS successful for user resource."
                " Method: '%s', URL: '%s'!\n",method,url);
#endif
        cmeWebServiceProcessEngineResourceFree();
        *responseCode=200;
        return(0);
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                            "METHOD: '%s' URL: '%s'."
                            "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgEngineOptions,
                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessEngineResource(), Error, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessEngineResourceFree();
        *responseCode=405;
        return(2);
    }
}

int cmeWebServiceProcessUserResource (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                      const char *url, const char **urlElements,const char **argumentElements, const char *method)
{   //IDD v. 1.0.20 definitions.
    int cont,result;
    int keyArg=0;
    int orgArg=0;
    int usrArg=0;
    int newKeyArg=0;
    int numSaveArgs=0;
    int numMatchArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL;                  //requester orgKey.
    char *userId=NULL;                  //requester userId.
    char *orgId=NULL;                   //requester orgId.
    char *newOrgKey=NULL;               //requester newOrgKey (optional).
    char *salt=NULL;
    char **columnValues=NULL;           //Values to be created/updated (POST/PUT)
    char **columnNames=NULL;            //Names of columns of values to be created/updated (POST/PUT)
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    const int numDuplicateMatchColumns=2;   //Columns by which we detect duplicates, in this case: "orgResourceId","userResourceId"; must be the first to be added to columnValuesToMatch and columnNamesToMatch
    const int numColumns=12;            //Constant: number of cols. in user table
    const char *tableName="users";
    const int numValidGETALLMatch=8;    //9 parameters + 2 from URL (orgResourceId and userResourceId)
    const int numValidPOSTSave=8;       //9 parameters + 2 from URL (orgResourceId and userResourceId)
    const int numValidPUTSave=8;
    const char *validGETALLMatchColumns[8]={"_userId","_orgId","_resourceInfo","_certificate","_publicKey","_basicAuthPwdHash","_oauthConsumerKey","_oauthConsumerSecret"};
    const char *validPOSTSaveColumns[8]={"userId","orgId","*resourceInfo","*certificate","*publicKey","*basicAuthPwdHash","*oauthConsumerKey","*oauthConsumerSecret"};
    const char *validPUTSaveColumns[8]={"userId","orgId","*resourceInfo","*certificate","*publicKey","*basicAuthPwdHash","*oauthConsumerKey","*oauthConsumerSecret"};
    #define cmeWebServiceProcessUserResourceFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            cmeFree(salt); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store user resource information, columns 1 to numColumns (POST/PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns); //Set space to store user resource information, columns 1 to numColumns (POST/PUT).
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store user resource information, column values to match (GET/PUT).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    if(!strcmp(method,"POST")) //Method = POST is ok, process:
    {
        cmeStrConstrAppend(&(columnValues[0]),"%s",urlElements[3]); //We ignore the argument "userResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[0]),urlElements[3]);
        cmeStrConstrAppend(&(columnNames[0]),"userResourceId");
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"userResourceId");
        cmeStrConstrAppend(&(columnValues[1]),"%s",urlElements[1]); //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[1]);
        cmeStrConstrAppend(&(columnNames[1]),"orgResourceId");
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"orgResourceId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), POST, column userResourceId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), POST, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=2;
        numSaveArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPOSTSaveColumns, numValidGETALLMatch, numValidPOSTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(numSaveArgs==10)&&(keyArg)&&(usrArg)&&(orgArg)) //Command POST successful. (at least orgId, orgKey, userId, >=2 Match and == 10 Save)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                if(newOrgKey) //Check resource using newOrgKey
                {
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                      numDuplicateMatchColumns,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,newOrgKey); //Check if user doesn't exist.
                }
                else //Check resource using orgKey
                {
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                      numDuplicateMatchColumns,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey); //Check if user doesn't exist.
                }
                if(numResultRegisters>0) //User is already in DB -> Error
                {
                    cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                                       "User already exists! "
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, forbidden request, user already exists!"
                            " Method: '%s', URL: '%s'!\n",method,url);
#endif
                    cmeWebServiceProcessUserResourceFree();
                    *responseCode=403;
                    return(1);
                }
                if(newOrgKey) //Create resource using newOrgKey
                {
                    result=cmePostProtectDBRegister(pDB,tableName,(const char **)columnNames,(const char **)columnValues,
                                                    numSaveArgs,newOrgKey);
                }
                else //Create resource using orgKey
                {
                    result=cmePostProtectDBRegister(pDB,tableName,(const char **)columnNames,(const char **)columnValues,
                                                    numSaveArgs,orgKey);
                }
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    cmeWebServiceProcessUserResourceFree();
                    *responseCode=500;
                    return(2);
                }
                else //Ok
                {
                    cmeStrConstrAppend(responseText,"Method '%s', user resource '%s' created successfully!<br>",
                                       method, urlElements[3]);
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), POST successful.\n");
#endif
                    *responseFilePath=NULL;

                    *responseCode=201;
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                    cmeWebServiceProcessUserResourceFree();
                    return(0);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessUserResourceFree();
                *responseCode=500;
                return(3);
            }
        }
        else //Error, invalid number of arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessUserResourceFree();
            *responseCode=409;
            return(4);
        }
    }
    else if(!strcmp(method,"PUT")) //Method = PUT is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[3]); //We ignore the argument "userResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"userResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[1]); //We also ignore the argument "orgId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"orgResourceId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), PUT, column userResourceId: '%s'.\n",
                urlElements[3]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), PUT, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPUTSaveColumns, numValidGETALLMatch, numValidPUTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(numSaveArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //Command PUT successful. (at least orgId, orgKey, userId, >=2 Match and >= 1 Save)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (result) //Error, internal server error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    *responseCode=500;
                    cmeWebServiceProcessUserResourceFree();
                    return(5);
                }
                else //Ok
                {
                    if (numResultRegisters>0) //Resource found
                    {
                        if (resultRegisterCols) //Free resultRegisterCols data obtained by cmeGetUnprotectDBRegisters() call above to check if results were available.
                        {
                            for (cont=0; cont<numResultRegisterCols;cont++)
                            {
                               cmeFree(resultRegisterCols[cont]);
                            }
                            cmeFree(resultRegisterCols);
                        }
                        numResultRegisterCols=0;
                        numResultRegisters=0;
                        result=cmePutProtectDBRegisters (pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,numMatchArgs,
                                                         (const char **)columnNames,(const char **)columnValues,numSaveArgs,&resultRegisterCols,
                                                         &numResultRegisterCols,&numResultRegisters,orgKey);
                        if (result) //Error updating - 500
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserOptions,
                                                cmeInternalDBDefinitionsVersion);
    #ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s'!\n",result,method,url);
    #endif
                            *responseCode=500;
                            cmeWebServiceProcessUserResourceFree();
                            return(6);
                        }
                        else //Ok
                        {
                            if (numResultRegisters>0) //Resource updated
                            {
                                *responseCode=200;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), PUT successful.\n");
#endif
                            }
                            else //Resource not found!
                            {
                                *responseCode=404;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), PUT successful but"
                                        " resource not found.\n");
#endif
                            }
                        }
                    }
                    else //Resource not found!
                    {
                        *responseCode=404;
                    }
                }
                cmeStrConstrAppend(responseText,"Method '%s', updated resources: %d .<br>",
                                   method, numResultRegisters);
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                cmeWebServiceProcessUserResourceFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessUserResourceFree();
                *responseCode=500;
                return(7);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessUserResourceFree();
            *responseCode=409;
            return(8);
        }
    }
    else if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[3]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
                                                                            //First match filter with index 0.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"userResourceId"); //We will match against this value for the search.
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), GET, column userResourceId: '%s'.\n",
                urlElements[3]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >= 2 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    //Construct responseText and create response headers according to the user's outputType (optional) request:
                    result=cmeConstructWebServiceTableResponse ((const char **)resultRegisterCols,numResultRegisterCols,numResultRegisters,
                                                                argumentElements, url, method, urlElements[3],
                                                                responseHeaders, responseText, responseCode);
                    cmeWebServiceProcessUserResourceFree();
                    return(0);
                }
                else //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessUserResourceFree();
                    *responseCode=500;
                    return(9);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessUserResourceFree();
                *responseCode=500;
                return(10);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessUserResourceFree();
            *responseCode=409;
            return(11);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[3]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
                                                                            //First match filter with index 0.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"userResourceId"); //We will match against this value for the search.
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[1]);  //We ignore the argument "orgId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), HEAD, column userResourceId: '%s'.\n",
                urlElements[3]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), HEAD, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >= 2 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) //Found >0 results
                    {
                        *responseCode=200;
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), HEAD successful.\n");
#endif
                    }
                    else //Found 0 results
                    {
                        *responseCode=404;
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), HEAD, successful but"
                        "no record found!\n");
#endif
                    }
                    //cmeStrConstrAppend(responseText,"<p>Matched results: %d</p><br>",numResultRegisters);  //HEAD does not return a body
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                    cmeWebServiceProcessUserResourceFree();
                    return(0);
                }
                else //Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                        "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'; cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessUserResourceFree();
                    return(12);
                }
            }
            else //Server ERROR
            {
                *responseCode=500;
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'; can't open DBFile: %s!\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessUserResourceFree();
                return(13);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessUserResourceFree();
            *responseCode=409;
            return(14);
        }
    }
    else if(!strcmp(method,"DELETE")) //Method = DELETE is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[3]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
                                                                            //First match filter with index 0.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"userResourceId"); //We will match against this value for the search.
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[1]);  //We ignore the argument "orgId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), DELETE, column userResourceId: '%s'.\n",
                urlElements[3]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), DELETE, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >= 2 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                     &numResultRegisters,orgKey);
                if (!result) //Delete OK
                {
                    if (numResultRegisters) // Deleted 1 register
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), DELETE successful.\n");
#endif
                    }
                    else // Deleted 0 registers
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), DELETE successful.\n");
#endif
                    }
                    cmeConstructWebServiceCountResponse("Deleted registers",numResultRegisters,
                                                        argumentElements,method,url,
                                                        responseHeaders,responseText,responseCode);
                    cmeWebServiceProcessUserResourceFree();
                    return(0);
                }
                else //Delete Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), DELETE error!, "
                            "cmeDeleteUnporotectDBRegisters error!\n");
#endif
                    cmeWebServiceProcessUserResourceFree();
                    return(15);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                   "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserOptions,
                                   cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open DB file: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessUserResourceFree();
                *responseCode=500;
                return(16);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessUserResourceFree();
            *responseCode=409;
            return(17);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[3]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
                                                                            //First match filter with index 0.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"userResourceId"); //We will match against this value for the search.
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[1]);  //We ignore the argument "orgId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), OPTIONS, column userResourceId: '%s'.\n",
                urlElements[3]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >= 2 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for user resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgUserOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessUserResource(), OPTIONS successful for user resource."
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessUserResourceFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessUserResourceFree();
            *responseCode=409;
            return(18);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserResource(), Error, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessUserResourceFree();
        *responseCode=405;
        return(19);
    }
}

int cmeWebServiceProcessUserClass (char **responseText, char ***responseHeaders, int *responseCode, const char *url,
                                   const char **urlElements,const char **argumentElements, const char *method)
{   //IDD v.1.0.20 definitions.
    int cont,result;
    int orgArg=0;
    int usrArg=0;
    int keyArg=0;
    int newKeyArg=0;
    int numMatchArgs=0;
    int numSaveArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL;
    char *userId=NULL;
    char *orgId=NULL;
    char *newOrgKey=NULL;
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET)
    char **columnValues=NULL;
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    char **columnNamesToMatch=NULL;
    char **columnNames=NULL;
    const int numColumns=12;            //Constant: number of cols. in user table
    const char *tableName="users";
    const int numValidGETALLMatch=9;    //9 parameters + 1 from URL (orgResourceId)
    const int numValidPUTSave=8;
    const char *validGETALLMatchColumns[9]={"_userId","_orgId","_resourceInfo","_certificate","_publicKey","_userResourceId","_basicAuthPwdHash","_oauthConsumerKey","_oauthConsumerSecret"};
    const char *validPUTSaveColumns[8]={"userId","orgId","*resourceInfo","*certificate","*publicKey","*basicAuthPwdHash","*oauthConsumerKey","*oauthConsumerSecret"};
    #define cmeWebServiceProcessUserClassFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(newOrgKey); \
            cmeFree(orgId); \
            cmeFree(userId); \
            cmeFree(dbFilePath); \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

 //   *responseText=NULL;
 //   *responseFilePath=NULL;
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store user resource information, column values to match (GET).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns);  //Set space to store column names to match (GET).
    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store user resource information, column values to match (PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns);  //Set space to store column names to match (PUT).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName); //Set DB full path.
    if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(usrArg)&&(keyArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, userId, orgId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
                //Construct responseText and create response headers according to the user's outputType (optional) request:
                result=cmeConstructWebServiceTableResponse ((const char **)resultRegisterCols,numResultRegisterCols,numResultRegisters,
                                                            argumentElements, url, method, urlElements[1],
                                                            responseHeaders, responseText, responseCode);
                cmeWebServiceProcessUserClassFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                    "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessUserClassFree();
                *responseCode=500;
                return(1);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Conflicting number of arguments."
                               "</b><br><br>The provided number of arguments is incorrect. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserClassOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, conflicting number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessUserClassFree();
            *responseCode=409;
            return(2);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "orgId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >= 1 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for user class resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgUserClassOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), OPTIONS successful for user class resource."
                    "Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessUserClassFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserClassOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessUserClassFree();
            *responseCode=409;
            return(3);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), HEAD, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(usrArg)&&(keyArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, userId, orgId and >= 1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) //Found >0 results
                    {
                        *responseCode=200;
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), HEAD successful.\n");
#endif
                    }
                    else //Found 0 results
                    {
                        *responseCode=404;
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), HEAD, successful but"
                        "no record found!\n");
#endif
                    }
                    //cmeStrConstrAppend(responseText,"Matched results: %d <br>",numResultRegisters);  //Head does not provide a body.
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                    cmeWebServiceProcessUserClassFree();
                    return(0);
                }
                else //Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                        "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserClassOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'; cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessUserClassFree();
                    return(12);
                }
            }
            else //Server ERROR
            {
                *responseCode=500;
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'; can't open DBFile: %s!\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessUserClassFree();
                return(13);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserClassOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessUserClassFree();
            *responseCode=409;
            return(14);
        }
    }
    else if(!strcmp(method,"DELETE")) //Method = DELETE is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "orgId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), DELETE, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >= 1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                     &numResultRegisters,orgKey);
                if (!result) //Delete OK
                {
                    if (numResultRegisters) // Deleted >=1 registers
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), DELETE successful.\n");
#endif
                    }
                    else // Deleted 0 registers
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), DELETE successful.\n");
#endif
                    }
                    cmeConstructWebServiceCountResponse("Deleted registers",numResultRegisters,
                                                        argumentElements,method,url,
                                                        responseHeaders,responseText,responseCode);
                    cmeWebServiceProcessUserClassFree();
                    return(0);
                }
                else //Delete Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserClassOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), DELETE error!, "
                            "cmeDeleteUnporotectDBRegisters error!\n");
#endif
                    cmeWebServiceProcessUserClassFree();
                    return(15);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                   "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserClassOptions,
                                   cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open DB file: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessUserClassFree();
                *responseCode=500;
                return(16);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserClassOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessUserClassFree();
            *responseCode=409;
            return(17);
        }
    }
    else if(!strcmp(method,"PUT")) //Method = PUT is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]); //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), PUT, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPUTSaveColumns, numValidGETALLMatch, numValidPUTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(numSaveArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId, >= 1 Match and >= 1 Save)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (result) //Error, internal server error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserClassOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    *responseCode=500;
                    cmeWebServiceProcessUserClassFree();
                    return(18);
                }
                else //Ok
                {
                    if (numResultRegisters>0) //Resource found
                    {
                        if (resultRegisterCols) //Free resultRegisterCols data obtained by cmeGetUnprotectDBRegisters() call above to check if results were available.
                        {
                            for (cont=0; cont<numResultRegisterCols;cont++)
                            {
                               cmeFree(resultRegisterCols[cont]);
                            }
                            cmeFree(resultRegisterCols);
                        }
                        numResultRegisterCols=0;
                        numResultRegisters=0;
                        result=cmePutProtectDBRegisters (pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,numMatchArgs,
                                                         (const char **)columnNames,(const char **)columnValues,numSaveArgs,&resultRegisterCols,
                                                         &numResultRegisterCols,&numResultRegisters,orgKey);
                        if (result) //Error updating - 500
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserClassOptions,
                                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                            *responseCode=500;
                            cmeWebServiceProcessUserClassFree();
                            return(19);
                        }
                        else //Ok
                        {
                            if (numResultRegisters>0) //Resource updated
                            {
                                *responseCode=200;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), PUT successful.\n");
#endif
                            }
                            else //Resource not found!
                            {
                                *responseCode=404;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), PUT successful but"
                                        " resource not found.\n");
#endif
                            }
                        }
                    }
                    else //Resource not found!
                    {
                        *responseCode=404;
                    }
                }
                cmeStrConstrAppend(responseText,"Method '%s', updated resources: %d .<br>",
                                   method, numResultRegisters);
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                cmeWebServiceProcessUserClassFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgUserClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessUserClassFree();
                *responseCode=500;
                return(20);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserClassOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessUserClassFree();
            *responseCode=409;
            return(21);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method is not allowed for this resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgUserClassOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessUserClass(), Error, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessUserClassFree();
        *responseCode=405;
        return(22);
    }
}

int cmeWebServiceProcessRoleTableClass (char **responseText, char ***responseHeaders, int *responseCode,
                                         const char *url, const char **urlElements, const char **argumentElements, const char *method)
{
    int cont;
    const char *tableNames[20]={"documents","users","roleTables","parserScripts","outputDocuments","content",
                                "contentRows","contentColumns","dbNames","dbTables","tableRows","tableColumns",
                                "organizations","storage","documentTypes","engineCommands","transactions","meta",
                                "filterWhitelist","filterBlacklist"};
    if(!strcmp(method,"GET"))
    {
        cmeStrConstrAppend(responseText,"<b>200 OK - Available role tables:</b><br>");
        for(cont=0;cont<20;cont++)
        {
            cmeStrConstrAppend(responseText,"%s<br>",tableNames[cont]);
        }
        *responseCode=200;
        return(0);
    }
    else if(!strcmp(method,"OPTIONS"))
    {
        cmeStrConstrAppend(responseText,"<b>200 OK - Options for role table class resources:</b><br>"
                           "%sLatest IDD version: <code>%s</code>",cmeWSMsgRoleTableClassOptions,
                           cmeInternalDBDefinitionsVersion);
        *responseCode=200;
        return(0);
    }
    else
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method is not allowed for this roleTable class resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableClassOptions,
                           cmeInternalDBDefinitionsVersion);
        *responseCode=405;
        return(2);
    }
}

static int cmeWebServiceProcessFilterListResource (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                           const char *url, const char **urlElements, const char **argumentElements, const char *method,
                                           const char *filterTableName, const char *filterLabel, const char *resourceOptions);

static int cmeWebServiceProcessFilterListClass (char **responseText, char ***responseHeaders, int *responseCode,
                                         const char *url, const char **urlElements, const char **argumentElements, const char *method,
                                         const char *filterTableName, const char *filterLabel,
                                         const char *classOptions, const char *resourceOptions)
{
    int result;
    char *responseFilePath=NULL;
    const char *resourceElements[6];

    if(!strcmp(method,"GET"))
    {
        resourceElements[0]=urlElements[0];
        resourceElements[1]=urlElements[1];
        resourceElements[2]=urlElements[2];
        resourceElements[3]=urlElements[3];
        resourceElements[4]=urlElements[4];
        resourceElements[5]=urlElements[3];
        result=cmeWebServiceProcessFilterListResource(responseText,&responseFilePath,responseHeaders,responseCode,
                                                      url,resourceElements,argumentElements,method,
                                                      filterTableName,filterLabel,resourceOptions);
        cmeFree(responseFilePath);
        return(result);
    }
    else if(!strcmp(method,"OPTIONS"))
    {
        cmeStrConstrAppend(responseText,"<b>200 OK - Options for %s class resources:</b><br>"
                           "%sLatest IDD version: <code>%s</code>",filterLabel,classOptions,
                           cmeInternalDBDefinitionsVersion);
        *responseCode=200;
        return(0);
    }
    else
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method is not allowed for this %s class resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",filterLabel,method,url,classOptions,
                           cmeInternalDBDefinitionsVersion);
        *responseCode=405;
        return(2);
    }
}

static int cmeWebServiceProcessFilterListResource (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                           const char *url, const char **urlElements, const char **argumentElements, const char *method,
                                           const char *filterTableName, const char *filterLabel, const char *resourceOptions)
{
    int cont,result=0;
    int keyArg=0,orgArg=0,usrArg=0,newKeyArg=0;
    int numSaveArgs=0,numMatchArgs=0;
    int numResultRegisterCols=0,numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL,*userId=NULL,*orgId=NULL,*newOrgKey=NULL;
    char **columnValues=NULL,**columnNames=NULL;
    char **columnValuesToMatch=NULL,**columnNamesToMatch=NULL;
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    const char *tableName=filterTableName;
    const int numColumns=cmeIDDRolesDBAnyTableNumCols;
    const int numDuplicateMatchColumns=2;
    const int numValidGETALLMatch=8;
    const int numValidPOSTSave=8;
    const int numValidPUTSave=8;
    const char *validGETALLMatchColumns[8]={"_userId","_orgId","__get","__post","__put","__delete","__head","__options"};
    const char *validPOSTSaveColumns[8]={"userId","orgId","*_get","*_post","*_put","*_delete","*_head","*_options"};
    const char *validPUTSaveColumns[8]={"userId","orgId","*_get","*_post","*_put","*_delete","*_head","*_options"};
    #define cmeWebServiceProcessFilterListResourceFree() \
        do { \
            cmeFree(orgKey); cmeFree(userId); cmeFree(orgId); cmeFree(newOrgKey); cmeFree(dbFilePath); \
            if (resultRegisterCols) { for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) cmeFree(resultRegisterCols[cont]); cmeFree(resultRegisterCols); } \
            if (columnValues) { for (cont=0;cont<numColumns;cont++) cmeFree(columnValues[cont]); cmeFree(columnValues); } \
            if (columnNames) { for (cont=0;cont<numColumns;cont++) cmeFree(columnNames[cont]); cmeFree(columnNames); } \
            if (columnValuesToMatch) { for (cont=0;cont<numColumns;cont++) cmeFree(columnValuesToMatch[cont]); cmeFree(columnValuesToMatch); } \
            if (columnNamesToMatch) { for (cont=0;cont<numColumns;cont++) cmeFree(columnNamesToMatch[cont]); cmeFree(columnNamesToMatch); } \
            if (pDB) { cmeDBClose(pDB); pDB=NULL; } \
        } while (0)

    columnValues=(char **)malloc(sizeof(char *)*numColumns);
    columnNames=(char **)malloc(sizeof(char *)*numColumns);
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns);
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns);
    if ((!columnValues)||(!columnNames)||(!columnValuesToMatch)||(!columnNamesToMatch))
    {
        *responseCode=500;
        cmeWebServiceProcessFilterListResourceFree();
        return(1);
    }
    for (cont=0;cont<numColumns;cont++)
    {
        columnValues[cont]=NULL;
        columnNames[cont]=NULL;
        columnValuesToMatch[cont]=NULL;
        columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);

    cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);
    cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
    cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[5]);
    cmeStrConstrAppend(&(columnNamesToMatch[1]),"userResourceId");
    numMatchArgs=2;
    if(!strcmp(method,"POST"))
    {
        cmeStrConstrAppend(&(columnValues[0]),"%s",urlElements[1]);
        cmeStrConstrAppend(&(columnNames[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValues[1]),"%s",urlElements[5]);
        cmeStrConstrAppend(&(columnNames[1]),"userResourceId");
        numSaveArgs=2;
        cmeProcessURLMatchSaveParameters(method,argumentElements,validGETALLMatchColumns,validPOSTSaveColumns,
                                         numValidGETALLMatch,numValidPOSTSave,columnValuesToMatch,columnNamesToMatch,
                                         columnValues,columnNames,&numMatchArgs,&numSaveArgs,&userId,&orgId,&orgKey,
                                         &newOrgKey,&usrArg,&orgArg,&keyArg,&newKeyArg);
        if ((numSaveArgs!=10)||(!keyArg)||(!usrArg)||(!orgArg))
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments.</b><br>"
                               "METHOD: '%s' URL: '%s'.%sLatest IDD version: <code>%s</code>",
                               method,url,resourceOptions,cmeInternalDBDefinitionsVersion);
            *responseCode=409;
            cmeWebServiceProcessFilterListResourceFree();
            return(2);
        }
        result=cmeDBOpen(dbFilePath,&pDB);
        if (!result)
        {
            result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                              numDuplicateMatchColumns,&resultRegisterCols,&numResultRegisterCols,
                                              &numResultRegisters,newOrgKey?newOrgKey:orgKey);
        }
        if (result)
        {
            *responseCode=500;
            cmeWebServiceProcessFilterListResourceFree();
            return(3);
        }
        if(numResultRegisters>0)
        {
            *responseCode=403;
            cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>%s resource already exists!",filterLabel);
            cmeWebServiceProcessFilterListResourceFree();
            return(4);
        }
        result=cmePostProtectDBRegister(pDB,tableName,(const char **)columnNames,(const char **)columnValues,
                                        numSaveArgs,newOrgKey?newOrgKey:orgKey);
        if (result)
        {
            *responseCode=500;
            cmeWebServiceProcessFilterListResourceFree();
            return(5);
        }
        *responseFilePath=NULL;
        *responseCode=201;
        cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
        cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
        cmeStrConstrAppend(responseText,"Method '%s' created %s resource for user '%s'.<br>",method,filterLabel,urlElements[5]);
        cmeWebServiceProcessFilterListResourceFree();
        return(0);
    }
    else if(!strcmp(method,"PUT"))
    {
        cmeProcessURLMatchSaveParameters(method,argumentElements,validGETALLMatchColumns,validPUTSaveColumns,
                                         numValidGETALLMatch,numValidPUTSave,columnValuesToMatch,columnNamesToMatch,
                                         columnValues,columnNames,&numMatchArgs,&numSaveArgs,&userId,&orgId,&orgKey,
                                         &newOrgKey,&usrArg,&orgArg,&keyArg,&newKeyArg);
        if ((numSaveArgs<1)||(!keyArg)||(!usrArg)||(!orgArg))
        {
            *responseCode=409;
            cmeWebServiceProcessFilterListResourceFree();
            return(6);
        }
        result=cmeDBOpen(dbFilePath,&pDB);
        if (!result)
        {
            result=cmePutProtectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                            numMatchArgs,(const char **)columnNames,(const char **)columnValues,
                                            numSaveArgs,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
        }
        if (result)
        {
            *responseCode=500;
            cmeWebServiceProcessFilterListResourceFree();
            return(7);
        }
        *responseCode=numResultRegisters?200:404;
        cmeConstructWebServiceCountResponse("Updated registers",numResultRegisters,argumentElements,method,url,
                                            responseHeaders,responseText,responseCode);
        cmeWebServiceProcessFilterListResourceFree();
        return(0);
    }
    else if((!strcmp(method,"GET"))||(!strcmp(method,"HEAD"))||(!strcmp(method,"OPTIONS"))||(!strcmp(method,"DELETE")))
    {
        if(!strcmp(method,"OPTIONS"))
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for %s resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",filterLabel,resourceOptions,cmeInternalDBDefinitionsVersion);
            *responseCode=200;
            cmeWebServiceProcessFilterListResourceFree();
            return(0);
        }
        cmeProcessURLMatchSaveParameters(method,argumentElements,validGETALLMatchColumns,NULL,
                                         numValidGETALLMatch,0,columnValuesToMatch,columnNamesToMatch,
                                         columnValues,columnNames,&numMatchArgs,&numSaveArgs,&userId,&orgId,&orgKey,
                                         &newOrgKey,&usrArg,&orgArg,&keyArg,&newKeyArg);
        if ((!keyArg)||(!usrArg)||(!orgArg))
        {
            *responseCode=409;
            cmeWebServiceProcessFilterListResourceFree();
            return(8);
        }
        result=cmeDBOpen(dbFilePath,&pDB);
        if (!result)
        {
            if(!strcmp(method,"DELETE"))
            {
                result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
            }
            else
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
            }
        }
        if (result)
        {
            *responseCode=500;
            cmeWebServiceProcessFilterListResourceFree();
            return(9);
        }
        if(!strcmp(method,"HEAD"))
        {
            *responseCode=numResultRegisters?200:404;
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
        }
        else if(!strcmp(method,"DELETE"))
        {
            *responseCode=numResultRegisters?200:404;
            cmeConstructWebServiceCountResponse("Deleted registers",numResultRegisters,argumentElements,method,url,
                                                responseHeaders,responseText,responseCode);
        }
        else
        {
            result=cmeConstructWebServiceTableResponse((const char **)resultRegisterCols,numResultRegisterCols,numResultRegisters,
                                                       argumentElements,method,url,NULL,responseHeaders,responseText,responseCode);
        }
        cmeWebServiceProcessFilterListResourceFree();
        return(result);
    }
    cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br>"
                       "METHOD: '%s' URL: '%s'.%sLatest IDD version: <code>%s</code>",
                       method,url,resourceOptions,cmeInternalDBDefinitionsVersion);
    *responseCode=405;
    cmeWebServiceProcessFilterListResourceFree();
    return(10);
}

int cmeWebServiceProcessFilterWhitelistClass (char **responseText, char ***responseHeaders, int *responseCode,
                                         const char *url, const char **urlElements, const char **argumentElements, const char *method)
{
    return cmeWebServiceProcessFilterListClass(responseText,responseHeaders,responseCode,url,urlElements,argumentElements,method,
                                               "filterWhitelist","filterWhitelist",cmeWSMsgFilterWhitelistClassOptions,
                                               cmeWSMsgFilterWhitelistOptions);
}

int cmeWebServiceProcessFilterWhitelistResource (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                           const char *url, const char **urlElements, const char **argumentElements, const char *method)
{
    return cmeWebServiceProcessFilterListResource(responseText,responseFilePath,responseHeaders,responseCode,url,urlElements,
                                                  argumentElements,method,"filterWhitelist","filterWhitelist",
                                                  cmeWSMsgFilterWhitelistOptions);
}

int cmeWebServiceProcessFilterBlacklistClass (char **responseText, char ***responseHeaders, int *responseCode,
                                         const char *url, const char **urlElements, const char **argumentElements, const char *method)
{
    return cmeWebServiceProcessFilterListClass(responseText,responseHeaders,responseCode,url,urlElements,argumentElements,method,
                                               "filterBlacklist","filterBlacklist",cmeWSMsgFilterBlacklistClassOptions,
                                               cmeWSMsgFilterBlacklistOptions);
}

int cmeWebServiceProcessFilterBlacklistResource (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                           const char *url, const char **urlElements, const char **argumentElements, const char *method)
{
    return cmeWebServiceProcessFilterListResource(responseText,responseFilePath,responseHeaders,responseCode,url,urlElements,
                                                  argumentElements,method,"filterBlacklist","filterBlacklist",
                                                  cmeWSMsgFilterBlacklistOptions);
}

int cmeWebServiceProcessRoleTableResource (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                           const char *url, const char **urlElements, const char **argumentElements, const char *method)
{   //IDD ver. 1.0.20  definitions.
    int cont,result;
    int keyArg=0;
    int orgArg=0;
    int usrArg=0;
    int newKeyArg=0;
    int numSaveArgs=0;
    int numMatchArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL;                  //requester orgKey.
    char *userId=NULL;                  //requester userId.
    char *orgId=NULL;                   //requester orgId.
    char *newOrgKey=NULL;               //requester newOrgKey (optional).
    char *salt=NULL;
    char **columnValues=NULL;           //Values to be created/updated (POST/PUT)
    char **columnNames=NULL;            //Names of columns of values to be created/updated (POST/PUT)
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    char *tableName=NULL;
    const int numDuplicateMatchColumns=2;   //Columns by which we detect duplicates, in this case: "orgResourceId","userResourceId"; must be the first to be added to columnValuesToMatch and columnNamesToMatch
    const int numColumns=cmeIDDRolesDBAnyTableNumCols;
    const int numValidGETALLMatch=8;    //8 parameters + 2 from URL (userResourceId and orgResourceId)
    const int numValidPOSTSave=8;       //8 parameters + 2 from URL (userResourceId and orgResourceId)
    const int numValidPUTSave=8;
    const int numTableNames=20;         //# of tables in RolesDB.
    const char *validGETALLMatchColumns[8]={"_userId","_orgId","__get","__post","__put","__delete","__head","__options"};
    const char *validPOSTSaveColumns[8]={"userId","orgId","*_get","*_post","*_put","*_delete","*_head","*_options"};
    const char *validPUTSaveColumns[8]={"userId","orgId","*_get","*_post","*_put","*_delete","*_head","*_options"};
    const char *tableNames[20]={"documents","users","roleTables","parserScripts","outputDocuments","content",
                                "contentRows","contentColumns","dbNames","dbTables","tableRows","tableColumns",
                                "organizations","storage","documentTypes","engineCommands","transactions","meta",
                                "filterWhitelist","filterBlacklist"}; //Note: also    const char *tableNames[]=...
    #define cmeWebServiceProcessRoleTableResourceFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey) \
            cmeFree(dbFilePath); \
            cmeFree(salt); \
            cmeFree(tableName); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    // *responseText=NULL;
    // *responseFilePath=NULL;

    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store role resource information, columns 1 to 12 (POST/PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns); //Set space to store role resource information, columns 1 to 12 (POST/PUT).
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store role resource information, column values to match (GET/PUT).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultRolesDBName);
    if(!strcmp(method,"POST")) //Method = POST is ok, process:
    {
        cmeStrConstrAppend(&(columnValues[0]),"%s",urlElements[1]); //We also ignore the argument "orgId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);
        cmeStrConstrAppend(&(columnNames[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValues[1]),"%s",urlElements[3]); //We ignore the argument "userResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[1]),urlElements[3]);
        cmeStrConstrAppend(&(columnNames[1]),"userResourceId");
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"userResourceId");
        cmeStrConstrAppend(&tableName,"%s",urlElements[5]); //We also get the tableName from the URL!
        result=1;
        for (cont=0;cont<numTableNames;cont++) //Check if tableName is valid.
        {
            if (!strcmp(tableNames[cont],tableName)) //If valid tableName found, set result to 0 and end loop.
            {
                result=0;
                break;
            }
        }
        if (result) //Error, no valid tablename!
        {
                cmeStrConstrAppend(responseText,"<b>404 ERROR resource not found!</b><br>"
                                   "Role table doesn't exist! "
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, roleTable: '%s' not found!."
                        " Method: '%s', URL: '%s'!\n",tableName,method,url);
#endif
                cmeWebServiceProcessRoleTableResourceFree();
                *responseCode=404;
                return(1);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), POST, column userResourceId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), POST, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), POST, parameter roleTable: '%s'.\n",
                tableName);
#endif
        numMatchArgs=2;
        numSaveArgs=2;

        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPOSTSaveColumns, numValidGETALLMatch, numValidPOSTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(numSaveArgs==10)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=2 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                if(newOrgKey) //Check resource using newOrgKey
                {
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                      numDuplicateMatchColumns,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,newOrgKey); //Check if resource doesn't exist.
                }
                else //Check resource using orgKey
                {
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                      numDuplicateMatchColumns,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey); //Check if resource doesn't exist.
                }
                if(numResultRegisters>0) //Role is already in DB -> Error
                {
                    cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                                       "RoleTable resource already exists! "
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, forbidden request, role already exists!"
                            " Method: '%s', URL: '%s'!\n",method,url);
#endif
                    cmeWebServiceProcessRoleTableResourceFree();
                    *responseCode=403;
                    return(8);
                }
                if(newOrgKey) //Create resource using newOrgKey
                {
                    result=cmePostProtectDBRegister(pDB,tableName,(const char **)columnNames,(const char **)columnValues,
                                                    numSaveArgs,newOrgKey);
                }
                else //Create resource using orgKey
                {
                    result=cmePostProtectDBRegister(pDB,tableName,(const char **)columnNames,(const char **)columnValues,
                                                    numSaveArgs,orgKey);
                }
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    cmeWebServiceProcessRoleTableResourceFree();
                    *responseCode=500;
                    return(9);
                }
                else //Ok
                {
                    cmeStrConstrAppend(responseText,"Method '%s', user '%s' created successfully roleTable resource for user '%s' "
                                       "in tableName: '%s'.<br>",method, urlElements[1], urlElements[3],tableName);
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), POST successful.\n");
#endif
                    *responseFilePath=NULL;

                    *responseCode=201;
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                    cmeWebServiceProcessRoleTableResourceFree();
                    return(0);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessRoleTableResourceFree();
                *responseCode=500;
                return(10);
            }
        }
        else //Error, invalid number of arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessRoleTableResourceFree();
            *responseCode=409;
            return(11);
        }
    }
    else if(!strcmp(method,"PUT")) //Method = PUT is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),urlElements[3]); //We ignore the argument "userResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"userResourceId");
        cmeStrConstrAppend(&tableName,"%s",urlElements[5]); //We also get the tableName from the URL!
        result=1;
        for (cont=0;cont<numTableNames;cont++) //Check if tableName is valid.
        {
            if (!strcmp(tableNames[cont],tableName)) //If valid tableName found, set result to 0 and end loop.
            {
                result=0;
                break;
            }
        }
        if (result) //Error, no valid tableName!
        {
                cmeStrConstrAppend(responseText,"<b>404 ERROR resource not found!</b><br>"
                                   "Role table doesn't exist! "
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, roleTable: '%s' not found!."
                        " Method: '%s', URL: '%s'!\n",tableName,method,url);
#endif
                cmeWebServiceProcessRoleTableResourceFree();
                *responseCode=404;
                return(12);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), PUT, column userResourceId: '%s'.\n",
                urlElements[3]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), PUT, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), PUT, parameter roleTable: '%s'.\n",
                tableName);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPUTSaveColumns, numValidGETALLMatch, numValidPUTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(numSaveArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=2 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (result) //Error, internal server error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    *responseCode=500;
                    cmeWebServiceProcessRoleTableResourceFree();
                    return(19);
                }
                else //Ok
                {
                    if (numResultRegisters>0) //Resource found
                    {
                        if (resultRegisterCols) //Free resultRegisterCols data obtained by cmeGetUnprotectDBRegisters() call above to check if results were available.
                        {
                            for (cont=0; cont<numResultRegisterCols;cont++)
                            {
                               cmeFree(resultRegisterCols[cont]);
                            }
                            cmeFree(resultRegisterCols);
                        }
                        numResultRegisterCols=0;
                        numResultRegisters=0;
                        result=cmePutProtectDBRegisters (pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,numMatchArgs,
                                                         (const char **)columnNames,(const char **)columnValues,numSaveArgs,&resultRegisterCols,
                                                         &numResultRegisterCols,&numResultRegisters,orgKey);
                        if (result) //Error updating - 500
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                                cmeInternalDBDefinitionsVersion);
    #ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s'!\n",result,method,url);
    #endif
                            *responseCode=500;
                            cmeWebServiceProcessRoleTableResourceFree();
                            return(20);
                        }
                        else //Ok
                        {
                            if (numResultRegisters>0) //Resource updated
                            {
                                *responseCode=200;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), PUT successful.\n");
#endif
                            }
                            else //Resource not found!
                            {
                                *responseCode=404;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), PUT successful but"
                                        " resource not found.\n");
#endif
                            }
                        }
                    }
                    else //Resource not found!
                    {
                        *responseCode=404;
                    }
                }
                cmeStrConstrAppend(responseText,"Method '%s', updated resources: %d .<br>",
                                   method, numResultRegisters);
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                cmeWebServiceProcessRoleTableResourceFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessRoleTableResourceFree();
                *responseCode=500;
                return(21);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessRoleTableResourceFree();
            *responseCode=409;
            return(22);
        }
    }
    else if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]); //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),urlElements[3]); //We ignore the argument "userResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"userResourceId");
        cmeStrConstrAppend(&tableName,"%s",urlElements[5]); //We also get the tableName from the URL!
        result=1;
        for (cont=0;cont<numTableNames;cont++) //Check if tableName is valid.
        {
            if (!strcmp(tableNames[cont],tableName)) //If valid tableName found, set result to 0 and end loop.
            {
                result=0;
                break;
            }
        }
        if (result) //Error, no valid tableName!
        {
                cmeStrConstrAppend(responseText,"<b>404 ERROR resource not found!</b><br>"
                                   "Role table doesn't exist! "
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, roleTable: '%s' not found!."
                        " Method: '%s', URL: '%s'!\n",tableName,method,url);
#endif
                cmeWebServiceProcessRoleTableResourceFree();
                *responseCode=404;
                return(23);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), GET, column userResourceId: '%s'.\n",
                urlElements[3]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), GET, parameter roleTable: '%s'.\n",
                tableName);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=2 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    //Construct responseText and create response headers according to the user's outputType (optional) request:
                    result=cmeConstructWebServiceTableResponse ((const char **)resultRegisterCols,numResultRegisterCols,numResultRegisters,
                                                                argumentElements, url, method, tableName,
                                                                responseHeaders, responseText, responseCode);
                    cmeWebServiceProcessRoleTableResourceFree();
                    return(0);
                }
                else //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessRoleTableResourceFree();
                    *responseCode=500;
                    return(24);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessRoleTableResourceFree();
                *responseCode=500;
                return(25);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessRoleTableResourceFree();
            *responseCode=409;
            return(26);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[3]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
                                                                            //First match filter with index 0.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"userResourceId"); //We will match against this value for the search.
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"orgResourceId"); //We will also match against this value for the search.
        cmeStrConstrAppend(&tableName,"%s",urlElements[5]); //We also get the tableName from the URL!
        result=1;
        for (cont=0;cont<numTableNames;cont++) //Check if tableName is valid.
        {
            if (!strcmp(tableNames[cont],tableName)) //If valid tableName found, set result to 0 and end loop.
            {
                result=0;
                break;
            }
        }
        if (result) //Error, no valid tableName!
        {
                cmeStrConstrAppend(responseText,"<b>404 ERROR resource not found!</b><br>"
                                   "Role table doesn't exist! "
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, roleTable: '%s' not found!."
                        " Method: '%s', URL: '%s'!\n",tableName,method,url);
#endif
                cmeWebServiceProcessRoleTableResourceFree();
                *responseCode=404;
                return(27);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), HEAD, parameter roleTable: '%s'.\n",
                tableName);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), HEAD, column userResourceId: '%s'.\n",
                urlElements[3]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), HEAD, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=2 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) //Found >0 results
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), HEAD successful.\n");
#endif
                    }
                    else //Found 0 results
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), HEAD, successful but"
                                "no record found.\n");
#endif
                    }
                    //cmeStrConstrAppend(responseText,"<p>Matched results: %d</p><br>",numResultRegisters);  //HEAD doesn't return a body.
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                    cmeWebServiceProcessRoleTableResourceFree();
                    return(0);
                }
                else //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                        "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'; cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessRoleTableResourceFree();
                    *responseCode=500;
                    return(28);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'; can't open DBFile: %s!\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessRoleTableResourceFree();
                *responseCode=500;
                return(29);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessRoleTableResourceFree();
            *responseCode=409;
            return(30);
        }
    }
    else if(!strcmp(method,"DELETE")) //Method = DELETE is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[3]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
                                                                            //First match filter with index 0.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"userResourceId"); //We will match against this value for the search.
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"orgResourceId"); //We will also match against this value for the search.
        cmeStrConstrAppend(&tableName,"%s",urlElements[5]); //We also get the tableName from the URL!
        result=1;
        for (cont=0;cont<numTableNames;cont++) //Check if tableName is valid.
        {
            if (!strcmp(tableNames[cont],tableName)) //If valid tableName found, set result to 0 and end loop.
            {
                result=0;
                break;
            }
        }
        if (result) //Error, no valid tableName!
        {
                cmeStrConstrAppend(responseText,"<b>404 ERROR resource not found!</b><br>"
                                   "Role table doesn't exist! "
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, roleTable: '%s' not found!."
                        " Method: '%s', URL: '%s'!\n",tableName,method,url);
#endif
                cmeWebServiceProcessRoleTableResourceFree();
                *responseCode=404;
                return(31);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), DELETE, parameter roleTable: '%s'.\n",
                tableName);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), DELETE, column userResourceId: '%s'.\n",
                urlElements[3]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), DELETE, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=2 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                     &numResultRegisters,orgKey);
                if (!result) //Delete OK
                {
                    if (numResultRegisters) // Deleted 1 register
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), DELETE successful.\n");
#endif
                    }
                    else // Deleted 0 registers
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), DELETE successful.\n");
#endif
                    }
                    cmeConstructWebServiceCountResponse("Deleted registers",numResultRegisters,
                                                        argumentElements,method,url,
                                                        responseHeaders,responseText,responseCode);
                    cmeWebServiceProcessRoleTableResourceFree();
                    return(0);
                }
                else //Delete Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), DELETE error!, "
                            "cmeDeleteUnporotectDBRegisters error!\n");
#endif
                    cmeWebServiceProcessRoleTableResourceFree();
                    *responseCode=500;
                    return(32);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                   "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgRoleTableOptions,
                                   cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open DB file: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessRoleTableResourceFree();
                *responseCode=500;
                return(33);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessRoleTableResourceFree();
            *responseCode=409;
            return(34);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[3]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
                                                                            //First match filter with index 0.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"userResourceId"); //We will match against this value for the search.
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"orgResourceId"); //We will also match against this value for the search.
        cmeStrConstrAppend(&tableName,"%s",urlElements[5]); //We also get the tableName from the URL!
        result=1;
        for (cont=0;cont<numTableNames;cont++) //Check if tableName is valid.
        {
            if (!strcmp(tableNames[cont],tableName)) //If valid tableName found, set result to 0 and end loop.
            {
                result=0;
                break;
            }
        }
        if (result) //Error, no valid tableName!
        {
                cmeStrConstrAppend(responseText,"<b>404 ERROR resource not found!</b><br>"
                                   "Role table doesn't exist! "
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, roleTable: '%s' not found!."
                        " Method: '%s', URL: '%s'!\n",tableName,method,url);
#endif
                cmeWebServiceProcessRoleTableResourceFree();
                *responseCode=404;
                return(35);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), OPTIONS, parameter roleTable: '%s'.\n",
                tableName);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), OPTIONS, column userResourceId: '%s'.\n",
                urlElements[3]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=2 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for role table resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgRoleTableOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessRoleTableResource(), OPTIONS successful for user resource."
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessRoleTableResourceFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessRoleTableResourceFree();
            *responseCode=409;
            return(36);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgRoleTableOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRoleTableResource(), Error, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessRoleTableResourceFree();
        *responseCode=405;
        return(37);
    }
}

int cmeWebServiceProcessOrgResource (char **responseText, char ***responseHeaders, int *responseCode,
                                     const char *url, const char **urlElements, const char **argumentElements, const char *method)
{   //IDD ver. 1.0.20 definitions.
    int cont,result;
    int keyArg=0;
    int orgArg=0;
    int usrArg=0;
    int newKeyArg=0;
    int numSaveArgs=0;
    int numMatchArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL;                  //requester orgKey.
    char *userId=NULL;                  //requester userId.
    char *orgId=NULL;                   //requester orgId.
    char *newOrgKey=NULL;               //requester newOrgKey (optional).
    char *salt=NULL;
    char **columnValues=NULL;           //Values to be created/updated (POST/PUT)
    char **columnNames=NULL;            //Names of columns of values to be created/updated (POST/PUT)
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    char *tableName="organizations";
    const int numDuplicateMatchColumns=1;   //Columns by which we detect duplicates, in this case: "orgResourceId"; must be the first to be added to columnValuesToMatch and columnNamesToMatch
    const int numColumns=8;             //Number of columns in corresponding resource table.
    const int numValidGETALLMatch=5;    //5 parameters + 1 from URL (orgResourceId)
    const int numValidPOSTSave=5;       //5 parameters + 1 from URL (orgResourceId)
    const int numValidPUTSave=5;
    const char *validGETALLMatchColumns[5]={"_userId","_orgId","_resourceInfo","_certificate","_publicKey"};
    const char *validPOSTSaveColumns[5]={"userId","orgId","*resourceInfo","*certificate","*publicKey"};
    const char *validPUTSaveColumns[5]={"userId","orgId","*resourceInfo","*certificate","*publicKey"};
    #define cmeWebServiceProcessOrgResourceFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            cmeFree(salt); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    // *responseText=NULL;
    // *responseFilePath=NULL;

    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 8 (POST/PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 8 (POST/PUT).
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, column values to match (GET/PUT).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    if(!strcmp(method,"POST")) //Method = POST is ok, process:
    {
        cmeStrConstrAppend(&(columnValues[0]),"%s",urlElements[1]); //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);
        cmeStrConstrAppend(&(columnNames[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), POST, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        numSaveArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPOSTSaveColumns, numValidGETALLMatch,numValidPOSTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(numSaveArgs==6)&&(keyArg)&&(usrArg)&&(orgArg)) //Command POST successful.
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                if(newOrgKey) //Check resource using newOrgKey
                {
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                      numDuplicateMatchColumns,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,newOrgKey); //Check if resource doesn't exist.
                }
                else //Check resource using orgKey
                {
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                      numDuplicateMatchColumns,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey); //Check if resource doesn't exist.
                }
                if(numResultRegisters>0) //Organization is already in DB -> Error
                {
                    cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                                       "Organization resource already exists! "
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, forbidden request, organization already exists!"
                            " Method: '%s', URL: '%s'!\n",method,url);
#endif
                    cmeWebServiceProcessOrgResourceFree();
                    *responseCode=403;
                    return(1);
                }
                if(newOrgKey) //Create resource using newOrgKey
                {
                    result=cmePostProtectDBRegister(pDB,tableName,(const char **)columnNames,(const char **)columnValues,
                                                    numSaveArgs,newOrgKey);
                }
                else //Create resource using orgKey
                {
                    result=cmePostProtectDBRegister(pDB,tableName,(const char **)columnNames,(const char **)columnValues,
                                                    numSaveArgs,orgKey);
                }
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    cmeWebServiceProcessOrgResourceFree();
                    *responseCode=500;
                    return(2);
                }
                else //Ok
                {
                    cmeStrConstrAppend(responseText,"Method '%s', user '%s' created successfully organization resource '%s' "
                                       "in tableName: '%s'.<br>",method, userId, urlElements[1],tableName);
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), POST successful.\n");
#endif
                    *responseCode=201;
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                    cmeWebServiceProcessOrgResourceFree();
                    return(0);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessOrgResourceFree();
                *responseCode=500;
                return(3);
            }
        }
        else //Error, invalid number of arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, incorrect number of "
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessOrgResourceFree();
            *responseCode=409;
            return(4);
        }
    }
    else if(!strcmp(method,"PUT")) //Method = PUT is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]); //We ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), PUT, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPUTSaveColumns, numValidGETALLMatch, numValidPUTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(numSaveArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg))
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
                if (result) //Error, internal server error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    *responseCode=500;
                    cmeWebServiceProcessOrgResourceFree();
                    return(5);
                }
                else //Ok
                {
                    if (numResultRegisters>0) //Resource found
                    {
                        if (resultRegisterCols) //Free resultRegisterCols data obtained by cmeGetUnprotectDBRegisters() call above to check if results were available.
                        {
                            for (cont=0; cont<numResultRegisterCols;cont++)
                            {
                               cmeFree(resultRegisterCols[cont]);
                            }
                            cmeFree(resultRegisterCols);
                        }
                        numResultRegisterCols=0;
                        numResultRegisters=0;
                        result=cmePutProtectDBRegisters (pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,numMatchArgs,
                                                         (const char **)columnNames,(const char **)columnValues,numSaveArgs,&resultRegisterCols,
                                                         &numResultRegisterCols,&numResultRegisters,orgKey);
                        if (result) //Error updating - 500
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgOptions,
                                                cmeInternalDBDefinitionsVersion);
    #ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s'!\n",result,method,url);
    #endif
                            *responseCode=500;
                            cmeWebServiceProcessOrgResourceFree();
                            return(6);
                        }
                        else //Ok
                        {
                            if (numResultRegisters>0) //Resource updated
                            {
                                *responseCode=200;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), PUT successful.\n");
#endif
                            }
                            else //Resource not found!
                            {
                                *responseCode=404;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), PUT successful but"
                                        " resource not found.\n");
#endif
                            }
                        }
                    }
                    else //Resource not found!
                    {
                        *responseCode=404;
                    }
                }
                cmeStrConstrAppend(responseText,"Method '%s', updated resources: %d .<br>",
                                   method, numResultRegisters);
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                cmeWebServiceProcessOrgResourceFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessOrgResourceFree();
                *responseCode=500;
                return(7);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, incorrect number of "
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessOrgResourceFree();
            *responseCode=409;
            return(8);
        }
    }
    else if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]); //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    //Construct responseText and create response headers according to the user's outputType (optional) request:
                    result=cmeConstructWebServiceTableResponse ((const char **)resultRegisterCols,numResultRegisterCols,numResultRegisters,
                                                                argumentElements, url, method, urlElements[1],
                                                                responseHeaders, responseText, responseCode);
                    cmeWebServiceProcessOrgResourceFree();
                    return(0);
                }
                else //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessOrgResourceFree();
                    *responseCode=500;
                    return(9);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessOrgResourceFree();
                *responseCode=500;
                return(10);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessOrgResourceFree();
            *responseCode=409;
            return(11);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 0.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), HEAD, column orgResourceId : '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL , numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) //Found >0 results
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), HEAD successful.\n");
#endif
                    }
                    else //Found 0 results
                    {
                        *responseCode=404;
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), HEAD, successful but"
                        "no record found.\n");
#endif
                    }
                    //cmeStrConstrAppend(responseText,"<p>Matched results: %d</p><br>",numResultRegisters);  //HEAD doesn't return a body.
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                    cmeWebServiceProcessOrgResourceFree();
                    return(0);
                }
                else //Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                        "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'; cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessOrgResourceFree();
                    return(12);
                }
            }
            else //Server ERROR
            {
                *responseCode=500;
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'; can't open DBFile: %s!\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessOrgResourceFree();
                return(13);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessOrgResourceFree();
            *responseCode=409;
            return(14);
        }
    }
    else if(!strcmp(method,"DELETE")) //Method = DELETE is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
                                                                            //First match filter with index 0.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), DELETE, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                     &numResultRegisters,orgKey);
                if (!result) //Delete OK
                {
                    if (numResultRegisters) // Deleted 1 register
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), DELETE successful.\n");
#endif
                    }
                    else // Deleted 0 registers
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), DELETE successful.\n");
#endif
                    }
                    cmeConstructWebServiceCountResponse("Deleted registers",numResultRegisters,
                                                        argumentElements,method,url,
                                                        responseHeaders,responseText,responseCode);
                    cmeWebServiceProcessOrgResourceFree();
                    return(0);
                }
                else //Delete Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), DELETE error!, "
                            "cmeDeleteUnporotectDBRegisters error!\n");
#endif
                    cmeWebServiceProcessOrgResourceFree();
                    return(15);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                   "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgOptions,
                                   cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open DB file: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessOrgResourceFree();
                *responseCode=500;
                return(16);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessOrgResourceFree();
            *responseCode=409;
            return(17);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
                                                                            //First match filter with index 0.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=1 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for organization resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgOrgOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessOrgResource(), OPTIONS successful for orgResource resource."
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessOrgResourceFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessOrgResourceFree();
            *responseCode=409;
            return(18);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgResource(), Error, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessOrgResourceFree();
        *responseCode=405;
        return(19);
    }
}

int cmeWebServiceProcessOrgClass (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                   const char *url,const char **argumentElements, const char *method)
{   //IDD v.1.0.20 definitions.
    int cont,result;
    int orgArg=0;
    int usrArg=0;
    int keyArg=0;
    int newKeyArg=0;
    int numMatchArgs=0;
    int numSaveArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL;
    char *userId=NULL;
    char *orgId=NULL;
    char *newOrgKey=NULL;
    char *dbFilePath=NULL;
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET)
    char **columnValues=NULL;
    char **resultRegisterCols=NULL;
    char **columnNamesToMatch=NULL;
    char **columnNames=NULL;
    const int numColumns=8;            //Constant: number of cols. in organizations table
    const int numValidGETALLMatch=6;
    const int numValidPUTSave=5;
    const char *tableName="organizations";
    const char *validGETALLMatchColumns[6]={"_userId","_orgId","_resourceInfo","_certificate","_publicKey","_orgResourceId"};
    const char *validPUTSaveColumns[5]={"userId","orgId","*resourceInfo","*certificate","*publicKey"};
    #define cmeWebServiceProcessOrgClassFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(orgId); \
            cmeFree(userId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    *responseText=NULL;
    *responseFilePath=NULL;

    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store user resource information, column values to match (GET).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns);  //Set space to store column names to match (GET).
    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store user resource information, column values to match (PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns);  //Set space to store column names to match (PUT).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName); //Set DB full path.
    if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch,0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(usrArg)&&(keyArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, userId and orgId + 1 or > match arguments)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {   //Note that if numMatchArgs==0 (i.e. columnNamesToMatch and columnValuesToMatch are NULL) then all results are returned.
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);

                //Construct responseText and create response headers according to the user's outputType (optional) request:
                result=cmeConstructWebServiceTableResponse ((const char **)resultRegisterCols,numResultRegisterCols,numResultRegisters,
                                                            argumentElements, url, method, "organizations",
                                                            responseHeaders, responseText, responseCode);
                cmeWebServiceProcessOrgClassFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                    "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessOrgClassFree();
                *responseCode=500;
                return(1);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Conflicting number of arguments."
                               "</b><br><br>The provided number of arguments is incorrect. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgClassOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, conflicting number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessOrgClassFree();
            *responseCode=409;
            return(2);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        cont=0;
        while ((cont<cmeWSURIMaxArguments)&&(argumentElements[cont])&&((!keyArg)||(!usrArg)||(!orgArg))) //Check for other required parameters not passed via URL (userId,orgId and orgKey).
        {
            if (!strcmp(argumentElements[cont],"orgId")) //parameter orgId found!.
            {
                cmeStrConstrAppend(&orgId,"%s",argumentElements[cont+1]); //special case; we pass it as a function parameter; not in columnValues.
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgClass(), OPTIONS, column orgId: '%s'.\n",
                        argumentElements[cont+1]);
#endif
                orgArg=1;
            }
            else if (!strcmp(argumentElements[cont],"userId")) //parameter userId found!.
            {
                cmeStrConstrAppend(&userId,"%s",argumentElements[cont+1]); //special case; we pass it as a function parameter; not in columnValues.
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgClass(), OPTIONS, column userId: '%s'.\n",
                        argumentElements[cont+1]);
#endif
                usrArg=1;
            }
            else if (!strcmp(argumentElements[cont],"orgKey")) //parameter column-resourceInfo found!.
            {
                cmeStrConstrAppend(&orgKey,"%s",argumentElements[cont+1]); //special case; we pass it as a function parameter; not in columnValues.
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgClass(), OPTIONS, parameter orgKey: '%s'.\n",
                        argumentElements[cont+1]);
#endif
                keyArg=1;
            }
            cont+=2;
        }
        //  No optional arguments for OPTIONS!
        if ((keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId and userResourceId)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for organization class resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgOrgClassOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessOrgClass(), OPTIONS successful for orgClass resource."
                    "Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessOrgClassFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgClassOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessOrgClassFree();
            *responseCode=409;
            return(3);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch,0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg); //Uses same parameters as GET.
        if ((numMatchArgs>=1)&&(usrArg)&&(keyArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, userId and orgId + 1 match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) //Found >0 results
                    {
                        *responseCode=200;
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgClass(), HEAD successful.\n");
#endif
                    }
                    else //Found 0 results
                    {
                        *responseCode=404;
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgClass(), HEAD, successful but"
                        "no record found!\n");
#endif
                    }
                    //cmeStrConstrAppend(responseText,"<p>Matched results: %d</p><br>",numResultRegisters);   //HEAD doesn't return a body.
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                    cmeWebServiceProcessOrgClassFree();
                    return(0);
                }
                else //Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                        "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgClassOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'; cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessOrgClassFree();
                    return(12);
                }
            }
            else //Server ERROR
            {
                *responseCode=500;
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'; can't open DBFile: %s!\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessOrgClassFree();
                return(13);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgClassOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessOrgClassFree();
            *responseCode=409;
            return(14);
        }
    }
    else if(!strcmp(method,"DELETE")) //Method = DELETE is ok, process:
    {
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch,0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg); //Uses same as GET.
        if ((numMatchArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId and and userId + >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                     &numResultRegisters,orgKey);
                if (!result) //Delete OK
                {
                    if (numResultRegisters) // Deleted >=1 registers
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgClass(), DELETE successful.\n");
#endif
                    }
                    else // Deleted 0 registers
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgClass(), DELETE successful.\n");
#endif
                    }
                    cmeConstructWebServiceCountResponse("Deleted registers",numResultRegisters,
                                                        argumentElements,method,url,
                                                        responseHeaders,responseText,responseCode);
                    cmeWebServiceProcessOrgClassFree();
                    return(0);
                }
                else //Delete Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgClassOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessOrgClass(), DELETE error!, "
                            "cmeDeleteUnporotectDBRegisters error!\n");
#endif
                    cmeWebServiceProcessOrgClassFree();
                    return(15);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                   "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgClassOptions,
                                   cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open DB file: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessOrgClassFree();
                *responseCode=500;
                return(16);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgClassOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessOrgClassFree();
            *responseCode=409;
            return(17);
        }
    }
    else if(!strcmp(method,"PUT")) //Method = PUT is ok, process:
    {
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPUTSaveColumns, numValidGETALLMatch,numValidPUTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(numSaveArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //orgKey + userId + orgId + >=1 Match + >=1 Save.
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (result) //Error, internal server error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgClassOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    *responseCode=500;
                    cmeWebServiceProcessOrgClassFree();
                    return(18);
                }
                else //Ok
                {
                    if (numResultRegisters>0) //Resource found
                    {
                        if (resultRegisterCols) //Free resultRegisterCols data obtained by cmeGetUnprotectDBRegisters() call above to check if results were available.
                        {
                            for (cont=0; cont<numResultRegisterCols;cont++)
                            {
                               cmeFree(resultRegisterCols[cont]);
                            }
                            cmeFree(resultRegisterCols);
                        }
                        numResultRegisterCols=0;
                        numResultRegisters=0;
                        result=cmePutProtectDBRegisters (pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,numMatchArgs,
                                                         (const char **)columnNames,(const char **)columnValues,numSaveArgs,&resultRegisterCols,
                                                         &numResultRegisterCols,&numResultRegisters,orgKey);
                        if (result) //Error updating - 500
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgClassOptions,
                                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                            *responseCode=500;
                            cmeWebServiceProcessOrgClassFree();
                            return(19);
                        }
                        else //Ok
                        {
                            if (numResultRegisters>0) //Resource updated
                            {
                                *responseCode=200;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgClass(), PUT successful.\n");
#endif
                            }
                            else //Resource not found!
                            {
                                *responseCode=404;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessOrgClass(), PUT successful but"
                                        " resource not found.\n");
#endif
                            }
                        }
                    }
                    else //Resource not found!
                    {
                        *responseCode=404;
                    }
                }
                cmeStrConstrAppend(responseText,"Method '%s', updated resources: %d .<br>",
                                   method, numResultRegisters);
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                cmeWebServiceProcessOrgClassFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgOrgClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessOrgClassFree();
                *responseCode=500;
                return(20);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgClassOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessOrgClassFree();
            *responseCode=409;
            return(21);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method is not allowed for this resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgOrgClassOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessOrgClass(), Error, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessOrgClassFree();
        *responseCode=405;
        return(22);
    }
}


int cmeWebServiceProcessStorageResource (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                     const char *url, const char **urlElements, const char **argumentElements, const char *method)
{   //IDD ver. 1.0.20 definitions.
    int cont,result;
    int keyArg=0;
    int orgArg=0;
    int usrArg=0;
    int newKeyArg=0;
    int numSaveArgs=0;
    int numMatchArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL;                  //requester orgKey.
    char *userId=NULL;                  //requester userId.
    char *orgId=NULL;                   //requester orgId.
    char *newOrgKey=NULL;               //requester newOrgKey (optional).
    char *salt=NULL;
    char **columnValues=NULL;           //Values to be created/updated (POST/PUT)
    char **columnNames=NULL;            //Names of columns of values to be created/updated (POST/PUT)
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    const int numColumns=12;            //Number of columns in corresponding resource table.
    const int numDuplicateMatchColumns=2;   //Columns by which we detect duplicates, in this case: "orgResourceId","storageId"; must be the first to be added to columnValuesToMatch and columnNamesToMatch
    const int numValidGETALLMatch=8;    //8 parameters + 2 (storageId,orgResourceId) from URL
    const int numValidPOSTSave=8;       //8 parameters + 2 (storageId,orgResourceId) from URL
    const int numValidPUTSave=8;
    const char *tableName="storage";
    const char *validGETALLMatchColumns[8]={"_userId","_orgId","_resourceInfo","_location","_type",
                                            "_accessPath","_accessUser","_accessPassword"};
    const char *validPOSTSaveColumns[8]={"userId","orgId","*resourceInfo","*location","*type",
                                         "*accessPath","*accessUser","*accessPassword"};
    const char *validPUTSaveColumns[8]={"userId","orgId","*resourceInfo","*location","*type",
                                         "*accessPath","*accessUser","*accessPassword"};
    #define cmeWebServiceProcessStorageResourceFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            cmeFree(salt); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

   // *responseText=NULL;
   // *responseFilePath=NULL;

    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, column values to match (GET/PUT).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    if(!strcmp(method,"POST")) //Method = POST is ok, process:
    {
        cmeStrConstrAppend(&(columnValues[0]),"%s",urlElements[1]); //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);
        cmeStrConstrAppend(&(columnNames[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValues[1]),"%s",urlElements[3]); //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);
        cmeStrConstrAppend(&(columnNames[1]),"storageId");
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), POST, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), POST, column storageId: '%s'.\n",
                urlElements[3]);
#endif
        numMatchArgs=2;
        numSaveArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPOSTSaveColumns, numValidGETALLMatch,numValidPOSTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(numSaveArgs==10)&&(keyArg)&&(usrArg)&&(orgArg)) //Command POST successful.
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                if(newOrgKey) //Check resource using newOrgKey
                {
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                      numDuplicateMatchColumns,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,newOrgKey); //Check if resource doesn't exist.
                }
                else //Check resource using orgKey
                {
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                      numDuplicateMatchColumns,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey); //Check if resource doesn't exist.
                }
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    cmeWebServiceProcessStorageResourceFree();
                    *responseCode=500;
                    return(1);
                }
                if (numResultRegisters>0) //resource is already in DB -> Error
                {
                    cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                                       "Storage resource already exists! "
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, forbidden request, storage resource already exists!"
                            " Method: '%s', URL: '%s'!\n",method,url);
#endif
                    cmeWebServiceProcessStorageResourceFree();
                    *responseCode=403;
                    return(2);
                }
                if(newOrgKey) //Create resource using newOrgKey
                {
                    result=cmePostProtectDBRegister(pDB,tableName,(const char **)columnNames,(const char **)columnValues,
                                                    numSaveArgs,newOrgKey);
                }
                else //Create resource using orgKey
                {
                    result=cmePostProtectDBRegister(pDB,tableName,(const char **)columnNames,(const char **)columnValues,
                                                    numSaveArgs,orgKey);
                }
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    cmeWebServiceProcessStorageResourceFree();
                    *responseCode=500;
                    return(3);
                }
                cmeStrConstrAppend(responseText,"Method '%s', user '%s' created successfully storage resource '%s' "
                                   "within organization '%s', in tableName: '%s'.<br>",method, userId, urlElements[3], urlElements[1],tableName);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), POST successful.\n");
#endif
                *responseFilePath=NULL;

                *responseCode=201;
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                cmeWebServiceProcessStorageResourceFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessStorageResourceFree();
                *responseCode=500;
                return(4);
            }
        }
        else //Error, invalid number of arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, incorrect number of "
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessStorageResourceFree();
            *responseCode=409;
            return(5);
        }
    }
    else if(!strcmp(method,"PUT")) //Method = PUT is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]); //We ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]); //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), PUT, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), PUT, column storageId: '%s'.\n",
                urlElements[3]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPUTSaveColumns, numValidGETALLMatch, numValidPUTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(numSaveArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg))
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
                if (result) //Error, internal server error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    *responseCode=500;
                    cmeWebServiceProcessStorageResourceFree();
                    return(6);
                }
                else //Ok
                {
                    if (numResultRegisters>0) //Resource found
                    {
                        if (resultRegisterCols) //Free resultRegisterCols data obtained by cmeGetUnprotectDBRegisters() call above to check if results were available.
                        {
                            for (cont=0; cont<numResultRegisterCols;cont++)
                            {
                               cmeFree(resultRegisterCols[cont]);
                            }
                            cmeFree(resultRegisterCols);
                        }
                        numResultRegisterCols=0;
                        numResultRegisters=0;
                        result=cmePutProtectDBRegisters (pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,numMatchArgs,
                                                         (const char **)columnNames,(const char **)columnValues,numSaveArgs,&resultRegisterCols,
                                                         &numResultRegisterCols,&numResultRegisters,orgKey);
                        if (result) //Error updating - 500
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                            *responseCode=500;
                            cmeWebServiceProcessStorageResourceFree();
                            return(7);
                        }
                        else //Ok
                        {
                            if (numResultRegisters>0) //Resource updated
                            {
                                *responseCode=200;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), PUT successful.\n");
#endif
                            }
                            else //Resource not found!
                            {
                                *responseCode=404;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), PUT successful but"
                                        " resource not found.\n");
#endif
                            }
                        }
                    }
                    else //Resource not found!
                    {
                        *responseCode=404;
                    }
                }
                cmeStrConstrAppend(responseText,"Method '%s', updated resources: %d .<br>",
                                   method, numResultRegisters);
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                cmeWebServiceProcessStorageResourceFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessStorageResourceFree();
                *responseCode=500;
                return(8);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, incorrect number of "
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessStorageResourceFree();
            *responseCode=409;
            return(9);
        }
    }
    else if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]); //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]); //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), GET, column storageId: '%s'.\n",
                urlElements[3]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    //Construct responseText and create response headers according to the user's outputType (optional) request:
                    result=cmeConstructWebServiceTableResponse ((const char **)resultRegisterCols,numResultRegisterCols,numResultRegisters,
                                                                argumentElements, url, method, urlElements[3],
                                                                responseHeaders, responseText, responseCode);
                    cmeWebServiceProcessStorageResourceFree();
                    return(0);
                }
                else //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessStorageResourceFree();
                    *responseCode=500;
                    return(10);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessStorageResourceFree();
                *responseCode=500;
                return(11);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessStorageResourceFree();
            *responseCode=409;
            return(12);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will also match against this value for the search.
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]); //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), HEAD, column orgResourceId : '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), HEAD, column storageId : '%s'.\n",
                urlElements[3]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL , numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) //Found >0 results
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), HEAD successful.\n");
#endif
                    }
                    else //Found 0 results
                    {
                        *responseCode=404;
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), HEAD, successful but"
                        "no record found.\n");
#endif
                    }
                    //cmeStrConstrAppend(responseText,"<p>Matched results: %d</p><br>",numResultRegisters);  //HEAD doesn't return a body.
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                    cmeWebServiceProcessStorageResourceFree();
                    return(0);
                }
                else //Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                        "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'; cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessStorageResourceFree();
                    return(13);
                }
            }
            else //Server ERROR
            {
                *responseCode=500;
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'; can't open DBFile: %s!\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessStorageResourceFree();
                return(14);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessStorageResourceFree();
            *responseCode=409;
            return(15);
        }
    }
    else if(!strcmp(method,"DELETE")) //Method = DELETE is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will match against this value for the search.
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]); //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), DELETE, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), DELETE, column storageId: '%s'.\n",
                urlElements[3]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                     &numResultRegisters,orgKey);
                if (!result) //Delete OK
                {
                    if (numResultRegisters) // Deleted 1 register
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), DELETE successful.\n");
#endif
                    }
                    else // Deleted 0 registers
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), DELETE successful, but resource not found.\n");
#endif
                    }
                    cmeConstructWebServiceCountResponse("Deleted registers",numResultRegisters,
                                                        argumentElements,method,url,
                                                        responseHeaders,responseText,responseCode);
                    cmeWebServiceProcessStorageResourceFree();
                    return(0);
                }
                else //Delete Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), DELETE error!, "
                            "cmeDeleteUnporotectDBRegisters error!\n");
#endif
                    cmeWebServiceProcessStorageResourceFree();
                    return(16);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                   "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageOptions,
                                   cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open DB file: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessStorageResourceFree();
                *responseCode=500;
                return(17);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessStorageResourceFree();
            *responseCode=409;
            return(18);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will match against this value for the search.
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]); //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), OPTIONS, column storageId: '%s'.\n",
                urlElements[3]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=2 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for storage resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgStorageOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessStorageResource(), OPTIONS successful for storage resource."
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessStorageResourceFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessStorageResourceFree();
            *responseCode=409;
            return(19);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageResource(), Error, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessStorageResourceFree();
        *responseCode=405;
        return(20);
    }
}

int cmeWebServiceProcessStorageClass (char **responseText, char ***responseHeaders, int *responseCode,
                                   const char *url, const char **urlElements, const char **argumentElements, const char *method)
{   //IDD v.1.0.20 definitions.
    int cont,result;
    int orgArg=0;
    int usrArg=0;
    int keyArg=0;
    int newKeyArg=0;
    int numMatchArgs=0;
    int numSaveArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL;
    char *userId=NULL;
    char *orgId=NULL;
    char *newOrgKey=NULL;
    char *dbFilePath=NULL;
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET)
    char **columnValues=NULL;
    char **resultRegisterCols=NULL;
    char **columnNamesToMatch=NULL;
    char **columnNames=NULL;
    const int numColumns=12;            //Number of columns in corresponding resource table.
    const int numValidGETALLMatch=9;    //9 parameters + 1 (orgResourceId) from URL
    const int numValidPUTSave=8;
    const char *tableName="storage";
    const char *validGETALLMatchColumns[9]={"_userId","_orgId","_resourceInfo","_location","_type",
                                            "_storageId","_accessPath","_accessUser","_accessPassword"};
    const char *validPUTSaveColumns[8]={"userId","orgId","*resourceInfo","*location","*type",
                                         "*accessPath","*accessUser","*accessPassword"};
    #define cmeWebServiceProcessStorageClassFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(orgId); \
            cmeFree(userId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store user resource information, column values to match (GET).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns);  //Set space to store column names to match (GET).
    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store user resource information, column values to match (PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns);  //Set space to store column names to match (PUT).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName); //Set DB full path.
    if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch,0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(usrArg)&&(keyArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, userId and orgId + 1 match argument)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {   //Note that if numMatchArgs==0 (i.e. columnNamesToMatch and columnValuesToMatch are NULL) then all results are returned.
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
                //Construct responseText and create response headers according to the user's outputType (optional) request:
                result=cmeConstructWebServiceTableResponse ((const char **)resultRegisterCols,numResultRegisterCols,numResultRegisters,
                                                            argumentElements, url, method, "storage",
                                                            responseHeaders, responseText, responseCode);
                cmeWebServiceProcessStorageClassFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                    "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessStorageClassFree();
                *responseCode=500;
                return(1);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Conflicting number of arguments."
                               "</b><br><br>The provided number of arguments is incorrect. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageClassOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, conflicting number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessStorageClassFree();
            *responseCode=409;
            return(2);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        cont=0;
        while ((cont<cmeWSURIMaxArguments)&&(argumentElements[cont])&&((!keyArg)||(!usrArg)||(!orgArg))) //Check for other required parameters not passed via URL (userId,orgId and orgKey).
        {
            if (!strcmp(argumentElements[cont],"orgId")) //parameter orgId found!.
            {
                cmeStrConstrAppend(&orgId,"%s",argumentElements[cont+1]); //special case; we pass it as a function parameter; not in columnValues.
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageClass(), OPTIONS, column orgId: '%s'.\n",
                        argumentElements[cont+1]);
#endif
                orgArg=1;
            }
            else if (!strcmp(argumentElements[cont],"userId")) //parameter userId found!.
            {
                cmeStrConstrAppend(&userId,"%s",argumentElements[cont+1]); //special case; we pass it as a function parameter; not in columnValues.
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageClass(), OPTIONS, column userId: '%s'.\n",
                        argumentElements[cont+1]);
#endif
                usrArg=1;
            }
            else if (!strcmp(argumentElements[cont],"orgKey")) //parameter column-resourceInfo found!.
            {
                cmeStrConstrAppend(&orgKey,"%s",argumentElements[cont+1]); //special case; we pass it as a function parameter; not in columnValues.
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageClass(), OPTIONS, parameter orgKey: '%s'.\n",
                        argumentElements[cont+1]);
#endif
                keyArg=1;
            }
            cont+=2;
        }
        //  No optional arguments for OPTIONS!
        if ((keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId and userResourceId)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for storage class resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgStorageClassOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessStorageClass(), OPTIONS successful for user class resource."
                    "Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessStorageClassFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageClassOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessStorageClassFree();
            *responseCode=409;
            return(3);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch,0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg); //Uses same parameters as GET.
        if ((numMatchArgs>=1)&&(usrArg)&&(keyArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, userId and orgId + 1 match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) //Found >0 results
                    {
                        *responseCode=200;
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageClass(), HEAD successful.\n");
#endif
                    }
                    else //Found 0 results
                    {
                        *responseCode=404;
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageClass(), HEAD, successful but"
                        "no record found!\n");
#endif
                    }
                    //cmeStrConstrAppend(responseText,"<p>Matched results: %d</p><br>",numResultRegisters);   //HEAD doesn't return a body.
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                    cmeWebServiceProcessStorageClassFree();
                    return(0);
                }
                else //Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                        "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageClassOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'; cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessStorageClassFree();
                    return(12);
                }
            }
            else //Server ERROR
            {
                *responseCode=500;
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'; can't open DBFile: %s!\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessStorageClassFree();
                return(13);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageClassOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessStorageClassFree();
            *responseCode=409;
            return(14);
        }
    }
    else if(!strcmp(method,"DELETE")) //Method = DELETE is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch,0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg); //Uses same as GET.
        if ((numMatchArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId and and userId + >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                     &numResultRegisters,orgKey);
                if (!result) //Delete OK
                {
                    if (numResultRegisters) // Deleted >=1 registers
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageClass(), DELETE successful.\n");
#endif
                    }
                    else // Deleted 0 registers
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageClass(), DELETE successful.\n");
#endif
                    }
                    cmeConstructWebServiceCountResponse("Deleted registers",numResultRegisters,
                                                        argumentElements,method,url,
                                                        responseHeaders,responseText,responseCode);
                    cmeWebServiceProcessStorageClassFree();
                    return(0);
                }
                else //Delete Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageClassOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessStorageClass(), DELETE error!, "
                            "cmeDeleteUnporotectDBRegisters error!\n");
#endif
                    cmeWebServiceProcessStorageClassFree();
                    return(15);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                   "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageClassOptions,
                                   cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open DB file: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessStorageClassFree();
                *responseCode=500;
                return(16);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageClassOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessStorageClassFree();
            *responseCode=409;
            return(17);
        }
    }
    else if(!strcmp(method,"PUT")) //Method = PUT is ok, process:
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "orgResourceId" and use the resource defined within the URL!
                                                                            //Second match filter, with index 1.
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will also match against this value for the search.
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessUserClass(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
#endif
        numMatchArgs=1;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPUTSaveColumns, numValidGETALLMatch,numValidPUTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=1)&&(numSaveArgs>=1)&&(keyArg)&&(usrArg)&&(orgArg)) //orgKey + userId + orgId + >=1 Match + >=1 Save.
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (result) //Error, internal server error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageClassOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    *responseCode=500;
                    cmeWebServiceProcessStorageClassFree();
                    return(18);
                }
                else //Ok
                {
                    if (numResultRegisters>0) //Resource found
                    {
                        if (resultRegisterCols) //Free resultRegisterCols data obtained by cmeGetUnprotectDBRegisters() call above to check if results were available.
                        {
                            for (cont=0; cont<numResultRegisterCols;cont++)
                            {
                               cmeFree(resultRegisterCols[cont]);
                            }
                            cmeFree(resultRegisterCols);
                        }
                        numResultRegisterCols=0;
                        numResultRegisters=0;
                        result=cmePutProtectDBRegisters (pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,numMatchArgs,
                                                         (const char **)columnNames,(const char **)columnValues,numSaveArgs,&resultRegisterCols,
                                                         &numResultRegisterCols,&numResultRegisters,orgKey);
                        if (result) //Error updating - 500
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageClassOptions,
                                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                            *responseCode=500;
                            cmeWebServiceProcessStorageClassFree();
                            return(19);
                        }
                        else //Ok
                        {
                            if (numResultRegisters>0) //Resource updated
                            {
                                *responseCode=200;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageClass(), PUT successful.\n");
#endif
                            }
                            else //Resource not found!
                            {
                                *responseCode=404;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessStorageClass(), PUT successful but"
                                        " resource not found.\n");
#endif
                            }
                        }
                    }
                    else //Resource not found!
                    {
                        *responseCode=404;
                    }
                }
                cmeStrConstrAppend(responseText,"Method '%s', updated resources: %d .<br>",
                                   method, numResultRegisters);
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                cmeWebServiceProcessStorageClassFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgStorageClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessStorageClassFree();
                *responseCode=500;
                return(20);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageClassOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessStorageClassFree();
            *responseCode=409;
            return(21);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method is not allowed for this resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgStorageClassOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessStorageClass(), Error, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessStorageClassFree();
        *responseCode=405;
        return(22);
    }
}

int cmeWebServiceProcessDocumentTypeClass (char **responseText, char ***responseHeaders, int *responseCode,
                                           const char *url, const char **urlElements,
                                           const char **argumentElements, const char *method)
{
    int cont;
    const char *pOutputType=NULL;

    if(!strcmp(method,"GET"))
    {
        if ((argumentElements)&&(!cmeFindInArgPairList(argumentElements,"outputType",&pOutputType))&&(pOutputType)&&(!strcmp("json",pOutputType)))
        {
            cmeStrConstrAppend(responseText,"{\"columns\":[\"documentType\"],\"rows\":[");
            for (cont=0;cont<cmeWebServiceNumSupportedDocumentTypes;cont++)
            {
                cmeStrConstrAppend(responseText,"{\"documentType\":\"%s\"}",cmeWebServiceSupportedDocumentTypes[cont]);
                if ((cont+1)<cmeWebServiceNumSupportedDocumentTypes)
                {
                    cmeStrConstrAppend(responseText,",");
                }
            }
            cmeStrConstrAppend(responseText,"]}");
            if ((responseHeaders)&&(*responseHeaders))
            {
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",cmeWebServiceNumSupportedDocumentTypes);
                cmeStrConstrAppend(&((*responseHeaders)[2]),"Content-Type");
                cmeStrConstrAppend(&((*responseHeaders)[3]),"application/json");
            }
        }
        else
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Available document types:</b><br>");
            for (cont=0;cont<cmeWebServiceNumSupportedDocumentTypes;cont++)
            {
                cmeStrConstrAppend(responseText,"%s<br>",cmeWebServiceSupportedDocumentTypes[cont]);
            }
        }
        *responseCode=200;
        return(0);
    }
    else if(!strcmp(method,"OPTIONS"))
    {
        cmeStrConstrAppend(responseText,"<b>200 OK - Options for document type class resources:</b><br>"
                           "%sLatest IDD version: <code>%s</code>",cmeWSMsgDocumentTypeClassOptions,
                           cmeInternalDBDefinitionsVersion);
        *responseCode=200;
        return(0);
    }
    else
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method is not allowed for this documentType class resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentTypeClassOptions,
                           cmeInternalDBDefinitionsVersion);
        *responseCode=405;
        return(2);
    }
}

int cmeWebServiceProcessDocumentTypeResource (char **responseText, char **responseFilePath, int *responseCode,
                                     const char *url, const char **urlElements, const char **argumentElements, const char *method)
{   //IDD ver. 1.0.20 definitions.
    int cont;
    int orgArg=0;
    int usrArg=0;
    int keyArg=0;
    int newKeyArg=0;
    int numMatchArgs=0;
    int numSaveArgs=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL;
    char *userId=NULL;
    char *orgId=NULL;
    char *newOrgKey=NULL;
    char *dbFilePath=NULL;
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET)
    char **columnNamesToMatch=NULL;
    char **columnValues=NULL;
    char **columnNames=NULL;
    const int numColumns=12;            //Number of columns in corresponding resource table.
    const int numValidGETALLMatch=0;    //No matches necessary for this resource

    #define cmeWebServiceProcessDocumentTypeResourceFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    *responseText=NULL;
    *responseFilePath=NULL;

    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store user resource information, column values to match (GET).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns);  //Set space to store column names to match (GET).
    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store user resource information, column values to match (PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns);  //Set space to store column names to match (PUT).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName); //Set DB full path.
    if((!strcmp(method,"GET"))||(!strcmp(method,"HEAD"))||(!strcmp(method,"OPTIONS")))
    {
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We ignore the argument "userResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId"); //We will match against this value for the search.
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]); //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentTypeResource(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentTypeResource(), OPTIONS, column storageId: '%s'.\n",
                urlElements[3]);
#endif
        numMatchArgs=2;
        cmeProcessURLMatchSaveParameters (method, argumentElements, NULL, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=2 Match)
        {
            if (cmeWebServiceIsSupportedDocumentType(urlElements[5])) //OK - Supported type.
            {
                if (strcmp(method,"HEAD"))
                {
                    cmeStrConstrAppend(responseText,"<b>200 OK - document type %s is supported.</b><br>"
                       "%sLatest IDD version: <code>%s</code>",urlElements[5],cmeWSMsgDocumentTypeOptions,cmeInternalDBDefinitionsVersion);
                }
#ifdef DEBUG
                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentTypeResource(), successful for documentType resource."
                        " Method: '%s', URL: '%s'!\n",method,url);
#endif
                cmeWebServiceProcessDocumentTypeResourceFree();
                *responseCode=200;
                return(0);
            }
            else //Error - Unsupported type
            {
                if (strcmp(method,"HEAD"))
                {
                    cmeStrConstrAppend(responseText,"<b>404 ERROR - Unsupported document type %s!</b><br>"
                       "%sLatest IDD version: <code>%s</code>",urlElements[5],cmeWSMsgDocumentTypeOptions,cmeInternalDBDefinitionsVersion);
                }
#ifdef DEBUG
                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentTypeResource(), unsupported documentType resource."
                        " Method: '%s', URL: '%s'!\n",method,url);
#endif
                cmeWebServiceProcessDocumentTypeResourceFree();
                *responseCode=404;
                return(0);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentTypeOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentTypeResource(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentTypeResourceFree();
            *responseCode=409;
            return(1);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentTypeOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentTypeResource(), Error, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessDocumentTypeResourceFree();
        *responseCode=405;
        return(2);
    }
}

int cmeWebServiceProcessDocumentResource (char **responseText, char ***responseHeaders, int *responseCode,
                                          const char *url, const char **urlElements, const char **argumentElements, const char *method,
                                          const char *storagePath, struct MHD_Connection *connection)
{   //IDD ver. 1.0.20 definitions.
    int cont,result;
    int keyArg=0;
    int orgArg=0;
    int usrArg=0;
    int newKeyArg=0;
    int numSaveArgs=0;
    int numMatchArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    int processedRows=0;
    int numCols=0;
    int numSecureDBAttributes=0;
    int replaceDB=0;
    int vacuumDB=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL;                  //requester orgKey.
    char *userId=NULL;                  //requester userId.
    char *orgId=NULL;                   //requester orgId.
    char *newOrgKey=NULL;               //requester newOrgKey (optional).
    char *salt=NULL;
    char **columnValues=NULL;           //Values to be created/updated (POST/PUT)
    char **columnNames=NULL;            //Names of columns of values to be created/updated (POST/PUT)
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *dbFilePath=NULL;
    char *columnFileFullPath=NULL;      //Temp. storage for full path of columnFile for method DELETE.
    char *postImportFile=NULL;          //Note that we will just get pointer to connection info. via MHD_lookup_connection_value. We won't free that memory here!
    char *resourceInfoText=NULL;        //Note that we will just get pointer to connection info. via MHD_lookup_connection_value. We won't free that memory here!
    char **resultRegisterCols=NULL;
    const int numColumns=15;            //Number of columns in corresponding resource table.
    const int numDuplicateMatchColumns=4;   //Columns by which we detect duplicates, in this case: "orgResourceId","storageId","type" and "documentId"; must be the first to be added to columnValuesToMatch and columnNamesToMatch
    const int numValidGETALLMatch=9;    //9 parameters + 4 (storageId,type,orgResourceId,documentId) from URL
    const int numValidPOSTSave=3;       //3 parameters + 4 (storageId,type,orgResourceId,documentId) from URL; columnFile, partMAC, totalParts, partId, columnId, lastModified are set automatically
    const int numValidPUTSave=3;        //3 parameters + 4 (storageId,type,orgResourceId,documentId) from URL; columnFile, partMAC, totalParts, partId, columnId, lastModified can't be updated (otherwise file indexes might break).
    const char *tableName="documents";
    const char *validGETALLMatchColumns[9]={"_userId","_orgId","_resourceInfo","_columnFile",
                                            "_partHash","_totalParts","_partId","_lastModified","_columnId"};
    const char *validPOSTSaveColumns[3]={"userId","orgId","*resourceInfo"};
    const char *validPUTSaveColumns[3]={"userId","orgId","*resourceInfo"};
    const char *attributes[2]={NULL,NULL};
    const char *attributesData[2]={NULL,NULL};
    #define cmeWebServiceProcessDocumentResourceFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            cmeFree(salt); \
            cmeFree(columnFileFullPath); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, column values to match (GET/PUT).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    numSecureDBAttributes=cmeWebServiceBuildSecureDBAttributes(argumentElements,attributes,attributesData,2);
    replaceDB=cmeWebServiceGetBooleanParam(argumentElements,"replaceDB",0);
    vacuumDB=cmeWebServiceGetBooleanParam(argumentElements,"vacuumDB",0);
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    if(!strcmp(method,"POST")) //Method = POST is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValues[0]),"%s",urlElements[1]); //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);
        cmeStrConstrAppend(&(columnNames[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValues[1]),"%s",urlElements[3]); //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);
        cmeStrConstrAppend(&(columnNames[1]),"storageId");
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValues[2]),"%s",urlElements[5]); //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);
        cmeStrConstrAppend(&(columnNames[2]),"type");
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValues[3]),"%s",urlElements[7]); //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);
        cmeStrConstrAppend(&(columnNames[3]),"documentId");
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
        //Mandatory, calculated values. For 'file.csv' We will calculate these values in cmeCSVFileToSecureDB(). Therefore they aren't included in the match list:
        cmeStrConstrAppend(&(columnValues[4]),"");
        cmeStrConstrAppend(&(columnNames[4]),"columnFile");
        cmeStrConstrAppend(&(columnValues[5]),"");
        cmeStrConstrAppend(&(columnNames[5]),"partMAC");
        cmeStrConstrAppend(&(columnValues[6]),"");
        cmeStrConstrAppend(&(columnNames[6]),"totalParts");
        cmeStrConstrAppend(&(columnValues[7]),"");
        cmeStrConstrAppend(&(columnNames[7]),"partId");
        cmeStrConstrAppend(&(columnValues[8]),"");
        cmeStrConstrAppend(&(columnNames[8]),"lastModified");
        cmeStrConstrAppend(&(columnValues[9]),"");
        cmeStrConstrAppend(&(columnNames[9]),"columnId");

#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), POST, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), POST, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), POST, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), POST, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        numSaveArgs=10;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPOSTSaveColumns, numValidGETALLMatch,numValidPOSTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(numSaveArgs==13)&&(keyArg)&&(usrArg)&&(orgArg)) //Command POST successful.
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                if(newOrgKey) //Check resource using newOrgKey
                {
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                      numDuplicateMatchColumns,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,newOrgKey); //Check if resource doesn't exist.
                }
                else //Check resource using orgKey
                {
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                      numDuplicateMatchColumns,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey); //Check if resource doesn't exist.
                }
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    cmeWebServiceProcessDocumentResourceFree();
                    *responseCode=500;
                    return(1);
                }
                else //OK
                {
                    if ((numResultRegisters>0)&&((!replaceDB)||(strcmp("file.csv",urlElements[5])))) //resource is already in DB -> Error
                    {
                        cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                                           "Document resource already exists! "
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), Warning, forbidden request, document resource already exists!"
                                " Method: '%s', URL: '%s'!\n",method,url);
#endif
                        cmeWebServiceProcessDocumentResourceFree();
                        *responseCode=403;
                        return(2);
                    }
                    postImportFile = (char *)MHD_lookup_connection_value(connection,MHD_GET_ARGUMENT_KIND,"file"); //Get full path to temporary uploaded file.
                    if (!postImportFile) //Error, File argument not found!
                    {
                        cmeStrConstrAppend(responseText,"<b>400 ERROR Bad request.</b><br>"
                                           "Document resource file not included in request! "
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), Warning, bad request. Document resource not included in the request!"
                                " Method: '%s', URL: '%s'!\n",method,url);
#endif
                        cmeWebServiceProcessDocumentResourceFree();
                        *responseCode=400;
                        return(3);
                    }
                    if(!strcmp("file.csv",urlElements[5])) //Process 'file.csv' type
                    {
                        resourceInfoText = (char *) MHD_lookup_connection_value(connection,MHD_GET_ARGUMENT_KIND,"*resourceInfo");
                        if(newOrgKey) //Create resource using newOrgKey
                        {
                            result=cmeCSVFileToSecureDB(postImportFile,1,&numCols,&processedRows,userId,orgId,newOrgKey,  //This will call cmeRegisterSecureDB(); no need to call cmePostProtectDBRegister here.
                                                        attributes, attributesData,numSecureDBAttributes,replaceDB,
                                                        vacuumDB,
                                                        resourceInfoText,
                                                        urlElements[5], //document type
                                                        urlElements[7], //documentId
                                                        urlElements[3], //storageId
                                                        storagePath);    //storagePath
                        }
                        else //Create resource using orgKey
                        {
                            result=cmeCSVFileToSecureDB(postImportFile,1,&numCols,&processedRows,userId,orgId,orgKey,  //This will call cmeRegisterSecureDB(); no need to call cmePostProtectDBRegister here.
                                                        attributes, attributesData,numSecureDBAttributes,replaceDB,
                                                        vacuumDB,
                                                        resourceInfoText,
                                                        urlElements[5], //document type
                                                        urlElements[7], //documentId
                                                        urlElements[3], //storageId
                                                        storagePath);    //storagePath
                        }
                        if (result) //Error, File couldn't be imported
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                            cmeWebServiceProcessDocumentResourceFree();
                            *responseCode=500;
                            return(4);
                        }
                    }
                    else if((cmeWebServiceIsParserScriptDocumentType(urlElements[5]))||
                            (cmeWebServiceIsRawFileDocumentType(urlElements[5]))) //Process raw-compatible secure file types.
                    {
                        resourceInfoText = (char *) MHD_lookup_connection_value(connection,MHD_GET_ARGUMENT_KIND,"*resourceInfo");
                        if(newOrgKey) //Create resource using newOrgKey
                        {
                            result=cmeRAWFileToSecureFile (postImportFile,userId,orgId,newOrgKey,resourceInfoText, //This will call cmeRegisterSecureDB(); no need to call cmePostProtectDBRegister here.
                                                            urlElements[5], //document type
                                                            urlElements[7], //documentId
                                                            urlElements[3], //storageId
                                                            storagePath);   //storagePath
                        }
                        else //Create resource using orgKey
                        {
                            result=cmeRAWFileToSecureFile (postImportFile,userId,orgId,orgKey,resourceInfoText, //This will call cmeRegisterSecureDB(); no need to call cmePostProtectDBRegister here.
                                                            urlElements[5], //document type
                                                            urlElements[7], //documentId
                                                            urlElements[3], //storageId
                                                            storagePath);   //storagePath
                        }
                        if (result) //Error, File couldn't be imported
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                            cmeWebServiceProcessDocumentResourceFree();
                            *responseCode=500;
                            return(5);
                        }
                    }
                    else //Error, unsupported file type
                    {
                        cmeStrConstrAppend(responseText,"<b>501 ERROR Not implemented.</b><br>"
                                           "The requested functionality has not been implemented."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), Debug, support "
                                "for file type '%s' has not been implemented. Method: '%s', URL: '%s'!\n",urlElements[5],method,url);
#endif
                        cmeWebServiceProcessDocumentResourceFree();
                        *responseCode=501;
                        return(7);
                    }
                    cmeStrConstrAppend(responseText,"Method '%s', user '%s' created successfully document resource '%s' of type '%s', "
                                       "within organization '%s', in storage '%s', using tableName: '%s'.<br>",method, userId, urlElements[7],
                                       urlElements[5], urlElements[1], urlElements[3], tableName);
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), POST successful.\n");
#endif
                    *responseCode=201;
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                    cmeWebServiceProcessDocumentResourceFree();
                    return(0);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessDocumentResourceFree();
                *responseCode=500;
                return(6);
            }
        }
        else //Error, invalid number of arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), Warning, incorrect number of "
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessDocumentResourceFree();
            *responseCode=409;
            return(7);
        }
    }
    else if(!strcmp(method,"PUT")) //Method = PUT is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), PUT, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), PUT, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), PUT, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), PUT, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPUTSaveColumns, numValidGETALLMatch, numValidPUTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(numSaveArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg))
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
                if (result) //Error, internal server error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    *responseCode=500;
                    cmeWebServiceProcessDocumentResourceFree();
                    return(8);
                }
                else //Ok
                {
                    if (numResultRegisters>0) //Resource found
                    {
                        if (resultRegisterCols) //Free resultRegisterCols data obtained by cmeGetUnprotectDBRegisters() call above to check if results were available.
                        {
                            for (cont=0; cont<numResultRegisterCols;cont++)
                            {
                               cmeFree(resultRegisterCols[cont]);
                            }
                            cmeFree(resultRegisterCols);
                        }
                        numResultRegisterCols=0;
                        numResultRegisters=0;
                        result=cmePutProtectDBRegisters (pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,numMatchArgs,
                                                         (const char **)columnNames,(const char **)columnValues,numSaveArgs,&resultRegisterCols,
                                                         &numResultRegisterCols,&numResultRegisters,orgKey);
                        if (result) //Error updating - 500
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                            *responseCode=500;
                            cmeWebServiceProcessDocumentResourceFree();
                            return(9);
                        }
                        else //Ok
                        {
                            if (numResultRegisters>0) //Resource updated
                            {
                                *responseCode=200;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), PUT successful.\n");
#endif
                            }
                            else //Resource not found!
                            {
                                *responseCode=404;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), PUT successful but"
                                        " resource not found.\n");
#endif
                            }
                        }
                    }
                    else //Resource not found!
                    {
                        *responseCode=404;
                    }
                }
                cmeStrConstrAppend(responseText,"Method '%s', updated resources: %d .<br>",
                                   method, numResultRegisters);
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                cmeWebServiceProcessDocumentResourceFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessDocumentResourceFree();
                *responseCode=500;
                return(10);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), Warning, incorrect number of "
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentResourceFree();
            *responseCode=409;
            return(11);
        }
    }
    else if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), GET, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), GET, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), GET, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    //Construct responseText and create response headers according to the user's outputType (optional) request:
                    result=cmeConstructWebServiceTableResponse ((const char **)resultRegisterCols,numResultRegisterCols,numResultRegisters,
                                                                argumentElements, url, method, urlElements[7],
                                                                responseHeaders, responseText, responseCode);
                    cmeWebServiceProcessDocumentResourceFree();
                    return(0);
                }
                else //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessDocumentResourceFree();
                    *responseCode=500;
                    return(12);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessDocumentResourceFree();
                *responseCode=500;
                return(13);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentResourceFree();
            *responseCode=409;
            return(14);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), HEAD, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), HEAD, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), HEAD, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), HEAD, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL , numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) //Found >0 results
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), HEAD successful.\n");
#endif
                    }
                    else //Found 0 results
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), HEAD, successful but"
                                "no record found.\n");
#endif
                    }
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                    cmeWebServiceProcessDocumentResourceFree();
                    return(0);
                }
                else //Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                        "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'; cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessDocumentResourceFree();
                    return(15);
                }
            }
            else //Server ERROR
            {
                *responseCode=500;
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'; can't open DBFile: %s!\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessDocumentResourceFree();
                return(16);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentResourceFree();
            *responseCode=409;
            return(17);
        }
    }
    else if(!strcmp(method,"DELETE")) //Method = DELETE is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), DELETE, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), DELETE, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), DELETE, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), DELETE, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                     &numResultRegisters,orgKey);
                if (!result) //Delete OK
                {
                    if (numResultRegisters) // Deleted 1 or + register(s)
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), DELETE successful.\n");
#endif
                        for (cont=1;cont<=numResultRegisters;cont++) //Delete corresponding column files. Skip headers (cont=1).
                        {
                            cmeStrConstrAppend(&columnFileFullPath,"%s%s",storagePath,resultRegisterCols[cont*cmeIDDResourcesDBDocumentsNumCols+cmeIDDResourcesDBDocuments_columnFile]);
                            result=cmeFileOverwriteAndDelete(columnFileFullPath);
                            if (result) //Error
                            {
#ifdef ERROR_LOG
                                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), cmeFileOverwriteAndDelete() error, "
                                        "can't remove columnId file: '%s' !\n",columnFileFullPath);
#endif
                            }
                            cmeFree(columnFileFullPath); //Clear for next iteration.
                        }
                    }
                    else // Deleted 0 registers
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), DELETE successful, but resource not found.\n");
#endif
                    }
                    cmeConstructWebServiceCountResponse("Deleted registers",numResultRegisters,
                                                        argumentElements,method,url,
                                                        responseHeaders,responseText,responseCode);
                    cmeWebServiceProcessDocumentResourceFree();
                    return(0);
                }
                else //Delete Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), DELETE error!, "
                            "cmeDeleteUnporotectDBRegisters error!\n");
#endif
                    cmeWebServiceProcessDocumentResourceFree();
                    return(18);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                   "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                   cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open DB file: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessDocumentResourceFree();
                *responseCode=500;
                return(19);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentResourceFree();
            *responseCode=409;
            return(20);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), OPTIONS, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), OPTIONS, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), OPTIONS, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=2 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for document resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgDocumentOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), OPTIONS successful for storage resource."
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentResourceFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentResourceFree();
            *responseCode=409;
            return(21);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), Warning, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessDocumentResourceFree();
        *responseCode=405;
        return(22);
    }
}

int cmeWebServicePOSTIteration (void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
                                const char *filename, const char *content_type,
                                const char *transfer_encoding, const char *data, uint64_t off,
                                size_t size)
{
    struct cmeWebServiceConnectionInfoStruct *con_info = coninfo_cls;
    FILE *filePointer=NULL;
    char *tmpFilename=NULL;
    char tmpBuf[cmeWSPostBufferSize+1]; //Temporary buffer for partial values in non-files
    #define cmeWebServicePOSTIterationFree() \
        do { \
            cmeFree(tmpFilename); \
        } while (0); //Local free() macro.

    if (cmeWebServiceGetThreadStatus(con_info)>=1) //Job is done; ignore any later POST iterator callbacks.
    {
        return MHD_YES;
    }
    if (0 != strcmp (key, "file"))
    {
        //Since MHD_set_connection_value() just copies the pointers to strings, we need to ensure that key and data are persistent during POST iterations.
        tmpBuf[0]='\0'; //reset string buffer.
        strncat(tmpBuf,data,size); //copy only size characters from data to tmpBuf and append ending null character.
        if ((con_info->postArgCont)>0) //Not the first argument.
        {
            if (!strcmp(key,con_info->postArglist[(con_info->postArgCont)-2])) //We have a repeated key-> value is incomplete, append next chunk!
            {
                if (size>0) //Only add another data chunk to the same key value if data is not empty (i.e. size >0).
                {
                    cmeStrConstrAppend(&(con_info->postArglist[(con_info->postArgCont)-1]),"%s",tmpBuf);
                }
            }
            else //New argument -> process as usual
            {
                cmeStrConstrAppend(&(con_info->postArglist[con_info->postArgCont]),"%s",key);
                cmeStrConstrAppend(&(con_info->postArglist[(con_info->postArgCont)+1]),"%s",tmpBuf);
                MHD_set_connection_value(con_info->connection,MHD_GET_ARGUMENT_KIND,
                                         con_info->postArglist[con_info->postArgCont],
                                         con_info->postArglist[(con_info->postArgCont)+1]);
                con_info->postArgCont+=2;
            }
        }
        else //First argument -> process as usual
        {
            cmeStrConstrAppend(&(con_info->postArglist[con_info->postArgCont]),"%s",key);
            cmeStrConstrAppend(&(con_info->postArglist[(con_info->postArgCont)+1]),"%s",tmpBuf);
            MHD_set_connection_value(con_info->connection,MHD_GET_ARGUMENT_KIND,
                                     con_info->postArglist[con_info->postArgCont],
                                     con_info->postArglist[(con_info->postArgCont)+1]);
            con_info->postArgCont+=2;
        }
        cmeWebServicePOSTIterationFree();
        return MHD_YES;
    }
    if (!con_info->filePointer)
    {
        cmeGetRndSalt(&tmpFilename); //Get random HexString for local temp. filename.
       // cmeStrConstrAppend(&fileFullPath,"%s%s",cmeDefaultFilePath,tmpFilename);
        cmeStrConstrAppend(&(con_info->fileName),"%s%s",cmeDefaultSecureTmpFilePath,tmpFilename);
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServicePOSTIteration(), User POSTS file '%s'; temporary "
                " file for processing POST request: '%s'.\n",filename,con_info->fileName);
#endif
        if (NULL != (filePointer = fopen (con_info->fileName, "rb")))
        {
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServicePOSTIteration(), Warning, physical temporary file already exists."
                    " Method: 'POST'. POST Iteration halted.\n");
#endif
            fclose (filePointer);
            cmeFree(con_info->answerString); //Free before replace.
            cmeStrConstrAppend(&(con_info->answerString),"<b>403 ERROR Forbidden request.</b><br><br>"
                               "Physical temporary file already exists.<br>METHOD: 'POST' - message chunk iteration<br>");
            con_info->answerCode = MHD_HTTP_FORBIDDEN;
            cmeWebServiceAbortPOST(con_info);
            cmeWebServicePOSTIterationFree();
            return MHD_NO;
        }
        con_info->filePointer = fopen (con_info->fileName, "ab");
        if (!con_info->filePointer)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServicePOSTIteration(), Error, can't create physical temp. file"
                    " '%s' with fopen(). Method: 'POST'!\n",con_info->fileName);
#endif
            cmeFree(con_info->answerString); //Free before replace.
            cmeStrConstrAppend(&(con_info->answerString),"<b>500 ERROR Internal server error.</b><br><br>"
                               "Can't create local copy of file.<br>METHOD: 'POST' - message chunk iteration<br>");
            con_info->answerCode = MHD_HTTP_INTERNAL_SERVER_ERROR;
            cmeWebServiceAbortPOST(con_info);
            cmeWebServicePOSTIterationFree();
            return MHD_NO;
        }
        cmeFree(con_info->answerString); //Free before replace.
        cmeStrConstrAppend(&(con_info->answerString),"<b>200 OK Resource File Uploaded correctly .</b><br><br>"
                           "METHOD: 'POST' - message chunk iteration<br>");
        con_info->answerCode = MHD_HTTP_OK;
        cmeStrConstrAppend(&(con_info->postArglist[con_info->postArgCont]),"file");  //Add argument pair "file",<con_info->fileName>
        cmeStrConstrAppend(&(con_info->postArglist[(con_info->postArgCont)+1]),"%s",con_info->fileName);
        MHD_set_connection_value(con_info->connection,MHD_GET_ARGUMENT_KIND,
                                 con_info->postArglist[con_info->postArgCont],
                                 con_info->postArglist[(con_info->postArgCont)+1]);
        con_info->postArgCont+=2;
    }
    if (size > 0)
    {
        if (!fwrite(data, size, sizeof (char), con_info->filePointer))
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServicePOSTIteration(), Error, can't fwrite() to file"
                    " '%s'. Method: 'POST'!\n",con_info->fileName);
#endif
            cmeFree(con_info->answerString); //Free before replace.
            cmeStrConstrAppend(&(con_info->answerString),"<b>500 ERROR Internal server error.</b><br><br>"
                               "Can't append data to local file.<br>METHOD: 'POST' - message chunk iteration<br>");
            con_info->answerCode = MHD_HTTP_INTERNAL_SERVER_ERROR;
            cmeWebServiceAbortPOST(con_info);
            cmeWebServicePOSTIterationFree();
            return MHD_NO;
        }
    }
#ifdef DEBUG
    fprintf(stderr,"CaumeDSE Debug: cmeWebServicePOSTIteration(), Iteration successfull; received %lu"
            " bytes for file: '%s' Method: 'POST'.\n",(unsigned long)size,con_info->fileName);
#endif
    cmeWebServicePOSTIterationFree();
    return MHD_YES;
}

void cmeWebServiceRequestCompleted (void *cls, struct MHD_Connection *connection,
                                    void **coninfo_cls, enum MHD_RequestTerminationCode toe)
{
    #define POST            1
    int cont,result __attribute__((unused));
    struct cmeWebServiceConnectionInfoStruct *con_info = *coninfo_cls;

#ifdef DEBUG
    fprintf(stderr,"\n\n\n\nCaumeDSE Debug: cmeWebServiceRequestCompleted(), Iteration cycle finished with TOE: '%d'.\n\n\n\n",(int)toe);
#endif

    if (NULL == con_info)
    {
        return;
    }
    cmeWebServiceWaitThreadStatus(con_info,2); //Wait until the POST processor has collected all data and the request has been processed.
    if (con_info->connectionType == POST)
    {
        if (NULL != con_info->postProcessor)
        {
            for (cont=0;cont<(con_info->postArgCont);cont++) //Clear pointers.
            {
                cmeFree(con_info->postArglist[cont]);
            }
            cmeFree(con_info->postArglist);
            con_info->postArgCont=0;
            MHD_destroy_post_processor (con_info->postProcessor);
            con_info->postProcessor=NULL;
            cmeFree(con_info->answerString);
            con_info->answerCode=0;
            con_info->connectionType=0;
            con_info->connection=NULL;
        }
        if (con_info->filePointer) //If file remained open (e.g. due to some error), we close it.
        {
            fclose (con_info->filePointer);
            con_info->filePointer=NULL;
        }
        if (con_info->fileName)
        {
            result=cmeFileOverwriteAndDelete(con_info->fileName); //Overwrite and delete the temporary file.
            cmeFree(con_info->fileName);
        }
    }
    cmeFree(con_info->answerString);
    pthread_cond_destroy(&(con_info->threadStatusCond));
    pthread_mutex_destroy(&(con_info->threadStatusMutex));
    cmeFree(con_info);
    *coninfo_cls = NULL;
}

int cmeWebServiceProcessDocumentClass (char **responseText, char ***responseHeaders, int *responseCode,
                                       const char *url, const char **urlElements, const char **argumentElements,
                                       const char *method, const char *storagePath)
{   //IDD ver. 1.0.20 definitions.
    int cont,result;
    int keyArg=0;
    int orgArg=0;
    int usrArg=0;
    int newKeyArg=0;
    int numSaveArgs=0;
    int numMatchArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL;                  //requester orgKey.
    char *userId=NULL;                  //requester userId.
    char *orgId=NULL;                   //requester orgId.
    char *newOrgKey=NULL;               //requester newOrgKey (optional).
    char *salt=NULL;
    char **columnValues=NULL;           //Values to be created/updated (POST/PUT)
    char **columnNames=NULL;            //Names of columns of values to be created/updated (POST/PUT)
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *dbFilePath=NULL;
    char *columnFileFullPath=NULL;      //Temp. storage for full path of columnFile for method DELETE.
    char **resultRegisterCols=NULL;
    const int numColumns=15;            //Number of columns in corresponding resource table.
    const int numValidGETALLMatch=10;   //10 parameters + 3 (storageId,orgResourceId,type) from URL
    const int numValidPUTSave=3;        //3 parameters + 3 (storageId,orgResourceId,type) from URL; columnFile, partMAC, totalParts, partId, lastModified, columnId can't be updated (otherwise file indexes might break).
    const char *tableName="documents";
    const char *validGETALLMatchColumns[10]={"_userId","_orgId","_resourceInfo","_columnFile",
                                            "_partHash","_totalParts","_partId","_lastModified",
                                            "_columnId","_documentId"};
    const char *validPUTSaveColumns[3]={"userId","orgId","*resourceInfo"};
    #define cmeWebServiceProcessDocumentClassFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            cmeFree(salt); \
            cmeFree(columnFileFullPath); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store resource information (POST/PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns); //Set space to store resource information (POST/PUT).
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store resource information, column values to match (GET/PUT).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    if(!strcmp(method,"PUT")) //Method = PUT is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), PUT, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), PUT, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), PUT, column type: '%s'.\n",
                urlElements[5]);
#endif
        numMatchArgs=3;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPUTSaveColumns, numValidGETALLMatch, numValidPUTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=3)&&(numSaveArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg))
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
                if (result) //Error, internal server error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentClass(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                    *responseCode=500;
                    cmeDBClose(pDB);
                    pDB=NULL;
                    cmeWebServiceProcessDocumentClassFree();
                    return(1);
                }
                else //Ok
                {
                    if (numResultRegisters>0) //Resource found
                    {
                        if (resultRegisterCols) //Free resultRegisterCols data obtained by cmeGetUnprotectDBRegisters() call above to check if results were available.
                        {
                            for (cont=0; cont<numResultRegisterCols;cont++)
                            {
                               cmeFree(resultRegisterCols[cont]);
                            }
                            cmeFree(resultRegisterCols);
                        }
                        numResultRegisterCols=0;
                        numResultRegisters=0;
                        result=cmePutProtectDBRegisters (pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,numMatchArgs,
                                                         (const char **)columnNames,(const char **)columnValues,numSaveArgs,&resultRegisterCols,
                                                         &numResultRegisterCols,&numResultRegisters,orgKey);
                        if (result) //Error updating - 500
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentClass(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                            *responseCode=500;
                            cmeDBClose(pDB);
                            pDB=NULL;
                            cmeWebServiceProcessDocumentClassFree();
                            return(2);
                        }
                        else //Ok
                        {
                            if (numResultRegisters>0) //Resource updated
                            {
                                *responseCode=200;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), PUT successful.\n");
#endif
                            }
                            else //Resource not found!
                            {
                                *responseCode=404;
#ifdef DEBUG
                                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), PUT successful but"
                                        " resource not found.\n");
#endif
                            }
                        }
                    }
                    else //Resource not found!
                    {
                        *responseCode=404;
                    }
                }
                cmeStrConstrAppend(responseText,"Method '%s', updated resources: %d .<br>",
                                   method, numResultRegisters);
                cmeDBClose(pDB);
                pDB=NULL;
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                cmeWebServiceProcessDocumentClassFree();
                return(0);
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeDBClose(pDB);
                pDB=NULL;
                cmeWebServiceProcessDocumentClassFree();
                *responseCode=500;
                return(3);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), Warning, incorrect number of "
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessDocumentClassFree();
            *responseCode=409;
            return(4);
        }
    }
    else if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), GET, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), GET, column type: '%s'.\n",
                urlElements[5]);
#endif
        numMatchArgs=3;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=3)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=3 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    //Construct responseText and create response headers according to the user's outputType (optional) request:
                    result=cmeConstructWebServiceTableResponse ((const char **)resultRegisterCols,numResultRegisterCols,numResultRegisters,
                                                                argumentElements, url, method, urlElements[5],
                                                                responseHeaders, responseText, responseCode);
                    cmeWebServiceProcessDocumentClassFree();
                    return(0);
                }
                else //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentClass(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeDBClose(pDB);
                    pDB=NULL;
                    cmeWebServiceProcessDocumentClassFree();
                    *responseCode=500;
                    return(5);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
                cmeDBClose(pDB);
                pDB=NULL;
                cmeWebServiceProcessDocumentClassFree();
                *responseCode=500;
                return(6);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentClassFree();
            *responseCode=409;
            return(7);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), HEAD, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), HEAD, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), HEAD, column type: '%s'.\n",
                urlElements[5]);
#endif
        numMatchArgs=3;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL , numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=3)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                  numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) //Found >0 results
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), HEAD successful.\n");
#endif
                    }
                    else //Found 0 results
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), HEAD, successful but"
                                "no record found.\n");
#endif
                    }
                    cmeDBClose(pDB);
                    pDB=NULL;
                    //cmeStrConstrAppend(responseText,"<p>Matched results: %d</p><br>",numResultRegisters);  //HEAD doesn't return a body.
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                    cmeWebServiceProcessDocumentClassFree();
                    return(0);
                }
                else //Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                        "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentClass(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'; cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeDBClose(pDB);
                    pDB=NULL;
                    cmeWebServiceProcessDocumentClassFree();
                    return(8);
                }
            }
            else //Server ERROR
            {
                *responseCode=500;
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'; can't open DBFile: %s!\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessDocumentClassFree();
                cmeDBClose(pDB);
                pDB=NULL;
                return(9);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentClassFree();
            *responseCode=409;
            return(10);
        }
    }
    else if(!strcmp(method,"DELETE")) //Method = DELETE is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), DELETE, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), DELETE, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), DELETE, column type: '%s'.\n",
                urlElements[5]);
#endif
        numMatchArgs=3;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=3)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                     &numResultRegisters,orgKey);
                if (!result) //Delete OK
                {
                    if (numResultRegisters) // Deleted 1 or + register(s)
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), DELETE successful.\n");
#endif
                        for (cont=1;cont<=numResultRegisters;cont++) //Delete corresponding column files. Skip headers (cont=1).
                        {
                            cmeStrConstrAppend(&columnFileFullPath,"%s%s",storagePath,resultRegisterCols[cont*cmeIDDResourcesDBDocumentsNumCols+cmeIDDResourcesDBDocuments_columnFile]);
                            result=cmeFileOverwriteAndDelete(columnFileFullPath);
                            if (result) //Error
                            {
#ifdef ERROR_LOG
                                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), cmeFileOverwriteAndDelete() error, "
                                        "can't remove columnId file: '%s' !\n",columnFileFullPath);
#endif
                            }
                            cmeFree(columnFileFullPath); //Clear for next iteration.
                        }
                    }
                    else // Deleted 0 registers
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), DELETE successful, but resource not found.\n");
#endif
                    }
                    cmeDBClose(pDB);
                    pDB=NULL;
                    cmeConstructWebServiceCountResponse("Deleted registers",numResultRegisters,
                                                        argumentElements,method,url,
                                                        responseHeaders,responseText,responseCode);
                    cmeWebServiceProcessDocumentClassFree();
                    return(0);
                }
                else //Delete Error
                {
                    *responseCode=500;
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), DELETE error!, "
                            "cmeDeleteUnporotectDBRegisters error!\n");
#endif
                    cmeDBClose(pDB);
                    pDB=NULL;
                    cmeWebServiceProcessDocumentClassFree();
                    return(11);
                }
            }
            else //Server ERROR
            {
                cmeDBClose(pDB);
                pDB=NULL;
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                   "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                   cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessDocumentClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open DB file: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessDocumentClassFree();
                *responseCode=500;
                return(12);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentClassFree();
            *responseCode=409;
            return(13);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), OPTIONS, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), OPTIONS, column type: '%s'.\n",
                urlElements[5]);
#endif
        numMatchArgs=3;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=3)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=2 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for document class resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgDocumentClassOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), OPTIONS successful for storage resource."
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentClassFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessDocumentClassFree();
            *responseCode=409;
            return(14);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgDocumentOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentClass(), Warning, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessDocumentClassFree();
        *responseCode=405;
        return(15);
    }
}

int cmeWebServiceProcessParserScriptClass (char **responseText, char ***responseHeaders, int *responseCode,
                                           const char *url, const char **urlElements, const char **argumentElements,
                                           const char *method)
{
    if(!strcmp(method,"OPTIONS"))
    {
        cmeStrConstrAppend(responseText,"<b>200 OK - Options for parser script class resources:</b><br>"
                           "%sLatest IDD version: <code>%s</code>",cmeWSMsgParserScriptClassOptions,
                           cmeInternalDBDefinitionsVersion);
        *responseCode=200;
        return(0);
    }
    cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                       "method is not allowed for this parserScripts class resource."
                       "METHOD: '%s' URL: '%s'."
                       "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgParserScriptClassOptions,
                       cmeInternalDBDefinitionsVersion);
    *responseCode=405;
    return(1);
}

int cmeWebServiceProcessParserScriptResource (char **responseText, char ***responseHeaders, int *responseCode,
                                              const char *url, const char **urlElements, const char **argumentElements,
                                              const char *method, const char *storagePath)
{   //IDD ver. 1.0.20 definitions.
    int cont,result;
    int keyArg=0;
    int orgArg=0;
    int usrArg=0;
    int newKeyArg=0;
    int numSaveArgs=0;
    int numMatchArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    sqlite3 *resultDB=NULL;             //Result DB for unprotected DB (before parsing)
    char *orgKey=NULL;                  //requester orgKey.
    char *userId=NULL;                  //requester userId.
    char *orgId=NULL;                   //requester orgId.
    char *newOrgKey=NULL;               //requester newOrgKey (optional).
    char **columnValues=NULL;           //Values to be created/updated (POST/PUT)
    char **columnNames=NULL;            //Names of columns of values to be created/updated (POST/PUT)
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *tmpRAWFile=NULL;              //Full path to temporal, unencrypted script file.
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    const int numColumns=15;            //Number of columns in corresponding resource table.
    const int numValidGETALLMatch=9;    //9 parameters + 4 (storageId,orgResourceId,documentId,type) from URL
    const char *tableName="documents";
    const char *validGETALLMatchColumns[9]={"_userId","_orgId","_resourceInfo","_columnFile",
                                            "_partHash","_totalParts","_partId","_lastModified","_columnId"};
    const char *scriptNameMatch[1]={"documentId"};
    char *scriptNameValues[1]={"TBD"};
    #define cmeWebServiceProcessParserScriptResourceFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            if(tmpRAWFile) \
            { \
                cmeFileOverwriteAndDelete(tmpRAWFile); \
            } \
            cmeFree(tmpRAWFile); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
            if (resultDB) \
            { \
                cmeDBClose(resultDB); \
                resultDB=NULL; \
            } \
            cmeResultMemTableClean(); \
        } while (0); //Local free() macro.

    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, column values to match (GET/PUT).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), GET, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), GET, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), GET, column documentId: '%s'.\n",
                urlElements[7]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), GET, parameter ParserScript: '%s'.\n",
                urlElements[9]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)&&(storagePath)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId, storagePath and >=4 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                scriptNameValues[0]=(void*)urlElements[9]; //Just point to proper documentId for the script; no need to free it here.
                //Get parser script first:
                result=cmeGetUnprotectDBRegisters(pDB,tableName,scriptNameMatch,(const char **)scriptNameValues,
                                                  1,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) // Found >0
                    {
                        result=cmeSecureFileToTmpRAWFile (&tmpRAWFile,pDB,scriptNameValues[0],resultRegisterCols
                                                          [cmeIDDResourcesDBDocumentsNumCols+cmeIDDResourcesDBDocuments_type],
                                                          storagePath,urlElements[1],urlElements[3],orgKey);
                        if (result)//Error
                        {
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgParserScriptResourceOptions,
                                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                            cmeWebServiceProcessParserScriptResourceFree();
                            *responseCode=500;
                            return(1);
                        }
                    }
                    else //Found 0
                    {
                        cmeStrConstrAppend(responseText,"<b>404 ERROR Script resource not found.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgParserScriptResourceOptions,
                                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), GET successful but "
                                "no records for script '%s' found.\n",urlElements[9]);
#endif
                        cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                        cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                        cmeFileOverwriteAndDelete(tmpRAWFile);
                        cmeWebServiceProcessParserScriptResourceFree();
                        *responseCode=404;
                        return(0);
                    }
                }
                else //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgParserScriptResourceOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessParserScriptResourceFree();
                    *responseCode=500;
                    return(2);
                }
                if ((numResultRegisters)&&
                    (!cmeWebServiceIsParserScriptDocumentType(resultRegisterCols[cmeIDDResourcesDBDocumentsNumCols+cmeIDDResourcesDBDocuments_type])))
                {
                    cmeStrConstrAppend(responseText,"<b>404 ERROR Script resource not found.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgParserScriptResourceOptions,
                                            cmeInternalDBDefinitionsVersion);
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                    cmeWebServiceProcessParserScriptResourceFree();
                    *responseCode=404;
                    return(0);
                }
                //Now, get the protected file.
                if (!strncmp(urlElements[5],"file.csv",8)) //If type of documentId to be parsed is file.csv, then...
                {
                    //First, load an unprotected copy in memory of "documentId" to be parsed:
                    result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
                    if (result) //Error
                    {
                        cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgParserScriptResourceOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                                " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                        cmeWebServiceProcessParserScriptResourceFree();
                        *responseCode=500;
                        return(4);
                    }
                    if (!strcmp(resultRegisterCols[cmeIDDResourcesDBDocumentsNumCols+cmeIDDResourcesDBDocuments_type],"script.perl"))
                    {
                        cmeResultMemTableClean();
                        result=cmeSQLRows(resultDB,"SELECT * FROM data;",NULL,NULL);
                        if (!result)
                        {
                            result=cmeWebServiceRunPerlParserScript(tmpRAWFile);
                        }
                    }
                    else
                    {
                        cmeResultMemTableClean();
                        result=cmeSQLRows(resultDB,"SELECT * FROM data;",NULL,NULL);
                        if (!result)
                        {
                            result=cmeWebServiceRunPythonParserScript(tmpRAWFile);
                        }
                    }
                    if (!result) //OK
                    {
                        //Construct responseText and create response headers according to the user's outputType (optional) request:
                        result=cmeConstructWebServiceTableResponse ((const char **)cmeResultMemTable, cmeResultMemTableCols, cmeResultMemTableRows,
                                                                    argumentElements, url, method, urlElements[7],
                                                                    responseHeaders, responseText, responseCode);
                        cmeWebServiceProcessParserScriptResourceFree();
                        return(0);
                    }
                    else //Error
                    {
                        cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgParserScriptResourceOptions,
                                            cmeInternalDBDefinitionsVersion);
    #ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                                " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
    #endif
                        cmeWebServiceProcessParserScriptResourceFree();
                        *responseCode=500;
                        return(5);
                    }
                }
                else if (cmeWebServiceIsRawFileDocumentType(urlElements[5])) //Raw-compatible files are stored as secure files, but parser execution on them is not implemented.
                {
                    cmeStrConstrAppend(responseText,"<b>501 ERROR Not implemented.</b><br>"
                                       "The requested functionality has not been implemented."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgParserScriptResourceOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), Debug, support "
                            "for file type '%s' has not been implemented. Method: '%s', URL: '%s'!\n",urlElements[5],method,url);
#endif
                    cmeWebServiceProcessParserScriptResourceFree();
                    *responseCode=501;  //No responseText with HEAD method!
                    return(6);
                }
                else //Unsuported file type
                {
                    cmeStrConstrAppend(responseText,"<b>501 ERROR Not implemented.</b><br>"
                                       "The requested functionality has not been implemented."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgParserScriptResourceOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), Debug, support "
                            "for file type '%s' has not been implemented. Method: '%s', URL: '%s'!\n",urlElements[5],method,url);
#endif
                    cmeWebServiceProcessParserScriptResourceFree();
                    *responseCode=501;
                    return(7);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgParserScriptResourceOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
                cmeDBClose(pDB);
                pDB=NULL;
                cmeWebServiceProcessParserScriptResourceFree();
                *responseCode=500;
                return(8);
            }
        }
        else //Error, invalid number of arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgParserScriptResourceOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessParserScriptResourceFree();
            *responseCode=409;
            return(9);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), HEAD, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), HEAD, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), HEAD, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), HEAD, column documentId: '%s'.\n",
                urlElements[7]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), HEAD, parameter ParserScript: '%s'.\n",
                urlElements[9]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)&&(storagePath)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId, storagePath and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                scriptNameValues[0]=(void*)urlElements[9]; //Just point to proper documentId for the script; no need to free it here.
                //Get parser script first:
                result=cmeGetUnprotectDBRegisters(pDB,tableName,scriptNameMatch,(const char **)scriptNameValues,
                                                  1,&resultRegisterCols,&numResultRegisterCols,
                                                  &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) // Found >0
                    {
                        result=cmeSecureFileToTmpRAWFile (&tmpRAWFile,pDB,scriptNameValues[0],resultRegisterCols
                                                          [cmeIDDResourcesDBDocumentsNumCols+cmeIDDResourcesDBDocuments_type],
                                                          storagePath,urlElements[1],urlElements[3],orgKey);
                        if (result)//Error
                        {
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                                    " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                            cmeWebServiceProcessParserScriptResourceFree();
                            *responseCode=500; //No responseText in HEAD!
                            return(10);
                        }
                    }
                    else //Found 0
                    {
                        cmeWebServiceProcessParserScriptResourceFree();
                        *responseCode=404; //No responseText in HEAD!
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), HEAD successful but "
                                "no records for script '%s' found.\n",urlElements[9]);
#endif
                        return(0);
                    }
                }
                else //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessParserScriptResourceFree();
                    *responseCode=500; //No responseText in HEAD!
                    return(11);
                }
                if ((numResultRegisters)&&
                    (!cmeWebServiceIsParserScriptDocumentType(resultRegisterCols[cmeIDDResourcesDBDocumentsNumCols+cmeIDDResourcesDBDocuments_type])))
                {
                    cmeWebServiceProcessParserScriptResourceFree();
                    *responseCode=404;
                    return(0);
                }
                //Now, get the protected file.
                if (!strncmp(urlElements[5],"file.csv",8)) //If type of documentId to be parsed is file.csv, then...
                {
                    //First, load an unprotected copy in memory of "documentId" to be parsed:
                    result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
                    if (result) //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                                " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                        cmeWebServiceProcessParserScriptResourceFree();
                        *responseCode=500;  //No responseText in HEAD!
                        return(13);
                    }
                    if (!strcmp(resultRegisterCols[cmeIDDResourcesDBDocumentsNumCols+cmeIDDResourcesDBDocuments_type],"script.perl"))
                    {
                        cmeResultMemTableClean();
                        result=cmeSQLRows(resultDB,"SELECT * FROM data;",NULL,NULL);
                        if (!result)
                        {
                            result=cmeWebServiceRunPerlParserScript(tmpRAWFile);
                        }
                    }
                    else
                    {
                        cmeResultMemTableClean();
                        result=cmeSQLRows(resultDB,"SELECT * FROM data;",NULL,NULL);
                        if (!result)
                        {
                            result=cmeWebServiceRunPythonParserScript(tmpRAWFile);
                        }
                    }
                    if (!result) //OK
                    {
                        if (cmeResultMemTableRows) // Found >0 rows.
                        {
                            //In HEAD method we just get counters.
                            *responseCode=200;
#ifdef DEBUG
                            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), HEAD successful.\n");
#endif
                        }
                        else //Found 0 rows.
                        {
                            *responseCode=404;
#ifdef DEBUG
                            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), HEAD successful but "
                                    "no records found.\n");
#endif
                        }
                        cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                        cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",cmeResultMemTableRows);
                        cmeFileOverwriteAndDelete(tmpRAWFile);
                        cmeWebServiceProcessParserScriptResourceFree();
                        return(0);  //No responseText in HEAD!
                    }
                    else //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                                " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                        cmeWebServiceProcessParserScriptResourceFree();
                        *responseCode=500; //No responseText in HEAD!
                        return(14);
                    }
                }
                else if (cmeWebServiceIsRawFileDocumentType(urlElements[5])) //Raw-compatible files are stored as secure files, but parser execution on them is not implemented.
                {
#ifdef DEBUG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), Debug, support "
                            "for file type '%s' has not been implemented. Method: '%s', URL: '%s'!\n",urlElements[5],method,url);
#endif
                    cmeWebServiceProcessParserScriptResourceFree();
                    *responseCode=501;  //No responseText with HEAD method!
                    return(15);
                }
                else //Unsuported file type
                {
#ifdef DEBUG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), Debug, support "
                            "for file type '%s' has not been implemented. Method: '%s', URL: '%s'!\n",urlElements[5],method,url);
#endif
                    cmeWebServiceProcessParserScriptResourceFree();
                    *responseCode=501;  //No responseText with HEAD method!
                    return(16);
                }
            }
            else //Server ERROR
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessParserScriptResourceFree();
                *responseCode=500; //No responseText in HEAD!
                return(17);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessParserScriptResourceFree();
            *responseCode=409; //No responseText in HEAD!
            return(18);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), OPTIONS, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), OPTIONS, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), OPTIONS, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=2 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for parser script resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgParserScriptResourceOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), OPTIONS successful for storage resource."
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessParserScriptResourceFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgParserScriptResourceOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessParserScriptResourceFree();
            *responseCode=409;
            return(19);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgParserScriptResourceOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessParserScriptResource(), Warning, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessParserScriptResourceFree();
        *responseCode=405;
        return(20);
    }
}

int cmeWebServiceGetStoragePath (char **storagePath, const char *storageId, const char *orgResourceId, const char *orgKey)
{
    int cont,result;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    const int numColumns=cmeIDDResourcesDBStorageNumCols;            //Number of columns in corresponding resource table.
    const char *tableName="storage";
    #define cmeWebServiceGetStoragePathFree() \
        do { \
            cmeFree(dbFilePath); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store resource information.
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    result=cmeDBOpen(dbFilePath,&pDB);
    if (result) //Error Opening ResourceDB
    {
#ifdef ERROR_LOG
        fprintf(stdout,"CaumeDSE Error: cmeWebServiceGetStoragePath(), can't open ResourceDB "
                "at '%s'!\n",dbFilePath);
#endif
        cmeWebServiceGetStoragePathFree();
        return(1);
    }
    //Mandatory values by user:
    cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",orgResourceId);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
    cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
    cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",storageId);  //We also ignore the argument "storageId" and use the resource defined within the URL!
    cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
    //Get storage Path:
    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                      2,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
    if ((result)||(!numResultRegisters)) //Error, can't find storage
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceGetStoragePath(), Warning, "
                "path for storageId '%s' was not found.\n",storageId);
#endif
        cmeWebServiceGetStoragePathFree();
        return(2);
    }
    cmeStrConstrAppend(storagePath,"%s",resultRegisterCols[numColumns*numResultRegisters+cmeIDDResourcesDBStorage_accessPath]); //Get Storage access path.
    if ((char)(*storagePath)[strlen(*storagePath)-1] != '/') //If path does not end with /, append it to the path.
    {
        cmeStrConstrAppend(storagePath,"/");
    }
    cmeWebServiceGetStoragePathFree();
    return(0);
}

int cmeWebServiceConfirmOrgId (const char *orgResourceId, const char *orgKey)
{
    int cont,result;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    const int numColumns=cmeIDDResourcesDBOrganizationsNumCols;            //Number of columns in corresponding resource table.
    const char *tableName="organizations";
    #define cmeWebServiceConfirmOrgIdFree() \
        do { \
            cmeFree(dbFilePath); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store resource information.
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    result=cmeDBOpen(dbFilePath,&pDB);
    if (result) //Error Opening ResourceDB
    {
#ifdef ERROR_LOG
        fprintf(stdout,"CaumeDSE Error: cmeWebServiceConfirmOrgId(), can't open ResourceDB "
                "at '%s'!\n",dbFilePath);
#endif
        cmeWebServiceConfirmOrgIdFree();
        return(1);
    }
    //Mandatory values by user:
    cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",orgResourceId);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
    cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
    //Get orgResourceId:
    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                      1,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
    if ((result)||(!numResultRegisters)) //Error, can't find orgResourceId
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceConfirmOrgId(), Warning, "
                "orgId '%s' was not found.\n",orgResourceId);
#endif
        cmeWebServiceConfirmOrgIdFree();
        return(2);
    }
    cmeWebServiceConfirmOrgIdFree();
    return(0);
}

int cmeWebServiceConfirmUserId (const char *userResourceId, const char *orgKey)
{
    int cont,result;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    const int numColumns=cmeIDDResourcesDBUsersNumCols;            //Number of columns in corresponding resource table.
    const char *tableName="users";
    #define cmeWebServiceConfirmUserIdFree() \
        do { \
            cmeFree(dbFilePath); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store resource information.
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    result=cmeDBOpen(dbFilePath,&pDB);
    if (result) //Error Opening ResourceDB
    {
#ifdef ERROR_LOG
        fprintf(stdout,"CaumeDSE Error: cmeWebServiceConfirmUserId(), can't open ResourceDB "
                "at '%s'!\n",dbFilePath);
#endif
        cmeWebServiceConfirmUserIdFree();
        return(1);
    }
    //Mandatory values by user:
    cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",userResourceId);  //We also ignore the argument "userResourceId" and use the resource defined within the URL!
    cmeStrConstrAppend(&(columnNamesToMatch[0]),"userResourceId");
    //Get userResourceId:
    result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                      1,&resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
    if ((result)||(!numResultRegisters)) //Error, can't find userResourceId
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceConfirmUserId(), Warning, "
                "orgId '%s' was not found.\n",userResourceId);
#endif
        cmeWebServiceConfirmUserIdFree();
        return(2);
    }
    cmeWebServiceConfirmUserIdFree();
    return(0);
}

int cmeWebServiceProcessContentClass (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                      const char *url, const char **urlElements, const char **argumentElements, const char *method,
                                      const char *storagePath)
{   //IDD ver. 1.0.21
    int cont,result;
    int keyArg=0;
    int orgArg=0;
    int usrArg=0;
    int newKeyArg=0;
    int numSaveArgs=0;
    int numMatchArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    sqlite3 *resultDB=NULL;             //Result DB for unprotected DB (before parsing)
    char *orgKey=NULL;                  //requester orgKey.
    char *userId=NULL;                  //requester userId.
    char *orgId=NULL;                   //requester orgId.
    char *newOrgKey=NULL;               //requester newOrgKey (optional).
    char **columnValues=NULL;           //Values to be created/updated (POST/PUT)
    char **columnNames=NULL;            //Names of columns of values to be created/updated (POST/PUT)
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    const int numColumns=15;            //Number of columns in corresponding resource table.
    const int numValidGETALLMatch=9;    //9 parameters + 4 (storageId,type,orgResourceId,documentId) from URL
    const char *validGETALLMatchColumns[9]={"_userId","_orgId","_resourceInfo","_columnFile",
                                            "_partHash","_totalParts","_partId","_lastModified","_columnId"};
    const char *tableName="documents";
    const char *fileNameMatch[2]={"documentId","type"};
    char *fileNameValues[2]={"TBD","file.raw"};
    #define cmeWebServiceProcessContentClassFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
            if (resultDB) \
            { \
                cmeDBClose(resultDB); \
                resultDB=NULL; \
            } \
            cmeResultMemTableClean(); \
        } while (0); //Local free() macro.

    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, column values to match (GET/PUT).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), GET, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), GET, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), GET, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)&&(storagePath)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId, storagePath and >=4 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                //Get the protected file.
                if (!strncmp(urlElements[5],"file.csv",8)) //If type of documentId to be parsed is file.csv, then...
                {
                    //First, load an unprotected copy in memory of "documentId" to be parsed:
                    result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
                    if (result) //Error
                    {
                        cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentClassOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentClass(), Error, internal server error '%d'."
                                " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                        cmeWebServiceProcessContentClassFree();
                        *responseCode=500;
                        return(1);
                    }
                    cmeResultMemTableClean();
                    result=cmeSQLRows(resultDB,"SELECT * FROM data;",
                                      NULL,NULL); //Select all data; no parser script.
                    if (result==2) //Internal logic error (e.g. no data).
                    {
                        cmeStrConstrAppend(responseText,"<b>404 ERROR resource document not found.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentClassOptions,
                                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), GET successful but "
                                "no records for documentId '%s' found.\n",urlElements[7]);
#endif
                        cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                        cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                        cmeFileOverwriteAndDelete(*responseFilePath);
                        cmeWebServiceProcessContentClassFree();
                        *responseCode=404;
                        return(0);
                    }
                    if (result) //Error (!=2)
                    {
                        cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentClassOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentClass(), Error, internal server error '%d'."
                                " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                        cmeWebServiceProcessContentClassFree();
                        *responseCode=500;
                        return(2);
                    }
                    if ((cmeResultMemTableCols==0)&&(cmeResultMemTableRows==0))//0 Rows tables return 0 columns in SQLite. To be sure we use an SQLite pragma to retrieve column names only.
                    {
                        //Call function to get just the column names in the cmeResultMemTable:
                        result=cmeMemTableWithTableColumnNames(resultDB,"data");
                    }
                    //OK, construct responseText and create response headers according to the user's outputType (optional) request:
                    result=cmeConstructWebServiceTableResponse ((const char **)cmeResultMemTable, cmeResultMemTableCols, cmeResultMemTableRows,
                                                                argumentElements, url, method, urlElements[7],
                                                                responseHeaders, responseText, responseCode);
                    cmeWebServiceProcessContentClassFree();
                    *responseCode=200;
                    return(0);
                }
                else if (cmeWebServiceIsRawFileDocumentType(urlElements[5])) //If document type uses raw file storage, then...
                {
                    fileNameValues[0]=(void*)urlElements[7]; //Just point to proper documentId for the file; no need to free it here.
                    fileNameValues[1]=(void*)urlElements[5]; //Match against the requested raw-compatible document type.
                    //Get raw file :
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,fileNameMatch,(const char **)fileNameValues,
                                                      2,&resultRegisterCols,&numResultRegisterCols,
                                                      &numResultRegisters,orgKey);
                    if (!result) //OK
                    {
                        if (numResultRegisters) // Found >0
                        {
                            result=cmeSecureFileToTmpRAWFile (responseFilePath,pDB,urlElements[7],urlElements[5],storagePath,
                                                              urlElements[1],urlElements[3],orgKey);
                            if (result)//Error
                            {
                                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                                   "Internal server error number '%d'."
                                                   "METHOD: '%s' URL: '%s'."
                                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentClassOptions,
                                                    cmeInternalDBDefinitionsVersion);
    #ifdef ERROR_LOG
                                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentClass(), Error, internal server error '%d'."
                                        " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
    #endif
                                cmeWebServiceProcessContentClassFree();
                                *responseCode=500;
                                return(3);
                            }
                            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                            cmeStrConstrAppend(&((*responseHeaders)[2]),"Content-Type");
                            cmeStrConstrAppend(&((*responseHeaders)[3]),"application/octet-stream");
                            cmeStrConstrAppend(&((*responseHeaders)[4]),"Content-Disposition");
                            cmeStrConstrAppend(&((*responseHeaders)[5]),"attachment;filename=\"%s\"",urlElements[7]);
                            cmeWebServiceProcessContentClassFree();
                            *responseCode=200;
                            return(0);
                        }
                        else //Found 0
                        {
                            cmeStrConstrAppend(responseText,"<b>404 ERROR resource not found.</b><br>"
                                                   "Internal server error number '%d'."
                                                   "METHOD: '%s' URL: '%s'."
                                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentClassOptions,
                                                    cmeInternalDBDefinitionsVersion);
    #ifdef DEBUG
                            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), GET successful but "
                                    "no records for documentId '%s' found.\n",urlElements[7]);
    #endif
                            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                            cmeFileOverwriteAndDelete(*responseFilePath);
                            cmeWebServiceProcessContentClassFree();
                            *responseCode=404;
                            return(0);
                        }
                    }
                    else //Error
                    {
                        cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentClassOptions,
                                            cmeInternalDBDefinitionsVersion);
    #ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentClass(), Error, internal server error '%d'."
                                " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
    #endif
                        cmeWebServiceProcessContentClassFree();
                        *responseCode=500;
                        return(4);
                    }
                }
                else //Unsuported file type
                {
                    cmeStrConstrAppend(responseText,"<b>501 ERROR Not implemented.</b><br>"
                                       "The requested functionality has not been implemented."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentClassOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), Debug, support "
                            "for file type '%s' has not been implemented. Method: '%s', URL: '%s'!\n",urlElements[5],method,url);
#endif
                    cmeWebServiceProcessContentClassFree();
                    *responseCode=501;
                    return(5);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessContentClassFree();
                *responseCode=500;
                return(6);
            }
        }
        else //Error, invalid number of arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentClassOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentClassFree();
            *responseCode=409;
            return(7);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), HEAD, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), HEAD, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), HEAD, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), HEAD, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)&&(storagePath)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId, storagePath and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                //Get the protected file.
                if (!strncmp(urlElements[5],"file.csv",8)) //If type of documentId to be parsed is file.csv, then...
                {
                    //First, load an unprotected copy in memory of "documentId" to be parsed:
                    result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
                    if (result) //Error
                    {
                        cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                           "Internal server error number '%d'."
                                           "METHOD: '%s' URL: '%s'."
                                            "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentClassOptions,
                                            cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentClass(), Error, internal server error '%d'."
                                " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                        cmeWebServiceProcessContentClassFree();
                        *responseCode=500;
                        return(8);
                    }
                    cmeResultMemTableClean();
                    result=cmeSQLRows(resultDB,"SELECT * FROM data;",
                                      NULL,NULL); //Select all data; no parser script.
                    if (result==2) //Error SQLITE_INTERNAL Logic (e.g. document not found)
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), HEAD successful but "
                                "document not found.\n");
#endif
                        cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                        cmeStrConstrAppend(&((*responseHeaders)[1]),"0");
                        cmeWebServiceProcessContentClassFree();
                        return(0);
                    }
                    if (result) //Error (!=2)
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentClass(), Error, internal server error '%d'."
                                " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                        cmeWebServiceProcessContentClassFree();
                        *responseCode=500;  //No responseText with HEAD method!
                        return(9);
                    }
                    //OK:
                    if (cmeResultMemTableRows) // Found >0 rows.
                    {
                        //In HEAD method we just get counters.
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), HEAD successful.\n");
#endif
                    }
                    else //Found 0 rows.
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), HEAD successful but "
                                "no records found.\n");
#endif
                    }
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",cmeResultMemTableRows);
                    cmeWebServiceProcessContentClassFree();
                    return(0);
                }
                else if (cmeWebServiceIsRawFileDocumentType(urlElements[5])) //If document type uses raw file storage, then...
                {
                    fileNameValues[0]=(void*)urlElements[7]; //Just point to proper documentId for the file; no need to free it here.
                    fileNameValues[1]=(void*)urlElements[5]; //Match against the requested raw-compatible document type.
                    //Get raw file :
                    result=cmeGetUnprotectDBRegisters(pDB,tableName,fileNameMatch,(const char **)fileNameValues,
                                                      2,&resultRegisterCols,&numResultRegisterCols,
                                                      &numResultRegisters,orgKey);
                    if (!result) //OK
                    {
                        if (numResultRegisters) // Found >0
                        {
                            result=cmeSecureFileToTmpRAWFile (responseFilePath,pDB,urlElements[7],urlElements[5],storagePath,
                                                              urlElements[1],urlElements[3],orgKey); //We don't need this for HEAD, but strictly speaking, we need to test that the "content" is there, even if we are not returning any file.
                            if (result)//Error
                            {
#ifdef ERROR_LOG
                                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentClass(), Error, internal server error '%d'."
                                        " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                                cmeWebServiceProcessContentClassFree(); //No responseText with HEAD method!
                                *responseCode=500;
                                return(10);
                            }
                            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                            cmeFileOverwriteAndDelete(*responseFilePath);
                            cmeFree(*responseFilePath); //We tested that we can open the file, now we delete it as we don't return anything for HEAD.
                            cmeWebServiceProcessContentClassFree();
                            *responseCode=200; //No responseText with HEAD method!
                            return(0);
                        }
                        else //Found 0
                        {
#ifdef DEBUG
                            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), GET successful but "
                                    "no records for documentId '%s' found.\n",urlElements[7]);
#endif
                            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                            cmeFileOverwriteAndDelete(*responseFilePath);
                            cmeWebServiceProcessContentClassFree();
                            *responseCode=404; //No responseText with HEAD method!
                            return(0);
                        }
                    }
                    else //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentClass(), Error, internal server error '%d'."
                                " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                        cmeWebServiceProcessContentClassFree();
                        *responseCode=500;
                        return(11);
                    }
                }
                else //Unsuported file type
                {
#ifdef DEBUG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), Debug, support "
                            "for file type '%s' has not been implemented. Method: '%s', URL: '%s'!\n",urlElements[5],method,url);
#endif
                    cmeWebServiceProcessContentClassFree();
                    *responseCode=501;  //No responseText with HEAD method!
                    return(12);
                }
            }
            else //Server ERROR
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessContentClassFree();
                *responseCode=500; //No responseText with HEAD method!
                return(13);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentClassFree();
            *responseCode=409; //No responseText with HEAD method!
            return(14);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), OPTIONS, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), OPTIONS, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), OPTIONS, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=2 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for parser script resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgContentClassOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), OPTIONS successful for storage resource."
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentClassFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentClassOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentClassFree();
            *responseCode=409;
            return(15);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentClassOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentClass(), Warning, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessContentClassFree();
        *responseCode=405;
        return(16);
    }
}

int cmeWebServiceClientCertAuth (const char *userId, const char *orgId, struct MHD_Connection *connection)
{
    int result,len;
    size_t dnBuf;
    unsigned int peerCertListNum=0;
    unsigned int clientCertStatus=0;
    void **tls_session_ptr=NULL; //No need to free (ptr to constant).
    void *tls_session=NULL; //No need to free (ptr to constant).
    const gnutls_datum_t *peerCertList=NULL;
    gnutls_x509_crt_t userCert=NULL;
    gnutls_x509_crt_t orgCert=NULL;
    char *userDN=NULL;
    char *orgDN=NULL;
    char *userCN=NULL;
    char *userO=NULL;
    char *orgCN=NULL;
    #define cmeWebServiceClientCertAuthFree() \
        do { \
            if (userCert) \
            { \
                gnutls_x509_crt_deinit(userCert); \
            } \
            if (orgCert) \
            { \
                gnutls_x509_crt_deinit(orgCert); \
            } \
            cmeFree(userDN); \
            cmeFree(userCN); \
            cmeFree(userO); \
            cmeFree(orgDN); \
            cmeFree(orgCN); \
        } while (0); //Local free() macro.

    tls_session_ptr=(void **)MHD_get_connection_info(connection,MHD_CONNECTION_INFO_GNUTLS_SESSION); //Get GnuTLS session from MHD_Connection.
    if (!tls_session_ptr) //Error, no TLS session pinter found. We probably don't have a TLS session
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), MHD_get_connection_info(), Warning, "
                "NULL tls_session_ptr.\n");
#endif
        cmeWebServiceClientCertAuthFree();
        return(1);
    }
    tls_session=*tls_session_ptr;
    if (!tls_session) //Error, no TLS session found
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), MHD_get_connection_info(), Warning, "
                "NULL tls_session.\n");
#endif
        cmeWebServiceClientCertAuthFree();
        return(2);
    }
    result=gnutls_certificate_type_get(tls_session);
    result=gnutls_certificate_verify_peers2(tls_session,&clientCertStatus);   //Validate certificate.
    if (result) //Error, cannot validate certificate.
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), gnutls_certificate_verify_peers2(), Warning, "
                "can't validate certificate.\n");
#endif
        cmeWebServiceClientCertAuthFree();
        return(3);
    }
    if (clientCertStatus & GNUTLS_CERT_INVALID)
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), gnutls_certificate_verify_peers2(), Warning, "
                "USER CERTIFICATE IS NOT TRUSTED.\n");
        if (clientCertStatus & GNUTLS_CERT_SIGNER_NOT_FOUND)
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), gnutls_certificate_verify_peers2(), Warning, "
                "NO ISSUER WAS FOUND.\n");
        if (clientCertStatus & GNUTLS_CERT_SIGNER_NOT_CA)
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), gnutls_certificate_verify_peers2(), Warning, "
                "ISSUER IS NOT A CA.\n");
        if (clientCertStatus & GNUTLS_CERT_NOT_ACTIVATED)
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), gnutls_certificate_verify_peers2(), Warning, "
                "USER CERTIFICATE HAS NOT BEEN ACTIVATED YET (date).\n");
        if (clientCertStatus & GNUTLS_CERT_EXPIRED)
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), gnutls_certificate_verify_peers2(), Warning, "
                "USER CERTIFICATE IS EXPIRED.\n");
#endif
        return(4);
    }
    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), gnutls_certificate_verify_peers2(), "
                "User certificate (certificate chain up to CA) is valid.\n");
#endif
    }
    peerCertList = gnutls_certificate_get_peers(tls_session,&peerCertListNum); //Get chain of certificates.
    if ((!peerCertList)||(peerCertListNum==0)) //Error, no certificate chain list
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), gnutls_certificate_get_peers(), Warning, "
                "no certificate chain list is available.\n");
#endif
        cmeWebServiceClientCertAuthFree();
        return(5);
    }
    if (peerCertListNum<2) //Error, invalid number of certificates in chain list
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), Warning, "
                "invalid number of certificates in chain list (<2).\n");
#endif
        cmeWebServiceClientCertAuthFree();
        return(6);
    }
    //Initialize certificate storage:
    gnutls_x509_crt_init(&userCert);
    gnutls_x509_crt_init(&orgCert);
    //Import certificates from chain list:
    gnutls_x509_crt_import(userCert,&peerCertList[0],GNUTLS_X509_FMT_DER);
    gnutls_x509_crt_import(orgCert,&peerCertList[1],GNUTLS_X509_FMT_DER);
    gnutls_x509_crt_get_dn(userCert, NULL, &dnBuf); //Get size of user DN.
    userDN = malloc(dnBuf);
    if (!userDN) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceClientCertAuth(), malloc(), can't allocate memory for userDN!\n");
#endif
        cmeWebServiceClientCertAuthFree();
        return(7);
    }
    gnutls_x509_crt_get_dn(userCert, userDN, &dnBuf); //Get user DN.
    gnutls_x509_crt_get_dn(orgCert, NULL, &dnBuf); //Get size of organization DN.
    orgDN = malloc(dnBuf);
    if (!orgDN) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceClientCertAuth(), malloc(), can't allocate memory for orgDN!\n");
#endif
        cmeWebServiceClientCertAuthFree();
        return(8);
    }
    gnutls_x509_crt_get_dn(orgCert, orgDN, &dnBuf);//Get organization DN.
    result=cmex509GetElementFromDN(userDN,"CN",&userCN,&len);
    result=cmex509GetElementFromDN(userDN,"O",&userO,&len);
    result=cmex509GetElementFromDN(orgDN,"CN",&orgCN,&len);
    //Verify that user CN (in userDN), user O (in userDN) and org O (in orgDN) against corresponding userId and orgId:
    if (!cmeStrSafeEq(userId,userCN)) //Authentication error: userId does not match client certificate CN!
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), Warning, "
                "Authentication error, userId (%s) does not match user certificate CN (user DN: %s).\n",userId,userDN);
#endif
        cmeWebServiceClientCertAuthFree();
        return(9);
    }
    if (!cmeStrSafeEq(orgId,userO)) //Authentication error: orgId does not match client certificate O!
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), Warning, "
                "Authentication error, orgId (%s) does not match user certificate O (user DN: %s).\n",orgId,userDN);
#endif
        cmeWebServiceClientCertAuthFree();
        return(10);
    }
    if (!cmeStrSafeEq(orgId,orgCN)) //Authentication error: orgId does not match issuer organization certificate CN!
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), Warning, "
                "Authentication error, orgId (%s) does not match issuerOrg certificate CN (issuerOrg DN: %s).\n",orgId,orgDN);
#endif
        cmeWebServiceClientCertAuthFree();
        return(11);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), "
            "TLS Certificate Chain Authentication Successful! userId (%s), orgId (%s), user DN (%s), issuerOrg DN (%s).\n",userId,orgId,userDN,orgDN);
#endif
    cmeWebServiceClientCertAuthFree();
    return(0); //Authentication successful.
}


int cmeWebServiceProcessContentRowClass (char **responseText, char ***responseHeaders, int *responseCode,
                                         const char *url, const char **urlElements, const char **argumentElements,
                                         const char *method)
{
    (void)responseHeaders;
    (void)urlElements;
    (void)argumentElements;
    if(!strcmp(method,"OPTIONS"))
    {
        cmeStrConstrAppend(responseText,"<b>200 OK - Options for contentRows class resources:</b><br>"
                           "%sLatest IDD version: <code>%s</code>",cmeWSMsgContenRowOptions,
                           cmeInternalDBDefinitionsVersion);
        *responseCode=200;
        return(0);
    }
    cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                       "method is not allowed for this contentRows class resource."
                       "METHOD: '%s' URL: '%s'."
                       "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContenRowOptions,
                       cmeInternalDBDefinitionsVersion);
    *responseCode=405;
    return(1);
}

int cmeWebServiceProcessContentRowResource (char **responseText, char ***responseHeaders, int *responseCode,
                                            const char *url, const char **urlElements, const char **argumentElements, const char *method,
                                            const char *storagePath)
{   //IDD ver. 1.0.21 definitions.
    int cont,result;
    int numColsContentRow=0;
    int keyArg=0;
    int orgArg=0;
    int usrArg=0;
    int newKeyArg=0;
    int numSaveArgs=0;
    int numMatchArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    int numSecureDBAttributes=0;
    int vacuumDB=0;
    sqlite3 *pDB=NULL;
    sqlite3 *resultDB=NULL;             //Result DB for unprotected DB (before parsing)
    char *orgKey=NULL;                  //requester orgKey.
    char *userId=NULL;                  //requester userId.
    char *orgId=NULL;                   //requester orgId.
    char *newOrgKey=NULL;               //requester newOrgKey (optional).
    char *salt=NULL;
    char **columnValues=NULL;           //Values to be created/updated (POST/PUT)
    char **columnNames=NULL;            //Names of columns of values to be created/updated (POST/PUT)
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char **newContentRow=NULL;          //Data of new content row (POST/PUT).
    char *dbFilePath=NULL;
    char *columnFileFullPath=NULL;      //Temp. storage for full path of columnFile for method DELETE.
    char *resourceInfoText=NULL;        //Stores the previous resourceInfo value (POST/PUT)
    char *sqlQuery=NULL;
    char **resultRegisterCols=NULL;
    const int numColumns=cmeIDDResourcesDBDocumentsNumCols;            //Number of columns in corresponding resource table.
    const int numValidGETALLMatch=9;    //9 parameters + 4 (storageId,type,orgResourceId,documentId) from URL
    const int numValidPOSTSave=3;       //3 parameters + 4 (storageId,type,orgResourceId,documentId) from URL; columnFile, partMAC, totalParts, partId, columnId, lastModified are set automatically
    const int numValidPUTSave=3;        //3 parameters + 4 (storageId,type,orgResourceId,documentId) from URL; columnFile, partMAC, totalParts, partId, columnId, lastModified can't be updated (otherwise file indexes might break).
    const char *tableName="documents";
    const char *validGETALLMatchColumns[9]={"_userId","_orgId","_resourceInfo","_columnFile",
                                            "_partHash","_totalParts","_partId","_lastModified","_columnId"};
    const char *validPOSTSaveColumns[3]={"userId","orgId"};
    const char *validPUTSaveColumns[3]={"userId","orgId"};
    const char *attributes[2]={NULL,NULL};
    const char *attributesData[2]={NULL,NULL};
    #define cmeWebServiceProcessContentRowResourceFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            cmeFree(salt); \
            cmeFree(columnFileFullPath); \
            cmeFree(resourceInfoText); \
            cmeFree(sqlQuery); \
            if ((newContentRow)&&(numColsContentRow)) \
            { \
               for (cont=0;cont<numColsContentRow;cont++) \
               { \
                   cmeFree(newContentRow[cont]); \
               } \
               cmeFree(newContentRow); \
            } \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0;cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0;cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0;cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
            if (resultDB) \
            { \
                cmeDBClose(resultDB); \
                resultDB=NULL; \
            } \
        } while (0); //Local free() macro.

    //Clear result Mem table from any previous queries:
    cmeResultMemTableClean();
    //Check that type =file.csv (we can only work with this type of document resources):
    if (strcmp("file.csv",urlElements[5])) //Error, file type is invalid. Abort
    {
        cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                           "File type must be 'file.csv' "
                           "METHOD: '%s' URL: '%s'."
                            "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContenRowOptions,
                            cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Warning, forbidden request, file type != 'file.csv'!"
                " Method: '%s', URL: '%s'!\n",method,url);
#endif
        cmeWebServiceProcessContentRowResourceFree();
        *responseCode=403;
        return(1);
    }
    numSecureDBAttributes=cmeWebServiceBuildSecureDBAttributes(argumentElements,attributes,attributesData,2);
    vacuumDB=cmeWebServiceGetBooleanParam(argumentElements,"vacuumDB",0);
    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, column values to match (GET/PUT).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    if(!strcmp(method,"POST")) //Method = POST is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValues[0]),"%s",urlElements[1]); //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);
        cmeStrConstrAppend(&(columnNames[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValues[1]),"%s",urlElements[3]); //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);
        cmeStrConstrAppend(&(columnNames[1]),"storageId");
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValues[2]),"%s",urlElements[5]); //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);
        cmeStrConstrAppend(&(columnNames[2]),"type");
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValues[3]),"%s",urlElements[7]); //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);
        cmeStrConstrAppend(&(columnNames[3]),"documentId");
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
        //Mandatory, calculated values. For 'file.csv' We will calculate these values in cmeCSVFileToSecureDB(). Therefore they aren't included in the match list:
        cmeStrConstrAppend(&(columnValues[4]),"");
        cmeStrConstrAppend(&(columnNames[4]),"columnFile");
        cmeStrConstrAppend(&(columnValues[5]),"");
        cmeStrConstrAppend(&(columnNames[5]),"partMAC");
        cmeStrConstrAppend(&(columnValues[6]),"");
        cmeStrConstrAppend(&(columnNames[6]),"totalParts");
        cmeStrConstrAppend(&(columnValues[7]),"");
        cmeStrConstrAppend(&(columnNames[7]),"partId");
        cmeStrConstrAppend(&(columnValues[8]),"");
        cmeStrConstrAppend(&(columnNames[8]),"lastModified");
        cmeStrConstrAppend(&(columnValues[9]),"");
        cmeStrConstrAppend(&(columnNames[9]),"columnId");

#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), POST, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), POST, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), POST, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), POST, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        numSaveArgs=10;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPOSTSaveColumns, numValidGETALLMatch,numValidPOSTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(numSaveArgs==12)&&(keyArg)&&(usrArg)&&(orgArg)) //Command POST successful.
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (result) //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(2);
            }
            result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                              numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                              &numResultRegisters,orgKey);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(3);
            }
            if (numResultRegisters<=0) //requested documentID not found
            {
                cmeStrConstrAppend(responseText,"<b>404 ERROR document resource not found.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), "
                        "no records for documentId '%s' found.\n",urlElements[7]);
#endif
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=404;
                return(0);
            }
            //Copy resourceInfo:
            cmeStrConstrAppend(&resourceInfoText,"%s",resultRegisterCols[numResultRegisterCols+cmeIDDResourcesDBDocuments_resourceInfo]);
            //Load an unprotected copy in memory of "documentId":
            result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(4);
            }
            cmeResultMemTableClean();
            result=cmeSQLRows(resultDB,"SELECT * FROM data;",
                              NULL,NULL); //Select all data; no parser script.
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSQLRows error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(5);
            }
            if ((cmeResultMemTableCols==0)&&(cmeResultMemTableRows==0))//0 Rows tables return 0 columns in SQLite. To be sure we use an SQLite pragma to retrieve column names only.
            {
               //Call function to get just the column names in the cmeResultMemTable:
               result=cmeMemTableWithTableColumnNames(resultDB,"data");
            }
            if (atoi(urlElements[9])!=cmeResultMemTableRows+1) //Error, specified row is out of range for a POST. Stop processing.
            {
                cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                                   "contentRow is out of range for POST. Next free row is: %d !"
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",cmeResultMemTableRows+1,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Warning, forbidden request, document row already exists!"
                        " Method: '%s', URL: '%s'!\n",method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=403;
                return(6);
            }
            //Construct new contentRow values form contentRow URI arguments:
            numColsContentRow=cmeResultMemTableCols; //Set number of columns in table.
            cmeConstructContentRow(argumentElements,(const char **)cmeResultMemTable,numColsContentRow,urlElements[9],&newContentRow);
            //Insert new content row in cmeResultMemTable:
            cmeResultMemTableRows++;
            cmeResultMemTable=(char **)realloc(cmeResultMemTable,sizeof(char *)*cmeResultMemTableCols*(cmeResultMemTableRows+1)); //Reallocate memory.
            for(cont=0;cont<numColsContentRow;cont++) //Set pointers in new row at cmeResultMemTable to the corresponding pointers in newContentRow.
            {
                cmeResultMemTable[(cmeResultMemTableRows)*cmeResultMemTableCols+cont]=NULL;
                cmeStrConstrAppend(&(cmeResultMemTable[(cmeResultMemTableRows)*cmeResultMemTableCols+cont]),"%s",newContentRow[cont]);
            }
            //Create new secureDB (delete old secureDB if it exists):
            result=cmeMemTableToSecureDB((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,userId,orgId,orgKey,
                                         attributes,attributesData,numSecureDBAttributes,1,
                                         vacuumDB,
                                         resourceInfoText,
                                         urlElements[5], //document type
                                         urlElements[7], //documentId
                                         urlElements[3], //storageId
                                         storagePath);    //storagePath
            //End:
            cmeStrConstrAppend(responseText,"Method '%s', user '%s' created successfully contentRow resource '%s', "
                               "within organization '%s', in storage '%s', using tableName: '%s'.<br>",method, userId, urlElements[9],
                               urlElements[1], urlElements[3], tableName);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), POST successful.\n");
#endif
            *responseCode=201;
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
            cmeWebServiceProcessContentRowResourceFree();
            return(0);
        }
        else //Error, invalid number of arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContenRowOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Warning, incorrect number of "
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessContentRowResourceFree();
            *responseCode=409;
            return(7);
        }
    }
    else if(!strcmp(method,"PUT")) //Method = PUT is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), PUT, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), PUT, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), PUT, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), PUT, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPUTSaveColumns, numValidGETALLMatch, numValidPUTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(numSaveArgs>=2)&&(keyArg)&&(usrArg)&&(orgArg))
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (result) //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(8);
            }
            result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                              numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                              &numResultRegisters,orgKey);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(9);
            }
            if (numResultRegisters<=0) //requested documentID not found
            {
                cmeStrConstrAppend(responseText,"<b>404 ERROR document resource not found.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), "
                        "no records for documentId '%s' found.\n",urlElements[7]);
#endif
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=404;
                return(0);
            }
            //Copy resourceInfo:
            cmeStrConstrAppend(&resourceInfoText,"%s",resultRegisterCols[numResultRegisterCols+cmeIDDResourcesDBDocuments_resourceInfo]);
            //Load an unprotected copy in memory of "documentId":
            result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(10);
            }
            cmeResultMemTableClean();
            result=cmeSQLRows(resultDB,"SELECT * FROM data;",
                              NULL,NULL); //Select all data; no parser script.
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSQLRows error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(11);
            }
            if ((atoi(urlElements[9])>cmeResultMemTableRows)||(atoi(urlElements[9])<1)) //Error, specified row is out of range for PUT. Stop processing.
            {
                cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                                   "contentRow is out of range for PUT. Last register is: %d !"
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",cmeResultMemTableRows,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Warning, forbidden request, document row already exists!"
                        " Method: '%s', URL: '%s'!\n",method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=403;
                return(12);
            }
            //Construct new contentRow values form contentRow URI arguments:
            numColsContentRow=cmeResultMemTableCols; //Set number of columns in table.
            cmeConstructContentRow(argumentElements,(const char **)cmeResultMemTable,numColsContentRow,"",&newContentRow);
            //Update content row in cmeResultMemTable:
            for(cont=0;cont<numColsContentRow;cont++) //Set pointers in new row at cmeResultMemTable to the corresponding pointers in newContentRow.
            {
                if (strcmp(newContentRow[cont],"")) // if new value != "" -> replace in table.
                {
                    cmeFree(cmeResultMemTable[(atoi(urlElements[9]))*cmeResultMemTableCols+cont]); //Free old value.
                    cmeStrConstrAppend(&(cmeResultMemTable[(atoi(urlElements[9]))*cmeResultMemTableCols+cont]),"%s",newContentRow[cont]); //Copy new value.
                }
            }
            //Create new secureDB (delete old secureDB by using replace flag):
            result=cmeMemTableToSecureDB((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,userId,orgId,orgKey,
                                         attributes,attributesData,numSecureDBAttributes,1,
                                         vacuumDB,
                                         resourceInfoText,
                                         urlElements[5], //document type
                                         urlElements[7], //documentId
                                         urlElements[3], //storageId
                                         storagePath);    //storagePath
            //End:
            cmeStrConstrAppend(responseText,"Method '%s', user '%s' updated successfully contentRow resource '%s', "
                               "within organization '%s', in storage '%s', using tableName: '%s'.<br>",method, userId, urlElements[9],
                               urlElements[1], urlElements[3], tableName);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), PUT successful.\n");
#endif
            *responseCode=200;
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
            cmeWebServiceProcessContentRowResourceFree();
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContenRowOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Warning, incorrect number of "
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentRowResourceFree();
            *responseCode=409;
            return(13);
        }
    }
    else if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), GET, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), GET, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), GET, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (result) //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(14);
            }
            result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                              numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                              &numResultRegisters,orgKey);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(15);
            }
            if (numResultRegisters<=0) //requested documentID not found
            {
                cmeStrConstrAppend(responseText,"<b>404 ERROR document resource not found.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), "
                        "no records for documentId '%s' found.\n",urlElements[7]);
#endif
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=404;
                return(0);
            }
            //Load an unprotected copy in memory of "documentId":
            result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(16);
            }
            cmeResultMemTableClean();
            cmeStrConstrAppend(&sqlQuery,"SELECT * FROM data WHERE id='%d';",atoi(urlElements[9])); //We sanitize the numeric input by using atoi().
            result=cmeSQLRows(resultDB,(const char *)sqlQuery,NULL,NULL); //Select the requested row only; no parser script.
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSQLRows error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(17);
            }
            if(!cmeResultMemTableRows)//No register was found. Construct standard response.
            {
                cmeStrConstrAppend(responseText,"Method '%s', user '%s'. Could not find row '%d', "
                                   "within organization '%s', in storage '%s', using tableName: '%s'.<br>",method, userId, atoi(urlElements[9]),
                                   urlElements[1], urlElements[3], tableName);
    #ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Get successful but row was not found.\n");
    #endif
                *responseCode=404;
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                cmeWebServiceProcessContentRowResourceFree();
                return(0);
            }
            else //Construct response table.
            {
                //Construct responseText and create response headers according to the user's outputType (optional) request:
                result=cmeConstructWebServiceTableResponse ((const char **)cmeResultMemTable, cmeResultMemTableCols, cmeResultMemTableRows,
                                                            argumentElements, url, method, urlElements[7],
                                                            responseHeaders, responseText, responseCode);
    #ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), GET successful.\n");
    #endif
                *responseCode=200;
                //We don't need to set response headers in GET; cmeConstructWebServiceTableResponse() did it for us.
                cmeWebServiceProcessContentRowResourceFree();
                return(0);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContenRowOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentRowResourceFree();
            *responseCode=409;
            return(18);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), HEAD, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), HEAD, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), HEAD, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), HEAD, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL , numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (result) //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(19);
            }
            result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                              numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                              &numResultRegisters,orgKey);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(20);
            }
            if (numResultRegisters<=0) //requested documentID not found
            {
                cmeStrConstrAppend(responseText,"<b>404 ERROR document resource not found.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), "
                        "no records for documentId '%s' found.\n",urlElements[7]);
#endif
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=404;
                return(0);
            }
            //Load an unprotected copy in memory of "documentId":
            result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(21);
            }
            cmeResultMemTableClean();
            cmeStrConstrAppend(&sqlQuery,"SELECT * FROM data WHERE id='%d';",atoi(urlElements[9])); //We sanitize the numeric input by using atoi().
            result=cmeSQLRows(resultDB,(const char *)sqlQuery,NULL,NULL); //Select the requested row only; no parser script.
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSQLRows error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(22);
            }
            //Construct response:

            if(!cmeResultMemTableRows)//No register was found.
            {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), HEAD successful but row was not found.\n");
#endif
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                *responseCode=404;
            }
            else //Register was found.
            {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), HEAD successful.\n");
#endif
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                *responseCode=200;
            }
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeWebServiceProcessContentRowResourceFree();
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContenRowOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentRowResourceFree();
            *responseCode=409;
            return(23);
        }
    }
    else if(!strcmp(method,"DELETE")) //Method = DELETE is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), DELETE, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), DELETE, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), DELETE, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), DELETE, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (result) //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(24);
            }
            result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                              numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                              &numResultRegisters,orgKey);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(25);
            }
            if (numResultRegisters<=0) //requested documentID not found
            {
                cmeStrConstrAppend(responseText,"<b>404 ERROR document resource not found.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), "
                        "no records for documentId '%s' found.\n",urlElements[7]);
#endif
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=404;
                return(0);
            }
            //Copy resourceInfo:
            cmeStrConstrAppend(&resourceInfoText,"%s",resultRegisterCols[numResultRegisterCols+cmeIDDResourcesDBDocuments_resourceInfo]);
            //Load an unprotected copy in memory of "documentId":
            result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(26);
            }
            //Get all rows and check that requested row is within bounds:
            cmeResultMemTableClean();
            cmeStrConstrAppend(&sqlQuery,"SELECT * FROM data;");
            result=cmeSQLRows(resultDB,(const char *)sqlQuery,NULL,NULL); //Select the requested row only; no parser script.
            if ((atoi(urlElements[9])>cmeResultMemTableRows)||(atoi(urlElements[9])<1)) //Error, specified row is out of range for DELETE. Stop processing.
            {
                cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                                   "contentRow is out of range for DELETE. Last register is: %d !"
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",cmeResultMemTableRows,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Warning, forbidden request, document row already exists!"
                        " Method: '%s', URL: '%s'!\n",method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=403;
                return(27);
            }
            //OK, now get all rows, excepted the one being deleted:
            cmeResultMemTableClean();
            cmeStrConstrAppend(&sqlQuery,"SELECT * FROM data WHERE id <> '%d';",atoi(urlElements[9])); //We sanitize the numeric input by using atoi().
            result=cmeSQLRows(resultDB,(const char *)sqlQuery,NULL,NULL); //Select the requested row only; no parser script.
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContenRowOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentRowResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSQLRows error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentRowResourceFree();
                *responseCode=500;
                return(28);
            }
            //Create new secureDB (delete old secureDB by using replace flag):
            result=cmeMemTableToSecureDB((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,userId,orgId,orgKey,
                                         attributes,attributesData,numSecureDBAttributes,1,
                                         vacuumDB,
                                         resourceInfoText,
                                         urlElements[5], //document type
                                         urlElements[7], //documentId
                                         urlElements[3], //storageId
                                         storagePath);    //storagePath
            //End:
            cmeStrConstrAppend(responseText,"Method '%s', user '%s' deleted successfully contentRow resource '%s', "
                               "within organization '%s', in storage '%s', using tableName: '%s'.<br>",method, userId, urlElements[9],
                               urlElements[1], urlElements[3], tableName);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), DELETE successful.\n");
#endif
            *responseCode=200;
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
            cmeWebServiceProcessContentRowResourceFree();
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContenRowOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentRowResourceFree();
            *responseCode=409;
            return(29);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), OPTIONS, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), OPTIONS, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), OPTIONS, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=2 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for document resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgContenRowOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), OPTIONS successful for storage resource."
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentRowResourceFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContenRowOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentRowResourceFree();
            *responseCode=409;
            return(30);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContenRowOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentRowResource(), Warning, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessContentRowResourceFree();
        *responseCode=405;
        return(31);
    }
}

int cmeWebServiceProcessContentColumnClass (char **responseText, char ***responseHeaders, int *responseCode,
                                            const char *url, const char **urlElements, const char **argumentElements,
                                            const char *method)
{
    (void)responseHeaders;
    (void)urlElements;
    (void)argumentElements;
    if(!strcmp(method,"OPTIONS"))
    {
        cmeStrConstrAppend(responseText,"<b>200 OK - Options for contentColumns class resources:</b><br>"
                           "%sLatest IDD version: <code>%s</code>",cmeWSMsgContentColumnOptions,
                           cmeInternalDBDefinitionsVersion);
        *responseCode=200;
        return(0);
    }
    cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                       "method is not allowed for this contentColumns class resource."
                       "METHOD: '%s' URL: '%s'."
                       "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentColumnOptions,
                       cmeInternalDBDefinitionsVersion);
    *responseCode=405;
    return(1);
}

int cmeWebServiceProcessContentColumnResource (char **responseText, char ***responseHeaders, int *responseCode,
                                               const char *url, const char **urlElements, const char **argumentElements, const char *method,
                                               const char *storagePath)
{   //IDD ver. 1.0.21 definitions.
    int cont,cont2,result;
    int columnExists=0;
    int numColsContentRow=0;
    int keyArg=0;
    int orgArg=0;
    int usrArg=0;
    int newKeyArg=0;
    int numSaveArgs=0;
    int numMatchArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    int requestedColNameIDX=0;
    int numSecureDBAttributes=0;
    int vacuumDB=0;
    sqlite3 *pDB=NULL;
    sqlite3 *resultDB=NULL;             //Result DB for unprotected DB (before parsing)
    char *orgKey=NULL;                  //requester orgKey.
    char *userId=NULL;                  //requester userId.
    char *orgId=NULL;                   //requester orgId.
    char *newOrgKey=NULL;               //requester newOrgKey (optional).
    char *salt=NULL;
    char **columnValues=NULL;           //Values to be created/updated (POST/PUT)
    char **columnNames=NULL;            //Names of columns of values to be created/updated (POST/PUT)
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char **newContentRow=NULL;          //Data of new content row (POST/PUT).
    char *dbFilePath=NULL;
    char *columnFileFullPath=NULL;      //Temp. storage for full path of columnFile for method DELETE.
    char *resourceInfoText=NULL;        //Stores the previous resourceInfo value (POST/PUT)
    char *sqlQuery=NULL;
    char *sanitizedSQLStr=NULL;         //Storage for sanitized SQL parameter to be used directly in SQL queries.
    char **resultRegisterCols=NULL;
    const int numColumns=cmeIDDResourcesDBDocumentsNumCols;            //Number of columns in corresponding resource table.
    const int numValidGETALLMatch=9;    //9 parameters + 4 (storageId,type,orgResourceId,documentId) from URL
    const int numValidPOSTSave=3;       //3 parameters + 4 (storageId,type,orgResourceId,documentId) from URL; columnFile, partMAC, totalParts, partId, columnId, lastModified are set automatically
    const char *tableName="documents";
    const char *validGETALLMatchColumns[9]={"_userId","_orgId","_resourceInfo","_columnFile",
                                            "_partHash","_totalParts","_partId","_lastModified","_columnId"};
    const char *validPOSTSaveColumns[3]={"userId","orgId"};
    const char *attributes[2]={NULL,NULL};
    const char *attributesData[2]={NULL,NULL};
    #define cmeWebServiceProcessContentColumnResourceFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey); \
            cmeFree(dbFilePath); \
            cmeFree(salt); \
            cmeFree(columnFileFullPath); \
            cmeFree(resourceInfoText); \
            cmeFree(sqlQuery); \
            cmeFree(sanitizedSQLStr); \
            if ((newContentRow)&&(numColsContentRow)) \
            { \
               for (cont=0;cont<numColsContentRow;cont++) \
               { \
                   cmeFree(newContentRow[cont]); \
               } \
               cmeFree(newContentRow); \
            } \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValues) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValues[cont]); \
               } \
               cmeFree(columnValues); \
            } \
            if (columnNames) \
            { \
               for (cont=0;cont<numColumns;cont++) \
               { \
                   cmeFree(columnNames[cont]); \
               } \
               cmeFree(columnNames); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0;cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0;cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
            if (resultDB) \
            { \
                cmeDBClose(resultDB); \
                resultDB=NULL; \
            } \
        } while (0); //Local free() macro.

    //Check that type =file.csv (we can only work with this type of document resources):
    if (strcmp("file.csv",urlElements[5])) //Error, file type is invalid. Abort
    {
        cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                           "File type must be 'file.csv' "
                           "METHOD: '%s' URL: '%s'."
                            "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentColumnOptions,
                            cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), Warning, forbidden request, file type != 'file.csv'!"
                " Method: '%s', URL: '%s'!\n",method,url);
#endif
        cmeWebServiceProcessContentColumnResourceFree();
        *responseCode=403;
        return(1);
    }
    numSecureDBAttributes=cmeWebServiceBuildSecureDBAttributes(argumentElements,attributes,attributesData,2);
    vacuumDB=cmeWebServiceGetBooleanParam(argumentElements,"vacuumDB",0);
    result=cmeSanitizeStrForSQL(urlElements[9],&sanitizedSQLStr); //Sanitize contentColumn name so that it can be used in SQL queries.
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), Sanitized (i.e. doubled single quotes) of "
            "content column parameter: '%s' -> '%s'.\n",urlElements[9],sanitizedSQLStr);
#endif
    columnValues=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnNames=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, columns 1 to 11 (POST/PUT).
    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store organization resource information, column values to match (GET/PUT).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValues[cont]=NULL;
       columnNames[cont]=NULL;
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    if(!strcmp(method,"POST")) //Method = POST is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValues[0]),"%s",urlElements[1]); //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);
        cmeStrConstrAppend(&(columnNames[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValues[1]),"%s",urlElements[3]); //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);
        cmeStrConstrAppend(&(columnNames[1]),"storageId");
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValues[2]),"%s",urlElements[5]); //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);
        cmeStrConstrAppend(&(columnNames[2]),"type");
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValues[3]),"%s",urlElements[7]); //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);
        cmeStrConstrAppend(&(columnNames[3]),"documentId");
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
        //Mandatory, calculated values. For 'file.csv' We will calculate these values in cmeCSVFileToSecureDB(). Therefore they aren't included in the match list:
        cmeStrConstrAppend(&(columnValues[4]),"");
        cmeStrConstrAppend(&(columnNames[4]),"columnFile");
        cmeStrConstrAppend(&(columnValues[5]),"");
        cmeStrConstrAppend(&(columnNames[5]),"partMAC");
        cmeStrConstrAppend(&(columnValues[6]),"");
        cmeStrConstrAppend(&(columnNames[6]),"totalParts");
        cmeStrConstrAppend(&(columnValues[7]),"");
        cmeStrConstrAppend(&(columnNames[7]),"partId");
        cmeStrConstrAppend(&(columnValues[8]),"");
        cmeStrConstrAppend(&(columnNames[8]),"lastModified");
        cmeStrConstrAppend(&(columnValues[9]),"");
        cmeStrConstrAppend(&(columnNames[9]),"columnId");

#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), POST, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), POST, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), POST, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), POST, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        numSaveArgs=10;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, validPOSTSaveColumns, numValidGETALLMatch,numValidPOSTSave,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(numSaveArgs==12)&&(keyArg)&&(usrArg)&&(orgArg)) //Command POST successful.
        {
            //Verify that contentColumn != "id":
            if (!strcmp(urlElements[9],"id")) //Error, Column id can't be "id"
            {
                cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                                   "contentColumn  '%s' is reserved!"
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",urlElements[9],method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), Warning, forbidden request, document column already exists!"
                        " Method: '%s', URL: '%s'!\n",method,url);
#endif
                cmeWebServiceProcessContentColumnResourceFree();
                *responseCode=403;
                return(2);
            }
            result=cmeDBOpen(dbFilePath,&pDB);
            if (result) //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessContentColumnResourceFree();
                *responseCode=500;
                return(3);
            }
            result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                              numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                              &numResultRegisters,orgKey);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentClassFree();
                *responseCode=500;
                return(4);
            }
            if (numResultRegisters<=0) //requested documentID not found -> create new, empty document with 1 column.
            {
                //Create new empty table data structure with columns id and requested contentColumn
                cmeResultMemTableClean();
                cmeResultMemTable=(char **)malloc(sizeof(char *)*1); //We just need the new column name. No Id column necessary.
                cmeResultMemTableRows=0;
                cmeResultMemTableCols=1;
                cmeResultMemTable[0]=NULL;
                cmeStrConstrAppend(&(cmeResultMemTable[0]),"%s",urlElements[9]);
                //Create new secureDB:
                result=cmeMemTableToSecureDB((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,userId,orgId,orgKey,
                                             attributes,attributesData,numSecureDBAttributes,1,
                                             vacuumDB,
                                             resourceInfoText,
                                             urlElements[5], //document type
                                             urlElements[7], //documentId
                                             urlElements[3], //storageId
                                             storagePath);    //storagePath
                //End:
                cmeStrConstrAppend(responseText,"Method '%s', user '%s' created successfully contentColumn resource '%s' and documentId '%s', "
                                   "within organization '%s', in storage '%s', using tableName: '%s'.<br>",method, userId, urlElements[9],
                                   urlElements[7],urlElements[1],urlElements[3],tableName);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), POST successful.\n");
#endif
                *responseCode=201;
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                cmeWebServiceProcessContentColumnResourceFree();
                return(0);
            }
            else //Document exists -> add new column with empty row values.
            {
                //Copy resourceInfo:
                cmeStrConstrAppend(&resourceInfoText,"%s",resultRegisterCols[numResultRegisterCols+cmeIDDResourcesDBDocuments_resourceInfo]);
                //Load an unprotected copy in memory of "documentId":
                result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                    cmeWebServiceProcessContentClassFree();
                    *responseCode=500;
                    return(5);
                }
                //Verify that content Column doesn't exist already:
                cmeResultMemTableClean();
                result=cmeMemTableWithTableColumnNames(resultDB,"data"); //Get just the column names in the cmeResultMemTable.
                for (cont=0;cont<cmeResultMemTableCols;cont++)
                {
                    if (!strcmp(cmeResultMemTable[cont],urlElements[9]))
                    {
                        columnExists=1;
                    }
                }
                if (columnExists) //Error, column exists already
                {
                    cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                                       "contentColumn  '%s' already exists!"
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",urlElements[9],method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), Warning, forbidden request, document column already exists!"
                            " Method: '%s', URL: '%s'!\n",method,url);
#endif
                    cmeWebServiceProcessContentColumnResourceFree();
                    *responseCode=403;
                    return(6);
                }
                //Add new column:
                cmeFree(sqlQuery);
                cmeResultMemTableClean();
                cmeStrConstrAppend(&sqlQuery,"BEGIN TRANSACTION; ALTER TABLE data ADD COLUMN '%s' TEXT NOT NULL DEFAULT ''; COMMIT;",sanitizedSQLStr); //Note that we pass column single quoted and not double quoted for sanitization to work. SQLITE converts literals to identifiers when needed.
                result=cmeSQLRows(resultDB,(const char *)sqlQuery,NULL,NULL); //Add new column.
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeSQLRows error!\n",result,method,url);
#endif
                    cmeWebServiceProcessContentClassFree();
                    *responseCode=500;
                    return(7);
                }
                //Load whole table with new column:
                cmeResultMemTableClean();
                result=cmeSQLRows(resultDB,"SELECT * FROM data;",NULL,NULL); //Select all data; no parser script.
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeSQLRows error!\n",result,method,url);
#endif
                    cmeWebServiceProcessContentClassFree();
                    *responseCode=500;
                    return(8);
                }
                if ((cmeResultMemTableCols==0)&&(cmeResultMemTableRows==0))//0 Rows tables return 0 columns in SQLite. To be sure we use an SQLite pragma to retrieve column names only.
                {
                    //Call function to get just the column names in the cmeResultMemTable:
                    result=cmeMemTableWithTableColumnNames(resultDB,"data");
                }
                //Create new secureDB (delete old secureDB if it exists):
                result=cmeMemTableToSecureDB((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,userId,orgId,orgKey,
                                             attributes,attributesData,numSecureDBAttributes,1,
                                             vacuumDB,
                                             resourceInfoText,
                                             urlElements[5], //document type
                                             urlElements[7], //documentId
                                             urlElements[3], //storageId
                                             storagePath);    //storagePath
                //End:
                cmeStrConstrAppend(responseText,"Method '%s', user '%s' created successfully contentColumn resource '%s', "
                                   "within organization '%s', in storage '%s', using tableName: '%s'.<br>",method, userId, urlElements[9],
                                   urlElements[1], urlElements[3], tableName);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), POST successful.\n");
#endif
                *responseCode=201;
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                cmeWebServiceProcessContentColumnResourceFree();
                return(0);
            }
        }
        else //Error, invalid number of arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentColumnOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), Warning, incorrect number of "
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif

            cmeWebServiceProcessContentColumnResourceFree();
            *responseCode=409;
            return(9);
        }
    }
    else if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), GET, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), GET, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), GET, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), GET, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (result) //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessContentColumnResourceFree();
                *responseCode=500;
                return(10);
            }
            result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                              numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                              &numResultRegisters,orgKey);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentClassFree();
                *responseCode=500;
                return(11);
            }
            if (numResultRegisters<=0) //requested documentID not found
            {
                cmeStrConstrAppend(responseText,"<b>404 ERROR document resource not found.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), "
                        "no records for documentId '%s' found.\n",urlElements[7]);
#endif
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                cmeWebServiceProcessContentColumnResourceFree();
                *responseCode=404;
                return(0);
            }
            else //Document exists -> GET requested column.
            {
                //Load an unprotected copy in memory of "documentId":
                result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                    cmeWebServiceProcessContentClassFree();
                    *responseCode=500;
                    return(12);
                }
                //Verify that content Column exists:
                cmeResultMemTableClean();
                result=cmeMemTableWithTableColumnNames(resultDB,"data"); //Get just the column names in the cmeResultMemTable.
                for (cont=0;cont<cmeResultMemTableCols;cont++) //flag and record index of the column to delete.
                {
                    if (!strcmp(cmeResultMemTable[cont],urlElements[9]))
                    {
                        requestedColNameIDX=cont;
                        columnExists=1;
                    }
                }
                if (!columnExists) //Error, column does not exist
                {
                    cmeStrConstrAppend(responseText,"<b>404 ERROR contentColumn resource not found.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), "
                            "contentColumn '%s' not found.\n",urlElements[9]);
#endif
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                    cmeWebServiceProcessContentColumnResourceFree();
                    *responseCode=404;
                    return(0);
                }
                //GET column:
                ///NOTE: The following approach of selecting specific columns does not work. sqlite_column_text() returns incorrect values when columns names have single quotes in them.
                /**   cmeStrConstrAppend(&sqlQuery,"SELECT "); //Note that SQLITE currently does not support ALTER TABLE DELETE, so we consruct a SELECT statement that omits the requested contentColumn.
                for (cont=0;cont<cmeResultMemTableCols;cont++)
                {
                    if (strcmp(cmeResultMemTable[cont],urlElements[9])) //Add all column names except requested colName to be deleted.
                    {
                        if (cont>0)
                        {
                            cmeStrConstrAppend(&sqlQuery,",");
                        }
                        cmeFree(sanitizedSQLStr);
                        cmeSanitizeStrForSQL(cmeResultMemTable[cont],&sanitizedSQLStr);
                        cmeStrConstrAppend(&sqlQuery,"'%s' AS C_%d",sanitizedSQLStr,cont); //Add to select statement.
                    }
                }
                cmeStrConstrAppend(&sqlQuery," FROM data;"); **/
                cmeFree(sqlQuery);
                cmeStrConstrAppend(&sqlQuery,"SELECT * FROM data;");
                cmeResultMemTableClean();
                result=cmeSQLRows(resultDB,(const char *)sqlQuery,NULL,NULL); //Add new column.
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeSQLRows error!\n",result,method,url);
#endif
                    cmeWebServiceProcessContentClassFree();
                    *responseCode=500;
                    return(13);
                }
                if ((cmeResultMemTableCols==0)&&(cmeResultMemTableRows==0))//0 Rows tables return 0 columns in SQLite. To be sure we use an SQLite pragma to retrieve column names only.
                {
                    //Call function to get just the column names in the cmeResultMemTable:
                    result=cmeMemTableWithTableColumnNames(resultDB,"data");
                    //Delete all columns except id & the requested column:
                    if (requestedColNameIDX!=1) //If requested column is not at idx 1 Free idx 1 and point idx1 to requested column.
                    {
                        cmeFree(cmeResultMemTable[1]);
                        cmeStrConstrAppend(&(cmeResultMemTable[1]),"%s",cmeResultMemTable[requestedColNameIDX]);
                    }
                    for(cont=2;cont<cmeResultMemTableCols;cont++) //Free all remaining columns.
                    {
                        cmeFree(cmeResultMemTable[cont]);
                    }
                    cmeResultMemTableCols=2; //Adjust columns (just id and requested column);
                    cmeResultMemTable=(char **)realloc(cmeResultMemTable,sizeof(char *)*(cmeResultMemTableCols*(cmeResultMemTableRows+1))); //Crop MemTable.
                }
                else //Otherwise, we need to eliminate manually column values in cmeResultMemTable
                {
                    if (cmeResultMemTableCols>2) //We process the table only if there are > 2 columns. If there are only to columns we are done!.
                    {
                        //GET the requested contentColumn.
                        //Process first row (column names):
                        if (requestedColNameIDX!=1) //If requested column is not at idx 1 Free idx 1 and point idx1 to requested column.
                        {
                            cmeFree(cmeResultMemTable[1]);
                            cmeStrConstrAppend(&(cmeResultMemTable[1]),"%s",cmeResultMemTable[requestedColNameIDX]);
                        }
                        //Process the rest of the rows:
                        cont2=2; //Pointer to next dest IDX.
                        for (cont=1;cont<=cmeResultMemTableRows;cont++) //Process all rows.
                        {
                            //Free dest idx; copy row id there:
                            cmeFree(cmeResultMemTable[cont2]);
                            cmeStrConstrAppend(&(cmeResultMemTable[cont2]),"%s",cmeResultMemTable[cmeResultMemTableCols*cont]);
                            cont2++; //Increment dest. pointer.
                            //Free dest idx; copy requested column there:
                            cmeFree(cmeResultMemTable[cont2]);
                            cmeStrConstrAppend(&(cmeResultMemTable[cont2]),"%s",cmeResultMemTable[cmeResultMemTableCols*cont+requestedColNameIDX]);
                            cont2++; //Increment dest. pointer.
                        }
                        //Free all remaining idxs:
                        for (cont=cont2;cont<cmeResultMemTableCols*(cmeResultMemTableRows+1);cont++)
                        {
                            cmeFree(cmeResultMemTable[cont]);
                        }
                        cmeResultMemTableCols=2; //Adjust columns (just id and requested column);
                        cmeResultMemTable=(char **)realloc(cmeResultMemTable,sizeof(char *)*(cmeResultMemTableCols*(cmeResultMemTableRows+1))); //Crop MemTable.
                    }
                }
                //Construct responseText and create response headers according to the user's outputType (optional) request:
                result=cmeConstructWebServiceTableResponse ((const char **)cmeResultMemTable, cmeResultMemTableCols, cmeResultMemTableRows,
                                                            argumentElements, url, method, urlElements[7],
                                                            responseHeaders, responseText, responseCode);
    #ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), GET successful.\n");
    #endif
                *responseCode=200;
                //We don't need to set response headers in GET; cmeConstructWebServiceTableResponse() did it for us.
                cmeWebServiceProcessContentColumnResourceFree();
                return(0);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentColumnOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentColumnResourceFree();
            *responseCode=409;
            return(14);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), HEAD, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), HEAD, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), HEAD, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), HEAD, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL , numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=1 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (result) //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessContentColumnResourceFree();
                *responseCode=500;
                return(15);
            }
            result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                              numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                              &numResultRegisters,orgKey);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentClassFree();
                *responseCode=500;
                return(16);
            }
            if (numResultRegisters<=0) //requested documentID not found
            {
                cmeStrConstrAppend(responseText,"<b>404 ERROR document resource not found.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), "
                        "no records for documentId '%s' found.\n",urlElements[7]);
#endif
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                cmeWebServiceProcessContentColumnResourceFree();
                *responseCode=404;
                return(0);
            }
            //Load an unprotected copy in memory of "documentId":
            result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentClassFree();
                *responseCode=500;
                return(17);
            }
            cmeResultMemTableClean();
            result=cmeMemTableWithTableColumnNames(resultDB,"data");
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeSQLRows error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentColumnResourceFree();
                *responseCode=500;
                return(18);
            }
            columnExists=0;
            for (cont=0;cont<cmeResultMemTableCols;cont++)
            {
                if (!strcmp(cmeResultMemTable[cont],urlElements[9]))
                {
                    columnExists=1;
                    break;
                }
            }
            //Construct response:
            if(!columnExists)//No column was found.
            {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), HEAD successful but column was not found.\n");
#endif
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                *responseCode=404;
            }
            else //Register was found.
            {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), HEAD successful.\n");
#endif
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                *responseCode=200;
            }
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeWebServiceProcessContentColumnResourceFree();
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentColumnOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentColumnResourceFree();
            *responseCode=409;
            return(19);
        }
    }
    else if(!strcmp(method,"DELETE")) //Method = DELETE is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), DELETE, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), DELETE, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), DELETE, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), DELETE, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=1 Match)
        {
            //Verify that contentColumn != "id":
            if (!strcmp(urlElements[9],"id")) //Error, Column id can't be "id"
            {
                cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                                   "contentColumn  '%s' is reserved!"
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",urlElements[9],method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), Warning, forbidden request, document column already exists!"
                        " Method: '%s', URL: '%s'!\n",method,url);
#endif
                cmeWebServiceProcessContentColumnResourceFree();
                *responseCode=403;
                return(20);
            }
            result=cmeDBOpen(dbFilePath,&pDB);
            if (result) //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'!\n",result,method,url);
#endif
                cmeWebServiceProcessContentColumnResourceFree();
                *responseCode=500;
                return(21);
            }
            result=cmeGetUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                              numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                              &numResultRegisters,orgKey);
            if (result) //Error
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters() error!\n",result,method,url);
#endif
                cmeWebServiceProcessContentClassFree();
                *responseCode=500;
                return(22);
            }
            if (numResultRegisters<=0) //requested documentID not found.
            {
                cmeStrConstrAppend(responseText,"<b>404 ERROR document resource not found.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), "
                        "no records for documentId '%s' found.\n",urlElements[7]);
#endif
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                cmeWebServiceProcessContentColumnResourceFree();
                *responseCode=404;
                return(0);
            }
            else //Document exists -> delete requested column.
            {
                //Copy resourceInfo:
                cmeStrConstrAppend(&resourceInfoText,"%s",resultRegisterCols[numResultRegisterCols+cmeIDDResourcesDBDocuments_resourceInfo]);
                //Load an unprotected copy in memory of "documentId":
                result=cmeSecureDBToMemDB (&resultDB,pDB,urlElements[7],orgKey,storagePath);
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeSecureDBToMemDB() error!\n",result,method,url);
#endif
                    cmeWebServiceProcessContentClassFree();
                    *responseCode=500;
                    return(23);
                }
                //Verify that content Column exists:
                cmeResultMemTableClean();
                result=cmeMemTableWithTableColumnNames(resultDB,"data"); //Get just the column names in the cmeResultMemTable.
                for (cont=0;cont<cmeResultMemTableCols;cont++) //flag and record index of the column to delete.
                {
                    if (!strcmp(cmeResultMemTable[cont],urlElements[9]))
                    {
                        requestedColNameIDX=cont;
                        columnExists=1;
                    }
                }
                if (!columnExists) //Error, column does not exist
                {
                    cmeStrConstrAppend(responseText,"<b>404 ERROR contentColumn resource not found.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                    fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), "
                            "contentColumn '%s' not found.\n",urlElements[9]);
#endif
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                    cmeWebServiceProcessContentColumnResourceFree();
                    *responseCode=404;
                    return(0);
                }
                //Delete column:
                ///NOTE: The following approach of selecting specific columns does not work. sqlite_column_text() returns incorrect values when columns names have single quotes in them.
                /**   cmeStrConstrAppend(&sqlQuery,"SELECT "); //Note that SQLITE currently does not support ALTER TABLE DELETE, so we consruct a SELECT statement that omits the requested contentColumn.
                for (cont=0;cont<cmeResultMemTableCols;cont++)
                {
                    if (strcmp(cmeResultMemTable[cont],urlElements[9])) //Add all column names except requested colName to be deleted.
                    {
                        if (cont>0)
                        {
                            cmeStrConstrAppend(&sqlQuery,",");
                        }
                        cmeFree(sanitizedSQLStr);
                        cmeSanitizeStrForSQL(cmeResultMemTable[cont],&sanitizedSQLStr);
                        cmeStrConstrAppend(&sqlQuery,"'%s' AS C_%d",sanitizedSQLStr,cont); //Add to select statement.
                    }
                }
                cmeStrConstrAppend(&sqlQuery," FROM data;"); **/
                cmeFree(sqlQuery);
                cmeStrConstrAppend(&sqlQuery,"SELECT * FROM data;");
                cmeResultMemTableClean();
                result=cmeSQLRows(resultDB,(const char *)sqlQuery,NULL,NULL); //Add new column.
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgContentColumnOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeSQLRows error!\n",result,method,url);
#endif
                    cmeWebServiceProcessContentClassFree();
                    *responseCode=500;
                    return(24);
                }
                if ((cmeResultMemTableCols==0)&&(cmeResultMemTableRows==0))//0 Rows tables return 0 columns in SQLite. To be sure we use an SQLite pragma to retrieve column names only.
                {
                    //Call function to get just the column names in the cmeResultMemTable:
                    result=cmeMemTableWithTableColumnNames(resultDB,"data");
                    if (cmeResultMemTableCols<=2)//Deleting last column? then we must delete the whole document
                    {
                        //Delete the whole document:
                        result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                             numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                             &numResultRegisters,orgKey);
                        if (result) //Error
                        {
                            *responseCode=500;
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), DELETE error!, "
                                    "cmeDeleteUnporotectDBRegisters error!\n");
#endif
                            cmeWebServiceProcessDocumentResourceFree();
                            return(25);
                        }
                        if (numResultRegisters) // Deleted 1 or + register(s)
                        {
                            *responseCode=200;
#ifdef DEBUG
                            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), DELETE successful.\n");
#endif
                            for (cont=1;cont<=numResultRegisters;cont++) //Delete corresponding column files. Skip headers (cont=1).
                            {
                                cmeStrConstrAppend(&columnFileFullPath,"%s%s",storagePath,resultRegisterCols[cont*cmeIDDResourcesDBDocumentsNumCols+cmeIDDResourcesDBDocuments_columnFile]);
                                result=cmeFileOverwriteAndDelete(columnFileFullPath);
                                if (result) //Error
                                {
#ifdef ERROR_LOG
                                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), cmeFileOverwriteAndDelete() error, "
                                            "can't remove columnId file: '%s' !\n",columnFileFullPath);
#endif
                                }
                                cmeFree(columnFileFullPath); //Clear for next iteration.
                            }
                        }
                        else // Deleted 0 registers
                        {
                            *responseCode=404;
#ifdef DEBUG
                            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), DELETE successful, but resource not found.\n");
#endif
                        }
                        cmeStrConstrAppend(responseText,"<p>Deleted documentId '%s'; registers: %d</p><br>",urlElements[7],numResultRegisters);
                        cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                        cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                        cmeWebServiceProcessDocumentResourceFree();
                        return(0);
                    }
                    cmeFree(cmeResultMemTable[requestedColNameIDX]); //Delete column in every row.
                    for(cont=requestedColNameIDX;cont<cmeResultMemTableCols;cont++)
                    {
                        if ((cont+1)<cmeResultMemTableCols) //If not the last element, shif left.
                        {
                            cmeResultMemTable[cont]=cmeResultMemTable[cont+1];
                        }
                        else
                        {
                            cmeResultMemTable[cont]=NULL;
                        }
                    }
                    cmeResultMemTableCols--; //Decrement number of columns to eliminate deleted column.
                    cmeResultMemTable=(char **)realloc(cmeResultMemTable,sizeof(char *)*(cmeResultMemTableCols*(cmeResultMemTableRows+1))); //Crop MemTable.
                }
                else //Otherwise, we need to eliminate manually column values in cmeResultMemTable
                {
                    if (cmeResultMemTableCols<=2)//Deleting last column? then we must delete the whole document
                    {
                        //Delete the whole document:
                        result=cmeDeleteUnprotectDBRegisters(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                             numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                             &numResultRegisters,orgKey);
                        if (result) //Error
                        {
                            *responseCode=500;
                            cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                               "Internal server error number '%d'."
                                               "METHOD: '%s' URL: '%s'."
                                                "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgDocumentOptions,
                                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), DELETE error!, "
                                    "cmeDeleteUnporotectDBRegisters error!\n");
#endif
                            cmeWebServiceProcessDocumentResourceFree();
                            return(26);
                        }
                        if (numResultRegisters) // Deleted 1 or + register(s)
                        {
                            *responseCode=200;
#ifdef DEBUG
                            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), DELETE successful.\n");
#endif
                            for (cont=1;cont<=numResultRegisters;cont++) //Delete corresponding column files. Skip headers (cont=1).
                            {
                                cmeStrConstrAppend(&columnFileFullPath,"%s%s",storagePath,resultRegisterCols[cont*cmeIDDResourcesDBDocumentsNumCols+cmeIDDResourcesDBDocuments_columnFile]);
                                result=cmeFileOverwriteAndDelete(columnFileFullPath);
                                if (result) //Error
                                {
#ifdef ERROR_LOG
                                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentColumnResource(), cmeFileOverwriteAndDelete() error, "
                                            "can't remove columnId file: '%s' !\n",columnFileFullPath);
#endif
                                }
                                cmeFree(columnFileFullPath); //Clear for next iteration.
                            }
                        }
                        else // Deleted 0 registers
                        {
                            *responseCode=404;
#ifdef DEBUG
                            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), DELETE successful, but resource not found.\n");
#endif
                        }
                        cmeStrConstrAppend(responseText,"<p>Deleted documentId; registers: %d</p><br>",numResultRegisters);
                        cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                        cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                        cmeWebServiceProcessDocumentResourceFree();
                        return(0);
                    }
                    //Delete the requested contentColumn.
                    for (cont=0;cont<=cmeResultMemTableRows;cont++) //Process all rows.
                    {
                        cmeFree(cmeResultMemTable[cont*cmeResultMemTableCols-cont+requestedColNameIDX]); //Delete column in every row.
                        for(cont2=cont*cmeResultMemTableCols-cont+requestedColNameIDX;
                            cont2<cmeResultMemTableCols*(cmeResultMemTableRows+1)-cont;cont2++)
                        {
                            if ((cont2+1)<cmeResultMemTableCols*(cmeResultMemTableRows+1)-cont) //If not the last element, shif left.
                            {
                                cmeResultMemTable[cont2]=cmeResultMemTable[cont2+1];
                            }
                            else
                            {
                                cmeResultMemTable[cont2]=NULL;
                            }
                        }
                    }
                    cmeResultMemTableCols--; //Decrement number of columns to eliminate deleted column.
                    cmeResultMemTable=(char **)realloc(cmeResultMemTable,sizeof(char *)*(cmeResultMemTableCols*(cmeResultMemTableRows+1))); //Crop MemTable.
                }
                //Create new secureDB (delete old secureDB if it exists):
                result=cmeMemTableToSecureDB((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,userId,orgId,orgKey,
                                             attributes,attributesData,numSecureDBAttributes,1,
                                             vacuumDB,
                                             resourceInfoText,
                                             urlElements[5], //document type
                                             urlElements[7], //documentId
                                             urlElements[3], //storageId
                                             storagePath);    //storagePath
                //End:
                cmeStrConstrAppend(responseText,"Method '%s', user '%s' deleted successfully contentColumn resource '%s', "
                                   "within document '%s', in storage '%s', using tableName: '%s'.<br>",method, userId, urlElements[9],
                                   urlElements[7], urlElements[3], tableName);
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), DELETE successful.\n");
#endif
                *responseCode=200;
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
                cmeWebServiceProcessContentColumnResourceFree();
                return(0);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentColumnOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentColumnResourceFree();
            *responseCode=409;
            return(27);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        //Mandatory values by user:
        cmeStrConstrAppend(&(columnValuesToMatch[0]),"%s",urlElements[1]);  //We also ignore the argument "orgResourceId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[0]),"orgResourceId");
        cmeStrConstrAppend(&(columnValuesToMatch[1]),"%s",urlElements[3]);  //We also ignore the argument "storageId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[1]),"storageId");
        cmeStrConstrAppend(&(columnValuesToMatch[2]),"%s",urlElements[5]);  //We also ignore the argument "type" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[2]),"type");
        cmeStrConstrAppend(&(columnValuesToMatch[3]),"%s",urlElements[7]);  //We also ignore the argument "documentId" and use the resource defined within the URL!
        cmeStrConstrAppend(&(columnNamesToMatch[3]),"documentId");
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), OPTIONS, column orgResourceId: '%s'.\n",
                urlElements[1]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), OPTIONS, column storageId: '%s'.\n",
                urlElements[3]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), OPTIONS, column type: '%s'.\n",
                urlElements[5]);
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), OPTIONS, column documentId: '%s'.\n",
                urlElements[7]);
#endif
        numMatchArgs=4;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, columnValues, columnNames, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=4)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId userId and >=2 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for document resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgContentColumnOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), OPTIONS successful for storage resource."
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentColumnResourceFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentColumnOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), Warning, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessContentColumnResourceFree();
            *responseCode=409;
            return(28);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgContentColumnOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessContentColumnResource(), Warning, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessContentColumnResourceFree();
        *responseCode=405;
        return(29);
    }
}

static int cmeWebServiceDBBrowseRequireArgs(const char **argumentElements, const char **userId,
                                            const char **orgId, const char **orgKey)
{
    *userId=NULL;
    *orgId=NULL;
    *orgKey=NULL;
    cmeFindInArgPairList(argumentElements,"userId",userId);
    cmeFindInArgPairList(argumentElements,"orgId",orgId);
    cmeFindInArgPairList(argumentElements,"orgKey",orgKey);
    return(!((*userId)&&(*orgId)&&(*orgKey)));
}

static int cmeWebServiceDBBrowseIsValidTable(const char *tableName)
{
    return((tableName)&&((!strcmp(tableName,"data"))||(!strcmp(tableName,"meta"))));
}

static int cmeWebServiceDBBrowseIsPositiveInteger(const char *value)
{
    const char *ptr=value;
    if ((!ptr)||(!*ptr)||(*ptr=='0'))
    {
        return(0);
    }
    while (*ptr)
    {
        if (!isdigit((unsigned char)*ptr))
        {
            return(0);
        }
        ptr++;
    }
    return(1);
}

static int cmeWebServiceDBBrowseAppendCell(int idx, const char *value)
{
    cmeResultMemTable[idx]=NULL;
    return(cmeStrConstrAppend(&(cmeResultMemTable[idx]),"%s",value?value:""));
}

static int cmeWebServiceDBBrowseInitTable(int cols, int rows)
{
    int cont;
    cmeResultMemTableClean();
    cmeResultMemTableCols=cols;
    cmeResultMemTableRows=rows;
    cmeResultMemTable=(char **)malloc(sizeof(char *)*cols*(rows+1));
    if (!cmeResultMemTable)
    {
        cmeResultMemTableCols=0;
        cmeResultMemTableRows=0;
        return(1);
    }
    for (cont=0;cont<cols*(rows+1);cont++)
    {
        cmeResultMemTable[cont]=NULL;
    }
    return(0);
}

static int cmeWebServiceDBBrowseDocumentExists(sqlite3 *resourcesDB, const char *orgResourceId,
                                               const char *storageId, const char *documentId,
                                               const char *orgKey, char ***resultRegisterCols,
                                               int *numResultRegisterCols, int *numResultRegisters)
{
    const char *columnNamesToMatch[4]={"orgResourceId","storageId","type","documentId"};
    const char *columnValuesToMatch[4]={orgResourceId,storageId,"file.csv",documentId};
    return(cmeGetUnprotectDBRegisters(resourcesDB,"documents",columnNamesToMatch,columnValuesToMatch,4,
                                      resultRegisterCols,numResultRegisterCols,numResultRegisters,orgKey));
}

int cmeWebServiceProcessDBBrowseResource (char **responseText, char ***responseHeaders, int *responseCode,
                                          const char *url, const char **urlElements, int numUrlElements,
                                          const char **argumentElements, const char *method,
                                          const char *storagePath)
{
    int cont,cont2,result=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    int tableRows=0;
    int tableCols=0;
    int requestedCol=-1;
    int outRows=0;
    int dest=0;
    sqlite3 *resourcesDB=NULL;
    sqlite3 *memDB=NULL;
    char *dbFilePath=NULL;
    char *sqlQuery=NULL;
    char **resultRegisterCols=NULL;
    char **rawTable=NULL;
    const char *userId=NULL;
    const char *orgId=NULL;
    const char *orgKey=NULL;
    const char *dbName=(numUrlElements>=6)?urlElements[5]:NULL;
    const char *dbTable=(numUrlElements>=8)?urlElements[7]:NULL;
    const char *tableRow=(numUrlElements==10 && !strcmp(urlElements[8],"tableRows"))?urlElements[9]:NULL;
    const char *tableColumn=(numUrlElements==10 && !strcmp(urlElements[8],"tableColumns"))?urlElements[9]:NULL;
    const char *docMatchColumns[3]={"orgResourceId","storageId","type"};
    const char *docMatchValues[3]={urlElements[1],urlElements[3],"file.csv"};
    #define cmeWebServiceProcessDBBrowseResourceFree() \
        do { \
            cmeFree(dbFilePath); \
            cmeFree(sqlQuery); \
            if (rawTable) \
            { \
                cmeMemTableFinal(rawTable); \
                rawTable=NULL; \
            } \
            if (resultRegisterCols) \
            { \
                for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
                { \
                    cmeFree(resultRegisterCols[cont]); \
                } \
                cmeFree(resultRegisterCols); \
                resultRegisterCols=NULL; \
            } \
            if (resourcesDB) \
            { \
                cmeDBClose(resourcesDB); \
                resourcesDB=NULL; \
            } \
            if (memDB) \
            { \
                cmeDBClose(memDB); \
                memDB=NULL; \
            } \
        } while (0)

    if ((strcmp(method,"GET"))&&(strcmp(method,"HEAD"))&&(strcmp(method,"OPTIONS")))
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br>"
                           "Only GET, HEAD and OPTIONS are supported for DB browsing resources."
                           "METHOD: '%s' URL: '%s'. Latest IDD version: <code>%s</code>",
                           method,url,cmeInternalDBDefinitionsVersion);
        *responseCode=405;
        return(1);
    }
    if (!strcmp(method,"OPTIONS"))
    {
        cmeStrConstrAppend(responseText,"<b>200 OK - Options for DB browsing resources:</b><br>"
                           "Supported methods: GET HEAD OPTIONS. Scope: registered file.csv secure document databases only."
                           " Latest IDD version: <code>%s</code>",cmeInternalDBDefinitionsVersion);
        *responseCode=200;
        return(0);
    }
    if (cmeWebServiceDBBrowseRequireArgs(argumentElements,&userId,&orgId,&orgKey))
    {
        cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments.</b><br>"
                           "Required arguments: userId, orgId and orgKey. METHOD: '%s' URL: '%s'."
                           " Latest IDD version: <code>%s</code>",method,url,cmeInternalDBDefinitionsVersion);
        *responseCode=409;
        return(2);
    }
    if ((strcmp(orgId,urlElements[1]))||(!cmeStrSafeEq(orgId,urlElements[1])))
    {
        cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                           "orgId must match the organization in the URL. METHOD: '%s' URL: '%s'."
                           " Latest IDD version: <code>%s</code>",method,url,cmeInternalDBDefinitionsVersion);
        *responseCode=403;
        return(3);
    }
    if ((numUrlElements>=7)&&(strcmp(urlElements[6],"dbTables")))
    {
        *responseCode=404;
        cmeStrConstrAppend(responseText,"<b>404 ERROR Resource not found.</b><br>"
                           "METHOD: '%s' URL: '%s'. Latest IDD version: <code>%s</code>",
                           method,url,cmeInternalDBDefinitionsVersion);
        return(4);
    }
    if ((numUrlElements>=9)&&(strcmp(urlElements[8],"tableRows"))&&(strcmp(urlElements[8],"tableColumns")))
    {
        *responseCode=404;
        cmeStrConstrAppend(responseText,"<b>404 ERROR Resource not found.</b><br>"
                           "METHOD: '%s' URL: '%s'. Latest IDD version: <code>%s</code>",
                           method,url,cmeInternalDBDefinitionsVersion);
        return(5);
    }
    if ((dbTable)&&(!cmeWebServiceDBBrowseIsValidTable(dbTable)))
    {
        *responseCode=404;
        cmeStrConstrAppend(responseText,"<b>404 ERROR table resource not found.</b><br>"
                           "Only data and meta tables are exposed. METHOD: '%s' URL: '%s'."
                           " Latest IDD version: <code>%s</code>",method,url,cmeInternalDBDefinitionsVersion);
        return(6);
    }
    if ((tableRow)&&(!cmeWebServiceDBBrowseIsPositiveInteger(tableRow)))
    {
        *responseCode=403;
        cmeStrConstrAppend(responseText,"<b>403 ERROR Forbidden request.</b><br>"
                           "tableRow must be a positive integer. METHOD: '%s' URL: '%s'."
                           " Latest IDD version: <code>%s</code>",method,url,cmeInternalDBDefinitionsVersion);
        return(7);
    }

    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultResourcesDBName);
    result=cmeDBOpen(dbFilePath,&resourcesDB);
    if (result)
    {
        cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                           "Internal server error number '%d'. METHOD: '%s' URL: '%s'."
                           " Latest IDD version: <code>%s</code>",result,method,url,cmeInternalDBDefinitionsVersion);
        *responseCode=500;
        cmeWebServiceProcessDBBrowseResourceFree();
        return(8);
    }

    if (!dbName)
    {
        result=cmeGetUnprotectDBRegisters(resourcesDB,"documents",docMatchColumns,docMatchValues,3,
                                          &resultRegisterCols,&numResultRegisterCols,&numResultRegisters,orgKey);
        if (result)
        {
            *responseCode=500;
            cmeWebServiceProcessDBBrowseResourceFree();
            return(9);
        }
        if (cmeWebServiceDBBrowseInitTable(3,numResultRegisters))
        {
            *responseCode=500;
            cmeWebServiceProcessDBBrowseResourceFree();
            return(10);
        }
        cmeWebServiceDBBrowseAppendCell(0,"dbName");
        cmeWebServiceDBBrowseAppendCell(1,"type");
        cmeWebServiceDBBrowseAppendCell(2,"storageId");
        outRows=0;
        for (cont=1;cont<=numResultRegisters;cont++)
        {
            const char *candidate=resultRegisterCols[cont*numResultRegisterCols+cmeIDDResourcesDBDocuments_documentId];
            int seen=0;
            for (cont2=1;cont2<=outRows;cont2++)
            {
                if (!strcmp(cmeResultMemTable[cont2*3],candidate))
                {
                    seen=1;
                    break;
                }
            }
            if (!seen)
            {
                outRows++;
                cmeWebServiceDBBrowseAppendCell(outRows*3,candidate);
                cmeWebServiceDBBrowseAppendCell(outRows*3+1,"file.csv");
                cmeWebServiceDBBrowseAppendCell(outRows*3+2,urlElements[3]);
            }
        }
        cmeResultMemTableRows=outRows;
        if (!strcmp(method,"HEAD"))
        {
            *responseCode=outRows?200:404;
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",outRows);
            cmeWebServiceProcessDBBrowseResourceFree();
            return(0);
        }
        result=cmeConstructWebServiceTableResponse((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,
                                                   argumentElements,method,url,"dbNames",responseHeaders,responseText,responseCode);
        cmeWebServiceProcessDBBrowseResourceFree();
        return(result);
    }

    result=cmeWebServiceDBBrowseDocumentExists(resourcesDB,urlElements[1],urlElements[3],dbName,orgKey,
                                               &resultRegisterCols,&numResultRegisterCols,&numResultRegisters);
    if (result)
    {
        *responseCode=500;
        cmeWebServiceProcessDBBrowseResourceFree();
        return(11);
    }
    if (!numResultRegisters)
    {
        *responseCode=404;
        cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
        cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
        cmeWebServiceProcessDBBrowseResourceFree();
        return(0);
    }
    if (numUrlElements==6)
    {
        if (cmeWebServiceDBBrowseInitTable(3,1))
        {
            *responseCode=500;
            cmeWebServiceProcessDBBrowseResourceFree();
            return(12);
        }
        cmeWebServiceDBBrowseAppendCell(0,"dbName");
        cmeWebServiceDBBrowseAppendCell(1,"type");
        cmeWebServiceDBBrowseAppendCell(2,"storageId");
        cmeWebServiceDBBrowseAppendCell(3,dbName);
        cmeWebServiceDBBrowseAppendCell(4,"file.csv");
        cmeWebServiceDBBrowseAppendCell(5,urlElements[3]);
        if (!strcmp(method,"HEAD"))
        {
            *responseCode=200;
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",1);
            cmeWebServiceProcessDBBrowseResourceFree();
            return(0);
        }
        result=cmeConstructWebServiceTableResponse((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,
                                                   argumentElements,method,url,dbName,responseHeaders,responseText,responseCode);
        cmeWebServiceProcessDBBrowseResourceFree();
        return(result);
    }

    result=cmeSecureDBToMemDB(&memDB,resourcesDB,dbName,orgKey,storagePath);
    if (result)
    {
        cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                           "Secure DB verification failed with error '%d'. METHOD: '%s' URL: '%s'."
                           " Latest IDD version: <code>%s</code>",result,method,url,cmeInternalDBDefinitionsVersion);
        *responseCode=500;
        cmeWebServiceProcessDBBrowseResourceFree();
        return(13);
    }
    if (numUrlElements==7)
    {
        if (cmeWebServiceDBBrowseInitTable(1,2))
        {
            *responseCode=500;
            cmeWebServiceProcessDBBrowseResourceFree();
            return(14);
        }
        cmeWebServiceDBBrowseAppendCell(0,"dbTable");
        cmeWebServiceDBBrowseAppendCell(1,"data");
        cmeWebServiceDBBrowseAppendCell(2,"meta");
        if (!strcmp(method,"HEAD"))
        {
            *responseCode=200;
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",2);
            cmeWebServiceProcessDBBrowseResourceFree();
            return(0);
        }
        result=cmeConstructWebServiceTableResponse((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,
                                                   argumentElements,method,url,dbName,responseHeaders,responseText,responseCode);
        cmeWebServiceProcessDBBrowseResourceFree();
        return(result);
    }

    cmeStrConstrAppend(&sqlQuery,"SELECT * FROM \"%s\";",dbTable);
    result=cmeMemTable(memDB,sqlQuery,&rawTable,&tableRows,&tableCols);
    if (result)
    {
        *responseCode=500;
        cmeWebServiceProcessDBBrowseResourceFree();
        return(15);
    }
    if ((numUrlElements==9)&&(!strcmp(urlElements[8],"tableColumns")))
    {
        if (cmeWebServiceDBBrowseInitTable(1,tableCols))
        {
            *responseCode=500;
            cmeWebServiceProcessDBBrowseResourceFree();
            return(16);
        }
        cmeWebServiceDBBrowseAppendCell(0,"tableColumn");
        for (cont=0;cont<tableCols;cont++)
        {
            cmeWebServiceDBBrowseAppendCell(cont+1,rawTable[cont]);
        }
        if (!strcmp(method,"HEAD"))
        {
            *responseCode=tableCols?200:404;
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",tableCols);
            cmeWebServiceProcessDBBrowseResourceFree();
            return(0);
        }
        result=cmeConstructWebServiceTableResponse((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,
                                                   argumentElements,method,url,dbName,responseHeaders,responseText,responseCode);
        cmeWebServiceProcessDBBrowseResourceFree();
        return(result);
    }
    if (numUrlElements==8 || ((numUrlElements==9)&&(!strcmp(urlElements[8],"tableRows"))) || tableRow)
    {
        if (tableRow)
        {
            int row=atoi(tableRow);
            if ((row<1)||(row>tableRows))
            {
                *responseCode=404;
                cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
                cmeWebServiceProcessDBBrowseResourceFree();
                return(0);
            }
            if (cmeWebServiceDBBrowseInitTable(tableCols,1))
            {
                *responseCode=500;
                cmeWebServiceProcessDBBrowseResourceFree();
                return(17);
            }
            for (cont=0;cont<tableCols;cont++)
            {
                cmeWebServiceDBBrowseAppendCell(cont,rawTable[cont]);
                cmeWebServiceDBBrowseAppendCell(tableCols+cont,rawTable[row*tableCols+cont]);
            }
        }
        else
        {
            cmeResultMemTableClean();
            cmeResultMemTable=rawTable;
            cmeResultMemTableCols=tableCols;
            cmeResultMemTableRows=tableRows;
            rawTable=NULL;
        }
        if (!strcmp(method,"HEAD"))
        {
            *responseCode=cmeResultMemTableRows?200:404;
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",cmeResultMemTableRows);
            cmeWebServiceProcessDBBrowseResourceFree();
            return(0);
        }
        result=cmeConstructWebServiceTableResponse((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,
                                                   argumentElements,method,url,dbName,responseHeaders,responseText,responseCode);
        cmeWebServiceProcessDBBrowseResourceFree();
        return(result);
    }
    if (tableColumn)
    {
        for (cont=0;cont<tableCols;cont++)
        {
            if (!strcmp(rawTable[cont],tableColumn))
            {
                requestedCol=cont;
                break;
            }
        }
        if (requestedCol<0)
        {
            *responseCode=404;
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",0);
            cmeWebServiceProcessDBBrowseResourceFree();
            return(0);
        }
        if (cmeWebServiceDBBrowseInitTable(2,tableRows))
        {
            *responseCode=500;
            cmeWebServiceProcessDBBrowseResourceFree();
            return(18);
        }
        cmeWebServiceDBBrowseAppendCell(0,rawTable[0]);
        cmeWebServiceDBBrowseAppendCell(1,rawTable[requestedCol]);
        dest=2;
        for (cont=1;cont<=tableRows;cont++)
        {
            cmeWebServiceDBBrowseAppendCell(dest++,rawTable[cont*tableCols]);
            cmeWebServiceDBBrowseAppendCell(dest++,rawTable[cont*tableCols+requestedCol]);
        }
        if (!strcmp(method,"HEAD"))
        {
            *responseCode=200;
            cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
            cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",tableRows);
            cmeWebServiceProcessDBBrowseResourceFree();
            return(0);
        }
        result=cmeConstructWebServiceTableResponse((const char **)cmeResultMemTable,cmeResultMemTableCols,cmeResultMemTableRows,
                                                   argumentElements,method,url,dbName,responseHeaders,responseText,responseCode);
        cmeWebServiceProcessDBBrowseResourceFree();
        return(result);
    }

    *responseCode=404;
    cmeWebServiceProcessDBBrowseResourceFree();
    return(19);
}

int cmeWebServiceLogRequest (const char *userId, const char *orgId, const char *requestMethod, const char *requestUrl, const char *requestHeaders,
                             const char *startTimestamp, const char *endTimestamp, const char *requestDataSize, const char *responseDataSize,
                             const char *orgResourceId, const char *requestIPAddress, const char *responseCode, const char *responseHeaders,
                             const char *authenticated, const char *orgKey)
{   //IDD version 1.0.21
    int cont,result,protectedValueLen,protectedValueMACLen;
    int authenticationFlag=0;
    char *protectedValue=NULL;
    char *protectedValueMAC=NULL;
    char *salt=NULL;
    char *boundValue=NULL;
    const int numColumns=cmeIDDLogsDBTransactionsNumCols-2;       //Constant: number of columns in table, ignoring id & salt
    const char *tableName=cmeIDDLogsDBTransactionsTableName;
    const char *columnNames[14]={cmeIDDanydb_userId_name,cmeIDDanydb_orgId_name,
                                 cmeIDDLogsDBTransactions_requestMethod_name,
                                 cmeIDDLogsDBTransactions_requestUrl_name,
                                 cmeIDDLogsDBTransactions_requestHeaders_name,
                                 cmeIDDLogsDBTransactions_startTimestamp_name,
                                 cmeIDDLogsDBTransactions_endTimestamp_name,
                                 cmeIDDLogsDBTransactions_requestDataSize_name,
                                 cmeIDDLogsDBTransactions_responseDataSize_name,
                                 cmeIDDLogsDBTransactions_orgResourceId_name,
                                 cmeIDDLogsDBTransactions_requestIPAddress_name,
                                 cmeIDDLogsDBTransactions_responseCode_name,
                                 cmeIDDLogsDBTransactions_responseHeaders_name,
                                 cmeIDDLogsDBTransactions_authenticated_name};
    char *columnValues[14]={NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
    sqlite3 *pDB=NULL;
    char *dbFilePath=NULL;
    sqlite3_stmt *insertStmt=NULL;
    #define cmeWebServiceLogRequestFree() \
        do { \
            cmeFree(protectedValue); \
            cmeFree(protectedValueMAC); \
            cmeFree(salt); \
            cmeFree(boundValue); \
            cmeFree(dbFilePath); \
            if (insertStmt) \
            { \
                sqlite3_finalize(insertStmt); \
                insertStmt=NULL; \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
            for (cont=0;cont<numColumns;cont++) \
            { \
                cmeFree(columnValues[cont]); \
                columnValues[cont]=NULL; \
            } \
        } while (0); //Local free() macro.

    cmeStrConstrAppend(&(columnValues[0]),"%s",userId);
    cmeStrConstrAppend(&(columnValues[1]),"%s",orgId);
    cmeStrConstrAppend(&(columnValues[2]),"%s",requestMethod);
    cmeStrConstrAppend(&(columnValues[3]),"%s",requestUrl);
    cmeStrConstrAppend(&(columnValues[4]),"%s",requestHeaders);
    cmeStrConstrAppend(&(columnValues[5]),"%s",startTimestamp);
    cmeStrConstrAppend(&(columnValues[6]),"%s",endTimestamp);
    cmeStrConstrAppend(&(columnValues[7]),"%s",requestDataSize);
    cmeStrConstrAppend(&(columnValues[8]),"%s",responseDataSize);
    cmeStrConstrAppend(&(columnValues[9]),"%s",orgResourceId);
    cmeStrConstrAppend(&(columnValues[10]),"%s",requestIPAddress);
    cmeStrConstrAppend(&(columnValues[11]),"%s",responseCode);
    cmeStrConstrAppend(&(columnValues[12]),"%s",responseHeaders);
    cmeStrConstrAppend(&(columnValues[13]),"%s",authenticated);
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultLogsDBName);
    result=cmeDBOpen(dbFilePath,&pDB);
    if (result) //Error
    {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceLogRequest(), can't open LogsDB!"
                    " File: '%s'!\n",dbFilePath);
#endif
                return(1);
    }
    result=cmeWebServiceEnsureLogsTransactionsTable(pDB);
    if (result)
    {
        cmeWebServiceLogRequestFree();
        return(2);
    }
    if (!strcmp(authenticated,"1")) //Connection was authenticated -> set flag to encrypt normally (otherwise store information unencrypted)
    {
        authenticationFlag=1;
    }
    else //Not authenticated -> clear salt field (otherwise the first call to cmeProtectDBSaltedValue will generate a random salt).
    {
        cmeStrConstrAppend(&salt,"");
    }
    for (cont=0; cont<numColumns; cont++)
    {
        if (!columnNames[cont]) //Error, colName is NULL!
        {
 #ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceLogRequest(), Error,"
                    "NULL pointer at columnNames[%d]\n",cont);
#endif
            cmeWebServiceLogRequestFree();
            return(1);
        }
    }
    result=sqlite3_prepare_v2(pDB,
                              "INSERT INTO " cmeIDDLogsDBTransactionsTableName " "
                              "(" cmeIDDanydb_id_name "," cmeIDDanydb_userId_name ","
                              cmeIDDanydb_orgId_name "," cmeIDDLogsDBTransactions_requestMethod_name ","
                              cmeIDDLogsDBTransactions_requestUrl_name ","
                              cmeIDDLogsDBTransactions_requestHeaders_name ","
                              cmeIDDLogsDBTransactions_startTimestamp_name ","
                              cmeIDDLogsDBTransactions_endTimestamp_name ","
                              cmeIDDLogsDBTransactions_requestDataSize_name ","
                              cmeIDDLogsDBTransactions_responseDataSize_name ","
                              cmeIDDLogsDBTransactions_orgResourceId_name ","
                              cmeIDDLogsDBTransactions_requestIPAddress_name ","
                              cmeIDDLogsDBTransactions_responseCode_name ","
                              cmeIDDLogsDBTransactions_responseHeaders_name ","
                              cmeIDDLogsDBTransactions_authenticated_name ","
                              cmeIDDanydb_salt_name ") VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
                              -1,&insertStmt,NULL);
    if (result!=SQLITE_OK)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceLogRequest(), sqlite3_prepare_v2() Error, can't "
                "prepare insert in table: %s: %s!\n",tableName,sqlite3_errmsg(pDB));
#endif
        cmeWebServiceLogRequestFree();
        return(2);
    }
    if (cmeSQLRows(pDB,"BEGIN TRANSACTION;",NULL,NULL))
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceLogRequest(), cmeSQLRows() Error, can't "
                "begin transaction for table: %s!\n",tableName);
#endif
        cmeWebServiceLogRequestFree();
        return(3);
    }
    for (cont=0; cont<numColumns; cont++)
    {
        if ((strcmp(columnNames[cont],cmeIDDanydb_salt_name)!=0)&&(columnValues[cont]!=NULL)) //Skip salt, we will add it at the end.
        {
            if((!strcmp(columnNames[cont],cmeIDDLogsDBTransactions_authenticated_name))||(authenticationFlag==0)) //We don't encrypt the authentication flag, or any field if the authentication flag is 0.
            {
                result=sqlite3_bind_text(insertStmt,cont+1,columnValues[cont],-1,SQLITE_TRANSIENT);
            }
            else
            {
                result=cmeProtectDBSaltedValue(columnValues[cont],&protectedValue,cmeDefaultEncAlg,&salt,orgKey,&protectedValueLen);
                if (!result)
                {
                    result=cmeHMACByteString((const unsigned char *)protectedValue,(unsigned char **)&protectedValueMAC,
                                             protectedValueLen,&protectedValueMACLen,cmeDefaultMACAlg,&salt,orgKey);
                }
                if (!result)
                {
                    cmeStrConstrAppend(&boundValue,"%s%s",protectedValueMAC,protectedValue);
                    result=sqlite3_bind_text(insertStmt,cont+1,boundValue,-1,SQLITE_TRANSIENT);
                }
                cmeFree(protectedValue);
                cmeFree(protectedValueMAC);
                cmeFree(boundValue);
            }
        }
        else
        {
            result=sqlite3_bind_null(insertStmt,cont+1);
        }
        if (result!=SQLITE_OK)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceLogRequest(), sqlite3_bind_text() Error, can't "
                    "bind column %s in table: %s: %s!\n",columnNames[cont],tableName,sqlite3_errmsg(pDB));
#endif
            cmeSQLRows(pDB,"ROLLBACK;",NULL,NULL);
            cmeWebServiceLogRequestFree();
            return(4);
        }
    }
    result=sqlite3_bind_text(insertStmt,numColumns+1,salt ? salt : "",-1,SQLITE_TRANSIENT);
    if (result==SQLITE_OK)
    {
        result=sqlite3_step(insertStmt);
    }
    if (result!=SQLITE_DONE) //Error.
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceLogRequest(), sqlite3_step() Error, can't "
                "create register in table: %s: %s!\n",tableName,sqlite3_errmsg(pDB));
#endif
        cmeSQLRows(pDB,"ROLLBACK;",NULL,NULL);
        cmeWebServiceLogRequestFree();
        return(5);
    }
    if (cmeSQLRows(pDB,"COMMIT;",NULL,NULL))
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceLogRequest(), cmeSQLRows() Error, can't "
                "commit transaction for table: %s!\n",tableName);
#endif
        cmeSQLRows(pDB,"ROLLBACK;",NULL,NULL);
        cmeWebServiceLogRequestFree();
        return(6);
    }
    cmeWebServiceLogRequestFree();
    return(0);
}

int cmeWebServiceLogConnection (struct MHD_Connection *connection, void *con_cls, const time_t startTime,
                                const char *method, const char *url, const long int requestDSize, const long int responseDSize,
                                const char **requestHeadersList, const char **responseHeadersList, const char **requestArgumentsList,
                                const char **urlElements, const int numUrlElements)
{   //IDD version 1.0.21
    int cont,result;
    const char *userId=NULL;
    const char *orgId=NULL;
    const char *requestMethod=NULL;
    const char *orgKey=NULL;
    const char *strEmpty="";
    const char *strOne="1";
    const char *strZero="0";
    const char *authenticated=NULL;
    struct cmeWebServiceConnectionInfoStruct *con_info=NULL;
    union MHD_ConnectionInfo *mhdConInfo=NULL;
    char *requestIPAddress=NULL;
    char *responseCode=NULL;
    char *requestDataSize=NULL;
    char *responseDataSize=NULL;
    char *startTimestamp=NULL;
    char *endTimestamp=NULL;
    char *responseHeaders=NULL;
    char *requestHeaders=NULL;
    char *requestUrl=NULL;
    char *orgResourceId=NULL;
    #define cmeWebServiceLogConnectionFree() \
        do { \
            cmeFree(responseHeaders); \
            cmeFree(requestHeaders); \
            cmeFree(startTimestamp); \
            cmeFree(endTimestamp); \
            cmeFree(requestDataSize); \
            cmeFree(responseDataSize); \
            cmeFree(requestIPAddress); \
            cmeFree(responseCode); \
            cmeFree(requestUrl); \
            cmeFree(orgResourceId); \
        } while (0); //Local free() macro.

    //Set con_info pointer
    con_info=con_cls;
    //Set userId:
    userId=MHD_lookup_connection_value(connection,MHD_GET_ARGUMENT_KIND,"userId");
    if (!userId) //If undefined, set to empty.
    {
        userId=strEmpty;
    }
    //Set orgId:
    orgId=MHD_lookup_connection_value(connection,MHD_GET_ARGUMENT_KIND,"orgId");
    if (!orgId) //If undefined, set to empty.
    {
        orgId=strEmpty;
    }
    //Set requestMethod:
    requestMethod=method;
    if (!requestMethod) //If undefined, set to empty.
    {
        requestMethod=strEmpty;
    }
    //Set requestUrl:
    if (url)
    {
        cmeStrConstrAppend(&requestUrl,"%s",url);
        cont=0;
        if (requestArgumentsList[cont]) // We have at least one argument -> append to url
        {
            cmeStrConstrAppend(&requestUrl,"?");
            while ((requestArgumentsList[cont])&&(cont<cmeWSURIMaxArguments))
            {
                cmeStrConstrAppend(&requestUrl,"%s=%s",requestArgumentsList[cont],requestArgumentsList[cont+1]);
                cont+=2;
                if (cont<cmeWSURIMaxArguments)
                {
                    if (requestArgumentsList[cont]) //Still arguments -> add separator
                    {
                        cmeStrConstrAppend(&requestUrl,",");
                    }
                }
            }
        }
    }
    else //If undefined, set to empty.
    {
        cmeStrConstrAppend(&requestUrl,"");
    }
    //Set orgResourceId:
    cmeStrConstrAppend(&orgResourceId,"");
    if ((numUrlElements>2)&&(strcmp(urlElements[0],"organizations")==0)) //We have an organization in the URL
    {
        cmeStrConstrAppend(&orgResourceId,"%s",urlElements[1]);
    }
    //Set orgKey:
    orgKey=MHD_lookup_connection_value(connection,MHD_GET_ARGUMENT_KIND,"orgKey");
    if (!orgKey) //If undefined, set to empty.
    {
        orgKey=strEmpty;
    }
    //Set requestIPAddress:
    mhdConInfo=(union MHD_ConnectionInfo *) MHD_get_connection_info(connection,MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if(mhdConInfo->client_addr->sa_family==AF_INET) //IPv4
    {
        requestIPAddress=(char *)malloc(INET_ADDRSTRLEN);
        inet_ntop(AF_INET,mhdConInfo->client_addr->sa_data+2,requestIPAddress,INET_ADDRSTRLEN);
    }
    else if (mhdConInfo->client_addr->sa_family==AF_INET6) //IPv6)
    {
        requestIPAddress=(char *)malloc(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6,mhdConInfo->client_addr->sa_data+2,requestIPAddress,INET6_ADDRSTRLEN);
    }
    else
    {
        cmeStrConstrAppend(&requestIPAddress,"unknownType");
    }
    //Set responseCode:
    cmeStrConstrAppend(&responseCode,"%d",con_info->answerCode);
    //Set authentication flag:
    if ((con_info->answerCode==401)||(!strcmp(orgKey,strEmpty))) //Not authenticated.
    {
        authenticated=(char *)strZero;
    }
    else
    {
        authenticated=(char *)strOne;
    }
    //Set requestDataSize:
    cmeStrConstrAppend(&requestDataSize,"%ld",requestDSize);
    //Set responseDataSize:
    cmeStrConstrAppend(&responseDataSize,"%ld",responseDSize);
    //Set startTimestamp:
    cmeStrConstrAppend(&startTimestamp,"%lld",(long long int)startTime);
    //Set endTimestamp:
    cmeStrConstrAppend(&endTimestamp,"%lld",(long long int)time(NULL));
    //Set responseHeaders:
    cmeStrConstrAppend(&responseHeaders,""); //Start with an empty string.
    cont=0;
    while ((responseHeadersList[cont])&&(cont<cmeWSHTTPMaxResponseHeaders))
    {
        cmeStrConstrAppend(&responseHeaders,"%s=%s\n",responseHeadersList[cont],responseHeadersList[cont+1]);
        cont+=2;
    }
    //Set requestHeaders:
    cmeStrConstrAppend(&requestHeaders,""); //Start with an empty string.
    cont=0;
    while ((requestHeadersList[cont])&&(cont<cmeWSHTTPMaxHeaders))
    {
        cmeStrConstrAppend(&requestHeaders,"%s=%s\n",requestHeadersList[cont],requestHeadersList[cont+1]);
        cont+=2;
    }
    //Log transaction:
    result= cmeWebServiceLogRequest (userId, orgId, requestMethod, requestUrl, requestHeaders,
                                     startTimestamp, endTimestamp, requestDataSize, responseDataSize,
                                     orgResourceId, requestIPAddress, responseCode, responseHeaders,
                                     authenticated, orgKey);
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceLogConnection(), cmeWebServiceLogRequest() Error, can't "
                "create register in table: transactions within LogsDB database!\n");
#endif
        cmeWebServiceLogConnectionFree();
        return(1);
    }
    cmeWebServiceLogConnectionFree();
    return(0);
}

int cmeWebServiceProcessTransactionClass (char **responseText, char ***responseHeaders, int *responseCode,
                                           const char *url, const char **argumentElements, const char *method)
{   //IDD ver. 1.0.21  definitions.
    int cont,result;
    int keyArg=0;
    int orgArg=0;
    int usrArg=0;
    int newKeyArg=0;
    int numSaveArgs=0;
    int numMatchArgs=0;
    int numResultRegisterCols=0;
    int numResultRegisters=0;
    sqlite3 *pDB=NULL;
    char *orgKey=NULL;                  //requester orgKey.
    char *userId=NULL;                  //requester userId.
    char *orgId=NULL;                   //requester orgId.
    char *newOrgKey=NULL;               //requester newOrgKey (optional).
    char *salt=NULL;
    char **columnValuesToMatch=NULL;    //Values to match a register to operate upon (GET/PUT)
    char **columnNamesToMatch=NULL;     //Names of columns for values to match a register (GET/PUT)
    char *dbFilePath=NULL;
    char **resultRegisterCols=NULL;
    const char *tableName=cmeIDDLogsDBTransactionsTableName;
    const int numColumns=cmeIDDLogsDBTransactionsNumCols;
    const int numValidGETALLMatch=14;    //8 parameters + NONE from URL
    const char *validGETALLMatchColumns[14]={cmeIDDMatchName(cmeIDDanydb_userId_name),
                                             cmeIDDMatchName(cmeIDDanydb_orgId_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_requestMethod_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_requestUrl_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_requestHeaders_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_startTimestamp_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_endTimestamp_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_requestDataSize_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_responseDataSize_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_orgResourceId_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_requestIPAddress_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_responseCode_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_responseHeaders_name),
                                             cmeIDDMatchName(cmeIDDLogsDBTransactions_authenticated_name)};
    #define cmeWebServiceProcessTransactionClassFree() \
        do { \
            cmeFree(orgKey); \
            cmeFree(userId); \
            cmeFree(orgId); \
            cmeFree(newOrgKey) \
            cmeFree(dbFilePath); \
            cmeFree(salt); \
            if (resultRegisterCols) \
            { \
               for (cont=0;cont<numResultRegisterCols*(numResultRegisters+1);cont++) \
               { \
                   cmeFree(resultRegisterCols[cont]); \
               } \
               cmeFree(resultRegisterCols); \
            } \
            if (columnValuesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnValuesToMatch[cont]); \
               } \
               cmeFree(columnValuesToMatch); \
            } \
            if (columnNamesToMatch) \
            { \
               for (cont=0; cont<numColumns;cont++) \
               { \
                   cmeFree(columnNamesToMatch[cont]); \
               } \
               cmeFree(columnNamesToMatch); \
            } \
            if (pDB) \
            { \
                cmeDBClose(pDB); \
                pDB=NULL; \
            } \
        } while (0); //Local free() macro.

    columnValuesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store role resource information, column values to match (GET/PUT).
    columnNamesToMatch=(char **)malloc(sizeof(char *)*numColumns); //Set space to store column names to match (GET).
    for (cont=0; cont<numColumns;cont++)
    {
       columnValuesToMatch[cont]=NULL;
       columnNamesToMatch[cont]=NULL;
    }
    cmeStrConstrAppend(&dbFilePath,"%s%s",cmeDefaultFilePath,cmeDefaultLogsDBName);

    if(!strcmp(method,"GET")) //Method = GET is ok, process:
    {
        numMatchArgs=0;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, NULL, NULL, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=0)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=0 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBTransactions(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                     &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    //Construct responseText and create response headers according to the user's outputType (optional) request:
                    result=cmeConstructWebServiceTableResponse ((const char **)resultRegisterCols,numResultRegisterCols,numResultRegisters,
                                                                argumentElements, url, method, tableName,
                                                                responseHeaders, responseText, responseCode);
                    cmeWebServiceProcessTransactionClassFree();
                    return(0);
                }
                else //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgTransactionClassOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessTransactionClass(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessTransactionClassFree();
                    *responseCode=500;
                    return(24);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgTransactionClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessTransactionClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s', can't open dbfile: %s !\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessTransactionClassFree();
                *responseCode=500;
                return(25);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgTransactionClassOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessTransactionClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessTransactionClassFree();
            *responseCode=409;
            return(26);
        }
    }
    else if(!strcmp(method,"HEAD")) //Method = HEAD is ok, process:
    {
        numMatchArgs=0;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, NULL, NULL, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=0)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=2 Match)
        {
            result=cmeDBOpen(dbFilePath,&pDB);
            if (!result) //if OK
            {
                result=cmeGetUnprotectDBTransactions(pDB,tableName,(const char **)columnNamesToMatch,(const char **)columnValuesToMatch,
                                                     numMatchArgs,&resultRegisterCols,&numResultRegisterCols,
                                                     &numResultRegisters,orgKey);
                if (!result) //OK
                {
                    if (numResultRegisters) //Found >0 results
                    {
                        *responseCode=200;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessTransactionClass(), HEAD successful.\n");
#endif
                    }
                    else //Found 0 results
                    {
                        *responseCode=404;
#ifdef DEBUG
                        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessTransactionClass(), HEAD, successful but"
                                "no record found.\n");
#endif
                    }
                    //cmeStrConstrAppend(responseText,"<p>Matched results: %d</p><br>",numResultRegisters);  //HEAD doesn't return a body.
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
                    cmeWebServiceProcessTransactionClassFree();
                    return(0);
                }
                else //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                        "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgTransactionClassOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessTransactionClass(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s'; cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                    cmeWebServiceProcessTransactionClassFree();
                    *responseCode=500;
                    return(28);
                }
            }
            else //Server ERROR
            {
                cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                   "Internal server error number '%d'."
                                   "METHOD: '%s' URL: '%s'."
                                    "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgTransactionClassOptions,
                                    cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessTransactionClass(), Error, internal server error '%d'."
                        " Method: '%s', URL: '%s'; can't open DBFile: %s!\n",result,method,url,dbFilePath);
#endif
                cmeWebServiceProcessTransactionClassFree();
                *responseCode=500;
                return(29);
            }
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                                "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgTransactionClassOptions,
                                cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessTransactionClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessTransactionClassFree();
            *responseCode=409;
            return(30);
        }
    }
    else if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
    {
        numMatchArgs=0;
        cmeProcessURLMatchSaveParameters (method, argumentElements, validGETALLMatchColumns, NULL, numValidGETALLMatch, 0,
                                          columnValuesToMatch, columnNamesToMatch, NULL, NULL, &numMatchArgs, &numSaveArgs,
                                          &userId, &orgId, &orgKey, &newOrgKey, &usrArg, &orgArg, &keyArg, &newKeyArg);
        if ((numMatchArgs>=0)&&(keyArg)&&(usrArg)&&(orgArg)) //Command successful; required number of arguments found (at least: orgKey, orgId, userId and >=2 Match)
        {
            cmeStrConstrAppend(responseText,"<b>200 OK - Options for role table resources:</b><br>"
                               "%sLatest IDD version: <code>%s</code>",cmeWSMsgTransactionClassOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessTransactionClass(), OPTIONS successful for user resource."
                    " Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessTransactionClassFree();
            *responseCode=200;
            return(0);
        }
        else //Error, invalid number of correct arguments for this command.
        {
            cmeStrConstrAppend(responseText,"<b>409 ERROR Incorrect number of arguments."
                               "</b><br><br>The provided number of arguments is insufficient. "
                               "METHOD: '%s' URL: '%s'."
                               "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgTransactionClassOptions,
                               cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessTransactionClass(), Error, incorrect number of"
                    " arguments. Method: '%s', URL: '%s'!\n",method,url);
#endif
            cmeWebServiceProcessTransactionClassFree();
            *responseCode=409;
            return(36);
        }
    }
    else //Error, unsupported method
    {
        cmeStrConstrAppend(responseText,"<b>405 ERROR Method is not allowed.</b><br><br>The selected "
                           "method, is not allowed for this engine resource."
                           "METHOD: '%s' URL: '%s'."
                           "%sLatest IDD version: <code>%s</code>",method,url,cmeWSMsgTransactionClassOptions,
                           cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessTransactionClass(), Error, method %s is not allowed!\n"
                " Url: %s!\n",method,url);
#endif
        cmeWebServiceProcessTransactionClassFree();
        *responseCode=405;
        return(37);
    }
}
