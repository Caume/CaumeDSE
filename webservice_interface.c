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

int cmeWebServiceAnswerConnection (void *cls, struct MHD_Connection *connection, const char *url,
                                   const char *method, const char *version, const char *upload_data,
                                   size_t *upload_data_size, void **con_cls)

{
    #define GET             0
    #define POST            1
    int cont,responseEncoding,result;
    int exitcode=1;
    int numUrlElements=0;
    int responseCode=0;
    char *page=NULL;
    const char *pOutputType=NULL;                         //Ptr to constant str. for output type. No need to free.
    char **urlElements=NULL;
    struct MHD_Response *response=NULL;
    struct MHD_Response *responseFile=NULL;
    char **headerElements=NULL;
    char **argumentElements=NULL;
    char *responseText=NULL;
    char *responseFilePath=NULL;
    char **responseHeaders=NULL;
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
        } while (0) //Local free() macro.

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
        con_info->threadStatus=0;
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
            con_info->postProcessor=MHD_create_post_processor(connection,cmeWSPostBufferSize,&cmeWebServicePOSTIteration,(void *) con_info);
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
                con_info->threadStatus=2;
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
            con_info->threadStatus=2;
        }
        *con_cls=(void *)con_info;
        return MHD_YES;
    }
    else
    {
        con_info=*con_cls;
    }
    if ((con_info->connectionType)==POST) //Iterate POST request.
    {
        if (*upload_data_size != 0) //If data is available, retrieve it and exit function for another iteration.
        {
            MHD_post_process (con_info->postProcessor, upload_data,*upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }
        else if (NULL != con_info->answerString) //If no data is available but we have an answer, signal job is done.
        {
            con_info->threadStatus=1; //Signal: POST iterator job is done, waiting...
        }
        if (con_info->filePointer) //We need to close the file before cmeWebServiceRequestCompleted() is called, since cmeWebServiceProcessRequest() will use it.
        {
            fclose (con_info->filePointer);
            con_info->filePointer=NULL;
        }
    }
    do  //Wait until the POST processor has collected all data.
    {
        sleep(cmeDefaultThreadWaitSeconds);
    } while (con_info->threadStatus==0);
    //Allocate space for headers and response headers:
    headerElements=(char **)malloc((sizeof (char *))*cmeWSHTTPMaxHeaders*2); //*2 since headers consist of headerElements PAIRS.
    responseHeaders=(char **)malloc((sizeof (char *))*cmeWSHTTPMaxHeaders*2); //*2 since headers consist of headerElements PAIRS.
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
    MHD_get_connection_values (connection, MHD_GET_ARGUMENT_KIND, &cmeWebServiceParseKeys, argumentElements);   //Parse Headers.
    MHD_get_connection_values (connection, MHD_HEADER_KIND, &cmeWebServiceParseKeys, headerElements);   //Parse Arguments.
    result=cmeWebServiceProcessRequest (&responseText,&responseFilePath,&responseHeaders,&responseCode,
                                        url,(const char **)urlElements,numUrlElements,
                                        (const char **)headerElements,(const char **)argumentElements,method,connection);
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
                //Create response body:
                response=MHD_create_response_from_data (strlen(page),(void*) page, MHD_NO, MHD_YES); //We have to create response body before adding headers.
                result=MHD_add_response_header(response,"Content-Type","text/html; charset=utf-8");
            }
            else
            {
                cmeStrConstrAppend(&page,"%s",responseText); //Add plain response to response page.
                //Create response body:
                response=MHD_create_response_from_data (strlen(page),(void*) page, MHD_NO, MHD_YES);
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
            response=MHD_create_response_from_data (0,NULL, MHD_NO, MHD_YES);
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
    con_info->threadStatus=2; //Now the POST handling routing thread can free memory and finish.
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

int cmeWebServiceProcessRequest (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                 const char *url, const char **urlElements, int numUrlElements,
                                 const char **headerElements,const char **argumentElements, const char *method,
                                 struct MHD_Connection *connection)
{   //IDD 1.0.20
    int cont,result;
    int authentication=0;
    static int powerStatus=1;   //TODO (OHR#5#) Set engine default to 'off'?
    char *userId=NULL;
    char *orgId=NULL;
    char *orgKey=NULL;
    char *newOrgKey=NULL;
    char *storagePath=NULL;
    const union MHD_ConnectionInfo *connectionInfo=NULL;
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
        } while (0) //Local free() macro.

    //TODO (OHR#2#): Sanitizing function for all inputs (filter:  ",',;,=,`)
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
            result=1; // TODO (OHR#2#): Add OAUTH authentication mechanism. The engine will still handle the same org. key (e.g. for authenticating owners with OAUTH), but for authorized users different from the owner another layer (e.g. an engine manager) should create another organization with different key and a standard name (e.g. <orgId>_OAUTH), put the authorized user and their permissions within this "temporal organization", and add any resources authorized by the user to this organization. When the OAUTH permissions timeout, the added layer should delete this organization and all associated resources (the engine doesn't store keys, so the added layer must maintain its own indexes).
            if (!result) //OAUTH Authentication Successful.
            {
                authentication+=1;
            }
        }
        connectionInfo=MHD_get_connection_info(connection, MHD_CONNECTION_INFO_PROTOCOL); //Get gnutls connection protocol information.
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
            cmeStrConstrAppend(responseText,"<b>404 ERROR The userResourceId corresponding to the userId specified in the URL was not found. Check parameters.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), Warning, '%d'."
                    " Method: '%s', URL: '%s', can't find userResourceId for userId %s!\n",result,method,url,userId);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=404;
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
            cmeStrConstrAppend(responseText,"<b>404 ERROR The orgResourceId corresponding to the orgId specified in the URL was not found. Check parameters.</b><br>"
                               "Internal server error number '%d'."
                               "METHOD: '%s' URL: '%s'."
                                "Latest IDD version: <code>%s</code>",result,method,url,
                                cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), Warning, '%d'."
                    " Method: '%s', URL: '%s', can't find userResourceId for orgId %s!\n",result,method,url,orgId);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=404;
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
    if ((numUrlElements>4)&&(strcmp(urlElements[2],"users")==0))// We have a storage resource in the URL. Check it is valid and get the corresponding storage path.
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
    if ((numUrlElements==1)&&(strcmp(urlElements[0],"engineCommands")==0)) // engine command resource (ignore powerStatus)
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                    "engine command resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
        result=cmeWebServiceProcessEngineResource(responseText, responseCode, url, argumentElements, method, &powerStatus);
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
    if ((numUrlElements>=1)&&(numUrlElements<=cmeIDDURIMaxDepth)&&(powerStatus)) //organization resource tree.
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
            cmeStrConstrAppend(responseText,"<b>403 ERROR No methods are currently available for this resource type.</b><br><br>"
               "Resource: '%s'. method: '%s', url: '%s'",urlElements[numUrlElements-1],method,url);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(). Error, no methods are currently available for this resource type."
                    "Unknown resource: '%s'. Method: '%s', url: '%s'\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=403; //Response: Error 404 (resource not found).
            return (15);
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
        //TODO (OHR#2#) process storage documentTypes and documents resource tree requests.
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
        else if ((numUrlElements==5)&&(strcmp(urlElements[4],"documentTypes")==0))// documentTypes class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "documentType class resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeStrConstrAppend(responseText,"<b>403 ERROR No methods are currently available for this resource type.</b><br><br>"
               "Resource: '%s'. method: '%s', url: '%s'",urlElements[numUrlElements-1],method,url);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(). Error, no methods are currently available for this resource type."
                    "Unknown resource: '%s'. Method: '%s', url: '%s'\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=403; //Response: Error 404 (resource not found).
            return (16);
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
            cmeStrConstrAppend(responseText,"<b>403 ERROR No methods are currently available for this resource type.</b><br><br>"
               "Resource: '%s'. method: '%s', url: '%s'",urlElements[numUrlElements-1],method,url);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(). Error, no methods are currently available for this resource type."
                    "Unknown resource: '%s'. Method: '%s', url: '%s'\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=403; //Response: Error 404 (resource not found).
            return (17);
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
        else if ((numUrlElements==10)&&(strcmp(urlElements[9],"contentRows")==0))// contentRows class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "outputDocument resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeStrConstrAppend(responseText,"<b>403 ERROR No methods are currently available for this resource type.</b><br><br>"
               "Resource: '%s'. method: '%s', url: '%s'",urlElements[numUrlElements-1],method,url);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(). Error, no methods are currently available for this resource type."
                    "Unknown resource: '%s'. Method: '%s', url: '%s'\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=403; //Response: Error 404 (resource not found).
            return (18);
        }
        else if ((numUrlElements==11)&&(strcmp(urlElements[9],"contentRows")==0))// contentRow resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "outputDocument resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeStrConstrAppend(responseText,"<b>403 ERROR No methods are currently available for this resource type.</b><br><br>"
               "Resource: '%s'. method: '%s', url: '%s'",urlElements[numUrlElements-1],method,url);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(). Error, no methods are currently available for this resource type."
                    "Unknown resource: '%s'. Method: '%s', url: '%s'\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=403; //Response: Error 404 (resource not found).
            return (19);
        }
        else if ((numUrlElements==10)&&(strcmp(urlElements[9],"contentColumns")==0))// contentColumns class resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "outputDocument resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeStrConstrAppend(responseText,"<b>403 ERROR No methods are currently available for this resource type.</b><br><br>"
               "Resource: '%s'. method: '%s', url: '%s'",urlElements[numUrlElements-1],method,url);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(). Error, no methods are currently available for this resource type."
                    "Unknown resource: '%s'. Method: '%s', url: '%s'\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=403; //Response: Error 404 (resource not found).
            return (20);
        }
        else if ((numUrlElements==11)&&(strcmp(urlElements[9],"contentColumns")==0))// contentColumn resource
        {
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeWebServiceProcessRequest(), client requests "
                        "outputDocument resource: '%s'. Method: '%s'. Url: '%s'.\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeStrConstrAppend(responseText,"<b>403 ERROR No methods are currently available for this resource type.</b><br><br>"
               "Resource: '%s'. method: '%s', url: '%s'",urlElements[numUrlElements-1],method,url);
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessRequest(). Error, no methods are currently available for this resource type."
                    "Unknown resource: '%s'. Method: '%s', url: '%s'\n",urlElements[numUrlElements-1],method,url);
#endif
            cmeWebServiceProcessRequestFree();
            *responseCode=403; //Response: Error 404 (resource not found).
            return (21);
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
    //Check engine power status.
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
        return(23);
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
    int cont, numCorrectArgs, tmpPowerStatus;
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
        } while (0) //Local free() macro.

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
        } while (0) //Local free() macro.

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
                    cmeStrConstrAppend(responseText,"<p>Deleted registers: %d</p><br>",numResultRegisters);
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
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
        } while (0) //Local free() macro.

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
                    cmeStrConstrAppend(responseText,"Deleted registers: %d <br>",numResultRegisters);
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
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
                    //TODO (OHR#3#): Create a function to process results according to user requests (plaintext, html, etc.) move the above code (HTML) there.
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
        } while (0) //Local free() macro.

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
                    cmeStrConstrAppend(responseText,"<p>Deleted registers: %d</p><br>",numResultRegisters);
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
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
        } while (0) //Local free() macro.

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
                    cmeStrConstrAppend(responseText,"<p>Deleted registers: %d</p><br>",numResultRegisters);
                    //TODO (OHR#3#): Create a function to process results according to user requests (plaintext, html, etc.) move the above code (HTML) there.
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
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
        } while (0) //Local free() macro.

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
                    cmeStrConstrAppend(responseText,"<p>Deleted registers: %d</p><br>",numResultRegisters);
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
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
        } while (0) //Local free() macro.

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
                    cmeStrConstrAppend(responseText,"<p>Deleted registers: %d</p><br>",numResultRegisters);
                    //TODO (OHR#3#): Create a function to process results according to user requests (plaintext, html, etc.) move tha above code (HTML) there.
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
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
        } while (0) //Local free() macro.

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
                    cmeStrConstrAppend(responseText,"<p>Deleted registers: %d</p><br>",numResultRegisters);
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
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

int cmeWebServiceProcessDocumentTypeResource (char **responseText, char **responseFilePath, int *responseCode,
                                     const char *url, const char **urlElements, const char **argumentElements, const char *method)
{   //IDD ver. 1.0.20 definitions.
    int cont, cont2;
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
    const int numSupportedDocTypes=3;
    const char *supportedDocTypes[3]={"file.csv","file.raw","script.perl"};

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
        } while (0) //Local free() macro.

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
    if(!strcmp(method,"OPTIONS")) //Method = OPTIONS is ok, process:
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
            cont2=0;
            for (cont=0; cont<numSupportedDocTypes; cont++)
            {
                if (!strcmp(urlElements[5],supportedDocTypes[cont])) //Check for valid document type.
                {
                    cont2++;
                }
            }
            if (cont2) //OK - Supported type.
            {
                cmeStrConstrAppend(responseText,"<b>200 OK - document type %s is supported. Options for document type resources:</b><br>"
                   "%sLatest IDD version: <code>%s</code>",urlElements[5],cmeWSMsgDocumentTypeOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentTypeResource(), OPTIONS successful for documentType resource."
                        " Method: '%s', URL: '%s'!\n",method,url);
#endif
                cmeWebServiceProcessDocumentTypeResourceFree();
                *responseCode=200;
                return(0);
            }
            else //Error - Unsupported type
            {
                cmeStrConstrAppend(responseText,"<b>404 ERROR - Unsupported document type %s! Options for document type resources:</b><br>"
                   "%sLatest IDD version: <code>%s</code>",urlElements[5],cmeWSMsgDocumentTypeOptions,cmeInternalDBDefinitionsVersion);
#ifdef DEBUG
                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentTypeResource(), OPTIONS successful for documentType resource."
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
    const int numValidPOSTSave=3;       //3 parameters + 4 (storageId,type,orgResourceId,documentId) from URL; columnFile, partHash, totalParts, partId, columnId, lastModified are set automatically
    const int numValidPUTSave=3;        //3 parameters + 4 (storageId,type,orgResourceId,documentId) from URL; columnFile, partHash, totalParts, partId, columnId, lastModified can't be updated (otherwise file indexes might break).
    const char *tableName="documents";
    const char *validGETALLMatchColumns[9]={"_userId","_orgId","_resourceInfo","_columnFile",
                                            "_partHash","_totalParts","_partId","_lastModified","_columnId"};
    const char *validPOSTSaveColumns[3]={"userId","orgId","*resourceInfo"};
    const char *validPUTSaveColumns[3]={"userId","orgId","*resourceInfo"};
    const char *attributes[]={"shuffle","protect"};                           // TODO (OHR#2#): TMP attributes to test POST. We MUST take these arguments from the user, via API!
    const char *attributesData[]={cmeDefaultEncAlg,cmeDefaultEncAlg};
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
        } while (0) //Local free() macro.

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
        cmeStrConstrAppend(&(columnNames[5]),"partHash");
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
                    if (numResultRegisters>0) //resource is already in DB -> Error
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
                                           "Document resource not included in request! "
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
                    {   // TODO (OHR#1#): if CSV -> Ensure that attribute, attributeData and replaceDB are taken from user parameters via API (right now these are only predefined test values!)
                        resourceInfoText = (char *) MHD_lookup_connection_value(connection,MHD_GET_ARGUMENT_KIND,"*resourceInfo");
                        if(newOrgKey) //Create resource using newOrgKey
                        {
                            result=cmeCSVFileToSecureDB(postImportFile,1,&numCols,&processedRows,userId,orgId,newOrgKey,  //This will call cmeRegisterSecureDB(); no need to call cmePostProtectDBRegister here.
                                                        attributes, attributesData,2,0,
                                                        resourceInfoText,
                                                        urlElements[5], //document type
                                                        urlElements[7], //documentId
                                                        urlElements[3], //storageId
                                                        storagePath);    //storagePath
                        }
                        else //Create resource using orgKey
                        {
                            result=cmeCSVFileToSecureDB(postImportFile,1,&numCols,&processedRows,userId,orgId,orgKey,  //This will call cmeRegisterSecureDB(); no need to call cmePostProtectDBRegister here.
                                                        attributes, attributesData,2,0,
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
                    else if(!strcmp("script.perl",urlElements[5])) //Process 'script.perl' type
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
                    else if(!strcmp("file.raw",urlElements[5])) //Process 'file.raw' type
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
                            return(6);
                        }
                    }
                    // TODO (OHR#2#): process other file types with ' else if (!strcmp("file.XXX",urlElements[5])) {  } '
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
                                fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), cmeFileOverwriteAndDelete() error, "
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
                    cmeStrConstrAppend(responseText,"<p>Deleted registers: %d</p><br>",numResultRegisters);
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
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
                    fprintf(stderr,"CaumeDSE Debug: cmeWebServiceProcessDocumentResource(), DELETE error!, "
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
    #define cmeWebServicePOSTIterationFree() \
        do { \
            cmeFree(tmpFilename); \
        } while (0) //Local free() macro.

    if (con_info->threadStatus==1) //Job is done, but we need to wait until the request has been fully processed by other parts of the program
    {
        sleep(cmeDefaultThreadWaitSeconds);
        return MHD_YES;
    }
    else if (con_info->threadStatus==2) //Job is done and request processing is done as well. Finish the routine.
    {
        sleep(cmeDefaultThreadWaitSeconds);
        return MHD_YES;
    }
    if (0 != strcmp (key, "file"))
    {
        //Since MHD_set_connection_value() just copies the pointers to strings, we need to ensure that key and data are persistent during POST iterations
        cmeStrConstrAppend(&(con_info->postArglist[con_info->postArgCont]),"%s",key);
        cmeStrConstrAppend(&(con_info->postArglist[(con_info->postArgCont)+1]),"%s",data);
        MHD_set_connection_value(con_info->connection,MHD_GET_ARGUMENT_KIND,
                                 con_info->postArglist[con_info->postArgCont],
                                 con_info->postArglist[(con_info->postArgCont)+1]);
        con_info->postArgCont+=2;
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
    int cont,result;
    long fileSize,lcont;
    FILE *fp=NULL;
    struct cmeWebServiceConnectionInfoStruct *con_info = *coninfo_cls;

#ifdef DEBUG
    fprintf(stderr,"\n\n\n\nCaumeDSE Debug: cmeWebServiceRequestCompleted(), Iteration cycle finished with TOE: '%d'.\n\n\n\n",(int)toe);
#endif

    if (NULL == con_info)
    {
        return;
    }
    do  //Wait until the POST processor has collected all data and the request has been processed.
    {
        sleep(cmeDefaultThreadWaitSeconds);
    } while (con_info->threadStatus!=2);
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
            fp=fopen(con_info->fileName,"r+b"); //Reopen file for updating in binary mode.
            if (fp)
            {
                fseek(fp,0,SEEK_END);
                fileSize=ftell(fp);     //Get size of file.
                fseek(fp,0,SEEK_SET);
                for (lcont=0;lcont<fileSize;lcont++) //Overwrite file with 0s.
                {   // TODO (OHR#3#): Add a conditional compiling option to replace simple overwriting with a sanitizing scheme with multiple rounds.                    fputc(0,fp);
                }
                fclose (fp);
                fp=NULL;
            }
            result=remove(con_info->fileName); //Finally, delete the temporary file.
            cmeFree(con_info->fileName);
        }
    }
    cmeFree(con_info->answerString);
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
    const int numValidPUTSave=3;        //3 parameters + 3 (storageId,orgResourceId,type) from URL; columnFile, partHash, totalParts, partId, lastModified, columnId can't be updated (otherwise file indexes might break).
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
        } while (0) //Local free() macro.

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
                    cmeStrConstrAppend(responseText,"<p>Deleted registers: %d</p><br>",numResultRegisters);
                    cmeStrConstrAppend(&((*responseHeaders)[0]),"Engine-results");
                    cmeStrConstrAppend(&((*responseHeaders)[1]),"%d",numResultRegisters);
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
    char *ilist[2];                     //Parameter list for myPerl initialization.
    const int numColumns=15;            //Number of columns in corresponding resource table.
    const int numValidGETALLMatch=9;    //9 parameters + 4 (storageId,orgResourceId,documentId,type) from URL
    const char *tableName="documents";
    const char *validGETALLMatchColumns[9]={"_userId","_orgId","_resourceInfo","_columnFile",
                                            "_partHash","_totalParts","_partId","_lastModified","_columnId"};
    const char *scriptNameMatch[2]={"documentId","type"};
    char *scriptNameValues[2]={"TBD","script.perl"};
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
        } while (0) //Local free() macro.

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
                /* NOTE (ANY#9#): Currently, only script.perl is supported. */
                //Get Script first:
                result=cmeGetUnprotectDBRegisters(pDB,tableName,scriptNameMatch,(const char **)scriptNameValues,
                                                  2,&resultRegisterCols,&numResultRegisterCols,
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
                //initialize Parser and script's global variables:
                ilist[0]="CaumeDSE";
                ilist[1]=tmpRAWFile;//Set pointer to TMP script full path.
                result=cmePerlParserCmdLineInit(2,ilist,cdsePerl);
                if (result) //Error
                {
                    cmeStrConstrAppend(responseText,"<b>500 ERROR Internal server error.</b><br>"
                                       "Internal server error number '%d'."
                                       "METHOD: '%s' URL: '%s'."
                                        "%sLatest IDD version: <code>%s</code>",result,method,url,cmeWSMsgParserScriptResourceOptions,
                                        cmeInternalDBDefinitionsVersion);
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmePerlParserCmdLineInit() error!\n",result,method,url);
#endif
                    cmeWebServiceProcessParserScriptResourceFree();
                    *responseCode=500;
                    return(3);
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
                                " Method: '%s', URL: '%s', cmePerlParserCmdLineInit() error!\n",result,method,url);
#endif
                        cmeWebServiceProcessParserScriptResourceFree();
                        *responseCode=500;
                        return(4);
                    }
                    result=cmeSQLRows(resultDB,"BEGIN TRANSACTION; SELECT * FROM data; COMMIT;",
                               cmeDefaultPerlIterationFunction,cdsePerl); //Select
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
                else if (!strncmp(urlElements[5],"file.raw",8)) //If type of documentId to be parsed is file.raw, then...
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
                /* NOTE (ANY#9#): Currently, only script.perl is supported. */
                //Get Script first:
                result=cmeGetUnprotectDBRegisters(pDB,tableName,scriptNameMatch,(const char **)scriptNameValues,
                                                  2,&resultRegisterCols,&numResultRegisterCols,
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
                //initialize Parser and script's global variables:
                ilist[0]="CaumeDSE";
                ilist[1]=tmpRAWFile;//Set pointer to TMP script full path.
                result=cmePerlParserCmdLineInit(2,ilist,cdsePerl);
                if (result) //Error
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessParserScriptResource(), Error, internal server error '%d'."
                            " Method: '%s', URL: '%s', cmePerlParserCmdLineInit() error!\n",result,method,url);
#endif
                    cmeWebServiceProcessParserScriptResourceFree();
                    *responseCode=500; //No responseText in HEAD!
                    return(12);
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
                                " Method: '%s', URL: '%s', cmePerlParserCmdLineInit() error!\n",result,method,url);
#endif
                        cmeWebServiceProcessParserScriptResourceFree();
                        *responseCode=500;  //No responseText in HEAD!
                        return(13);
                    }
                    result=cmeSQLRows(resultDB,"BEGIN TRANSACTION; SELECT * FROM data; COMMIT;",
                                      cmeDefaultPerlIterationFunction,cdsePerl); //Select
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
                else if (!strncmp(urlElements[5],"file.raw",8)) //If type of documentId to be parsed is file.raw, then...
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
        } while (0) //Local free() macro.

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
        } while (0) //Local free() macro.

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
        } while (0) //Local free() macro.

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
        } while (0) //Local free() macro.

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
                                " Method: '%s', URL: '%s', cmePerlParserCmdLineInit() error!\n",result,method,url);
#endif
                        cmeWebServiceProcessContentClassFree();
                        *responseCode=500;
                        return(1);
                    }
                    result=cmeSQLRows(resultDB,"BEGIN TRANSACTION; SELECT * FROM data; COMMIT;",
                                      NULL,NULL); //Select all data; no parser script.
                    if (!result) //OK
                    {
                        //Construct responseText and create response headers according to the user's outputType (optional) request:
                        result=cmeConstructWebServiceTableResponse ((const char **)cmeResultMemTable, cmeResultMemTableCols, cmeResultMemTableRows,
                                                                    argumentElements, url, method, urlElements[7],
                                                                    responseHeaders, responseText, responseCode);
                        cmeWebServiceProcessContentClassFree();
                        return(0);
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
                        return(2);
                    }
                }
                else if (!strncmp(urlElements[5],"file.raw",8)) //If type of documentId to be parsed is file.raw, then...
                {
                    fileNameValues[0]=(void*)urlElements[7]; //Just point to proper documentId for the file; no need to free it here.
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
                                " Method: '%s', URL: '%s', cmePerlParserCmdLineInit() error!\n",result,method,url);
#endif
                        cmeWebServiceProcessContentClassFree();
                        *responseCode=500;
                        return(8);
                    }
                    result=cmeSQLRows(resultDB,"BEGIN TRANSACTION; SELECT * FROM data; COMMIT;",
                                      NULL,NULL); //Select all data; no parser script.
                    if (!result) //OK
                    {
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
                    else //Error
                    {
#ifdef ERROR_LOG
                        fprintf(stderr,"CaumeDSE Error: cmeWebServiceProcessContentClass(), Error, internal server error '%d'."
                                " Method: '%s', URL: '%s', cmeGetUnprotectDBRegisters error!\n",result,method,url);
#endif
                        cmeWebServiceProcessContentClassFree();
                        *responseCode=500;  //No responseText with HEAD method!
                        return(9);
                    }
                }
                else if (!strncmp(urlElements[5],"file.raw",8)) //If type of documentId to be parsed is file.raw, then...
                {
                    fileNameValues[0]=(void*)urlElements[7]; //Just point to proper documentId for the file; no need to free it here.
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
        } while (0) //Local free() macro.

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
    if (strcmp(userId,userCN)) //Authentication error: userId does not match client certificate CN!
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), Warning, "
                "Authentication error, userId (%s) does not match user certificate CN (user DN: %s).\n",userId,userDN);
#endif
        cmeWebServiceClientCertAuthFree();
        return(9);
    }
    if (strcmp(orgId,userO)) //Authentication error: orgId does not match client certificate O!
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeWebServiceClientCertAuth(), Warning, "
                "Authentication error, orgId (%s) does not match user certificate O (user DN: %s).\n",orgId,userDN);
#endif
        cmeWebServiceClientCertAuthFree();
        return(10);
    }
    if (strcmp(orgId,orgCN)) //Authentication error: orgId does not match issuer organization certificate CN!
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
