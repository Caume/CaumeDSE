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
#ifndef WEBSERVICE_INTERFACE_H_INCLUDED
#define WEBSERVICE_INTERFACE_H_INCLUDED

//Structure to hold connection information to be shared during POST iterations (from 'A Tutorial for GNU libmicrohttpd' v.0.9.8).
struct cmeWebServiceConnectionInfoStruct
{
    int connectionType;
    struct MHD_Connection *connection;
    struct MHD_PostProcessor *postProcessor;
    FILE *filePointer;
    char *fileName;     //required by remove ()
    char *answerString; //Note: this will be dynamically allocated! cmeWebServicePOSTIterationCompleted must free it.
    char **postArglist; //Note: this will be dynamically allocated! cmeWebServicePOSTIterationCompleted must free it.
    int postArgCont;
    int answerCode;
    int threadStatus; //signal to the thread that it is ok to clean stuff here. 0=in progress, 1=thread done,waiting, 2=thread done, closing.
};

//Structure to hold conten reader information to be shared during ContentReader iterations.
struct cmeWebServiceContentReaderStruct
{
    FILE *fpResponseFile;
    char *fileName;
};

//IN-Callback function to process web services connections from clients.
int cmeWebServiceAnswerConnection (void *cls, struct MHD_Connection *connection, const char *url,
                                    const char *method, const char *version, const char *upload_data,
                                    size_t *upload_data_size, void **con_cls);
//IN-Callback function to parse HTTP key pairs (headers, arguments,...) depending on kind.
int cmeWebServiceParseKeys(void *cls, enum MHD_ValueKind kind, const char *key, const char *value);
//IN-Callback function to parse elements of a URI/URL.
int cmeWebServiceParseURL(const char *url, char ***urlElements, int *numUrlElements);
//IN-Callback function to process Web service requests.
int cmeWebServiceProcessRequest (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                 const char *url, const char **urlElements, int numUrlElements,
                                 const char **headerElements,const char **argumentElements, const char *method,
                                 struct MHD_Connection *connection);
//Function to process user resource requests
int cmeWebServiceProcessUserResource (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                      const char *url, const char **urlElements,const char **argumentElements, const char *method);
//Function to process user class resource requests
int cmeWebServiceProcessUserClass (char **responseText, char ***responseHeaders, int *responseCode, const char *url,
                                   const char **urlElements,const char **argumentElements, const char *method);
//Function to process engine resource requests
int cmeWebServiceProcessEngineResource (char **responseText, int *responseCode, const char *url,
                                        const char **argumentElements, const char *method, int *powerStatus);
//Function to process roleTable resource requests
int cmeWebServiceProcessRoleTableResource (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                           const char *url, const char **urlElements, const char **argumentElements, const char *method);
//Function to process organization resource requests
int cmeWebServiceProcessOrgResource (char **responseText, char ***responseHeaders, int *responseCode,
                                     const char *url, const char **urlElements, const char **argumentElements, const char *method);
//Function to process organization class resource requests
int cmeWebServiceProcessOrgClass (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                  const char *url, const char **argumentElements, const char *method);
//Function to process storage resource requests
int cmeWebServiceProcessStorageResource (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                         const char *url, const char **urlElements, const char **argumentElements, const char *method);
//Function to process storage class resource requests
int cmeWebServiceProcessStorageClass (char **responseText, char ***responseHeaders, int *responseCode,
                                      const char *url, const char **urlElements, const char **argumentElements, const char *method);
//Function to process documentType resource requests
int cmeWebServiceProcessDocumentTypeResource (char **responseText, char **responseFilePath, int *responseCode,
                                              const char *url, const char **urlElements, const char **argumentElements, const char *method);
//Function to process document resource requests
int cmeWebServiceProcessDocumentResource (char **responseText, char ***responseHeaders, int *responseCode,
                                          const char *url, const char **urlElements, const char **argumentElements, const char *method,
                                          const char *storagePath, struct MHD_Connection *connection);
//Function to process document class resource requests
int cmeWebServiceProcessDocumentClass (char **responseText, char ***responseHeaders, int *responseCode,
                                       const char *url, const char **urlElements, const char **argumentElements,
                                       const char *method, const char *storagePath);
//Function to process parserScripts resource requests for handling document content
int cmeWebServiceProcessParserScriptResource (char **responseText, char ***responseHeaders, int *responseCode,
                                              const char *url, const char **urlElements, const char **argumentElements,
                                              const char *method, const char *storagePath);
//Function to process document content requests
int cmeWebServiceProcessContentClass (char **responseText, char **responseFilePath, char ***responseHeaders, int *responseCode,
                                      const char *url, const char **urlElements, const char **argumentElements, const char *method,
                                      const char *storagePath);
//IN-CALLBACK function to iterate message chunks of POST requests.
int cmeWebServicePOSTIteration (void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
                                       const char *filename, const char *content_type,
                                       const char *transfer_encoding, const char *data, uint64_t off,
                                       size_t size);
//IN-CALLBACK function to finish message chunks iteration of POST requests.
void cmeWebServiceRequestCompleted (void *cls, struct MHD_Connection *connection,
                                    void **coninfo_cls, enum MHD_RequestTerminationCode toe);
//Function to get the file path for a specific storageId and organizationId.
int cmeWebServiceGetStoragePath (char **storagePath, const char *storageId, const char *orgResourceId, const char *orgKey);
//Function to confirm that a specific orgId is valid (registered).
int cmeWebServiceConfirmOrgId (const char *orgResourceId, const char *orgKey);
//Function to confirm that a specific userId is valid (registered).
int cmeWebServiceConfirmUserId (const char *userResourceId, const char *orgKey);
//Function to verify client certificate chain in a TLS session.
int cmeWebServiceClientCertAuth (const char *userId, const char *orgId, struct MHD_Connection *connection);

#endif // WEBSERVICE_INTERFACE_H_INCLUDED
