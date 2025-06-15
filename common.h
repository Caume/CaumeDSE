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

    This product includes software from the GNU Libmicrohttpd project, Copyright
    © 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
    2008, 2009, 2010 , 2011, 2012 Free Software Foundation, Inc.

    This product includes software from Perl5, which is Copyright (C) 1993-2005,
    by Larry Wall and others.

***/
#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

// --- Autoconf includes
#if HAVE_CONFIG_H
#include "config.h"
#endif

//TODO (OHR#8#): Replace calls to malloc with audited, simple, wrapper function.
//TODO (OHR#9#): Define function to read Globals in main.c from config file
#define prngSeedBytes 16
#define evpMaxHashStrLen 2*64+1         //Max length for character representation of hex bytestr hash {RECOMMENDED: 2*64+1}. At 2 chars per byte, SHA-512 requires 64 bytes, + 1 ending null char.
#define evpMaxHashBytesLen 64           //Max length for byte representation of hash {RECOMMENDED: 64}. SHA-512 requires 64 bytes.
#define evpBufferSize 1024              //Default Cipher buffer size {4096}
#define evpMaxKeyIvLen 64               //Max size for Key and IV arrays {64 bytes allows symmetric crypto keys of up to 512 bits}
#define evpSaltBufferSize 16             //EVP_BytesToKey{} uses this many bytes long salts to derive key and iv.
#define bioReadBufferSize 4096          //Buffer Size for BIO_read {RECOMMENDED: 4096}.
#ifdef BYPASS_TLS_IN_HTTP
#define cmeBypassTLSAuthenticationInHTTP BYPASS_TLS_IN_HTTP //Enable/disable bypassing TLS authentication with non TLS sessions {i.e. HTTP} with config. script {1=ON, 0=OFF}.
#else
#define cmeBypassTLSAuthenticationInHTTP 1 //Allows bypassing TLS authentication with non TLS sessions {e.g. when testing HTTP connections with TLS auth. enabled, where TLS authentication would allways fail obvoiusly}.
#endif /*BYPASS_TLS_IN_HTTP*/
#define cmeUseTLSAuthentication 1       //TLS user authentication module {1=ON, 0=OFF}.
#define cmeUseOAUTHAuthentication 0     //OAUTH user authentication module {1=ON, 0=OFF}. NOTE: NOT YET IMPLEMENTED
#define cmeCSVRowBuffer 5000            //Buffer for processing CSV files - reads at most this # of rows at a time {RECOMMENDED: 5000} and processes them before reading more.
#define cmeMaxCSVRowsInPart 500         //Max number of rows in a column slice {part} {RECOMMENDED: 1000}
#define cmeMaxCSVRowSize 10240          //Max row size in a CSV file. {10240}
#define cmeMaxCSVElemSize 4096          //Max element size in a CSV element.
#define cmeMaxCSVDefaultColNameSize 15  //Max size of default CSV column name: "Column_xxxxxxxx".
#define cmeMaxCSVColumns 256            //Max # of column parts in a CSV file
#define cmeMaxCSVPartsPerColumn 10000   //Max {estimated} number of parts that a CSV table can hold {required by cmeSecureDBtoMemDB}.
#define cmeMaxRAWDataInPart 4000        //Max number of bytes in a secure file slice {part}, estimated from smallest SQLITE secureDB column files. {RECOMMENDED: 5120}
#define cmeDefaultContentReaderCallbackPageSize 1024*32     //Default Page size for ContentReaderCallback functions.    {RECOMMENDED: 1024*32}

#ifdef PATH_DATADIR
#define cmeDefaultFilePath PATH_DATADIR "/"                     //Default virtual root path for storing engine files {DBs}.
#define cmeDefaultSecureTmpFilePath PATH_DATADIR "/secureTmp/"  //Default virtual root for storing temporal files that in a restricted storage {e.g. encrypted memory FS this though access restrictions}.
#define cmeDefaultHTTPSKeyFile PATH_DATADIR "/server.key"       //Default file with PEM key file for TLS/SSL server.
#define cmeDefaultHTTPSCertFile PATH_DATADIR "/server.pem"      //Default file with PEM cert file for TLS/SSL server.
#define cmeDefaultCACertFile PATH_DATADIR "/ca.pem"             //Default file with PEM cert file for CA to validate client certificates.
#define cmeAdminDefaultStoragePath PATH_DATADIR "/"             //Default storage path for first organization { = cmeDefaultFilePath}.
#else
#define cmeDefaultFilePath "/opt/cdse/"                     //Default virtual root path for storing engine files {DBs}.
#define cmeDefaultSecureTmpFilePath "/opt/cdse/secureTmp/"  //default virtual root for storing temporal files that in a restricted storage {e.g. encrypted memory FS this though access restrictions}.
#define cmeDefaultHTTPSKeyFile "/opt/cdse/server.key"       //Default file with PEM key file for TLS/SSL server.
#define cmeDefaultHTTPSCertFile "/opt/cdse/server.pem"      //Default file with PEM cert file for TLS/SSL server.
#define cmeDefaultCACertFile "/opt/cdse/ca.pem"             //Default file with PEM cert file for CA to validate client certificates.
#define cmeAdminDefaultStoragePath "/opt/cdse/"             //Default storage path for first organization { = cmeDefaultFilePath}.
#endif /*PATH_DATADIR*/

#define cmeDefaultResourcesDBName "ResourcesDB"     //Default filename for ResourcesDB sqlite3 filename.
#define cmeDefaultRolesDBName "RolesDB"             //Default filename for ResourcesDB sqlite3 filename.
#define cmeDefaultLogsDBName "LogsDB"               //Default filename for ResourcesDB sqlite3 filename.
#define cmeStorageProvider 0            //Default Cloud storage provider {0=local/standard filesystem}.
#define cmeDefaultIDBytesLen 16         //Default size for CaumeDSE Byte based IDs {e.g. random DB filenames}. Note that it is also used by cmeGetRndSalt for this purpose.
#define cmeDefaultSecureDBSaltLen 16    //Default salt length for meta and data salts within secure databases.
#define cmeDefaultValueSaltLen 16        //Default size for prep-ended bytes for internal databases' encrypted values.
#define cmeDefaultValueSaltCharLen 2*cmeDefaultValueSaltLen             //Default size for CaumeDSE ByteHexStr value salts used in protected DBs.
#define cmeDefaultSqlBufferLen 8192         //Default size of Buffer for SQL queries. {8192}
#define cmeDefaultEncAlg "aes-256-gcm"      //Default algorithm for symmetric encryption in engine admin. databases.
#define cmeDefaultHshAlg "sha256"           //Default algorithm for bytestring hashing {digest}.
#define cmeDefaultMACAlg "sha256"             //Default algorithm for bytestring HMAC MACs .
#define cmeDefaultInsertSqlRows 512         //Default # of rows to be inserted into a sqlite3 db at a time {within a Begin - Commit block}.
#define cmeDefaultWebservicePort 80         //Default port for regular HTTP web services.
#define cmeDefaultWebServiceSSLPort 443     //Default port for TLS/SSL web services.
#define cmeDefaultThreadWaitSeconds 0                     //Default number of seconds to wait for thread synchronization.
#define cmeDefaultPerlIterationFunction     "cmePERLProcessRow"               //Name for the perl iteration function to be called when parsing SQL results with PERL
#define cmeDefaultPerlColNameSetupFunction  "cmePERLProcessColumnNames"       //Name for the perl iteration function to be called when parsing SQL results with PERL
#define cmeDefaultPBKDFCount 2000           //Default count for the key derivation function, cmePBKDF. {Recommended: 2,000. Note: 10,000 = iOS4; iOS3 uses 2,000, RFC 2898 recommends at least 1,000, but note that high values hava a huge impact on performance since we use a different key - different salt with same organization key- for each element!}.
#ifdef PBKDF1_OPENSSL_CLI_COMPATIBILITY
#define cmeDefaultPBKDFVersion PBKDF1_OPENSSL_CLI_COMPATIBILITY //Enable use of old PBKDF1 that is compatible with Openssl command line password KDF {i.e. PKCS5v1.5: MD5 + count=1}. NOT RECOMMENDED!
#else
#define cmeDefaultPBKDFVersion 2 //Default PBKDF2 (PKCS5 v2: HMAC-SHA1 + count=cmeDefaultPBKDFCount) {Recommended setting}.
#endif /*PBKDF1_OPENSSL_CLI_COMPATIBILITY*/

#define cmeAdminDefaultUserId "EngineAdmin"            //Default userId for first administrator account.
#define cmeAdminDefaultStorageId "EngineStorage"       //Default storageId for first administrator account.
#define cmeAdminDefaultOrgId "EngineOrg"               //Default orgId for first administrator account.
                                                       //Note that there is NO default orgKey for EngineOrg... it will be generated randomly the first time the engine is run and won't be stored in clear {so take note!}.

#define cmeInternalDBDefinitionsVersion "1.0.21_1 Jul 2012" //Version of internal DB definitions for engine
// TODO (OHR#4#): Standardize the use of IDD in the project (i.e. avoid direct use of numbers and col. names).
#define cmeIDDanydb_id 0                        //Column index {0 based} for WSID column for most internal sqlite register id
#define cmeIDDanydb_id_name "id"                //Column name for WSID column for most internal sqlite register id
#define cmeIDDanydb_userId 1                    //Column index {0 based} for WSID column for most internal sqlite user id of creator
#define cmeIDDanydb_userId_name "userId"        //Column name for WSID column for most internal sqlite user id of creator
#define cmeIDDanydb_orgId 2                     //Column index {0 based} for WSID column for most internal sqlite organization id of creator
#define cmeIDDanydb_orgId_name "orgId"          //Column name for WSID column for most internal sqlite organization id of creator
#define cmeIDDanydb_salt 3                      //Column index {0 based} for WSID column for most internal sqlite register salt for encryption
#define cmeIDDanydb_salt_name "salt"            //Column name for WSID column for most internal sqlite register salt for encryption
#define cmeIDDColumnFileMetaNumCols 6                               //# of columns for Meta tables in ColumnFile databases
#define cmeIDDColumnFileMeta_attribute 4                            //Column index {0 based} for WSID column attribute
#define cmeIDDColumnFileMeta_attribute_name "attribute"             //Column name for WSID column attribute
#define cmeIDDColumnFileMeta_attributeData 5                        //Column index {0 based} for WSID column attribute data
#define cmeIDDColumnFileMeta_attributeData_name "attributeData"     //Column name for WSID column attribute data
#define cmeIDDColumnFileDataNumCols 11                              //# of columns for Data tables in ColumnFile databases
#define cmeIDDColumnFileData_value 4                                //Column index {0 based} for WSID column value
#define cmeIDDColumnFileData_value_name "value"                     //Column name for WSID column value
#define cmeIDDColumnFileData_rowOrder 5                             //Column index {0 based} for WSID column row order
#define cmeIDDColumnFileData_rowOrder_name "rowOrder"               //Column name for WSID column row order
#define cmeIDDColumnFileData_MAC 6                                  //Column index {0 based} for WSID column MAC {MAC of data before protection}
#define cmeIDDColumnFileData_MAC_name "MAC"                         //Column name for WSID column MAC {MAC of data before protection}
#define cmeIDDColumnFileData_sign 7                            //Column index {0 based} for WSID column digital signature {signed data before protection}
#define cmeIDDColumnFileData_sign_name "sign"                  //Column name for WSID column digital signature {signed data before protection}
#define cmeIDDColumnFileData_MACProtected 8                         //Column index {0 based} for WSID column MAC of protected data {MAC after protection}
#define cmeIDDColumnFileData_MACProtected_name "MACProtected"       //Column name for WSID column MAC of protected data {MAC after protection}
#define cmeIDDColumnFileData_signProtected 9                        //Column index {0 based} for WSID column digital signature of protected data (DS after protection}
#define cmeIDDColumnFileData_signProtected_name "signProtected"     //Column name for WSID column digital signature of protected data (DS after protection}
#define cmeIDDColumnFileData_otphDKey 10                            //Column index {0 based} for WSID column one-time-password homomorphic dynamic key {experimental homomorphic encryption of real numbers}
#define cmeIDDColumnFileData_otphDKey_name "otphDKey"               //Column index {0 based} for WSID column one-time-password homomorphic dynamic key {experimental homomorphic encryption of real numbers}
#define cmeIDDColumnFileMeta_attribute_0 "name"                 //Column value {0 based} for WSID column name attribute
#define cmeIDDColumnFileMeta_attribute_1 "shuffle"              //Column value {0 based} for WSID column shuffle attribute
#define cmeIDDColumnFileMeta_attribute_2 "protect"              //Column value {0 based} for WSID column protection attribute
#define cmeIDDColumnFileMeta_attribute_3 "sign"                 //Column value {0 based} for WSID column digital signature before protection attribute
#define cmeIDDColumnFileMeta_attribute_4 "signProtected"        //Column value {0 based} for WSID column digital signature after protection attribute
#define cmeIDDColumnFileMeta_attribute_5 "MAC"                  //Column value {0 based} for WSID column MAC before protection attribute
#define cmeIDDColumnFileMeta_attribute_6 "MACProtected"         //Column value {0 based} for WSID column MAC after protection attribute
#define cmeIDDResourcesDBDocumentsNumCols 15                            //# of columns for User tables in ResourceDB databases
#define cmeIDDResourcesDBDocuments_resourceInfo 4                       //Column index {0 based} for WSID column resource information
#define cmeIDDResourcesDBDocuments_resourceInfo_name "resourceInfo"     //Column name for WSID column resource information
#define cmeIDDResourcesDBDocuments_columnFile 5                         //Column index {0 based} for WSID column column file
#define cmeIDDResourcesDBDocuments_columnFile_name "columnFile"         //Column name for WSID column column file
#define cmeIDDResourcesDBDocuments_type 6                               //Column index {0 based} for WSID column type
#define cmeIDDResourcesDBDocuments_type_name "type"                     //Column name for WSID column type
#define cmeIDDResourcesDBDocuments_documentId 7                         //Column index {0 based} for WSID column document id
#define cmeIDDResourcesDBDocuments_documentId_name "documentId"         //Column name for WSID column document id
#define cmeIDDResourcesDBDocuments_storageId 8                          //Column index {0 based} for WSID column storage id
#define cmeIDDResourcesDBDocuments_storageId_name "storageId"           //Column name for WSID column storage id
#define cmeIDDResourcesDBDocuments_orgResourceId 9                      //Column index {0 based} for WSID column organization resource id
#define cmeIDDResourcesDBDocuments_orgResourceId_name "orgResourceId"   //Column name for WSID column organization resource id
#define cmeIDDResourcesDBDocuments_partMAC 10                           //Column index {0 based} for WSID column MAC of file part (MAC after encryption}
#define cmeIDDResourcesDBDocuments_partMAC_name "partMAC"               //Column name for WSID column MAC of file part (MAC after encryption}
#define cmeIDDResourcesDBDocuments_totalParts 11                        //Column index {0 based} for WSID column total file parts
#define cmeIDDResourcesDBDocuments_totalParts_name "totalParts"         //Column name for WSID column total file parts
#define cmeIDDResourcesDBDocuments_partId 12                            //Column index {0 based} for WSID column file part id
#define cmeIDDResourcesDBDocuments_partId_name "partId"                 //Column name for WSID column file part id
#define cmeIDDResourcesDBDocuments_lastModified 13                      //Column index {0 based} for WSID column last modified date {UNIX/POSIX time}
#define cmeIDDResourcesDBDocuments_lastModified_name "lastModified"     //Column name for WSID column last modified date {UNIX/POSIX time}
#define cmeIDDResourcesDBDocuments_columnId 14                          //Column index {0 based} for WSID column column id
#define cmeIDDResourcesDBDocuments_columnId_name "columnId"             //Column name for WSID column column id
#define cmeIDDResourcesDBUsersNumCols 12                                //# of columns for User tables in ResourceDB databases
#define cmeIDDResourcesDBUsers_resourceInfo 4                           //Column index {0 based} for WSID column resource information
#define cmeIDDResourcesDBUsers_resourceInfo_name "resourceInfo"         //Column name for WSID column resource information
#define cmeIDDResourcesDBUsers_certificate 5                            //Column index {0 based} for WSID column user digital certificate
#define cmeIDDResourcesDBUsers_certificate_name "certificate"           //Column name for WSID column user digital certificate
#define cmeIDDResourcesDBUsers_publicKey 6                              //Column index {0 based} for WSID column user publick key
#define cmeIDDResourcesDBUsers_publicKey_name "publicKey"               //Column name for WSID column user publick key
#define cmeIDDResourcesDBUsers_userResourceId 7                         //Column index {0 based} for WSID column user resource id
#define cmeIDDResourcesDBUsers_userResourceId_name "userResourceId"     //Column name for WSID column user resource id
#define cmeIDDResourcesDBUsers_basicAuthPwdHash 8                       //Column index {0 based} for WSID column user 'basic authentication' password hash
#define cmeIDDResourcesDBUsers_basicAuthPwdHash_name "basicAuthPwdHash" //Column name for WSID column user 'basic authentication' password hash
#define cmeIDDResourcesDBUsers_oauthConsumerKey 9                       //Column index {0 based} for WSID column user OAUTH consumer key
#define cmeIDDResourcesDBUsers_oauthConsumerKey_name "oauthConsumerKey" //Column name for WSID column user OAUTH consumer key
#define cmeIDDResourcesDBUsers_oauthConsumerSecret 10                   //Column index {0 based} for WSID column user OAUTH consumer secret
#define cmeIDDResourcesDBUsers_oauthConsumerSecret_name "oauthConsumerSecret"   //Column index {0 based} for WSID column user OAUTH consumer secret
#define cmeIDDResourcesDBUsers_orgResourceId 11                         //Column index {0 based} for WSID column user organization resource id
#define cmeIDDResourcesDBUsers_orgResourceId_name "orgResourceId"       //Column name for WSID column user organization resource id
#define cmeIDDResourcesDBStorageNumCols 12                              //# of columns for Storage tables in ResourceDB databases
#define cmeIDDResourcesDBStorage_resourceInfo 4                         //Column index {0 based} for WSID column storage resource information
#define cmeIDDResourcesDBStorage_resourceInfo_name "resourceInfo"       //Column name for WSID column storage resource information
#define cmeIDDResourcesDBStorage_location 5                             //Column index {0 based} for WSID column storage location
#define cmeIDDResourcesDBStorage_location_name "location"               //Column name for WSID column storage location
#define cmeIDDResourcesDBStorage_type 6                                 //Column index {0 based} for WSID column storage type
#define cmeIDDResourcesDBStorage_type_name "type"                       //Column name for WSID column storage type
#define cmeIDDResourcesDBStorage_storageId 7                            //Column index {0 based} for WSID column storage id
#define cmeIDDResourcesDBStorage_storageId_name "storageId"             //Column name for WSID column storage id
#define cmeIDDResourcesDBStorage_accessPath 8                           //Column index {0 based} for WSID column storage access path
#define cmeIDDResourcesDBStorage_accessPath_name "accessPath"           //Column name for WSID column storage access path
#define cmeIDDResourcesDBStorage_accessUser 9                           //Column index {0 based} for WSID column storage access user id
#define cmeIDDResourcesDBStorage_accessUser_name "accessUser"           //Column name for WSID column storage access user id
#define cmeIDDResourcesDBStorage_accessPassword 10                      //Column index {0 based} for WSID column storae access user password/key/secret
#define cmeIDDResourcesDBStorage_accessPassword_name "accessPassword"   //Column name for WSID column storae access user password/key/secret
#define cmeIDDResourcesDBStorage_orgResourceId 11                       //Column index {0 based} for WSID column storage organization resource id
#define cmeIDDResourcesDBStorage_orgResourceId_name "orgResourceId"     //Column name for WSID column storage organization resource id
#define cmeIDDResourcesDBOrganizationsNumCols 8                         //# of columns for Storage tables in ResourceDB databases
#define cmeIDDResourcesDBOrganizations_resourceInfo 4                   //Column index {0 based} for WSID column organization resource information
#define cmeIDDResourcesDBOrganizations_resourceInfo_name "resourceInfo" //Column name for WSID column organization resource information
#define cmeIDDResourcesDBOrganizations_certificate 5                    //Column index {0 based} for WSID column organization digital certificate
#define cmeIDDResourcesDBOrganizations_certificate_name "certificate"   //Column name for WSID column organization digital certificate
#define cmeIDDResourcesDBOrganizations_publicKey 6                      //Column index {0 based} for WSID column organization public key
#define cmeIDDResourcesDBOrganizations_publicKey_name "publicKey"       //Column name for WSID column organization public key
#define cmeIDDResourcesDBOrganizations_orgResourceId 7                  //Column index {0 based} for WSID column organization resource id that created this organization
#define cmeIDDResourcesDBOrganizations_orgResourceId_name "orgResourceId"   //Column name for WSID column organization resource id that created this organization
#define cmeIDDRolesDBAnyTableNumCols 12                             //# of columns for tables in RolesDB databases
#define cmeIDDRolesDBAnyTable__get 4                                //Column index {0 based} for WSID column GET method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable__get_name "_get"                      //Column name for WSID column GET method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable__post 5                               //Column index {0 based} for WSID column POST method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable__post_name "_post"                    //Column name for WSID column POST method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable__put 6                                //Column index {0 based} for WSID column PUT method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable__put_name "_put"                      //Column name for WSID column PUT method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable__delete 7                             //Column index {0 based} for WSID column DELETE method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable__delete_name "_delete"                //Column name for WSID column DELETE method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable__head 8                               //Column index {0 based} for WSID column HEAD method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable__head_name "_head"                    //Column name for WSID column HEAD method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable__options 9                            //Column index {0 based} for WSID column OPTIONS method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable__options_name "_options"              //Column name for WSID column OPTIONS method permissions ('1'=allow, '0'=disallow)
#define cmeIDDRolesDBAnyTable_userResourceId 10                     //Column index {0 based} for WSID column user resource id for which permissions apply
#define cmeIDDRolesDBAnyTable_userResourceId_name "userResourceId"  //Column name for WSID column user resource id for which permissions apply
#define cmeIDDRolesDBAnyTable_orgResourceId 11                      //Column index {0 based} for WSID column organization resource id of user for which permissions apply
#define cmeIDDRolesDBAnyTable_orgResourceId_name "orgResourceId"    //Column name for WSID column organization resource id of user for which permissions apply
#define cmeIDDLogsDBTransactionsNumCols 16                          //# of columns for table transactions in LogsDB database
#define cmeIDDLogsDBTransactions_requestMethod 4                            //Column index {0 based} for WSID column request method
#define cmeIDDLogsDBTransactions_requestMethod_name "requestMethod"         //Column name for WSID column request method
#define cmeIDDLogsDBTransactions_requestUrl	5                               //Column index {0 based} for WSID column request URL
#define cmeIDDLogsDBTransactions_requestUrl_name "requestUrl"               //Column name for WSID column request URL
#define cmeIDDLogsDBTransactions_requestHeaders 6                           //Column index {0 based} for WSID column request headers (separated with \n)
#define cmeIDDLogsDBTransactions_requestHeaders_name "requestHeaders"       //Column name for WSID column request headers
#define cmeIDDLogsDBTransactions_startTimestamp 7                           //Column index {0 based} for WSID column start timestamp
#define cmeIDDLogsDBTransactions_startTimestamp_name "startTimestamp"       //Column name for WSID column start timestamp
#define cmeIDDLogsDBTransactions_endTimestamp 8                             //Column index {0 based} for WSID column end timestamp
#define cmeIDDLogsDBTransactions_endTimestamp_name "endTimestamp"           //Column name for WSID column end timestamp
#define cmeIDDLogsDBTransactions_requestDataSize 9                          //Column index {0 based} for WSID column request data size (in bytes)
#define cmeIDDLogsDBTransactions_requestDataSize_name "requestDataSize"     //Column name for WSID column request data size
#define cmeIDDLogsDBTransactions_responseDataSize 10                        //Column index {0 based} for WSID column response data size (in bytes)
#define cmeIDDLogsDBTransactions_responseDataSize_name "responseDataSize"   //Column name for WSID column response data size
#define cmeIDDLogsDBTransactions_orgResourceId 11                           //Column index {0 based} for WSID column organization resource id
#define cmeIDDLogsDBTransactions_orgResourceId_name "orgResourceId"         //Column name for WSID column organization resource id
#define cmeIDDLogsDBTransactions_requestIPAddress 12                        //Column index {0 based} for WSID column request IP address
#define cmeIDDLogsDBTransactions_requestIPAddress_name "requestIPAddress"   //Column name for WSID column request IP address
#define cmeIDDLogsDBTransactions_responseCode 13                            //Column index {0 based} for WSID column response code
#define cmeIDDLogsDBTransactions_responseCode_name "responseCode"           //Column name for WSID column response code
#define cmeIDDLogsDBTransactions_responseHeaders 14                         //Column index {0 based} for WSID column response headers
#define cmeIDDLogsDBTransactions_responseHeaders_name "responseHeaders"     //Column name for WSID column response headers
#define cmeIDDLogsDBTransactions_authenticated 15                           //Column index {0 based} for WSID column authentication flag ('1'=authenticated -> fields are encrypted with orgKey, '0'=not authenticated -> fields are NOT encrypted)
#define cmeIDDLogsDBTransactions_authenticated_name "authenticated"         //Column name for WSID column authentication flag
#define cmeIDDURIMaxDepth 12                                        //Max. # of elements in an URI {excluding parameters}.

#define cmeCopyright "Copyright 2010-2021 by Omar Alejandro Herrera Reyna."   //Copyright string.
#ifdef PACKAGE_VERSION
#define cmeEngineVersion PACKAGE_VERSION
#else
#define cmeEngineVersion "Undefined version"
#endif /*PACKAGE_VERSION*/
#define cmeWSHTMLPageStart "<html><head><title>Caume Data Security Engine </title></head>" \
 "<body><p><b>Caume DSE version " cmeEngineVersion "</b>"\
 "<br>" cmeCopyright "</p><br><br>" //Standard Webpage Title, open tags and (c).

#define cmeWSHTMLPageEnd "</body></html>" //Standard Webpage closing tags.
#define cmeWSMsgEngineOptions "Allowed Methods: <code>GET,PUT,OPTIONS</code><br>" \
                            "Syntax: <code> HTTPS:&#47;&#47;{engine}/engineCommands?" \
                            "userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;<br>" \
                            "*setEnginePower=&lt;on|off&gt;]<br></code>" //Engine resource options.

#define cmeWSMsgUserOptions "Allowed Methods: <code>GET,PUT,POST,DELETE,HEAD,OPTIONS</code><br>" \
                            "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/users/{user}?" \
                            "userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                            "OptionalParameters...]<br></code><br>" //User resource options.

#define cmeWSMsgUserClassOptions "Allowed Methods: <code>GET,PUT,DELETE,HEAD,OPTIONS</code><br>" \
                                 "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/users" \
                                 "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                 "OptionalParameters...]<br></code><br>"   //User class resource options.

#define cmeWSMsgRoleTableOptions "Allowed Methods: <code>GET,PUT,POST,DELETE,HEAD,OPTIONS</code><br>" \
                                 "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/users/{user}/roleTable/{roleTable}" \
                                 "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                 "OptionalParameters...]<br></code><br>" //RoleTable resource options.
#define cmeWSMsgRoleTableClassOptions "Allowed Methods: <code>GET,OPTIONS</code><br>" \
                                    "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/users/{user}/roleTables" \
                                    "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                    "OptionalParameters...]<br></code><br>" //RoleTable class resource options.

#define cmeWSMsgOrgOptions  "Allowed Methods: <code>GET,PUT,POST,DELETE,HEAD,OPTIONS</code><br>" \
                            "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}" \
                            "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                            "OptionalParameters]<br></code><br>" //Org resource options.

#define cmeWSMsgOrgClassOptions "Allowed Methods: <code>GET,PUT,DELETE,HEAD,OPTIONS</code><br>" \
                                "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations" \
                                "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;&lt;&amp;AtLeastOneMatchParameter&gt;[&amp;" \
                                "OptionalParameters...]<br></code><br>"   //Org class resource options.

#define cmeWSMsgStorageOptions  "Allowed Methods: <code>GET,PUT,POST,DELETE,HEAD,OPTIONS</code><br>" \
                                "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/storage/{storage}/" \
                                "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                "OptionalParameters...]<br></code><br>" //Storage resource options.

#define cmeWSMsgStorageClassOptions "Allowed Methods: <code>GET,PUT,DELETE,HEAD,OPTIONS</code><br>" \
                                    "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/storage" \
                                    "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                    "OptionalParameters...]<br></code><br>"   //Storage class resource options.

#define cmeWSMsgDocumentTypeOptions  "Allowed Methods: <code>OPTIONS</code><br>" \
                                     "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/storage/{storage}/documentTypes/{documentType}" \
                                     "/&lt;file.csv|file.raw|script.perl&gt;" \
                                     "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                     "OptionalParameters...]<br></code><br>" //Document Type resource options.

#define cmeWSMsgDocumentTypeClassOptions "Allowed Methods: <code>OPTIONS</code><br>" \
                                         "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/storage/{storage}/documentTypes" \
                                         "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                         "OptionalParameters...]<br></code><br>"   //DocumentType class resource options.

#define cmeWSMsgDocumentOptions  "Allowed Methods: <code>GET,PUT,POST,DELETE,HEAD,OPTIONS</code><br>" \
                                 "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/storage/{storage}/documentTypes/{documentType}" \
                                 "/documents/{document}" \
                                 "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                 "OptionalParameters...]<br></code><br>" //Document resource options.

#define cmeWSMsgDocumentClassOptions  "Allowed Methods: <code>GET,PUT,DELETE,HEAD,OPTIONS</code><br>" \
                                      "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/storage/{storage}/documentTypes/{documentType}" \
                                      "/documents/{document}" \
                                      "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                      "OptionalParameters...]<br></code><br>" //Document Class resource options.

#define cmeWSMsgParserScriptResourceOptions  "Allowed Methods: <code>GET,HEAD,OPTIONS</code><br>" \
                                              "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/storage/{storage}/documentTypes/{documentType}" \
                                              "/documents/{document}/parserScripts/{parserScript}" \
                                              "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                              "OptionalParameters...]<br></code><br>" //Parser Script resource options.

#define cmeWSMsgContentClassOptions "Allowed Methods: <code>GET,HEAD,OPTIONS</code><br>" \
                                    "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/storage/{storage}/documentTypes/{documentType}" \
                                    "/documents/{document}/content" \
                                    "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                    "OptionalParameters...]<br></code><br>" //Parser Script Class options.

#define cmeWSMsgContenRowOptions  "Allowed Methods: <code>GET,PUT,POST,DELETE,HEAD,OPTIONS</code><br>" \
                                 "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/storage/{storage}/documentTypes/file.csv" \
                                 "/documents/{document}/content/contentRows/{contentRow}" \
                                 "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                 "OptionalParameters...]<br></code><br>" //contentRow resource options.

#define cmeWSMsgContentColumnOptions  "Allowed Methods: <code>GET,POST,DELETE,HEAD,OPTIONS</code><br>" \
                                      "Syntax: <code> HTTPS:&#47;&#47;{engine}/organizations/{organization}/storage/{storage}/documentTypes/file.csv" \
                                      "/documents/{document}/content/contentColumns/{contentColumn}" \
                                      "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                      "OptionalParameters...]<br></code><br>" //contentColumn resource options.

#define cmeWSMsgTransactionClassOptions  "Allowed Methods: <code>GET,HEAD,OPTIONS</code><br>" \
                                          "Syntax: <code> HTTPS:&#47;&#47;{engine}/transactions" \
                                          "?userId=&lt;userid&gt;&amp;orgId=&lt;orgid&gt;&amp;orgKey=&lt;orgKey&gt;[&amp;" \
                                          "OptionalParameters...]<br></code><br>" //tansaction Class options.

/**
#define cmeWSMsgServerErrorPage     cmeWSHTMLPageStart "<b>500 ERROR Internal server error.</b><br>" cmeWSHTMLPageEnd
**/


#define cmeWSHTTPMaxHeaders 32                      //Max. # of HTTP headers elements {pairs} to process.
#define cmeWSHTTPMaxResponseHeaders 32               //Max. # of HTTP response headers {pairs} to process.
#define cmeWSURIMaxArguments 512                    //Max. # of URI arguments {pairs} to process.
#define cmeWSURIMaxMatchSaveArguments 15            //Max. # of arguments available in tables {depends on IDD version!}
#define cmeWSEncoding_CSV 1                         //CSV+plaintext encoding for WS response.
#define cmeWSEncoding_XML 4                         //XML+plaintext encoding for WS response.
#define cmeWSEncoding_RAW 3                         //plaintext encoding for WS response.
#define cmeWSEncoding_HTML 4                        //HTML encoding for WS response {DEFAULT}.
#define cmeWSPostBufferSize 512                     //Buffer size for iterating POST requests.

#define cmeFree(a) {if(a){ free(a); a=NULL;}}       //Internal free function that resets pointers to NULL.
#define MHD_PLATFORM_H                              //for microhttpd.
#define _FILE_OFFSET_BITS 64                        //for microhttpd {MHD_create_response_from_callback}.

// --- General C libraries includes
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDARG_H
#include <stdarg.h>     //handle va_list types for string formatting functions (e.g. vsnprintf())
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STDINT_H
#include <stdint.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>      //toupper(),isalpha()
#endif
#if HAVE_LOCALE_H
#include <locale.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>      //for microhttpd
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>       //for microhttpd
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>     //for microhttpd
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>     //for microhttpd
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>          //for microhttpd
#endif
#if HAVE_LIBMICROHTTPD
#include <microhttpd.h>     //for microhttpd
#endif

#define OPENSSL_SUPPRESS_DEPRECATED
// --- OpenSSL includes
#if HAVE_OPENSSL_BIO_H
#include <openssl/bio.h>      //I/O piped memory and filter functions in OpenSSL
#endif
#if HAVE_OPENSSL_ERR_H
#include <openssl/err.h>      //Error functions
#endif
#if HAVE_OPENSSL_RAND_H
#include <openssl/rand.h>     //Pseudo Random generator functions
#endif
#if HAVE_OPENSSL_BN_H
#include <openssl/bn.h>       //BIG number functions
#endif
#if HAVE_OPENSSL_HMAC_H
#include <openssl/hmac.h>     //Hash Message Authentication Code algorithm
#endif
#if HAVE_OPENSSL_EVP_H
#include <openssl/evp.h>      //Symmetric Encryption algorithms wrapper
#endif
#if HAVE_OPENSSL_BUFFER_H
#include <openssl/buffer.h>
#endif

// --- GnuTLS includes
#if HAVE_GNUTLS_GNUTLS_H
#include <gnutls/gnutls.h>
#endif
#if HAVE_GNUTLS_X509_H
#include <gnutls/x509.h>
#endif

// --- Embedded PERL includes
#if HAVE_EXTERN_H
#include <EXTERN.h> //for embedded perl interpreter
#endif
#if HAVE_PERL_H
#include <perl.h>   //for embedded perl interpreter
#endif
#if HAVE_XSUB_H
#include <XSUB.h>   //for embedded perl interpreter (32 bit machines)
#endif
EXTERN_C void xs_init (pTHX); //for embedded perl interpreter (using dynamically generated: 'xs_init.c')

// --- CaumeDSE includes
#include "crypto.h"
#include "sqlite3.h"
#include "db.h"
#include "perl_interpreter.h"
#include "function_tests.h"
#include "filehandling.h"
#include "engine_interface.h"
#include "engine_admin.h"
#include "strhandling.h"
#include "webservice_interface.h"

// --- Necessary globals
extern PerlInterpreter *cdsePerl;       //Used by cmeSQLIterate() & cmeWebServiceProcessParserScriptResource()
extern char **cmeResultMemTable;        //Used by cmeSQLIterate() & cmeWebServiceProcessParserScriptResource()
extern int cmeResultMemTableRows;       //Used by cmeSQLIterate() & cmeWebServiceProcessParserScriptResource()
extern int cmeResultMemTableCols;       //Used by cmeSQLIterate() & cmeWebServiceProcessParserScriptResource()


#endif // COMMON_H_INCLUDED
