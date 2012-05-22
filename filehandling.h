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
#ifndef FILEHANDLING_H_INCLUDED
#define FILEHANDLING_H_INCLUDED

// Function wrapper for Cloud storage services or standard filesystem that checks if a Directory exists.
int cmeDirectoryExists (const char *dirPath);
// Import to memory rows from a CVS file
int cmeCSVFileRowsToMemTable (const char *fName, char ***elements, int *numCols,
                         int *processedRows, int hasColNames, int rowStart, int rowEnd);
// Free reserved memory by cmeCSVFileRowsToMem()
int cmeCSVFileRowsToMemTableFinal (char ***elements, int numCols,int processedRows);
// Function to read a file into a char array.
int cmeLoadStrFromFile (char **pDstStr, const char *filePath, int *dstStrLen);
// Function to write to a file from a char array.
int cmeWriteStrToFile (char *pSrcStr, const char *filePath, int srcStrLen);
// Function that imports a CSV file into several, security preprocessed, SQLite Databases.
// ~ POST file.csv
int cmeCSVFileToSecureDB (const char *CSVfName,const int hasColNames,int *numCols,int *processedRows,
                          const char *userId,const char *orgId,const char *orgKey, const char **attribute,
                          const char **attributeData, const int numAttribute,const int replaceDB,
                          const char *resourceInfo, const char *documentType, const char *documentId,
                          const char *storageId, const char *storagePath);
// Function that imports a memory table into several, security preprocessed, SQLite Databases (e.g. after inserting/updating a contentRow).
int cmeMemTableToSecureDB (const char **memTable, const int numCols,const int numRows,
                           const char *userId,const char *orgId,const char *orgKey, const char **attribute,
                           const char **attributeData, const int numAttribute, const int replaceDB,
                           const char *resourceInfo, const char *documentType, const char *documentId,
                           const char *storageId, const char *storagePath);
// Function that slices and encrypts a raw file into several parts.
// ~ POST file.raw, script.perl, ...
int cmeRAWFileToSecureFile (const char *rawFileName, const char *userId,const char *orgId,const char *orgKey,
                            const char *resourceInfo, const char *documentType, const char *documentId,
                            const char *storageId, const char *storagePath);
// Function that unprotects and stores a protected raw file in an unprotected, temporal file.
// ~ GET file.raw, script.perl, ...
int cmeSecureFileToTmpRAWFile (char **tmpRAWFile, sqlite3 *pResourcesDB,const char *documentId,
                               const char *documentType, const char *documentPath, const char *orgId,
                               const char *storageId, const char *orgKey);
// Function to overwrite and delete a file (meant for Temporal files in restricted/memory storage.
// TODO (ANY#3#): Check and apply the appropriate kind of secure deletion mechanism.
int cmeFileOverwriteAndDelete (const char *filePath);
// Function to process callback iterations from MHD_create_response_from_callback (libmicrohttpd).
ssize_t cmeContentReaderCallback (void *cls, uint64_t pos, char *buf, size_t max);
// Function to perform cleanup after callback iterations from MHD_create_response_from_callback (libmicrohttpd).
void cmeContentReaderFreeCallback (void *cls);



#endif // FILEHANDLING_H_INCLUDED
