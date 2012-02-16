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
#ifndef ENGINE_INTERFACE_H_INCLUDED
#define ENGINE_INTERFACE_H_INCLUDED

// Function that deletes a SecureDB (registers from ResourcesDB and column files).
// ~ DELETE CSVFile
int cmeDeleteSecureDB (sqlite3 *pResourcesDB,const char *documentId, const char *orgKey, const char *storagePath);
// Function for unprotecting and importing a secure DB into an insecure SQLite3, memory based, database
int cmeSecureDBToMemDB (sqlite3 **resultDB, sqlite3 *pResourcesDB,const char *documentId,
                        const char *orgKey, const char *storagePath);
// Function to get all columns for all registers that match columnValues for each columnNames (after decrypting with orgKey).
int cmeGetUnprotectDBRegisters (sqlite3 *pDB, const char *tableName, const char **columnNames,
                               const char **columnValues,const int numColumnValues, char ***resultRegisterCols,
                               int *numResultRegisterCols, int *numResultRegisters, const char *orgKey);
// Function to delete all registers that match columnValues for each columnNames (after decrypting with orgKey).
int cmeDeleteUnprotectDBRegisters (sqlite3 *pDB, const char *tableName, const char **columnNames,
                                   const char **columnValues,const int numColumnValues, char ***resultRegisterCols,
                                   int *numResultRegisterCols, int *numResultRegisters, const char *orgKey);
// Function to insert all columns for all registers that match columnValues for each columnNames (encrypting with orgKey before insert).
int cmePostProtectDBRegister (sqlite3 *pDB, const char *tableName, const char **columnNames,
                              const char **columnValues,const int numColumnValues, const char *orgKey);
// Function to update all registers that match columnValues for each columnNames using columnNamesUpdate=columnValuesUpdate (after decrypting with orgKey).
int cmePutProtectDBRegisters (sqlite3 *pDB, const char *tableName, const char **columnNames,
                                const char **columnValues,const int numColumnValues, const char **columnNamesUpdate,
                                const char **columnValuesUpdate,const int numColumnValuesUpdate, char ***resultRegisterCols,
                                int *numResultRegisterCols, int *numResultRegisters, const char *orgKey);
//Function to process all Match and Save parameters + orgId, userId, orgKey and optional parameter newOrgKey; puts them in corresponding arrays before method execution.
int cmeProcessURLMatchSaveParameters (const char *urlMethod, const char **argumentElements, const char **validNamesToMatch,
                                      const char **validNamesToSave, const int numValidMatch, const int numValidSaves,
                                      char **columnValuesToMatch, char **columnNamesToMatch, char **columnValuesToSave,
                                      char **columnNamesToSave, int *numMatchArgs, int *numSaveArgs, char **userId, char **orgId,
                                      char **orgKey, char **newOrgKey, int *usrArg, int *orgArg, int *keyArg, int *newKeyArg);

#endif // ENGINE_INTERFACE_H_INCLUDED
