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
#ifndef DBSQLITE_H_INCLUDED
#define DBSQLITE_H_INCLUDED


// Wrapper function for sqlite3_open_v2() to create a new database file
int cmeDBCreateOpen (const char *filename, sqlite3 **ppDB);
// Wrapper function for sqlite3_open_v2() to open an esisting database file for R/W
int cmeDBOpen (const char *filename, sqlite3 **ppDB);
// Wrapper function for sqlite3_close()
int cmeDBClose (sqlite3 *ppDB);
// Wrapper function for sqlite3_backup_init(), sqlite3_backup_step() and sqlite3_backup_finish()
int cmeMemDBLoadOrSave(sqlite3 *pInMemory, const char *zFilename, int isSave);
// Iteration function for cmeSQLRows that wrapps cmePerlParserScriptFunction()
int cmeSQLIterate (const char *args,int numCols,char **pStrResults,char **pColNames);
// Wrapper function for sqlite3_exec() and cmeSQLIterate ()
int cmeSQLRows (sqlite3 *db, const char *sqlQuery, char *perlScriptName,
                PerlInterpreter *myPerl);
// Wrapper function for sqlite3_get_table()
int cmeMemTable (sqlite3 *db, const char *sqlQuery,char ***pQueryResult,
                 int *numRows, int *numColumns);
// Wrapper function for sqlite3_free_table()
int cmeMemTableFinal (char **QueryResult);
// Function to import a Memory table (eg. result from cmeSQLTable() into a SQLite3 DB
int cmeMemTableToMemDB (sqlite3 *dstMemDB, const char **srcMemTable, const int numRows,
                        const int numCols, char *sqlTableName);
// Function to shuffle rows in a SQLite3 Memory table (resulting from cmeSQLTable()).
int cmeMemTableShuffle(char **sqlTable, const int numRows, const int numCols, const int skipHeaderRows,
                       const int skipIdCols);
// Function to (re)order shuffled rows in an unprotected, SQLite3 Memory table (resulting from cmeSQLTable()).
int cmeMemTableOrder(char **sqlTable, const int numRows, const int numCols, const int orderIdxCol, const int skipHeaderRows,
                       const int skipIdCols);
// Function to apply protections on individual secureDB Column Files.
int cmeMemSecureDBProtect (sqlite3 *memSecureDB, const char *orgKey);
// Function to remove protections on individual secureDB Column Files.
int cmeMemSecureDBUnprotect (sqlite3 *memSecureDB, const char *orgKey);
// Function to protect (encrypt and B64 codify) a text string. Note that source length is determined by strlen(). For byte strings use cmeProtectByteString() instead!
int cmeProtectDBValue (const char *value, char **protectedValue, const char *encAlg, char **salt,
                       const char *orgKey, int *protectedValueLen);
// Function to unprotect (decodify B64 and unencrypt) a text string. Note that source length is determined by strlen(). For byte strings use cmeUnprotectByteString() instead!
int cmeUnprotectDBValue (const char *protectedValue, char **value, const char *encAlg, char **salt,
                         const char *orgKey, int *valueLen);
// Function to salt+protect (add salt to value, encrypt and B64 codify) a text string.
int cmeProtectDBSaltedValue (const char *value, char **protectedValue, const char *encAlg, char **salt,
                             const char *orgKey, int *protectedValueLen);
// Function to unprotect+unsalt (decodify B64, unencrypt and remove salt from value) a salt+protected text string.
int cmeUnprotectDBSaltedValue (const char *protectedValue, char **value, const char *encAlg, char **salt,
                               const char *orgKey, int *valueLen);
// Function to reintegrate (before unprotecting) sliced DB columns of secure DB column files in memory.
int cmeMemSecureDBReintegrate (sqlite3 **memSecureDB, const char *orgKey,
                               const int dbNumCols, int *dbNumReintegratedCols);
// Function to wipe and free memory associated with global result database (used by cmeSQLRows, cmeSQLIterate).
int cmeResultMemTableClean ();

#endif // DBSQLITE_H_INCLUDED
