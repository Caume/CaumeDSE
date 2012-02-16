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
#ifndef STRHANDLING_H_INCLUDED
#define STRHANDLING_H_INCLUDED

#define BASE16SYM           ("0123456789ABCDEF")
#define BASE16VAL           ("\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9|||||||\xA\xB\xC\xD\xE\xF")

#define BASE16_DECODELO(b)      (BASE16VAL[toupper(b) - '0'] << 4)
#define BASE16_DECODEHI(b)      (BASE16VAL[toupper(b) - '0'])

#define BASE16_ENCODELO(b)      (BASE16SYM[((unsigned char)(b))>>4])
#define BASE16_ENCODEHI(b)      (BASE16SYM[((unsigned char)(b))&0xF])

// --- Function prototypes
// Convert Hexadecimal strings to Byte array (chars).
int cmeHexstrToBytes (unsigned char **bytearray, unsigned const char *hexstr);
// Convert Byte array to hexadecimal, uppercase string.
int cmeBytesToHexstr (unsigned const char *bytearray, unsigned char **hexstr, int len);
// Encode string Base 64
int cmeStrToB64(unsigned char *bufIn, unsigned char **bufOut, int biLen, int *written);
// Decode a Bases 64 string
int cmeB64ToStr(unsigned char *bufIn, unsigned char **bufOut, int biLen, int *written);
// Function to concatenate strings (e.g. to construct parts of queries dynamically)
int cmeStrConstrAppend (char **resultStr, const char *addString, ...);
// Function to construct an INSERT query (SQL).
int cmeStrSqlINSERTConstruct (char **resultQuery, const char *tableName, const char **colNamesValuesPairs,
                              const int numColumns);
// Function to construct an UPDATE query (SQL)
int cmeStrSqlUPDATEonstruct (char **resultQuery, const char *tableName, const char **colNamesValuesPairs,
                            const int numColumns, const char *matchColumn, const char *matchValue);
// Function to create a string with an HTML representation of a MemTable
int cmeMemTableToHTMLTableStr (const char** srcMemTable,char **resultHTMLTableStr,int numColumns,int numRows);
// Function to create a string with a CSV representation of a MemTable
int cmeMemTableToCSVTableStr (const char** srcMemTable,char **resultCSVTableStr,int numColumns,int numRows);
// Function to find a key string within an (URI) Argument pair list, and return a pointer of the corresponding value within the list, if a match is found.
int cmeFindInArgPairList (const char** stringPairs, const char *key, const char **pValue);
// Function to construct a responseStr and add corresponding headers, according to an (optional) outputType parameter, as requested by the user (e.g. csv, html)
int cmeConstructWebServiceTableResponse (const char **resultTable, const int tableCols, const int tableRows,
                                         const char **argumentElements, const char *method, const char *url, const char *documentId,
                                         char ***responseHeaders, char **resultTableStr, int *responseCode);
//Function to get an element (C, ST, L, O, OU or CN) from an x509 DN.
int cmex509GetElementFromDN (const char* DN, const char *elementId, char **element, int *elementLen);

#endif // STRHANDLING_H_INCLUDED
