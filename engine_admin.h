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
#ifndef ENGINE_ADMIN_H_INCLUDED
#define ENGINE_ADMIN_H_INCLUDED

//Function to create Engine's internal databases for management.
int cmeSetupEngineAdminDBs ();
//Function to register a secure DB in databasesDB, colsDB table.
int cmeRegisterSecureDBorFile (const char **SQLDBfNames, const int numSQLDBfNames, const char **SQLDBfSalts, const char **SQLDBpartHash,
                               const int numSQLDBparts, const char *orgKey, const char *userId, const char *orgId, const char *resourceInfo,
                               const char *type, const char *documentId, const char *storageId, const char *orgResourceId);
//Function to setup WebServices on specified TCP port (HTTP or HTTPS) using libmicrohttpd.
int cmeWebServiceSetup (unsigned short port, int useSSL, const char *sslKeyFile, const char *sslCertFile, const char *caCertFile);
//Function to create default roles within RolesDB for a default Admin user within the default engine organization.
int cmeWebServiceInitAdminSetup (const char *orgKey);
//Function to validate resource permissions for the specified userId and orgId in RolesDB.
int cmeWebServiceCheckPermissions (const char *method, const char *url, const char **urlElements, const int numUrlElements,
                                   char **responseText, int *responseCode, const char *userId, const char *orgId, const char *orgKey);
//Function to create a default engine organization within ResourcesDB.
int cmeWebServiceInitOrgSetup (const char *orgKey);
//Function to create a default engine storage within ResourcesDB.
int cmeWebServiceInitStorageSetup (const char *orgKey);
//Function to create default Admin user within the default engine organization.
int cmeWebServiceInitAdminIdSetup (const char *orgKey);
//Function to start (and indefinitely restart on each keystroke) the web service.
void cmeWebServiceStart ();
#endif // AUTHHANDLING_H_INCLUDED
