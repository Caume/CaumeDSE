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
#include "runtime.h"

// --- Function prototypes
int main(int argc, char *argv[], char *env[]);   //'main' function

// --- Function definitions
int main(int argc, char *argv[], char *env[])
{
    unsigned char *bufIn=NULL;
    unsigned char *bufOut=NULL;
    char *title=NULL;
    const char *algorithm=cmeDefaultEncAlg;
    const EVP_CIPHER *cipher=NULL;
    #define mainFree() \
        do { \
            cmeFree(title); \
            cmeEndRuntime(&bufIn,&bufOut,&cdsePerl); \
            PERL_SYS_TERM(); \
        } while (0); //Local free() macro

    PERL_SYS_INIT3(&argc,&argv,&env);
    if (cmeSetupRuntime(&bufIn,&bufOut,&cdsePerl))  //Setup/allocate general stuff.
    {
        PERL_SYS_TERM();
        return(1);
    }
    cmeStrConstrAppend(&title,"Caume Data Security Engine, ver. %s - %s.\n",cmeEngineVersion,cmeCopyright);
    printf("%s",title);
    if (cmeGetCipher(&cipher,algorithm))
    { // Error, cmeDefaultEncAlg points to an unsupported encryption algorithm identifier.
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: main(), cmeGetCipher(), unsupported algorithm id"
                " %s specified in cmeDefaultEncAlg!\n",cmeDefaultEncAlg);
#endif
        mainFree();
        return(1);
    }
#ifdef RELEASE
    cmeWebServiceStart();
#elif !defined(DEBUG)
    testWebServices();
#endif
    mainFree();
    return (0);
}
