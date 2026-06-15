/***
Copyright 2010-2026 by Omar Alejandro Herrera Reyna

    Caume Data Security Engine, also known as CaumeDSE is released under the
    GNU General Public License by the Copyright holder, with the additional
    exemption that compiling, linking, and/or using OpenSSL is allowed.

***/
#include "common.h"
#include "function_tests.h"
#include "runtime.h"

int main(int argc, char *argv[], char *env[])
{
    unsigned char *bufIn=NULL;
    unsigned char *bufOut=NULL;
    char *title=NULL;
    #define debugTestsFree() \
        do { \
            cmeFree(title); \
            cmeEndRuntime(&bufIn,&bufOut,&cdsePerl); \
            PERL_SYS_TERM(); \
        } while (0)

    PERL_SYS_INIT3(&argc,&argv,&env);
    if (cmeSetupRuntime(&bufIn,&bufOut,&cdsePerl))
    {
        PERL_SYS_TERM();
        return(1);
    }
    cmeStrConstrAppend(&title,"Caume Data Security Engine DEBUG tests, ver. %s - %s.\n",
                       cmeEngineVersion,cmeCopyright);
    printf("%s",title);

    testCryptoSymmetricGCM();
    testCryptoSymmetricGCM_ByteString();
    testEngMgmnt();
    testCryptoSymmetric(bufIn,bufOut);
    testCryptoDigest_Str(bufIn);
    testCryptoHMAC();
    testPerl(cdsePerl);
    testDB(cdsePerl);
    testCSV();
    testWebServices();

    debugTestsFree();
    return(0);
}
