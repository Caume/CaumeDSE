/***
Copyright 2010-2026 by Omar Alejandro Herrera Reyna

    Caume Data Security Engine, also known as CaumeDSE is released under the
    GNU General Public License by the Copyright holder, with the additional
    exemption that compiling, linking, and/or using OpenSSL is allowed.

***/
#include "common.h"
#include "engine_admin.h"
#include "function_tests.h"
#include "runtime.h"

static void cmeDebugTestsPrintUsage(const char *programName)
{
    printf("Usage: %s [--web-service http|https]\n",
           programName ? programName : "CaumeDSE-debug-tests");
}

static int cmeDebugTestsRunWebService(const char *protocol)
{
    const char *httpEnv=getenv("CDSE_DEBUG_TEST_HTTP_PORT");
    const char *httpsEnv=getenv("CDSE_DEBUG_TEST_HTTPS_PORT");
    int port=0;

    if (!strcmp(protocol,"http"))
    {
        port=(httpEnv && *httpEnv) ? atoi(httpEnv) : cmeDefaultWebservicePort;
        printf("--- Running DEBUG HTTP web service on port %d\n",port);
        if (cmeSetupEngineAdminDBs())
        {
            fprintf(stderr,"CaumeDSE Error: debug_tests(), can't initialize EngineAdmin databases.\n");
            return(1);
        }
        return(cmeWebServiceSetup((unsigned short)port,0,NULL,NULL,NULL,0));
    }
    if (!strcmp(protocol,"https"))
    {
        port=(httpsEnv && *httpsEnv) ? atoi(httpsEnv) : cmeDefaultWebServiceSSLPort;
        printf("--- Running DEBUG HTTPS web service on port %d\n",port);
        if (cmeSetupEngineAdminDBs())
        {
            fprintf(stderr,"CaumeDSE Error: debug_tests(), can't initialize EngineAdmin databases.\n");
            return(1);
        }
        return(cmeWebServiceSetup((unsigned short)port,1,cmeDefaultHTTPSKeyFile,
                                  cmeDefaultHTTPSCertFile,cmeDefaultCACertFile,0));
    }
    fprintf(stderr,"CaumeDSE Error: unknown web service protocol '%s'.\n",protocol);
    return(2);
}

int main(int argc, char *argv[], char *env[])
{
    unsigned char *bufIn=NULL;
    unsigned char *bufOut=NULL;
    char *title=NULL;
    int webServiceMode=0;
    const char *webServiceProtocol=NULL;
    int result=0;
    #define debugTestsFree() \
        do { \
            cmeFree(title); \
            cmeEndRuntime(&bufIn,&bufOut,&cdsePerl); \
            PERL_SYS_TERM(); \
        } while (0)

    if (argc>1)
    {
        if ((!strcmp(argv[1],"--help"))||(!strcmp(argv[1],"-h")))
        {
            cmeDebugTestsPrintUsage(argv[0]);
            return(0);
        }
        if ((!strcmp(argv[1],"--web-service"))&&(argc==3))
        {
            webServiceMode=1;
            webServiceProtocol=argv[2];
        }
        else
        {
            fprintf(stderr,"CaumeDSE Error: invalid debug test option.\n");
            cmeDebugTestsPrintUsage(argv[0]);
            return(2);
        }
    }

    PERL_SYS_INIT3(&argc,&argv,&env);
    if (cmeSetupRuntime(&bufIn,&bufOut,&cdsePerl))
    {
        PERL_SYS_TERM();
        return(1);
    }
    cmeStrConstrAppend(&title,"Caume Data Security Engine DEBUG tests, ver. %s - %s.\n",
                       cmeEngineVersion,cmeCopyright);
    printf("%s",title);

    if (webServiceMode)
    {
        result=cmeDebugTestsRunWebService(webServiceProtocol);
        debugTestsFree();
        return(result);
    }

    testCryptoSymmetricGCM();
    testCryptoSymmetricGCM_ByteString();
    testEngMgmnt();
    testCryptoSymmetric(bufIn,bufOut);
    testCryptoDigest_Str(bufIn);
    testCryptoHMAC();
    testPerl(cdsePerl);
    testDB(cdsePerl);
    testCSV();
    testJSONResponses();
    testWebServices();

    debugTestsFree();
    return(0);
}
