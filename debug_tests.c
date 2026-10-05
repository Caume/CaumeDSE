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
    printf("Usage: %s [--web-service http|https [--data-dir PRIVATE_DIRECTORY]] | --capabilities\n",
           programName ? programName : "CaumeDSE-debug-tests");
}

static int cmeDebugTestsRunWebService(const char *protocol)
{
    const char *httpEnv=getenv("CDSE_DEBUG_TEST_HTTP_PORT");
    const char *httpsEnv=getenv("CDSE_DEBUG_TEST_HTTPS_PORT");
    int port=0;
    char *end=NULL;
    const char *selected=NULL;
    long parsed;

    selected=!strcmp(protocol,"http") ? httpEnv : httpsEnv;
    if (selected && *selected)
    {
        errno=0;
        parsed=strtol(selected,&end,10);
        if (errno || end==selected || *end || parsed<1 || parsed>65535)
        {
            fputs("Invalid DEBUG web service port; expected 1-65535.\n",stderr);
            return(2);
        }
        port=(int)parsed;
    }

    if (!strcmp(protocol,"http"))
    {
        if (!port) port=cmeDefaultWebservicePort;
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
        if (!port) port=cmeDefaultWebServiceSSLPort;
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
    const char *dataDirectory=NULL;
    int result=0;
    #define debugTestsFree() \
        do { \
            cmeFree(title); \
            cmeEndRuntime(&bufIn,&bufOut,&cdsePerl); \
            PERL_SYS_TERM(); \
        } while (0)

    if (argc>1)
    {
        if (argc==2 && !strcmp(argv[1],"--capabilities"))
        {
#ifdef DEBUG
            printf("{\"debugBuild\":true,\"isolatedDataDir\":true,\"httpTlsAuthBypass\":%s}\n",
                   BYPASS_TLS_IN_HTTP ? "true" : "false");
#else
            puts("{\"debugBuild\":false,\"isolatedDataDir\":false,\"httpTlsAuthBypass\":false}");
#endif
            return(0);
        }
        if ((!strcmp(argv[1],"--help"))||(!strcmp(argv[1],"-h")))
        {
            cmeDebugTestsPrintUsage(argv[0]);
            return(0);
        }
        if ((!strcmp(argv[1],"--web-service"))&&(argc==3 ||
            (argc==5 && !strcmp(argv[3],"--data-dir"))))
        {
            webServiceMode=1;
            webServiceProtocol=argv[2];
            if (strcmp(webServiceProtocol,"http") && strcmp(webServiceProtocol,"https")) return(2);
            if (argc==5) dataDirectory=argv[4];
        }
        else
        {
            fprintf(stderr,"CaumeDSE Error: invalid debug test option.\n");
            cmeDebugTestsPrintUsage(argv[0]);
            return(2);
        }
    }

    if (dataDirectory)
    {
#ifdef DEBUG
        if (cmeSetDebugTestDataDirectory(dataDirectory))
        {
            fputs("DEBUG data directory must be an owned private directory, not a link.\n",stderr);
            return(2);
        }
        cmeAdminKeyAutoConfirm=1;
#else
        fputs("Isolated data directories require a DEBUG build.\n",stderr);
        return(2);
#endif
    }
    if (webServiceMode) setvbuf(stdout,NULL,_IOLBF,0);

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
    testCryptoReprotectDBValue();
    testHerraduraIndependent();
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
