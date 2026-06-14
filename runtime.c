/***
Copyright 2010-2026 by Omar Alejandro Herrera Reyna

    Caume Data Security Engine, also known as CaumeDSE is released under the
    GNU General Public License by the Copyright holder, with the additional
    exemption that compiling, linking, and/or using OpenSSL is allowed.

***/
#include "common.h"
#include "runtime.h"

// --- Necessary globals
PerlInterpreter *cdsePerl=NULL;
pthread_mutex_t cmePerlMutex=PTHREAD_MUTEX_INITIALIZER;   //Protects cdsePerl (shared Perl interpreter).
pthread_mutex_t cmePowerMutex=PTHREAD_MUTEX_INITIALIZER;  //Protects cmeEnginePowerStatus flag.
__thread char **cmeResultMemTable=NULL;    //Thread-local SQL result table; each worker thread owns its copy.
__thread int cmeResultMemTableRows=0;      //Thread-local row count.
__thread int cmeResultMemTableCols=0;      //Thread-local column count.

int cmeSetupRuntime(unsigned char **bIn,unsigned char **bOut,PerlInterpreter **myPerl)
{
    char *localeName=NULL;

    *bIn=(unsigned char *)malloc(evpBufferSize);   //allocate buffers for cryptographic operations
    *bOut=(unsigned char *)malloc(evpBufferSize+128);

    localeName=setlocale(LC_CTYPE,"");
    if(!localeName)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSetupRuntime(), Error in setlocale(), can't set"
                " the specified locale; check LANG, LC_CTYPE, LC_ALL!\n");
#endif
        return(1);
    }
    if (MB_CUR_MAX<2)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSetupRuntime(), Error, locale '%s' is not"
                " multibyte-capable; configure a UTF-8 locale for printf output.\n",
                localeName);
#endif
        return(1);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeSetupRuntime(), locale '%s' supports multibyte printf output (MB_CUR_MAX=%d).\n",
            localeName,(int)MB_CUR_MAX);
#endif
    *myPerl = perl_alloc();     //Prepare Perl interpreter.
    perl_construct(*myPerl);
    cmeSeedPrng();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms();                   //Get all available ciphers and digests.
#else
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ADD_ALL_CIPHERS |
                        OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
#endif
    cmeLoadConfiguration();
    return(0);
}

int cmeEndRuntime(unsigned char **bIn,unsigned char **bOut,PerlInterpreter **myPerl)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ERR_free_strings(); //OPENSSL Release all strings.
    EVP_cleanup(); //OPENSSL Release all available ciphers.
    CRYPTO_cleanup_all_ex_data(); //OPENSSL Release all crypto data.
#else
    OPENSSL_cleanup();
#endif

    perl_destruct(*myPerl);
    perl_free(*myPerl);
    cmeFree(*bIn);
    cmeFree(*bOut);

    return (0);
}
