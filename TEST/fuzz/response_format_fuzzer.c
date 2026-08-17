#define CDSE_FUZZING 1

#include "common.h"
#include "TEST/fuzz/fuzz_common.h"

static void cdseFuzzFreeHeaders(char **headers)
{
    int cont;

    if (!headers)
    {
        return;
    }
    for (cont=0;headers[cont]&&(cont<cmeWSHTTPMaxResponseHeaders);cont++)
    {
        cmeFree(headers[cont]);
    }
    cmeFree(headers);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *input=cdseFuzzDupInput(data,size,4096);
    char *argumentElements[cmeWSURIMaxArguments+2]={0};
    const char *table[6]={"name","value","alpha","1","beta","2"};
    char *response=NULL;
    char **headers=NULL;
    int responseCode=0;

    if (!input)
    {
        return 0;
    }
    if (size%3==0)
    {
        cmeStrConstrAppend(&argumentElements[0],"%s","outputType");
        cmeStrConstrAppend(&argumentElements[1],"%s","json");
    }
    else if (size%3==1)
    {
        cmeStrConstrAppend(&argumentElements[0],"%s","outputType");
        cmeStrConstrAppend(&argumentElements[1],"%s","csv");
    }
    else
    {
        cmeStrConstrAppend(&argumentElements[0],"%s","outputType");
        cmeStrConstrAppend(&argumentElements[1],"%s",input);
    }
    headers=(char **)calloc(cmeWSHTTPMaxResponseHeaders+2,sizeof(char *));
    if (!headers)
    {
        cdseFuzzFreePairList(argumentElements,cmeWSURIMaxArguments);
        free(input);
        return 0;
    }
    cmeConstructWebServiceCountResponse("count",(int)(size%1024),
                                        (const char **)argumentElements,"GET","/fuzz",
                                        &headers,&response,&responseCode);
    cmeFree(response);
    cdseFuzzFreeHeaders(headers);
    headers=(char **)calloc(cmeWSHTTPMaxResponseHeaders+2,sizeof(char *));
    if (!headers)
    {
        cdseFuzzFreePairList(argumentElements,cmeWSURIMaxArguments);
        free(input);
        return 0;
    }
    cmeConstructWebServiceTableResponse(table,2,2,(const char **)argumentElements,
                                        "GET","/fuzz","doc",&headers,&response,
                                        &responseCode);
    cmeFree(response);
    cdseFuzzFreeHeaders(headers);
    cdseFuzzFreePairList(argumentElements,cmeWSURIMaxArguments);
    free(input);
    return 0;
}

#ifdef CDSE_FUZZ_STANDALONE
int main(int argc, char **argv)
{
    int cont;

    for (cont=1;cont<argc;cont++)
    {
        if (cdseFuzzRunOneFile(argv[cont],LLVMFuzzerTestOneInput))
        {
            return 1;
        }
    }
    return 0;
}
#endif
