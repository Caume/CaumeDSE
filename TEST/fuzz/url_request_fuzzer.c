#define CDSE_FUZZING 1

#include "common.h"
#include "TEST/fuzz/fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *input=cdseFuzzDupInput(data,size,8192);
    char *saveptr=NULL;
    char *line;
    char **urlElements=NULL;
    char *argumentElements[cmeWSURIMaxArguments+2]={0};
    int numUrlElements=0;
    int argSlot=0;
    int cont;

    if (!input)
    {
        return 0;
    }
    line=strtok_r(input,"\n",&saveptr);
    if (!line)
    {
        line="/";
    }
    cmeWebServiceParseURL(line,&urlElements,&numUrlElements);
    while (((line=strtok_r(NULL,"\n",&saveptr)))&&((argSlot+1)<cmeWSURIMaxArguments))
    {
        char *equals=strchr(line,'=');

        if (equals)
        {
            *equals='\0';
            cmeWebServiceParseKeys(argumentElements,MHD_GET_ARGUMENT_KIND,line,equals+1);
        }
        else
        {
            cmeWebServiceParseKeys(argumentElements,MHD_GET_ARGUMENT_KIND,line,"");
        }
        argSlot+=2;
    }
    (void)cmeWebServiceHasUnsafeRequestInputForTest((const char **)urlElements,numUrlElements,
                                                    (const char **)argumentElements);
    if (urlElements)
    {
        for (cont=0;cont<numUrlElements;cont++)
        {
            cmeFree(urlElements[cont]);
        }
        cmeFree(urlElements);
    }
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
