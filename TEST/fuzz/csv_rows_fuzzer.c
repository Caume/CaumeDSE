#define CDSE_FUZZING 1

#include <fcntl.h>
#include <unistd.h>

#include "common.h"
#include "TEST/fuzz/fuzz_common.h"

static void cdseFuzzCSVRunOne(const char *path, int hasColNames, int rowStart, int rowEnd)
{
    char **elements=NULL;
    int numCols=0;
    int processedRows=0;

    if (!cmeCSVFileRowsToMemTable(path,&elements,&numCols,&processedRows,
                                  hasColNames,rowStart,rowEnd))
    {
        if (elements && numCols>0)
        {
            cmeCSVFileRowsToMemTableFinal(&elements,numCols,processedRows+1);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char path[]="/tmp/cdse-csv-fuzz-XXXXXX";
    char *text=cdseFuzzDupInput(data,size,16384);
    int fd=mkstemp(path);
    int rowStart=(size>0)?(data[0]%3):0;
    int rowEnd=rowStart+((size>1)?(data[1]%5):2);

    if (!text)
    {
        return 0;
    }
    if (fd<0)
    {
        free(text);
        return 0;
    }
    if (text[0])
    {
        (void)write(fd,text,strlen(text));
    }
    close(fd);
    cdseFuzzCSVRunOne(path,0,rowStart,rowEnd);
    cdseFuzzCSVRunOne(path,1,0,rowEnd);
    (void)cmeStorageFileRemove(path);
    free(text);
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
