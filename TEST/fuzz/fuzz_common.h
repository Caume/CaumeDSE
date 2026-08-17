/*
 * Shared helpers for CaumeDSE fuzz harnesses.
 *
 * These helpers intentionally keep harness inputs bounded and NUL-terminated so
 * existing C string APIs can be fuzzed without relying on undefined caller
 * behavior.
 */
#ifndef CDSE_FUZZ_COMMON_H
#define CDSE_FUZZ_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *cdseFuzzDupInput(const uint8_t *data, size_t size, size_t maxSize)
{
    size_t copySize=(size<maxSize)?size:maxSize;
    char *result=(char *)malloc(copySize+1);
    size_t cont;

    if (!result)
    {
        return NULL;
    }
    for (cont=0;cont<copySize;cont++)
    {
        result[cont]=data[cont]?(char)data[cont]:' ';
    }
    result[copySize]='\0';
    return result;
}

static void cdseFuzzFreePairList(char **pairs, size_t maxPairs)
{
    size_t cont;

    if (!pairs)
    {
        return;
    }
    for (cont=0;cont<maxPairs;cont++)
    {
        if (pairs[cont])
        {
            free(pairs[cont]);
            pairs[cont]=NULL;
        }
    }
}

#ifdef CDSE_FUZZ_STANDALONE
static int cdseFuzzRunOneFile(const char *path,
                              int (*target)(const uint8_t *data, size_t size))
{
    FILE *fp=fopen(path,"rb");
    long len;
    uint8_t *buf;
    int result;

    if (!fp)
    {
        return 2;
    }
    if (fseek(fp,0,SEEK_END))
    {
        fclose(fp);
        return 2;
    }
    len=ftell(fp);
    if (len<0)
    {
        fclose(fp);
        return 2;
    }
    if (fseek(fp,0,SEEK_SET))
    {
        fclose(fp);
        return 2;
    }
    buf=(uint8_t *)malloc((size_t)len);
    if ((!buf)&&(len>0))
    {
        fclose(fp);
        return 2;
    }
    if ((len>0)&&(fread(buf,1,(size_t)len,fp)!=(size_t)len))
    {
        free(buf);
        fclose(fp);
        return 2;
    }
    fclose(fp);
    result=target(buf,(size_t)len);
    free(buf);
    return result;
}
#endif

#endif
