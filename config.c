#include "common.h"
#include <string.h>

char cmeDefaultEncAlg[64] = "aes-256-cbc";

void cmeInitDefaultEncAlg()
{
    const char *envAlg = getenv("CDSE_DEFAULT_ENC_ALG");
    const EVP_CIPHER *cipher = NULL;
    if (envAlg && *envAlg)
    {
        if (cmeGetCipher(&cipher, envAlg) == 0)
        {
            strncpy(cmeDefaultEncAlg, envAlg, sizeof(cmeDefaultEncAlg)-1);
            cmeDefaultEncAlg[sizeof(cmeDefaultEncAlg)-1] = '\0';
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: using default encryption algorithm %s from environment.\n", cmeDefaultEncAlg);
#endif
            return;
        }
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeInitDefaultEncAlg(), unsupported algorithm %s; using default %s.\n", envAlg, cmeDefaultEncAlg);
#endif
    }
}
