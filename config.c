#include "common.h"

char cmeDefaultEncAlg[64] = "aes-256-gcm";

static char *cmeTrimConfigValue(char *value)
{
    char *end = NULL;
    while (*value && isspace((unsigned char)*value))
    {
        value++;
    }
    if (!*value)
    {
        return value;
    }
    end = value + strlen(value) - 1;
    while (end > value && isspace((unsigned char)*end))
    {
        *end = '\0';
        end--;
    }
    return value;
}

static char *cmeUnquoteConfigValue(char *value)
{
    size_t valueLen = strlen(value);
    if (valueLen >= 2 &&
        ((value[0] == '"' && value[valueLen-1] == '"') ||
         (value[0] == '\'' && value[valueLen-1] == '\'')))
    {
        value[valueLen-1] = '\0';
        value++;
    }
    return value;
}

static int cmeSetDefaultEncAlg(const char *value, const char *source)
{
    const EVP_CIPHER *cipher = NULL;
    if (!value || !*value)
    {
        return 1;
    }
    if (cmeGetCipher(&cipher, value) == 0)
    {
        strncpy(cmeDefaultEncAlg, value, sizeof(cmeDefaultEncAlg)-1);
        cmeDefaultEncAlg[sizeof(cmeDefaultEncAlg)-1] = '\0';
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: using default encryption algorithm %s from %s.\n", cmeDefaultEncAlg, source);
#endif
        return 0;
    }
#ifdef ERROR_LOG
    fprintf(stderr,"CaumeDSE Error: cmeSetDefaultEncAlg(), unsupported algorithm %s from %s; using default %s.\n", value, source, cmeDefaultEncAlg);
#endif
    return 1;
}

static void cmeLoadConfigFile(const char *configPath)
{
    FILE *configFile = NULL;
    char line[512];
    configFile = fopen(configPath, "r");
    if (!configFile)
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: configuration file %s not loaded.\n", configPath);
#endif
        return;
    }
    while (fgets(line, sizeof(line), configFile))
    {
        char *comment = strchr(line, '#');
        char *separator = NULL;
        char *key = NULL;
        char *value = NULL;
        if (comment)
        {
            *comment = '\0';
        }
        separator = strchr(line, '=');
        if (!separator)
        {
            continue;
        }
        *separator = '\0';
        key = cmeTrimConfigValue(line);
        value = cmeTrimConfigValue(separator + 1);
        value = cmeUnquoteConfigValue(value);
        if (!*key || !*value)
        {
            continue;
        }
        if (strcmp(key, "defaultEncAlg") == 0 ||
            strcmp(key, "default_enc_alg") == 0 ||
            strcmp(key, "CDSE_DEFAULT_ENC_ALG") == 0)
        {
            cmeSetDefaultEncAlg(value, configPath);
        }
    }
    fclose(configFile);
}

void cmeLoadConfiguration()
{
    const char *configPath = getenv("CDSE_CONFIG_FILE");
    if (!configPath || !*configPath)
    {
        configPath = cmeDefaultConfigFile;
    }
    cmeLoadConfigFile(configPath);
    cmeInitDefaultEncAlg();
}

void cmeInitDefaultEncAlg()
{
    const char *envAlg = getenv("CDSE_DEFAULT_ENC_ALG");
    if (envAlg && *envAlg)
    {
        cmeSetDefaultEncAlg(envAlg, "environment CDSE_DEFAULT_ENC_ALG");
    }
}
