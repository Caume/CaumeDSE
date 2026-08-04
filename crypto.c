/***
Copyright 2010-2026 by Omar Alejandro Herrera Reyna

    Caume Data Security Engine, also known as CaumeDSE is released under the
    GNU General Public License by the Copyright holder, with the additional
    exemption that compiling, linking, and/or using OpenSSL is allowed.

    LICENSE

    This file is part of Caume Data Security Engine, also called CaumeDSE.

    CaumeDSE is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CaumeDSE is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with CaumeDSE.  If not, see <http://www.gnu.org/licenses/>.

    INCLUDED SOFTWARE

    This product includes software developed by the OpenSSL Project
    for use in the OpenSSL Toolkit (http://www.openssl.org/).
    This product includes cryptographic software written by
    Eric Young (eay@cryptsoft.com).
    This product includes software written by
    Tim Hudson (tjh@cryptsoft.com).

    This product includes software from the SQLite library that is in
    the public domain (http://www.sqlite.org/copyright.html).

    This product includes software from the GNU Libmicrohttpd project, Copyright
    © 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
    2008, 2009, 2010 , 2011, 2012 Free Software Foundation, Inc.

    This product includes software from Perl5, which is Copyright (C) 1993-2005,
    by Larry Wall and others.

***/
#include "common.h"
#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#endif
#include <herradura.h>
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#endif

typedef struct
{
    const char *algorithm;
    int keyLen;
    int nonceLen;
    int saltLen;
    int tagLen;
    int isAEAD;
    int frameVersion;
    int frameProfileId;
    int compiledIn;
    int implemented;
    int allowedAsDefault;
} cmeStaticCryptoProfile;

static const cmeStaticCryptoProfile cmeHerraduraKExProfiles[] =
{
    {cmeHerraduraKExProfileHSKENLA1AEAD256, 32, 32, evpSaltBufferSize, 32, 1,
     cmeCryptoFrameHerraduraKExV1, cmeHerraduraKExProfileIdHSKENLA1AEAD256,
     cmeUseHerraduraKEx, cmeUseHerraduraKEx, cmeUseHerraduraKEx},
    {cmeHerraduraKExProfileHSKEDuplex256, 32, 32, evpSaltBufferSize, 32, 1,
     cmeCryptoFrameHerraduraKExV1, cmeHerraduraKExProfileIdHSKEDuplex256,
     cmeUseHerraduraKEx, cmeUseHerraduraKEx, cmeUseHerraduraKEx},
    {cmeHerraduraKExProfileHSKENLA2256, 32, 32, evpSaltBufferSize, 0, 0,
     cmeCryptoFrameHerraduraKExV1, cmeHerraduraKExProfileIdHSKENLA2256,
     cmeUseHerraduraKEx, 0, 0}
};

static void cmeCopyCryptoProfileAlgorithm(cmeCryptoProfile *profile, const char *algorithm)
{
    strncpy(profile->algorithm, algorithm, cmeCryptoProfileNameMaxLen-1);
    profile->algorithm[cmeCryptoProfileNameMaxLen-1]='\0';
}

int cmeGetCryptoProfile (cmeCryptoProfile *profile, const char *algorithm)
{
    const EVP_CIPHER *cipher=NULL;
    size_t cont=0;

    if (!profile || !algorithm || !*algorithm)
    {
        return(1);
    }
    memset(profile,0,sizeof(cmeCryptoProfile));
    cmeCopyCryptoProfileAlgorithm(profile,algorithm);

    cipher=EVP_get_cipherbyname(algorithm);
    if (cipher)
    {
        profile->provider=cmeCryptoProviderOpenSSLEVP;
        profile->keyLen=EVP_CIPHER_key_length(cipher);
        profile->nonceLen=EVP_CIPHER_iv_length(cipher);
        profile->saltLen=evpSaltBufferSize;
#ifdef EVP_CIPH_GCM_MODE
        if (EVP_CIPHER_mode(cipher)==EVP_CIPH_GCM_MODE)
        {
            profile->isAEAD=1;
            profile->tagLen=cmeGCMTagLen;
        }
#endif
        profile->frameVersion=cmeCryptoFrameNone;
        profile->compiledIn=1;
        profile->implemented=1;
        profile->allowedAsDefault=1;
        return(0);
    }

    for (cont=0; cont<(sizeof(cmeHerraduraKExProfiles)/sizeof(cmeHerraduraKExProfiles[0])); cont++)
    {
        if (!strcmp(algorithm,cmeHerraduraKExProfiles[cont].algorithm))
        {
            cmeCopyCryptoProfileAlgorithm(profile,cmeHerraduraKExProfiles[cont].algorithm);
            profile->provider=cmeCryptoProviderHerraduraKEx;
            profile->keyLen=cmeHerraduraKExProfiles[cont].keyLen;
            profile->nonceLen=cmeHerraduraKExProfiles[cont].nonceLen;
            profile->saltLen=cmeHerraduraKExProfiles[cont].saltLen;
            profile->tagLen=cmeHerraduraKExProfiles[cont].tagLen;
            profile->isAEAD=cmeHerraduraKExProfiles[cont].isAEAD;
            profile->frameVersion=cmeHerraduraKExProfiles[cont].frameVersion;
            profile->frameProfileId=cmeHerraduraKExProfiles[cont].frameProfileId;
            profile->compiledIn=cmeHerraduraKExProfiles[cont].compiledIn;
            profile->implemented=cmeHerraduraKExProfiles[cont].implemented;
            profile->allowedAsDefault=cmeHerraduraKExProfiles[cont].allowedAsDefault;
            return(0);
        }
    }

    profile->provider=cmeCryptoProviderUnknown;
    return(2);
}

int cmeCryptoAlgorithmIsImplemented (const char *algorithm)
{
    cmeCryptoProfile profile;

    if (cmeGetCryptoProfile(&profile,algorithm))
    {
        return(0);
    }
    return(profile.implemented);
}

#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
static int cmeHerraduraKExBuildAAD (unsigned char **ad, int *adLen, const char *algorithm, const char *salt)
{
    const char *prefix="CDSE-HKX-AAD-v1";
    int needed=0;

    *ad=NULL;
    *adLen=0;
    if (!algorithm || !salt)
    {
        return(1);
    }
    needed=snprintf(NULL,0,"%s|%s|%s",prefix,algorithm,salt);
    if (needed<0)
    {
        return(2);
    }
    *ad=(unsigned char *)malloc(needed+1);
    if (!*ad)
    {
        return(3);
    }
    snprintf((char *)*ad,needed+1,"%s|%s|%s",prefix,algorithm,salt);
    *adLen=needed;
    return(0);
}

static int cmeHerraduraKExProfileIdMatchesAlgorithm (unsigned char profileId, const char *algorithm)
{
    return((profileId==cmeHerraduraKExProfileIdHSKENLA1AEAD256 &&
            !strcmp(algorithm,cmeHerraduraKExProfileHSKENLA1AEAD256)) ||
           (profileId==cmeHerraduraKExProfileIdHSKEDuplex256 &&
            !strcmp(algorithm,cmeHerraduraKExProfileHSKEDuplex256)));
}
#endif

static const char *cmeHerraduraKExAlgorithmFromProfileId (unsigned char profileId)
{
    if (profileId==cmeHerraduraKExProfileIdHSKENLA1AEAD256)
    {
        return(cmeHerraduraKExProfileHSKENLA1AEAD256);
    }
    if (profileId==cmeHerraduraKExProfileIdHSKEDuplex256)
    {
        return(cmeHerraduraKExProfileHSKEDuplex256);
    }
    return(NULL);
}

static int cmeIsHerraduraKExFrame (const unsigned char *srcBuf, int srcLen)
{
    return(srcBuf && srcLen>=cmeHerraduraKExFrameHeaderLen &&
           !memcmp(srcBuf,cmeHerraduraKExFrameMagic,cmeHerraduraKExFrameMagicLen));
}

static int cmeHerraduraKExCipherByteString (const unsigned char *srcBuf, unsigned char **dstBuf,
                                            unsigned char **salt, const int srcLen, int *dstWritten,
                                            const char *algorithm, const char *ctPassword,
                                            const char mode, const cmeCryptoProfile *profile)
{
#if CDSE_ENABLE_HERRADURAKEX && HAVE_HERRADURA_H
    BitArray key;
    BitArray nonce;
    unsigned char *byteSalt=NULL;
    unsigned char hexStrbyteSalt[evpSaltBufferSize*2+1];
    unsigned char *ad=NULL;
    int adLen=0;
    int result=0;
    int ctLen=0;
    unsigned char *randomNonce=NULL;
    #define cmeHerraduraKExCipherByteStringFree() \
        { \
            OPENSSL_cleanse(key.b,sizeof(key.b)); \
            OPENSSL_cleanse(nonce.b,sizeof(nonce.b)); \
            if (byteSalt) { memset(byteSalt,0,evpSaltBufferSize); cmeFree(byteSalt); } \
            if (ad) { memset(ad,0,adLen); cmeFree(ad); } \
            if (randomNonce) { memset(randomNonce,0,cmeHerraduraKExNonceLen); cmeFree(randomNonce); } \
        }

    memset(&key,0,sizeof(key));
    memset(&nonce,0,sizeof(nonce));
    if (!profile || !profile->implemented || !profile->isAEAD ||
        profile->frameVersion!=cmeCryptoFrameHerraduraKExV1 ||
        (profile->frameProfileId!=cmeHerraduraKExProfileIdHSKENLA1AEAD256 &&
         profile->frameProfileId!=cmeHerraduraKExProfileIdHSKEDuplex256))
    {
        return(20);
    }
    if (mode=='e')
    {
        if (!(*salt))
        {
            cmePrngGetBytes(&byteSalt,evpSaltBufferSize);
            cmeBytesToHexstr(byteSalt,salt,evpSaltBufferSize);
        }
        else
        {
            strncpy((char *)hexStrbyteSalt,(char *)*salt,evpSaltBufferSize*2);
            hexStrbyteSalt[evpSaltBufferSize*2]='\0';
            if (cmeHexstrToBytes(&byteSalt,hexStrbyteSalt))
            {
                cmeHerraduraKExCipherByteStringFree();
                return(21);
            }
        }
        cmePrngGetBytes(&randomNonce,cmeHerraduraKExNonceLen);
        memcpy(nonce.b,randomNonce,cmeHerraduraKExNonceLen);
    }
    else if (mode=='d')
    {
        if (srcLen<cmeHerraduraKExFrameHeaderLen ||
            memcmp(srcBuf,cmeHerraduraKExFrameMagic,cmeHerraduraKExFrameMagicLen) ||
            !cmeHerraduraKExProfileIdMatchesAlgorithm(srcBuf[cmeHerraduraKExFrameMagicLen],algorithm))
        {
            return(22);
        }
        strncpy((char *)hexStrbyteSalt,(char *)*salt,evpSaltBufferSize*2);
        hexStrbyteSalt[evpSaltBufferSize*2]='\0';
        if (cmeHexstrToBytes(&byteSalt,hexStrbyteSalt))
        {
            cmeHerraduraKExCipherByteStringFree();
            return(23);
        }
        memcpy(nonce.b,srcBuf+cmeHerraduraKExFrameMagicLen+2,cmeHerraduraKExNonceLen);
    }
    else
    {
        return(24);
    }
    if (!byteSalt)
    {
        cmeHerraduraKExCipherByteStringFree();
        return(25);
    }
    if (!PKCS5_PBKDF2_HMAC((const char *)ctPassword,strlen(ctPassword),byteSalt,evpSaltBufferSize,
                           cmeDefaultPBKDFCount,EVP_sha256(),cmeHerraduraKExNonceLen,key.b))
    {
        cmeHerraduraKExCipherByteStringFree();
        return(26);
    }
    if (cmeHerraduraKExBuildAAD(&ad,&adLen,algorithm,(const char *)*salt))
    {
        cmeHerraduraKExCipherByteStringFree();
        return(27);
    }
    if (mode=='e')
    {
        int frameLen=cmeHerraduraKExFrameHeaderLen+srcLen;
        *dstBuf=(unsigned char *)malloc(frameLen+1);
        if (!*dstBuf)
        {
            cmeHerraduraKExCipherByteStringFree();
            return(28);
        }
        memset(*dstBuf,0,frameLen+1);
        memcpy(*dstBuf,cmeHerraduraKExFrameMagic,cmeHerraduraKExFrameMagicLen);
        (*dstBuf)[cmeHerraduraKExFrameMagicLen]=(unsigned char)profile->frameProfileId;
        (*dstBuf)[cmeHerraduraKExFrameMagicLen+1]=0;
        memcpy(*dstBuf+cmeHerraduraKExFrameMagicLen+2,nonce.b,cmeHerraduraKExNonceLen);
        if (profile->frameProfileId==cmeHerraduraKExProfileIdHSKENLA1AEAD256)
        {
            hske_nl_aead_encrypt(&key,&nonce,ad,adLen,srcBuf,srcLen,
                                 *dstBuf+cmeHerraduraKExFrameHeaderLen,
                                 *dstBuf+cmeHerraduraKExFrameMagicLen+2+cmeHerraduraKExNonceLen);
        }
        else
        {
            hske_nl_v2_duplex_encrypt(&key,&nonce,ad,adLen,srcBuf,srcLen,
                                      *dstBuf+cmeHerraduraKExFrameHeaderLen,
                                      *dstBuf+cmeHerraduraKExFrameMagicLen+2+cmeHerraduraKExNonceLen);
        }
        *dstWritten=frameLen;
    }
    else
    {
        ctLen=srcLen-cmeHerraduraKExFrameHeaderLen;
        *dstBuf=(unsigned char *)malloc(ctLen+1);
        if (!*dstBuf)
        {
            cmeHerraduraKExCipherByteStringFree();
            return(29);
        }
        memset(*dstBuf,0,ctLen+1);
        if (srcBuf[cmeHerraduraKExFrameMagicLen]==cmeHerraduraKExProfileIdHSKENLA1AEAD256)
        {
            result=hske_nl_aead_decrypt(&key,&nonce,ad,adLen,
                                        srcBuf+cmeHerraduraKExFrameHeaderLen,ctLen,
                                        srcBuf+cmeHerraduraKExFrameMagicLen+2+cmeHerraduraKExNonceLen,
                                        *dstBuf);
        }
        else
        {
            result=hske_nl_v2_duplex_decrypt(&key,&nonce,ad,adLen,
                                             srcBuf+cmeHerraduraKExFrameHeaderLen,ctLen,
                                             srcBuf+cmeHerraduraKExFrameMagicLen+2+cmeHerraduraKExNonceLen,
                                             *dstBuf);
        }
        if (!result)
        {
            cmeFree(*dstBuf);
            *dstWritten=0;
            cmeHerraduraKExCipherByteStringFree();
            return(30);
        }
        (*dstBuf)[ctLen]='\0';
        *dstWritten=ctLen;
    }
    cmeHerraduraKExCipherByteStringFree();
    return(0);
#else
    (void)srcBuf;
    (void)dstBuf;
    (void)salt;
    (void)srcLen;
    (void)dstWritten;
    (void)algorithm;
    (void)ctPassword;
    (void)mode;
    (void)profile;
    return(31);
#endif
}

int cmeGetDigest (EVP_MD **digest, const char *algorithm)
{
    *digest = (EVP_MD*)EVP_get_digestbyname(algorithm);
    if (digest == NULL)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: evpGetDigest(), algorithm %s not found!\n",algorithm);
#endif
        return (1);
    }

    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: evpGetDigest(), algorithm %s selected.\n",algorithm);
#endif
        return (0);
    }
}

int cmeDigestInit (EVP_MD_CTX **ctx, ENGINE *engine, EVP_MD *digest)
{
    int result;

    *ctx=EVP_MD_CTX_new();
    result= EVP_DigestInit_ex(*ctx,digest,engine);
    if (result==0)  //1= success, 0=failure
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: evpDigestInit(), EVP_DigestInit_ex() failure!\n");
#endif
        return (1);
    }
    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: evpDigestInit(), EVP_DigestInit_ex() success.\n");
#endif
        return (0);
    }
}

int cmeDigestUpdate (EVP_MD_CTX *ctx, const void *in, size_t inl)
{
    int result;

    result=EVP_DigestUpdate(ctx,in,inl);
    if (result==0)  //1= success, 0=failure
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: evpDigestUpdate(), EVP_DigestUpdate() failure!\n");
#endif
        return (1);
    }
    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: evpDigestUpdate(), EVP_DigestUpdate() success.\n");
#endif
        return (0);
    }
}

int cmeDigestFinal(EVP_MD_CTX **ctx, unsigned char *out, unsigned int *outl)
{
    int result;

    result=EVP_DigestFinal_ex(*ctx,out,outl);
    EVP_MD_CTX_free(*ctx); // override generic free: cmeFree(*ctx);
    *ctx=NULL;
    if (result==0)  //1= success, 0=failure
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: evpDigestFinal(), EVP_DigestFinal_ex() failure!\n");
#endif
        return (1);
    }
    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: evpDigestFinal(), EVP_DigestFinal_ex() success.\n");
#endif
       return (0);
    }
}

int cmeGetCipher (const EVP_CIPHER** cipher, const char *algorithm)
{
    *cipher = EVP_get_cipherbyname(algorithm);
    //NOTE: results from EVP_get_cipherbyname are pointers to const cipher desc. in Openssl memory (can't free()).
    if (*cipher==NULL)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: evpGetCipher(), algorithm %s not found!\n",algorithm);
#endif
        return (1);
    }

    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: evpGetCipher(), algorithm %s selected.\n",algorithm);
#endif
        return (0);
    }
}

int cmeCipherInit (EVP_CIPHER_CTX **ctx, ENGINE *engine, const EVP_CIPHER *cipher, unsigned char *key,
                   unsigned char* iv, char mode)
{
    int result;
    int ivLen = 0;
    int isGCM = 0;

    *ctx = EVP_CIPHER_CTX_new();
    if ((mode!='d')&&(mode!='e'))
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: evpCipherInit(), unknown cipher mode '%c'!\n",mode);
#endif
        return (1);
    }

    ivLen = EVP_CIPHER_iv_length(cipher);
#ifdef EVP_CIPH_GCM_MODE
    if (cipher && (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE))
    {
        isGCM = 1;
    }
#endif

#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: evpCipherInit(), cipher mode '%c' selected.%s\n",mode,
            isGCM ? " (GCM)" : "");
#endif

    if (mode=='e')  //Encrypt
    {
        if (isGCM)
        {
            result = EVP_EncryptInit_ex(*ctx,cipher,engine,NULL,NULL);
            if (result==0)
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: evpCipherInit(), EVP_EncryptInit_ex() failure!\n");
#endif
                return (2);
            }
            if (ivLen > 0)
            {
                if (!EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL))
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: evpCipherInit(), EVP_CTRL_GCM_SET_IVLEN failure!\n");
#endif
                    return (3);
                }
            }
            result = EVP_EncryptInit_ex(*ctx,NULL,engine,key,iv);
        }
        else
        {
            result= EVP_EncryptInit_ex(*ctx,cipher,engine,key,iv);
        }

        if (result==0)  //1= success, 0=failure
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: evpCipherInit(), EVP_EncryptInit_ex() failure!\n");
#endif
            return (2);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: evpCipherInit(), EVP_EncryptInit_ex() success.\n");
#endif

    }
    else            //Decrypt
    {
        if (isGCM)
        {
            result = EVP_DecryptInit_ex(*ctx,cipher,engine,NULL,NULL);
            if (result==0)
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: evpCipherInit(), EVP_DecryptInit_ex() failure!\n");
#endif
                return (2);
            }
            if (ivLen > 0)
            {
                if (!EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL))
                {
#ifdef ERROR_LOG
                    fprintf(stderr,"CaumeDSE Error: evpCipherInit(), EVP_CTRL_GCM_SET_IVLEN failure!\n");
#endif
                    return (3);
                }
            }
            result = EVP_DecryptInit_ex(*ctx,NULL,engine,key,iv);
        }
        else
        {
            result= EVP_DecryptInit_ex(*ctx,cipher,engine,key,iv);
        }

        if (result==0)  //1= success, 0=failure
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: evpCipherInit(), EVP_DecryptInit_ex() failure!\n");
#endif
            return (2);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: evpCipherInit(), EVP_DecryptInit_ex() success.\n");
#endif

    }
    return (0);
}

int cmeCipherUpdate (EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl,
                     unsigned char* in, int inl, char mode)
{
    int result;

    if ((mode!='d')&&(mode!='e'))
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: evpCipherUpdate(), unknown cipher mode '%c'!\n",mode);
#endif
        return (1);
    }
    else
    {
        if (mode=='e')  //Encrypt
        {
            result=EVP_EncryptUpdate(ctx,out,outl,in,inl);
            if (result==0)  //1= success, 0=failure
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: evpCipherUpdate(), EVP_EncryptUpdate() failure!\n");
#endif
                return (2);
            }
            else
            {
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: evpCipherUpdate(), EVP_EncryptUpdate() success.\n");
#endif
            }
        }
        else            //Decrypt
        {
            result=EVP_DecryptUpdate(ctx,out,outl,in,inl);
            if (result==0)  //1= success, 0=failure
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: evpCipherUpdate(), EVP_DecryptUpdate() failure!\n");
#endif
                return (2);
            }
            else
            {
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: evpCipherUpdate(), EVP_DecryptUpdate() success.\n");
#endif
            }
        }
    }
    return (0);
}

int cmeCipherFinal(EVP_CIPHER_CTX **ctx, unsigned char *out, int *outl, const char mode)
{
    int result=0;
    #define cmeCipherFinalFree() \
        { \
            if(*ctx)\
            {\
                EVP_CIPHER_CTX_free(*ctx); \
                *ctx=NULL; \
            }\
        } //Local free() macro. Call to EVP_CIPHER_CTX_free() to securely dispose of context memory!

    if ((mode!='d')&&(mode!='e'))
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: evpCipherFinal(), unknown cipher mode '%c'!\n",mode);
#endif
        cmeCipherFinalFree();
        return (1);
    }
    if (mode=='e')  //Encrypt
    {
        result=EVP_EncryptFinal_ex(*ctx,out,outl);
        if (result==0)  //1= success, 0=failure
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: evpCipherFinal(), EVP_EncryptFinal_ex() failure!\n");
#endif
            cmeCipherFinalFree();
            return(2);
        }
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: evpCipherFinal(), EVP_EncryptFinal_ex() success.\n");
#endif
    }
    else            //Decrypt
    {
        result=EVP_DecryptFinal_ex(*ctx,out,outl);
        if (result==0)  //1= success, 0=failure
        {
#ifdef DEBUG
            fprintf(stderr,"CaumeDSE Debug: evpCipherFinal(), EVP_DecryptFinal() failure (key might be incorrect)!\n");
#endif
            cmeCipherFinalFree();
            return(3);
        }
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: evpCipherFinal(), EVP_DecryptFinal() success.\n");
#endif
    }
    cmeCipherFinalFree();
    return (0);
}

static int cmePBKDFProfile (const EVP_CIPHER *cipher, const unsigned char *salt, int saltLen,
                            const unsigned char *password,int passwordLen,unsigned char *key,unsigned char *iv,
                            int profileVersion)
{
    int result;
    EVP_MD *md=NULL;
    unsigned char *buf=NULL;        //Max. size of key+IV buffer = 2 * max. length for symmetric key or IV.
    int keyLen=EVP_CIPHER_key_length(cipher);   //Get cipher key length.
    int ivLen=EVP_CIPHER_iv_length(cipher);     //Get cipher iv length.
    int kdfCount=cmeDefaultPBKDFCount;
    #define cmePBKDFFree() \
        { \
                if (buf) \
                { \
                    memset(buf,0,keyLen+ivLen); \
                    cmeFree(buf); \
                } \
        } //Local free() macro


    if (profileVersion==1) //PBKDF1
    {   //Use PBKDF1 with cipher=cmeDefaultEncAlg + MD5 + count=1 (compatible with command line password KDF from OpenSSL):
        md = (EVP_MD *)EVP_get_digestbyname("md5");
        result=EVP_BytesToKey(cipher,md,salt,password,passwordLen,1,key,iv);
    }
    else //PBKDF2
    {
        buf=(unsigned char*)malloc(sizeof(unsigned char)*(keyLen+ivLen));
        if (!buf)
        {
            return(2);
        }
        if (profileVersion==cmeLegacyPBKDFVersion)
        {
            if (cmeIsHexString((const char *)password) && passwordLen/2 >= keyLen)
            {
                kdfCount=1;
            }
            else
            {
                kdfCount=cmeLegacyPBKDFCount;
            }
            result=PKCS5_PBKDF2_HMAC_SHA1((const char *)password,passwordLen,salt,saltLen,kdfCount,keyLen+ivLen,buf);
        }
        else
        {
            result=PKCS5_PBKDF2_HMAC((const char *)password,passwordLen,salt,saltLen,
                                     cmeDefaultPBKDFCount,EVP_sha256(),keyLen+ivLen,buf);
        }
        if (result)
        {
            memcpy(key,buf,keyLen);
            memcpy(iv,buf+keyLen,ivLen);
        }
    }
    if (result==0)  //0= failure, n=size of generated key (success)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmePBKDF(), PBKDF profile %d -> 0 length key!\n",profileVersion);
#endif
        cmePBKDFFree();
        return (1);
    }
    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmePBKDF(), PBKDF profile %d -> %d bytes key, %d bytes iv.\n",profileVersion,keyLen,ivLen);
#endif
        cmePBKDFFree();
        return(0);
    }
}

int cmePBKDF (const EVP_CIPHER *cipher, const unsigned char *salt, int saltLen,
              const unsigned char *password,int passwordLen,unsigned char *key,unsigned char *iv)
{
    return(cmePBKDFProfile(cipher,salt,saltLen,password,passwordLen,key,iv,cmeDefaultPBKDFVersion));
}

int cmeSeedPrng ()
{
    int loadedBytes=0;

    if (!RAND_poll())
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSeedPrng(), RAND_poll() failed to seed OpenSSL PRNG!\n");
#endif
        if (RAND_status()!=1)
        {
            return(1);
        }
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeSeedPrng(), RAND_poll() completed.\n");
#endif
    if (access("/dev/random",R_OK)==0)
    {
        loadedBytes=RAND_load_file("/dev/random",prngSeedBytes);
        if (loadedBytes!=prngSeedBytes)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSeedPrng(), RAND_load_file() loaded %d bytes from /dev/random; expected %d.\n",
                    loadedBytes,prngSeedBytes);
#endif
        }
#ifdef DEBUG
        else
        {
            fprintf(stdout,"CaumeDSE Debug: cmeSeedPrng(), PRNG seeded - random.\n");
        }
#endif
    }
#ifdef DEBUG
    else
    {
        fprintf(stdout,"CaumeDSE Debug: cmeSeedPrng(), /dev/random not available; using OpenSSL platform seeding.\n");
    }
#endif
    if (access("/dev/urandom",R_OK)==0)
    {
        loadedBytes=RAND_load_file("/dev/urandom",prngSeedBytes*32);
        if (loadedBytes!=(prngSeedBytes*32))
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeSeedPrng(), RAND_load_file() loaded %d bytes from /dev/urandom; expected %d.\n",
                    loadedBytes,prngSeedBytes*32);
#endif
        }
#ifdef DEBUG
        else
        {
            fprintf(stdout,"CaumeDSE Debug: cmeSeedPrng(), PRNG seeded - urandom.\n");
        }
#endif
    }
#ifdef DEBUG
    else
    {
        fprintf(stdout,"CaumeDSE Debug: cmeSeedPrng(), /dev/urandom not available; using OpenSSL platform seeding.\n");
    }
#endif
    if (RAND_status()!=1)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSeedPrng(), OpenSSL PRNG is not sufficiently seeded!\n");
#endif
        return(1);
    }
    return(0);
}

int cmePrngGetBytes (unsigned char **buffer, int num)
{
    int result=0;
    *buffer=(unsigned char *)malloc(sizeof(unsigned char)*num);    //Note: caller must free memory after use !!
    if (*buffer)
    {
        if (RAND_status()!=1)
        {
            if (cmeSeedPrng())
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmePrngGetBytes(), PRNG is not sufficiently seeded!\n");
#endif
                cmeFree(*buffer);
                return(1);
            }
        }
        result=RAND_bytes(*buffer,num);
        if(!result) //Error
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmePrngGetBytes(), Error geting random bytes with"
                " RAND_bytes()!\n");
#endif
            return(1);
        }
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmePrngGetBytes(), obtained %d bytes from PRNG.\n",num);
#endif
        return(0);
    }
    else
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmePrngGetBytes(), malloc() error allocating buffer for"
                " %d pseudo random bytes!\n", num);
#endif
        return(255);
    }
}

int cmeGetRndSalt (char **rndHexSalt)
{
    char *rndBytes = NULL;

    /* Obtain random bytes for the salt and return them as a hex string. */
    cmePrngGetBytes((unsigned char **)&rndBytes, cmeDefaultIDBytesLen);
    cmeBytesToHexstr((const unsigned char *)rndBytes,
                     (unsigned char **)rndHexSalt,
                     cmeDefaultIDBytesLen); /* caller must free rndHexSalt */
    cmeFree(rndBytes);
    return (0);
}

int cmeGetRndSaltAnySize (char **rndHexSalt, int size)
{
    char *rndBytes=NULL;

    cmePrngGetBytes((unsigned char **)&rndBytes,size);  //Get random bytes for salt
    cmeBytesToHexstr((const unsigned char *)rndBytes,(unsigned char **)rndHexSalt,size); //Note that caller must free rndHexSalt!
    cmeFree(rndBytes);
    return (0);
}

int cmeCipherByteString (const unsigned char *srcBuf, unsigned char **dstBuf, unsigned char **salt,
                         const int srcLen, int *dstWritten, const char *algorithm, const char *ctPassword,
                         const char mode)
{
    int result;
    int cont=0;
    int exitcode=0;
    int written=0;
    int cipherBlockLen=0;
    int keyLen=0;
    int ivLen=0;
    unsigned char *key=NULL;
    unsigned char *iv=NULL;
    unsigned char *byteSalt=NULL;
    unsigned char hexStrbyteSalt[evpSaltBufferSize*2+1];     //Space for an hex str representation of an evpSaltBufferSize long, byte salt
    EVP_CIPHER_CTX *ctx=NULL;
    const EVP_CIPHER *cipher=NULL; //Note that cipher is a pointer to a constant cipher function in OPENSSL.
    cmeCryptoProfile cryptoProfile;
    const char *effectiveAlgorithm=algorithm;
    #define cmeCipherByteStringFree() \
        { \
                if (key) \
                { \
                    memset(key,0,keyLen); \
                    cmeFree(key); \
                } \
                if (iv) \
                { \
                    memset(iv,0,ivLen); \
                    cmeFree(iv); \
                } \
                if (byteSalt) \
                { \
                    memset(byteSalt,0,evpSaltBufferSize); \
                    cmeFree(byteSalt); \
                } \
                if (ctx) \
                { \
                    EVP_CIPHER_CTX_free(ctx); \
                } \
        }//Local free() macro

    if (srcBuf==NULL) //Error, source buffer can't be null!
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeCipherByteString(), srcBuf is NULL!\n");
#endif
        return(1);
    }
    if (mode=='d' && cmeIsHerraduraKExFrame(srcBuf,srcLen))
    {
        effectiveAlgorithm=cmeHerraduraKExAlgorithmFromProfileId(srcBuf[cmeHerraduraKExFrameMagicLen]);
        if (!effectiveAlgorithm)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeCipherByteString(), unsupported HerraduraKEx frame profile id: %u!\n",
                    (unsigned int)srcBuf[cmeHerraduraKExFrameMagicLen]);
#endif
            return(31);
        }
    }
    else if (mode=='d')
    {
        cmeCryptoProfile requestedProfile;
        if (!cmeGetCryptoProfile(&requestedProfile,algorithm) &&
            requestedProfile.provider==cmeCryptoProviderHerraduraKEx)
        {
            effectiveAlgorithm=cmeOpenSSLLegacyStorageProfile;
        }
    }
    if (cmeGetCryptoProfile(&cryptoProfile,effectiveAlgorithm) || !cryptoProfile.implemented)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeCipherByteString(), unsupported storage crypto profile: %s!\n",effectiveAlgorithm);
#endif
        return(2);
    }
    if (cryptoProfile.provider==cmeCryptoProviderHerraduraKEx)
    {
        return(cmeHerraduraKExCipherByteString(srcBuf,dstBuf,salt,srcLen,dstWritten,
                                               effectiveAlgorithm,ctPassword,mode,&cryptoProfile));
    }
    if (cryptoProfile.provider!=cmeCryptoProviderOpenSSLEVP)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeCipherByteString(), unsupported storage crypto provider for profile: %s!\n",effectiveAlgorithm);
#endif
        return(2);
    }
    if (cmeGetCipher(&cipher,effectiveAlgorithm)) //Verify algorithm and get cipher object.
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeCipherByteString(), incorrect cipher algorithm: %s!\n",effectiveAlgorithm);
#endif
        return(2);
    }
    int isGCM=0;
    int gcmTagLen=cmeGCMTagLen;
    int processedSrcLen=srcLen;
    unsigned char gcmTag[cmeGCMTagLen];
    memset(gcmTag,0,sizeof(gcmTag));
    cipherBlockLen=EVP_CIPHER_block_size(cipher); //Get cipher block length.
    keyLen=EVP_CIPHER_key_length(cipher); //Get cipher key length.
    ivLen=EVP_CIPHER_iv_length(cipher); //Get cipher iv length.
#ifdef EVP_CIPH_GCM_MODE
    if (EVP_CIPHER_mode(cipher)==EVP_CIPH_GCM_MODE)
    {
        isGCM=1;
    }
#endif
    if ((mode=='d') && isGCM)
    {
        if (srcLen<gcmTagLen)
        {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeCipherByteString(), ciphertext too short for GCM tag!\n");
#endif
            cmeCipherByteStringFree();
            return(8);
        }
        processedSrcLen=srcLen-gcmTagLen;
        memcpy(gcmTag,srcBuf+processedSrcLen,gcmTagLen);
    }
    if (mode=='e') //Encryption mode
    {
        if (!(*salt)) //if salt==NULL, We need to generate salt and return it in hexStr format.
        {             //Otherwise we use the salt provided by the caller.
            cmePrngGetBytes(&byteSalt,evpSaltBufferSize);
            cmeBytesToHexstr(byteSalt,salt,evpSaltBufferSize); //We need to return str representation of salt.
                                                               //Note:Caller must free memory for salt!
#ifdef DEBUG
            fprintf(stdout,"CaumeDSE Debug: cmeCipherByteString(), salt parameter is NULL; "
                    "defining new random salt: %s.\n",*salt);
#endif
        }
        else
        {
            strncpy((char *)hexStrbyteSalt,(char *)*salt,evpSaltBufferSize*2);
            hexStrbyteSalt[evpSaltBufferSize*2]='\0';
            if ((cmeHexstrToBytes(&byteSalt,hexStrbyteSalt))) // Error, salt is not a hexStr representation!
            {

#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: cmeCipherByteString(), salt is not a "
                        "hexStr representation; string: %s !\n",hexStrbyteSalt);
#endif
                cmeCipherByteStringFree();
                return(3);
            }
        }
    }
    else if (mode=='d') //Decryption mode
    {
        strncpy((char *)hexStrbyteSalt,(char *)*salt,evpSaltBufferSize*2);
        hexStrbyteSalt[evpSaltBufferSize*2]='\0';
        if ((cmeHexstrToBytes(&byteSalt,hexStrbyteSalt))) // Error, salt is not a hexStr representation!
        {
            cmeCipherByteStringFree();
            return(4);
        }
    }
    else //Error, unknown mode!
    {
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeCipherByteString(), Unknown cipher mode %c !\n",mode);
#endif
            cmeCipherByteStringFree();
            return(5);
    }
    {
        int allocLen=processedSrcLen+cipherBlockLen+1+(isGCM && mode=='e' ? gcmTagLen : 0);
        if(!(*dstBuf=(unsigned char *)malloc(allocLen))) //Error allocating memory!
        {                                                //Note: Caller must free *dstBuf!
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeCipherByteString(), Error in memory allocation!\n");
#endif
            cmeCipherByteStringFree();
            return(6);
        }
        memset(*dstBuf,0,allocLen);     // we add 1 block more (for encryption padding). + 1 for null ending for unencrypted strings
    }
    key=(unsigned char *)malloc(keyLen);
    iv=(unsigned char *)malloc(ivLen);
    {
        int kdfProfiles[2];
        int numKDFProfiles=1;
        int profileIndex=0;
        int attemptExitcode=0;

        kdfProfiles[0]=cmeDefaultPBKDFVersion;
        if ((mode=='d')&&(cmeDefaultPBKDFVersion!=cmeLegacyPBKDFVersion))
        {
            kdfProfiles[1]=cmeLegacyPBKDFVersion;
            numKDFProfiles=2;
        }

        for (profileIndex=0;profileIndex<numKDFProfiles;profileIndex++)
        {
            if (ctx)
            {
                EVP_CIPHER_CTX_free(ctx);
                ctx=NULL;
            }
            memset(key,0,keyLen);
            memset(iv,0,ivLen);
            memset(*dstBuf,0,processedSrcLen+cipherBlockLen+1+(isGCM && mode=='e' ? gcmTagLen : 0));
            attemptExitcode=0;
            cont=0;
            *dstWritten=0;
            if ((cmePBKDFProfile(cipher,byteSalt,evpSaltBufferSize,(unsigned char *)ctPassword,strlen(ctPassword),
                                 key,iv,kdfProfiles[profileIndex]))) //Error setting key & IV.
            {
                cmeCipherByteStringFree();
                return(7);
            }
            result=cmeCipherInit(&ctx,NULL,cipher,key,iv,mode);
            if (result)
            {
                attemptExitcode+=result;
                *dstWritten=0;
            }
            else
            {
                {
                    int updateLen=(mode=='d' && isGCM) ? processedSrcLen : srcLen;
                    cmeCipherUpdate(ctx,(*dstBuf),&written,(unsigned char *)srcBuf,updateLen,mode);
                }
                cont+=written;
                if (isGCM)
                {
                    if (mode=='e')
                    {
                        if (!EVP_EncryptFinal_ex(ctx,((*dstBuf)+cont),&written))
                        {
                            attemptExitcode+=2;
                        }
                        else
                        {
                            cont+=written;
                            if (!EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,gcmTagLen,gcmTag))
                            {
                                attemptExitcode+=4;
                            }
                            else
                            {
                                memcpy((*dstBuf)+cont,gcmTag,gcmTagLen);
                                cont+=gcmTagLen;
                            }
                        }
                    }
                    else
                    {
                        if (!EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,gcmTagLen,gcmTag))
                        {
                            attemptExitcode+=4;
                        }
                        else if (!EVP_DecryptFinal_ex(ctx,((*dstBuf)+cont),&written))
                        {
                            attemptExitcode+=3;
                        }
                        else
                        {
                            cont+=written;
                        }
                    }
                    *dstWritten=cont;
                    (*dstBuf)[cont]='\0';
                }
                else
                {
                    result=cmeCipherFinal(&ctx,((*dstBuf)+cont),&written,mode);
                    attemptExitcode+=result;
                    cont+=written;
                    *dstWritten=cont;
                    (*dstBuf)[cont]='\0'; //Decryption does not guarantee that an unencrypted string will be null terminated.
                }
            }
            exitcode=attemptExitcode;
            if (!exitcode)
            {
                break;
            }
#ifdef DEBUG
            if ((mode=='d')&&(profileIndex+1<numKDFProfiles))
            {
                fprintf(stdout,"CaumeDSE Debug: cmeCipherByteString(), retrying decrypt with legacy PBKDF profile %d.\n",
                        kdfProfiles[profileIndex+1]);
            }
#endif
        }
    }
    memset(gcmTag,0,sizeof(gcmTag));
    cmeCipherByteStringFree();
    return (exitcode);
}

int cmeProtectByteString (const char *value, char **protectedValue, const char *encAlg, char **salt,
                          const char *orgKey, int *protectedValueLen, const int valueLen)
{
    int result,written;
    char *currentEncData=NULL;
    #define cmeProtectByteStringFree() \
        { \
            if (currentEncData) \
                { \
                    cmeFree(currentEncData); \
                } \
        }//Local free() macro

    if (value==NULL) //Error: no value to encrypt
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeProtectByteString(), cmeCipherByteString() Error, can't "
                "encrypt NULL byte string with algorithm %s!\n",encAlg);
#endif
        return(1);
    }
    result=cmeCipherByteString((unsigned char *)value,(unsigned char **)&currentEncData,(unsigned char **)salt,
                               valueLen,&written,encAlg,orgKey,'e');   //Encrypt Value
    if (result) //Error
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeProtectByteString(), cmeCipherByteString() Error, can't "
                "encrypt 'byte string' len=%d with algorithm %s!\n",valueLen,encAlg);
#endif
        cmeProtectByteStringFree();
        return(2);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeProtectByteString(), encrypted 'byte string': "
            "valueLen=%d with algorithm %s.\n",valueLen,encAlg);
#endif
    result=cmeStrToB64((unsigned char *)currentEncData,(unsigned char **)protectedValue,
                       written,protectedValueLen);
    cmeProtectByteStringFree();
    return (0);
}

int cmeUnprotectByteString (const char *protectedValue, char **value, const char *encAlg, char **salt,
                            const char *orgKey, int *valueLen, const int protectedValueLen)
{
    int result,written;
    char *currentEncData=NULL;
    #define cmeUnProtectByteStringFree() \
        { \
            if (currentEncData) \
                { \
                    cmeFree(currentEncData); \
                } \
        }//Local free() macro

    *value=NULL;
    if (!protectedValue) //WARNING: null input!
    {
        *valueLen=0;
        cmeStrConstrAppend(value,"");
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeUnprotectByteString(), cmeCipherByteString() Warning, can't "
                "decrypt 'byte string' = NULL, with algorithm %s and key <redacted>!\n",encAlg);
#endif
        return(0); //Not an error, just a warning!
    }
    result=cmeB64ToStr((unsigned char *)protectedValue,(unsigned char **)&currentEncData,
                       protectedValueLen,&written);
    result=cmeCipherByteString((unsigned char *)currentEncData,(unsigned char **)value,(unsigned char **)salt,
                               written,valueLen,encAlg,orgKey,'d');   //Decrypt Value.
    cmeUnProtectByteStringFree();
    if (result) //Decryption failed. Return empty string.
    {
        cmeFree(*value); //Clean value; we will return an empty string.
        *valueLen=0;
        cmeStrConstrAppend(value,"");
#ifdef DEBUG
        fprintf(stderr,"CaumeDSE Debug: cmeUnprotectByteString(), cmeCipherByteString() Warning, can't "
                "decrypt 'byte string' len=%d with algorithm %s and key <redacted>!\n",
                protectedValueLen,encAlg);
#endif
    }
    else //Decryption successful.
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeUnprotectByteString(), decrypted 'byte string': "
                "protectedLen=%d with algorithm %s -> valueLen=%d.\n",protectedValueLen,encAlg,*valueLen);
#endif
    }
    cmeUnProtectByteStringFree();
    return (0);
}

int cmeDigestByteString (const unsigned char *srcBuf, unsigned char **dstBuf, const int srcLen,
                         int *dstWritten, const char *algorithm)
{
    int result=0;
    int cont=0;
    int cont2=0;
    int exitcode=0;
    int written=0;
    unsigned char *digestBytes=NULL;
    EVP_MD_CTX *ctx=NULL;     //Note that ctx will be freed normally by cmeDigestFinal(), but we need to free it if we exit before cmeDigestFinal() is called.
    EVP_MD *digest=NULL;      //Note that digest is a pointer to a constant digest function in OPENSSL.
    #define cmeDigestByteStringFree() \
        { \
                if(ctx)\
                {\
                    EVP_MD_CTX_free(ctx); \
                }\
                if(digestBytes)\
                {\
                    cmeFree(digestBytes); \
                }\
        } //Local free() macro

    if (srcBuf==NULL) //Error, source buffer can't be null!
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeDigestByteString(), srcBuf is NULL!\n");
#endif
        return(1);
    }
    if ((cmeGetDigest(&digest,algorithm))) //Verify algorithm and create digest object.
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeDigestByteString(), incorrect digest algorithm; %s!\n",algorithm);
#endif
        cmeDigestByteStringFree();
        return(2);
    }
    digestBytes=(unsigned char *)malloc(EVP_MAX_MD_SIZE);
    if(!(*dstBuf=(unsigned char *)malloc(evpMaxHashStrLen))) //Error allocating memory!
    {                                                             //Note that Caller must free *dstBuf!
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeDigestByteString(), Error in memory allocation!\n");
#endif
        cmeDigestByteStringFree();
        return(3);
    }
    memset(*dstBuf,0,evpMaxHashStrLen);
    cmeDigestInit(&ctx,NULL,digest);
    cont2=0;
    for (cont=0; cont<(srcLen/evpBufferSize); cont++) //Process all blocks of size evpBufferSize.
    {
        cmeDigestUpdate(ctx,srcBuf+cont2,evpBufferSize);
        cont2 += evpBufferSize;
    }
    if (srcLen%evpBufferSize) //Process last chunk with size < evpBufferSize.
    {
        cmeDigestUpdate(ctx,srcBuf+cont2,(srcLen%evpBufferSize));
        cont2 += (srcLen%evpBufferSize);
    }
    result=cmeDigestFinal(&ctx,digestBytes,(unsigned int *)&written);
    exitcode+=result;
    cmeBytesToHexstr(digestBytes,dstBuf,written); //convert byte array to Byte HexStr.
    *dstWritten=strlen((const char *)*dstBuf);
    memset(digestBytes,0,EVP_MAX_MD_SIZE); //Clear memory of resulting digest bytes.
    cmeDigestByteStringFree();
    return (exitcode);
}

int cmeHMACInit (CME_HMAC_CTX **ctx, ENGINE *engine, EVP_MD *digest, const char *key, int keyLen)
{
    int result;
#if OPENSSL_VERSION_MAJOR >= 3
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac)
        return 1;
    *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (*ctx == NULL)
        return 1;
    const char *mdname = EVP_MD_get0_name(digest);
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)mdname, 0),
        OSSL_PARAM_END
    };
    result = EVP_MAC_init(*ctx, (const unsigned char *)key, keyLen, params);
#else
    *ctx=HMAC_CTX_new();
    result= HMAC_Init_ex(*ctx,key,keyLen,digest,engine);
#endif
    if (result==0)  //1= success, 0=failure
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeHMACInit(), HMAC_Init_ex() failure!\n");
#endif
        return (1);
    }
    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeHMACInit(), HMAC_Init_ex() success.\n");
#endif
        return (0);
    }
}

int cmeHMACUpdate (CME_HMAC_CTX *ctx, const void *in, size_t inl)
{
    int result;
#if OPENSSL_VERSION_MAJOR >= 3
    result=EVP_MAC_update(ctx,in,inl);
#else
    result=HMAC_Update(ctx,in,inl);
#endif
    if (result==0)  //1= success, 0=failure
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeHMACUpdate(), HMAC_Update() failure!\n");
#endif
        return (1);
    }
    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeHMACUpdate(), HMAC_Update() success.\n");
#endif
        return (0);
    }
}

int cmeHMACFinal(CME_HMAC_CTX **ctx, unsigned char *out, unsigned int *outl)
{
    int result;
#if OPENSSL_VERSION_MAJOR >= 3
    size_t outlen=0;
    result=EVP_MAC_final(*ctx,out,&outlen,EVP_MAC_CTX_get_mac_size(*ctx));
    if(outl) *outl=(unsigned int)outlen;
    CME_HMAC_CTX_free(*ctx); //override generic free: cmeFree(*ctx);
#else
    result=HMAC_Final(*ctx,out,outl);
    CME_HMAC_CTX_free(*ctx); //override generic free: cmeFree(*ctx);
#endif
    *ctx=NULL;
    if (result==0)  //1= success, 0=failure
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeHMACFinal(), HMAC_Final() failure!\n");
#endif
        return (1);
    }
    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeHMACFinal(), HMAC_Final() success.\n");
#endif
       return (0);
    }
}

int cmeHMACByteString (const unsigned char *srcBuf, unsigned char **dstBuf, const int srcLen,
                       int *dstWritten, const char *algorithm, char **salt, const char *userKey)
{
    int result=0;
    int cont=0;
    int cont2=0;
    int exitcode=0;
    int written=0;
    int keyLen=0;
    unsigned char *key=NULL;
    unsigned char *digestBytes=NULL;
    unsigned char *byteSalt=NULL;
    unsigned char hexStrbyteSalt[evpSaltBufferSize*2+1];     //Space for an hex str representation of an evpSaltBufferSize long, byte salt
    CME_HMAC_CTX *ctx=NULL;                 //Note that ctx will be freed normally by cmeHMACFinal(), but we need to free it if we exit before cmeHMACFinal() is called.
    EVP_MD *digest=NULL;          //Note that digest is a pointer to a constant digest function in OPENSSL.
    cmeCryptoProfile defaultProfile;
#if OPENSSL_VERSION_MAJOR >= 3
    #define cmeHMACByteStringFree() \
        { \
                if (ctx) \
                    CME_HMAC_CTX_free(ctx); \
                if (digestBytes) \
                    cmeFree(digestBytes); \
                if (key) \
                    { memset(key,0,keyLen); cmeFree(key); } \
                if (byteSalt) \
                    { memset(byteSalt,0,evpSaltBufferSize); cmeFree(byteSalt); } \
        }
#else
    #define cmeHMACByteStringFree() \
        { \
                if (ctx) \
                    CME_HMAC_CTX_free(ctx); \
                if (digestBytes) \
                    cmeFree(digestBytes); \
                if (key) \
                    { memset(key,0,keyLen); cmeFree(key); } \
                if (byteSalt) \
                    { memset(byteSalt,0,evpSaltBufferSize); cmeFree(byteSalt); } \
        }
#endif
        //Local free() macro

    if (srcBuf==NULL) //Error, source buffer can't be null!
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeHMACByteString(), srcBuf is NULL!\n");
#endif
        return(1);
    }
    if (cmeGetCryptoProfile(&defaultProfile,cmeDefaultEncAlg) ||
        !defaultProfile.implemented || !defaultProfile.allowedAsDefault ||
        defaultProfile.keyLen<=0)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeHMACByteString(), unsupported default storage crypto profile; %s!\n",cmeDefaultEncAlg);
#endif
        cmeHMACByteStringFree();
        return(2);
    }
    if ((cmeGetDigest(&digest,algorithm))) //Verify algorithm and create digest object.
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeHMACByteString(), incorrect digest algorithm; %s!\n",algorithm);
#endif
        cmeHMACByteStringFree();
        return(3);
    }
    digestBytes=(unsigned char *)malloc(EVP_MAX_MD_SIZE);
    if(!(*dstBuf=(unsigned char *)malloc(evpMaxHashStrLen))) //Error allocating memory!
    {                                                             //Note that Caller must free *dstBuf!
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeHMACByteString(), Error in memory allocation!\n");
#endif
        cmeHMACByteStringFree();
        return(4);
    }
    memset(*dstBuf,0,evpMaxHashStrLen);

    if (!(*salt)) //if salt==NULL, We need to generate salt and return it in hexStr format.
    {             //Otherwise we use the salt provided by the caller.
        cmePrngGetBytes(&byteSalt,evpSaltBufferSize);
        cmeBytesToHexstr(byteSalt,(unsigned char **)salt,evpSaltBufferSize); //We need to return str representation of salt.
                                                           //Note:Caller must free memory for salt!
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeHMACByteString(), salt parameter is NULL; "
                "defining new random salt: %s.\n",*salt);
#endif
    }
    else
    {
        strncpy((char *)hexStrbyteSalt,(char *)*salt,evpSaltBufferSize*2);
        hexStrbyteSalt[evpSaltBufferSize*2]='\0';
        if ((cmeHexstrToBytes(&byteSalt,hexStrbyteSalt))) // Error, salt is not a hexStr representation!
        {

#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeHMACByteString(), salt is not a "
                    "hexStr representation; string: %s !\n",hexStrbyteSalt);
#endif
            cmeHMACByteStringFree();
            return(3);
        }
    }
    keyLen=defaultProfile.keyLen;
    key=(unsigned char *)malloc(keyLen);
    if (!key)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeHMACByteString(), Error in memory allocation!\n");
#endif
        cmeHMACByteStringFree();
        return(4);
    }
    if (!PKCS5_PBKDF2_HMAC(userKey,strlen(userKey),byteSalt,evpSaltBufferSize,
                           cmeDefaultPBKDFCount,EVP_sha256(),keyLen,key))
    {
        cmeHMACByteStringFree();
        return(7);
    }

    ///keyLen=strlen(key);
    cmeHMACInit(&ctx,NULL,digest,(const char *)key,keyLen);
    cont2=0;
    for (cont=0; cont<(srcLen/evpBufferSize); cont++) //Process all blocks of size evpBufferSize.
    {
        cmeHMACUpdate(ctx,srcBuf+cont2,evpBufferSize);
        cont2 += evpBufferSize;
    }
    if (srcLen%evpBufferSize) //Process last chunk with size < evpBufferSize.
    {
        cmeHMACUpdate(ctx,srcBuf+cont2,(srcLen%evpBufferSize));
        cont2 += (srcLen%evpBufferSize);
    }
    result=cmeHMACFinal(&ctx,digestBytes,(unsigned int *)&written);
    exitcode+=result;
    cmeBytesToHexstr(digestBytes,dstBuf,written); //Convert byte array to Byte HexStr.
    *dstWritten=strlen((const char *)*dstBuf);
    memset(digestBytes,0,EVP_MAX_MD_SIZE); //Clear memory of resulting MAC bytes.
    cmeHMACByteStringFree();
    return (exitcode);
}

int cmeDigestLen (const char *algorithm, int *digestLen)
{
    EVP_MD *digest=NULL;      //Note that digest is a pointer to a constant digest function in OPENSSL.

    *digestLen=0;
    if ((cmeGetDigest(&digest,algorithm))) //Verify algorithm and point to digest object.
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeDigestLen(), incorrect digest algorithm; %s!\n",algorithm);
#endif
        return(1);
    }
    *digestLen=EVP_MD_size(digest);
    return (0);
}
