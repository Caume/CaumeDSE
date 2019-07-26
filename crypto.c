/***
Copyright 2010-2019 by Omar Alejandro Herrera Reyna

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

    *ctx = EVP_CIPHER_CTX_new();
    if ((mode!='d')&&(mode!='e'))
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: evpCipherInit(), unknown cipher mode '%c'!\n",mode);
#endif
        return (1);
    }

    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: evpCipherInit(), cipher mode '%c' selected.\n",mode);
#endif
        if (mode=='e')  //Encrypt
        {
            result= EVP_EncryptInit_ex(*ctx,cipher,engine,key,iv);

            if (result==0)  //1= success, 0=failure
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: evpCipherInit(), EVP_EncryptInit_ex() failure!\n");
#endif
                return (2);
            }
            else
            {
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: evpCipherInit(), EVP_EncryptInit_ex() success.\n");
#endif
            }

        }
        else            //Decrypt
        {
            result= EVP_DecryptInit_ex(*ctx,cipher,engine,key,iv);

            if (result==0)  //1= success, 0=failure
            {
#ifdef ERROR_LOG
                fprintf(stderr,"CaumeDSE Error: evpCipherInit(), EVP_DecryptInit_ex() failure!\n");
#endif
                return (2);
            }
            else
            {
#ifdef DEBUG
                fprintf(stdout,"CaumeDSE Debug: evpCipherInit(), EVP_DecryptInit_ex() success.\n");
#endif
            }

        }
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

int cmePBKDF (const EVP_CIPHER *cipher, const unsigned char *salt, int saltLen,
              const unsigned char *password,int passwordLen,unsigned char *key,unsigned char *iv)
{
    int result;
    EVP_MD *md=NULL;
    unsigned char *HexStrToByteBuffer=NULL;
    unsigned char *buf=NULL;        //Max. size of key+IV buffer = 2 * max. length for symmetric key or IV.
    int keyLen=EVP_CIPHER_key_length(cipher);   //Get cipher key length.
    int ivLen=EVP_CIPHER_iv_length(cipher);     //Get cipher iv length.
    #define cmePBKDFFree() \
        { \
                if (HexStrToByteBuffer) \
                { \
                    memset(HexStrToByteBuffer,0,strlen(password)/2); \
                    cmeFree(HexStrToByteBuffer); \
                } \
                if (buf) \
                { \
                    memset(buf,0,keyLen+ivLen); \
                    cmeFree(buf); \
                } \
        } //Local free() macro


    if (cmeDefaultPBKDFVersion==1) //PBKDF1
    {   //Use PBKDF1 with cipher=cmeDefaultEncAlg + MD5 + count=1 (compatible with command line password KDF from OpenSSL):
        md = (EVP_MD *)EVP_get_digestbyname("md5");
        result=EVP_BytesToKey(cipher,md,salt,password,passwordLen,1,key,iv);
    }
    else //PBKDF2
    {
        result=cmeHexstrToBytes(&HexStrToByteBuffer,password);
        if ((result)||(passwordLen/2<keyLen)) //Password is not a HexStr representation of a binary key in cipher's keyspace -> Use PBKDF2 with several iterations for password expansion into full keyspace.
        {   // (Very slow, but provides a good security level for keys derived from human generated passwords).
            //Use PBKDF2 with HMAC_SHA1 + count=cmeDefaultPBKDFCount (not compatible with command line password KDF from OpenSSL):
            buf=(unsigned char*)malloc(sizeof(unsigned char)*(keyLen+ivLen));
            result=PKCS5_PBKDF2_HMAC_SHA1((const char *)password,passwordLen,salt,saltLen,cmeDefaultPBKDFCount,keyLen+ivLen,buf);
            memcpy(key,buf,keyLen);
            memcpy(iv,buf+keyLen,ivLen);
        }
        else //Password is a HexStr representation of a binary key in cipher's keyspace -> Use PBKDF2 with 1 iteration as a permutation in keyspace using the provided salt.
        {   // (Fast; provides equivalent security level as a random key selected from crypto algorithm's full keyspace).
            //Use PBKDF2 with HMAC_SHA1 + count=cmeDefaultPBKDFCount (not compatible with command line password KDF from OpenSSL):
            buf=(unsigned char*)malloc(sizeof(unsigned char)*(keyLen+ivLen));
            result=PKCS5_PBKDF2_HMAC_SHA1((const char *)password,passwordLen,salt,saltLen,1,keyLen+ivLen,buf);
            memcpy(key,buf,keyLen);
            memcpy(iv,buf+keyLen,ivLen);
        }
    }
    if (result==0)  //0= failure, n=size of generated key (success)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmePBKDF(), PBKDF ver. %d -> 0 length key!\n",cmeDefaultPBKDFVersion);
#endif
        cmePBKDFFree();
        return (1);
    }
    else
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmePBKDF(), PBKDF ver. %d -> %d bytes key, %d bytes iv.\n",cmeDefaultPBKDFVersion,keyLen,ivLen);
#endif
        cmePBKDFFree();
        return(0);
    }
}

int cmeSeedPrng (){   // TODO (OHR#5#): Check if another random source is needed, especially for OSes that do not have /dev/random and /dev/urandom.
    if(!RAND_load_file("/dev/random",prngSeedBytes)) //Get information from best entropy source. But note that implementation varies from OS to OS! (http://en.wikipedia.org/wiki//dev/random)
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSeedPrng(), Error seeding PRNG with RAND_load_file()"
                " and /dev/random!\n");
#endif
        return(1);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeSeedPrng(), PRNG seeded - random.\n");
#endif
    if(!RAND_load_file("/dev/urandom",prngSeedBytes*32)) //Get information from second best entropy source
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeSeedPrng(), Error seeding PRNG with RAND_load_file()"
                " and /dev/urandom!\n");
#endif
        return(1);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeSeedPrng(), PRNG seeded - urandom.\n");
#endif
    return(0);
}

int cmePrngGetBytes (unsigned char **buffer, int num)
{
    int result=0;
    *buffer=(unsigned char *)malloc(sizeof(unsigned char)*num);    //Note: caller must free memory after use !!
    if (*buffer)
    {
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
    char *rndBytes=NULL;

    cmePrngGetBytes((unsigned char **)&rndBytes,cmeDefaultIDBytesLen);  //Get random bytes for salt
    cmeBytesToHexstr((const unsigned char *)rndBytes,(unsigned char **)rndHexSalt,cmeDefaultIDBytesLen); //Note that caller must free rndHexSalt!
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
    if (cmeGetCipher(&cipher,algorithm)) //Verify algorithm and get cipher object.
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeCipherByteString(), incorrect cipher algorithm: %s!\n",algorithm);
#endif
        return(2);
    }
    cipherBlockLen=EVP_CIPHER_block_size(cipher); //Get cipher block length.
    keyLen=EVP_CIPHER_key_length(cipher); //Get cipher key length.
    ivLen=EVP_CIPHER_iv_length(cipher); //Get cipher iv length.
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
    if(!(*dstBuf=(unsigned char *)malloc(srcLen+cipherBlockLen+1))) //Error allocating memory!
    {                                                                //Note: Caller must free *dstBuf!
#ifdef ERROR_LOG
            fprintf(stderr,"CaumeDSE Error: cmeCipherByteString(), Error in memory allocation!\n");
#endif
        cmeCipherByteStringFree();
        return(6);
    }
    memset(*dstBuf,0,srcLen+cipherBlockLen+1);     // we add 1 block more (for encryption padding). + 1 for null ending for unencrypted strings
    key=(unsigned char *)malloc(keyLen);
    iv=(unsigned char *)malloc(ivLen);
    if ((cmePBKDF(cipher,byteSalt,evpSaltBufferSize,(unsigned char *)ctPassword,strlen(ctPassword),key,iv))) //Error setting key & IV.
    {
        cmeCipherByteStringFree();
        return(7);
    }
    else //Key & IV set; proceed.
    {
        cmeCipherInit(&ctx,NULL,cipher,key,iv,mode);
        cont=0;
        cmeCipherUpdate(ctx,(*dstBuf),&written,(unsigned char *)srcBuf,srcLen,mode);
        cont+=written;
        result=cmeCipherFinal(&ctx,((*dstBuf)+cont),&written,mode);
        exitcode+=result;
        cont += written;
        *dstWritten=cont;
        (*dstBuf)[cont]='\0'; //Decryption does not guarantee that an unencrypted string will be null terminated.
    }
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
                "encrypt 'byte string' %s with algorithm %s!\n",value,encAlg);
#endif
        cmeProtectByteStringFree();
        return(2);
    }
#ifdef DEBUG
    fprintf(stdout,"CaumeDSE Debug: cmeProtectByteString(), encrypted 'byte string': "
            "%s with algorithm %s.\n",value,encAlg);
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
                "decrypt 'byte string' = NULL, with algorithm %s and key %s!\n",encAlg,orgKey);
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
                "decrypt 'byte string' %s with algorithm %s and the key %s!\n",
                protectedValue,encAlg,orgKey);
#endif
    }
    else //Decryption successful.
    {
#ifdef DEBUG
        fprintf(stdout,"CaumeDSE Debug: cmeUnprotectByteString(), decrypted 'byte string': "
                "%s with algorithm %s -> %s.\n",protectedValue,encAlg,*value);
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

int cmeHMACInit (HMAC_CTX **ctx, ENGINE *engine, EVP_MD *digest, const char *key, int keyLen)
{
    int result;

    *ctx=HMAC_CTX_new();
    result= HMAC_Init_ex(*ctx,key,keyLen,digest,engine);
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

int cmeHMACUpdate (HMAC_CTX *ctx, const void *in, size_t inl)
{
    int result;

    result=HMAC_Update(ctx,in,inl);
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

int cmeHMACFinal(HMAC_CTX **ctx, unsigned char *out, unsigned int *outl)
{
    int result;

    result=HMAC_Final(*ctx,out,outl);
    HMAC_CTX_free(*ctx); //override generic free: cmeFree(*ctx);
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
    int ivLen=0;
    unsigned char *key=NULL;
    unsigned char *iv=NULL;
    unsigned char *digestBytes=NULL;
    unsigned char *byteSalt=NULL;
    unsigned char hexStrbyteSalt[evpSaltBufferSize*2+1];     //Space for an hex str representation of an evpSaltBufferSize long, byte salt
    HMAC_CTX *ctx=NULL;                 //Note that ctx will be freed normally by cmeHMACFinal(), but we need to free it if we exit before cmeHMACFinal() is called.
    EVP_MD *digest=NULL;          //Note that digest is a pointer to a constant digest function in OPENSSL.
    const EVP_CIPHER *cipher=NULL;      //Note that cipher is a pointer to a constant cipher function in OPENSSL.
    #define cmeHMACByteStringFree() \
        { \
                if (ctx) \
                { \
                    HMAC_CTX_free(ctx); \
                }\
                if (digestBytes) \
                { \
                    cmeFree(digestBytes); \
                }\
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
        } //Local free() macro

    if (srcBuf==NULL) //Error, source buffer can't be null!
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeHMACByteString(), srcBuf is NULL!\n");
#endif
        return(1);
    }
    if ((cmeGetCipher(&cipher,cmeDefaultEncAlg))) //Use default encryption algorithm's key length for PBKDF.
    {
#ifdef ERROR_LOG
        fprintf(stderr,"CaumeDSE Error: cmeHMACByteString(), incorrect digest algorithm; %s!\n",algorithm);
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
    keyLen=EVP_CIPHER_key_length(cipher); //Get cipher key length.
    ivLen=EVP_CIPHER_iv_length(cipher); //Get cipher iv length.
    key=(unsigned char *)malloc(keyLen);
    iv=(unsigned char *)malloc(ivLen);
    if ((cmePBKDF(cipher,byteSalt,evpSaltBufferSize,(unsigned char *)userKey,strlen(userKey),key,iv))) //Error setting key & IV.
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
