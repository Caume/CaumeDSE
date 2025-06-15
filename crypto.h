/***
Copyright 2010-2021 by Omar Alejandro Herrera Reyna

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
#ifndef CRYPTO_H_INCLUDED
#define CRYPTO_H_INCLUDED
#if OPENSSL_VERSION_MAJOR >= 3
typedef EVP_MAC_CTX CME_HMAC_CTX;
#define CME_HMAC_CTX_free(ctx) EVP_MAC_CTX_free(ctx)
#else
typedef HMAC_CTX CME_HMAC_CTX;
#define CME_HMAC_CTX_free(ctx) HMAC_CTX_free(ctx)
#endif

// --- OpenSSL Wrappers and CaumeDSE Crypto functions prototypes
// Wrapper Function to get a digest function pointer by name
int cmeGetDigest (EVP_MD** digest, const char* algorithm);
// Wrapper Function for OpenSSL's EVP_DigestInit_ex()
int cmeDigestInit (EVP_MD_CTX** ctx, ENGINE* engine, EVP_MD* digest);
// Wrapper Function for OpenSSL's EVP_DigestUpdate()
int cmeDigestUpdate (EVP_MD_CTX* ctx, const void* in, size_t inl);
// Wrapper Function for OpenSSl's EVP_DigestFinal_ex()
int cmeDigestFinal(EVP_MD_CTX** ctx, unsigned char* out, unsigned int* outl);
// Wrapper Function to get a cipher function pointer by name
int cmeGetCipher (const EVP_CIPHER** cipher,const char* algorithm);
// Wrapper Function for OpenSSL's EVP_EncryptInit_ex() and EVP_DecryptInit_ex()
int cmeCipherInit (EVP_CIPHER_CTX** ctx, ENGINE* engine, const EVP_CIPHER* cipher, unsigned char* key,
                   unsigned char* iv, char mode);
// Wrapper Function for OpenSSL's EVP_EncryptUpdate() and EVP_DecryptUpdate()
int cmeCipherUpdate (EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl,
                     unsigned char* in, int inl, char mode);
// Wrapper Function for OpenSSl's EVP_EncryptFinal_ex() and EVP_DecryptFinal_ex()
int cmeCipherFinal(EVP_CIPHER_CTX **ctx, unsigned char *out, int *outl, const char mode);
// Wrapper Function for OpenSSL's EVP_BytesToKey(). This is compatible with command line 'openssl enc' command.
int cmePBKDF (const EVP_CIPHER *cipher, const unsigned char *salt, int saltLen,
              const unsigned char *password, int passwordLen,unsigned char *key,unsigned char *iv);
// Wrapper function for OpenSSL's RAND_load_file()
int cmeSeedPrng ();
// Wrapper function for OpenSSL's RAND_bytes()
int cmePrngGetBytes (unsigned char **buffer, int num);
// Wrapper function to create HEX string random salt of cmeDefaultIDBytesLen length.
int cmeGetRndSalt (char **rndHexSalt);
// Wrapper function to create HEX string random salt of 'size' length.
int cmeGetRndSaltAnySize (char **rndHexSalt, int size);
// Function that encrypts/decrypts symmetrically a byte string in blocks of evpBufferSize.
int cmeCipherByteString (const unsigned char *srcBuf, unsigned char **dstBuf, unsigned char **salt,
                         const int srcLen, int *dstWritten, const char *algorithm, const char *ctPassword,
                         const char mode);
// Function to protect (encrypt and B64 encode) a byte string.
int cmeProtectByteString (const char *value, char **protectedValue, const char *encAlg, char **salt,
                          const char *orgKey, int *protectedValueLen, const int valueLen);
// Function to unprotect (decode B64 and decrypt) a byte string.
int cmeUnprotectByteString (const char *protectedValue, char **value, const char *encAlg, char **salt,
                            const char *orgKey, int *valueLen, const int protectedValueLen);
// Function to hash a byte string in blocks of evpBufferSize.
int cmeDigestByteString (const unsigned char *srcBuf, unsigned char **dstBuf, const int srcLen,
                         int *dstWritten, const char *algorithm);
// Function to return the size (in bytes) of digest for the specified hash algorithm.
int cmeDigestLen (const char *algorithm, int *digestLen);
// Wrapper Function for OpenSSL's HMAC_Init_ex().
int cmeHMACInit (CME_HMAC_CTX **ctx, ENGINE *engine, EVP_MD *digest, const char *key, int keyLen);
// Wrapper Function for OpenSSL's HMAC_Update().
int cmeHMACUpdate (CME_HMAC_CTX *ctx, const void *in, size_t inl);
// Wrapper Function for OpenSSl's HMAC_Final().
int cmeHMACFinal(CME_HMAC_CTX **ctx, unsigned char *out, unsigned int *outl);
// Function to create an HMAC MAC of byte string, in blocks of evpBufferSize.
int cmeHMACByteString (const unsigned char *srcBuf, unsigned char **dstBuf, const int srcLen,
                       int *dstWritten, const char *algorithm, char **salt, const char *userKey);


#endif // CRYPTO_H_INCLUDED
