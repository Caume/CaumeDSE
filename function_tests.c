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

static int cmeDebugTestsNonInteractiveEnabled(void)
{
    const char *env = getenv("CDSE_DEBUG_TESTS_NONINTERACTIVE");
    return (env && *env && strcmp(env,"0"));
}

static char *cmeTestPath(const char *relativePath)
{
    char *result = NULL;
    cmeStrConstrAppend(&result, "%s%s", cmeDefaultFilePath, relativePath);
    return result;
}

static int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                           const unsigned char *aad, int aad_len,
                           const unsigned char *key, const unsigned char *iv,
                           int iv_len, unsigned char *ciphertext,
                           unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ciphertext_len = 0;
    if (!ctx)
        return -1;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        goto err;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        goto err;
    if (aad && aad_len)
        if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            goto err;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        goto err;
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        goto err;
    ciphertext_len += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        goto err;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static int aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                           const unsigned char *aad, int aad_len,
                           const unsigned char *tag,
                           const unsigned char *key, const unsigned char *iv,
                           int iv_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, plaintext_len = 0, ret = -1;
    if (!ctx)
        return -1;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        goto err;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        goto err;
    if (aad && aad_len)
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            goto err;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        goto err;
    plaintext_len = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag))
        goto err;
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret > 0)
    {
        plaintext_len += len;
        ret = plaintext_len;
    }
    else
        ret = -1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

void testCryptoSymmetric(unsigned char *bufIn, unsigned char *bufOut)
{
    int cont,cont2,written,ctSize,result __attribute__((unused));
    unsigned char password[10]= "Password";
    unsigned char cleartext[] = "This is cleartext This is cleartext This is cleartext This is cleartext.\n";
    const char *algorithm = cmeDefaultEncAlg;
    unsigned char *key=NULL;
    unsigned char *iv=NULL;
    unsigned char *ciphertext=NULL;
    unsigned char *deciphertext=NULL;
    unsigned char *salt=NULL;
    FILE *fp=NULL;
    EVP_CIPHER_CTX *ctx=NULL;
    const EVP_CIPHER *cipher=NULL;

    key=(unsigned char *)malloc(1024);
    iv=(unsigned char *)malloc(1024);
    ciphertext=(unsigned char *)malloc(1024);

    cmeGetCipher(&cipher,algorithm);
    cmePBKDF(cipher,NULL,0,password,8,key,iv);
    cmeCipherInit(&ctx,NULL,cipher,key,iv,'e');
    cont2=0;
    ctSize=strlen((char*)cleartext);
    printf ("---ctSize: %d\n",ctSize);
    for (cont=0; cont<(ctSize/evpBufferSize); cont++)
    {
        memcpy(bufIn,&cleartext[cont2],evpBufferSize);
        cmeCipherUpdate(ctx,bufOut,&written,bufIn,evpBufferSize,'e');
        memcpy(&ciphertext[cont2],bufOut,written);
        cont2 += written;
    }
    if (ctSize % evpBufferSize)
    {
        memcpy(bufIn,&cleartext[cont2],ctSize % evpBufferSize);
        cmeCipherUpdate(ctx,bufOut,&written,bufIn,ctSize % evpBufferSize,'e');
        memcpy(&ciphertext[cont2],bufOut,written);
        cont2 += written;
    }
    cmeCipherFinal(&ctx,bufOut,&written,'e');
    memcpy(&ciphertext[cont2],bufOut,written);
    cont2 += written;
    printf ("---etSize: %d\n",cont2);

    {
        char *encipheredPath = cmeTestPath("testfiles/enciphered.bin");
        fp=fopen(encipheredPath,"wb");
        if (fp)
        {
            result=fwrite(ciphertext,cont2,1,fp);
            if (result != 1)
            {
                printf("---error writing file '%s'\n",encipheredPath);
            }
            fflush(fp);
            fclose(fp);
        }
        else
        {
            printf("---error opening file '%s' for writing\n",encipheredPath);
        }
        cmeFree(encipheredPath);
    }
    cmeFree(key);                          //Free stuff
    cmeFree(iv);
    cmeFree(ciphertext);
    /**
        Manual Decryption of enciphered.bin using command line openssl works like this (using "Password"):
            gentoo64 ~ # openssl enc -d -p -nosalt -des-ede3-cbc -in enciphered.bin -out deciphered.txt
            enter des-ede3-cbc decryption password:
            key=DC647EB65E6711E155375218212B3964B17C7672C64FEF03
            iv =078BE05EDFE25CD0
    **/

    cmeCipherByteString(cleartext,&ciphertext,&salt,strlen((char *)cleartext),&written,cmeDefaultEncAlg, "Password", 'e');
    printf("Generated salt: %s \n",salt);
    //cmeFree(salt);
    cmeCipherByteString(ciphertext,&deciphertext,&salt,written,&written,cmeDefaultEncAlg, "Password", 'd');
    printf("Decrypted text: %s  \n",deciphertext);
    cmeFree (salt);
    cmeFree (ciphertext);
    cmeFree (deciphertext);
    cmeProtectByteString((const char*)cleartext,(char **)&ciphertext,cmeDefaultEncAlg,(char **)&salt,"Password",&written,strlen((char *)cleartext));
    cmeUnprotectByteString((const char *)ciphertext,(char **)&deciphertext,cmeDefaultEncAlg,(char **)&salt,"Password",&written,written);
    printf("Unprotected text: %s  \n",deciphertext);
    cmeFree (salt);
    cmeFree (ciphertext);
    cmeFree (deciphertext);
}

void testCryptoSymmetricGCM()
{
    const unsigned char cleartext[] = "This is cleartext for GCM.";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    unsigned char tag[16];
    unsigned char key[32];
    unsigned char iv[12];
    unsigned char combo[144];
    unsigned char *b64=NULL;
    unsigned char *decoded=NULL;
    int enc_len, dec_len, written, combo_len;

    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    enc_len = aes_gcm_encrypt(cleartext, strlen((const char *)cleartext),
                              NULL, 0, key, iv, sizeof(iv),
                              ciphertext, tag);
    printf("GCM ciphertext size: %d\n", enc_len);

    memcpy(combo, ciphertext, enc_len);
    memcpy(combo + enc_len, tag, sizeof(tag));
    combo_len = enc_len + sizeof(tag);
    cmeStrToB64(combo, &b64, combo_len, &written);
    printf("GCM B64: %s\n", b64);

    cmeB64ToStr(b64, &decoded, written, &written);
    combo_len = written;
    memcpy(ciphertext, decoded, combo_len - sizeof(tag));
    memcpy(tag, decoded + combo_len - sizeof(tag), sizeof(tag));
    enc_len = combo_len - sizeof(tag);
    cmeFree(b64);
    cmeFree(decoded);

    dec_len = aes_gcm_decrypt(ciphertext, enc_len, NULL, 0, tag,
                              key, iv, sizeof(iv), decrypted);
    decrypted[dec_len] = '\0';
    printf("GCM decrypted text: %s\n", decrypted);
}

void testCryptoSymmetricGCM_ByteString()
{
    const unsigned char cleartext[] = "This is cleartext for GCM via cmeCipherByteString.";
    unsigned char *ciphertext = NULL;
    unsigned char *deciphertext = NULL;
    unsigned char *salt = NULL;
    int written = 0;
    int result;

    result = cmeCipherByteString(cleartext, &ciphertext, &salt,
                                 strlen((const char *)cleartext), &written,
                                 "aes-256-gcm", "Password", 'e');
    if (result || !ciphertext)
    {
        printf("TESTS: testCryptoSymmetricGCM_ByteString(), cmeCipherByteString() encrypt failed! result=%d\n", result);
        cmeFree(salt);
        return;
    }
    printf("TESTS: testCryptoSymmetricGCM_ByteString(), encrypted %d bytes (incl. 16-byte tag). salt: %s\n",
           written, salt);

    result = cmeCipherByteString(ciphertext, &deciphertext, &salt,
                                 written, &written,
                                 "aes-256-gcm", "Password", 'd');
    if (result || !deciphertext)
    {
        printf("TESTS: testCryptoSymmetricGCM_ByteString(), cmeCipherByteString() decrypt failed! result=%d\n", result);
    }
    else
    {
        printf("TESTS: testCryptoSymmetricGCM_ByteString(), decrypted: %s\n", deciphertext);
        if (strcmp((const char *)deciphertext, (const char *)cleartext) == 0)
            printf("TESTS: testCryptoSymmetricGCM_ByteString(), PASS: plaintext matches.\n");
        else
            printf("TESTS: testCryptoSymmetricGCM_ByteString(), FAIL: plaintext mismatch!\n");
    }
    cmeFree(salt);
    cmeFree(ciphertext);
    cmeFree(deciphertext);
}

void testCryptoDigest_Str(unsigned char *bufIn)
{
    int cont,cont2,cont3,written,ctSize;
    unsigned char *digest_bytes=NULL;
    unsigned char *digest_str=NULL;
    EVP_MD_CTX *ctx2=NULL;
    EVP_MD *digest=NULL;
    const unsigned char cleartext[] = "This is cleartext This is cleartext This is cleartext This is cleartext.\n";
    const unsigned char b64str[] =  "UmVtYXJrcw0KVGhlIGNsZWFyZXJyIGZ1bmN0aW9uIHJlc2V0cyB0aGUgZXJyb3Ig\n"
                                    "aW5kaWNhdG9yIGFuZCBlbmQtb2YtZmlsZSBpbmRpY2F0b3IgZm9yIHN0cmVhbS4g\n"
                                    "RXJyb3IgaW5kaWNhdG9ycyBhcmUgbm90IGF1dG9tYXRpY2FsbHkgY2xlYXJlZDsg\n"
                                    "b25jZSB0aGUgZXJyb3IgaW5kaWNhdG9yIGZvciBhIHNwZWNpZmllZCBzdHJlYW0g\n"
                                    "aXMgc2V0LCBvcGVyYXRpb25zIG9uIHRoYXQgc3RyZWFtIGNvbnRpbnVlIHRvIHJl\n"
                                    "dHVybiBhbiBlcnJvciB2YWx1ZSB1bnRpbCBjbGVhcmVyciwgZnNlZWssIGZzZXRw\n"
                                    "b3MsIG9yIHJld2luZCBpcyBjYWxsZWQuDQoNCklmIHN0cmVhbSBpcyBOVUxMLCB0\n"
                                    "aGUgaW52YWxpZCBwYXJhbWV0ZXIgDQoNCg0KDQo=\n";
    const char algorithm2[] = cmeDefaultHshAlg;
    char *resultStr=NULL;
    unsigned char *bufOut=NULL;

    digest_bytes=(unsigned char *)malloc(EVP_MAX_MD_SIZE);
    cmeGetDigest(&digest,algorithm2);
    cmeDigestInit(&ctx2,NULL,digest);
    cont2=0;
    ctSize=strlen((char *)cleartext);
    printf ("--- HASH parameters - algorithm: %s\n",cmeDefaultHshAlg);
    printf ("--- HASH cleartext Size: %d\n",ctSize);
    for (cont=0; cont<(ctSize/evpBufferSize); cont++)
    {
        memcpy(bufIn,&cleartext[cont2],evpBufferSize);
        cmeDigestUpdate(ctx2,bufIn,evpBufferSize);
        cont2 += evpBufferSize;
    }
    if (ctSize % evpBufferSize)
    {
        memcpy(bufIn,&cleartext[cont2],ctSize % evpBufferSize);
        cmeDigestUpdate(ctx2,bufIn,ctSize % evpBufferSize);
        cont2 += (ctSize % evpBufferSize);
    }
    cmeDigestFinal(&ctx2,digest_bytes,(unsigned int *)&written);
    cont3 = written;
    printf ("--- HASH digest Size (bytes): %d\n",cont3);

    cmeBytesToHexstr(digest_bytes,&digest_str,cont3);
    printf ("HASH digest: \n%s\n",digest_str);

    cmeFree(digest_str); //Now we repeat the process with the integrated function in 1 step
    cmeDigestByteString(cleartext,&digest_str,strlen((const char *)cleartext),&written,algorithm2);
    printf ("--- HASH digest Size (chars) with integrated function: %d\n",written);
    printf ("HASH digest with integrated function: \n%s\n",digest_str);

    memset(bufIn,0,evpBufferSize);
    memcpy(bufIn,digest_bytes,cont3);
    cmeStrToB64(bufIn,&bufOut,cont3,&written);
    printf ("StrToB64:\n%s\n",bufOut);

    cont3=strlen((char *)cleartext);
    memset(bufIn,0,evpBufferSize);
    memcpy(bufIn,cleartext,strlen((char *)cleartext));
    cmeFree(bufOut);
    cmeStrToB64(bufIn,&bufOut,cont3,&written);
    printf ("StrToB64:\n%s\n",bufOut);

    cont3=strlen((char *)bufOut);
    memset(bufIn,0,evpBufferSize);
    memcpy(bufIn,bufOut,strlen((char *)bufOut));
    cmeFree(bufOut);
    cmeB64ToStr(bufIn,&bufOut,cont3,&written);
    printf ("B64ToStr:\n%s\n",bufOut);

    cont3=strlen((char *)b64str);
    memset(bufIn,0,evpBufferSize);
    memcpy(bufIn,b64str,strlen((char *)b64str));
    cmeFree(bufOut);
    cmeB64ToStr(bufIn,&bufOut,cont3,&written);
    printf ("B64ToStr:\n%s\n",bufOut);

    cont3=strlen((char *)bufOut);
    memset(bufIn,0,evpBufferSize);
    memcpy(bufIn,bufOut,strlen((char *)bufOut));
    cmeFree(bufOut);
    cmeStrToB64(bufIn,&bufOut,cont3,&written);
    printf ("StrToB64:\n%s\n",bufOut);

    cont3=strlen((char *)bufOut);
    memset(bufIn,0,evpBufferSize);
    memcpy(bufIn,bufOut,strlen((char *)bufOut));
    cmeFree(bufOut);
    cmeB64ToStr(bufIn,&bufOut,cont3,&written);
    printf ("B64ToStr:\n%s\n",bufOut);

    cmeStrConstrAppend (&resultStr, "Hello %d",2);
    cmeStrConstrAppend (&resultStr, " World!\n %s\n","Goodbye World");
    printf("cmeStrConstrAppend () test: %s",resultStr);
    cmeFree (resultStr);

    cmeFree(bufOut);
    cmeFree(digest_bytes);
    cmeFree(digest_str);
}

void testCryptoHMAC ()
{
    int cont,cont2,written,ctSize;
    int localBuferSize=10;                  //Set local buffer size smaller than cleartext length to test HMAC iteration.
    unsigned char localBuffer[10];
    unsigned char *HMACBytes=NULL;
    unsigned char *HMACStr=NULL;
    CME_HMAC_CTX *ctx=NULL;
    EVP_MD *digest=NULL;
    const unsigned char cleartext[] = "This is cleartext This is cleartext This is cleartext This is cleartext.\n";
    const char dgstAlg[] = cmeDefaultMACAlg;
    const char key[] = "HMAC test key";
    const char *salt = "C02002FD232CCA6809840668C26DB385";

    HMACBytes=(unsigned char *)malloc(EVP_MAX_MD_SIZE);
    if (cmeGetDigest(&digest,dgstAlg))
    {
        printf ("TESTS: testCryptoHMAC (), Error in cmeGetDigest() with default MAC algorithm %s!\n",cmeDefaultMACAlg);
        return;
    }
    cmeHMACInit(&ctx,NULL,digest,key,strlen(key));
    cont2=0;
    ctSize=strlen((char *)cleartext);
    printf ("--- HMAC parameters - algorithm: %s, user key: %s\n",cmeDefaultMACAlg,key);
    printf ("--- HMAC Cleartext Size: %d\n",ctSize);
    for (cont=0; cont<(ctSize/localBuferSize); cont++)
    {
        memcpy(localBuffer,&cleartext[cont2],localBuferSize);
        cmeHMACUpdate(ctx,localBuffer,localBuferSize);
        cont2 += localBuferSize;
    }
    if (ctSize % localBuferSize)
    {
        memcpy(localBuffer,&cleartext[cont2],ctSize % localBuferSize);
        cmeHMACUpdate(ctx,localBuffer,ctSize % localBuferSize);
        cont2 += (ctSize % localBuferSize);
    }
    cmeHMACFinal(&ctx,HMACBytes,(unsigned int *)&written);
    printf ("--- HMAC MAC Size (bytes): %d\n",written);

    cmeBytesToHexstr(HMACBytes,&HMACStr,written);
    printf ("HMAC MAC: %s\n",HMACStr);

    printf ("--- HMAC parameters - algorithm: %s, password (PBKDF): %s, salt (PBKDF): %s\n",cmeDefaultMACAlg,key,salt);
    cmeFree(HMACStr); //Now we repeat the process with the integrated function in 1 step
    cmeHMACByteString(cleartext,&HMACStr,strlen((const char *)cleartext),&written,dgstAlg,(char **)&salt,key);
    printf ("--- HMAC MAC Size (chars) with integrated function: %d\n",written);
    printf ("HMAC MAC with integrated function (derives key from PBKDF): %s\n",HMACStr);

    cmeFree(HMACBytes);
    cmeFree(HMACStr);
}

void testPerl (PerlInterpreter *myPerl)
{
    int result __attribute__((unused))=0;
    int cont=0;
    char *ilist[2];
    char *rlist[2];
    char *testScriptPath=NULL;
    char ilist_1[]="This is string 1.\n";
    char ilist_2[]="This is string 2.\n";

    cmePerlParserInstruction ("print \"this is a single line instruction test\\n\";",myPerl);
    cmePerlParserRun(myPerl);

    testScriptPath=cmeTestPath("testfiles/test.pl");
    ilist[0]="cdse";
    ilist[1]=testScriptPath;
    result=cmePerlParserCmdLineInit(2,ilist,myPerl);    //initialize Parser and script's global variables
    ilist[0]=ilist_1;
    ilist[1]=ilist_2;
    result=cmePerlParserScriptFunction("function",myPerl,ilist,2,rlist,2,&cont);
    printf ("perl function result 1: %s",rlist[0]);
    printf ("perl function result 2: %s",rlist[1]);
    ilist[0]=ilist_1;
    ilist[1]=ilist_2;
    result=cmePerlParserScriptFunction("iterate",myPerl,ilist,2,rlist,2,&cont);
    printf ("perl function result 1: %s",rlist[0]);
    printf ("perl function result 2: %s",rlist[1]);


    ilist[0]="cdse";
    ilist[1]=testScriptPath;
    result=cmePerlParserCmdLineInit(2,ilist,myPerl);    //initialize Parser and script's global variables
    ilist[0]=ilist_1;
    ilist[1]=ilist_2;
    result=cmePerlParserScriptFunction("iterate",myPerl,ilist,2,rlist,2,&cont);
    printf ("perl function result 1: %s",rlist[0]);
    printf ("perl function result 2: %s",rlist[1]);
    cmeFree(testScriptPath);
}

void testDB (PerlInterpreter* myPerl)
{
    int cont,cont2,result __attribute__((unused));
    char *ilist[2];
    char *testScriptPath=NULL;
    int numRows=0;
    int numColumns=0;
    sqlite3 *DB;
    char **pQueryResult;        //Important: do not declare it as char ***

    cmeDBCreateOpen (":memory:",&DB);       //Create memory DB
    cmeSQLRows(DB,"BEGIN TRANSACTION; CREATE TABLE table1 (key INTEGER PRIMARY KEY,"
               "nombre TEXT, apellido TEXT, salario FLOAT);"
               "INSERT INTO table1 (nombre,apellido,salario) VALUES('Enrique','Sorcia',10011);"
               "INSERT INTO table1 (nombre,apellido,salario) VALUES('Omar','Herrera',6500.90);"
               "INSERT INTO table1 (nombre,apellido,salario) VALUES('Antonio','Lugo',12100.50);"
               "INSERT INTO table1 (nombre,apellido,salario) VALUES('Dante','Ferrini',10014);"
               "INSERT INTO table1 (nombre,apellido,salario) VALUES('Joaquín','González',7800);"
               "COMMIT;",NULL,NULL); //Create a table

    cmeMemTable(DB,"SELECT * FROM table1;",&pQueryResult,&numRows,&numColumns);
    for (cont=0;cont<=numRows;cont++)
    {
        for (cont2=0;cont2<numColumns;cont2++)
        {
            printf("[%s]",pQueryResult[(cont*numColumns)+cont2]);
        }
        printf("\n");
    }
    cmeMemTableFinal(pQueryResult);
    cmeDBClose(DB);

    testScriptPath=cmeTestPath("testfiles/test.pl");
    ilist[0]="cdse";
    ilist[1]=testScriptPath;
    result=cmePerlParserCmdLineInit(2,ilist,myPerl);    //initialize Parser and script's global variables
    cmeDBCreateOpen (":memory:",&DB);       //Create memory DB
    cmeSQLRows(DB,"BEGIN TRANSACTION; CREATE TABLE table1 (key INTEGER PRIMARY KEY,"
               "nombre TEXT, apellido TEXT, salario FLOAT);"
               "INSERT INTO table1 (nombre,apellido,salario) VALUES('Enrique','Sorcia',10011);"
               "INSERT INTO table1 (nombre,apellido,salario) VALUES('Omar','Herrera',6500.90);"
               "INSERT INTO table1 (nombre,apellido,salario) VALUES('Antonio','Lugo',12100.50);"
               "INSERT INTO table1 (nombre,apellido,salario) VALUES('Dante','Ferrini',10014);"
               "INSERT INTO table1 (nombre,apellido,salario) VALUES('Joaquín','González',7800);"
               "COMMIT;","iterate",myPerl); //Create a table
               //Callback function is called only when results are available, so the
               //above is also safe. Otherwise use:
               //"COMMIT;",NULL,NULL,&pErrmsg); //Create a table

    cmeResultMemTableClean();
    cmeSQLRows(DB,"BEGIN TRANSACTION; SELECT * FROM table1 WHERE salario > 10000;"
               " COMMIT;","iterate",myPerl); //Select
    cmeResultMemTableClean();
    cmeDBClose(DB);
    cmeFree(testScriptPath);
}

void testCSV ()
{
    int cont, cont2, result __attribute__((unused));
    int numCols=0;
    int numRows=0;
    int processedRows=0;
    char *fName=NULL;
    char *fName2=NULL;
    char *resourcesDBPath=NULL;
    char **elements=NULL;
    char **pQueryResult=NULL;
    char **pQueryResult2=NULL;
    const char *attributes[]={"shuffle","protect"};
    const char *attributesData[]={cmeDefaultEncAlg,cmeDefaultEncAlg};
    const char *attributesMAC[]={"protect","MAC","MACProtected"};
    const char *attributesMACData[]={cmeDefaultEncAlg,cmeDefaultMACAlg,cmeDefaultMACAlg};
    sqlite3 *resultDB=NULL;
    sqlite3 *pResourcesDB=NULL;

    fName=cmeTestPath("testfiles/CSVtest.csv");
    fName2=cmeTestPath("testfiles/CSVtest2.csv");
    resourcesDBPath=cmeTestPath(cmeDefaultResourcesDBName);

    result=cmeCSVFileRowsToMemTable (fName, &elements, &numCols, &processedRows, 0, 6, 10);
    for (cont2=0; cont2<=processedRows; cont2++)
    {
        for (cont=0; cont<numCols; cont++)
        {
            printf ("%s",elements[cont+(cont2*numCols)]);
            if (cont<numCols-1)
            {
                printf(",");
            }
        }
        printf("\n");
    }
    cmeCSVFileRowsToMemTableFinal (&elements, numCols, processedRows);
    printf("\n");

    result=cmeCSVFileRowsToMemTable (fName2, &elements, &numCols, &processedRows, 1, 0, 10);
    for (cont2=0; cont2<=processedRows; cont2++)
    {
        for (cont=0; cont<numCols; cont++)
        {
            printf ("%s",elements[cont+(cont2*numCols)]);
            if (cont<numCols-1)
            {
                printf(",");
            }
        }
        printf("\n");
    }
    cmeCSVFileRowsToMemTableFinal (&elements, numCols, processedRows);
    result=cmeCSVFileToSecureDB(fName,1,&numCols,&processedRows,"User123","CaumeDSE",
                          "password1",attributes, attributesData,2,0,"Payroll Database; Confidential.",
                          "file.csv", "AcmeIncPayroll.csv", "storage1",cmeDefaultFilePath);
    result=cmeCSVFileToSecureDB(fName2,1,&numCols,&processedRows,"User123","CaumeDSE",
                          "password2",attributes, attributesData,2,1,"Payroll Database 2; Tests.",
                          "file.csv", "AcmeIncPayroll Tests.csv","storage2",cmeDefaultFilePath);
    result=cmeCSVFileToSecureDB(fName,1,&numCols,&processedRows,"User123","CaumeDSE",
                          "password1",attributes, attributesData,2,1,"Payroll Database; Confidential.",
                          "file.csv", "AcmeIncPayroll.csv","storage1",cmeDefaultFilePath);
    if (cmeDBOpen(resourcesDBPath,&pResourcesDB)) //Error
    {
        cmeFree(fName);
        cmeFree(fName2);
        cmeFree(resourcesDBPath);
        return;
    }
    cmeSecureDBToMemDB (&resultDB, pResourcesDB,"AcmeIncPayroll.csv","password1",cmeDefaultFilePath);
    printf("--- Retrieved data from secure table (CSV file to secure DB):\n");
    result=cmeMemTable(resultDB,"SELECT * FROM data;",&pQueryResult,&numRows,&numCols);
    if (result==0 && pQueryResult)
    {
        for (cont=0;cont<=numRows;cont++)
        {
            for (cont2=0;cont2<numCols;cont2++)
            {
                printf("[%s]",pQueryResult[(cont*numCols)+cont2]);
            }
            printf("\n");
        }
    }
    else
    {
        fprintf(stderr,"CaumeDSE Error: testCSV(), cmeMemTable() failed. Skipping table to secure DB conversion.\n");
        cmeFree(fName);
        cmeFree(fName2);
        cmeFree(resourcesDBPath);
        return;
    }
    result=cmeMemTableToSecureDB((const char **)pQueryResult,numCols,numRows,"User123","CaumeDSE",
                                 "password2",attributes, attributesData,2,1,"Payroll Database 2; Tests.",
                                 "file.csv", "AcmeIncPayroll Tests.csv","storage2",cmeDefaultFilePath);
    cmeSecureDBToMemDB (&resultDB, pResourcesDB,"AcmeIncPayroll Tests.csv","password2",cmeDefaultFilePath);
    printf("--- Retrieved data from secure table (Memory Table to secure DB):\n");
    result=cmeMemTable(resultDB,"SELECT * FROM data;",&pQueryResult2,&numRows,&numCols);
    if (result==0 && pQueryResult2)
    {
        for (cont=0;cont<=numRows;cont++)
        {
            for (cont2=0;cont2<numCols;cont2++)
            {
                printf("[%s]",pQueryResult2[(cont*numCols)+cont2]);
            }
            printf("\n");
        }
    }
    else
    {
        fprintf(stderr,"CaumeDSE Error: testCSV(), cmeMemTable() failed when reading secure DB.\n");
        cmeMemTableFinal(pQueryResult);
        cmeDBClose(resultDB);
        cmeDBClose(pResourcesDB);
        cmeFree(fName);
        cmeFree(fName2);
        cmeFree(resourcesDBPath);
        return;
    }
    cmeMemTableFinal(pQueryResult);
    cmeMemTableFinal(pQueryResult2);
    cmeDBClose(resultDB);
    resultDB=NULL;
    //result=cmeDeleteSecureDB(pResourcesDB,"AcmeIncPayroll Tests.csv", "password2",cmeDefaultFilePath);

    // Test "protect","MAC","MACProtected" column attributes: protect data, compute plaintext MAC
    // and post-encryption MACProtected, then verify integrity on retrieval.
    printf("\n--- Testing MAC and MACProtected column attributes:\n");
    result=cmeCSVFileToSecureDB(fName,1,&numCols,&processedRows,"User123","CaumeDSE",
                                "password3",attributesMAC,attributesMACData,3,1,
                                "Payroll Database MAC Test.",
                                "file.csv","AcmeIncPayrollMAC.csv","storage3",cmeDefaultFilePath);
    if (result)
    {
        fprintf(stderr,"CaumeDSE Error: testCSV() MAC test, cmeCSVFileToSecureDB() failed (result=%d)!\n",result);
    }
    else
    {
        cmeSecureDBToMemDB(&resultDB,pResourcesDB,"AcmeIncPayrollMAC.csv","password3",cmeDefaultFilePath);
        printf("--- Retrieved data from secure table (MAC+MACProtected test):\n");
        result=cmeMemTable(resultDB,"SELECT * FROM data;",&pQueryResult,&numRows,&numCols);
        if (result==0 && pQueryResult)
        {
            for (cont=0;cont<=numRows;cont++)
            {
                for (cont2=0;cont2<numCols;cont2++)
                {
                    printf("[%s]",pQueryResult[(cont*numCols)+cont2]);
                }
                printf("\n");
            }
            cmeMemTableFinal(pQueryResult);
            pQueryResult=NULL;
        }
        else
        {
            fprintf(stderr,"CaumeDSE Error: testCSV() MAC test, cmeMemTable() failed!\n");
        }
        cmeDBClose(resultDB);
        resultDB=NULL;
    }

    cmeDBClose(pResourcesDB);
    cmeFree(fName);
    cmeFree(fName2);
    cmeFree(resourcesDBPath);
}

// ---------------------------------------------------------------------------
// Thread-safety test: verify that cmeDefaultMaxThreads concurrent threads can
// perform independent SQLite operations in parallel without data corruption.
// Each thread creates its own in-memory DB, inserts rows, queries them back,
// and checks the results match.  The test exercises thread-local cmeResultMemTable
// and the SQLITE_OPEN_FULLMUTEX serialisation.
// ---------------------------------------------------------------------------

struct cmeTestThreadArgs
{
    int threadId;   //Input: unique id used to generate distinct values.
    int result;     //Output: 0=success, non-zero=error.
};

static void *cmeTestThreadWorker (void *arg)
{
    struct cmeTestThreadArgs *a=(struct cmeTestThreadArgs *)arg;
    int i,cont,result=0;
    const int numRows=10;
    char sql[256];
    char expected[64];
    sqlite3 *db=NULL;
    char *dbPath=NULL;

    // Each thread uses its own temporary file-based DB with a unique name.
    cmeStrConstrAppend(&dbPath,"%stest_thread_%d.db",cmeDefaultFilePath,a->threadId);
    remove(dbPath); // Ensure no stale data from a previous failed run.

    // Open (create) the per-thread DB.
    if (cmeDBCreateOpen(dbPath,&db))
    {
        fprintf(stderr,"CaumeDSE Thread Test Error: thread %d: cmeDBCreateOpen() failed for '%s'.\n",
                a->threadId,dbPath);
        cmeFree(dbPath);
        a->result=1;
        return NULL;
    }

    // Create a simple table.
    snprintf(sql,sizeof(sql),"CREATE TABLE IF NOT EXISTS ttest (id INTEGER, val TEXT);");
    if (cmeSQLRows(db,sql,NULL,NULL))
    {
        fprintf(stderr,"CaumeDSE Thread Test Error: thread %d: CREATE TABLE failed.\n",a->threadId);
        cmeDBClose(db);
        cmeFree(dbPath);
        a->result=2;
        return NULL;
    }

    // Insert numRows rows with values specific to this thread.
    for (i=0;i<numRows;i++)
    {
        snprintf(sql,sizeof(sql),
                 "BEGIN; INSERT INTO ttest(id,val) VALUES(%d,'thread_%d_row_%d'); COMMIT;",
                 i, a->threadId, i);
        if (cmeSQLRows(db,sql,NULL,NULL))
        {
            fprintf(stderr,"CaumeDSE Thread Test Error: thread %d: INSERT row %d failed.\n",
                    a->threadId,i);
            cmeDBClose(db);
            cmeFree(dbPath);
            a->result=3;
            return NULL;
        }
    }

    // Query back and verify using the thread-local cmeResultMemTable.
    snprintf(sql,sizeof(sql),"SELECT id,val FROM ttest ORDER BY id;");
    if (cmeSQLRows(db,sql,NULL,NULL))
    {
        fprintf(stderr,"CaumeDSE Thread Test Error: thread %d: SELECT failed.\n",a->threadId);
        cmeDBClose(db);
        cmeFree(dbPath);
        a->result=4;
        return NULL;
    }

    // Verify row count.
    if (cmeResultMemTableRows!=numRows)
    {
        fprintf(stderr,"CaumeDSE Thread Test Error: thread %d: expected %d rows, got %d.\n",
                a->threadId,numRows,cmeResultMemTableRows);
        cmeResultMemTableClean();
        cmeDBClose(db);
        cmeFree(dbPath);
        a->result=5;
        return NULL;
    }

    // Spot-check last row value.
    snprintf(expected,sizeof(expected),"thread_%d_row_%d",a->threadId,numRows-1);
    // cmeResultMemTable layout: row 0 = column headers; data starts at row 1.
    // Each row has cmeResultMemTableCols entries.
    cont=(cmeResultMemTableRows)*cmeResultMemTableCols + 1; // last row, second column (val)
    if (!cmeResultMemTable[cont] || strcmp(cmeResultMemTable[cont],expected)!=0)
    {
        fprintf(stderr,"CaumeDSE Thread Test Error: thread %d: last val mismatch: "
                "expected '%s', got '%s'.\n",
                a->threadId, expected,
                cmeResultMemTable[cont] ? cmeResultMemTable[cont] : "(null)");
        result=6;
    }
    cmeResultMemTableClean();
    cmeDBClose(db);

    // Remove the per-thread DB file.
    remove(dbPath);
    cmeFree(dbPath);
    a->result=result;
    return NULL;
}

void testThreadSafety ()
{
    int i,errors=0;
    pthread_t threads[cmeDefaultMaxThreads];
    struct cmeTestThreadArgs args[cmeDefaultMaxThreads];

    printf("--- Testing thread safety: %d concurrent SQLite worker threads ---\n",
           cmeDefaultMaxThreads);

    for (i=0;i<cmeDefaultMaxThreads;i++)
    {
        args[i].threadId=i;
        args[i].result=-1;
        if (pthread_create(&threads[i],NULL,cmeTestThreadWorker,&args[i])!=0)
        {
            fprintf(stderr,"CaumeDSE Thread Test Error: pthread_create() failed for thread %d.\n",i);
            errors++;
        }
    }
    for (i=0;i<cmeDefaultMaxThreads;i++)
    {
        pthread_join(threads[i],NULL);
        if (args[i].result!=0)
        {
            errors++;
        }
    }
    if (errors==0)
        printf("--- Thread safety test: PASSED (%d threads, 0 errors)\n",cmeDefaultMaxThreads);
    else
        printf("--- Thread safety test: FAILED (%d threads, %d errors)\n",cmeDefaultMaxThreads,errors);
}

void testEngMgmnt ()
{
    int result __attribute__((unused));
    result=cmeSetupEngineAdminDBs();
    testThreadSafety();
}

void testWebServices ()
{
    const char *httpEnv = getenv("CDSE_DEBUG_TEST_HTTP_PORT");
    const char *httpsEnv = getenv("CDSE_DEBUG_TEST_HTTPS_PORT");
    int httpPort = cmeDefaultWebservicePort;
    int httpsPort = cmeDefaultWebServiceSSLPort;

    if (cmeDebugTestsNonInteractiveEnabled())
    {
        httpPort = 8080;
        httpsPort = 8443;
    }
    if (httpEnv && *httpEnv)
    {
        httpPort = atoi(httpEnv);
    }
    if (httpsEnv && *httpsEnv)
    {
        httpsPort = atoi(httpsEnv);
    }

    printf("--- Testing Web server HTTP port %d%s (thread pool: %d)\n",httpPort,
           cmeDebugTestsNonInteractiveEnabled() ? " (non-interactive)" : " (press enter to continue)",
           cmeDefaultMaxThreads);
    cmeWebServiceSetup(httpPort,0,NULL,NULL,NULL,0);
    printf("--- Testing Web server HTTPS port %d%s (thread pool: %d)\n",httpsPort,
           cmeDebugTestsNonInteractiveEnabled() ? " (non-interactive)" : " (press enter to continue)",
           cmeDefaultMaxThreads);
    cmeWebServiceSetup(httpsPort,1,cmeDefaultHTTPSKeyFile,cmeDefaultHTTPSCertFile,cmeDefaultCACertFile,0);
}
