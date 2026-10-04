#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "herradura_compat.h"

int main(void)
{
    BitArray key=BA_INIT;
    BitArray nonce=BA_INIT;
    uint8_t plaintext[97], ciphertext[97], decrypted[97], tag[32];
    const uint8_t aad[]="cdse-independent-hkx-test-aad-v1";
#ifdef CDSE_PROBE_LEGACY_DUPLEX
    const uint8_t expectedTag[32]={
        0x7d,0x8d,0x43,0x5a,0x21,0xc9,0xea,0xd0,0xac,0x6f,0x63,0x27,0x26,0x49,0x54,0x54,
        0x4e,0xab,0x75,0x60,0xab,0xb6,0x18,0x25,0xa5,0x69,0x32,0xdd,0x5d,0x15,0xee,0x6a
    };
#else
    const uint8_t expectedTag[32]={
        0x6e,0x80,0x58,0xb3,0x8d,0xb2,0xad,0x25,0x68,0x5c,0xfe,0x3f,0xbf,0xcc,0x9d,0xa9,
        0xf4,0x04,0xc3,0x65,0x70,0xd4,0x77,0xac,0x8f,0xb1,0x7c,0x16,0x2d,0x1c,0x72,0x90
    };
#endif
    size_t i;
    for (i=0;i<32;i++)
    {
        key.b[i]=(uint8_t)(0x10+i*3);
        nonce.b[i]=(uint8_t)(0xa0-i*5);
    }
    for (i=0;i<sizeof(plaintext);i++) plaintext[i]=(uint8_t)((i*7+3)&0xff);
#ifdef CDSE_PROBE_LEGACY_DUPLEX
    hske_nl_v2_duplex_encrypt(&key,&nonce,aad,sizeof(aad)-1,plaintext,sizeof(plaintext),ciphertext,tag);
    if (memcmp(tag,expectedTag,sizeof(tag))) return 1;
    if (!hske_nl_v2_duplex_decrypt(&key,&nonce,aad,sizeof(aad)-1,ciphertext,sizeof(ciphertext),tag,decrypted)) return 1;
#else
    hske_nl_aead_encrypt(&key,&nonce,aad,sizeof(aad)-1,plaintext,sizeof(plaintext),ciphertext,tag);
    if (memcmp(tag,expectedTag,sizeof(tag))) return 1;
    if (!hske_nl_aead_decrypt(&key,&nonce,aad,sizeof(aad)-1,ciphertext,sizeof(ciphertext),tag,decrypted)) return 1;
#endif
    return memcmp(plaintext,decrypted,sizeof(plaintext))!=0;
}
