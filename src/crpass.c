
#include "crpass.h"
#include "tiny_aes.h"
#include "server.h"


static const uint8_t * get_interanl_key(){
    static uint8_t key[] = { 
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c 
    };
    return key;
}

static size_t hex_str_to_bytes(const char * str, uint8_t * bytes, size_t bsize)
{
   uint8_t  pos;
   uint8_t  idx0;
   uint8_t  idx1;

   // mapping of ASCII characters to hex values
   static
   const uint8_t hashmap[] =
   {
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
     0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
     0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
     0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // ........
   };

   for (pos = 0; ((pos < (bsize*2)) && (pos < strlen(str))); pos += 2)
   {
      idx0 = (uint8_t)str[pos+0];
      idx1 = (uint8_t)str[pos+1];
      bytes[pos/2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
   };

   return(pos/2);
}


char *crpass_encrypt(const char *s) {

    size_t plain_len;
    size_t crypt_len;
    char * crypt_txt;
    struct AES_ctx ctx;
    uint8_t buf[16];
    size_t plain_remains;
    char * p;
    unsigned char i;

    if(!s || s[0] == '\0'){
        return NULL;
    }

    plain_len = strlen(s);
    crypt_len = plain_len;
    if((crypt_len % 16)){
        crypt_len += (16 - (crypt_len % 16));
    }
    crypt_len = crypt_len * 2;
    crypt_txt = zmalloc(crypt_len+1);

    plain_remains = plain_len;
    p = crypt_txt;
    AES_init_ctx(&ctx, get_interanl_key());
    while( plain_remains > 0 ){
        if(plain_remains < 16){
            memcpy(buf, s, plain_remains);
            memset(buf+plain_remains, 0, 16-plain_remains); // padding
            s += plain_remains;
            plain_remains = 0;
        }else{
            memcpy(buf, s, 16);
            s += 16;
            plain_remains -= 16;
        }

        AES_ECB_encrypt(&ctx, buf);
        
        for (i = 0; i < 16; ++i){
            p += sprintf(p, "%.2x", buf[i]);
        }
        
    } // while
    crypt_txt[crypt_len] = '\0'; 
    return crypt_txt;
}

char *crpass_decrypt(const char *s) {
    size_t crypt_len;
    size_t plain_len;
    char * plain_txt;
    struct AES_ctx ctx;
    uint8_t buf[16];
    size_t crypt_remains;
    char * p;
    size_t elen;

    if(!s || s[0] == '\0'){
        return NULL;
    }

    crypt_len = strlen(s);
    plain_len = crypt_len/2;
    if((plain_len % 16)){
        plain_len += (16 - (plain_len % 16));
    }
    plain_txt = zmalloc(plain_len+1);

    crypt_remains = crypt_len;
    p = plain_txt;
    AES_init_ctx(&ctx, get_interanl_key());
    while( crypt_remains > 0 ){
        elen = hex_str_to_bytes(s, buf, 16);
        s += (elen*2);
        crypt_remains -= (elen*2);
        if(elen < 16){
            memset(buf+elen, 0, 16-elen); // padding
        }

        AES_ECB_decrypt(&ctx, buf);
        memcpy(p, buf, 16);
        p += 16;
    } // while
    plain_txt[plain_len] = '\0'; 
    return plain_txt;
}

int crpass_verification_test(const char *s) {
    char * crypt_txt;
    char * plain_txt;

    if (strlen(s) > (CONFIG_AUTHPASS_MAX_LEN)) {
        printf("Password is longer than CONFIG_AUTHPASS_MAX_LEN\n");
        return 1;
    }

    crypt_txt = crpass_encrypt(s);
    if(crypt_txt){
        plain_txt = crpass_decrypt(crypt_txt);
        printf("[%s] -(encypt)-> [%s] -(decrypt)-> [%s]\n", s, crypt_txt, plain_txt);
        if(!strcmp(s, plain_txt)){
            printf("verification OK\n");
        } else {
            printf("verification failure\n");
        }
        zfree(plain_txt);
        zfree(crypt_txt);
        return 0;
    } else {
        printf("encrypt: empty text");
        return 1;
    }
}

int crpass_encrypt_test(const char *s) {
    char * crypt_txt;

    if (strlen(s) > (CONFIG_AUTHPASS_MAX_LEN)) {
        printf("Password is longer than CONFIG_AUTHPASS_MAX_LEN\n");
        return 1;
    }

    crypt_txt = crpass_encrypt(s);
    if(crypt_txt){
        printf("encrypt: [%s] -> [%s]\n", s, crypt_txt);
        zfree(crypt_txt);
        return 0;
    } else {
        printf("encrypt: empty text");
        return 1;
    }
}

int crpass_decrypt_test(const char *s) {
    char * plain_txt;

    if (strlen(s) > (CONFIG_AUTHPASS_MAX_LEN*2)) {
        printf("Password is longer than CONFIG_AUTHPASS_MAX_LEN*2\n");
        return 1;
    }

    plain_txt = crpass_decrypt(s);
    if(plain_txt){
        printf("decrypt: [%s] -> [%s]\n", s, plain_txt);
        zfree(plain_txt);
        return 0;
    } else {
        printf("decrypt: empty text");
        return 1;
    }
}

