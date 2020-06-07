
#include <stdlib.h>

#include "server.h"
#include "crpass.h"
#include "tiny_aes.h"

#define PBKDF2_SHA256_STATIC
#define PBKDF2_SHA256_IMPLEMENTATION
#include "pbkdf2_sha256.h"



#define MAKE_STR1(x) #x
#define MAKE_STR2(R)  MAKE_STR1(R)

static size_t bytes_to_hex_str(const uint8_t * buf, size_t bsize, char * str){
    size_t i;
    char * p = str;
    for (i = 0; i < bsize; ++i){
        p += sprintf(p, "%.2x", buf[i]);
    }
    p[0] = '\0'; 
    return bsize*2;
}

static size_t bytes_to_hex_str_alloc(const uint8_t * buf, size_t bsize, char ** pstr){
    *pstr = zmalloc(bsize*2+1);
    return bytes_to_hex_str(buf, bsize, *pstr);
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

void print_as_hex(const uint8_t *s,  const uint32_t slen){
	for (uint32_t i = 0; i < slen; i++){
		printf("%02X%s", s[ i ], (i % 4 == 3) && (i != slen - 1) ? "-" : "");
	}
	printf("\n");
}

static int check_pbkdf2_hmac_sha256(const char * name,
                            const void *pw, size_t npw,
                            const void *salt, size_t nsalt,
                            unsigned iterations,
                            const void *expect, size_t nexpect){
	uint8_t * dk = zmalloc(nexpect);
	HMAC_SHA256_CTX pbkdf_hmac;
	pbkdf2_sha256(&pbkdf_hmac, pw, npw, salt, nsalt, iterations, dk, nexpect);
    int ret = memcmp(dk, expect, nexpect);
    if(ret == 0){
        printf("%s: pass\n", name);
    } else {
        printf("%s: fail !!!\n", name);
    }
    zfree(dk);
    return ret;         
}

int test_pbkdf2_hmac_sha256(){
    int ret = 0;
    ret = check_pbkdf2_hmac_sha256(
        "pbkdf2-sha256-test1",
        "passwd", 6,
        "salt", 4,
        1,
        "U\xac\x04\x6e\x56\xe3\x08\x9f\xec\x16\x91\xc2\x25\x44\xb6\x05\xf9\x41\x85\x21\x6d\xde\x04\x65\xe6\x8b\x9d\x57\xc2\x0d\xac\xbc\x49\xca\x9c\xcc\xf1\x79\xb6\x45\x99\x16\x64\xb3\x9d\x77\xef\x31\x7c\x71\xb8\x45\xb1\xe3\x0b\xd5\x09\x11\x20\x41\xd3\xa1\x97\x83", 64
    );

    return ret;
}

static int check_sha256(const char * name,
                        const void *msg, size_t nmsg,
                        const void *expect, size_t nexpect){
    uint8_t md[SHA256_DIGESTLEN];
	SHA256_CTX sha;
	sha256_init(&sha);
	sha256_update(&sha, msg, nmsg);
	sha256_final(&sha, md);

    int ret = 0;
    if(nexpect != SHA256_DIGESTLEN){
        printf("%s: fail, wrong output len!!!\n", name);
    } else {
        ret = memcmp(md, expect, SHA256_DIGESTLEN);
        if(ret == 0){
            printf("%s: pass\n", name);
        } else {
            printf("%s: fail !!!\n", name);
        }
    }


    return ret;         
}

int test_sha256(){
    int ret = 0;
    ret = check_sha256(
        "sha256-test1",
        "password", 8,
        "\x5e\x88\x48\x98\xda\x28\x04\x71\x51\xd0\xe5\x6f\x8d\xc6\x29\x27\x73\x60\x3d\x0d\x6a\xab\xbd\xd6\x2a\x11\xef\x72\x1d\x15\x42\xd8",
        32
    );

    return ret;
}

#ifndef CRPASS_SALT
#define CRPASS_SALT salt
#endif

#ifndef CRPASS_ROUNDS
#define CRPASS_ROUNDS 1000
#endif

const uint8_t * get_internal_salt(size_t * saltlen){
    static const char * s = MAKE_STR2(CRPASS_SALT);
    *saltlen = strlen(s);
    return (const uint8_t *) s;
}

static char *crpass_encrypt_sha256(const char *s) {
    char * output_text;
    uint8_t md[SHA256_DIGESTLEN];
	SHA256_CTX sha;
	sha256_init(&sha);
	sha256_update(&sha, (const uint8_t *)s, strlen(s));
	sha256_final(&sha, md);
    bytes_to_hex_str_alloc(md, SHA256_DIGESTLEN, &output_text);
    return output_text;
}

static char *crpass_encrypt_pbkdf2(const char *s) {

    size_t plain_len;
    size_t crypt_len;
    char * crypt_txt;

    uint8_t buf[64];

    const uint8_t * salt;
    size_t nsalt;
    size_t i;
    char *p;

    if(!s || s[0] == '\0'){
        return NULL;
    }
    
    salt = get_internal_salt(&nsalt);
    plain_len = strlen(s);

	HMAC_SHA256_CTX pbkdf_hmac;
	pbkdf2_sha256(&pbkdf_hmac, (const uint8_t*)s, plain_len, salt, nsalt, CRPASS_ROUNDS, buf, 64);

    crypt_len = 64*2;
    crypt_txt = zmalloc(crypt_len+1);
    p = crypt_txt;
    for (i = 0; i < 64; ++i){
        p += sprintf(p, "%.2x", buf[i]);
    }
    crypt_txt[crypt_len] = '\0'; 
    return crypt_txt;
}

char *crpass_encrypt(const char *s) {
    return crpass_encrypt_pbkdf2(s);
}

int crpass_verify(const char *plain_text, const char * encrypted_text, char ** p_second_text) {

    char * output;
    int ret = 0;

    if(!(*p_second_text)){
        output = crpass_encrypt(plain_text);
        if(strcmp(output, encrypted_text) != 0){
            ret = -1;
        } else {
            *p_second_text = crpass_encrypt_sha256(plain_text);
        }
        
    } else {
        output = crpass_encrypt_sha256(plain_text);
        if(strcmp(output, *p_second_text) != 0){
            ret = -1;
        }
    }

    zfree(output);
    return ret;
}

char *crpass_decrypt(const char *s) {
    (void) s;
    return NULL;
}

int crpass_verification_test(const char *s) {
    int ret = 0;
    uint32_t i;
    char * first_encrypted_text;
    char * second_encrypted_text = NULL;
    first_encrypted_text = crpass_encrypt_pbkdf2(s);
    
    if(ret == 0){
        ret = test_pbkdf2_hmac_sha256();
    }

    if(ret == 0){
        ret = test_sha256();
    }

    i = 0;
    while(ret == 0 && i < 1000){
        ret = crpass_verify(s, first_encrypted_text, &second_encrypted_text);
        ++i;
    }

    zfree(first_encrypted_text);

    printf("crpass_verification_test result : [%s]\n", ret == 0 ? "OK" : "fail !!!");
    return ret;
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
        printf("encrypt: empty text\n");
        return 1;
    }
}

int crpass_decrypt_test(const char *s) {
    (void) s;
    printf("NOT implement crpass_decrypt_test\n");
    return -1;
}


















#ifdef CRPASS_USE_AES
static uint8_t * make_key_from_str(const char * s){
    static uint8_t key[16];

    size_t plain_len;
    size_t plain_remains;
    size_t j;

    memset(key, 0, 16);

    if(!s || s[0] == '\0'){
        s = "it's a secret";
    }

    plain_len = strlen(s);
    plain_remains = plain_len;
    while( plain_remains > 0 ){
        if(plain_remains < 16){
            for(j = 0; j < plain_remains; j++){
                key[j] += s[j];
            }
            s += plain_remains;
            plain_remains = 0;
        }else{
            for(j = 0; j < 16; j++){
                key[j] += s[j];
            }
            s += 16;
            plain_remains -= 16;
        }
    } // while

    return key;
}

static const uint8_t * get_interanl_key(){
    // static uint8_t key[] = { 
    //     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    //     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c 
    // };
    // return key;

    static uint8_t * key = NULL;
    if(!key){
        key = make_key_from_str(MAKE_STR2(CRPASS_KEY));
    }
    return key;
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
        printf("encrypt: empty text\n");
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
        printf("encrypt: empty text\n");
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
        printf("decrypt: empty text\n");
        return 1;
    }
}
#endif //#ifdef CRPASS_USE_AES
