
#ifndef __CRPASS_H
#define __CRPASS_H

char *crpass_encrypt(const char *s);
char *crpass_decrypt(const char *s);
int crpass_verify(const char *plain_text, const char * encrypted_text, char ** p_second_text);

int crpass_verification_test(const char *s);
int crpass_encrypt_test(const char *s);
int crpass_decrypt_test(const char *s);

int test_pbkdf2_hmac_sha256();
int test_sha256();

#endif /*__CRPASS_H*/
