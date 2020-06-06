
#ifndef __CRPASS_H
#define __CRPASS_H

char *crpass_encrypt(const char *s);
char *crpass_decrypt(const char *s);

int crpass_verification_test(const char *s);
int crpass_encrypt_test(const char *s);
int crpass_decrypt_test(const char *s);

#endif /*__CRPASS_H*/
