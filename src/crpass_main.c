
#include <stdio.h>
#include <strings.h>
#include "crpass.h"

// #define MAKE_STR1(x) #x
// #define MAKE_STR2(R)  MAKE_STR1(R)

static void print_usage(const char * argv0){
    printf("%s --test [plain-password]\n", argv0);
    printf("%s --encrypt [plain-password]\n", argv0);
    printf("%s --decrypt [encrypted-password]\n", argv0);
}

int main(int argc, char **argv) {

    // const char * key = MAKE_STR2(CRPASS_KEY);
    // printf("key=[%s]\n", key);

    if(argc != 3){
        print_usage(argv[0]);
        return 1;
    }

    if (!strcasecmp(argv[1],"--test")) {
        return (crpass_verification_test(argv[2]));

    } else if (!strcasecmp(argv[1],"--encrypt")) {
        return (crpass_encrypt_test(argv[2]));

    } else if (!strcasecmp(argv[1],"--decrypt")) {
        return (crpass_decrypt_test(argv[2]));

    } else {
        printf("error: unknown opt [%s]\n\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
