
#include <stdio.h>
#include <strings.h>
#include "crpass.h"


static void print_usage(const char * argv0){
    printf("%s --encrypt [plain-password]\n", argv0);
    printf("%s --test [plain-password]\n", argv0);
}

int main(int argc, char **argv) {

    if(argc != 3){
        print_usage(argv[0]);
        return 1;
    }

    if (!strcasecmp(argv[1],"--test")) {
        return (crpass_verification_test(argv[2]));

    } else if (!strcasecmp(argv[1],"--encrypt")) {
        return (crpass_encrypt_test(argv[2]));

    } else {
        printf("error: unknown opt [%s]\n\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
