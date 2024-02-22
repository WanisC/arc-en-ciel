
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include "../lib/cmathematics/data/hashing/sha3.h"

unsigned char* sha3_256(unsigned char *input, unsigned char *out) {
    void *ctx = NULL;
    ctx = malloc(sizeof(sha3_context));
    sha3_initContext(ctx, 6);
    sha3_update(ctx, input, strlen(input));
    sha3_digest(ctx, &out);
    free(ctx);
    return out;
}

void printHash(unsigned char *hash) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
}

unsigned char* hash_to_string(unsigned char *hash) {
    char *hash_str = malloc(65 * sizeof(char));
    for (int i = 0; i < 32; i++) {
        sprintf(&hash_str[i*2], "%02x", hash[i]);
    }
    return hash_str;
}