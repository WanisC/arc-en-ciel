
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include "../lib/cmathematics/data/hashing/sha3.h"

void init_sha3(void **ctx) {
    *ctx = malloc(sizeof(sha3_context));
    sha3_initContext(*ctx, 6);
}

void sha3_256(void *ctx, unsigned char *input, unsigned char **out) {
    // TODO : check ctx
    ctx = malloc(sizeof(sha3_context));
    init_sha3(&ctx);
    sha3_update(ctx, input, 7);
    sha3_digest(ctx, out);
}

void printHash(unsigned char *hash) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void printHash_bin(unsigned char *hash_bin) {
    for (int i = 0; i < 256; i++) {
        printf("%d", hash_bin[i]);
    }
    printf("\n");
}

unsigned char* hash_to_string(unsigned char *hash) {
    char *hash_str = malloc(65 * sizeof(char));
    for (int i = 0; i < 32; i++) {
        sprintf(&hash_str[i*2], "%02x", hash[i]);
    }
    printf("\n");
    return hash_str;
}