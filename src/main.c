#include "main.h"
#include "hashage.h"
#include "reduction.h"
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    // Open file for writing reduced passwords
    
    FILE *fptr;
    fptr = fopen("rsc/test.txt", "w");
    if (fptr == NULL) {
        printf("Error!");
        exit(1);
    }
    void *ctx = NULL;
    init_sha3(&ctx); // Initialize sha3 context (6 = sha3-256)

    unsigned char password[8] = "0000000";
    for (int i = 0; i < 100; i++) {
        generate(ctx, password, fptr);
        int j = 6;
        while (1) {
            if (password[j] == '9') {
                password[j] = 'a';
                j--;
            } else if (password[j] == 'z') {
                password[j] = 'A';
            } else {
                password[j]++;
                break;
            }
        }
    }

    free(ctx);
    fclose(fptr);

    return 0;
}

void generate(void *ctx, unsigned char *password, FILE *fptr) {
    unsigned char out[8] = "";
    unsigned char *hash;

    fprintf(fptr, "%s\n", password);

    for (int i = 0; i < 10; i++) {
        sha3_256(ctx, password, &hash);
        reduction(hash, out);
        password = out;
        fprintf(fptr, "%s\n", password);
    }
    fprintf(fptr, "\n");
}