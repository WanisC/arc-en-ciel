#include "main.h"
#include "hashage.h"
#include "reduction.h"
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    // FILE *fptr;
    // fptr = fopen("rsc/rockyou_7.txt", "r");
    // if (fptr == NULL) {
    //     printf("Error!");
    //     exit(1);
    // }

    // FILE *fptr2;
    // fptr2 = fopen("rsc/rockyou_7_hashed.txt", "w");
    // if (fptr2 == NULL) {
    //     printf("Error!");
    //     exit(1);
    // }

    // unsigned char *line = malloc(9 * sizeof(unsigned char));
    // while (1) {
    //     if (fgets(line, 9, fptr) == NULL) {
    //         break;
    //     }
    //     line[7] = '\0';

    //     generate(line, fptr2);
    // }
    // fclose(fptr);
    // fclose(fptr2);

    test();
    return 0;
}

unsigned char* H_R(unsigned char *password, int offset) {
    unsigned char *hash = NULL;
    hash = sha3_256(password, hash);
    unsigned char *result = reduction(hash, offset);
    free(hash);
    return result;
}

void generate(unsigned char *password, FILE *fptr) {
    char * first_password = malloc(9 * sizeof(char));
    strcpy(first_password, password);

    for (int i = 0; i < 99; i++) {
        password = H_R(password, i);
    }
    unsigned char *hash = NULL;
    hash = sha3_256(password, hash);
    char* hash_str = hash_to_string(hash);

    fprintf(fptr, "%s-%s\n", first_password, hash_str);
}