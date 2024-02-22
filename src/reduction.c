#include <stdio.h>
#include <stdlib.h>
#include "hashage.h"

void reduction(unsigned char* hash, unsigned char* password) {
    for (int i = 0; i < 42; i++) {
        unsigned char packet = 0;
        for (int j = 0; j < 6; j++) {
            packet <<= 1;
            packet += ((hash[(i * 6 + j) / 8] >> (7 - ((i * 6 + j) % 8))) & 1);
        }

        if (packet < 62) {
            password[i / 6] = packet < 10 ? packet + '0' : packet < 36 ? packet + 87 : packet + 29;
            i += 5 - (i % 6);
        } else if (i % 6 == 5) {
            password[i / 6] = packet + 10;
        }
    }
}