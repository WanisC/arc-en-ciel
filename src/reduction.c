#include <stdio.h>
#include <stdlib.h>
#include "hashage.h"

reduction(unsigned char* hash, unsigned char* password) {
    unsigned char hash_bin[256];
    unsigned char hash_6b_packet[42];
    hash_to_bin(hash, hash_bin);
    hash_bin_to_6b_packet(hash_bin, hash_6b_packet);

    for (int i = 0; i < 7; i++) {
        char continuer;
        int j = 0;
        do {
            continuer = 0;
            char c = hash_6b_packet[i*6 + j];
            if (c < 10) {
                c += '0';
            } else if (c < 36) {
                c += 'a' - 10;
            } else if (c < 62) {
                c += 'A' - 36;
            } else {
                continuer = 1;
                j += 1;
                if (j == 6) {
                    c = 'a';    // TODO améliorer ?
                    continuer = 0;
                }
            }
            if (!continuer) {
                password[i] = c;
            }
        } while (continuer);
    }
}

void hash_to_bin(unsigned char* hash, unsigned char* hash_bin)
{
    for (int i = 0; i < 32; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            hash_bin[i * 8 + j] = (hash[i] >> (7-j)) & 1;
        }
    }

}

void hash_bin_to_6b_packet(unsigned char* hash_bin, unsigned char* hash_6b_packet)
{
    for (int i = 0; i < 42; i++)    // on va faire 42 paquets de 6 bits pour avoir 252 bits les 4 derniers bits seront ignorés
    {
        int s = 0;
        for (int j = 0; j < 6; j++) // on regarde 6 bits
        {
            s <<= 1;                    // on décale s de 1 bit vers la gauche
            s += hash_bin[i * 6 + j];   // on ajoute 1 si le bit est à 1
        }
        hash_6b_packet[i] = s;
    }
}