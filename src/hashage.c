#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

void SHA256(char *mdp, unsigned char *hash) {
	// Initialisation de la librairie	
	if (sodium_init() == -1) {
		printf("Erreur lors de l'initialisation de libsodium\n");
		exit(1);
	}

	crypto_hash_sha256(hash, (const unsigned char *)mdp, strlen(mdp));
}
