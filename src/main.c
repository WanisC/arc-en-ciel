/* Cryptologie: Cassage de mots de passe via les tables arc-en-ciel

	Auteurs: 
		Mathis ALLOUCHE
		Basile LAURIOLA
		Antoine RIOS CAMPO
		Wanis CHOUAIB
	
	Année: 2023/2024

	Tutrice: Christina Boura

	Université: UVSQ, Versailles
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sodium.h>
#include "hashage.h"
#include "reduction.h"

#define HASH_SIZE crypto_hash_sha256_BYTES

int main(void) {

	printf("\033[0;31m / / / / / / / / / / / / / / / / / / / / / / / / / /\n");
    	printf("\033[0;33m  __ _ _ __ ___       ___ _ __         ___(_) ___| |\n");
    	printf("\033[0;32m / _` | '__/ __|____ / _ \\ '_ \\ _____ / __| |/ _ \\ |\n");
    	printf("\033[0;36m| (_| | | | (_|_____|  __/ | | |_____| (__| |  __/ |\n");
    	printf("\033[0;34m \\__,_|_|  \\___|     \\___|_| |_|      \\___|_|\\___|_|\n");
    	printf("\n\033[0;35m / / / / / / / / / / / / / / / / / / / / / / / / / /\n");
    	printf("\033[0m");
	
	
	printf("\nMathis ALLOUCHE - Basile LAURIOLA - Antoine RIOS CAMPO - Wanis CHOUAIB\n");
    	printf("Ce projet est destiné à l'implémentation d'un craquage de mots de passe en utilisant les tables arc-en-ciel.\n\n");

   	printf("[*] Début du processus de cassage\n");	

	char hash[128];
	char rainbow_table[100];

	printf("Chiffré d'entrée: ");
	if (fgets(hash, sizeof(hash), stdin) == NULL) {
		fprintf(stderr, "\033[0;33mErreur de lecture de l'entrée.\n");
		printf("\033[0m");
		exit(EXIT_FAILURE);
	}
	if (hash[strlen(hash)-1] == '\n') hash[strlen(hash)-1] = '\0';

	printf("Chemin vers la table arc-en-ciel: ");
	if (fgets(rainbow_table, sizeof(rainbow_table), stdin) == NULL) {
		fprintf(stderr, "\033[0;33mErreur de lecture de l'entrée.\n");
		printf("\033[0m");
		exit(EXIT_FAILURE);
	}
	if (rainbow_table[strlen(rainbow_table)-1] == '\n') rainbow_table[strlen(rainbow_table)-1] = '\0';
	bool trouve = false;

	// Tant que nous n'avons pas trouvé le mot de passe
	while (!trouve) {
		// Appel de la fonction de réduction
		char reduit[7] = "";
		printf("[*] Application de la fonction de réduction (en cours...)\n");
		reduction(hash, reduit);
		printf("\t-> %s\n", reduit);
		// Vérification si le mot de passe est dans notre table arc-en-ciel
		if (recherche(reduit, rainbow_table)) {
			// On doit retrouver le mot de passe
			trouve = true;
		} else {
			unsigned char chiffre[HASH_SIZE];
			// Appel de la fonction de hashage
			printf("Le hachage SHA-256 de '%s' est : ", reduit);
			SHA256(reduit, chiffre);
		    	for (int i=0; i<HASH_SIZE; i++) {
		        	printf("%02x", chiffre[i]);
		    	}
		    	printf("\n");
			exit(0);
		}
	} 
	return 0; 
}
