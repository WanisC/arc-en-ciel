#include <stdbool.h>
#include <string.h>
#include <ctype.h>

void reduction(char *chiffre, char *reduit) {	
	int cpt=0;
	for (int i=0; i<strlen(chiffre); i++) {
		if (cpt != 7) {
			if (isdigit(chiffre[i])) {
				char temp[2] = {chiffre[i], '\0'};
				strncat(reduit, temp, 2);
				cpt++;
			}
		} else break;
	}
}

bool recherche(char *mdp, char *table) {
	return false;
}
