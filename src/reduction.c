#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

void R1(char *chiffre, char *reduit) {	
	int cpt=0;
	for (int i=0; i<strlen(chiffre); i++) {
		if (cpt!=7) {
			if (isdigit(chiffre[i])) {
				char temp[2]={chiffre[i],'\0'};
				strncat(reduit,temp,2);
				cpt++;
			}
		} else break;
	}
}

void R2(char *chiffre, char *reduit) {
	int somme=0;
	for (int i=0; i<strlen(chiffre); i++) {
		if (chiffre[i]>='0' && chiffre[i]<='9') {
			somme+=chiffre[i]-'0';
		} else if (chiffre[i]>='a' && chiffre[i]<='f') {
			somme+=chiffre[i]-'a'+10;
		} else {
			somme+=chiffre[i]-'A'+10;
		}
	}
	sprintf(reduit,"%d",somme);
}

void R3(char *chiffre, char *reduit) {
	int cpt=0;
	for (int i=0; i<strlen(chiffre); i++) {
		if (cpt!=7) {
			if (isalpha(chiffre[i])) {
				char temp[2]={chiffre[i],'\0'};
				strncat(reduit,temp,2);
				cpt++;
			}
		} else break;
	}
}

void R4(char *chiffre, char *reduit) {
	int cpt=0;
	for (int i=0; i<strlen(chiffre); i++) {
		if (cpt!=7) {
			char temp[2]={chiffre[i],'\0'};
			strncat(reduit,temp,2);
			cpt++;
		} else break;
	}
}

void R5(char *chiffre, char *reduit) {
	int somme=0;
	for (int i=0; i<strlen(chiffre); i++) {
		if (isdigit(chiffre[i])) {
			somme+=chiffre[i];
		}
	}
	sprintf(reduit,"%d",somme);
}

void R6(char *chiffre, char *reduit) {
	int somme=0;
	for (int i=0; i<strlen(chiffre); i++) {
		if (chiffre[i]>='a' && chiffre[i]<='j') {
			somme=chiffre[i]-'a'+10;
		} else if (chiffre[i]>='A' && chiffre[i]<='J') {
			somme=chiffre[i]-'A'+10;
		} else continue;
	}
	sprintf(reduit,"%d",somme);
}

void R7(char *chiffre, char*reduit) {}

void R8(char *chiffre, char *reduit) {}

void R9(char *chiffre, char *reduit) {}

void R10(char *chiffre, char *reduit) {}

bool recherche(char *mdp, char *table) {
	return false;
}
