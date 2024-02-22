#include <stdbool.h>

/* Fonction de réduction (R1)

	Entrée: un chiffré
	Sortie: "texte clair" dans une taille spécifique

	Description: 
		R1  - ne récupère que les 7 premiers caractères numériques rencontrés
		R2  - transforme le chiffré en base décimale
		R3  - ne récupère que les 7 premiers caractères alphabétiques recontrés
		R4  - ne récupère que les 7 premiers caractères rencontrés (alphabétique ou numérique)
		R5  - 
		R6  - 
		R7  -
		R8  -
		R9  -
		R10 -
*/
void R1(char *chiffre, char *reduit);
void R2(char *chiffre, char *reduit);
void R3(char *chiffre, char *reduit);
void R4(char *chiffre, char *reduit);
void R5(char *chiffre, char *reduit);
void R6(char *chiffre, char *reduit);
void R7(char *chiffre, char *reduit);
void R8(char *chiffre, char *reduit);
void R9(char *chiffre, char *reduit);
void R10(char *chiffre, char *reduit);

/* Fonction de recherche dans la table arc-en-ciel

	Entrée: un mot de passe
	Sortie: True ou False

	Description: pour tout couple (P1,P2) retourne True si on trouve P2 dans notre table, False sinon
*/
bool recherche(char *mdp, char *table);
