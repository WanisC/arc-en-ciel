#include <stdbool.h>

/* Fonction de réduction (R)

	Entrée: un chiffré
	Sortie: "texte clair" dans une taille spécifique

	Description: notre fonction de réduction prendra les 6 premiers chiffres de notre chiffré
*/
void reduction(char *chiffre, char *reduit);

/* Fonction de recherche dans la table arc-en-ciel

	Entrée: un mot de passe
	Sortie: pour tout couple (P1, P2), retourne True si le mot de passe est égal à P2, False sinon

	Description: recherche du mot de passe dans notre table arc-en-ciel
*/
bool recherche(char *mdp, char *table);
