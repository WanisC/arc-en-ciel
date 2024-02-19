/* Fonction de hashage (H)

	Entrée: un mot de passe
	Sortie: le chiffré du mot de passe en entrée

	Description: utilise la fonction crypto_hash_sha256 de la librairie sodium.h pour chiffrer le mot de passe et stocker le résultat dans la variable hash 

*/
void SHA256(char *mdp, unsigned char *hash);
