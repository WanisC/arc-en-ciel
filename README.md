# Craquage de Mots de Passe avec les Tables Arc-en-ciel

## Auteurs
* Wanis CHOUAIB  
	wanis.chouaib@ens.uvsq.fr
* Mathis ALLOUCHE  
	mathis.allouche@ens.uvsq.fr
* Antoine RIOS CAMPO  
	antoine.rios-campo@ens.uvsq.fr
* Basile LAURIOLA  
	basile.lauriola@ens.uvsq.fr

## Introduction (avec un peu d'histoire)
Ce projet résultera à une implémentation du craquage de mots de passe en utilisant les tables arc-en-ciel.  
Les tables arc-en-ciel sont une technique efficace pour accélérer la recherche de mots de passe en précalculant une grande table contenant des empreintes de mots de passe et leurs correspondances. Cette méthode peut être utilisée pour retrouver les mots de passe originaux à partir de leur empreinte (hash).  
Il s'agit ici d'une amélioration des compromis *temps-mémoire* proposés par *Martin Hellman* dans les années 1980.

## Objectif
L'objectif, ici, est de démontrer comment les tables arc-en-ciel sont utilisées pour casser des mots de passe. Nous implémenterons donc la génération de tables ainsi que les fonctions de hashage/réduction et pour finir, la recherche d'une empreinte de mot de passe dans les tables générées et la récupération du mot de passe original.

## Utilisation
L'utilisateur aura à sa disposition un fichier Makefile permettant de simplifier l'exécution manuelle des commandes.  
Veuillez vous référer à ce fichier afin de vous familiariser avec les différentes *targets*.
```bash
# Compile le fichier main.c et exécute le fichier compilé
make
make run
# Compile le fichier main.c sans exécuter le fichier compilé
make main
# Compile le fichier main.c avec des switchs générant des informations de débogage et permet de vérifier les fuites de mémoire (memory leaks)
make valgrind
# Compile le fichier main.c avec des switchs générant des informations de débogage et permet le lancement du débuggeur
make gdb
# Installation des outils
make intall_gdb
make install_valgrind
```

## Responsable
* Christina BOURA  
	christina.boura@uvsq.fr

## Version

* 2023-2024

## Informations supplémentaires

* Langage: C
* Unité d'enseignement: Cryptographie
* Université: UVSQ-Versailles
