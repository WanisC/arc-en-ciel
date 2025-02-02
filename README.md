
# Craquage de Mots de Passe avec les Tables Arc-en-ciel

## Auteurs
* Mathis ALLOUCHE  
	mathis.allouche@ens.uvsq.fr
* Wanis CHOUAIB  
	wanis.chouaib@ens.uvsq.fr
* Basile LAURIOLA  
	basile.lauriola@ens.uvsq.fr
* Antoine RIOS CAMPO  
	antoine.rios-campo@ens.uvsq.fr





# Présentation
    

  

## Objectif

  

Le projet vise à implémenter une attaque par table arc-en-ciel pour casser des mots de passe hachés. Cette méthode repose sur la génération de tables arc-en-ciel pré-calculées, permettant de récupérer les mots de passe originaux à partir de leurs hachages correspondants.

  

Le projet explore la méthode des tables arc-en-ciel pour casser les hachages de mots de passe et offre une mise en œuvre pratique de cette technique. En utilisant Rust, il combine sécurité et performance pour fournir une solution robuste et efficace. En explorant l'histoire des tables arc-en-ciel, il met également en lumière l'évolution de la cryptanalyse moderne et les défis persistants liés à la sécurité des mots de passe.

  

## Contexte et historique

  

Les tables arc-en-ciel ont été inventées par Philippe Oechslin en 2003 comme une méthode efficace pour casser les hachages de mots de passe. Leur introduction a marqué une avancée significative dans la cryptanalyse des hachages. Elles ont été largement utilisées dans la cryptographie jusqu'à ce que des contre-mesures telles que l'utilisation de sels et d'itérations rendent ces attaques moins efficaces. Cependant, elles restent une technique importante dans l'étude des vulnérabilités liées aux hachages de mots de passe.

  
# Utilisation
**Usage :**
 arc-en-ciel.exe <*COMMAND*>
cargo run -- <*COMMAND*>

***Commands :***
**generation**
	*Generate the rainbow table*
**search**
	*Search for a password in the rainbow table*
***Options:***
 **-h, --help**     
  *Print help*
  **-V, --version**
 *Print version*
  
  # generation
  
**Usage:**
 arc-en-ciel.exe generation [OPTIONS] [PATH]

**Arguments:**
  [PATH]  [default: ./output/]

**Options:**
  *-m, --use-mem*
          Use memory file If the memory file exists, use it to generate the rainbow table from the last password in the memory file If the memory file does not exist, generate the rainbow table and store the last password if the program is stopped Default is true
  *-c, --chain-length <CHAIN_LENGTH>*
          Chain length Chain length must be between 1 and 2048 Default is 100 Chain length is the number of reductions to perform before storing the password in the memory file The higher the chain length is, the less memory is used but the longer it takes to retrieve a password The lower the chain length is, the more memory is used but the faster it is to retrieve a password [default: 100]
 *-l, --password-length <PASSWORD_LENGTH>*
          [default: 7]
 *-h, --help*
          Print help
  *-V, --version*
          Print version
  
  ## search
  
  **Usage:** 
  arc-en-ciel.exe search [OPTIONS] --password-length <PASSWORD_LENGTH> [PATH]

**Arguments:**
  [PATH]  [default: ./output/]

**Options:**
  *-m, --use-mem*
          Use memory file If the memory file exists, use it to generate the rainbow table from the last password in the memory file If the memory file does not exist, generate the rainbow table and store the last password if the program is stopped Default is true
  *-c, --chain-length <CHAIN_LENGTH>*
          [default: 100]
      --hash <HASH>

  *-p, --hashs-path <HASHS_PATH>*

  *-l, --password-length <PASSWORD_LENGTH>*

  *-h, --help*
          Print help
  *-V, --version*
          Print version
 *help*
 Print this message or the help of the given subcommand(s)
  

# Méthodologie
    

  

## Génération de tables arc-en-ciel

On génère les couple de réduit de la taille du mot de passe en réduisant et hachant tous les mot de passe possible avec un décalage de la longueur de la chaîne multiplié par 0.7, pour obtenir le premier et le dernier mot de passe. Nous avons ainsi des fichiers avec des couples de mots de passe de début et de fin de chaîne. Le tout étant fait de façon multi threader.

## Recherche dans les tables arc-en-ciel

### Lecture des hash et génération des couples réductions index:

On lit nos hash pour les réduire puis hacher à la chaîne afin de créer une liste de couple réduit index.

### Recherche des réduits dans les fichiers (fin de chaîne):

On parcourt nos fichiers générés précédemment afin de trouver pour chaque couple réduit index un réduit correspondant dans notre table en fin de chaîne.

### Correspondance:

Prendre le réduit du début de chaîne correspondant, le hasher et réduire un certain nombre de fois pour arriver au réduit qui est censé avoir donné le Hash recherché.

Vérifier que quand on hash se réduit on obtient bien le Hash recherché sinon on continue à chercher dans les fichiers

## Réduction et hachage

Les fonctions de réduction sont cruciales dans la génération et la recherche des tables arc-en-ciel. Elles prennent un hachage en entrée et produisent un mot de passe potentiel. Le hachage original est utilisé pour sécuriser les mots de passe en les transformant en une forme irréversible.

  
  
  

## Langage de programmation utilisé

  

Le projet est implémenté en Rust, un langage de programmation moderne et sécurisé, réputé pour sa performance et sa sûreté. Rust offre un équilibre entre sécurité, performance et productivité, ce qui en fait un choix idéal pour les applications sensibles à la sécurité telles que la cryptographie. De plus, Rust garantit l'absence de certaines classes de bugs courantes, ce qui est crucial dans les applications de sécurité où les erreurs peuvent avoir de graves conséquences.

  

## Documentation utilisé

[https://www.crypto-textbook.com/download/Understanding-Cryptography-Keccak.pdf](https://www.crypto-textbook.com/download/Understanding-Cryptography-Keccak.pdf)

  

[https://security.stackexchange.com/questions/379/what-are-rainbow-tables-and-how-are-they-used/440#440](https://security.stackexchange.com/questions/379/what-are-rainbow-tables-and-how-are-they-used/440#440)

  

[https://en.wikipedia.org/wiki/Rainbow_table](https://en.wikipedia.org/wiki/Rainbow_table)

  
  

[https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)

  

# SHA-3
    

  

## Introduction :

SHA-3, qui signifie Secure Hash Algorithm 3, est une fonction de hachage cryptographique standardisée par le NIST (National Institute of Standards and Technology). Il fait partie de la famille de fonctions de hachage Keccak, qui a été sélectionnée après un processus de compétition. Ici nous utilisons SHA 3 - 256 pour ce projet (avec des mots de passe de taille raisonnable)

## Phase de prétraitement :

### Padding :

Les données d'entrée sont d'abord remplies (padding) pour obtenir une longueur multiple de la capacité du bloc de hachage. On utilise un padding du type 10*1 c'est-à-dire qu’on utilise des 1 comme délimiteur.

### Divisions en blocs :

Les données sont ensuite divisées en blocs de taille fixe pour le traitement ultérieur.

## Keccak :

### Forme du state array (Tableau d’état):

Ici on représente les donnés sous forme d’une matrice 3*3*3

![](https://lh7-us.googleusercontent.com/hXm56B1-d2Yysrk_ihLU9bL-xKkDomwOtRRVPMKVTpglj92kr2otwX56YofbBh18t-2jNnj8UbJCfLfRDODlALPvOZ3ABgEmDlxFIf29GjupHbBuaiasgtMe9E3BNOUBz6esGXN2M4pqSY9Vb4_R2A)

### Absorption :

Les blocs de données sont absorbés dans l'état interne du système de hachage via une opération XOR.

### Rounds de permutation :

Les blocs absorbés passent par plusieurs rounds de permutation où chaque round consiste en une série d'opérations non linéaires. Ici on a 24 round.

### Theta :

Une opération de diffusion linéaire qui modifie l'état de manière non locale.

### Rho et Pi :

Des décalages et permutations des bits de l'état.

### Chi :

Une opération de non-linéarité qui mélange les bits de chaque colonne de l'état.

### Iota :

Une opération de XOR en fonction du round actuel.

### Squeezing (Essorage) :

Une fois que tous les blocs ont été absorbés et que les rounds de permutation sont terminés, le processus de hachage passe à l'étape de "squeezing". Pendant cette phase, les bits de sortie sont extraits de l'état interne et concaténés pour former le hash final.

![](https://lh7-us.googleusercontent.com/ynoIHZNM-0ftHsdEky1RW7D222Y7iZIGDGF-qyZQ8KFP3Y-qKuVEbJoZtkF4pZcfDPGMtlBLU0GK5nrtg_N5SmmOZbyAF2pEJtuX4kbYU91faf_SQx0FjGf0Amc0xkuKXeDRDbO11-a42sl0huEvzA)

## Phase finale de rendu du hash :

Le résultat final est la valeur de hachage, représentée généralement par une chaîne de caractères hexadécimaux, qui est une représentation numérique compacte des données d'entrée. Cette valeur de hachage est généralement utilisée pour la vérification de l'intégrité des données, la génération de signatures numériques et d'autres applications de sécurité informatique.

# Conclusion
    

  

En conclusion, ce projet de cassage de mots de passe par hachage de table arc-en-ciel s'inscrit dans une démarche à la fois historique et contemporaine de la cryptanalyse. En utilisant les tables arc-en-ciel, nous avons exploré une approche efficace pour retrouver les mots de passe originaux à partir de leurs hachages correspondants. Cette méthode, bien que largement utilisée dans le passé, reste pertinente pour comprendre les défis persistants en matière de sécurité des mots de passe. En implémentant cette technique en Rust, un langage de programmation moderne et sécurisé, nous avons non seulement démontré son application pratique, mais aussi souligné l'importance de l'équilibre entre sécurité et performance dans le domaine de la cryptographie. En définitive, ce projet illustre comment l'alliance de méthodes classiques et de technologies modernes peut conduire à des avancées significatives dans la sécurité informatique.
## Responsable
* Christina BOURA  
	christina.boura@uvsq.fr

## Version

* 2023-2024

## Informations supplémentaires

* Langage: Rust
* Unité d'enseignement: Cryptographie
* Université: UVSQ-Versailles
