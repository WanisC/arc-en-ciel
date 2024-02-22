# Détection de l'OS
ifeq ($(OS),Windows_NT)
	DEL = del /Q
	EXE = .exe
else
	DEL = rm -f
	EXE =
endif

run: clean main 
	./main$(EXE)

main: reduction.o hashage.o
	gcc -o main$(EXE) -Wall src/main.c src/reduction.c src/hashage.c lib/cmathematics/cmathematics.c lib/cmathematics/data/hashing/sha.c lib/cmathematics/data/hashing/sha1.c lib/cmathematics/data/hashing/sha2.c lib/cmathematics/data/hashing/sha3.c lib/cmathematics/lib/arrays.c

reduction.o:
	gcc -c -Wall src/reduction.c -o src/reduction.o

hashage.o:
	gcc -c -Wall src/hashage.c -o src/hashage.o
	
# Fichiers source
SRCS := $(wildcard lib/cmathematics/**/*.c)
# Fichiers objets à partir des fichiers source
OBJS := $(patsubst %.c, %.o, $(SRCS))
# Compilation des fichiers source en fichiers objets
%.o: %.c
	gcc -c $< -o $@
# Va créer les fichiers objets directement dans le dossier lib
lib: $(OBJS)
	
# Va créer les fichiers objets dans la racine du projet
lib.o:
	gcc -o lib.o -c -Wall lib/cmathematics/cmathematics.c lib/cmathematics/data/encryption/aes.c lib/cmathematics/data/hashing/hmac.c lib/cmathematics/data/hashing/pbkdf.c lib/cmathematics/data/hashing/sha.c lib/cmathematics/data/hashing/sha1.c lib/cmathematics/data/hashing/sha2.c lib/cmathematics/data/hashing/sha3.c lib/cmathematics/graph/graph.c lib/cmathematics/lib/arrays.c lib/cmathematics/lib/avl.c lib/cmathematics/lib/dynamicarray.c lib/cmathematics/lib/functions.c lib/cmathematics/lib/minheap.c lib/cmathematics/lib/strstream.c lib/cmathematics/linalg/matrix.c lib/cmathematics/linalg/vec.c lib/cmathematics/util/bigint.c lib/cmathematics/util/exp_util.c lib/cmathematics/util/expressions.c lib/cmathematics/util/numio.c

valgrind:
	gcc -g -ggdb3 src/hashage.c src/reduction.c src/main.c -o src/valgrind_check$(EXE)
	valgrind --leak-check=full src/valgrind_check$(EXE)

gdb:
	gcc -g -ggdb3 src/hashage.c src/reduction.c src/main.c -o src/gdb_check$(EXE)
	gdb src/gdb_check$(EXE)

update:
	sudo apt update

install_valgrind: update
	sudo apt install valgrind

install_gdb: update
	sudo apt install gdb

clean:
	$(DEL) src/main$(EXE)
	$(DEL) src/gdb_check$(EXE)
	$(DEL) src/valgrind_check$(EXE)
	$(DEL) src/*.o
	$(DEL) *.o
	$(DEL) src/*.out
	$(DEL) *.out
	$(DEL) src/*.output
	$(DEL) *.output
	$(DEL) src/${LADIR}
	$(DEL) src/${LADIR}.zip
	clear

LADIR="ALLOUCHE_LAURIOLA_RIOS-CAMPO_CHOUAIB"
zip:
	$(DEL) src/${LADIR}
	mkdir src/${LADIR}
	cp Makefile src/main.c src/main.h src/hashage.c src/hashage.h src/reduction.c src/reduction.h src/${LADIR}
	$(DEL) src/${LADIR}.zip
	zip -r src/${LADIR}.zip src/${LADIR}
	$(DEL) src/${LADIR}

run:
	gcc -g -o main.exe src/main.c src/hashage.c src/reduction.c lib/cmathematics/cmathematics.c lib/cmathematics/data/encryption/aes.c lib/cmathematics/data/hashing/hmac.c lib/cmathematics/data/hashing/pbkdf.c lib/cmathematics/data/hashing/sha.c lib/cmathematics/data/hashing/sha1.c lib/cmathematics/data/hashing/sha2.c lib/cmathematics/data/hashing/sha3.c lib/cmathematics/graph/graph.c lib/cmathematics/lib/arrays.c lib/cmathematics/lib/avl.c lib/cmathematics/lib/dynamicarray.c lib/cmathematics/lib/functions.c lib/cmathematics/lib/minheap.c lib/cmathematics/lib/strstream.c lib/cmathematics/linalg/matrix.c lib/cmathematics/linalg/vec.c lib/cmathematics/util/bigint.c lib/cmathematics/util/exp_util.c lib/cmathematics/util/expressions.c lib/cmathematics/util/numio.c
	./main.exe
