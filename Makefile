run: clean main 
	./main

main: reduction.o hashage.o cmathematics.o sha.o sha1.o sha2.o sha3.o arrays.o
	gcc -o main -Wall src/main.c reduction.o hashage.o cmathematics.o sha.o sha1.o sha2.o sha3.o arrays.o

reduction.o:
	gcc -c -Wall src/reduction.c -o reduction.o

hashage.o:
	gcc -c -Wall src/hashage.c -o hashage.o
	
cmathematics.o:
	gcc -c -Wall lib/cmathematics/cmathematics.c -o cmathematics.o

sha.o:
	gcc -c -Wall lib/cmathematics/data/hashing/sha.c -o sha.o

sha1.o:
	gcc -c -Wall lib/cmathematics/data/hashing/sha1.c -o sha1.o

sha2.o:
	gcc -c -Wall lib/cmathematics/data/hashing/sha2.c -o sha2.o

sha3.o:
	gcc -c -Wall lib/cmathematics/data/hashing/sha3.c -o sha3.o

arrays.o:
	gcc -c -Wall lib/cmathematics/lib/arrays.c -o arrays.o

valgrind:
	gcc -g -ggdb3 src/hashage.c src/reduction.c src/main.c -o valgrind_check
	valgrind --leak-check=full valgrind_check

gdb:
	gcc -g -ggdb3 src/hashage.c src/reduction.c src/main.c -o gdb_check
	gdb gdb_check

update:
	sudo apt update

install_valgrind: update
	sudo apt install valgrind

install_gdb: update
	sudo apt install gdb

clean:
	rm -f main
	rm -f gdb_check
	rm -f valgrind_check
	rm -f *.o
	rm -f *.out
	rm -f *.output
	rm -rf ${LADIR}
	rm -rf ${LADIR}.zip
	clear

LADIR="ALLOUCHE_LAURIOLA_RIOS-CAMPO_CHOUAIB"
zip:
	rm -rf ${LADIR}
	mkdir ${LADIR}
	cp Makefile src/main.c src/main.h src/hashage.c src/hashage.h src/reduction.c src/reduction.h ${LADIR}
	rm -rf ${LADIR}.zip
	zip -r ${LADIR}.zip ${LADIR}
	rm -rf ${LADIR}

mathis_run:
	gcc -g -o main.exe src/main.c src/hashage.c src/reduction.c lib/cmathematics/cmathematics.c lib/cmathematics/data/encryption/aes.c lib/cmathematics/data/hashing/hmac.c lib/cmathematics/data/hashing/pbkdf.c lib/cmathematics/data/hashing/sha.c lib/cmathematics/data/hashing/sha1.c lib/cmathematics/data/hashing/sha2.c lib/cmathematics/data/hashing/sha3.c lib/cmathematics/graph/graph.c lib/cmathematics/lib/arrays.c lib/cmathematics/lib/avl.c lib/cmathematics/lib/dynamicarray.c lib/cmathematics/lib/functions.c lib/cmathematics/lib/minheap.c lib/cmathematics/lib/strstream.c lib/cmathematics/linalg/matrix.c lib/cmathematics/linalg/vec.c lib/cmathematics/util/bigint.c lib/cmathematics/util/exp_util.c lib/cmathematics/util/expressions.c lib/cmathematics/util/numio.c
	./main.exe