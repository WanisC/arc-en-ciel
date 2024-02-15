run: main
	./main

main:
	gcc main.c -o main

valgrind:
	gcc -g -ggdb3 main.c -o valgrind_check
	valgrind --leak-check=full ./valgrind_check

gdb:
	gcc -g -ggdb3 main.c -o gdb_check
	gdb ./gdb_check

update:
	sudo apt update

upgrade:
	sudo apt upgrade

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

LADIR="ALLOUCHE_LAURIOLA_RIOSCAMPO_CHOUAIB"
zip:
	rm -rf ${LADIR}
	mkdir ${LADIR}
	cp Makefile main.c hashage.c hashage.h ${LADIR}
	rm -f ${LADIR}.zip
	zip -r ${LADIR}.zip ${LADIR}
	rm -rf ${LADIR}
