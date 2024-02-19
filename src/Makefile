run: clean main
	./main

main: reduction.o hashage.o
	gcc -Wall main.c reduction.o hashage.o -o main -lsodium

reduction.o:
	gcc -c -Wall reduction.c

hashage.o:
	gcc -c -Wall hashage.c

valgrind:
	gcc -g -ggdb3 hashage.c reduction.c main.c -o valgrind_check -lsodium
	valgrind --leak-check=full ./valgrind_check

gdb:
	gcc -g -ggdb3 hashage.c reduction.c main.c -o gdb_check -lsodium
	gdb ./gdb_check

update:
	sudo apt update

install_valgrind: update
	sudo apt install valgrind

install_gdb: update
	sudo apt install gdb

unknown_libsodium:
	@echo "[*] Ecriture sur ~/.bashrc..."
	@echo "\nexport LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH" >> ~/.bashrc
	@sleep 2
	@echo "[*] Ecriture sur ~/.bash_profile..."
	@echo "test -f ./.bashrc && source ./.bashrc" >> ~/.bash_profile
	@sleep 2
	@echo "[*] Votre machine va redémarrer dans 5 secondes."
	@sleep 5
	init 6

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
	cp Makefile main.c hashage.c hashage.h reduction.c reduction.h ${LADIR}
	rm -f ${LADIR}.zip
	zip -r ${LADIR}.zip ${LADIR}
	rm -rf ${LADIR}
