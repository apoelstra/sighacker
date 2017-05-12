
CFLAGS=-Wall -Wextra -Werror -W -g
LFLAGS=-lsecp256k1

SOURCES=src/main.c src/command.c src/hash.c src/util.c


all: $(SOURCES)
	gcc $(CFLAGS) $(LFLAGS) $(SOURCES) -o sighacker

check: all
	./tests.sh


