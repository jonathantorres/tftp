VPATH = src
CFLAGS = gcc -g -std=gnu17 -Wall -Wextra
PROGS = server client

.PHONY: all
all: $(PROGS)

$(PROGS):%: %.c tftp.h
	$(CFLAGS) $< -o ./bin/$@

.PHONY: clean
clean:
	rm -f ./*.o ./*.h.gch
	rm -fr ./bin
	mkdir ./bin && touch ./bin/.gitkeep
