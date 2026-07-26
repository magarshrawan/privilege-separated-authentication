CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
LDFLAGS ?=

.PHONY: all clean disassembly

all: frontend backend create_verifier

frontend: Frontend.c Protocol.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ Frontend.c

backend: Backend.c Protocol.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ Backend.c -lcrypt

create_verifier: create_verifier.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ create_verifier.c -lcrypt

disassembly: all
	objdump -d -Mintel frontend > frontend.disassembly.txt
	objdump -d -Mintel backend > backend.disassembly.txt

clean:
	rm -f frontend backend create_verifier *.disassembly.txt
