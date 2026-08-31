OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || echo /usr/local)

CC := gcc
CFLAGS := -Wall -Wextra -I$(OPENSSL_PREFIX)/include
LDFLAGS := -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto

all: pwcrack

pwcrack: pwcrack.c
	$(CC) $(CFLAGS) -o pwcrack pwcrack.c $(LDFLAGS)

# Build a testing binary (tests are gated behind -DTESTING) and run it.
test: pwcrack.c
	$(CC) $(CFLAGS) -DTESTING -o pwcrack_test pwcrack.c $(LDFLAGS)
	./pwcrack_test

clean:
	rm -f pwcrack pwcrack_test

.PHONY: all test clean
