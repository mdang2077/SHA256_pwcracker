OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || echo /usr/local)

all: pwcrack

pwcrack: pwcrack.c
	gcc -o pwcrack pwcrack.c -I$(OPENSSL_PREFIX)/include -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto

clean:
	rm -f pwcrack