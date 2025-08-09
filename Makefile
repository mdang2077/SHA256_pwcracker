all: pwcrack

pwcrack: pwcrack.c
	gcc -o pwcrack pwcrack.c -lssl -lcrypto

clean:
	rm -f pwcrack