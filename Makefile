all: pwcrack

pwcrack: pwcrack.c
	gcc -std=c11 -Wall -Wno-unused-variables -fsanitize=address -g pwcrack.c -o pwcrack -lcrypto

clean:
	rm -f pwcrack