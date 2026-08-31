#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <assert.h>
#include <ctype.h>


const int SHA_LENGTH = 32;

int8_t isSpecial(char character) {
	// Special variations: a/A/@, e/E/3, o/O/0, i,I,1
	switch (character) {
		case 'a': case 'A': case '@':
		case 'e': case 'E': case '3':
		case 'o': case 'O': case '0':
		case 'i': case 'I': case '1':
			return 1;
	}
	return 0;
}
int hex_to_dec(char c)
{
	char input = toupper(c);
	if (input >= 'A' && input <= 'F')
	{
		return input -= 55;
	}
	else if (input >= '0' && input <= '9')
	{
		return input -= 48;
	}
	return 0;

}

uint8_t hex_to_byte(unsigned char h1, unsigned char h2)
{
	uint8_t c1 = hex_to_dec(h1) * 16;
	uint8_t c2 = hex_to_dec(h2);
	return c1 + c2;
}

// Returns 1 if the string is exactly 64 hexadecimal characters, 0 otherwise.
int is_valid_hash(const char *hexstr)
{
	if (strlen(hexstr) != 64) {
		return 0;
	}
	for (int i = 0; i < 64; i++) {
		if (!isxdigit((unsigned char)hexstr[i])) {
			return 0;
		}
	}
	return 1;
}

//Converts 64 hex characters into 32 byte array
void hexstr_to_hash(char hexstr[], unsigned char hash[32])
{
	int i = 0;
	for (i = 0; i < 32; i++)
	{
		hash[i] = hex_to_byte(hexstr[2*i], hexstr[2*i+1]);
	}
}

// Checks a single variation of the password
int8_t check_password(char password[], unsigned char given_hash[32])
{
	unsigned char password_hash[32];
	// Will store address rather than value, unsigning all the values when I use given later in the function
	SHA256((const unsigned char *)password, strlen(password), password_hash);
	
	return memcmp(password_hash, given_hash, SHA256_DIGEST_LENGTH) == 0;
}

int8_t check_case_variations(char *word, unsigned char given_hash[32]) {
    int len = strlen(word);
    int alpha_count = 0;
    int alpha_indexes[len];

    // Record indexes of letters only
    for (int i = 0; i < len; i++) {
        if (isalpha(word[i])) {
            alpha_indexes[alpha_count++] = i;
        }
    }

    int total_variants = 1 << alpha_count;  // 2^alpha_count
    char variant[len + 1];

    for (int mask = 0; mask < total_variants; mask++) {
        strcpy(variant, word);

        for (int bit = 0; bit < alpha_count; bit++) {
            int idx = alpha_indexes[bit];
            if (mask & (1 << bit)) {
                variant[idx] = toupper(variant[idx]);
            } else {
                variant[idx] = tolower(variant[idx]);
            }
        }

		if (check_password(variant, given_hash)) {
            strcpy(word, variant);
            return 1;
        }

		/* Digit Brute force, removed to reduce space
		for (int i = 0; i < len; i++) {
			if (isdigit(variant[i])) {
				char original_digit = variant[i];
				for (char digit = '0'; digit <= '9'; digit++) {
					variant[i] = digit;
					if (check_password(variant, given_hash)) {
						strcpy(word, variant);
						return 1;
					}
				}
				variant[i] = original_digit; // restore original digit before next digit index
			}
		} */
    }
	return 0;
}

int8_t check_special_variations(char* word, unsigned char given_hash[]) {
	// Special variations: a/A/@, e/E/3, o/O/0, i,I,1
	int len = strlen(word);
	int special_char_count = 0;
	int special_char_index[len];

	char variant[len + 1];

	for (int i = 0; i < len; i++) {
		if (isSpecial(word[i])) {
			special_char_index[special_char_count++] = i;
		}
	}

	int total_variants = 1 << special_char_count;

	for (int mask = 0; mask < total_variants; mask++) {
        strcpy(variant, word);

        for (int bit = 0; bit < special_char_count; bit++) {
            int idx = special_char_index[bit];
            
			char c = tolower(word[idx]);

			if (c == 'a') {
				variant[idx] = (mask & (1 << bit)) ? '@' : 'a';
			}
			else if (c == 'e') {
				variant[idx] = (mask & (1 << bit)) ? '3' : 'e';
			}
			else if (c == 'o') {
				variant[idx] = (mask & (1 << bit)) ? '0' : 'o';
			}
			else if (c == 'i') {
				variant[idx] = (mask & (1 << bit)) ? '1' : 'i';
			}
        }
		if (check_password(variant, given_hash))
		{
			strcpy(word, variant);
			return 1;
		}		
    }

	return 0;
}

// Functions runs against multiple variations of the password
int8_t crack_password(char password[], unsigned char given_hash[])
{
	//Make copy of password plus a byte for the null terminator
	char tmp[strlen(password) + 1];
	strcpy(tmp, password);

	if (check_password(password, given_hash)) {
    	return 1;
	}

	if (check_case_variations(tmp, given_hash)) {
		strcpy(password, tmp); // copy back the match
		return 1;
	}

	if (check_special_variations(tmp, given_hash)) {
		strcpy(password, tmp); // copy back the match
		return 1;
	}

	// No matches
	return 0;


}


void test_hexstr_to_hash() {
  char hexstr[] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
  unsigned char hash[32];
  hexstr_to_hash(hexstr, hash);
  assert(hash[0] == 0xa2);
  assert(hash[29] == 0xc8);
  assert(hash[31] == 0xfd);

}

void test_hex_to_byte() {
	assert(hex_to_byte('c', '8') == 200);
	assert(hex_to_byte('0', '3') == 3);
	assert(hex_to_byte('0', 'a') == 10);
	assert(hex_to_byte('1', '0') == 16);
}

void test_check_password() {
	// SHA256 hash for 'password'
	char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
	char seCret_hash_as_hexstr[] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
	unsigned char secret_hash[32];
	unsigned char given_hash[32];
	hexstr_to_hash(seCret_hash_as_hexstr, secret_hash);
	assert(secret_hash[0] == 0xa2);
	assert(check_password("seCret", secret_hash) == 1);
    
	hexstr_to_hash(hash_as_hexstr, given_hash);
	assert(given_hash[0] == 0x5e);
	assert(given_hash[6] == 0x04);
	assert(check_password("password", given_hash) == 1);
	assert(check_password("wrongpass", given_hash) == 0);
}

void test_check_case_variations() {
	char password[] = "paSSwoRd";
	char hash_as_hexstr[] = "9cd00dd3e377d2ee3a4d2432783de680f8bb736031bff686260601b22f7b0e0f"; // SHA256 hash of "paSSwoRd"
	unsigned char given_hash[32];
	hexstr_to_hash(hash_as_hexstr, given_hash);
	int8_t match = check_case_variations(password, given_hash);
	assert(match == 1);
}

void test_crack_password() {
	char password[] = "paSSwoRd";
	char hash_as_hexstr[] = "9cd00dd3e377d2ee3a4d2432783de680f8bb736031bff686260601b22f7b0e0f"; // SHA256 hash of "paSSwoRd"
	unsigned char given_hash[32];
	hexstr_to_hash(hash_as_hexstr, given_hash);
	int8_t match = crack_password(password, given_hash);
	assert(match == 1);
}

#ifdef TESTING
const int testing = 1;
#else
const int testing = 0;
#endif

// Searches a single wordlist file for a password matching given_hash.
// Prints progress dots and, on success, the cracked password.
// Returns 1 if found, 0 if not found, -1 if the file could not be opened.
int search_wordlist(const char *filename, unsigned char hash[32], const char *hexstr)
{
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "pwcrack: cannot open wordlist '%s': ", filename);
        perror(NULL);
        return -1;
    }

    const char *dots[] = {".  ", ".. ", "...", "   "};
    int dot_index = 0;
    int count = 0;
    char word[256];

    while (fgets(word, sizeof(word), file)) {
        word[strcspn(word, "\r\n")] = 0;  // strip CR and/or LF
        if (crack_password(word, hash)) {
            printf("\nFound password: SHA256(%s) = %s\n", word, hexstr);
            fclose(file);
            return 1;
        }
        if (++count % 5000 == 0) {
            printf("\rSearching%s", dots[dot_index]);
            fflush(stdout);
            dot_index = (dot_index + 1) % 4;
        }
    }

    fclose(file);
    return 0;
}

// Tests a single candidate word (and its case/leet variations) against the hash.
// Prints the result. Returns 1 if found, 0 otherwise.
int crack_single_word(const char *candidate, unsigned char hash[32], const char *hexstr)
{
    char word[256];
    strncpy(word, candidate, sizeof(word) - 1);
    word[sizeof(word) - 1] = 0;

    if (crack_password(word, hash)) {
        printf("Found password: SHA256(%s) = %s\n", word, hexstr);
        return 1;
    }
    printf("Could not find a matching password\n");
    return 0;
}

// Returns 1 if path names a readable file, 0 otherwise.
int is_readable_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

int main(int argc, char** argv) {
    if (testing) {
        test_hex_to_byte();
        test_hexstr_to_hash();
        test_check_password();
        test_check_case_variations();
        test_crack_password();

        printf("ALL TESTS PASSED!\n");
        return 0;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <sha256_hash> [wordlist | word]\n", argv[0]);
        fprintf(stderr, "  <sha256_hash>    64-character hex SHA256 hash to crack\n");
        fprintf(stderr, "  [wordlist|word]  optional: a wordlist file to search, or a single word\n");
        fprintf(stderr, "                   to test directly. If the argument names an existing\n");
        fprintf(stderr, "                   file it is treated as a wordlist, otherwise as a word.\n");
        fprintf(stderr, "                   Omit to search the bundled rockyou wordlist.\n");
        return 1;
    }

    if (!is_valid_hash(argv[1])) {
        fprintf(stderr, "pwcrack: invalid hash '%s'\n", argv[1]);
        fprintf(stderr, "         expected exactly 64 hexadecimal characters (0-9, a-f).\n");
        return 1;
    }

    unsigned char hash[32];
    hexstr_to_hash(argv[1], hash);

    // Second argument: either a wordlist file to search, or a single word to test.
    // If it names an existing file, treat it as a wordlist; otherwise as a word.
    if (argc >= 3) {
        if (is_readable_file(argv[2])) {
            int result = search_wordlist(argv[2], hash, argv[1]);
            if (result == 1) {
                return 0;
            }
            if (result == -1) {
                return 1;
            }
            printf("\nCould not find a matching password\n");
            return 0;
        }
        crack_single_word(argv[2], hash, argv[1]);
        return 0;
    }

    // No wordlist/word given: search the bundled rockyou wordlist (two files).
    const char *default_files[] = {"rockyou_part_aa", "rockyou_part_ab"};
    int nfiles = sizeof(default_files) / sizeof(default_files[0]);

    for (int i = 0; i < nfiles; i++) {
        int result = search_wordlist(default_files[i], hash, argv[1]);
        if (result == 1) {
            return 0;   // found
        }
        if (result == -1) {
            return 1;   // could not open a wordlist file
        }
    }

    printf("\nCould not find a matching password\n");
    return 0;
}
