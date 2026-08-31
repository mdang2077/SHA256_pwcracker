#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <assert.h>
#include <ctype.h>

// Per-word ceiling on generated variations. Words whose case+leet expansion
// exceeds this are only checked as an exact match (see crack_variations).
#define MAX_VARIANTS (1ULL << 20)  // 1,048,576


const int SHA_LENGTH = 32;

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
	unsigned int md_len = 0;
	// EVP_Digest is the non-deprecated one-shot SHA256 API in OpenSSL 3.
	EVP_Digest(password, strlen(password), password_hash, &md_len, EVP_sha256(), NULL);

	return memcmp(password_hash, given_hash, SHA256_DIGEST_LENGTH) == 0;
}

// Fills opts[] with the candidate characters for input char c and returns the
// count (1..3). Letters yield {lower, upper}; a/e/o/i additionally yield their
// leet form; and leet symbols @/3/0/1 map back to their base letter's options
// (reverse-leet). Everything else yields itself unchanged.
int char_options(char c, char opts[3])
{
	char base;
	switch (c) {
		case '@': base = 'a'; break;
		case '3': base = 'e'; break;
		case '0': base = 'o'; break;
		case '1': base = 'i'; break;
		default:
			base = isalpha((unsigned char)c) ? tolower((unsigned char)c) : c;
	}

	switch (base) {
		case 'a': opts[0] = 'a'; opts[1] = 'A'; opts[2] = '@'; return 3;
		case 'e': opts[0] = 'e'; opts[1] = 'E'; opts[2] = '3'; return 3;
		case 'o': opts[0] = 'o'; opts[1] = 'O'; opts[2] = '0'; return 3;
		case 'i': opts[0] = 'i'; opts[1] = 'I'; opts[2] = '1'; return 3;
		default:
			if (isalpha((unsigned char)base)) {
				opts[0] = (char)tolower((unsigned char)base);
				opts[1] = (char)toupper((unsigned char)base);
				return 2;
			}
			opts[0] = c;
			return 1;
	}
}

// Combined case + leet variation search. Enumerates the mixed-radix product of
// each character's options. If the product exceeds MAX_VARIANTS the word is left
// to the exact-match check (returns 0) to bound runtime and avoid the old
// signed-shift undefined behavior. On a match, writes the variant into word.
int8_t crack_variations(char *word, unsigned char given_hash[32])
{
	int len = strlen(word);
	if (len == 0) {
		return 0;  // nothing to vary; exact match already tried by caller
	}

	char options[len][3];
	int nopts[len];
	unsigned long long total = 1;

	for (int i = 0; i < len; i++) {
		nopts[i] = char_options(word[i], options[i]);
		if (nopts[i] > 1) {
			// Guard the multiply against overflow / exceeding the budget.
			if (total > MAX_VARIANTS / (unsigned)nopts[i]) {
				return 0;  // too large: exact-match only
			}
			total *= (unsigned)nopts[i];
		}
	}

	if (total <= 1) {
		return 0;  // no transformable characters
	}

	char variant[len + 1];
	variant[len] = 0;

	for (unsigned long long idx = 0; idx < total; idx++) {
		unsigned long long rem = idx;
		for (int i = 0; i < len; i++) {
			int k = 0;
			if (nopts[i] > 1) {
				k = (int)(rem % (unsigned)nopts[i]);
				rem /= (unsigned)nopts[i];
			}
			variant[i] = options[i][k];
		}
		if (check_password(variant, given_hash)) {
			strcpy(word, variant);
			return 1;
		}
	}

	return 0;
}

// Functions runs against multiple variations of the password
int8_t crack_password(char password[], unsigned char given_hash[])
{
	// Make a copy plus a byte for the null terminator so the generator can
	// overwrite it in place without clobbering the caller's exact-match input.
	char tmp[strlen(password) + 1];
	strcpy(tmp, password);

	if (check_password(password, given_hash)) {
		return 1;
	}

	if (crack_variations(tmp, given_hash)) {
		strcpy(password, tmp);  // copy back the match
		return 1;
	}

	// No matches
	return 0;
}

// Strips a trailing CR and/or LF (handles LF, CRLF, and lone CR line endings).
void strip_eol(char *s)
{
	s[strcspn(s, "\r\n")] = 0;
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Convenience: build a 32-byte hash from a 64-char hex string literal.
void hash_of_hex(const char *hex, unsigned char out[32]) {
	char buf[65];
	strncpy(buf, hex, 64);
	buf[64] = 0;
	hexstr_to_hash(buf, out);
}

void test_hexstr_to_hash() {
	unsigned char hash[32];
	hash_of_hex("a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd", hash);
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
	unsigned char given_hash[32];
	unsigned char secret_hash[32];
	hash_of_hex("a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd", secret_hash);
	assert(check_password("seCret", secret_hash) == 1);

	hash_of_hex("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", given_hash);
	assert(check_password("password", given_hash) == 1);
	assert(check_password("wrongpass", given_hash) == 0);
}

// #1 Empty string: guards the zero-length path.
void test_empty_string() {
	unsigned char h[32];
	hash_of_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", h);
	assert(check_password("", h) == 1);
	char word[] = "";
	assert(crack_variations(word, h) == 0);  // nothing to vary
}

// #2 Smallest non-trivial input: single char, exact + case variation.
void test_single_char() {
	unsigned char hash_a[32];
	unsigned char hash_A[32];
	hash_of_hex("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", hash_a);
	hash_of_hex("559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd", hash_A);
	assert(check_password("a", hash_a) == 1);
	char word[] = "a";
	assert(crack_password(word, hash_A) == 1);  // 'a' -> 'A'
	assert(strcmp(word, "A") == 0);
}

// #3 Exact match short-circuits: an unmodified word matches and is left as-is.
void test_exact_short_circuit() {
	unsigned char h[32];
	hash_of_hex("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", h);
	char word[] = "password";
	assert(crack_password(word, h) == 1);
	assert(strcmp(word, "password") == 0);  // unchanged
}

// #4 Leet-only variation from a lowercase dictionary word.
void test_leet_only() {
	unsigned char h[32];
	hash_of_hex("a075d17f3d453073853f813838c15b8023b8c487038436354fe599c3942e1f95", h);  // p@ssw0rd
	char word[] = "password";
	assert(crack_password(word, h) == 1);
	assert(strcmp(word, "p@ssw0rd") == 0);
}

// #5 Combined case + leet: previously uncrackable (bug 1.1), now passes.
void test_combined_case_leet() {
	unsigned char h[32];
	hash_of_hex("b03ddf3ca2e714a6548e7495e2a03f5e824eaac9837cd7f159c67b90fb4b7342", h);  // P@ssw0rd
	char word[] = "password";
	assert(crack_password(word, h) == 1);
	assert(strcmp(word, "P@ssw0rd") == 0);
}

// #6 hex_to_dec digit mapping, including the 0-fallback for invalid input.
void test_hex_to_dec() {
	assert(hex_to_dec('a') == 10);
	assert(hex_to_dec('A') == 10);
	assert(hex_to_dec('f') == 15);
	assert(hex_to_dec('F') == 15);
	assert(hex_to_dec('0') == 0);
	assert(hex_to_dec('9') == 9);
	assert(hex_to_dec('g') == 0);  // invalid -> 0-fallback
	assert(hex_to_dec('z') == 0);
	assert(hex_to_dec(' ') == 0);
}

// #7 Hash-string validation.
void test_is_valid_hash() {
	assert(is_valid_hash("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8") == 1);
	assert(is_valid_hash("5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8") == 1);  // uppercase ok
	assert(is_valid_hash("5e884898") == 0);  // too short
	assert(is_valid_hash("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8a") == 0);  // too long
	assert(is_valid_hash("g5884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8") == 0);  // non-hex
}

// #8 Uppercase-hex input hash still cracks (hex_to_dec is case-insensitive).
void test_uppercase_hex_input() {
	unsigned char h[32];
	hash_of_hex("5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8", h);
	assert(check_password("password", h) == 1);
}

// #9 Definite no-match: returns 0, no crash.
void test_no_match() {
	unsigned char h[32];
	hash_of_hex("0000000000000000000000000000000000000000000000000000000000000000", h);
	char word[] = "password";
	assert(crack_password(word, h) == 0);
}

// #10 Non-transformable word (no case/leet options): exact only, no expansion.
void test_no_transformable_chars() {
	unsigned char h[32];
	hash_of_hex("7f048c26d647f131dcfadc28d7c35f82f0881a5e087c7dc4ea0e6c762d3fdf9f", h);  // "2459"
	char word[] = "2459";
	assert(crack_variations(word, h) == 0);   // total == 1, nothing to enumerate
	assert(crack_password(word, h) == 1);      // matches via exact check
	char opts[3];
	assert(char_options('2', opts) == 1);      // digit with no leet meaning
	assert(char_options('9', opts) == 1);
}

// #11 Long all-alpha word: capped (no shift UB, no hang), exact still works.
void test_length_boundary() {
	unsigned char h[32];
	hash_of_hex("61c60b487d1a921e0bcc9bf853dda0fb159b30bf57b2e2d2c753b00be15b5a09", h);  // 31 x 'a'
	char word[32];
	memset(word, 'a', 31);
	word[31] = 0;
	assert(crack_variations(word, h) == 0);   // over MAX_VARIANTS -> exact only, returns fast
	assert(crack_password(word, h) == 1);      // exact match

	unsigned char zero[32] = {0};
	char word2[32];
	memset(word2, 'a', 31);
	word2[31] = 0;
	assert(crack_password(word2, zero) == 0);  // no match, no UB/hang
}

// #12 Buffer integrity: the matching variant is copied back with the same length.
void test_buffer_integrity() {
	unsigned char h[32];
	hash_of_hex("9cd00dd3e377d2ee3a4d2432783de680f8bb736031bff686260601b22f7b0e0f", h);  // paSSwoRd
	char word[] = "password";
	assert(crack_password(word, h) == 1);
	assert(strcmp(word, "paSSwoRd") == 0);
	assert(strlen(word) == 8);
}

// #13 Reverse-leet: a word already containing @ cracks the plain-letter form.
void test_reverse_leet() {
	unsigned char h[32];
	hash_of_hex("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", h);  // password
	char word[] = "p@ssword";
	assert(crack_password(word, h) == 1);
	assert(strcmp(word, "password") == 0);
}

// #14 CRLF handling: strip_eol removes trailing CR and/or LF.
void test_strip_eol() {
	char lf[]   = "password\n";
	char crlf[] = "password\r\n";
	char cr[]   = "password\r";
	char none[] = "password";
	strip_eol(lf);   assert(strcmp(lf, "password") == 0);
	strip_eol(crlf); assert(strcmp(crlf, "password") == 0);
	strip_eol(cr);   assert(strcmp(cr, "password") == 0);
	strip_eol(none); assert(strcmp(none, "password") == 0);
}

void test_crack_password() {
	unsigned char given_hash[32];
	hash_of_hex("9cd00dd3e377d2ee3a4d2432783de680f8bb736031bff686260601b22f7b0e0f", given_hash);  // paSSwoRd
	char password[] = "paSSwoRd";
	assert(crack_password(password, given_hash) == 1);
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
    char word[4096];

    while (fgets(word, sizeof(word), file)) {
        size_t n = strcspn(word, "\r\n");
        int had_eol = (word[n] != 0);
        word[n] = 0;  // strip CR and/or LF

        // Line longer than the buffer: drain the remainder so its tail is not
        // parsed as a separate bogus word, and skip this over-long entry.
        if (!had_eol && !feof(file)) {
            int ch;
            while ((ch = fgetc(file)) != '\n' && ch != EOF) { }
            continue;
        }

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
        test_crack_password();

        test_empty_string();           // #1
        test_single_char();            // #2
        test_exact_short_circuit();    // #3
        test_leet_only();              // #4
        test_combined_case_leet();     // #5
        test_hex_to_dec();             // #6
        test_is_valid_hash();          // #7
        test_uppercase_hex_input();    // #8
        test_no_match();               // #9
        test_no_transformable_chars(); // #10
        test_length_boundary();        // #11
        test_buffer_integrity();       // #12
        test_reverse_leet();           // #13
        test_strip_eol();              // #14

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
