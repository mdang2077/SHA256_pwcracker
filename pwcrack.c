#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <assert.h>

const int SHA_LENGTH = 32;

char uppercase(char c)
{
	if (c >= 'a' && c <= 'z')
	{
		c -= 32;
	}
	return c;
}

char lowercase(char c)
{
	if (c >= 'A' && c <= 'Z')
	{
		c += 32;
	}
	return c;
}

int hex_to_dec(char c)
{
	char input = uppercase(c);
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

//Converts 64 hex characters into 32 byte array
void hexstr_to_hash(char hexstr[], unsigned char hash[32])
{
	int i = 0;
	for (i = 0; i < 32; i++)
	{
		hash[i] = hex_to_byte(hexstr[2*i], hexstr[2*i+1]);
	}
}

int8_t check_password(char password[], unsigned char given_hash[32])
{
	unsigned char password_hash[32];
	// Will store address rather than value, unsigning all the values when I use given later in the function
	unsigned char *given = (unsigned char *)given_hash;
	SHA256(password, strlen(password), password_hash);

	int count = 0;
	uint8_t i = 0;
	for (i = 0; i < 32; i+=1)
	{
		if (password_hash[i] != given[i])
		{
			count++;
		}
	}
	if (count == 0)
	{
		return 1;
	}
	return 0;
}

int8_t crack_password(char password[], unsigned char given_hash[])
{
	//Make copy of password plus a byte for the null terminator
	char tmp[strlen(password) + 1];
	strcpy(tmp, password);

	int i = 0;
	// Uppercase all letters one at a time, then use check_password on it with given hash
	for(i = 0; i < strlen(password); i++)
	{
		tmp[i] = uppercase(tmp[i]);
		if (check_password(tmp, given_hash))
		{
			password[i] = tmp[i];
			return 1;
		}
		//Resets string back to original
		strcpy(tmp, password);

	}
	// Lowercase all letters one at a time, then use check_password on it with given hash
	for(i = 0; i< strlen(password); i++)
	{
		tmp[i] = lowercase(tmp[i]);
		if (check_password(tmp, given_hash))
		{
			password[i] = tmp[i];
			return 1;			
		}
		strcpy(tmp, password);
	}

	// Change number
	for(int i = 0; i< strlen(password); i++)
	{
		if (tmp[i] >= '0' && tmp[i] <= '9')
		{
			tmp[i] = '0';
			for (int j = 0; j < 10; j++)
			{
				tmp[i] += 1;
				if (check_password(tmp, given_hash))
				{
					password[i] = tmp[i];
					return 1;			
				}
			}
		}
		strcpy(tmp, password);
	}
	// No matches
	return 0;


}


void test_hexstr_to_hash() {
  char hexstr[64] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
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

void test_crack_password() {
	char password[] = "paSsword";
	char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"; // SHA256 hash of "password"
	unsigned char given_hash[32];
	hexstr_to_hash(hash_as_hexstr, given_hash);
	int8_t match = crack_password(password, given_hash);
	assert(match == 1);
	assert(password[2] == 's'); // the uppercase 'S' has been lowercased
}

const int testing = 0;
int main(int argc, char** argv) {
  if(testing) {
    test_hex_to_byte();
    test_hexstr_to_hash();
    test_check_password();
    test_crack_password();

    printf("ALL TESTS PASSED!\n");
    return 0;
  }

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <hash>\n", argv[0]);
    return 1;
  }
  
  char line[1000];
  unsigned char hash[32];
  while (fgets(line, sizeof(line), stdin) != NULL) {
	  hexstr_to_hash(argv[1], hash);
	  line[strcspn(line, "\n")] = '\0';
	  if (crack_password(line, hash))
	  {
		printf("Found password: SHA256(%s) = %s\n", line, argv[1]);
		return 0;
	  }

  }
  printf("Did not find a matching password\n");
  return 0;

}


