# SHA256_pwcracker
Given an input of a SHA256 hash, the program runs the hash and compares it to rock.txt passwords. The program can detect the password or simple variations of the password, and will notify the user if the hash is cracked.

Program currently checks variations for all potential capitalizations of the words in the dictionary. Because of the vastness, the search make takes time.

# Examples
Input: ./pwcrack 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Output: Found password: SHA256(password) = 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

Input: ./pwcrack 9cd00dd3e377d2ee3a4d2432783de680f8bb736031bff686260601b22f7b0e0f
Output: Found password: SHA256(paSSwoRd) = 9cd00dd3e377d2ee3a4d2432783de680f8bb736031bff686260601b22f7b0e0f

Input: ./pwcrack bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023
Output: Found password: SHA256(123400) = bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023



