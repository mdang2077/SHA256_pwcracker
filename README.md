# SHA256 Password Cracker

A dictionary-based SHA256 hash cracker written in C. Given a SHA256 hash, the program searches a wordlist (sourced from the rockyou dataset) and attempts to match it against the hash — including common password variations like mixed casing and leet-speak substitutions.

## How It Works

For each word in the dictionary, the cracker tries the following in order:
1. **Exact match** — the word as-is
2. **Case variations** — all combinations of upper/lowercase letters (e.g. `password` → `paSSwoRd`)
3. **Leet-speak substitutions** — symbol/number swaps for common characters: `a↔@`, `e↔3`, `o↔0`, `i↔1`

## Prerequisites

The program requires OpenSSL. Install it before building:

**macOS (Homebrew):**
```bash
brew install openssl
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install libssl-dev
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install openssl-devel
```

## Installation

```bash
git clone https://github.com/mdang2077/SHA256_pwcracker.git
cd SHA256_pwcracker
make
```

This produces a `./pwcrack` binary in the project directory.

## Usage

```bash
./pwcrack <sha256_hash> [wordlist | word]
```

- `<sha256_hash>` — the target hash, exactly 64 hexadecimal characters. Invalid input is rejected with an error.
- `[wordlist | word]` — optional second argument:
  - If it names an **existing file**, it's treated as a wordlist (one candidate per line).
  - Otherwise it's treated as a **single word** to test directly (still trying case and leet-speak variations).
  - If omitted, the cracker searches the bundled rockyou wordlist (`rockyou_part_aa` and `rockyou_part_ab`).

If the password is found, the program prints the cracked password and exits. If not found, it reports that no match was found.

**Test a single word:**
```bash
./pwcrack 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 password
```

**Using your own wordlist** (one candidate per line):
```bash
./pwcrack 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 mywords.txt
```

## Examples

**Exact dictionary match:**
```
Input:  ./pwcrack 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Output: Found password: SHA256(password) = 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

**Case variation:**
```
Input:  ./pwcrack 9cd00dd3e377d2ee3a4d2432783de680f8bb736031bff686260601b22f7b0e0f
Output: Found password: SHA256(paSSwoRd) = 9cd00dd3e377d2ee3a4d2432783de680f8bb736031bff686260601b22f7b0e0f
```

**Leet-speak substitution:**
```
Input:  ./pwcrack a075d17f3d453073853f813838c15b8023b8c487038436354fe599c3942e1f95
Output: Found password: SHA256(p@ssw0rd) = a075d17f3d453073853f813838c15b8023b8c487038436354fe599c3942e1f95
```

**No match found:**
```
Input:  ./pwcrack 0000000000000000000000000000000000000000000000000000000000000000
Output: Could not find a matching password
```

## Testing

Build and run the unit tests:

```bash
make test
```

This compiles a separate `pwcrack_test` binary (tests gated behind `-DTESTING`) and runs it, printing `ALL TESTS PASSED!` on success.

## Cleanup

```bash
make clean
```