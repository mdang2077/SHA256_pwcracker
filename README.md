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
./pwcrack <sha256_hash>
```

If the password is found, the program prints the cracked password and exits. If not found, it reports that no match was found.

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

## Cleanup

```bash
make clean
```