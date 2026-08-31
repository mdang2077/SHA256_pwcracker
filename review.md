# Code Review — SHA256 Password Cracker

Reviewer notes on `pwcrack.c`. Focus: correctness gaps, robustness, and **easy-win
edge-case tests** for the SHA256 cracking logic. Findings are ordered by severity.

> **Note:** The "safe fixes + test harness" batch has already been merged and removed
> from this document — input-hash validation, `\r` stripping, the second-loop
> `fclose`/progress fix, the `-Wpointer-sign` cast, `-Wall -Wextra`, the misleading
> test comments, and a `make test` target. The items below are what remains to review.
> Line numbers below refer to the original `pwcrack.c` at commit `b2edf22` and may have
> shifted.

---

## 1. Correctness bugs & coverage gaps

### 1.1 Combined case + leet variations are never tried (coverage gap) — HIGH
`crack_password` runs three **independent** passes: exact → case-only → leet-only. It
never combines them, so a password that mixes an uppercase letter *and* a leet
substitution cannot be cracked.

- `P@ssw0rd` (uppercase `P` **and** `@`/`0`) is unreachable from dictionary word
  `password`. `check_case_variations` only ever emits `a`/`@`-free case combos;
  `check_special_variations` only ever emits lowercase-cased leet combos.
- The README ("Leet-speak substitutions") implies this class is covered — it is not.
- **Verify:** `SHA256(P@ssw0rd) = b03ddf3ca2e714a6...`; feeding that hash returns
  "Could not find a matching password" even though `password` is in the wordlist.

### 1.2 Integer-shift undefined behavior on long words — HIGH
`int total_variants = 1 << alpha_count;` and the identical line in
`check_special_variations` shift a signed `int` by `alpha_count`. For
`alpha_count >= 31` this is **undefined behavior** (shift ≥ width / sign-bit
overflow); at 32+ it wraps to nonsense loop bounds.

- Measured against the shipped wordlist: **809 words in `rockyou_part_aa` have ≥31
  alphabetic characters.** These trigger UB in the case pass every run.
- Fix direction: cap variant expansion, use `unsigned long long`, and guard
  `alpha_count`/`special_char_count` before shifting.

### 1.3 Combinatorial explosion / effective hang — HIGH
Case expansion is `2^alpha_count` SHA256 calls **per dictionary word**.

- **54,946 words in `rockyou_part_aa` have >16 letters** → ≥131,072 hashes each; a
  20-letter word costs 1,048,576 hashes. A single such word can dominate runtime.
- This is also a denial-of-service surface: any moderately long dictionary word
  stalls the search. Needs a hard ceiling on `alpha_count` (e.g. skip/limit words
  beyond N transformable chars).

### 1.4 Reverse-leet and pre-substituted words unhandled — LOW
`isSpecial` flags `@`,`3`,`0`,`1` as special, but `check_special_variations` has no
branch for them (`tolower('@')` is `'@'`, matches no `if`). Effect:
- A wordlist entry already containing `@`/`3`/`0`/`1` wastes mask iterations doing
  nothing (variant unchanged), and reverse mappings (`3`→`e`) are never explored.

### 1.5 Line truncation on long wordlist entries — LOW
`char word[256]` truncates lines >255 chars. The shipped wordlist has lines
**exactly at the 255 cap**, so truncation is actively occurring and the tail is
parsed as a separate bogus word.

### 1.6 Deprecated OpenSSL API — LOW
`SHA256()` is deprecated in OpenSSL 3 (the toolchain here) — consider the
`EVP_Digest` API or an explicit deprecation suppression.

---

## 2. Easy-win edge-case tests to add

Cheap, high-value unit tests (no wordlist needed — call the helpers directly). None
of these have been written yet; a `make test` target now exists to run them.

| # | Test | Why it's a win |
|---|------|----------------|
| 1 | `check_password("", SHA256(""))` → 1 | Empty-string hash `e3b0c442...`; guards zero-length path |
| 2 | Single-char password (`"a"`) exact + case | Smallest non-trivial input |
| 3 | Exact match short-circuits before variations | Assert `crack_password` on an unmodified word returns via the exact check |
| 4 | Leet-only `p@ssw0rd` | `SHA256(p@ssw0rd)=a075d17f...` — regression-locks the leet pass |
| 5 | **Combined case+leet `P@ssw0rd`** | Currently **fails** — encodes bug 1.1 as an xfail/TODO |
| 6 | `hex_to_dec` for `'a'`,`'A'`,`'f'`,`'F'`,`'0'`,`'9'` and invalid `'g'`,`'z'`,`' '` | Locks the 0-fallback in `hex_to_dec` (still present internally) |
| 7 | `hexstr_to_hash` length/validation | CLI now rejects bad hashes via `is_valid_hash`; `hexstr_to_hash` itself still assumes valid input |
| 8 | Uppercase-hex input hash still cracks | `hex_to_dec` uppercases — assert `5E8848...` works like `5e8848...` |
| 9 | Definite no-match returns 0 | e.g. all-zero hash → `crack_password` returns 0, no crash |
| 10 | Word with 0 alpha chars (`"12345"`) | `alpha_count==0`, `1<<0==1` boundary in case pass |
| 11 | All-alpha word length boundary (e.g. 30, 31 letters) | Pins bug 1.2 (shift UB) |
| 12 | Buffer integrity: cracked variant copied back correctly | Assert `password[]` holds the matching variant, unchanged length |
| 13 | `check_special_variations` on a word already containing `@`/`3` | Documents bug 1.4 (no reverse-leet) |
| 14 | CRLF wordlist entry now matches | `\r` is stripped in the read loop; regression-lock that CRLF wordlists crack |

### Verified reference hashes (for the tests above)
```
SHA256("")          = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
SHA256("password")  = 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
SHA256("paSSwoRd")  = 9cd00dd3e377d2ee3a4d2432783de680f8bb736031bff686260601b22f7b0e0f
SHA256("p@ssw0rd")  = a075d17f3d453073853f813838c15b8023b8c487038436354fe599c3942e1f95
SHA256("seCret")    = a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd
```

---

## Summary

- **Fix first:** shift UB (1.2) and the case-expansion explosion (1.3) — both
  reproduce on the shipped wordlist today.
- **Coverage gap to acknowledge:** combined case+leet (1.1) is a real limitation the
  README oversells.
- **Cheapest remaining wins:** add tests #1–#10 above; they need no wordlist and lock
  in current behavior before any refactor.
