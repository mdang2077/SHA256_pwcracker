# Code Review — SHA256 Password Cracker

Reviewer notes on `pwcrack.c`. All findings from the original review have now been
addressed; this file is kept as a resolution log. New findings can be added below.

## Resolved

**Safe fixes + test harness**
- Input-hash validation (`is_valid_hash`) — rejects non-64 / non-hex input.
- `\r` stripping on wordlist lines.
- Second-loop `fclose` + progress dots (search unified into `search_wordlist`).
- `-Wpointer-sign` fixed; builds with `-Wall -Wextra`.
- Corrected misleading test comments; added a `make test` target.

**Correctness bugs & coverage gaps**
- **1.1 Combined case + leet** — the three independent passes were replaced with a
  single mixed-radix generator (`char_options` + `crack_variations`), so mixed
  case+leet passwords (e.g. `P@ssw0rd`) are now cracked.
- **1.2 Integer-shift UB** — variant counts use `unsigned long long` with a
  divide-guarded multiply; no signed shift remains.
- **1.3 Combinatorial explosion** — per-word ceiling `MAX_VARIANTS = 1 << 20`; words
  exceeding it fall back to an exact-match check only, bounding runtime.
- **1.4 Reverse-leet / pre-substituted words** — `@`/`3`/`0`/`1` map back to their
  base letter's options, so wordlist entries already containing leet symbols are
  handled.
- **1.5 Line truncation** — wordlist buffer raised to 4096 and over-long lines are
  drained + skipped so a truncated tail is never parsed as a separate word.
- **1.6 Deprecated OpenSSL API** — hashing moved from `SHA256()` to
  `EVP_Digest`/`EVP_sha256()`.

**Edge-case tests** — the 14 tests from the original section 2 were added and are wired
into `make test` (empty string, single char, exact short-circuit, leet-only, combined
case+leet, `hex_to_dec` fallbacks, `is_valid_hash`, uppercase-hex input, no-match,
non-transformable input, length boundary/cap, buffer integrity, reverse-leet, CRLF).

## Notes / follow-ups

- With `MAX_VARIANTS = 1 << 20`, a *non-matching* full-wordlist scan is slower per word
  (long words can expand toward ~1M variants each). Correct and bounded, but not fast
  on a guaranteed miss — revisit the ceiling if scan latency becomes a concern.

## Open

_None._
