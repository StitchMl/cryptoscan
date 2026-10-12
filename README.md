# cryptoscan

`cryptoscan` inspects CTF Jeopardy cryptography artifacts without network access, AI, or required runtime dependencies. It reports evidence, exploit preconditions, a computed solver payload, an attack path, and a repair for each finding.

Use it only on CTF challenges and systems you may test.

## Detectors

- RSA shared primes across the input corpus
- RSA `e=3` exact-root plaintext recovery
- Fermat factorization for close RSA primes
- RSA common-modulus plaintext recovery
- Hastad `e=3` broadcast recovery across three pairwise-coprime moduli
- Wiener recovery of unsafe small RSA private exponents
- DSA/ECDSA repeated-nonce private-key recovery
- single-byte XOR recovery and reused XOR/stream keystream evidence
- repeated ECB blocks at 16-byte and 8-byte boundaries
- CTR, GCM, and ChaCha-family nonce reuse for a matching key identifier
- source patterns for MD5/SHA-1, secret-prefix hash MACs, ECB, constant nonces, Mersenne Twister, and time-seeded PRNGs
- hardcoded keys and non-cryptographic `random` calls used for keys, nonces, tokens, or OTP material

The scanner calculates factors, plaintext roots, Bezout coefficients, XOR combinations, candidate keys, and recovered plaintext when the available evidence permits it. A source match alone receives lower confidence.

## Install and run

Python 3.10 or newer is required.

```console
python -m pip install .
cryptoscan challenge.py artifacts.json
cryptoscan ./challenge --format json > report.json
cryptoscan ./challenge --fail-on-findings
```

Run from a checkout without installing:

```console
$env:PYTHONPATH = "src"
python -m cryptoscan ./fixtures
```

Text output uses color only on a terminal. Set `NO_COLOR=1` or pass `--no-color` to disable it. JSON output never includes ANSI escapes.

`--fermat-steps` controls a bounded deterministic search. Its default is `100000` iterations per modulus.

## Accepted artifacts

The scanner walks files in sorted order. It parses JSON objects recursively and simple Python-style assignments such as:

```python
n = 0xc34f...
e = 3
c = 123456...
```

Byte strings may use hexadecimal, `0x`-prefixed hexadecimal, Base64, or JSON byte arrays. Structured nonce-reuse checks understand fields such as `mode`, `key_id`, `nonce` or `iv`, and `ciphertext` or `ct`.
The parser also accepts Python byte literals and common `key: value` challenge dumps.
It scans text members inside ZIP, TAR, TAR.GZ, TAR.BZ2, and TAR.XZ archives without extracting them to disk. Per-member and entry-count limits bound archive processing.

## Stable reports

Finding IDs derive from rule, relative location, and evidence. Reports omit timestamps, scan duration, and absolute input paths. Sorting does not depend on filesystem enumeration order.

## Limits

`cryptoscan` performs bounded static and corpus analysis. It does not execute challenge code, connect to services, guess arbitrary encodings, disassemble binaries, or prove that a matched source line is reachable. Findings marked `certain` include a mathematical verification, such as exact roots, recovered factors, signature-equation checks, or ciphertext re-encryption. Heuristic source and language findings use lower confidence. Confirm them against challenge behavior and the stated preconditions.

## Development

```console
python -m pytest
```
