# cryptoscan

`cryptoscan` inspects CTF Jeopardy cryptography artifacts without network access, AI, or required runtime dependencies. It reports evidence, exploit preconditions, a computed solver payload, an attack path, and a repair for each finding.

Use it only on CTF challenges and systems you may test.

## Detectors

- RSA shared primes across the input corpus
- RSA exact and bounded wrapped low-exponent plaintext recovery for `e=3`, `5`, `7`, `11`, and `17`
- Fermat factorization for close RSA primes
- RSA small-factor recovery by trial division and bounded Pollard's rho (weak or smooth moduli only)
- RSA common-modulus plaintext recovery
- Hastad broadcast recovery for `e=3`, `5`, and `7` across pairwise-coprime moduli
- Wiener recovery of unsafe small RSA private exponents
- RSA CRT-fault factorization from valid and faulty signatures
- DSA/ECDSA repeated or disclosed-nonce private-key recovery
- RSA `p`, `q`, `d`, `dp`, or `dq` leaks with verified factorization or re-encryption
- LCG parameter recovery and next-output prediction from structured output sequences
- MT19937 state cloning and next-output prediction from 624 complete outputs
- small or degenerate finite-field Diffie-Hellman groups with verified discrete-log recovery
- calculated CBC first-block bit flips when known and target plaintext are supplied
- calculated SHA-1 secret-prefix length-extension messages and digests
- single-byte XOR recovery and reused XOR/stream keystream evidence
- repeated ECB blocks at 16-byte and 8-byte boundaries
- CTR, GCM, and ChaCha-family nonce reuse, including exact recovery when one plaintext is known
- CBC IV reuse and compound static padding-oracle indicators
- source patterns for MD5/SHA-1, secret-prefix hash MACs, ECB, constant nonces, Mersenne Twister, and time-seeded PRNGs
- hardcoded keys and non-cryptographic `random` calls used for keys, nonces, tokens, or OTP material

The scanner calculates factors, plaintext roots, Bezout coefficients, XOR combinations, candidate keys, and recovered plaintext when the available evidence permits it. A source match alone receives lower confidence.

Each finding has a recovery status:

- `flag-recovered`: a verified computation produced flag-shaped plaintext in `solver.result_hex`.
- `payload-ready`: the solver contains verified factors, keys, secrets, predictions, or a transformed payload usable under the listed preconditions.
- `validation-only`: the scanner found guidance or a heuristic signal, but not enough proof to claim a usable flag-recovery vector.

The status is derived from rule-specific arithmetic checks. It never upgrades a source-pattern match or an unverified plaintext guess.

Source-pattern findings (for example `NONCE-CONSTANT`, `CIPHER-ECB`) also carry a
`playbook`: an ordered, step-by-step attack procedure for that weakness,
including the actions to run against a live challenge service. The text report
prints it as `Step 1`, `Step 2`, ... and the JSON report exposes it under
`playbook`. The steps are guidance, not a guaranteed solve: an interactive
challenge still needs you to collect ciphertexts and submit the forged value.

## Authentification-1 cookie utilities (offline)

These commands are independent of scanning and target the specific custom AES-GCM
implementation used in the supplied Authentification-1 CTF challenge, **not arbitrary
web session cookies**. Install the optional cryptographic library for `build`:

```powershell
python -m pip install pycryptodome
cryptoscan cookie build --masterkey "00112233445566778899aabbccddeeff" --user demo --role guest
```

Given a cookie plus the known original username and role, the XOR helper can
change its plaintext without recovering the master key:

```powershell
cryptoscan cookie forge --cookie "CIPHERTEXT_HEX;TAG_HEX" --user long_username --role guest --target-role super_admin
```

The modified cookie reuses an **invalid** authentication tag and is only suitable
for challenge verifiers that ignore authentication failure. It requires the exact
known JSON plaintext and enough known ciphertext bytes to cover the replacement.
If a longer role will not fit, the command automatically shortens an ASCII username;
specify `--target-user` to choose one. Neither mode contacts a live service.

The scanner also reports `AEAD-AUTH-RESULT-IGNORED` (critical, static diagnostic)
when a Python function appears to discard the authentication status returned
alongside decrypted plaintext. Confirm the actual method semantics and call path
before treating this result as exploitable.

## Interactive, finding-guided analysis

Run a normal scan in an interactive terminal and, when findings exist, cryptoscan
automatically offers a guided menu. The menu shows each finding's preconditions,
the current solver evidence, and compatible calculations. For scripts, CI, and
redirected output, the menu is disabled by default. Use `--no-assist` to
suppress it in terminals; use `--assist` to request it explicitly:

```powershell
cryptoscan challenge.zip
cryptoscan challenge.zip --assist
cryptoscan challenge.zip --no-assist
cryptoscan assist challenge.zip
cryptoscan assist
```

The standalone `cryptoscan assist` mode works without a scan or a finding.
Its reusable workflows include:

- **e**: collect separately an observed username, password, role, and opaque auth cookie, plus optional target values. Unknown fields remain unknown. This is an evidence worksheet, **not** a semicolon-delimited token parser or a cryptographic solver.

- **t**: inspect semicolon-delimited records without assuming that a field is a
  hash, key, password or GCM tag. It reports the number of fields and whether a
  hexadecimal field has a conventional digest length.
- **r**: rewrite selected delimited fields, then recompute a digest or MAC
  using an *explicitly provided* algorithm, signed-field order, encoding, and
  secret (when required).
- **h**: compute or compare plain digests, secret-prefix/suffix hashes and HMAC
  from known inputs.
- **x**: perform a known-plaintext XOR/stream transformation with aligned
  ciphertext; it does not manufacture an authentication tag.

Selecting a finding displays the corresponding preconditions and existing
scanner solver; for compatible source findings it offers the XOR or digest
workflow. No generic transform is silently assumed valid.

Example of a captured record:

```text
demo;demo;guest;afbbb704b5f8af60f155aa7dfe5c9ec7b5e91228430226bd1f382815e044f6f4daf7d18412
```

The final field is 74 hex characters, not the length of a standard complete
SHA-256 digest. The assistant can inspect its structure and request an exact
digest formula, but it **cannot** derive unknown credentials or a secret MAC
key from this record. Knowing that the desired fields include
`admin` and `super_admin` does not determine the missing values.

Guided workflows are **extensible, not universal**: a finding can be heuristic,
and different CTFs need different solvers, oracles, and evidence. The tool never
claims a verified payload merely because an interactive calculation ran.
The standalone Authentification-1 cookie commands remain available separately.

## Source-grounded assistant (0.8)

The guided assistant now receives the **actual parsed source documents** from the
same scan, including Python code inside ZIP and TAR challenge packages. Selecting
a finding displays the matched source line, containing function, file path and
the existing preconditions. A source-derived token workflow is only proposed
when static analysis identifies **both** a matching JSON-token builder and a
verifier that does not read the authenticated-decryption result in the same
source module and challenge scope.

For the supported JSON/hex-ciphertext/hex-tag recipe, the prompt explains the
inferred plaintext fields, asks for the exact observed username, role and cookie,
then asks for the desired role and optional username. Passwords are not requested
when the recognized token-creation code does not use them. The procedure does
not claim to recover a master key and explicitly warns that an unchanged GCM tag
is invalid. If the known cookie is too short for the target plaintext, the
assistant reports the missing precondition rather than inventing bytes.

Use:

```powershell
cryptoscan "C:\\Users\\matte\\Downloads\\challenge.zip" --assist
```

**Limits:** Source-derived token recipes require an exact supported AST shape.
Other challenges still get their source context and ordinary finding evidence,
but no arbitrary cookie construction is inferred. Static source analysis does
not prove runtime reachability, nor can it infer unknown passwords, keys,
algorithms or remote acceptance. `cryptoscan assist` without an input file
has no source-grounding and remains a manual worksheet.

### Automatic minimal token payloads

When source analysis demonstrates a JSON token builder and a verifier that
rejects a precise inequality (for example `role != "super_admin"`) but ignores
the authentication status, the guided CLI determines which plaintext fields are
actually required by the verifier. It constructs only those fields rather than
retaining optional fields such as a username.

```powershell
cryptoscan "challenge.zip" --assist
```

Select the corresponding `AEAD-AUTH-RESULT-IGNORED` finding, accept the
source-derived workflow, and enter the **observed** plaintext field values and
the complete `ciphertext_hex;tag_hex` cookie. CryptoScan derives the minimum
plaintext dictated by the source and checks whether the known keystream covers
it. It does not ask for unknown admin credentials if the verifier doesn't
read them.

The resulting cookie is a local **candidate**, not a verified remote exploit;
the original tag no longer authenticates the altered ciphertext. This
technique is limited to the observed serialization and source-verified
unchecked-authentication path. With unsupported conditions, the tool will
not guess a token or invent missing bytes.

### HTTP Cookie transport and rule provenance

For source-derived cookie candidates the assistant now prints both the opaque
cookie value and a correctly encoded `Cookie:` header for Burp Repeater. For
example, a token containing an internal semicolon must not be copied into an
unquoted HTTP Cookie field: that semicolon separates cookies. CryptoScan uses
Python's standard `http.cookies.SimpleCookie` encoder and locally verifies a
parser round-trip before displaying the header. The header is only a transport
example, not proof of server acceptance.

The verifier constraint parser does **not** hardcode `role` or
`super_admin`; it derives literal key/expected-value checks from the Python
AST and declines unsupported conditional flows. The current token codec still
recognizes only specific JSON + GCM + hex/ciphertext/tag constructions. It is
not a universal solver for other crypto systems, and tests for that recognized
construction do not imply the target endpoint has accepted the token.

## Additional source-independent guided workflows

The interactive assistant now exposes general-purpose calculations independently
of any particular CTF challenge:

- **RSA (`f`)**: given verified factors `p` and `q`, exponent `e`
  and ciphertext integer `c`, calculate `d`, decrypt and verify
  `pow(m,e,n)==c`. On suitable RSA findings, the assistant also offers
  this path automatically. Factor primality and challenge acceptance still
  need independent validation.
- **CBC IV manipulation (`b`)**: given an original IV, known first
  plaintext block and desired first plaintext block (all 8 or 16 bytes),
  calculate the modified IV and check the XOR identity. Only applies when
  the target has no effective ciphertext authentication.
- **Verified scanner results**: when a finding already contains a
  mathematically verified computed payload, show its hex and, when valid,
  UTF-8 interpretation without asking for values again. This does not
  turn a source-pattern finding into a verified exploit.

The workflows are deterministic and offline. The tool will not invent
missing exponents, prime factors, ciphertexts, keys, plaintext encodings,
authentication tags or remote responses. Each crypto family needs explicit
solver support; arbitrary CTFs are **not guaranteed solvable**.

## Custom GCM counter/tag-mask overlap

When a Python implementation calls the same initial GCTR counter for both
plaintext encryption and GHASH tag masking, CryptoScan reports
`GCM-COUNTER-OVERLAP`. In interactive mode it tries to locate the associated
JSON token serializer and authenticated verifier in the analyzed sources.
If a unique compatible codec is discovered, it asks for **fresh** observed
values and the token `ciphertext_hex;tag_hex`.

The offline solver uses a known first plaintext block to recover the exposed
counter mask, solves the bounded GHASH polynomial over GF(2^128), verifies
each candidate against the captured tag, and constructs candidate tags for
the minimum plaintext required by the source verifier. There may be multiple
algebraically consistent candidates. It also emits correctly encoded HTTP
Cookie headers when the source names a cookie.

```powershell
cryptoscan challenge.zip --assist
```

This is not a generic GCM break: it needs the proven faulty counter reuse,
the expected GHASH arithmetic, aligned known plaintext, matching nonce/key,
a full tag and a supported token serialization. The tool makes no remote
network requests and does not guarantee that any endpoint accepts the
candidates. Correct authenticated GCM is not vulnerable to this workflow.
AES-ECB used solely as an internal block primitive of GCM is not independently
reported as ECB-mode data encryption when this implementation is recognized.

## Sage / Module-LWE quotient-ring distinguisher

CryptoScan recognizes a family of Sage short-secret Module-LWE vs uniform
challenges where the polynomial quotient modulus includes the factor x-1
(for example x^N-1, rather than a modulus that does not vanish at x=1).
It **derives** q, N, the matrix dimensions, eta and the weak ring polynomial
from the analyzed Sage sources, not from any challenge name or flag.

The source-derived attack evaluates each polynomial at x=1, builds the
corresponding modular LWE lattice and applies LLL plus Babai nearest-plane.
It checks the modular relation and compares the residual to a conservative
short-error threshold. This is an evidence-backed statistical classifier,
**not** a universal MLWE solver or a guaranteed result for arbitrary ring
parameters. Numerical and shortness assumptions must hold.

Usage:

~~~powershell
cryptoscan ".\challenge-files" --assist
~~~

Select the new \`MLWE-REDUCIBLE-RING-QUOTIENT\` finding. Choose \`file\`
to analyze a captured text transcript with \`sanitize_mat(A)\` and
\`sanitize_vec(t)\` (base64/gzip encoded). The tool outputs an MLWE
prediction \`1\` or a uniform prediction \`0\` and a residual bound.
Choose \`tcp\` **only for CTF services you are authorized to test**,
and supply the server host and port. It uses the native TCP challenge
protocol, not HTTP, and submits consecutive predictions; it does not
embed a challenge URL, flag or known response. Press Ctrl+C to stop.

The decoder uses bounded gzip decompression and literal parsing,
and the lattice solver runs offline. Python/SymPy are sufficient;
SageMath and an AI connection are not required at runtime. The
current pattern recognizer covers the supported Python/Sage source
structure; other MLWE schemes may require additional structural
recognizers and mathematical solvers.

## Diagnose Python and SymPy on Windows

Use `cryptoscan doctor` to inspect which Python executable is actually
running the console entry point, whether SymPy imports, and whether LLL works:

```powershell
cryptoscan doctor
```

A broken `mpmath` installation may cause SymPy imports to fail with
`No module named 'mpmath.libmp.gammazeta'` **even when pip reports that
SymPy and mpmath are installed**. Repair packages using the same Python
interpreter shown by `cryptoscan doctor`:

```powershell
py -3.12 -m pip install --no-cache-dir --force-reinstall "mpmath==1.3.0" "sympy==1.14.0"
py -3.12 -c "import sympy, mpmath; from sympy import Matrix; print(Matrix([[1,2],[3,4]]).lll())"
```

If different Python installations still conflict, create a virtual
environment with `py -3.12 -m venv .venv` and install this repository
using `.\\.venv\\Scripts\\python.exe -m pip install -e .`. Run
`.\\.venv\\Scripts\\cryptoscan.exe` to use exactly that environment.

## Polynomial NTRU inputs (not XOR ciphertext bytes)

For Sage NTRU sources that establish sparse f/g/r polynomials and
c = p*h*r + m in Z_q[x]/(x^n-1), CryptoScan recognizes the public key
and ciphertext as **coefficient vectors**, not byte strings. It does not
run XOR brute force or generate a CyberChef XOR recipe from such vectors.

With matching public-key and ciphertext coefficient arrays, it can
compute an exact x=1 projection: the source-proven message Hamming
weight modulo q, along with possible integer weights in [0,n].
The finding is `NTRU-X1-HAMMING-LEAK` and remains
**validation-only**: knowing the weight does not reveal the bit positions
or recover the flag. Without matching arrays it emits an NTRU source
diagnostic instead.

The same guard tightens generic repeating-key XOR recognition: a
forged flag-shaped substring embedded in control characters is not
sufficient to label a random byte sequence `flag-recovered`.
Tests cover independent NTRU parameters, the false-positive case,
and a genuine repeating-key XOR ciphertext.

```powershell
cryptoscan .\\output.txt .\\source.sage --assist
```

## Optional complete NTRU key recovery (experimental)

When the source establishes sparse binary NTRU private polynomials and a
matching public key/ciphertext, selecting `NTRU-X1-HAMMING-LEAK` now
offers a **separate, opt-in lattice key-recovery attempt**. It is not just
the x=1 bit-weight projection.

The attack constructs an integer lattice from the public polynomial h and
the source-derived secret key weights df/dg. The constraints force
f(1)=df and g(1)=dg; candidate short vectors must independently verify
f*h=g modulo (x^n-1,q), binary coefficients and the exact weights.
For p=2, the decoder inverts f modulo (x^n-1,2), computes centered
f*c modulo q and maps recovered binary polynomial coefficients to
big-endian bytes in the same order as the source's integer-to-polynomial
encoder. Only a fully verified and printable plaintext is shown.

**Computational limits:** SymPy LLL supports small degrees up to n=32
(included automatically for testing). For larger NTRU instances, including
n=512, the native Windows backend uses `python-flint` for LLL; optional
`fpylll` and `cysignals` are available on supported systems for BKZ. Install them
under Linux/WSL or SageMath if they are not available on your Windows
Python installation. A 1023-dimensional LLL and optional BKZ may require
considerable memory/time and might still find no private key.
The menu asks before starting and optionally accepts a BKZ block size
(0 for LLL only, 2–60 for BKZ). It never invents a flag from the
Hamming-weight leak.

This is a deterministic mathematical method derived from the analyzed
source. It does not contain challenge-specific keys, flag strings or
hardcoded ciphertexts; it is not guaranteed to solve every NTRU
instance or avoid decryption failures.

## Native Windows NTRU lattice backend

CryptoScan installs `python-flint` automatically on Windows x64
(`python -m pip install -e .`). It supplies compiled Windows wheels and
can run native FLINT LLL for NTRU degrees above 32 without WSL, SageMath
or attempting to build `fpylll` from source.

The assistant selects this backend automatically on Windows. Select
`NTRU-X1-HAMMING-LEAK`, agree to try the lattice recovery, and enter
`0` at the optional BKZ prompt for the Windows FLINT LLL backend.
BKZ is **not implemented** by this Windows backend: a positive BKZ
block size is rejected *before* starting a large reduction.

```powershell
cd C:\\ctf\\cryptoscan
git pull --ff-only origin main
py -3.12 -m pip install --upgrade -e .
py -3.12 -c "from flint import fmpz_mat; print(fmpz_mat([[11,17],[13,19]]).lll())"
cryptoscan doctor
cryptoscan "..\\path\\to\\output.txt" "..\\path\\to\\source.sage" --assist
```

NTRU instances with n=512 still require a 1023-dimensional lattice
reduction; native Windows compatibility is *not* a guarantee of a quick
solution or successful private-key recovery. Missing or rejected keys
are never presented as a recovered flag.

## Offline CyberChef recipes

Compatible XOR findings include a structured `cyberchef` object in JSON and a compact recipe in text output. The recipe preserves `From Hex` or `From Base64`, then applies the calculated XOR key. It contains no URL and does not open a browser or transmit data.

Import the emitted recipe and input into a CyberChef instance you run locally. For example, after cloning or downloading CyberChef into `C:\Tools\CyberChef`:

```powershell
Set-Location C:\Tools\CyberChef
npm install
npm run build
```

Open the resulting local build yourself and use **Load recipe**. Keep challenge inputs off public CyberChef instances. The generated object is also suitable for deterministic tooling that consumes CyberChef's JSON recipe format.

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
RSA public keys in PKCS#1 or SubjectPublicKeyInfo PEM and DER form are parsed with a bounded built-in DER reader.

By default, corpus collection skips documentation, notebooks, tests, writeups, solvers, and exploit scripts. Exact duplicate artifacts across release, server, and archive copies are scanned once. Cross-artifact attacks stay inside one inferred challenge boundary, so unrelated challenge directories do not produce shared-prime, common-modulus, nonce-reuse, or broadcast findings.

## Stable reports

Finding IDs derive from rule, relative location, and evidence. Reports omit timestamps, scan duration, and absolute input paths. Sorting does not depend on filesystem enumeration order.

## Limits

`cryptoscan` performs bounded static and corpus analysis. It does not execute challenge code, connect to services, guess arbitrary encodings, disassemble binaries, or prove that a matched source line is reachable. Findings marked `certain` include a mathematical verification, such as exact roots, recovered factors, signature-equation checks, or ciphertext re-encryption. Heuristic source and language findings use lower confidence. Confirm them against challenge behavior and the stated preconditions.

## Development

```console
python -m pytest
```
