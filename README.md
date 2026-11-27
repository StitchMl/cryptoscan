# cryptoscan

## Scan challenge files or a challenge URL

CryptoScan accepts local files, directories, archives, and an HTTP(S) challenge
URL. Passing a URL selects it as the scan target; no extra authorization flag is
needed. For a page, it reads the page and follows a
bounded set of same-origin links that look like downloadable challenge
artifacts; it does not submit probes or follow redirects. The URL fetch uses
the same destination validation as online CTF connections, and local lab
addresses require `CRYPTOSCAN_ALLOW_PRIVATE_NETWORK=1`.

```powershell
cryptoscan .\challenge.zip --plan-attacks
cryptoscan https://ctf.example/challenge/ --plan-attacks
```

The existing offline codecs, source recognizers, and attack planners still
decide what can be identified or solved. An unsupported construction remains
unresolved and is not treated as a successful recovery.

## Public-residue multiplicative exchange

Some key-exchange-like CTF ciphers publish a private value modulo a
public modulus and later use that private value only inside a multiplication
reduced modulo the same modulus. CryptoScan parses the Python source to
prove the residue relation, derive the shared-key monomial from the
exchange statements, and confirm that encryption multiplies the message
by that key as an ordinary integer (without ciphertext reduction).

The solver joins the source to a same-scope transcript containing the
modulus, two public residues and ciphertext. It reconstructs the shared
key, requires exact integer divisibility, decodes the source's byte order,
and checks a flag-shaped plaintext with a ciphertext round trip. Variable
names and multiplicative coefficients in the exchange can differ; no
challenge-specific key or plaintext is stored in the solver.

```powershell
cryptoscan chall.py output.txt --plan-attacks
cryptoscan chall.py output.txt --solve
```

The recognizer rejects ambiguous transcripts, unsupported formulas and
modular ciphertext encryption. A transcript without source evidence is
insufficient.

## Sparse MT19937 output prediction

Some CTF services reveal a sequence of Python `random.getrandbits(32)`
outputs while allowing the client to choose two output indices. When the
source establishes a consecutive stream and a target draw at least one
MT19937 period beyond the seed state, the twist recurrence can recover that
target from two strategically selected outputs. CryptoScan derives the
indices from the source's output count, reverses output tempering, computes
the recurrence, and submits the prediction through the explicitly supplied
remote endpoint.

The solver is source-gated on 32-bit outputs and a bounded generated
sequence; it does not execute challenge code or store challenge-specific
outputs. It currently supports services that prompt with `number!\n`,
accept two indices on separate lines, return the generated sequence as
one integer per line, then accept the predicted value.

```powershell
cryptoscan challenge.py --solve --host archive.cryptohack.org --port 63222
```

## Recursive Cantor pairing of byte sequences

CryptoScan recognizes Python source that recursively combines byte values
with Cantor's pairing function, using the source's half-length split. A
published decimal integer can appear as a numeric comment in the source,
in a separate plain-text file, or in an output assignment. The solver does
not execute the challenge source. It uses integer square roots to undo each
pairing, tries byte lengths from 2 to 256, checks a printable CTF flag
shape, and re-encodes the result to verify the exact published integer.
Ambiguous or unsupported inputs do not produce a flag.

```powershell
cryptoscan challenge.py --plan-attacks
cryptoscan challenge.py --solve
cryptoscan generator.py output.txt --solve
```

The source and output must be in the same challenge scope. The method
applies only to a source-verified recursive Cantor encoder over bytes;
an arbitrary large integer alone is insufficient evidence.


## RSA factors from reused base digits

CryptoScan recognizes RSA source that draws a candidate factor, renders its
digits in a source base from 2 through 36, and interprets that string in
a target base up to 36 that is at least as large, to form the other factor.
The usual implicit decimal target is supported. It checks the prime tests, factor product,
and encryption expression from the Python AST without running the generator.
The draw may use `random.getrandbits`, `secrets.randbits`, or
`Crypto.Util.number.getPrime`; import aliases and literal base variables
are supported. The finding identifies the source base, decimal target base,
prime width, and whether a matching same-scope modulus is present.

This is an **analysis-only** finding in `--plan-attacks`. It does not
recover factors or a plaintext through `--solve`. A source file by itself
still gives a useful finding, while a modulus from another scope or
ambiguous public transcripts are not attached to it. The appropriate
remediation is to regenerate both RSA primes independently with fresh
cryptographic randomness and rotate affected keys.

```powershell
cryptoscan generator.py output.txt --plan-attacks --format json
```

## Weak-seeded RSA and partial CRT recovery

CryptoScan recognizes RSA prime generation built from a deterministic
pseudorandom generator initialized with a bounded-entropy seed. The
source-derived model includes the seed-width progression, prime sampling
method, public exponent and an explicit plaintext-size upper bound.
Known candidate primes are regenerated and tested by exact divisibility
of the public modulus; no factor or seed from a named CTF is embedded.

**Full factorization is not necessary.** For recovered factors p_i,
the solver reconstructs the message residue modulo each p_i and combines
those values with CRT. If their product M exceeds the source-proven
message upper bound, the entire plaintext is uniquely determined.
The result must pass partial RSA re-encryption and CTF text validation.

Supported PRNG sampling variants include getrandbits, _randbelow and
randrange, plus intermediate seed/prime assignments and alternative
product-comprehension structures. The source weakness is reported even
without a ciphertext, but solving remains gated on matching public data.

Use `cryptoscan . --plan-attacks --format json` to inspect the candidate
family, or `cryptoscan . --solve --seed-search-limit 16384` to explicitly
increase the bounded search budget. The default is 4096 seeds.

### Scope

The attack only applies when limited entropy makes some factor seeds
enumerable and when enough recovered factors exceed a known message
bound. Other RSA constructions cannot be assumed vulnerable.

## Biased Shamir secret-sharing: candidate elimination and CRT

Shamir's information-theoretic secrecy assumes uniformly random
nonconstant polynomial coefficients over the entire field F_p. A
half-open sampler such as getRandomRange(0, p-1) excludes p-1 and
breaks that assumption. Given one fewer share than the reconstruction
threshold, each possible secret determines the missing polynomial
degree of freedom. Coefficients forbidden by the sampler eliminate
candidate secrets. Repeated independent polynomials with the same
constant term allow safe candidate intersection.

CryptoScan separates a generic finite-field core from an optional
source-verified TCP adapter. The core accepts arbitrary distinct
nonzero share coordinates and an arbitrary count of excluded high
field elements, rather than a stored instance or CTF-specific indices.
After one residue becomes unique modulo each small prime, the solver
combines independently recovered residues by CRT. It submits a secret
only when the product of the resolved prime fields strictly exceeds
the source-derived bit bound on the secret.

The remote adapter first verifies that the source reuses one secret,
creates independently randomized sharing polynomials, publishes all
but one share, and lets the client choose prime-field parameters. It
recognizes the semantics of bounded inclusive and exclusive random
sampling APIs and records the original public input/output labels.

```powershell
cryptoscan server.py
cryptoscan server.py --plan-attacks --host HOST --port PORT
cryptoscan server.py --solve --host HOST --port PORT --timeout 60
```

The server's own execution time limit may be shorter than the CLI
socket timeout; the solver respects source-derived deadlines where
possible. This attack is not applicable to uniformly sampled
polynomials or to transcripts without a fixed secret across queries.

## Cyclotomic related-prime RSA via finite-field extension

CryptoScan can detect RSA modulus constructions with a factor pair
`p` and `Q(p) = 1 + p + ... + p**(d-1)`, also recognized in
the equivalent expression `(p**d - 1) // (p - 1)`. This property
implies `Q(p) | (p**d - 1)`: in a degree-`d` finite-field extension
modulo `p`, exponentiation by the public modulus removes the
`Q(p)`-order component. Quotient-ring calculations over `Z/NZ`
then yield nonconstant coefficients divisible by `p`, allowing
its extraction by a GCD with `N`.

The solver explores bounded independent monic quotient polynomials,
checks every proposed factor with exact integer division, verifies the
relation `Q(p)`, checks primality of all recovered factors, decrypts
RSA, and validates re-encryption. Neither factors nor message
constants from any known challenge are incorporated. The detector
uses source ASTs and links the inferred construction to the
public `N,e,c` transcript; variable names and import aliases are
derived rather than fixed.

```powershell
cryptoscan challenge.py output.txt
cryptoscan challenge.py output.txt --plan-attacks --format json
cryptoscan challenge.py output.txt --solve
```

Source-only scans can report the algebraic relation even when
the public transcript is missing. The method is **conditional**:
if the prime relation is absent, the extension is reducible for
the chosen trials, or the model cannot verify factors, CryptoScan
will not claim recovery. This is not generic RSA factoring.

## Modular-noise LWE mixtures: noiseless projection and block RANSAC

An LWE-like source may sample its additive error from a **proper additive
subgroup**, rather than from a distribution with full support modulo the
public modulus. For example, left shifting the noise by `t` bits and
subtracting an offset divisible by `2**t` forces the error to vanish
modulo `2**t`. Every authentic sample then leaks an **exact linear
equation modulo `2**t`**.

The scanner derives the key length, sample modulus, noise divisibility,
real-versus-decoy ordering, observations per secret bit, and the bit
packing order from Python AST. The solver uses block-wise RANSAC over
`GF(2)` and lifts key residues bit by bit for higher powers of two.
Coherent observation blocks reveal the selected message bits without
reconstructing the original full-precision key. Different variable
names, sample counts, secret lengths, shift counts and sampler order
are supported; no flag or key from a known challenge is embedded.

```powershell
cryptoscan challenge.py output.txt
cryptoscan challenge.py output.txt --plan-attacks --format json
cryptoscan challenge.py output.txt --solve
```

The output is statistical, **not a perfect membership oracle**: an
independent decoy block may accidentally satisfy every modular
equation. For `k` independent samples projected modulo `2**t`,
its chance is `2**(-t*k)`. The tool checks for strong cross-block
consistency and a plausible decoded text token, but ambiguous cases
can require more observations or independent validation. It must not
claim that this attack applies to ordinary full-support LWE errors.

## Chosen-coordinate elliptic-curve quadratic-twist attacks

An x-only elliptic-curve scalar multiplier can often operate on two
groups: its intended short-Weierstrass curve and its **quadratic twist**.
A program that accepts arbitrary `x` inputs, constructs `(x, 1)`
as a projective point, and uses a secret scalar **without checking curve
membership** can therefore reveal that scalar modulo factors of the
twist's order. A prime-order *main curve* does not protect against
a weakly factored twist.

CryptoScan's source analyzer identifies untrusted x-coordinate flow
into the projective ladder, the public field and Weierstrass
coefficients, optional published curve order, and input checks.
The generic mathematical core selects a twist point of verified
order, derives its associated x-coordinate, collects one
authorized oracle response, and applies bounded subgroup discrete
logarithms, Pohlig-Hellman and CRT. Every recovered scalar residue
is validated against the oracle point, and both possible signs
are retained because x-only responses identify P and -P.

```powershell
cryptoscan twist_source.py
cryptoscan twist_source.py --plan-attacks --format json --host HOST --port PORT
cryptoscan twist_source.py --solve --host HOST --port PORT --timeout 60
```

The scanner flags source-only weaknesses. The planner additionally
requires a prime field, either a supplied main-curve order or a
small-field order computed by bounded point counting, a feasible twist
factorization, and a verified full-order twist point. Large-field
point counting without source-provided order requires another backend.
For a secret longer than the twist order, the recovered scalar is
**only a residue**, not necessarily the original secret; decoding
must be unique under explicit source-derived encoding constraints.
Unknown or ambiguous cases fail rather than fabricating a flag.

## Hyperelliptic Jacobian state disclosure and analysis-only attack plans

CryptoScan recognizes Sage hyperelliptic curves and Jacobian-based stream
generators whose internal Mumford divisor coefficients are serialized
and XORed directly with input data. A **chosen-zero plaintext** query
then discloses a complete binary state, not merely a generic stream
cipher ciphertext.

If a state contains the Mumford pair `(u(x), v(x))` on a curve
`y**2 = f(x)`, it satisfies `f(x) == v(x)**2 (mod u(x))`.
The finite-field algebra in `hyperelliptic_state_leak.py` unpacks
the coefficient bytes (with source-derived word width and byte order),
collects equations from independent states and reconstructs a hidden
curve polynomial of source-derived degree whenever the equations have
full rank. The result is verified against every observed pair.

The Sage normalizer handles polynomial-ring declarations and distinguishes
Sage power `^` from Sage bitwise XOR `^^` without executing source.
Source recognition relies on AST dataflow from group state through
binary packing to the XOR, not on the challenge's filename, field prime,
class name, genus, multiplier or known suffix.

```powershell
cryptoscan chall.sage
cryptoscan chall.sage --plan-attacks --format json --host HOST --port PORT
```

The report distinguishes `status: "analysis-only"` (an analytical
family) from `status: "applicable"` (a source-verified executable attack).
The full-result solver only returns a flag when the captured transcript
provides a **unique verified** Mumford-state completion.

```powershell
cryptoscan chall.sage --investigate --host HOST --port PORT --format json --timeout 60
cryptoscan chall.sage --solve --host HOST --port PORT --timeout 60
```

The opt-in `--investigate` workflow connects once to the authorized
service, captures its source-defined public ciphertext, queries a chosen
zero plaintext to reveal several consecutive complete Jacobian states,
and reconstructs the hidden curve polynomial by finite-field linear
algebra. This yields a useful report even without any flag recovery.

The conditional last stage uses the source-defined **known-plaintext
suffix**. If it reveals all coefficients of the first state's Mumford
`v(x)`, then `u(x)` is a monic degree-`g` divisor of
`f(x) - v(x)**2`. The solver enumerates bounded finite-field factors,
reconstructs candidate keystreams, and validates all known plaintext
bytes and CTF text syntax. A plaintext is returned only if precisely
one candidate passes. This factor method is generic over the field,
genus, coefficient width and polynomial; it is not tied to a specific
source, fixed scalar, ciphertext or flag.

**Limit:** a suffix that exposes only *part* of `v(x)` does not meet
these preconditions. The analyzer then still returns the recovered
curve and an explicit partial result, not a fabricated plaintext.
Reconstruction of the hidden curve is mathematically distinct from
full recovery of a partially observed unknown divisor. A general
solver for that latter case remains a separate problem.

## Reciprocal-Rabin CRT fault oracles

CryptoScan recognizes a family of chosen-ciphertext faults in
reciprocal-Rabin cryptosystems. Encryption maps an invertible message
`m` to the modular reciprocal expression `r = m + c/m (mod N)`
with two auxiliary bits selecting the unique inverse. Decryption
recovers roots of `X**2 - r*X + c` separately modulo the factors of
the RSA-like modulus and combines the results by CRT.

When an implementation does not check that the quadratic root
exists modulo *both* primes, a chosen ciphertext can cause an
incorrect CRT component. A decrypt-then-reencrypt service then
exposes two different values of `r` for the same chosen input.
Their difference is often divisible by exactly one hidden prime.
Pairwise GCDs of independently obtained differences recover both
factors, **even if the public modulus is not explicitly supplied**.

After the factorization, the root-sum identity provides an elementary
linear congruence for the reciprocal parameter `c` modulo each
prime. The solver CRT-combines those residues, derives candidate
plaintext roots of the captured secret ciphertext and **verifies
the result by full re-encryption**, including both disambiguation
bits. The attack stops if the recovered factors, constant or
plaintext fail their mathematical certificates.

The AST recognizer traces the reciprocal encryptor, independent
private-factor root inversions, CRT recombination, the visible
decrypt/re-encrypt dataflow and the exception response. It derives
the source's key-size, ciphertext field labels, source input separator
and wire prompts rather than requiring one challenge's identifiers.
Bounded symbolic propagation recognizes temporary assignments and
commuted reciprocal terms, and resolves trusted modular inversion
libraries (Python's pow, gmpy2, SymPy and Crypto.Util.number, including
import aliases) while rejecting shadowed functions.

The response decoder accepts named integer fields printed on separate
lines, dataclass-style repr records, or JSON/dictionary records.
Missing or repeated fields are rejected. The probe collector uses any
two distinct successful selector responses, even if another selector
returns an error. Input delimiters parsed from source include commas,
semicolons, colons, pipes and whitespace. The adapter also supports
JSON-array requests when the source directly unpacks three elements
from `json.loads(input(...))`. JSON-object inputs, arbitrary schema
transformations and generic binary protocols remain out of scope until
a source-verified adapter is available.

```powershell
cryptoscan server.py
cryptoscan server.py --plan-attacks --format json --host HOST --port PORT
cryptoscan server.py --solve --host HOST --port PORT --timeout 60
```

Network access is always opt-in. A source-only scan can report the
potential design flaw without sending requests. The executable attack
depends on observing independent nontrivial re-encryption differences,
so some valid reciprocal-Rabin implementations will not be exploitable
by this solver.

**Generalization and validation boundary:** the scanner now verifies
the quotient-ring root extraction identity, sources the Jacobi symbol
from a recognized cryptographic library (including aliases), and
distinguishes true two-residue CRT recombination from an unrelated
modulo-product calculation. Explicit root-verification guards suppress
the executable finding. Its positive tests use an independently
implemented *working* reciprocal-Rabin source and a separate
mathematical oracle, not fake Jacobi functions or placeholder roots.
Adversarial negative cases cover fake Jacobi functions, unrelated
modular inversions, bogus CRT and rejected roots.

Other quadratic-root algorithms and protocol shapes (JSON transports,
variable numbers of disambiguation bits, different message padding)
are **not automatically supported** by the exact solver. A generic
CRT component-consistency hypothesis may still be emitted for such
sources, without claiming vulnerability or execution. The existing
tests exercise small and medium prime sizes; performance at arbitrary
cryptographic sizes and availability of a usable fault oracle must be
verified separately.

## Readable output and colors

By default the terminal report is a short, color-coded finding summary
(severity, location, recovery status, attack, and flag path). Expensive
details stay available without cluttering every scan:

```powershell
cryptoscan .                       # compact report, automatic terminal colors
cryptoscan . --verbose             # evidence, preconditions, steps, solver data and patches
cryptoscan . --color               # explicitly enable ANSI colors
cryptoscan . --no-color            # clean monochrome report
cryptoscan . --format json         # unchanged structured results for scripts
```

The standard `NO_COLOR` environment variable disables ANSI output.
In PowerShell use `$env:NO_COLOR = "1"` to disable colors, then
`Remove-Item Env:NO_COLOR` to restore them. The guided assistant menu
also uses grouped concise commands instead of repeating long descriptions.

## Offline NTRU folding recovery

The source-verified offline NTRU solver can now be invoked directly:

```powershell
cryptoscan . --solve --bkz-block 20 --lattice-timeout 900
```

For difficult NTRU parameters, **LLL alone is not enough**. CryptoScan
supports a native `fpylll` backend or the `fplll` command-line BKZ
backend. On Windows, `fplll` can run inside WSL Ubuntu and is called
automatically from the isolated worker when BKZ is selected. Install
the one-time dependency inside your existing WSL Ubuntu environment:

```powershell
wsl -e sh -lc "sudo apt-get update && sudo apt-get install -y fplll-tools"
```

A Windows system with no WSL distro must first install and configure
WSL Ubuntu. The worker shows each folding stage, enforces a timeout,
and prints a flag only if a binary sparse private key is validated by
`f*h == g (mod q)` and its plaintext decodes to a flag. Native
`python-flint` provides LLL but not BKZ. The original Origami public-key/ciphertext instance was successfully
recovered and decrypted by the optional BKZ-20 `fplll` integration
benchmark on Ubuntu (GitHub Actions run 44540926120, approximately 4m12s).
This verifies the original instance on that backend, but it does not
guarantee the recovery of arbitrary NTRU challenges or equivalent
performance on native Windows/WSL systems.

## NTRU folding (experimental)

For binary sparse-polynomial NTRU with a composite ring degree, CryptoScan
now has reusable polynomial folding, stage-wise lattice constructions, and
independent key/decryption verification. The guided NTRU workflow offers
`fold` versus `full`; the isolated worker accepts the selected strategy
so Windows can reclaim native LLL memory. This is an **experimental**
attack: successful algebraic primitive tests do not establish that Origami
or arbitrary NTRU instances will yield a private key. Larger degrees may
need advanced lattice reductions; the tool must report failure rather than
fabricate a flag.



## Batch Fiat-Shamir serialization equivocation

CryptoScan also detects a different, **batch** Fiat-Shamir failure mode:
the verifier hashes all commitments before deriving its challenges, but
serializes integer matrices with a delimiter-free concatenation of decimal
strings. The hash input is not injective. With a modular Pedersen commitment
verifier that accepts noncanonical integer representatives, an adversary
can construct two distinct commitments with exactly the same hash preimage:
one opens completely to the public graph, and the other opens a
Hamiltonian cycle. The terminal hash bits determine which valid opening
to send for each of the batch rounds. This is not a preimage attack on
SHA-256 and does not work for securely framed transcripts.

```powershell
cryptoscan . --no-assist
cryptoscan . --solve --host archive.cryptohack.org --port 34597
```

The generic decimal resegmentation and cycle-search primitive is
independently tested; the network adapter activates only after source
verification of batch hashing, ambiguous serialization, absent range checks,
and the two Pedersen verification branches. This supports Hamiltonicity 2, but the detector is not tied to the
name or known flag. The public verifier accepted the complete 128-proof
batch and returned the flag in GitHub Actions run 44545924933. The
full protocol adapter was verified on this specific authorized service;
other challenge instances require their own independent verification.

## Correlation attacks against LFSR stream combiners

CryptoScan can recognize source-defined stream ciphers built from parallel
LFSRs with public feedback masks, repeated output clocks, and a Boolean
combiner. When a same-scope output file exposes known plaintext and
ciphertext, the optional offline solver:

1. derives the Boolean truth table and per-register correlations from the
   source, rather than searching for a challenge name;
2. finds sparse degree-three feedback multiples over GF(2);
3. performs a fast correlation attack to recover biased register states;
4. solves the remaining unknown register bits with packed GF(2) linear algebra;
5. verifies **every available known keystream bit** before attempting to
   recover a flag from the following ciphertext.

```powershell
cryptoscan . --no-assist
cryptoscan . --solve
```

The Hyper512 HITCON benchmark includes the original 32,768 known
keystream bits and randomized independent LFSR states in regression
tests. The solver does not contain precomputed LFSR states, known flag
strings, or challenge-specific feedback polynomials. This attack is
applicable only when the Boolean combiner and polynomial structure
satisfy its mathematical preconditions, and it may require multiple
noise-correction schedules.

## Fiat-Shamir low-entropy challenge grinding

CryptoScan detects a class of noninteractive proof flaws in which a prover
controls a randomized commitment, computes the challenge locally from a
public hash, and can efficiently construct a valid transcript for one
challenge branch. A **generic bounded-grinding primitive** searches for a
suitable commitment; it works independently of graph size, round count,
and user-visible protocol strings.

A currently supported adapter implements Pedersen-committed graph-opening
proofs: it extracts the active graph and public group parameters from the
challenge source, grinds each Fiat-Shamir challenge bit to the full-graph
opening branch, validates the commitment openings, and sends 128 (or the
source-specified number of) proofs to the authorized verifier. No secret
Hamiltonian cycle or known flag is embedded in the solver.

```powershell
cryptoscan . --no-assist
cryptoscan . --solve --host archive.cryptohack.org --port 14635
```

Network access requires `--solve --host --port`. The detector is offline;
the live protocol adapter expects a compatible JSON line-oriented graph
proof server. The original CryptoHack artifacts and independent synthetic
graphs are regression-tested. Live flag recovery must be independently
confirmed against the real service.

## General-purpose scanning and benchmark policy

CryptoScan treats public CTFs as **regression fixtures**, not templates whose
variable names, flags, or command strings should be embedded in detectors.

- **Detection**: static analysis looks for vulnerable cryptographic behavior.
  A detector may identify a vulnerability even when no solver applies.
- **Mathematics**: reusable, independently tested primitives perform finite
  field, lattice, modular, and transcript analysis.
- **Protocol adapters**: online solvers are separate from detection. A known
  network command protocol must be verified before a matching adapter can be
  selected; a detected vulnerability does **not** authorize sending a
  challenge-specific command sequence to an unknown service.
- **Evidence**: a finding remains `validation-only` until a rule-specific,
  independently checked recovery is available. No generated or copied flag
  may be reported as recovered.
- **Multiple challenges**: files with identical bytes are deduplicated within
  the same challenge scope, not across independent challenge directories
  or archives.

`cryptoscan .` is offline. `--solve` explicitly requests an applicable
solver, and `--host/--port` are required for network workflows. Not every
cryptographic challenge can be solved automatically.


## Hidden-state GCM tag oracle (CODEGATE Greatest Common Multiple)

CryptoScan's GCM detector recognizes the behavior of a fixed-nonce tag
oracle with hidden mutable AAD and ciphertext using Python AST analysis.
Renaming source variables or command strings does not change the finding.
The bundled **online adapter** understands only the documented CODEGATE
`tag` / `u1` / `u2` protocol and refuses incompatible command vocabularies.
Ordinary scans remain offline and report `GCM-HIDDEN-STATE-TAG-ORACLE`
as validation-only.

To explicitly run the **authorized** CryptoHack service attack:

```powershell
cryptoscan chall.py --solve --host archive.cryptohack.org --port 2762
```

The workflow solves the service's 26-bit MD5 proof of work, collects
fixed-length GCM tag differences, recovers GHASH subkey H using bit-packed
GF(2) nullspaces, and uses length extensions and linear algebra to
enumerate candidates for the empty-message authentication tag. It sends
one candidate per connection and prints `FLAG: ...` only when the
server actually returns a flag. State guesses and PoW are reattempted
on new sessions as needed. This solver is **experimental**: the
mathematical primitives and simulated protocol are regression-tested,
but the public service has not been end-to-end verified from this
environment. A tag candidate alone is never a recovered flag.


## Source-verified Fischlin witness-discrimination CTF workflow

For the CryptoHack **Fischlin's Transformation** CTF (with its original
`chal.py` and `params.py`), CryptoScan recognizes that the prover selects
the **first** hash satisfying a threshold and reveals a witness selected by
the client. Under the hypothesis that the revealed witness is the real
branch, the client can reconstruct earlier trial hashes. An earlier
successful hash disproves that hypothesis and identifies the other branch.
Uninformative transcripts are skipped, never guessed.

To run against the **authorized** challenge server, opt in to network
access:

```powershell
cryptoscan . --solve --host archive.cryptohack.org --port 3583
```

The solver retries fresh sessions when the 16 attempts in a round produce
no conclusive transcript. It must complete all 64 rounds before it can print
`FLAG: ...`. The approach uses the disclosed witness and is not a
generic attack on Fischlin's transformation or witness indistinguishability.


## Opt-in DGHV chosen-N noise-overflow recovery

CryptoScan can recognize a source-established 128-bit DGHV additive scheme
with positive bounded noise and an exposed chosen-N/add/decrypt oracle.
Scanning remains offline. To attack an **authorized CTF** service, specify
the TCP endpoint explicitly:

```powershell
cryptoscan server.py --solve --host archive.cryptohack.org --port 21970
```

The solver collects ciphertexts, uses zero additions to detect the first
noise wraparound for distinct coprime N values, reconstructs the private
modulus with CRT, and prints `FLAG: CSC{...}` only after validating the
128-bit key range and plaintext flag shape. The endpoint is never contacted
without `--solve`; unsupported source models are refused. This is a
source-scoped workflow, not a generic DGHV solver.


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

Select the new `MLWE-REDUCIBLE-RING-QUOTIENT` finding. Choose `file`
to analyze a captured text transcript with `sanitize_mat(A)` and
`sanitize_vec(t)` (base64/gzip encoded). The tool outputs an MLWE
prediction `1` or a uniform prediction `0` and a residual bound.
Choose `tcp` **only for CTF services you are authorized to test**,
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
(0 for LLL only, 2-60 for BKZ). It never invents a flag from the
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

## NTRU memory isolation on Windows

For NTRU degree >32, CryptoScan now starts an **isolated Python worker**
for the expensive native FLINT/fpylll lattice reduction instead of holding
million-entry lattice matrices in the interactive scanner process. The child
exits after the result or a configurable timeout (default 300 seconds), so
Windows releases its native allocations. The parent shows only verified
plaintext candidates; it never imports or retains a reduced lattice matrix.

After the `0` (LLL only) answer, the assistant asks:

```text
Maximum worker duration in seconds [300]:
```

Press Enter for 300 seconds, or choose 1-3600 seconds. A timeout stops the
child process without claiming a flag. If large-instance LLL is too expensive,
choose `N` at the confirmation rather than repeatedly running it. Native
Windows LLL at NTRU n=512 is still computationally demanding and is **not**
guaranteed to recover a private key.

For immediate termination, use Ctrl+C or close the process. If you are
already running an older CryptoScan, quit the terminal process to return
memory before updating. Windows Task Manager can identify an unrelated
Python process that continues to consume resources.

## Modular small-alphabet matrix hashes (Sage)

CryptoScan now distinguishes an RSA public modulus from the unrelated
`n` of a Sage quotient ring (`Zmod(n)`). A standalone `n=256` without
an RSA exponent is not RSA evidence.

When the analyzed source establishes a modular matrix hash of a
truncated base-B encoding over a small alphabet, CryptoScan derives the
matrix dimensions, coefficient modulus, alphabet, block size, original
format regular expression, and output from files in the same scope.
It applies unit-pivot modular elimination, enumerates a **bounded**
number of free alphabet variables, inverts the source-defined radix
encoding, then independently recomputes the complete hash. If exactly
one flag-shaped preimage survives, it reports `flag-recovered` and
prints the candidate in `--assist`.

For a recognized source with `A.txt` and `output.txt`:

```powershell
cryptoscan .\challenge.zip --assist
```

This is a deterministic offline solver, not a hardcoded CTF answer.
The resulting candidate must satisfy both the source-defined format and
the original matrix output. Incompatible encodings, non-unit pivots,
excessively many free variables, missing files and ambiguous candidate
sets remain `validation-only`; no flag is fabricated. The supported
source recognizer currently targets the observed family of base-B,
block-XOR, matrix-hash constructions; it does not solve every linear
code or arbitrary Sage script.

## RSA PKCS#1 v1.5 positive padding-oracle transcripts

The scanner recognizes a source-proven RSA PKCS#1 v1.5 verifier that
returns padding validity, and a matching public RSA key plus a list of
**known-positive** blinded-ciphertext multipliers. Positive results
restrict `m*r mod n` to the interval `[2B,3B)`, where
`B=2^(8*(key_bytes-2))`. These simultaneous modular constraints form
an offline hidden-number/lattice problem. This is **not** a traditional
small-factor or private-exponent RSA attack.

The finding `RSA-PKCS1-V15-POSITIVE-PADDING-LEAK` opens an opt-in
offline solver. It builds a Kannan embedding, applies LLL, and checks
candidate representatives by RSA re-encryption, PKCS#1 v1.5 padding
parsing and all published positive interval constraints. Only
cryptographically validated results are printed as candidate plaintexts.
There is no network access and no hardcoded challenge key or flag.

```powershell
cryptoscan .\\output.txt .\\pubkey.pem .\\source.py --assist
```

The Windows installation already includes `python-flint`; it is the
default lattice backend for substantial transcripts. The attack may
still fail if there are too few positive samples or if LLL does not
expose a close vector; large lattices can require significant CPU/RAM.
The scanner does **not** claim `flag-recovered` merely because the
source contains a padding oracle. It is a separately verified,
opt-in computational step.

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

The scanner walks files in sorted order. It parses JSON objects and arrays recursively and simple Python-style assignments such as:

```python
n = 0xc34f...
e = 3
c = 123456...
```

Byte strings may use hexadecimal, `0x`-prefixed hexadecimal, Base64, or JSON byte arrays. Structured nonce-reuse checks understand fields such as `mode`, `key_id`, `nonce` or `iv`, and `ciphertext` or `ct`.
The parser also accepts Python byte literals and common `key: value` challenge dumps.
It scans text members inside ZIP, TAR, TAR.GZ, TAR.BZ2, and TAR.XZ archives without extracting them to disk. Per-member and entry-count limits bound archive processing.
RSA public keys in PKCS#1 or SubjectPublicKeyInfo PEM and DER form, X.509 certificate keys, OpenSSH `ssh-rsa` keys, and unencrypted PKCS#1/PKCS#8 private keys in PEM or raw DER form are extracted as exact integer parameters. Private-key findings expose decimal `d`, `p`, and `q` for static challenge artifacts; encrypted private keys require a passphrase and are not guessed.

Static encoding recovery also recognizes byte-ordinal arrays in JSON and
bracketed HTML/text challenge statements when the values decode to readable
ASCII and the source supplies an encoding hint or a standard flag-shaped
plaintext. For text payloads it can infer a bounded chain of supported
reversible encodings from unlabeled hex, or Base64 when the statement signals
that encoding. A recovery is reported only when the resulting flag is unique;
ambiguous candidates remain unresolved.

By default, recursive corpus collection skips documentation, notebooks, tests, writeups, solvers, and exploit scripts. Files supplied explicitly are always examined, regardless of their filename or extension. Exact duplicate artifacts across release, server, and archive copies are scanned once. Cross-artifact attacks stay inside one inferred challenge boundary, so unrelated challenge directories do not produce shared-prime, common-modulus, nonce-reuse, or broadcast findings.

## Reducible cyclic-ring signatures (source-derived GLP-like verification)

The interactive resolver recognizes short-secret signatures whose public key
satisfies `t = a*s + e` over a ring `F_q[x]/(x^n - 1)`, when the program
uses a hash-to-polynomial challenge and a coefficient-bounded verifier.
It reads `q`, `n`, the coefficient limits, the public-polynomial wire
encoding and message from the provided source; no fixed cyclotomic factors
or challenge parameters are bundled.

The Sage worker factors the cyclic modulus over the integers, constructs
small quotient lattices from each factor, attempts embedded-CVP recovery
with LLL (or the optional external `flatter` reducer), and reconstructs
the short private key with CRT. The Python frontend verifies the entire
public-key relation, recomputes a valid signature, and submits it using
source-derived prompts. This is a **potentially expensive technique**, not a
universal guarantee: factors of large degree, inadequate lattice reduction
or nonstandard serialization can prevent recovery.

On Windows, invoke CryptoScan **from PowerShell** as usual; the algebraic
worker runs automatically under an existing SageMath installation in WSL:

```powershell
cryptoscan . --no-assist
cryptoscan . --solve --host <authorized-host> --port <port> --timeout 600
```

For medium and large quotient lattices, the solver preflights an accelerated
reducer **before opening the remote connection**. It prefers `flatter` and
otherwise tries the packaged `fplll` executable. To install the latter,
run `sudo apt update && sudo apt install -y fplll-tools` in Ubuntu WSL.
Verify from PowerShell using `wsl --exec which fplll`.
For more demanding instances, compile `flatter` from the
[upstream installation instructions](https://github.com/keeganryan/flatter).
Small lattices can fall back to Sage LLL; an explicit
`CRYPTOSCAN_SLOW_LLL=1` setting in the worker's WSL environment can
allow a slower fallback for large lattices, potentially exceeding the service
deadline. The remote resolver bounds lattice work to leave time for proof
submission, reports the failing factor and surfaces reducer errors.

Synthetic tests cover the source-independent detector, algebraic forgery,
backend preflight and JSON/TCP adapter; successful recovery on live Sage
lattices must still be verified per parameter regime.

## Offline recovery of message-masked EC signatures

CryptoScan supports a source-verified recovery pattern in which one genuine
elliptic-curve signature is hidden among random signature-shaped decoys. The
signing relation permits reconstructing a point from each candidate and the
public key; its coordinate masks a reversibly encoded secret. An independent
hash relation identifies the authentic candidate before any expensive KDF is
invoked. The recovered material is then passed to a source-derived KDF and
symmetric cipher profile.

The scanner derives the finite field, curve coefficients, generator, group
order, coordinate transformation, message-expansion domains, salt, KDF
parameters and cipher nonce from the supplied source. It does not use known
flags, hardcoded challenge constants or filenames, and accepts candidate
transcripts in separate files within the same scope.

```powershell
cryptoscan . --no-assist
cryptoscan . --solve
```

The offline solver requires `bcrypt` and `pycryptodome`, which are installed
as project dependencies. A high KDF work factor can make the final decryption
significantly more expensive than identification of the authentic signature.
Source-inferred compatibility does not establish exploitability until a
candidate passes the independent hash check and the decrypted plaintext
passes validation.

## Source-independent detection and exploratory hypotheses

CryptoScan distinguishes three levels of evidence:

1. **Cryptographic mechanisms**: content-derived hypotheses suggest checks such as nonce reuse, transcript consistency, signature-inlier search, or proof malleability. These are not confirmed vulnerabilities and never authorize network solvers.
2. **Source-verified weaknesses**: a detector validates the relevant algebraic relationships, regardless of arbitrary source filenames, extensions, or variable names it can infer. The finding must include evidence from actual data or code.
3. **Verified solver profiles**: a network attack is dispatched only when a compatible protocol and input constraints have been established. Some historical adapters still require specific wire semantics or message encodings; detecting a cryptographic family alone does not mean every implementation is automatically solvable.

Source recognition now uses parsed Python or Sage-compatible code and Rust grammar where possible. Source/output correlation is restricted to the same challenge scope; ambiguous multiple candidates are not silently resolved by picking the first file.

On Windows PowerShell:

```powershell
cryptoscan . --no-assist
cryptoscan . --verbose
cryptoscan . --solve --host <authorized-host> --port <port>
```

The default text report can show **unverified attack hypotheses even when no confirmed weakness has been established**. Hypotheses do not change the status or confidence of the security findings, and do not appear in machine-readable JSON reports.

## Stable reports

Finding IDs derive from rule, relative location, and evidence. Reports omit timestamps, scan duration, and absolute input paths. Sorting does not depend on filesystem enumeration order.

## Limits

`cryptoscan` performs bounded static and corpus analysis. It does not execute challenge code, disassemble binaries, or prove that a matched source line is reachable. Automatic encoding inference is limited to supported reversible codecs and only reports a unique verified result; it does not infer arbitrary custom transformations. Findings marked `certain` include a mathematical verification, such as exact roots, recovered factors, signature-equation checks, or ciphertext re-encryption. Heuristic source and language findings use lower confidence. Confirm them against challenge behavior and the stated preconditions.

## Development

```console
python -m pytest
```
