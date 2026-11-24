"""Conservative hypotheses from cryptographic *mechanisms*, not challenge names.

Signals are intentionally not Findings: a primitive's presence is not proof
of a vulnerability. The hypotheses guide further analysis when no supported
attack has been established. Never executes user-provided source.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Sequence

from .parser import Document
from .source_units import MAX_SOURCE_LENGTH, parse_python
from .hyperelliptic_state_leak import _sage_tree
from .reciprocal_rabin_oracle import _crt_functions


@dataclass(frozen=True)
class AttackHypothesis:
    family: str
    scenario: str
    next_checks: tuple[str, ...]
    source_count: int


_SIGNATURE_PATTERNS = (
    (re.compile(r"\b(?:EllipticCurve|EccPoint|Ed448|Ed25519)\b"), "elliptic_curve"),
    (re.compile(r"\bHyperellipticCurve\s*\("), "hyperelliptic_curve"),
    (re.compile(r"\.jacobian\s*\("), "jacobian_construction"),
    (re.compile(r"\bstruct\.pack\s*\("), "binary_coefficient_serialization"),
    (re.compile(r"\b(?:secrets\.randbelow|randrange|randint)\s*\("), "random_scalar"),
    (re.compile(r"\b(?:shuffle|sample)\s*\("), "shuffle"),
    (re.compile(r"\b(?:AES\.MODE_CTR|MODE_CTR|ChaCha20)\b"), "stream_encryption"),
    (re.compile(r"\b(?:bcrypt\.kdf|scrypt|pbkdf2_hmac|HKDF)\s*\("), "key_derivation"),
    (re.compile(r"\b(?:Groth16|SNARK|R1CS|Poseidon)\b"), "zkp"),
    (re.compile(r"\b(?:ate_pairing|weil_pairing|tate_pairing)\b"), "pairing"),
    (re.compile(r"\b(?:getPrime|RSA\.generate|rsa\.generate)\s*\("), "rsa"),
    (re.compile(r"\b(?:GF|PolynomialRing|quotient_ring|Zmod)\s*\("), "finite_algebra"),
    (re.compile(r"\b(?:signature|sign|verify|proof)\b", re.I), "authentication"),
    (re.compile(r"\b(?:oracle|PoW|input)\s*\(", re.I), "interaction"),
    (re.compile(r"\b(?:xor|operator\.xor)\b"), "xor"),
    (re.compile(r"\b(?:nonce|IV|counter)\b", re.I), "nonce"),
)


def _signatures(source: str) -> set[str]:
    return {name for pattern, name in _SIGNATURE_PATTERNS
            if pattern.search(source)}


def _calls_named(node, names):
    return isinstance(node, ast.Call) and (
        (isinstance(node.func, ast.Name) and node.func.id in names)
        or (isinstance(node.func, ast.Attribute) and node.func.attr in names)
    )


def _has_modular_power(nodes):
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == "pow"
        and len(node.args) == 3
        for node in nodes
    )


def _has_xor_operator(nodes):
    return any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor)
        for node in nodes
    )


def _has_shuffle_call(nodes):
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr == "shuffle"
        for node in nodes
    )


def _has_gcd_operation(nodes):
    return any(
        _calls_named(node, {"gcd"}) and len(node.args) == 2
        for node in nodes
    )


def _has_computed_output_slice(nodes):
    return any(
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Slice)
        and node.slice.upper is not None
        and not isinstance(node.slice.upper, ast.Constant)
        for node in nodes
    )


def _has_indexed_modular_reduction(nodes):
    return any(
        isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Subscript) for target in node.targets)
        and isinstance(node.value, ast.BinOp)
        and isinstance(node.value.op, ast.Mod)
        for node in nodes
    )


_RANDOM_SCALAR_NAMES = {"getrandbits", "randbits", "randbelow", "randrange"}


def _random_imports(tree):
    random_names = set()
    random_modules = set()
    for imported in tree.body:
        if (isinstance(imported, ast.ImportFrom)
                and imported.module in {"secrets", "random"}):
            random_names.update(
                alias.asname or alias.name for alias in imported.names
                if alias.name in _RANDOM_SCALAR_NAMES
            )
        elif isinstance(imported, ast.Import):
            random_modules.update(
                alias.asname or alias.name for alias in imported.names
                if alias.name in {"secrets", "random"}
            )
    return random_names, random_modules


def _is_random_scalar_call(node, random_names, random_modules):
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Name):
        return node.func.id in random_names
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in _RANDOM_SCALAR_NAMES
        and (isinstance(node.func.value, ast.Name)
             and node.func.value.id in random_modules
             or isinstance(node.func.value, ast.Call))
    )


def _has_sampled_random_scalars(tree, nodes):
    random_names, random_modules = _random_imports(tree)
    return any(
        _is_random_scalar_call(node, random_names, random_modules)
        for node in nodes
    )


def _has_inverse_conjugation(nodes):
    return any(
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Pow)
        and isinstance(node.right, ast.UnaryOp)
        and isinstance(node.right.op, ast.USub)
        and isinstance(node.right.operand, ast.Constant)
        and node.right.operand.value == 1
        for node in nodes
    ) and any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult)
        for node in nodes
    )


def _has_sum_of_scaled_terms(nodes):
    return any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
        and isinstance(node.left, ast.BinOp)
        and isinstance(node.left.op, ast.Mult)
        and isinstance(node.right, ast.BinOp)
        and isinstance(node.right.op, ast.Mult)
        for node in nodes
    )


def _has_hash_key_material(nodes):
    return (any(isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"sha256", "sha512", "blake2b"}
                for node in nodes)
            and any(isinstance(node, ast.Attribute)
                    and node.attr in {"MODE_CBC", "MODE_CTR", "MODE_GCM"}
                    for node in nodes))


def _has_restricted_polynomial_sampler(nodes):
    return any(
        _calls_named(node, {"getRandomRange", "randbelow", "randrange"})
        and len(node.args) >= 1
        and isinstance(node.args[-1], ast.BinOp)
        and isinstance(node.args[-1].op, ast.Sub)
        and isinstance(node.args[-1].right, ast.Constant)
        and type(node.args[-1].right.value) is int
        and node.args[-1].right.value > 0
        for node in nodes
    )


def _has_modular_polynomial_evaluation(nodes):
    return _has_modular_power(nodes) and any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
        for node in nodes
    )


def _has_polynomially_related_primes(nodes):
    # Related prime polynomials may imply nontrivial subgroup orders.
    prime_related = set()
    for assignment in nodes:
        if (isinstance(assignment, ast.Assign)
                and len(assignment.targets) == 1
                and isinstance(assignment.targets[0], ast.Name)
                and any(
                    isinstance(term, ast.BinOp)
                    and isinstance(term.op, ast.Pow)
                    and isinstance(term.left, ast.Name)
                    for term in ast.walk(assignment.value)
                )):
            prime_related.add(assignment.targets[0].id)
    return any(
        _calls_named(node, {"isPrime", "isprime"}) and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in prime_related
        for node in nodes
    )


def _shift_amount(node):
    if not isinstance(node, (ast.BinOp, ast.AugAssign)):
        return None
    if not isinstance(node.op, ast.LShift):
        return None
    operand = node.value if isinstance(node, ast.AugAssign) else node.right
    if isinstance(operand, ast.Constant) and type(operand.value) is int:
        return operand.value
    return None


def _has_shifted_noise_support(nodes):
    return any(
        (amount := _shift_amount(node)) is not None and amount > 0
        for node in nodes
    )


def _has_linear_observation(nodes):
    return any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "sum" and len(node.args) == 1
        and isinstance(node.args[0], (ast.GeneratorExp, ast.ListComp))
        and isinstance(node.args[0].elt, ast.BinOp)
        and isinstance(node.args[0].elt.op, ast.Mult)
        for node in nodes
    )


def _has_power_two_modulus(nodes):
    return any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
        and isinstance(node.right, ast.Constant)
        and type(node.right.value) is int
        and node.right.value >= 4
        and node.right.value & (node.right.value - 1) == 0
        for node in nodes
    )


def _has_projective_x_scalar_arithmetic(nodes):
    return any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "pow" and len(node.args) == 3
        and isinstance(node.args[1], ast.UnaryOp)
        and isinstance(node.args[1].op, ast.USub)
        and isinstance(node.args[1].operand, ast.Constant)
        and node.args[1].operand.value == 1
        and isinstance(node.args[0], ast.Subscript)
        for node in nodes
    ) and any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.RShift)
        for node in nodes
    )


def _has_interactive_chosen_coordinate(nodes):
    return any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "input"
        for node in nodes
    ) and any(
        isinstance(node, ast.While) for node in nodes
    )


def _has_factorwise_crt(tree, crt_combiners):
    # This recognizes repeated calls into a factor-wise computation
    # without assuming the specific root extraction algorithm.
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef):
            continue
        all_calls = [
            node for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        ]
        by_function = {}
        for call in all_calls:
            if call.func.id not in crt_combiners:
                by_function.setdefault(call.func.id, []).append(call)
        if not any(
            len(invocations) >= 2
            and len({
                (arg.value.id, arg.attr)
                for call in invocations for arg in call.args
                if isinstance(arg, ast.Attribute)
                and isinstance(arg.value, ast.Name)
            }) >= 2
            for invocations in by_function.values()
        ):
            continue
        if any(call.func.id in crt_combiners for call in all_calls):
            return True
    return False


_NODE_SIGNALS = (
    ("modular_power", _has_modular_power),
    ("xor_operator", _has_xor_operator),
    ("shuffle", _has_shuffle_call),
    ("gcd_operation", _has_gcd_operation),
    ("computed_output_slice", _has_computed_output_slice),
    ("indexed_modular_reduction", _has_indexed_modular_reduction),
    ("inverse_conjugation", _has_inverse_conjugation),
    ("sum_of_scaled_terms", _has_sum_of_scaled_terms),
    ("hash_key_material", _has_hash_key_material),
    ("restricted_polynomial_sampler", _has_restricted_polynomial_sampler),
    ("modular_polynomial_evaluation", _has_modular_polynomial_evaluation),
    ("polynomially_related_primes", _has_polynomially_related_primes),
    ("shifted_noise_support", _has_shifted_noise_support),
    ("linear_observation", _has_linear_observation),
    ("power_two_modulus", _has_power_two_modulus),
    ("projective_x_scalar_arithmetic", _has_projective_x_scalar_arithmetic),
    ("interactive_chosen_coordinate", _has_interactive_chosen_coordinate),
)


def _syntactic_signals(tree: ast.Module | None) -> set[str]:
    if tree is None:
        return set()
    nodes = list(ast.walk(tree))
    result = {name for name, predicate in _NODE_SIGNALS if predicate(nodes)}
    if _has_sampled_random_scalars(tree, nodes):
        result.add("sampled_random_scalars")
    crt_combiners = _crt_functions(tree)
    if crt_combiners:
        result.add("crt_residue_recombination")
        if _has_factorwise_crt(tree, crt_combiners):
            result.add("factorwise_crt_computation")
    return result


# Requirements describe mechanisms rather than target service names.
HYPOTHESIS_RULES = (
    ({"factorwise_crt_computation", "crt_residue_recombination",
      "interaction"},
     "CRT component-consistency and chosen-ciphertext oracle",
     "An interactive computation repeats a factor-wise operation and "
     "recombines results via CRT, requiring validation of every residue.",
     ("Trace whether attacker-controlled ciphertexts reach both factor-wise operations",
      "Verify that each modular root is correct before CRT recombination",
      "Compare re-encryption across auxiliary ciphertext selectors")),
    ({"hyperelliptic_curve", "jacobian_construction",
      "binary_coefficient_serialization", "xor_operator", "interaction"},
     "Hyperelliptic Jacobian state exposure under chosen plaintext",
     "A hyperelliptic Jacobian is serialized into a byte stream and "
     "an interactive program XORs data with that stream.",
     ("Trace chosen plaintext to the serialized divisor coefficients",
      "Look for Mumford pairs (u,v) satisfying u divides v**2 - f",
      "Recover hidden curve parameters from repeated state observations")),
    ({"projective_x_scalar_arithmetic", "interactive_chosen_coordinate"},
     "Unvalidated x-only scalar multiplication and quadratic twist",
     "An interactive source performs projective-coordinate inversion "
     "and bitwise scalar processing.",
     ("Trace the client-controlled coordinate to the scalar multiplier",
      "Check on-curve validation and subgroup-order enforcement",
      "Compute the quadratic-twist order and inspect its factorization")),
    ({"shifted_noise_support", "linear_observation", "power_two_modulus"},
     "Noise-subgroup leakage in linear modular samples",
     "A linear observation is reduced modulo a power of two while "
     "another source operation shifts a noise-like quantity.",
     ("Trace the shifted data into the actual additive error",
      "Check whether the error vanishes under reduction modulo 2**t",
      "Look for repeated authentic blocks among random decoys")),
    ({"rsa", "polynomially_related_primes"},
     "Algebraically correlated RSA prime factors",
     "A candidate RSA factor is a polynomial in another variable and "
     "then tested for primality.",
     ("Extract its polynomial and test cyclotomic divisibility properties",
      "Explore quotient-field subgroup-collapse and related factorization")),
    ({"restricted_polynomial_sampler", "modular_polynomial_evaluation",
      "interaction"},
     "Potential coefficient-support leakage in polynomial secret sharing",
     "A field polynomial is evaluated while a random sampler appears to "
     "omit part of its coefficient support.",
     ("Determine the coefficient support and whether every field value can occur",
      "Check whether independent share rounds use a fixed secret and "
      "whether missing coefficients restrict secret candidates")),
    ({"gcd_operation", "computed_output_slice", "interaction"},
     "Attacker-controlled polynomial GCD information leak",
     "An attacker-controlled input influences an integer GCD and the length of an output.",
     ("Build polynomial expressions and calculate their resultant",
      "Check whether a modular common root forces a large GCD")),
    ({"indexed_modular_reduction", "sampled_random_scalars"},
     "Signature scalar distribution distinguishability",
     "Arrays of responses include modular reductions and a separate random sampler.",
     ("Trace sampled scalars into each signer response array",
      "Compare the true and decoy distributions and check statistical significance")),
    ({"inverse_conjugation", "hash_key_material"},
     "Conjugation equivalent-key recovery",
     "An algebraic inverse conjugation and symmetric-key derivation occur together.",
     ("Build the noncommutative equation graph and locate commuting public powers",
      "Search for an equivalent key through modular linear equations")),
    ({"elliptic_curve", "sum_of_scaled_terms"},
     "Public linear combinations over a group",
     "The source forms additive combinations of scaled terms on an elliptic curve.",
     ("Determine whether observations invert to hidden group elements",
      "Inspect the generated subgroup order for feasible discrete logarithms")),
    ({"elliptic_curve", "random_scalar", "shuffle", "authentication"},
     "Hidden authentic signature among decoys",
     "An elliptic-curve signature generator is combined with randomized or shuffled candidates.",
     ("Identify and verify genuine transcripts with the public key",
      "Check whether a signature encodes or recovers an encrypted secret")),
    ({"stream_encryption", "key_derivation"},
     "Derived symmetric key and stream encryption",
     "A KDF feeds stream/CTR encryption; inspect how its input can be recovered.",
     ("Identify material used to derive the key",
      "Check nonce uniqueness and known plaintext")),
    ({"zkp", "authentication"},
     "Zero-knowledge proof and soundness",
     "A proof system is used to authorize a state change or authenticate data.",
     ("Check malleability, replay identifiers and public-input binding",
      "Check whether verification enforces the intended statement")),
    ({"pairing"},
     "Bilinear-pairing relations",
     "Pairing computations may permit algebraic transformations of verification equations.",
     ("Express verifier equations with bilinearity",
      "Check identity-point rejection and subgroup membership")),
    ({"rsa", "modular_power"},
     "RSA modular arithmetic",
     "Public-key generation and modular exponentiation occur in the source.",
     ("Inspect reused primes, exponents and shared factors",
      "Inspect algebraic relations and padding oracles")),
    ({"finite_algebra", "interaction"},
     "Algebraic interactive oracle",
     "Finite-ring or polynomial operations are exposed through an interactive protocol.",
     ("Determine which polynomial identities or isomorphisms leak information",
      "Check whether query outputs provide an overdetermined linear system")),
)


def _document_features(document: Document) -> set[str]:
    parsed = parse_python(document)
    if parsed is None and "HyperellipticCurve" in document.text:
        parsed = _sage_tree(document.text)
    return _signatures(document.text) | _syntactic_signals(parsed)


def inspect_hypotheses(documents: Sequence[Document]) -> list[AttackHypothesis]:
    """Generate scoped, unverified avenues of investigation from actual code."""
    by_scope: dict[str, list[Document]] = {}
    for document in documents:
        if document.text and len(document.text) <= MAX_SOURCE_LENGTH:
            by_scope.setdefault(document.scope, []).append(document)
    unique: dict[str, AttackHypothesis] = {}
    groups = [
        group for scope, docs in by_scope.items()
        for group in ([[doc] for doc in docs] if scope == "." else [docs])
    ]
    for docs in groups:
        features = set()
        for document in docs:
            features |= _document_features(document)
        for required, family, scenario, checks in HYPOTHESIS_RULES:
            if required <= features:
                unique.setdefault(family, AttackHypothesis(
                    family, scenario, checks, len(docs),
                ))
    # A hypothesis alone must never trigger an automatic solver.
    return list(unique.values())[:8]
