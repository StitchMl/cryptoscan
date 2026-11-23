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


@dataclass(frozen=True)
class AttackHypothesis:
    family: str
    scenario: str
    next_checks: tuple[str, ...]
    source_count: int


def _signatures(source: str) -> set[str]:
    features: set[str] = set()
    if re.search(r"\b(?:EllipticCurve|EccPoint|Ed448|Ed25519)\b", source):
        features.add("elliptic_curve")
    if re.search(r"\b(?:secrets\.randbelow|randrange|randint)\s*\(", source):
        features.add("random_scalar")
    if re.search(r"\b(?:shuffle|sample)\s*\(", source):
        features.add("shuffle")
    if re.search(r"\b(?:AES\.MODE_CTR|MODE_CTR|ChaCha20)\b", source):
        features.add("stream_encryption")
    if re.search(r"\b(?:bcrypt\.kdf|scrypt|pbkdf2_hmac|HKDF)\s*\(", source):
        features.add("key_derivation")
    if re.search(r"\b(?:Groth16|SNARK|R1CS|Poseidon)\b", source):
        features.add("zkp")
    if re.search(r"\b(?:ate_pairing|weil_pairing|tate_pairing)\b", source):
        features.add("pairing")
    if re.search(r"\b(?:getPrime|RSA\.generate|rsa\.generate)\s*\(", source):
        features.add("rsa")
    if re.search(r"\b(?:GF|PolynomialRing|quotient_ring|Zmod)\s*\(", source):
        features.add("finite_algebra")
    if re.search(r"\b(?:signature|sign|verify|proof)\b", source, flags=re.I):
        features.add("authentication")
    if re.search(r"\b(?:oracle|PoW|input)\s*\(", source, flags=re.I):
        features.add("interaction")
    if re.search(r"\b(?:xor|operator\.xor)\b", source):
        features.add("xor")
    if re.search(r"\b(?:nonce|IV|counter)\b", source, flags=re.I):
        features.add("nonce")
    return features


def _syntactic_signals(tree: ast.Module | None) -> set[str]:
    if tree is None:
        return set()
    result = set()
    has_modular_power = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == "pow"
        and len(node.args) == 3
        for node in ast.walk(tree)
    )
    if has_modular_power:
        result.add("modular_power")
    if any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor)
        for node in ast.walk(tree)
    ):
        result.add("xor_operator")
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr == "shuffle"
        for node in ast.walk(tree)
    ):
        result.add("shuffle")
    nodes = list(ast.walk(tree))
    if any(isinstance(node, ast.Call)
           and (isinstance(node.func, ast.Name) and node.func.id == "gcd"
                or isinstance(node.func, ast.Attribute)
                and node.func.attr == "gcd")
           and len(node.args) == 2 for node in nodes):
        result.add("gcd_operation")
    if any(
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Slice)
        and node.slice.upper is not None
        and not isinstance(node.slice.upper, ast.Constant)
        for node in nodes
    ):
        result.add("computed_output_slice")
    if any(
        isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Subscript) for target in node.targets)
        and isinstance(node.value, ast.BinOp)
        and isinstance(node.value.op, ast.Mod)
        for node in nodes
    ):
        result.add("indexed_modular_reduction")
    random_names = set()
    random_modules = set()
    for imported in tree.body:
        if (isinstance(imported, ast.ImportFrom)
                and imported.module in {"secrets", "random"}):
            random_names.update(
                alias.asname or alias.name for alias in imported.names
                if alias.name in {"getrandbits", "randbits", "randbelow", "randrange"}
            )
        elif isinstance(imported, ast.Import):
            random_modules.update(
                alias.asname or alias.name for alias in imported.names
                if alias.name in {"secrets", "random"}
            )
    if any(
        isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Name) and node.func.id in random_names
            or isinstance(node.func, ast.Attribute)
            and node.func.attr in {"getrandbits", "randbits", "randbelow", "randrange"}
            and (isinstance(node.func.value, ast.Name)
                 and node.func.value.id in random_modules
                 or isinstance(node.func.value, ast.Call))
        )
        for node in nodes
    ):
        result.add("sampled_random_scalars")
    if any(
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
    ):
        result.add("inverse_conjugation")
    if any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
        and isinstance(node.left, ast.BinOp)
        and isinstance(node.left.op, ast.Mult)
        and isinstance(node.right, ast.BinOp)
        and isinstance(node.right.op, ast.Mult)
        for node in nodes
    ):
        result.add("sum_of_scaled_terms")
    if (any(isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"sha256", "sha512", "blake2b"}
            for node in nodes)
            and any(isinstance(node, ast.Attribute)
                    and node.attr in {"MODE_CBC", "MODE_CTR", "MODE_GCM"}
                    for node in nodes)):
        result.add("hash_key_material")
    if any(
        isinstance(node, ast.Call) and len(node.args) >= 1
        and ((isinstance(node.func, ast.Name)
              and node.func.id in {"getRandomRange", "randbelow", "randrange"})
             or (isinstance(node.func, ast.Attribute)
                 and node.func.attr in {"getRandomRange", "randbelow", "randrange"}))
        and isinstance(node.args[-1], ast.BinOp)
        and isinstance(node.args[-1].op, ast.Sub)
        and isinstance(node.args[-1].right, ast.Constant)
        and type(node.args[-1].right.value) is int
        and node.args[-1].right.value > 0
        for node in nodes
    ):
        result.add("restricted_polynomial_sampler")
    if any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "pow" and len(node.args) == 3
        for node in nodes
    ) and any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
        for node in nodes
    ):
        result.add("modular_polynomial_evaluation")
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
    if any(
        isinstance(node, ast.Call) and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in prime_related
        and ((isinstance(node.func, ast.Name)
              and node.func.id in ("isPrime", "isprime"))
             or (isinstance(node.func, ast.Attribute)
                 and node.func.attr in ("isPrime", "isprime")))
        for node in nodes
    ):
        result.add("polynomially_related_primes")
    return result


# Requirements describe mechanisms rather than target service names.
HYPOTHESIS_RULES = (
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
            features |= _signatures(document.text)
            features |= _syntactic_signals(parse_python(document))
        for required, family, scenario, checks in HYPOTHESIS_RULES:
            if required <= features:
                unique.setdefault(family, AttackHypothesis(
                    family, scenario, checks, len(docs),
                ))
    # A hypothesis alone must never trigger an automatic solver.
    return list(unique.values())[:8]
