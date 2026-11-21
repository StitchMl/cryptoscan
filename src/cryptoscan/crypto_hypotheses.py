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
    return result


def inspect_hypotheses(documents: Sequence[Document]) -> list[AttackHypothesis]:
    """Generate scoped, unverified avenues of investigation from actual code."""
    by_scope: dict[str, list[Document]] = {}
    for document in documents:
        if not document.text or len(document.text) > MAX_SOURCE_LENGTH:
            continue
        by_scope.setdefault(document.scope, []).append(document)
    signals: list[AttackHypothesis] = []
    for docs in by_scope.values():
        features = set()
        for document in docs:
            features |= _signatures(document.text)
            features |= _syntactic_signals(parse_python(document))
        count = len(docs)
        if {"elliptic_curve", "random_scalar", "shuffle", "authentication"} <= features:
            signals.append(AttackHypothesis(
                "Hidden authentic signature among decoys",
                "An elliptic-curve signature generator is combined with randomized or shuffled candidates.",
                ("Identify and verify genuine transcripts with the public key",
                 "Check whether a signature encodes or recovers an encrypted secret"),
                count,
            ))
        if {"stream_encryption", "key_derivation"} <= features:
            signals.append(AttackHypothesis(
                "Derived symmetric key and stream encryption",
                "A KDF feeds stream/CTR encryption; inspect how its input can be recovered.",
                ("Identify material used to derive the key",
                 "Check nonce uniqueness and known plaintext"), count,
            ))
        if {"zkp", "authentication"} <= features:
            signals.append(AttackHypothesis(
                "Zero-knowledge proof and soundness",
                "A proof system is used to authorize a state change or authenticate data.",
                ("Check malleability, replay identifiers and public-input binding",
                 "Check whether verification enforces the intended statement"), count,
            ))
        if "pairing" in features:
            signals.append(AttackHypothesis(
                "Bilinear-pairing relations",
                "Pairing computations may permit algebraic transformations of verification equations.",
                ("Express verifier equations with bilinearity",
                 "Check identity-point rejection and subgroup membership"), count,
            ))
        if {"rsa", "modular_power"} <= features:
            signals.append(AttackHypothesis(
                "RSA modular arithmetic",
                "Public-key generation and modular exponentiation occur in the source.",
                ("Inspect reused primes, exponents and shared factors",
                 "Inspect algebraic relations and padding oracles"), count,
            ))
        if {"finite_algebra", "interaction"} <= features:
            signals.append(AttackHypothesis(
                "Algebraic interactive oracle",
                "Finite-ring or polynomial operations are exposed through an interactive protocol.",
                ("Determine which polynomial identities or isomorphisms leak information",
                 "Check whether query outputs provide an overdetermined linear system"), count,
            ))
    # Never claim any of the above is exploitably weak without verification.
    unique: dict[str, AttackHypothesis] = {}
    for candidate in signals:
        unique.setdefault(candidate.family, candidate)
    return list(unique.values())[:8]
