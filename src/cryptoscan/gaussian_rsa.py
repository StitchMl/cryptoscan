"""Source-derived recovery for Gaussian-integer RSA variants.

The family uses the Gaussian ring Z[i]/nZ[i], represents messages as pairs of
integers, and performs RSA exponentiation with component-wise complex
multiplication.  The missing decryption operation is recovered from the
integer-prime factorisation of n: for every odd prime r, r == 1 (mod 4)
splits into two Gaussian primes while r == 3 (mod 4) remains Gaussian prime.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from math import gcd
from typing import Sequence

from .parser import Document
from .source_units import parse_python


_MAX_BITS = 16384
_OUTPUT_LIMIT = 4_000_000
_ASSIGNMENT = re.compile(
    r"(?m)^\s*(private_key|public_key|ciphertext)\s*=\s*(.*)$",
    re.ASCII,
)


@dataclass(frozen=True)
class GaussianRSA:
    factors: tuple[tuple[int, int], ...]
    modulus: int
    exponent: int
    ciphertext: bytes
    source_path: str = ""


@dataclass(frozen=True)
class _SourceProfile:
    modulus_name: str
    factors: tuple[tuple[str, int], ...]
    exponent: int


def _name(node: ast.AST | None) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _call_name(node: ast.AST | None) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _integer(node: ast.AST, constants: dict[str, int]) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if not isinstance(node, ast.BinOp):
        return None
    left = _integer(node.left, constants)
    right = _integer(node.right, constants)
    if left is None or right is None:
        return None
    if isinstance(node.op, ast.Mult):
        value = left * right
    elif isinstance(node.op, ast.Pow) and 0 <= right <= 16:
        value = left**right
    elif isinstance(node.op, ast.Add):
        value = left + right
    else:
        return None
    return value if abs(value) <= 1 << 20 else None


def _constants(tree: ast.AST) -> dict[str, int]:
    result: dict[str, int] = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            value = _integer(node.value, result)
            if value is not None:
                result[node.targets[0].id] = value
    return result


def _factor_terms(node: ast.AST, constants: dict[str, int]):
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mult):
        return []
    terms = []
    for term in (node.left, node.right):
        if not (isinstance(term, ast.BinOp) and isinstance(term.op, ast.Pow)):
            return []
        prime = _name(term.left)
        power = _integer(term.right, constants)
        if prime is None or power is None or not 1 <= power <= 8:
            return []
        terms.append((prime, power))
    return terms


def _has_prime_source(tree: ast.AST, names: set[str]) -> bool:
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and len(node.args) == 1
                and _call_name(node) in {"getPrime", "getStrongPrime"}):
            continue
        target = node
        for parent in ast.walk(tree):
            if isinstance(parent, ast.Assign) and parent.value is target:
                if any(_name(item) in names for item in parent.targets):
                    return True
    return False


def _has_gaussian_arithmetic(tree: ast.AST) -> bool:
    has_mult = False
    has_pow = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name == "complex_mult":
            has_mult = any(
                isinstance(item, ast.Return)
                and isinstance(item.value, ast.Call)
                and _call_name(item.value) == "Complex"
                and len(item.value.args) == 2
                for item in ast.walk(node)
            )
        if node.name == "complex_pow":
            has_pow = any(
                isinstance(item, ast.Call)
                and _call_name(item) == "complex_mult"
                for item in ast.walk(node)
            )
    return has_mult and has_pow


def _source_profile(document: Document) -> _SourceProfile | None:
    tree = parse_python(document)
    if tree is None or len(document.text) > _OUTPUT_LIMIT:
        return None
    constants = _constants(tree)
    if not _has_gaussian_arithmetic(tree):
        return None
    profiles = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1):
            continue
        modulus_name = _name(node.targets[0])
        if modulus_name is None:
            continue
        terms = _factor_terms(node.value, constants)
        names = {prime for prime, _ in terms}
        if len(terms) != 2 or len(names) != 2:
            continue
        if not _has_prime_source(tree, names):
            continue
        for call in ast.walk(tree):
            if not (isinstance(call, ast.Call)
                    and _call_name(call) == "complex_pow"
                    and len(call.args) == 3
                    and _name(call.args[2]) == modulus_name):
                continue
            exponent = _integer(call.args[1], constants)
            if exponent is not None and exponent > 1 and exponent % 2:
                profiles.append(_SourceProfile(
                    modulus_name, tuple(terms), exponent,
                ))
    if len(profiles) != 1:
        return None
    return profiles[0]


def source_profile(document: Document) -> _SourceProfile | None:
    """Expose the source recognizer for scanner diagnostics and tests."""
    return _source_profile(document)


def _literal_assignment(text: str, key: str):
    match = re.search(
        rf"(?m)^\s*{re.escape(key)}\s*=\s*(.+?)(?=\n\s*[A-Za-z_]\w*\s*=|\Z)",
        text,
        re.ASCII | re.DOTALL,
    )
    if match is None:
        return None
    try:
        return ast.literal_eval(match.group(1).strip())
    except (SyntaxError, ValueError):
        return None


def _public_output(document: Document):
    private = _literal_assignment(document.text, "private_key")
    public = _literal_assignment(document.text, "public_key")
    ciphertext = _literal_assignment(document.text, "ciphertext")
    if (not isinstance(private, tuple) or len(private) != 2
            or not all(type(value) is int for value in private)):
        return None
    if type(public) is not int or not isinstance(ciphertext, bytes):
        return None
    return private, public, ciphertext


def extract_instance(documents: Sequence[Document]) -> GaussianRSA | None:
    profiles = [
        (document, source_profile(document))
        for document in documents
    ]
    profiles = [
        (document, profile) for document, profile in profiles
        if profile is not None
    ]
    if len(profiles) != 1:
        return None
    source, profile = profiles[0]
    matches = []
    for document in documents:
        if document.scope != source.scope or document.path == source.path:
            continue
        values = _public_output(document)
        if values is None:
            continue
        private, public, ciphertext = values
        factors = tuple((value, power) for value, (_, power)
                        in zip(private, profile.factors, strict=True))
        modulus = 1
        for value, power in factors:
            modulus *= value**power
        if (modulus == public and modulus.bit_length() <= _MAX_BITS
                and len(ciphertext) >= 2 and len(ciphertext) % 2 == 0):
            matches.append(GaussianRSA(
                factors, modulus, profile.exponent, ciphertext, source.path,
            ))
    return matches[0] if len(matches) == 1 else None


def gaussian_totient(factors: Sequence[tuple[int, int]]) -> int:
    """Return |(Z[i]/nZ[i])^*| for integer-prime factors r^k."""
    result = 1
    for prime, power in factors:
        if prime <= 2:
            raise ValueError("Gaussian RSA requires odd prime factors")
        if prime % 4 == 1:
            result *= (prime ** (power - 1) * (prime - 1)) ** 2
        elif prime % 4 == 3:
            result *= (prime ** (power - 1)) ** 2 * (prime**2 - 1)
        else:
            raise ValueError("factor is not an odd integer prime")
    return result


def _complex_mult(left: tuple[int, int], right: tuple[int, int],
                  modulus: int) -> tuple[int, int]:
    return (
        (left[0] * right[0] - left[1] * right[1]) % modulus,
        (left[0] * right[1] + left[1] * right[0]) % modulus,
    )


def complex_pow(value: tuple[int, int], exponent: int,
                modulus: int) -> tuple[int, int]:
    result = (1, 0)
    while exponent:
        if exponent & 1:
            result = _complex_mult(result, value, modulus)
        value = _complex_mult(value, value, modulus)
        exponent >>= 1
    return result


def recover_details(instance: GaussianRSA):
    """Decrypt and verify a source-derived Gaussian RSA transcript."""
    width = len(instance.ciphertext) // 2
    component = (
        int.from_bytes(instance.ciphertext[:width], "big"),
        int.from_bytes(instance.ciphertext[width:], "big"),
    )
    phi = gaussian_totient(instance.factors)
    if gcd(instance.exponent, phi) != 1:
        raise RuntimeError("public exponent is not invertible in Gaussian totient")
    private_exponent = pow(instance.exponent, -1, phi)
    message = complex_pow(component, private_exponent, instance.modulus)
    if complex_pow(message, instance.exponent, instance.modulus) != component:
        raise RuntimeError("Gaussian RSA re-encryption check failed")
    raw = (
        message[0].to_bytes(width, "big")
        + message[1].to_bytes(width, "big")
    )
    plaintext = raw.rsplit(b"\\x00", 1)[-1]
    if not plaintext:
        raise RuntimeError("Gaussian RSA plaintext is empty")
    try:
        decoded = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Gaussian RSA plaintext is not UTF-8") from exc
    return decoded, {
        "factors": [prime for prime, _ in instance.factors],
        "factor_powers": [power for _, power in instance.factors],
        "gaussian_totient_bits": phi.bit_length(),
        "reencryption_verified": True,
    }


def recover_flag(documents: Sequence[Document]) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("no unique source-verified Gaussian RSA instance")
    plaintext, _ = recover_details(instance)
    return plaintext
