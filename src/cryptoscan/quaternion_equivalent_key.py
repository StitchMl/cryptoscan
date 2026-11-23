"""Source-gated equivalent-key recovery in Hamilton quaternion conjugation.

Public values beta = chi^-1 alpha^-1 chi and gamma = chi^r expose a
projectively equivalent private conjugator if chi lies in the 2D
centralizer of gamma. This solver uses public modular linear equations,
not factorization or challenge-specific parameters.
"""
from __future__ import annotations

import ast
import hashlib
import math
import re
from dataclasses import dataclass
from typing import Sequence

from .parser import Document

_NAME = r"([^\W\d]\w*)"
_QUAT = re.compile(r"\((?:\s*\d+\s*\(mod\s+\d+\)\s*,?){4}\)")
_COMPONENT = re.compile(r"(\d+)\s*\(mod\s+(\d+)\)")
_BYTES = re.compile(r"""b(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")""")


@dataclass(frozen=True)
class QuaternionConjugationLeak:
    modulus: int
    public: tuple[tuple[int, ...], ...]
    ciphertext: bytes
    masked: tuple[int, ...]
    observed: tuple[int, ...]
    iv: bytes


def _symbol_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == "self"):
        return node.attr
    return None


def _has_tuple_return(tree, names):
    return any(
        isinstance(node, ast.Return)
        and isinstance(node.value, ast.Tuple)
        and len(node.value.elts) == len(names) + 1
        and tuple(_symbol_name(value) for value in node.value.elts[1:])
        == tuple(names)
        and _symbol_name(node.value.elts[0]) is not None
        for node in ast.walk(tree)
    )


def _has_ciphertext_return(tree, masked, observed):
    return any(
        isinstance(node, ast.Return)
        and isinstance(node.value, ast.Tuple)
        and len(node.value.elts) == 3
        and _symbol_name(node.value.elts[1]) == masked
        and _symbol_name(node.value.elts[2]) == observed
        for node in ast.walk(tree)
    )


def _negative_one(node):
    return (isinstance(node, ast.UnaryOp)
            and isinstance(node.op, ast.USub)
            and isinstance(node.operand, ast.Constant)
            and node.operand.value == 1)


def _inverse_name(node):
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow)
            and _negative_one(node.right)):
        return _symbol_name(node.left)
    return None


def _power_base(node):
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow)
            and not _negative_one(node.right)):
        return _symbol_name(node.left)
    return None


def _multiplicative_terms(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        return _multiplicative_terms(node.left) + _multiplicative_terms(node.right)
    return [node]


def _has_key_digest(tree, key_name):
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "sha256" and len(node.args) == 1):
            continue
        value = node.args[0]
        if not (isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "encode"
                and isinstance(value.func.value, ast.Call)
                and isinstance(value.func.value.func, ast.Name)
                and value.func.value.func.id == "str"
                and len(value.func.value.args) == 1):
            continue
        if _symbol_name(value.func.value.args[0]) == key_name:
            return True
    return False


def _algebraic_roles(tree):
    """Extract the conjugation graph from syntax trees, not text formatting.

    Supports arbitrary identifiers, attributes, parenthesization, and
    multiplication association, while preserving operand order.
    """
    assignments = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and (name := _symbol_name(node.targets[0])) is not None):
            assignments.append((name, node.value))
    candidates = []
    for beta, expression in assignments:
        terms = _multiplicative_terms(expression)
        if len(terms) != 3:
            continue
        chi = _inverse_name(terms[0])
        alpha = _inverse_name(terms[1])
        if not chi or not alpha or _symbol_name(terms[2]) != chi:
            continue
        for gamma, gamma_expression in assignments:
            if _power_base(gamma_expression) != chi:
                continue
            for delta, delta_expression in assignments:
                if _power_base(delta_expression) != gamma:
                    continue
                def conjugates(name):
                    return [
                        output for output, equation in assignments
                        if (lambda parts: len(parts) == 3
                            and _inverse_name(parts[0]) == delta
                            and _symbol_name(parts[1]) == name
                            and _symbol_name(parts[2]) == delta)(
                                _multiplicative_terms(equation))
                    ]
                for epsilon in conjugates(alpha):
                    for kappa in conjugates(beta):
                        for mu, equation in assignments:
                            parts = _multiplicative_terms(equation)
                            if (len(parts) != 3
                                    or _symbol_name(parts[0]) != kappa
                                    or _symbol_name(parts[2]) != kappa):
                                continue
                            key_name = _symbol_name(parts[1])
                            if not key_name or not _has_key_digest(tree, key_name):
                                continue
                            if not _has_tuple_return(tree, (alpha, beta, gamma)):
                                continue
                            if not _has_ciphertext_return(tree, mu, epsilon):
                                continue
                            candidates.append((alpha, beta, gamma))
    return candidates[0] if len(candidates) == 1 else None


def _source_shape(source: str) -> bytes | None:
    """Accept only a linked conjugation-and-double-mask source structure."""
    if len(source) > 1_000_000:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    # Detect the required algebra interface by methods rather than the
    # implementation's class name. A renamed quaternion class is equivalent.
    classes = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and {"__mul__", "invert", "__str__"} <= {
            method.name for method in node.body
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
    ]
    if len(classes) != 1:
        return None
    if not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "sha256"
        and node.args and isinstance(node.args[0], ast.Call)
        and isinstance(node.args[0].func, ast.Attribute)
        and node.args[0].func.attr == "encode"
        for node in ast.walk(tree)
    ):
        return None
    if _algebraic_roles(tree) is None:
        return None
    # Extract the CBC IV without executing input source.
    iv_values = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "new":
            continue
        if not any(
            isinstance(arg, ast.Attribute) and arg.attr == "MODE_CBC"
            for arg in node.args
        ):
            continue
        for keyword in node.keywords:
            if keyword.arg != "iv":
                continue
            expression = keyword.value
            try:
                if (isinstance(expression, ast.BinOp)
                        and isinstance(expression.op, ast.Mult)
                        and isinstance(expression.left, ast.Constant)
                        and isinstance(expression.left.value, bytes)
                        and isinstance(expression.right, ast.Constant)
                        and type(expression.right.value) is int
                        and 0 <= expression.right.value <= 32):
                    value = expression.left.value * expression.right.value
                else:
                    value = ast.literal_eval(expression)
            except (ValueError, TypeError, SyntaxError):
                continue
            if isinstance(value, bytes) and len(value) == 16:
                iv_values.append(value)
    return iv_values[0] if len(iv_values) == 1 else None


def _parse_quaternion(text: str, modulus: int) -> tuple[int, ...] | None:
    fields = _COMPONENT.findall(text)
    if len(fields) != 4 or any(int(mod) != modulus for _, mod in fields):
        return None
    coords = tuple(int(value) for value, _ in fields)
    return coords if all(0 <= value < modulus for value in coords) else None


def _parse_output(text: str):
    if len(text) > 1_000_000:
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 2:
        return None
    public_q = _QUAT.findall(lines[0])
    encrypted_q = _QUAT.findall(lines[1])
    if len(public_q) != 3 or len(encrypted_q) != 2:
        return None
    prefix = lines[0].split(",", 1)[0]
    modulus_match = re.search(r"(\d+)\s*$", prefix)
    if not modulus_match:
        return None
    modulus = int(modulus_match.group(1))
    if not 16 <= modulus.bit_length() <= 8192 or modulus % 2 == 0:
        return None
    coordinates = [_parse_quaternion(q, modulus)
                   for q in (*public_q, *encrypted_q)]
    if any(q is None for q in coordinates):
        return None
    before_first_quat = lines[1].split(encrypted_q[0], 1)[0]
    encoded = _BYTES.search(before_first_quat)
    if encoded is None:
        return None
    try:
        ciphertext = ast.literal_eval(encoded.group())
    except (SyntaxError, ValueError):
        return None
    if not isinstance(ciphertext, bytes) or not ciphertext or len(ciphertext) % 16:
        return None
    return modulus, tuple(coordinates[:3]), ciphertext, coordinates[3], coordinates[4]


def extract_instance(documents: Sequence[Document]) -> QuaternionConjugationLeak | None:
    instances = []
    for source in documents:
        iv = _source_shape(source.text)
        if iv is None:
            continue
        for output in documents:
            if output.path == source.path or output.scope != source.scope:
                continue
            parsed = _parse_output(output.text)
            if parsed is None:
                continue
            instances.append(QuaternionConjugationLeak(*parsed, iv))
    return instances[0] if len(instances) == 1 else None


def _add(a, b, n):
    return tuple((u + v) % n for u, v in zip(a, b, strict=True))


def _neg(a, n):
    return tuple(-x % n for x in a)


def _sub(a, b, n):
    return _add(a, _neg(b, n), n)


def _mul(x, y, n):
    a, b, c, d = x
    e, f, g, h = y
    return ((a*e-b*f-c*g-d*h) % n,
            (a*f+b*e+c*h-d*g) % n,
            (a*g-b*h+c*e+d*f) % n,
            (a*h+b*g-c*f+d*e) % n)


def _inverse(x, n):
    norm = sum(v*v for v in x) % n
    return _mul((x[0], -x[1], -x[2], -x[3]),
                (pow(norm, -1, n), 0, 0, 0), n)


def _equivalent_conjugator(alpha, beta, gamma, n):
    """Solve t*(beta-alpha^-1)=alpha^-1*gamma-gamma*beta."""
    inverse_alpha = _inverse(alpha, n)
    left = _sub(beta, inverse_alpha, n)
    right = _sub(_mul(inverse_alpha, gamma, n),
                 _mul(gamma, beta, n), n)
    for coefficient, target in zip(left, right, strict=True):
        if math.gcd(coefficient, n) != 1:
            continue
        t = target * pow(coefficient, -1, n) % n
        if any((t*u-v) % n for u, v in zip(left, right, strict=True)):
            continue
        conjugator = _add(gamma, (t, 0, 0, 0), n)
        if (_mul(conjugator, beta, n)
                == _mul(inverse_alpha, conjugator, n)
                and _mul(conjugator, gamma, n)
                == _mul(gamma, conjugator, n)):
            return conjugator
    raise RuntimeError("no verified unit-pivot equivalent quaternion conjugator")


def recover_flag(documents: Sequence[Document]) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("no supported quaternion equivalent-key corpus")
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except ImportError as exc:
        raise RuntimeError("pycryptodome required for quaternion AES recovery") from exc
    n = instance.modulus
    alpha, beta, gamma = instance.public
    chi_equiv = _equivalent_conjugator(alpha, beta, gamma, n)
    # delta is a power of gamma and commutes with chi_equiv.
    kappa = _mul(_mul(_inverse(chi_equiv, n),
                      _inverse(instance.observed, n), n),
                 chi_equiv, n)
    inverse_kappa = _inverse(kappa, n)
    key_quaternion = _mul(_mul(inverse_kappa, instance.masked, n),
                          inverse_kappa, n)
    textual = "(" + ",".join(f"{value} (mod {n})" for value in key_quaternion) + ")"
    aes_key = hashlib.sha256(textual.encode()).digest()
    try:
        plaintext = unpad(
            AES.new(aes_key, AES.MODE_CBC, iv=instance.iv)
            .decrypt(instance.ciphertext), 16,
        )
        decoded = plaintext.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("equivalent key did not decrypt valid UTF-8/PKCS7") from exc
    if not re.search(r"\w{2,32}\{[^{}\r\n]{1,256}\}", decoded):
        raise RuntimeError("decryption did not yield independently recognizable plaintext")
    return decoded
