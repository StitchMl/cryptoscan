"""Source-gated Gaussian-integer RSA over a squared semiprime modulus.

The prime factors are part of the public CTF transcript. This module parses
source syntax and literals; it never imports or runs the challenge program.
"""
from __future__ import annotations

import ast
import math
import re
from dataclasses import dataclass
from typing import Sequence

from sympy import isprime

from .parser import Document

MAX_SOURCE = 2_000_000
MAX_OUTPUT = 200_000
MAX_BITS = 16_384
FLAG_SHAPE = re.compile(rb"[A-Za-z0-9_]{2,32}\{[\x20-\x7e]{1,200}\}")


@dataclass(frozen=True)
class Profile:
    exponent: int
    byteorder: str


@dataclass(frozen=True)
class Instance:
    p: int
    q: int
    modulus: int
    ciphertext: bytes
    profile: Profile
    source: str
    output: str
    scope: str


def _name(node: ast.AST, expected: str) -> bool:
    return isinstance(node, ast.Name) and node.id == expected


def _literal(node: ast.AST, expected: object) -> bool:
    return isinstance(node, ast.Constant) and node.value == expected


def _attribute(node: ast.AST, owner: str, field: str) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == field
            and _name(node.value, owner))


def _product_fields(node: ast.AST, first: str,
                    second: str) -> tuple[str, str] | None:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mult):
        return None
    left, right = node.left, node.right
    if not isinstance(left, ast.Attribute) or not isinstance(right, ast.Attribute):
        return None
    if _name(left.value, first) and _name(right.value, second):
        return left.attr, right.attr
    return None


def _modular_parts(node: ast.AST, modulus: str,
                   operation: type[ast.operator]) -> tuple[ast.AST, ast.AST] | None:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mod):
        return None
    inner = node.left
    if not _name(node.right, modulus):
        return None
    if isinstance(inner, ast.BinOp) and isinstance(inner.op, operation):
        return inner.left, inner.right
    return None


def _gaussian_fields(method: ast.FunctionDef) -> tuple[str, str] | None:
    if len(method.args.args) != 3:
        return None
    first, second, modulus = (item.arg for item in method.args.args)
    for statement in method.body:
        if not isinstance(statement, ast.Return):
            continue
        call = statement.value
        if not isinstance(call, ast.Call) or len(call.args) != 2:
            continue
        real = _modular_parts(call.args[0], modulus, ast.Sub)
        imag = _modular_parts(call.args[1], modulus, ast.Add)
        if real is None or imag is None:
            continue
        rr = _product_fields(real[0], first, second)
        ii = _product_fields(real[1], first, second)
        ri = _product_fields(imag[0], first, second)
        ir = _product_fields(imag[1], first, second)
        if (rr is not None and ii is not None and rr[0] == rr[1]
                and ii[0] == ii[1] and rr[0] != ii[0]
                and ri == (rr[0], ii[0]) and ir == (ii[0], rr[0])):
            return rr[0], ii[0]
    return None


def _is_power_function(method: ast.FunctionDef, multiply: str) -> bool:
    calls = [node for node in ast.walk(method)
             if isinstance(node, ast.Call) and _name(node.func, multiply)]
    shifts = [node for node in ast.walk(method)
              if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.RShift)
              and _literal(node.value, 1)]
    return len(method.args.args) == 3 and len(calls) >= 2 and bool(shifts)


def _squared_prime_product(node: ast.AST) -> bool:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mult):
        return False
    left, right = node.left, node.right
    return (
        isinstance(left, ast.BinOp) and isinstance(left.op, ast.Pow)
        and isinstance(right, ast.BinOp) and isinstance(right.op, ast.Pow)
        and isinstance(left.left, ast.Name) and isinstance(right.left, ast.Name)
        and left.left.id != right.left.id
        and _literal(left.right, 2) and _literal(right.right, 2)
    )


def _has_squared_modulus(tree: ast.Module) -> bool:
    return any(_squared_prime_product(node.value) for node in ast.walk(tree)
               if isinstance(node, ast.Assign))


def _bit_length(node: ast.AST, modulus: str) -> bool:
    return (
        isinstance(node, ast.Call) and not node.args
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "bit_length"
        and _name(node.func.value, modulus)
    )


def _half_width(node: ast.AST, modulus: str) -> bool:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.FloorDiv):
        return False
    difference = node.left
    return (
        _literal(node.right, 8)
        and isinstance(difference, ast.BinOp)
        and isinstance(difference.op, ast.Sub)
        and _bit_length(difference.left, modulus)
        and _literal(difference.right, 1)
    )


def _padding_width(node: ast.AST, modulus: str) -> bool:
    return (
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult)
        and _literal(node.left, 2) and _half_width(node.right, modulus)
    )


def _cipher_width(node: ast.AST, modulus: str) -> bool:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.FloorDiv):
        return False
    added = node.left
    return (
        _literal(node.right, 8)
        and isinstance(added, ast.BinOp) and isinstance(added.op, ast.Add)
        and _bit_length(added.left, modulus)
        and _literal(added.right, 7)
    )


def _serialization(method: ast.FunctionDef, modulus: str,
                   fields: tuple[str, str]) -> str | None:
    padded = any(
        isinstance(node, ast.Call) and len(node.args) == 2
        and _padding_width(node.args[1], modulus)
        for node in ast.walk(method)
    )
    output_fields = {
        node.func.value.attr
        for node in ast.walk(method)
        if isinstance(node, ast.Call) and len(node.args) == 2
        and isinstance(node.func, ast.Attribute) and node.func.attr == "to_bytes"
        and isinstance(node.func.value, ast.Attribute)
        and _cipher_width(node.args[0], modulus)
        and _literal(node.args[1], "big")
    }
    inputs = [
        node.args[1].value for node in ast.walk(method)
        if isinstance(node, ast.Call) and len(node.args) == 2
        and isinstance(node.func, ast.Attribute) and node.func.attr == "from_bytes"
        and _name(node.func.value, "int")
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value in ("big", "little")
    ]
    if padded and set(fields) <= output_fields and len(inputs) == 2:
        return inputs[0] if inputs[0] == inputs[1] else None
    return None


def _exponent(node: ast.AST, constants: dict[str, int]) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _encryption_profiles(method: ast.FunctionDef, power: str,
                         fields: tuple[str, str],
                         constants: dict[str, int]) -> list[Profile]:
    found = []
    for node in ast.walk(method):
        if not isinstance(node, ast.Call) or not _name(node.func, power):
            continue
        if len(node.args) != 3 or not isinstance(node.args[2], ast.Name):
            continue
        exponent = _exponent(node.args[1], constants)
        order = _serialization(method, node.args[2].id, fields)
        if exponent is not None and 3 <= exponent <= 1 << 20 and order:
            found.append(Profile(exponent, order))
    return found


def source_profiles(document: Document) -> list[Profile]:
    if not document.path.lower().endswith(".py") or len(document.text) > MAX_SOURCE:
        return []
    try:
        tree = ast.parse(document.text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    if not _has_squared_modulus(tree):
        return []
    if not any(_literal(node, b"\x00") for node in ast.walk(tree)):
        return []
    methods = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    constants = {
        stmt.targets[0].id: stmt.value.value for stmt in tree.body
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and isinstance(stmt.value, ast.Constant)
        and type(stmt.value.value) is int
    }
    found = []
    for multiplier in methods:
        fields = _gaussian_fields(multiplier)
        if fields is None:
            continue
        for powering in methods:
            if _is_power_function(powering, multiplier.name):
                for method in methods:
                    found.extend(_encryption_profiles(
                        method, powering.name, fields, constants,
                    ))
    return list(dict.fromkeys(found))


def _transcript(document: Document) -> tuple[int, int, int, bytes] | None:
    if len(document.text) > MAX_OUTPUT:
        return None
    try:
        tree = ast.parse(document.text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in {
                    "private_key", "factors", "public_key", "modulus",
                    "ciphertext", "c"}:
                try:
                    values[target.id] = ast.literal_eval(node.value)
                except (ValueError, SyntaxError, RecursionError, MemoryError):
                    return None
    factors = values.get("private_key", values.get("factors"))
    modulus = values.get("public_key", values.get("modulus"))
    ciphertext = values.get("ciphertext", values.get("c"))
    if not isinstance(factors, tuple) or len(factors) != 2:
        return None
    p, q = factors
    if (type(p) is not int or type(q) is not int or type(modulus) is not int
            or type(ciphertext) is not bytes):
        return None
    if (p <= 2 or q <= 2 or p == q or modulus.bit_length() > MAX_BITS
            or modulus != p*p*q*q or not isprime(p) or not isprime(q)):
        return None
    width = (modulus.bit_length() + 7) // 8
    if len(ciphertext) != 2 * width:
        return None
    return p, q, modulus, ciphertext


def extract_instance(documents: Sequence[Document]) -> Instance | None:
    found = set()
    for source in documents:
        for profile in source_profiles(source):
            for output in documents:
                if output.path == source.path or output.scope != source.scope:
                    continue
                transcript = _transcript(output)
                if transcript is not None:
                    found.add(Instance(*transcript, profile, source.path,
                                       output.path, source.scope))
    return next(iter(found)) if len(found) == 1 else None


def gaussian_multiply(left: tuple[int, int], right: tuple[int, int],
                      modulus: int) -> tuple[int, int]:
    a, b = left
    c, d = right
    return ((a*c - b*d) % modulus, (a*d + b*c) % modulus)


def gaussian_power(base: tuple[int, int], exponent: int,
                   modulus: int) -> tuple[int, int]:
    result = (1, 0)
    while exponent:
        if exponent & 1:
            result = gaussian_multiply(result, base, modulus)
        base = gaussian_multiply(base, base, modulus)
        exponent >>= 1
    return result


def local_unit_order(prime: int) -> int:
    """Size of (Z[i]/prime**2 Z[i]) units for odd primes."""
    if prime <= 2 or not isprime(prime):
        raise ValueError("expected an odd prime")
    if prime % 4 == 1:
        return prime**2 * (prime - 1)**2
    return prime**2 * (prime**2 - 1)


def _decrypt(instance: Instance) -> bytes:
    p, q, n = instance.p, instance.q, instance.modulus
    exponent = instance.profile.exponent
    order = math.lcm(local_unit_order(p), local_unit_order(q))
    if math.gcd(exponent, order) != 1:
        raise RuntimeError("exponent is not invertible in the Gaussian unit group")
    private = pow(exponent, -1, order)
    width = (n.bit_length() + 7) // 8
    ciphertext = instance.ciphertext
    cipher = (int.from_bytes(ciphertext[:width], "big"),
              int.from_bytes(ciphertext[width:], "big"))
    if max(cipher) >= n:
        raise ValueError("ciphertext component is outside the modulus")
    plain = gaussian_power(cipher, private, n)
    if gaussian_power(plain, exponent, n) != cipher:
        raise RuntimeError("Gaussian re-encryption failed")
    half = (n.bit_length() - 1) // 8
    try:
        padded = b"".join(value.to_bytes(half, instance.profile.byteorder)
                          for value in plain)
    except OverflowError as exc:
        raise RuntimeError("recovered component exceeds the source's padding width") from exc
    if b"\x00" not in padded:
        raise RuntimeError("zero padding delimiter is missing")
    prefix, flag = padded.split(b"\x00", 1)
    if not prefix or b"\x00" in prefix or not FLAG_SHAPE.fullmatch(flag):
        raise RuntimeError("recovered padded text has no verified flag")
    return flag


def recover_flag(documents: Sequence[Document]) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("need a Gaussian square-modulus source and matching factor transcript")
    return _decrypt(instance).decode("ascii")

