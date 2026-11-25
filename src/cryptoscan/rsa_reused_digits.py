"""Recognize RSA primes made by reinterpreting one factor's base digits.

Only parse source syntax and public assignments. No challenge source is run.
The relation is useful even when the prime draw itself has full entropy:
the same digits determine both factors.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

from .parser import Document, parse_int, scalar_records
from .source_units import parse_python


@dataclass(frozen=True)
class DigitReuse:
    source_base: int
    target_base: int
    prime_bits: int
    exponent: int
    modulus: int | None = None
    ciphertext_available: bool = False


def _name(node):
    return node.id if isinstance(node, ast.Name) else None


def _call(node, names):
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            return names.get(func.id)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return names.get(func.value.id + "." + func.attr)
    return None


def _module_aliases(stmt, names):
    for alias in stmt.names:
        if alias.name not in ("gmpy2", "random", "secrets"):
            continue
        local = alias.asname or alias.name
        for attr in ("digits", "is_prime", "getrandbits", "randbits"):
            names[local + "." + attr] = alias.name + "." + attr


def _function_aliases(stmt, names):
    if stmt.module not in ("gmpy2", "random", "secrets", "Crypto.Util.number"):
        return
    for alias in stmt.names:
        if alias.name in ("digits", "is_prime", "getrandbits",
                          "randbits", "getPrime"):
            names[alias.asname or alias.name] = stmt.module + "." + alias.name


def _aliases(tree):
    names = {"int": "int", "pow": "pow"}
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            _module_aliases(stmt, names)
        if isinstance(stmt, ast.ImportFrom):
            _function_aliases(stmt, names)
    return names


def _constants(tree):
    values = {}
    for stmt in tree.body:
        if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                and isinstance(stmt.value, ast.Constant)
                and type(stmt.value.value) is int):
            values[_name(stmt.targets[0])] = stmt.value.value
    return values


def _integer(node, values):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.Name):
        return values.get(node.id)
    return None


def _assignment(tree, predicate):
    matches = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            name = _name(node.targets[0])
            if name and predicate(node.value):
                matches.append((name, node.value, node.lineno))
    return matches


def _digits(value, prime, names, values):
    if _call(value, names) != "gmpy2.digits" or len(value.args) != 2:
        return None
    if _name(value.args[0]) != prime:
        return None
    base = _integer(value.args[1], values)
    return base if base is not None and 2 <= base <= 36 else None


def _reinterpretation(value, prime, names, values):
    if _call(value, names) != "int" or not 1 <= len(value.args) <= 2:
        return None
    if value.keywords:
        return None
    target = 10 if len(value.args) == 1 else _integer(value.args[1], values)
    source = _digits(value.args[0], prime, names, values)
    if target is None or source is None or not source <= target <= 36:
        return None
    return source, target


def _primality_checks(tree, prime, derived, names):
    checked = set()
    for node in ast.walk(tree):
        if _call(node, names) == "gmpy2.is_prime" and len(node.args) == 1:
            checked.add(_name(node.args[0]))
    return {prime, derived} <= checked


def _product(value, prime, derived):
    if not isinstance(value, ast.BinOp) or not isinstance(value.op, ast.Mult):
        return False
    return {_name(value.left), _name(value.right)} == {prime, derived}


def _encryption(tree, modulus, exponent, values, names):
    for node in ast.walk(tree):
        if (_call(node, names) == "pow" and len(node.args) == 3
                and _name(node.args[2]) == modulus
                and _integer(node.args[1], values) == exponent):
            return True
    return False


def _prime_draw(value, names, values):
    method = _call(value, names)
    if method not in ("random.getrandbits", "secrets.randbits",
                      "Crypto.Util.number.getPrime") or len(value.args) != 1:
        return None
    bits = _integer(value.args[0], values)
    return bits if bits is not None and 16 <= bits <= 4096 else None


def _matching_exponent(tree, modulus, values, names):
    exponents = {
        value for value in values.values()
        if 3 <= value <= (1 << 32) and value % 2
        and _encryption(tree, modulus, value, values, names)
    }
    return next(iter(exponents)) if len(exponents) == 1 else None


def _related_profiles(tree, names, values, prime, bits, draw_line):
    profiles = []
    derived_values = _assignment(
        tree, lambda expr: _reinterpretation(expr, prime, names, values) is not None,
    )
    for derived, value, derived_line in derived_values:
        if derived_line <= draw_line or not _primality_checks(tree, prime, derived, names):
            continue
        source, target = _reinterpretation(value, prime, names, values)
        products = _assignment(
            tree, lambda expr, other=derived: _product(expr, prime, other),
        )
        for modulus, _, product_line in products:
            if product_line <= derived_line:
                continue
            exponent = _matching_exponent(tree, modulus, values, names)
            if exponent is not None:
                profiles.append(DigitReuse(source, target, bits, exponent))
    return profiles


def source_profile(document: Document) -> DigitReuse | None:
    tree = parse_python(document)
    if tree is None:
        return None
    names, values = _aliases(tree), _constants(tree)
    candidates = []
    draws = _assignment(
        tree, lambda value: _prime_draw(value, names, values) is not None,
    )
    for prime, draw, draw_line in draws:
        bits = _prime_draw(draw, names, values)
        candidates.extend(_related_profiles(tree, names, values, prime, bits,
                                            draw_line))
    return candidates[0] if len(candidates) == 1 else None


def extract_instance(documents) -> DigitReuse | None:
    """Match one source model with one same-scope public modulus transcript."""
    profiles = [(doc.scope, source_profile(doc)) for doc in documents]
    profiles = [(scope, profile) for scope, profile in profiles if profile is not None]
    if len(profiles) != 1:
        return None
    scope, profile = profiles[0]
    records = []
    for doc in documents:
        if doc.scope != scope:
            continue
        for values in scalar_records(doc.text):
            modulus = parse_int(values.get("n", values.get("modulus")))
            exponent = parse_int(values.get("e", values.get("exponent")))
            if (modulus is not None and exponent == profile.exponent
                    and modulus.bit_length() <= 16384):
                records.append((modulus, parse_int(values.get("c", values.get("ciphertext")))))
    if len(records) != 1:
        return None
    modulus, ciphertext = records[0]
    if modulus <= 3 or (ciphertext is not None and not 0 <= ciphertext < modulus):
        return None
    return DigitReuse(profile.source_base, profile.target_base,
                      profile.prime_bits, profile.exponent, modulus,
                      ciphertext is not None)
