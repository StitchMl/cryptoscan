"""Recover bit encodings when an RSA factor is leaked by a square-root hint.

Some CTF implementations publish ``D*(sqrt(p)+sqrt(q))`` alongside an RSA
modulus.  Truncation gives a close approximation to one factor; a univariate
approximate-common-divisor lattice recovers the exact factor.  This module is
source gated and deliberately accepts equivalent variable names and constant
exponents rather than a particular challenge name.
"""
from __future__ import annotations

import ast
import math
from dataclasses import dataclass
from decimal import Decimal, localcontext
from typing import Sequence

from sympy import Matrix, Poly, Symbol
from sympy.matrices.normalforms import hermite_normal_form

from .parser import Document, scalar_records
from .source_units import parse_python


@dataclass(frozen=True)
class HintFactorRSA:
    modulus: int
    hint: int
    scale: int
    ciphertexts: tuple[int, ...]
    odd_exponent: int
    source_path: str = ""


def _name(node: ast.AST | None) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
    return None


def _integer(node: ast.AST, constants: dict[str, int]) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return int(node.value)
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if not isinstance(node, ast.BinOp):
        return None
    left, right = _integer(node.left, constants), _integer(node.right, constants)
    if left is None or right is None:
        return None
    if isinstance(node.op, ast.Add):
        return left + right
    if isinstance(node.op, ast.Sub):
        return left - right
    if isinstance(node.op, ast.Mult):
        return left * right
    if isinstance(node.op, ast.Pow) and 0 <= right <= 16:
        return left**right
    return None


def _constants(tree: ast.AST) -> dict[str, int]:
    values: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = _name(node.targets[0])
            value = _integer(node.value, values)
            if target is not None and value is not None and abs(value).bit_length() <= 256:
                values[target] = value
    return values


def _prime_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        if isinstance(node.value, ast.Call) and _call_name(node.value) in {"getPrime", "getStrongPrime"}:
            target = _name(node.targets[0])
            if target is not None:
                names.add(target)
    return names


def _modulus_name(tree: ast.AST, primes: set[str], constants: dict[str, int]) -> str | None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = _name(node.targets[0])
        value = node.value
        if target is None or not isinstance(value, ast.BinOp) or not isinstance(value.op, ast.Mult):
            continue
        if {_name(value.left), _name(value.right)} == primes and len(primes) == 2:
            return target
        if _integer(value, constants) is not None and target.casefold() in {"n", "modulus"}:
            return target
    return None


def _radical_term(node: ast.AST, primes: set[str]):
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mult):
        return None
    radical = next((part for part in (node.left, node.right)
                    if isinstance(part, ast.Call) and _call_name(part) in {"sqrt", "isqrt"}), None)
    factor = next((part for part in (node.left, node.right) if part is not radical), None)
    if (not isinstance(radical, ast.Call) or len(radical.args) != 1
            or _name(radical.args[0]) not in primes):
        return None
    return _name(radical.args[0]), factor


def _sqrt_terms(node: ast.AST, primes: set[str]) -> tuple[str, str, int] | None:
    if isinstance(node, ast.Call) and _call_name(node) == "int" and len(node.args) == 1:
        node = node.args[0]
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
        return None
    terms = [_radical_term(term, primes) for term in (node.left, node.right)]
    if any(term is None for term in terms):
        return None
    if {term[0] for term in terms} != primes or ast.dump(terms[0][1]) != ast.dump(terms[1][1]):
        return None
    return terms[0][0], terms[1][0], ast.dump(terms[0][1])


def _hint_scale(node: ast.AST, constants: dict[str, int]) -> int | None:
    expr = node.args[0] if isinstance(node, ast.Call) else node
    if not isinstance(expr, ast.BinOp):
        return None
    factors = []
    for term in (expr.left, expr.right):
        if not isinstance(term, ast.BinOp) or not isinstance(term.op, ast.Mult):
            return None
        factor = next((part for part in (term.left, term.right)
                       if not (isinstance(part, ast.Call) and _call_name(part) in {"sqrt", "isqrt"})), None)
        factors.append(_integer(factor, constants))
    return factors[0] if factors[0] and factors[0] == factors[1] else None


def _hint_profile(tree: ast.AST, constants: dict[str, int], primes: set[str]):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = _name(node.targets[0])
        if target is None:
            continue
        if _sqrt_terms(node.value, primes) is not None:
            scale = _hint_scale(node.value, constants)
            if scale is not None and scale > 1:
                return target, scale
    return None


def _exponent_value(node: ast.AST, constants: dict[str, int]) -> int | None:
    value = _integer(node, constants)
    if value is None and isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        value = _integer(node.left, constants) or _integer(node.right, constants)
    return value


def _exponent_profile(tree: ast.AST, modulus_name: str, constants: dict[str, int]) -> int | None:
    exponents = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node) != "pow" or len(node.args) != 3:
            continue
        if _name(node.args[2]) != modulus_name:
            continue
        exponent = _exponent_value(node.args[1], constants)
        if exponent is not None and exponent > 1:
            exponents.append(exponent)
    odd = sorted({value for value in exponents if value & 1})
    return odd[0] if len(odd) == 1 else None


def _source_profile(document: Document):
    tree = parse_python(document)
    if tree is None or len(document.text) > 4_000_000:
        return None
    constants = _constants(tree)
    primes = _prime_names(tree)
    modulus = _modulus_name(tree, primes, constants)
    hint = _hint_profile(tree, constants, primes)
    if modulus is None or hint is None:
        return None
    exponent = _exponent_profile(tree, modulus, constants)
    if exponent is None:
        return None
    return modulus, hint[1], exponent


def _public_values(documents: Sequence[Document]):
    matches = []
    for document in documents:
        for record in scalar_records(document.text):
            values = {key.casefold(): value for key, value in record.items()}
            hint, scale, modulus, ciphertexts = (
                values.get("hint"), values.get("d", values.get("scale")),
                values.get("n", values.get("modulus")), values.get("c", values.get("ciphertexts")),
            )
            if (type(hint) is int and type(scale) is int and type(modulus) is int
                    and isinstance(ciphertexts, (list, tuple))
                    and all(type(value) is int for value in ciphertexts)):
                matches.append((document, hint, scale, modulus, tuple(ciphertexts)))
    return matches


def _valid_output(source: Document, profile, item) -> HintFactorRSA | None:
    document, hint, scale, modulus, ciphertexts = item
    modulus_name, expected_scale, exponent = profile
    if document.scope != source.scope or scale != expected_scale or document.path == source.path:
        return None
    if modulus <= 3 or hint <= 0 or modulus.bit_length() > 8192:
        return None
    if not ciphertexts or any(value < 0 or value >= modulus for value in ciphertexts):
        return None
    if modulus_name.casefold() not in {"n", "modulus"} and modulus_name not in document.text:
        return None
    return HintFactorRSA(modulus, hint, scale, ciphertexts, exponent, source.path)


def extract_instance(documents: Sequence[Document]) -> HintFactorRSA | None:
    profiles = [(document, _source_profile(document)) for document in documents]
    profiles = [(document, profile) for document, profile in profiles if profile is not None]
    if len(profiles) != 1:
        return None
    source, (modulus_name, scale, exponent) = profiles[0]
    matches = [candidate for candidate in
               (_valid_output(source, (modulus_name, scale, exponent), item)
                for item in _public_values(documents)) if candidate is not None]
    return matches[0] if len(matches) == 1 else None


def _approximate_factor(instance: HintFactorRSA) -> int:
    bits = instance.modulus.bit_length()
    with localcontext() as context:
        context.prec = bits // 2 + 80
        n = Decimal(instance.modulus)
        d = Decimal(instance.hint) ** 2 - Decimal(4 * instance.scale**2) * n.sqrt()
        root = (Decimal(instance.hint) + (d if d > 0 else Decimal(0)).sqrt()) / 2
        return int((root / Decimal(instance.scale)) ** 2)


def _lattice_rows(modulus: int, offset: int, bound: int, m: int, t: int):
    width = m + t + 1
    rows = []
    for i in range(m + 1):
        for j in range(t + 1):
            coefficients = [0] * width
            for k in range(i + 1):
                coefficients[j + k] = math.comb(i, k) * offset ** (i - k) * modulus ** (m - i)
            rows.append([value * bound**degree for degree, value in enumerate(coefficients)])
    return rows


def _integer_roots(rows, bound: int, offset: int, modulus: int):
    symbol = Symbol("x")
    candidates = set()
    for row in rows:
        coefficients = [int(value) // bound**degree for degree, value in enumerate(row)]
        polynomial = Poly(sum(value * symbol**degree for degree, value in enumerate(coefficients)), symbol)
        for root in polynomial.ground_roots():
            if root.is_Integer and abs(int(root)) < bound:
                candidates.add(offset + int(root))
    return [candidate for candidate in candidates if candidate > 1 and modulus % candidate == 0]


def _recover_factor(instance: HintFactorRSA) -> int:
    offset = _approximate_factor(instance)
    bound = 1 << max(16, instance.modulus.bit_length() // 2 - 590)
    # The challenge family publishes a ~590-bit absolute error for 1337-bit
    # factors.  Derive a conservative bound from the modulus, then enlarge it
    # slightly for smaller educational instances.
    bound = max(bound, 1 << (instance.modulus.bit_length() // 4 + 8))
    for m, t in ((1, 1), (2, 2), (3, 3), (4, 5), (6, 9)):
        matrix = Matrix(_lattice_rows(instance.modulus, offset, bound, m, t))
        basis = hermite_normal_form(matrix.T).T.lll().tolist()
        factors = _integer_roots(basis, bound, offset, instance.modulus)
        if factors:
            return min(factors, key=lambda value: abs(value - offset))
    raise RuntimeError("approximate-factor lattice did not recover a divisor")


def recover_flag(documents: Sequence[Document]) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("no source-verified square-root RSA hint instance")
    factor = _recover_factor(instance)
    if not (1 < factor < instance.modulus and instance.modulus % factor == 0):
        raise RuntimeError("lattice returned an invalid RSA factor")
    bits = []
    for ciphertext in instance.ciphertexts:
        legendre = pow(ciphertext, (factor - 1) // 2, factor)
        if legendre not in {1, factor - 1}:
            raise RuntimeError("ciphertext is not a quadratic-residue bit encoding")
        bits.append("1" if legendre == 1 else "0")
    raw = int("".join(bits), 2).to_bytes((len(bits) + 7) // 8, "big")
    return raw.lstrip(b"\x00").decode("utf-8")

