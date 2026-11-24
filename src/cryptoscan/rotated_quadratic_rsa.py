"""Recover RSA keys from two high-precision, jointly rotated norm representations.

The source must establish x_i**2 + e*y_i**2 = n twice, publish a common
orthogonal rotation of the two integer vectors, and encrypt an XOR-masked
message. No challenge program is executed and every numerical guess is
checked with exact integer arithmetic before it is used.
"""
from __future__ import annotations

import ast
import math
from collections.abc import Sequence
from dataclasses import dataclass

from mpmath import mp

from .parser import Document, assignments

MAX_DECIMAL_DIGITS = 2000


@dataclass(frozen=True)
class Profile:
    modulus: str
    ciphertext: str
    public_exponent: str
    vectors: tuple[str, str]
    coordinates: tuple[str, str, str, str]


@dataclass(frozen=True)
class Instance:
    n: int
    ciphertext: int
    x: tuple[str, str]
    y: tuple[str, str]
    profile: Profile


def _name(node):
    return node.id if isinstance(node, ast.Name) else None


def _call(node, function):
    return isinstance(node, ast.Call) and _name(node.func) == function


def _power_of(node, name):
    return (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow)
            and _name(node.left) == name
            and isinstance(node.right, ast.Constant) and node.right.value == 2)


def _quadratic(node, x, y, exponent):
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
        return False
    left, right = node.left, node.right
    return (_power_of(left, x)
            and isinstance(right, ast.BinOp) and isinstance(right.op, ast.Mult)
            and _name(right.left) == exponent and _power_of(right.right, y))


def _vectors(tree):
    found = []
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
            continue
        name = _name(stmt.targets[0])
        value = stmt.value
        if (name is None or not _call(value, "vector") or len(value.args) != 2
                or not isinstance(value.args[1], (ast.List, ast.Tuple))):
            continue
        elements = value.args[1].elts
        if len(elements) == 2 and all(_name(item) for item in elements):
            found.append((name, tuple(_name(item) for item in elements)))
    return found


def _rotation(tree, vector_names):
    matrices = _rotation_matrices(tree)
    rotated = _rotated_assignments(tree, vector_names, matrices)
    return any({(name, matrix) for name in vector_names} <= rotated for matrix in matrices)


def _rotation_matrices(tree):
    matrices = set()
    for stmt in tree.body:
        if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                and _name(stmt.targets[0]) and _call(stmt.value, "matrix")):
            matrix = stmt.value.args[-1] if stmt.value.args else None
            if _rotation_matrix(matrix):
                matrices.add(_name(stmt.targets[0]))
    return matrices


def _rotated_assignments(tree, vector_names, matrices):
    rotated = set()
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
            continue
        target = _name(stmt.targets[0])
        value = stmt.value
        if (target in vector_names and isinstance(value, ast.BinOp)
                and isinstance(value.op, ast.Mult) and _name(value.left) in matrices
                and _name(value.right) == target):
            rotated.add((target, _name(value.left)))
    return rotated


def _rotation_matrix(node):
    if not isinstance(node, (ast.List, ast.Tuple)) or len(node.elts) != 2:
        return False
    rows = node.elts
    if not all(isinstance(row, (ast.List, ast.Tuple)) and len(row.elts) == 2 for row in rows):
        return False
    a, b = rows[0].elts
    c, d = rows[1].elts
    if not (_call(a, "cos") and _call(d, "cos") and _call(c, "sin")):
        return False
    if not (len(a.args) == len(c.args) == len(d.args) == 1):
        return False
    if not (ast.dump(a) == ast.dump(d) and ast.dump(a.args[0]) == ast.dump(c.args[0])):
        return False
    return (isinstance(b, ast.UnaryOp) and isinstance(b.op, ast.USub)
            and ast.dump(b.operand) == ast.dump(c))


def _xor_terms(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor):
        return _xor_terms(node.left) + _xor_terms(node.right)
    return [node]


def _encrypted_message(tree, names, exponent, modulus):
    coordinates = set(names)
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
            continue
        call = stmt.value
        if not _call(call, "pow") or len(call.args) != 3:
            continue
        base, power, mod = call.args
        if _name(power) != exponent or _name(mod) != modulus:
            continue
        terms = _xor_terms(base)
        literals = [_name(term) for term in terms if isinstance(term, ast.Name)]
        encoders = [term for term in terms if _call(term, "bytes_to_long")]
        if len(terms) == 5 and set(literals) == coordinates and len(encoders) == 1:
            return _name(stmt.targets[0])
    return None


def _moduli(tree):
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
            continue
        value = stmt.value
        if (isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mult)
                and _name(value.left) and _name(value.right)):
            yield _name(stmt.targets[0]), value


def _relations(tree, modulus_node, x, y):
    candidates = set()
    for stmt in tree.body:
        compare = _matching_assertion(stmt, modulus_node)
        if compare is None:
            continue
        for exponent in (_name(item) for item in ast.walk(compare.left)):
            if exponent and _quadratic(compare.left, x, y, exponent):
                candidates.add(exponent)
    return candidates


def _matching_assertion(stmt, modulus_node):
    if not isinstance(stmt, ast.Assert):
        return None
    compare = stmt.test
    if not isinstance(compare, ast.Compare) or len(compare.ops) != 1:
        return None
    if not isinstance(compare.ops[0], ast.Eq):
        return None
    if ast.dump(compare.comparators[0]) != ast.dump(modulus_node):
        return None
    return compare


def source_profiles(document: Document) -> list[Profile]:
    if len(document.text) > 2_000_000:
        return []
    try:
        # Sage's ^^ is XOR; Python's AST spells the same operation ^.
        tree = ast.parse(document.text.replace("^^", "^"))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    vectors = _vectors(tree)
    if len(vectors) != 2 or not _rotation(tree, tuple(name for name, _ in vectors)):
        return []
    (x_name, x), (y_name, y) = vectors
    coordinates = (*x, *y)
    if len(set(coordinates)) != 4:
        return []
    result = []
    for modulus, expression in _moduli(tree):
        exponents = _relations(tree, expression, x[0], y[0])
        exponents &= _relations(tree, expression, x[1], y[1])
        for exponent in exponents:
            cipher = _encrypted_message(tree, coordinates, exponent, modulus)
            if cipher:
                result.append(Profile(modulus, cipher, exponent,
                                      (x_name, y_name), coordinates))
    return result


def _decimal_pair(text, label):
    matches = []
    for line in text.splitlines():
        name, sep, value = line.partition("=")
        if not sep or name.strip() != label:
            continue
        value = value.strip()
        if not value.startswith("(") or not value.endswith(")"):
            return None
        parts = value[1:-1].split(",")
        if len(parts) != 2 or any(len(part) > MAX_DECIMAL_DIGITS for part in parts):
            return None
        if not all(part.strip() and set(part.strip()) <= set("0123456789+-.eE") for part in parts):
            return None
        matches.append(tuple(part.strip() for part in parts))
    return matches[0] if len(matches) == 1 else None


def extract_instance(documents: Sequence[Document]) -> Instance | None:
    found = set()
    for source in documents:
        for profile in source_profiles(source):
            found.update(_instances_for_profile(profile, source, documents))
    return next(iter(found)) if len(found) == 1 else None


def _instances_for_profile(profile, source, documents):
    for output in documents:
        if output.path == source.path or output.scope != source.scope:
            continue
        instance = _public_instance(profile, output)
        if instance is not None:
            yield instance


def _public_instance(profile, output):
    values = assignments(output.text)
    n = values.get(profile.modulus.casefold())
    ciphertext = values.get(profile.ciphertext.casefold())
    x = _decimal_pair(output.text, profile.vectors[0])
    y = _decimal_pair(output.text, profile.vectors[1])
    if (type(n) is int and 8 <= n.bit_length() <= 8192
            and type(ciphertext) is int and 0 <= ciphertext < n
            and x is not None and y is not None):
        return Instance(n, ciphertext, x, y, profile)
    return None


def _candidate_vectors(x, y, theta):
    cosine, sine = mp.cos(theta), mp.sin(theta)
    first = (cosine * x[0] + sine * x[1], -sine * x[0] + cosine * x[1])
    second = (cosine * y[0] + sine * y[1], -sine * y[0] + cosine * y[1])
    return tuple(int(mp.nint(value)) for value in (*first, *second))


def _exact_recovery(instance, exponent, values):
    x0, x1, y0, y1 = values
    n = instance.n
    if min(values) < 0 or x0*x0 + exponent*y0*y0 != n:
        return None
    if x1*x1 + exponent*y1*y1 != n:
        return None
    p = math.gcd(x0*y1 - x1*y0, n)
    if not 1 < p < n or n % p:
        return None
    q = n // p
    from Crypto.Util.number import isPrime

    if not (isPrime(p) and isPrime(q)):
        return None
    try:
        private = pow(exponent, -1, (p - 1) * (q - 1))
    except ValueError:
        return None
    masked = pow(instance.ciphertext, private, n)
    if pow(masked, exponent, n) != instance.ciphertext:
        return None
    message = masked ^ x0 ^ x1 ^ y0 ^ y1
    return message.to_bytes((message.bit_length() + 7) // 8, "big")


def recover_message(instance: Instance) -> bytes:
    """Recover only from an exact factor and two exact norm equations."""
    digits = max(len(value) for value in (*instance.x, *instance.y))
    with mp.workdps(min(2200, max(100, digits + 30))):
        x = tuple(mp.mpf(value) for value in instance.x)
        y = tuple(mp.mpf(value) for value in instance.y)
        y_norm = y[0]*y[0] + y[1]*y[1]
        if y_norm == 0:
            raise RuntimeError("zero norm in published vector")
        approximate = (2*instance.n - x[0]*x[0] - x[1]*x[1]) / y_norm
        exponent = int(mp.nint(approximate))
        if exponent <= 1 or exponent.bit_length() > 4096 or abs(approximate-exponent) >= mp.mpf("0.25"):
            raise RuntimeError("no unique integral exponent from rotation invariant")
        a = x[0]*x[0] + exponent*y[0]*y[0] - x[1]*x[1] - exponent*y[1]*y[1]
        b = 2*(x[0]*x[1] + exponent*y[0]*y[1])
        if a == 0 and b == 0:
            raise RuntimeError("rotation is underdetermined")
        theta = mp.atan2(-a, b) / 2
        results = set()
        for quarter_turn in range(4):
            values = _candidate_vectors(x, y, theta + quarter_turn*mp.pi/2)
            recovered = _exact_recovery(instance, exponent, values)
            if recovered is not None:
                results.add(recovered)
        if len(results) == 1:
            return results.pop()
    raise RuntimeError("no unique exact RSA recovery from rotated vectors")


def recover_flag(documents: Sequence[Document]) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("no unambiguous rotated quadratic RSA instance")
    return recover_message(instance).decode("utf-8")

