"""Recognize RSA encryption of modular inverses and their inverse moduli."""
from __future__ import annotations

import ast
import math
from collections.abc import Sequence
from dataclasses import dataclass

from .parser import Document, assignments
from .source_units import parse_python

MAX_RECOVERY_EXPONENT = 17


@dataclass(frozen=True)
class Profile:
    exponent: int
    modulus: str
    inverse_cipher: str
    order_cipher: str
    message_cipher: str | None


@dataclass(frozen=True)
class Instance:
    exponent: int
    modulus: int
    inverse_cipher: int
    order_cipher: int
    message_cipher: int


def _bindings(tree):
    """Only analyze unambiguous straight-line assignments."""
    result = {}
    for stmt in tree.body:
        match stmt:
            case ast.Assign(targets=[ast.Name(id=name)], value=value):
                if name in result:
                    return {}
                result[name] = value
            case _:
                continue
    return result


def _power(node):
    match node:
        case ast.Call(func=ast.Name(id="pow"), args=[base, exponent, modulus], keywords=[]):
            return base, exponent, modulus
    return None


def _same(left, right):
    return ast.dump(left) == ast.dump(right)


def _exponent(node, bindings):
    if isinstance(node, ast.Name):
        node = bindings.get(node.id)
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None


def _cipher_groups(bindings):
    for name, value in bindings.items():
        power = _power(value)
        if power is not None:
            yield name, power


def _profile_inverse(inverse_name, inverse, bindings):
    public, negative_one, order = inverse
    if not isinstance(order, ast.Name):
        return
    if not _same(negative_one, ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=1))):
        return
    exponent = _exponent(public, bindings)
    # Detection is mathematical, not solver-specific.  Very large public
    # exponents are still a related-key leak even when this polynomial
    # recovery implementation deliberately declines to solve them.
    if exponent is None or exponent < 3 or exponent % 2 == 0:
        return
    groups = {}
    for name, (base, power, modulus) in _cipher_groups(bindings):
        if isinstance(modulus, ast.Name) and _exponent(power, bindings) == exponent:
            groups.setdefault(modulus.id, []).append((name, base))
    for modulus, entries in groups.items():
        inverse_ciphers = [name for name, base in entries if isinstance(base, ast.Name) and base.id == inverse_name]
        order_ciphers = [name for name, base in entries if isinstance(base, ast.Name) and base.id == order.id]
        other = [name for name, _ in entries if name not in inverse_ciphers + order_ciphers]
        if len(inverse_ciphers) == len(order_ciphers) == 1:
            # Payload recovery is intentionally optional.  The vulnerability
            # exists as soon as encryptions of d and phi(n) are published.
            # A solver target is attached only when exactly one additional
            # ciphertext is present, avoiding challenge-specific guessing.
            message_cipher = other[0] if len(other) == 1 else None
            yield Profile(exponent, modulus, inverse_ciphers[0], order_ciphers[0], message_cipher)


def source_profiles(document: Document) -> list[Profile]:
    tree = parse_python(document)
    if tree is None:
        return []
    bindings = _bindings(tree)
    result = []
    for name, power in _cipher_groups(bindings):
        result.extend(_profile_inverse(name, power, bindings))
    return result


def _public_instance(profile, output):
    if profile.message_cipher is None or profile.exponent > MAX_RECOVERY_EXPONENT:
        return None
    values = assignments(output.text)
    labels = (profile.modulus, profile.inverse_cipher, profile.order_cipher, profile.message_cipher)
    numbers = [values.get(label.casefold()) for label in labels]
    if not all(type(number) is int for number in numbers):
        return None
    n, *ciphertexts = numbers
    if not 8 <= n.bit_length() <= 16384 or n % 2 == 0:
        return None
    if not all(0 <= value < n for value in ciphertexts):
        return None
    return Instance(profile.exponent, n, *ciphertexts)


def extract_instance(documents: Sequence[Document]):
    matches = set()
    for source in documents:
        for profile in source_profiles(source):
            for output in documents:
                if output.scope == source.scope and output.path != source.path:
                    instance = _public_instance(profile, output)
                    if instance is not None:
                        matches.add(instance)
    return next(iter(matches)) if len(matches) == 1 else None


def _trim(poly):
    while poly and poly[-1] == 0:
        poly.pop()
    return poly


def _remainder(left, right, modulus):
    remainder = left[:]
    inverse = pow(right[-1], -1, modulus)
    while len(remainder) >= len(right):
        shift = len(remainder) - len(right)
        scale = remainder[-1] * inverse % modulus
        for index, coefficient in enumerate(right):
            remainder[index + shift] = (remainder[index + shift] - scale * coefficient) % modulus
        _trim(remainder)
    return remainder


def _linear_root(left, right, modulus):
    try:
        while right:
            left, right = right, _remainder(left, right, modulus)
        if len(left) == 2:
            return -left[0] * pow(left[1], -1, modulus) % modulus
    except ValueError:
        # Nonunits in the composite ring are not a linear-root certificate.
        return None
    return None


def _candidate_order(instance, multiplier):
    e, n = instance.exponent, instance.modulus
    left = [-instance.order_cipher % n] + [0] * (e - 1) + [1]
    right = [math.comb(e, j) * pow(multiplier, j, n) % n for j in range(e + 1)]
    right[0] = (right[0] - pow(e, e, n) * instance.inverse_cipher) % n
    return _linear_root(left, _trim(right), n)


def _verified_private(instance, order, multiplier):
    e, n = instance.exponent, instance.modulus
    if not 0 < order < n or pow(order, e, n) != instance.order_cipher:
        return None
    total = n + 1 - order
    discriminant = total * total - 4 * n
    if discriminant < 0:
        return None
    root = math.isqrt(discriminant)
    if root * root != discriminant or (total + root) % 2:
        return None
    p, q = (total + root) // 2, (total - root) // 2
    if q <= 1 or p == q or p * q != n:
        return None
    from Crypto.Util.number import isPrime

    if not (isPrime(p) and isPrime(q)):
        return None
    private, remainder = divmod(1 + multiplier * order, e)
    if remainder or not 0 < private < order:
        return None
    return private if pow(private, e, n) == instance.inverse_cipher else None


def recover_message(instance: Instance) -> bytes:
    """Recover only when the totient, factors and all ciphertexts agree."""
    for multiplier in range(1, instance.exponent):
        order = _candidate_order(instance, multiplier)
        if order is None:
            continue
        private = _verified_private(instance, order, multiplier)
        if private is None:
            continue
        message = pow(instance.message_cipher, private, instance.modulus)
        if pow(message, instance.exponent, instance.modulus) == instance.message_cipher:
            return message.to_bytes((message.bit_length() + 7) // 8, "big")
    raise RuntimeError("no certified RSA related-key-material recovery")


def recover_flag(documents: Sequence[Document]) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("no unambiguous related RSA ciphertexts")
    return recover_message(instance).decode("utf-8")
