from __future__ import annotations

import math
from collections.abc import Iterable


def integer_nth_root(value: int, degree: int) -> tuple[int, bool]:
    if value < 0 or degree < 1:
        raise ValueError("value must be non-negative and degree positive")
    if value in (0, 1):
        return value, True
    low, high = 0, 1 << ((value.bit_length() + degree - 1) // degree)
    while low + 1 < high:
        mid = (low + high) // 2
        powered = mid**degree
        if powered <= value:
            low = mid
        else:
            high = mid
    return low, low**degree == value


def fermat_factor(n: int, max_steps: int = 100_000) -> tuple[int, int, int] | None:
    if n <= 0 or n % 2 == 0:
        return None
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for step in range(max_steps + 1):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return p, q, step
        a += 1
    return None


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def signed_mod_pow(base: int, exponent: int, modulus: int) -> int:
    if exponent < 0:
        base = pow(base, -1, modulus)
        exponent = -exponent
    return pow(base, exponent, modulus)


def int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\0"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def crt(values: Iterable[tuple[int, int]]) -> tuple[int, int]:
    """Return x and modulus for pairwise-coprime (remainder, modulus) pairs."""
    pairs = list(values)
    modulus = math.prod(n for _, n in pairs)
    result = 0
    for remainder, current in pairs:
        partial = modulus // current
        result = (result + remainder * partial * pow(partial, -1, current)) % modulus
    return result, modulus


def continued_fraction(numerator: int, denominator: int) -> list[int]:
    terms: list[int] = []
    while denominator:
        quotient, numerator, denominator = numerator // denominator, denominator, numerator % denominator
        terms.append(quotient)
    return terms


def convergents(terms: Iterable[int]) -> Iterable[tuple[int, int]]:
    p0, p1, q0, q1 = 0, 1, 1, 0
    for term in terms:
        p0, p1 = p1, term * p1 + p0
        q0, q1 = q1, term * q1 + q0
        yield p1, q1


def wiener_private_exponent(n: int, e: int) -> tuple[int, int, int] | None:
    """Recover d when RSA uses Wiener's small-private-exponent regime."""
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0 or d == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        total = n - phi + 1
        discriminant = total * total - 4 * n
        if discriminant < 0:
            continue
        root = math.isqrt(discriminant)
        if root * root == discriminant and (total + root) % 2 == 0:
            p, q = (total + root) // 2, (total - root) // 2
            if p > 1 and p * q == n:
                return d, p, q
    return None


def discrete_log_bsgs(base: int, target: int, modulus: int, max_steps: int = 1_000_000) -> int | None:
    size = math.isqrt(modulus - 1) + 1
    if size > max_steps or math.gcd(base, modulus) != 1:
        return None
    table: dict[int, int] = {}
    value = 1
    for exponent in range(size):
        table.setdefault(value, exponent)
        value = value * base % modulus
    factor = pow(pow(base, size, modulus), -1, modulus)
    gamma = target % modulus
    for giant in range(size + 1):
        if gamma in table:
            exponent = giant * size + table[gamma]
            if pow(base, exponent, modulus) == target % modulus:
                return exponent
        gamma = gamma * factor % modulus
    return None
