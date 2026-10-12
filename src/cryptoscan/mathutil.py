from __future__ import annotations

import math


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
