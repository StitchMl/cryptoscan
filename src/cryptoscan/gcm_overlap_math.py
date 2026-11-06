"""Offline finite-field arithmetic for a GCM implementation with counter overlap.

Only valid if analyzed source proves plaintext GCTR begins at J0 and tag GCTR
also begins at J0, using GHASH over the supplied ciphertext/AAD.
No target-specific constants or HTTP/network operations.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

ONE = 1 << 127
REDUCTION = 0xE1000000000000000000000000000000


def gf_mul(x: int, y: int) -> int:
    acc = 0
    for bit in range(128):
        if x & (1 << (127 - bit)):
            acc ^= y
        y = (y >> 1) ^ (REDUCTION if y & 1 else 0)
    return acc


def gf_exp(x: int, exponent: int) -> int:
    result = ONE
    while exponent:
        if exponent & 1:
            result = gf_mul(result, x)
        exponent >>= 1
        if exponent:
            x = gf_mul(x, x)
    return result


def _trim(poly: list[int]) -> list[int]:
    while poly and poly[-1] == 0:
        poly.pop()
    return poly


def _add(a: list[int], b: list[int]) -> list[int]:
    out = [0] * max(len(a), len(b))
    for i, value in enumerate(a):
        out[i] ^= value
    for i, value in enumerate(b):
        out[i] ^= value
    return _trim(out)


def _divmod(a: list[int], b: list[int]) -> tuple[list[int], list[int]]:
    a, b = _trim(a[:]), _trim(b[:])
    if not b:
        raise ZeroDivisionError("zero GF(2^128) polynomial")
    quotient = [0] * max(0, len(a) - len(b) + 1)
    inv = gf_exp(b[-1], (1 << 128) - 2)
    while a and len(a) >= len(b):
        offset = len(a) - len(b)
        factor = gf_mul(a[-1], inv)
        quotient[offset] = factor
        for i, coefficient in enumerate(b):
            a[offset + i] ^= gf_mul(factor, coefficient)
        _trim(a)
    return _trim(quotient), a


def _mod(a: list[int], b: list[int]) -> list[int]:
    return _divmod(a, b)[1]


def _gcd(a: list[int], b: list[int]) -> list[int]:
    while b:
        a, b = b, _mod(a, b)
    if not a:
        return []
    inv = gf_exp(a[-1], (1 << 128) - 2)
    return _trim([gf_mul(value, inv) for value in a])


def _square_mod(poly: list[int], modulus: list[int]) -> list[int]:
    squared = [0] * (2 * len(poly) - 1)
    for index, coefficient in enumerate(poly):
        squared[2 * index] = gf_mul(coefficient, coefficient)
    return _mod(_trim(squared), modulus)


def polynomial_roots(poly: list[int]) -> list[int]:
    poly = _trim(poly[:])
    if len(poly) < 2:
        return []
    monic = _divmod(poly, [poly[-1]])[0]
    x = [0, ONE]
    power = x[:]
    for _ in range(128):
        power = _square_mod(power, monic)
    linear = _gcd(monic, _add(power, x))
    if len(linear) < 2:
        return []
    rng = random.Random(0xC7F)

    def split(factor: list[int]) -> list[int]:
        if len(factor) == 2:
            return [gf_mul(factor[0], gf_exp(factor[1], (1 << 128) - 2))]
        for _ in range(64):
            trace = []
            term = _mod([0, rng.getrandbits(128)], factor)
            for _ in range(128):
                trace = _add(trace, term)
                term = _square_mod(term, factor)
            part = _gcd(factor, trace)
            if len(part) in (0, 1, len(factor)):
                continue
            quotient, remainder = _divmod(factor, part)
            if remainder:
                raise ValueError("polynomial split verification failed")
            return split(part) + split(quotient)
        raise ValueError("could not split polynomial; use additional observations")

    return sorted(set(split(linear)))


def _blocks(ciphertext: bytes, aad: bytes) -> list[int]:
    data = aad + bytes(-len(aad) % 16)
    data += ciphertext + bytes(-len(ciphertext) % 16)
    data += (8 * len(aad)).to_bytes(8, "big")
    data += (8 * len(ciphertext)).to_bytes(8, "big")
    return [int.from_bytes(data[i:i + 16], "big") for i in range(0, len(data), 16)]


def ghash(h: int, ciphertext: bytes, aad: bytes = b"") -> int:
    value = 0
    for block in _blocks(ciphertext, aad):
        value = gf_mul(value ^ block, h)
    return value


@dataclass(frozen=True)
class Candidate:
    token: str
    plaintext: bytes
    subkey_hex: str


def compute_counter_overlap_candidates(
    observed_token: str, known_plaintext: bytes, desired_plaintext: bytes,
    aad: bytes = b"", max_blocks: int = 32,
) -> list[Candidate]:
    """Produce GHASH-consistent candidates; do not infer acceptance by a server."""
    parts = observed_token.strip().split(";")
    if len(parts) != 2:
        raise ValueError("expected ciphertext_hex;tag_hex")
    try:
        ciphertext, tag = (bytes.fromhex(value) for value in parts)
    except ValueError as exc:
        raise ValueError("invalid hexadecimal token") from exc
    if len(tag) != 16:
        raise ValueError("tag must have 16 bytes")
    if len(known_plaintext) != len(ciphertext):
        raise ValueError("known plaintext length differs from ciphertext")
    if len(known_plaintext) < 16:
        raise ValueError("at least 16 known plaintext bytes are required")
    if len(desired_plaintext) > len(known_plaintext):
        raise ValueError("desired plaintext exceeds available known keystream")
    blocks = _blocks(ciphertext, aad)
    if len(blocks) > max_blocks:
        raise ValueError("GHASH polynomial exceeds solver block bound")
    mask = int.from_bytes(bytes(a ^ b for a, b in zip(known_plaintext[:16], ciphertext[:16])), "big")
    observed_ghash = int.from_bytes(tag, "big") ^ mask
    roots = polynomial_roots([observed_ghash] + blocks[::-1])
    valid = [h for h in roots if ghash(h, ciphertext, aad) == observed_ghash]
    keystream = bytes(a ^ b for a, b in zip(known_plaintext, ciphertext))
    modified = bytes(a ^ b for a, b in zip(desired_plaintext, keystream))
    answers = []
    for h in valid:
        tag_value = (ghash(h, modified, aad) ^ mask).to_bytes(16, "big")
        answers.append(Candidate(
            modified.hex() + ";" + tag_value.hex(), desired_plaintext,
            h.to_bytes(16, "big").hex(),
        ))
    return answers
