"""Recognize and solve explicitly requested integer factorizations."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Sequence

from sympy import factorint, isprime

MIN_BITS = 16
MAX_BITS = 192
_DECIMAL = r"(?:0|[1-9][0-9]{4,})"
_HEXADECIMAL = r"0[xX][0-9a-fA-F]{4,}"
_NUMBER = rf"({_HEXADECIMAL}|{_DECIMAL})"
_REQUESTS = (
    re.compile(rf"(?is)\b(?:factori[sz]e|factorization|factorisation)\b"
               rf"[^\r\n]{{0,100}}?\b(?:number|integer|modulus|n)\b"
               rf"[^\r\n]{{0,30}}?{_NUMBER}(?![0-9a-fA-F])"),
    re.compile(rf"(?is)\b(?:factori[sz]e|factorization|factorisation)\s+{_NUMBER}"
               rf"(?![0-9a-fA-F])"),
    re.compile(rf"(?is)\b(?:find|give|compute|recover)\b[^.\r\n]{{0,100}}?"
               rf"\b(?:prime factors?|factorization|factorisation)\b"
               rf"[^\r\n]{{0,100}}?{_NUMBER}(?![0-9a-fA-F])"),
)


@dataclass(frozen=True)
class FactorizationTask:
    modulus: int
    location: str


def _requested_values(text: str) -> list[int]:
    values = []
    for pattern in _REQUESTS:
        for match in pattern.finditer(text):
            token = match.group(1)
            value = int(token, 16 if token.lower().startswith("0x") else 10)
            if MIN_BITS <= value.bit_length() <= MAX_BITS:
                values.append(value)
    return values


def extract_instance(documents: Sequence[object]) -> FactorizationTask | None:
    """Extract a bounded integer only when the text explicitly requests factors."""
    matches: dict[int, str] = {}
    for document in documents:
        text = getattr(document, "text", "")
        if isinstance(text, str):
            for value in _requested_values(text):
                matches.setdefault(value, str(getattr(document, "path", "input")))
    if len(matches) != 1:
        return None
    modulus, location = next(iter(matches.items()))
    return FactorizationTask(modulus, location)


def smallest_prime_factor(task: FactorizationTask) -> int:
    """Factor a bounded integer and certify a complete prime factorization."""
    if not isinstance(task.modulus, int) or task.modulus < 2:
        raise ValueError("invalid factorization input")
    if not MIN_BITS <= task.modulus.bit_length() <= MAX_BITS:
        raise ValueError("integer is outside the configured factorization size bound")
    try:
        from flint import fmpz
    except ImportError:
        factors = factorint(task.modulus)
    else:
        factors = dict(fmpz(task.modulus).factor())
    if math.prod(int(prime) ** int(power) for prime, power in factors.items()) != task.modulus:
        raise ValueError("factorization is incomplete")
    primes = [int(prime) for prime, power in factors.items() if int(power) > 0]
    if (sum(int(power) for power in factors.values()) < 2 or not primes
            or not all(isprime(prime) for prime in primes)):
        raise ValueError("factorization did not produce certified primes")
    return min(primes)


def recover_answer(documents: Sequence[object]) -> str:
    task = extract_instance(documents)
    if task is None:
        raise ValueError("no unique bounded factorization request found")
    return str(smallest_prime_factor(task))

