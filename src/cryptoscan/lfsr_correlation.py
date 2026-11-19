"""Reusable binary LFSR algebra, sparse feedback and fast correlation attacks.

No polynomial, seed or expected ciphertext is specific to a CTF instance.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from math import log


@dataclass(frozen=True)
class CorrelationResult:
    initial_state: int
    agreement: float
    iterations: int


def polynomial_remainders(mask: int, degree: int, length: int) -> list[int]:
    """Return x**i modulo x**degree + mask as GF(2) bitsets."""
    if not (1 <= mask < 1 << degree and 2 <= degree <= 512 and length >= 0):
        raise ValueError("Invalid LFSR feedback polynomial or sequence length")
    result = []
    term = 1
    polynomial = (1 << degree) | mask
    for _ in range(length):
        result.append(term)
        term <<= 1
        if term & (1 << degree):
            term ^= polynomial
    return result


def low_weight_trinomials(
    mask: int, degree: int, *, maximum_degree: int = 4096,
) -> list[tuple[int, int]]:
    """Search x**a + x**b + 1 multiples via GF(2) remainder matching."""
    if not degree < maximum_degree <= 100000:
        raise ValueError("Search degree must exceed the recurrence order")
    remainders = polynomial_remainders(mask, degree, maximum_degree + 1)
    positions = {value: index for index, value in enumerate(remainders)}
    return sorted(
        (a, b) for b in range(1, maximum_degree)
        if (a := positions.get(remainders[b] ^ 1)) is not None and a > b
    )


def lfsr_bits(initial_state: int, mask: int, degree: int, length: int) -> list[int]:
    """Generate a right-shift LFSR output stream with parity feedback."""
    if not 0 <= initial_state < 1 << degree:
        raise ValueError("Initial state exceeds LFSR degree")
    state = initial_state
    bits = []
    for _ in range(length):
        bits.append(state & 1)
        state = (state >> 1) | (((state & mask).bit_count() & 1) << (degree - 1))
    return bits


def solve_gf2(equations: Sequence[tuple[int, int]], unknowns: int) -> int | None:
    """Solve an overdetermined binary linear system using packed integers."""
    if not 1 <= unknowns <= 1024:
        raise ValueError("Unsupported GF(2) system size")
    pivots: dict[int, tuple[int, int]] = {}
    for coefficients, right in equations:
        if coefficients < 0 or coefficients >> unknowns or right not in (0, 1):
            raise ValueError("Malformed binary equation")
        row, bit = coefficients, right
        while row:
            pivot = row.bit_length() - 1
            if pivot in pivots:
                old_row, old_bit = pivots[pivot]
                row ^= old_row
                bit ^= old_bit
            else:
                pivots[pivot] = (row, bit)
                break
        if not row and bit:
            return None
    if len(pivots) != unknowns:
        return None
    solution = 0
    for pivot in sorted(pivots):
        row, bit = pivots[pivot]
        bit ^= (row & solution).bit_count() & 1
        solution |= bit << pivot
    return solution


def _sparse_checks(length: int, triple: tuple[int, int]):
    """Build every shifted/squared weight-three parity equation."""
    import numpy as np

    a, b = triple
    groups = []
    scale = 1
    while a * scale < length:
        positions = np.arange(length - a * scale, dtype=np.int32)
        groups.append(np.stack((positions, positions + b * scale,
                                positions + a * scale), axis=1))
        scale *= 2
    if not groups:
        raise ValueError("No usable sparse checks")
    return np.concatenate(groups, axis=0).T


def _attempt_state(
    ranked, adjusted, rows: Sequence[int], degree: int,
) -> int | None:
    return solve_gf2(
        [(rows[int(index)], int(adjusted[index]))
         for index in ranked[:degree * 2 + 4]], degree,
    )


def correlation_recover(
    observed: Sequence[int], mask: int, degree: int,
    probability: float, triple: tuple[int, int], *,
    max_iterations: int = 100,
    flip_divisor: int = 32,
    progress: Callable[[str], None] | None = None,
) -> CorrelationResult:
    """Estimate a correlated LFSR state using biased sparse checks.

    Candidate solutions are checked against the *original* observed
    keystream, not the in-place denoised working copy.
    """
    try:
        import numpy as np
    except ImportError as exc:
        raise RuntimeError("Fast correlation recovery requires numpy") from exc
    if not 0.55 <= max(probability, 1 - probability) < 1:
        raise ValueError("Insufficient LFSR correlation")
    if not 1 <= max_iterations <= 1000 or not 8 <= flip_divisor <= 256 or len(observed) <= 2 * degree:
        raise ValueError("Invalid recovery budget or keystream length")
    a, b = triple
    if not (a > b > 0 and a < len(observed)):
        raise ValueError("Invalid sparse feedback multiple")
    length = len(observed)
    original = np.asarray(observed, dtype=np.uint8)
    if np.any(original > 1):
        raise ValueError("Expected binary observed symbols")
    anticorrelated = probability < 0.5
    p = max(probability, 1 - probability)
    adjusted = original.copy() ^ int(anticorrelated)
    linear_rows = polynomial_remainders(mask, degree, length)
    i0, i1, i2 = _sparse_checks(length, triple)
    pair_probability = p * p + (1 - p) * (1 - p)
    posterior = log(p / (1 - p))
    multiplier = log(pair_probability / (1 - pair_probability))
    for iteration in range(max_iterations):
        parity = adjusted[i0] ^ adjusted[i1] ^ adjusted[i2]
        votes = 1 - 2 * parity.astype(np.int8)
        counts = sum(
            (np.bincount(indices, weights=votes, minlength=length)
             for indices in (i0, i1, i2))
        )
        likelihoods = posterior + multiplier * counts
        if iteration >= 5:
            candidate = _attempt_state(np.argsort(-likelihoods),
                                       adjusted, linear_rows, degree)
            if candidate is not None:
                recovered = lfsr_bits(candidate, mask, degree, length)
                # Unmodified symbols are the independent verification
                # reference. Denoised symbols are not evidence.
                matches = sum(left == right for left, right in
                              zip(recovered, original))
                agreement = matches / length
                if abs(agreement - p) <= 0.035:
                    if progress is not None:
                        progress(f"[FCA] Recovered {degree}-bit output state; "
                                 f"agreement={agreement:.4f}, iterations={iteration}")
                    return CorrelationResult(candidate, agreement, iteration)
        count = max(1, length // flip_divisor)
        least_likely = np.argpartition(likelihoods, count)[:count]
        adjusted[least_likely] ^= 1
    raise RuntimeError("Fast correlation attack exhausted its iteration budget")
