"""Generic Fiat-Shamir transcript ambiguity and graph-proof equivocation.

If commitment integers are encoded with str() and concatenated without
framing, multiple integer matrices share the same serialized preimage.
This module searches for a second matrix that opens selected Pedersen
commitments as a Hamiltonian cycle, while an original matrix fully opens
as the public graph. Neither private keys nor expected flags are embedded.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from collections.abc import Sequence


def decimal_transcript(matrix: Sequence[Sequence[int]]) -> bytes:
    """Mimic row-major ''.join(str(value) ...) in a Fiat-Shamir hash."""
    return "".join(str(value) for row in matrix for value in row).encode("ascii")


def _segment_recurse(digits: str, start: int, remaining: int) -> tuple[int, ...] | None:
    if remaining == 0:
        return () if start == len(digits) else None
    if len(digits) - start < remaining or digits[start] == "0":
        return None
    # Prefer short tokens; failure propagates to a longer split.
    for end in range(start + 1, len(digits) - remaining + 2):
        if end < len(digits) and digits[end] == "0" and remaining > 1:
            continue
        rest = _segment_recurse(digits, end, remaining - 1)
        if rest is not None:
            return (int(digits[start:end]),) + rest
    return None


def _segment_positive_decimal(digits: str, count: int) -> tuple[int, ...] | None:
    """Split into count canonical positive decimal integers (no leading 0)."""
    if count == 0:
        return () if not digits else None
    if len(digits) < count or not digits or digits[0] == "0":
        return None
    cached = lru_cache(None)(_segment_recurse)
    return cached(digits, 0, count)


def resegment_row(
    original_row: Sequence[int],
    *,
    fixed_entry: int,
    target_index: int,
) -> list[int] | None:
    """Preserve encoded row bytes while placing fixed_entry in target cell."""
    n = len(original_row)
    if not 0 <= target_index < n or n < 2:
        return None
    digits = decimal_transcript([original_row]).decode("ascii")
    token = str(fixed_entry)
    if any(v <= 0 for v in original_row) or not token.isdecimal() or token[0] == "0":
        return None
    start = 0
    while (position := digits.find(token, start)) >= 0:
        left = _segment_positive_decimal(digits[:position], target_index)
        right = _segment_positive_decimal(
            digits[position + len(token):], n - target_index - 1,
        )
        if left is not None and right is not None:
            candidate = list(left) + [fixed_entry] + list(right)
            if decimal_transcript([candidate]) == decimal_transcript([original_row]):
                return candidate
        start = position + 1
    return None


class _VisitBudgetExceeded(Exception):
    pass


def _extend_path(
    options: Sequence[dict[int, list[int]]], first: int,
    path: list[int], visited: int, visits: list[int], max_visits: int,
) -> tuple[int, ...] | None:
    visits[0] += 1
    if visits[0] > max_visits:
        raise _VisitBudgetExceeded
    n = len(options)
    current = path[-1]
    if len(path) == n:
        return tuple(path) if first in options[current] else None
    for nxt in options[current]:
        if visited & (1 << nxt):
            continue
        answer = _extend_path(
            options, first, path + [nxt], visited | (1 << nxt), visits, max_visits,
        )
        if answer is not None:
            return answer
    return None


def _search_hamiltonian_cycle(options: Sequence[dict[int, list[int]]]) -> tuple[int, ...] | None:
    """Find a cycle in the *resegmentable* edge graph with bounded DFS."""
    n = len(options)
    visits = [0]
    max_visits = 200_000
    try:
        for first in range(n):
            found = _extend_path(options, first, [first], 1 << first, visits, max_visits)
            if found is not None:
                return found
        return None
    except _VisitBudgetExceeded:
        return None


@dataclass(frozen=True)
class EquivocalGraphProof:
    zero_matrix: list[list[int]]
    zero_opening: list[object]
    one_matrix: list[list[int]]
    one_opening: list[object]
    cycle: tuple[int, ...]


def _validate_graph_inputs(
    public_graph: Sequence[Sequence[int]],
    params: tuple[int, int, int, int],
    max_representatives: int,
) -> None:
    n = len(public_graph)
    p, q, h1, h2 = params
    if not 2 <= n <= 12 or any(len(row) != n for row in public_graph):
        raise ValueError("Expected a 2..12 vertex adjacency matrix")
    if not (p > q > 2 and 0 < h1 < p and 0 < h2 < p):
        raise ValueError("Invalid Pedersen parameters")
    if any(type(bit) is not int or bit not in (0, 1)
           for row in public_graph for bit in row):
        raise ValueError("Graph must be binary")
    if not 1 <= max_representatives <= 64:
        raise ValueError("Invalid collision search budget")


def _try_equivocation_candidate(
    public_graph: Sequence[Sequence[int]],
    params: tuple[int, int, int, int],
    multiplier: int,
) -> EquivocalGraphProof | None:
    n = len(public_graph)
    p, _q, h1, _h2 = params
    commit_zero = 1 + multiplier * p
    commit_one = h1
    zero = [[commit_one if v else commit_zero for v in row]
            for row in public_graph]
    options = [
        {j: result for j in range(n)
         if (result := resegment_row(row, fixed_entry=commit_one,
                                     target_index=j)) is not None}
        for row in zero
    ]
    cycle = _search_hamiltonian_cycle(options)
    if cycle is None:
        return None
    one = [row[:] for row in zero]
    cycle_edges = [(cycle[i], cycle[(i + 1) % n]) for i in range(n)]
    for src, dst in cycle_edges:
        one[src] = options[src][dst]
    z0 = [
        list(range(n)),
        [[[int(v), 0] for v in row] for row in public_graph],
    ]
    z1 = [
        [[src, dst] for src, dst in cycle_edges],
        [0] * n,
    ]
    if decimal_transcript(zero) != decimal_transcript(one):
        return None
    if not verify_equivocal_graph_proof(zero, z0, one, z1, public_graph, params):
        return None
    return EquivocalGraphProof(zero, z0, one, z1, cycle)


def construct_equivocal_pedersen_graph(
    public_graph: Sequence[Sequence[int]],
    params: tuple[int, int, int, int],
    *,
    max_representatives: int = 16,
) -> EquivocalGraphProof:
    """Construct transcript-equivalent branch-0 and branch-1 proofs.

    Works whenever the byte-level integer concatenation admits a
    Hamiltonian cycle of separately resegmentable rows. The 0-commitment
    representative 1 + k*p is valid modulo p in a verifier that accepts
    noncanonical commitment integers. This precondition is essential.
    """
    _validate_graph_inputs(public_graph, params, max_representatives)
    for multiplier in range(1, max_representatives + 1):
        proof = _try_equivocation_candidate(public_graph, params, multiplier)
        if proof is not None:
            return proof
    raise RuntimeError(
        "No valid serialization-equivalent cycle found within the "
        "representative search budget"
    )


def _verify_full_opening(
    zero: Sequence[Sequence[int]], z0: Sequence[object],
    public_graph: Sequence[Sequence[int]], p: int, h1: int, h2: int, n: int,
) -> bool:
    perm, openings = z0
    if sorted(perm) != list(range(n)) or len(openings) != n:
        return False
    for i in range(n):
        if len(openings[i]) != n:
            return False
        for j in range(n):
            bit, rand = openings[i][j]
            if bit != public_graph[perm[i]][perm[j]]:
                return False
            if zero[i][j] % p != pow(h1, bit, p) * pow(h2, rand, p) % p:
                return False
    return True


def _verify_cycle_opening(
    one: Sequence[Sequence[int]], z1: Sequence[object], p: int, h1: int, h2: int, n: int,
) -> bool:
    cycle_edges, rand_values = z1
    if len(cycle_edges) != n or len(rand_values) != n:
        return False
    if sorted(src for src, _ in cycle_edges) != list(range(n)):
        return False
    if sorted(dst for _, dst in cycle_edges) != list(range(n)):
        return False
    for i, ((src, dst), rand) in enumerate(zip(cycle_edges, rand_values)):
        if cycle_edges[(i + 1) % n][0] != dst:
            return False
        if one[src][dst] % p != (h1 * pow(h2, rand, p)) % p:
            return False
    return True


def verify_equivocal_graph_proof(
    zero: Sequence[Sequence[int]], z0: Sequence[object],
    one: Sequence[Sequence[int]], z1: Sequence[object],
    public_graph: Sequence[Sequence[int]],
    params: tuple[int, int, int, int],
) -> bool:
    """Independently check the two verifier branches and identical hashing."""
    try:
        p, _, h1, h2 = params
        n = len(public_graph)
        if len(zero) != n or len(one) != n:
            return False
        if any(len(row) != n for row in zero) or any(len(row) != n for row in one):
            return False
        if decimal_transcript(zero) != decimal_transcript(one):
            return False
        if not _verify_full_opening(zero, z0, public_graph, p, h1, h2, n):
            return False
        return _verify_cycle_opening(one, z1, p, h1, h2, n)
    except (TypeError, ValueError, IndexError, KeyError, OverflowError, AttributeError):
        return False
