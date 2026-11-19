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


def _segment_positive_decimal(digits: str, count: int) -> tuple[int, ...] | None:
    """Split into count canonical positive decimal integers (no leading 0)."""
    if count == 0:
        return () if not digits else None
    if len(digits) < count or not digits or digits[0] == "0":
        return None

    @lru_cache(None)
    def recurse(start: int, remaining: int) -> tuple[int, ...] | None:
        if remaining == 0:
            return () if start == len(digits) else None
        if len(digits) - start < remaining or digits[start] == "0":
            return None
        # Prefer short tokens; failure propagates to a longer split.
        for end in range(start + 1, len(digits) - remaining + 2):
            if end < len(digits) and digits[end] == "0" and remaining > 1:
                continue
            rest = recurse(end, remaining - 1)
            if rest is not None:
                return (int(digits[start:end]),) + rest
        return None

    return recurse(0, count)


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


def _search_hamiltonian_cycle(options: Sequence[dict[int, list[int]]]) -> tuple[int, ...] | None:
    """Find a cycle in the *resegmentable* edge graph with bounded DFS."""
    n = len(options)
    for first in range(n):
        def extend(path: list[int], visited: int) -> tuple[int, ...] | None:
            current = path[-1]
            if len(path) == n:
                return tuple(path) if first in options[current] else None
            for nxt in options[current]:
                if visited & (1 << nxt):
                    continue
                answer = extend(path + [nxt], visited | (1 << nxt))
                if answer is not None:
                    return answer
            return None
        found = extend([first], 1 << first)
        if found is not None:
            return found
    return None


@dataclass(frozen=True)
class EquivocalGraphProof:
    zero_matrix: list[list[int]]
    zero_opening: list[object]
    one_matrix: list[list[int]]
    one_opening: list[object]
    cycle: tuple[int, ...]


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

    for multiplier in range(1, max_representatives + 1):
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
            continue
        one = [row[:] for row in zero]
        cycle_edges = [
            (cycle[i], cycle[(i + 1) % n]) for i in range(n)
        ]
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
            continue
        if not verify_equivocal_graph_proof(
            zero, z0, one, z1, public_graph, params,
        ):
            continue
        return EquivocalGraphProof(zero, z0, one, z1, cycle)
    raise RuntimeError(
        "No valid serialization-equivalent cycle found within the "
        "representative search budget"
    )


def verify_equivocal_graph_proof(
    zero: Sequence[Sequence[int]], z0: Sequence[object],
    one: Sequence[Sequence[int]], z1: Sequence[object],
    public_graph: Sequence[Sequence[int]],
    params: tuple[int, int, int, int],
) -> bool:
    """Independently check the two verifier branches and identical hashing."""
    try:
        p, q, h1, h2 = params
        n = len(public_graph)
        if len(zero) != n or len(one) != n:
            return False
        if any(len(row) != n for row in zero) or any(len(row) != n for row in one):
            return False
        if decimal_transcript(zero) != decimal_transcript(one):
            return False
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
    except (TypeError, ValueError, IndexError, KeyError, OverflowError, AttributeError):
        return False
