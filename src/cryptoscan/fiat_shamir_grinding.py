"""Reusable bounded Fiat-Shamir challenge grinding and Pedersen graph proofs.

An attacker who controls a commitment before a low-entropy, publicly
computable Fiat-Shamir challenge can sample until the verifier selects a
branch for which the attacker knows a valid opening.

This module does not depend on a specific challenge name, expected flag,
network command vocabulary, graph size, or number of rounds.
"""
from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Sequence
from typing import TypeVar

T = TypeVar("T")


def grind_challenge(
    state: bytes,
    propose: Callable[[], tuple[T, object]],
    derive_state: Callable[[T, bytes], bytes],
    acceptable: Callable[[bytes], bool],
    *,
    max_trials: int = 1024,
) -> tuple[T, object, bytes, int]:
    """Find a commitment whose public challenge lies in an exploitable branch.

    The caller supplies its own commitment generator, Fiat-Shamir hash,
    and acceptance predicate. Unsuccessful attempts do not advance state.
    """
    if max_trials <= 0:
        raise ValueError("max_trials must be positive")
    for trials in range(1, max_trials + 1):
        commitment, opening = propose()
        next_state = derive_state(commitment, state)
        if acceptable(next_state):
            return commitment, opening, next_state, trials
    raise RuntimeError("Fiat-Shamir challenge grinding exhausted its trial budget")


def pedersen_commit_matrix(
    adjacency: Sequence[Sequence[int]],
    params: tuple[int, int, int, int],
    *,
    randint: Callable[[int], int] = secrets.randbelow,
) -> tuple[list[list[int]], list[list[list[int]]]]:
    """Commit to a bit-valued adjacency matrix with reusable Pedersen arithmetic."""
    p, q, h1, h2 = params
    n = len(adjacency)
    if not 1 <= n <= 512 or any(len(row) != n for row in adjacency):
        raise ValueError("Expected a square adjacency matrix")
    if q <= 2 or p <= q or not (0 < h1 < p and 0 < h2 < p):
        raise ValueError("Invalid Pedersen group parameters")
    if any(type(v) is not int or v not in (0, 1)
           for row in adjacency for v in row):
        raise ValueError("The graph must have binary entries")
    bases = (1, h1)
    commitments = []
    openings = []
    for row in adjacency:
        crow, orow = [], []
        for value in row:
            randomizer = randint(q + 1)
            if not 0 <= randomizer <= q:
                raise ValueError("Invalid supplied Pedersen randomizer")
            crow.append((bases[value] * pow(h2, randomizer, p)) % p)
            orow.append([value, randomizer])
        commitments.append(crow)
        openings.append(orow)
    return commitments, openings


def iterated_graph_hash(
    commitment: Sequence[Sequence[int]],
    state: bytes,
    params: tuple[int, int, int, int],
) -> bytes:
    """Hash one graph matrix in row-major order with an inherited FS state."""
    digest = hashlib.sha256(str(params).encode())
    digest.update(state)
    digest.update("".join(str(x) for row in commitment for x in row).encode())
    return digest.digest()


def grind_pedersen_graph_opening(
    adjacency: Sequence[Sequence[int]],
    params: tuple[int, int, int, int],
    state: bytes,
    *,
    desired_bit: int = 0,
    challenge_bit: int = 0,
    max_trials: int = 1024,
    randint: Callable[[int], int] = secrets.randbelow,
) -> tuple[list[list[int]], list[object], bytes, int]:
    """Build a valid graph-opening proof while grinding a one-bit FS branch.

    Only one commitment is regenerated between trials; all other openings
    remain unchanged. For this branch the identity permutation is valid.
    """
    if desired_bit not in (0, 1) or not 0 <= challenge_bit <= 7:
        raise ValueError("Invalid Fiat-Shamir challenge selection")
    commitments, openings = pedersen_commit_matrix(adjacency, params, randint=randint)
    p, q, h1, h2 = params
    value = int(adjacency[0][0])
    target = desired_bit << challenge_bit
    for attempts in range(1, max_trials + 1):
        new_state = iterated_graph_hash(commitments, state, params)
        if new_state[-1] & (1 << challenge_bit) == target:
            return commitments, [list(range(len(adjacency))), openings], new_state, attempts
        randomizer = randint(q + 1)
        if not 0 <= randomizer <= q:
            raise ValueError("Invalid supplied Pedersen randomizer")
        commitments[0][0] = (pow(h1, value, p) * pow(h2, randomizer, p)) % p
        openings[0][0] = [value, randomizer]
    raise RuntimeError("No acceptable Fiat-Shamir challenge within trial budget")


def verify_pedersen_graph_opening(
    commitments: Sequence[Sequence[int]],
    opening: Sequence[object],
    reference: Sequence[Sequence[int]],
    params: tuple[int, int, int, int],
) -> bool:
    """Independently verify all openings of the commitment matrix."""
    try:
        p, _, h1, h2 = params
        permutation, disclosed = opening
        n = len(reference)
        if sorted(permutation) != list(range(n)) or len(disclosed) != n:
            return False
        for i in range(n):
            if len(disclosed[i]) != n or len(commitments[i]) != n:
                return False
            for j in range(n):
                bit, randomizer = disclosed[i][j]
                if bit != reference[permutation[i]][permutation[j]]:
                    return False
                if (pow(h1, bit, p) * pow(h2, randomizer, p)) % p != commitments[i][j]:
                    return False
        return True
    except (TypeError, ValueError, IndexError, KeyError, OverflowError):
        return False
