"""Offline GHASH authentication-pad recovery from hidden-state GCM growth tags."""
from __future__ import annotations

from collections.abc import Sequence
from itertools import product

from .gcm_hidden_state import gf128_mul, gf128_pow


def _length_block(aad_bytes: int, ciphertext_bytes: int) -> int:
    return (aad_bytes * 8 << 64) | (ciphertext_bytes * 8)


def identify_growth_prefix(h: int, captured_tags: Sequence[bytes]) -> tuple[int, ...] | None:
    """Prove the first six u2 branches are CCCAAA or AAACCC, else return None.

    1 represents a ciphertext extension, 0 an AAD extension.
    """
    if len(captured_tags) < 7 or any(len(tag) != 16 for tag in captured_tags):
        raise ValueError("Need at least 7 valid 16-byte tags")
    tags = [int.from_bytes(tag, "big") for tag in captured_tags]
    inv = {n: gf128_pow(h, (1 << 128) - 1 - n) for n in (2, 3, 5)}

    def check(i: int, before: tuple[int, int], after: tuple[int, int], power: int) -> bool:
        delta = (tags[i] ^ tags[i-1] ^
                 gf128_mul(_length_block(*before) ^ _length_block(*after), h))
        # A 36->48 extension fills the final 12 bytes of an existing block.
        return gf128_mul(delta, inv[power]) >> 96 == 0

    if (check(3, (12, 36), (12, 48), 2)
            and check(6, (36, 48), (48, 48), 5)):
        return (1, 1, 1, 0, 0, 0)
    if (check(3, (36, 12), (48, 12), 3)
            and check(6, (48, 36), (48, 48), 2)):
        return (0, 0, 0, 1, 1, 1)
    return None


def _matrix_rows(h: int, tags: list[int], choices: tuple[int, ...],
                 coefficients: dict[int, list[int]]) -> tuple[list[int], int, int]:
    total_aad = 96 + 96 * choices.count(0)
    total_ciphertext = 96 + 96 * choices.count(1)
    columns = total_aad + total_ciphertext + 128
    rows: list[int] = []
    for step, tag in enumerate(tags):
        aad_len = 96 + 96 * choices[:step].count(0)
        ct_len = 96 + 96 * choices[:step].count(1)
        aad_blocks = (aad_len + 127) // 128
        ct_blocks = (ct_len + 127) // 128
        equations = [0] * 128
        for bit_index in range(aad_len):
            exponent = 1 + ct_blocks + aad_blocks - bit_index // 128
            contribution = coefficients[exponent][bit_index % 128]
            position = 1 << bit_index
            while contribution:
                bit = contribution.bit_length() - 1
                equations[127-bit] |= position
                contribution ^= 1 << bit
        for bit_index in range(ct_len):
            exponent = 1 + ct_blocks - bit_index // 128
            contribution = coefficients[exponent][bit_index % 128]
            position = 1 << (total_aad + bit_index)
            while contribution:
                bit = contribution.bit_length() - 1
                equations[127-bit] |= position
                contribution ^= 1 << bit
        rhs = tag ^ gf128_mul(_length_block(aad_len // 8, ct_len // 8), h)
        for bit in range(128):
            equations[bit] |= 1 << (total_aad + total_ciphertext + bit)
            equations[bit] |= ((rhs >> (127-bit)) & 1) << columns
        rows.extend(equations)
    return rows, columns, total_aad + total_ciphertext


def _pad_candidates_from_rows(rows: list[int], columns: int,
                              pad_offset: int, max_kernel_dimension: int = 10) -> set[int]:
    mask = (1 << columns)-1
    pivots: dict[int, int] = {}
    for entry in rows:
        row = entry
        while row & mask:
            pivot = (row & mask).bit_length()-1
            if pivot in pivots:
                row ^= pivots[pivot]
            else:
                pivots[pivot] = row
                break
        else:
            if row >> columns:
                return set()
    free = [i for i in range(columns) if i not in pivots]
    if len(free) > max_kernel_dimension:
        return set()
    positions = sorted(pivots)

    def backsub(initial: int, affine: bool) -> int:
        vector = initial
        for pivot in positions:
            equation = pivots[pivot]
            parity = ((equation & vector).bit_count() & 1)
            if affine:
                parity ^= (equation >> columns) & 1
            if parity:
                vector |= 1 << pivot
        return vector

    fieldmask = (1 << 128)-1
    base = (backsub(0, True) >> pad_offset) & fieldmask
    deltas = [(backsub(1 << index, False) >> pad_offset) & fieldmask
              for index in free]
    candidates = {base}
    for delta in deltas:
        candidates |= {value ^ delta for value in candidates.copy()}
    # Packed variables number the MSB of each GHASH block first.
    return {int(f"{x:0128b}"[::-1], 2) for x in candidates}


def recover_empty_gcm_tag_candidates(
    h: int, tags: Sequence[bytes], *, max_kernel_dimension: int = 10
) -> set[int]:
    """Recover candidate E_K(J0) pads from 11 u2 mutations.

    The first six updates must have order CCCAAA or AAACCC.
    The remaining five assignments are enumerated and checked for consistency.
    Some transcripts inherently admit several pad candidates; no candidate
    is called verified until checked by the target service.
    """
    if len(tags) != 12 or any(len(tag) != 16 for tag in tags):
        raise ValueError("Exactly twelve 16-byte tags are required")
    prefix = identify_growth_prefix(h, tags)
    if prefix is None:
        raise ValueError("No uniquely identifiable u2 growth prefix")
    coeff = {degree: [gf128_mul(1 << (127-i), gf128_pow(h, degree))
                      for i in range(128)] for degree in range(1, 18)}
    values = [int.from_bytes(tag, "big") for tag in tags]
    candidates: set[int] = set()
    for suffix in product((0, 1), repeat=5):
        branches = prefix + suffix
        rows, cols, pad_offset = _matrix_rows(h, values, branches, coeff)
        candidates |= _pad_candidates_from_rows(rows, cols, pad_offset,
                                                 max_kernel_dimension)
    if not candidates:
        raise RuntimeError("No consistent small-kernel GCM extension model")
    return candidates
