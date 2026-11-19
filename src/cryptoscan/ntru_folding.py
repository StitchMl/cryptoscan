"""Parameter-driven folding attack for sparse binary NTRU keys.

For n divisible by d, folding maps coefficients to x^d-1. Given a
folded f at dimension d, lifting to 2d uses f_i + f_{i+d} = f^(d)_i.
The resulting constrained (roughly d-dimensional) lattice is much
smaller than the original 2n-dimensional NTRU lattice.

This module has no challenge constants, known keys, or expected flag.
All reconstructed keys are checked against the full public key.
"""
from __future__ import annotations

import ast
import math
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence

from .ntru_lattice import cyclic_mul, binary_inverse


def fold_poly(values: Sequence[int], degree: int, modulus: int | None = None) -> list[int]:
    """Canonical Z[x]/(x^degree - 1) image of a cyclic polynomial."""
    if not values or degree <= 0 or len(values) % degree:
        raise ValueError("Fold degree must divide polynomial length")
    result = [0] * degree
    for index, value in enumerate(values):
        result[index % degree] += int(value)
    return [v % modulus for v in result] if modulus else result


def circulant_rows(h: Sequence[int]) -> list[list[int]]:
    """Multiplication by h, using row-vector convention f * H = f*h."""
    d = len(h)
    return [[int(h[(j-i) % d]) for j in range(d)] for i in range(d)]


def fold_lattice_basis(
    h: Sequence[int], q: int, previous_f: Sequence[int] | None = None
) -> tuple[list[list[int]], int]:
    """Construct the initial or next-stage NTRU folding lattice.

    Return (basis, unknown_first_half_length). Full-stage candidates
    must be reconstructed with f = (u, previous_f-u).
    """
    degree = len(h)
    if not 2 <= degree <= 2048 or q <= 2:
        raise ValueError("Invalid folding degree or ciphertext modulus")
    centered_h = [value % q if value % q <= q // 2 else value % q - q for value in h]
    H = circulant_rows(centered_h)
    if previous_f is None:
        rows = [[int(i == j) for j in range(degree)] + H[i][:]
                for i in range(degree)]
        rows.extend([[0]*degree + [q*int(i == j) for j in range(degree)]
                     for i in range(degree)])
        return rows, degree
    half = len(previous_f)
    if 2*half != degree:
        raise ValueError("Previous fold must have exactly half the new degree")
    # Given f=(u, f_old-u), the first half of f*h equals
    # f_old*H_bottom + u*(H_top-H_bottom).
    # Reduce a lattice encoding u and the first half of f*h, modulo q.
    basis: list[list[int]] = []
    for i in range(half):
        row = [int(i == j) for j in range(half)]
        row.extend(H[i][j] - H[half+i][j] for j in range(half))
        basis.append(row)
    target = [0] * half
    target.extend(
        sum(int(previous_f[i])*H[half+i][j] for i in range(half))
        for j in range(half)
    )
    basis.append(target)
    basis.extend([[0]*half + [q*int(i == j) for j in range(half)]
                  for i in range(half)])
    # If previous_f[i]=0 and the original secret is binary, both new
    # coefficients must be zero; its unit row can be eliminated.
    return [row for i, row in enumerate(basis)
            if i >= half or previous_f[i] != 0], half


def _parse_fplll_matrix(output: str, expected_rows: int, expected_cols: int) -> list[list[int]]:
    """Parse the whitespace-separated integer matrix printed by fplll."""
    chunks = re.findall(r"\\[([^\\[\\]]+)\\]", output)
    matrix = []
    for chunk in chunks:
        tokens = chunk.replace(",", " ").split()
        if not tokens:
            continue
        try:
            row = [int(token) for token in tokens]
        except ValueError as exc:
            raise RuntimeError("Malformed fplll integer matrix") from exc
        matrix.append(row)
    if len(matrix) != expected_rows or any(len(row) != expected_cols for row in matrix):
        raise RuntimeError(
            f"fplll produced unexpected lattice dimensions: expected "
            f"{expected_rows}x{expected_cols}, got {len(matrix)} rows"
        )
    return matrix


def _fplll_command() -> list[str] | None:
    if shutil.which("fplll"):
        return ["fplll"]
    if sys.platform == "win32" and shutil.which("wsl.exe"):
        return ["wsl.exe", "-e", "fplll"]
    return None


def _run_fplll(
    rows: list[list[int]], bkz: int, progress: Callable[[str], None],
) -> list[list[int]]:
    executable = _fplll_command()
    if executable is None:
        raise RuntimeError(
            "BKZ needs fpylll or fplll-tools. On Windows, install "
            "fplll-tools inside WSL Ubuntu, or use a compatible fpylll environment."
        )
    payload = "[" + "\\n".join(
        "[" + " ".join(map(str, row)) + "]" for row in rows
    ) + "]\\n"
    args = executable + (["-a", "bkz", "-b", str(bkz), "-bkzmaxloops", "4"]
                         if bkz else ["-a", "lll"])
    progress(f"[NTRU-FOLD] Native fplll reduction, {len(rows)} rows; "
             f"BKZ block size {bkz if bkz else 'none'}")
    try:
        finished = subprocess.run(
            args, input=payload, text=True, capture_output=True,
            timeout=1200, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("fplll lattice reduction was interrupted") from exc
    if finished.returncode:
        raise RuntimeError(
            "fplll failed: " + finished.stderr.strip()[-700:]
        )
    return _parse_fplll_matrix(
        finished.stdout, len(rows), len(rows[0])
    )


def _reduce(rows: list[list[int]], *, backend: str, bkz: int,
            progress: Callable[[str], None]) -> list[list[int]]:
    if not rows:
        raise ValueError("Empty lattice")
    if backend == "auto":
        try:
            import fpylll  # noqa: F401
        except ImportError:
            if bkz:
                backend = "fplll"
            else:
                backend = "sympy" if len(rows) <= 24 else "flint"
        else:
            backend = "fpylll"
    if backend == "fplll":
        if bkz and not 2 <= bkz <= min(60, len(rows)):
            raise ValueError("BKZ block size must be between 2 and 60")
        return _run_fplll(rows, bkz, progress)
    if backend == "sympy":
        if bkz:
            raise RuntimeError("BKZ requires the optional fpylll backend")
        if len(rows) > 32:
            raise RuntimeError("SymPy is limited to small folding stages")
        from sympy import Matrix
        return [[int(v) for v in row] for row in Matrix(rows).lll().tolist()]
    if backend == "flint":
        if bkz:
            raise RuntimeError("Install fpylll to use BKZ (python-flint supplies LLL)")
        try:
            from flint import fmpz_mat
        except ImportError as exc:
            raise RuntimeError("Install python-flint for native folding LLL") from exc
        matrix = fmpz_mat(rows).lll(delta=0.99)
        return [[int(matrix[i, j]) for j in range(matrix.ncols())]
                for i in range(matrix.nrows())]
    if backend == "fpylll":
        try:
            from fpylll import IntegerMatrix, LLL, BKZ
        except ImportError as exc:
            raise RuntimeError("Install fpylll for BKZ folding") from exc
        matrix = IntegerMatrix.from_matrix(rows)
        LLL.reduction(matrix)
        if bkz:
            if not 2 <= bkz <= min(60, len(rows)):
                raise ValueError("BKZ block size must be between 2 and 60")
            BKZ.reduction(matrix, BKZ.Param(block_size=bkz, max_loops=4))
        return [[int(matrix[i, j]) for j in range(matrix.ncols)]
                for i in range(matrix.nrows)]
    raise ValueError("Unknown folding backend")


def _folded_key_candidates(
    reduced: Sequence[Sequence[int]], h: Sequence[int], q: int,
    df: int, dg: int, previous: Sequence[int] | None,
) -> list[list[int]]:
    degree = len(h)
    half = degree if previous is None else len(previous)
    results: list[list[int]] = []
    seen: set[tuple[int, ...]] = set()
    for row in reduced:
        if len(row) < half:
            continue
        for sign in (1, -1):
            part = [sign*int(v) for v in row[:half]]
            f = part if previous is None else part + [
                int(previous[i])-part[i] for i in range(half)
            ]
            if any(v < 0 for v in f) or sum(f) != df:
                continue
            key = tuple(f)
            if key in seen:
                continue
            # Every valid folded secret also folds g to nonnegative
            # coefficients of total weight dg.
            g = cyclic_mul(f, list(h), q)
            g = [v if v <= dg else v-q for v in g]
            if all(v >= 0 for v in g) and sum(g) == dg:
                seen.add(key)
                results.append(f)
    return results


def decrypt_with_private_key(
    f: Sequence[int], h: Sequence[int], ct: Sequence[int],
    p: int, q: int, df: int, dg: int,
) -> bytes | None:
    """Verify a binary NTRU private key, decrypt, and check encoding."""
    n = len(h)
    if p != 2 or len(f) != n or len(ct) != n:
        return None
    if any(v not in (0, 1) for v in f) or sum(f) != df:
        return None
    g = cyclic_mul(list(f), list(h), q)
    if any(v not in (0, 1) for v in g) or sum(g) != dg:
        return None
    try:
        inv_f = binary_inverse(list(f))
    except ValueError:
        return None
    intermediate = cyclic_mul(list(f), list(ct), q)
    centered = [v - q if v > q//2 else v for v in intermediate]
    message_bits = cyclic_mul(inv_f, [v % 2 for v in centered], 2)
    number = sum(bit << i for i, bit in enumerate(message_bits))
    return number.to_bytes(max(1, (number.bit_length()+7)//8), "big")


def solve_folded(
    h: list[int], ct: list[int], n: int, p: int, q: int,
    df: int, dg: int, *,
    initial_degree: int = 64, backend: str = "auto", bkz: int = 0,
    progress: Callable[[str], None] = print,
) -> list[dict]:
    """Attempt staged NTRU folding; return only verified private-key plaintexts.

    Requires n/initial_degree to be a power of two. Each stage has an
    explicit candidate check; failure is reported instead of fabricated
    plaintext. For hard instances BKZ may be necessary.
    """
    if (len(h) != n or len(ct) != n or n < 4 or
            any(type(x) is not int or not 0 <= x < q for x in h+ct) or
            not (1 <= df <= n and 1 <= dg <= n)):
        raise ValueError("Invalid NTRU instance")
    if (initial_degree < 2 or n % initial_degree or
            (n//initial_degree) & (n//initial_degree - 1)):
        raise ValueError("Initial fold must divide n with a power-of-two ratio")

    degree = initial_degree
    candidates: list[list[int] | None] = [None]
    while True:
        folded_h = fold_poly(h, degree, q)
        next_candidates: list[list[int]] = []
        seen = set()
        for previous in candidates:
            rows, unknown = fold_lattice_basis(folded_h, q, previous)
            progress(f"[NTRU-FOLD] Degree {degree}; lattice {len(rows)}x{len(rows[0])}")
            reduced = _reduce(rows, backend=backend, bkz=bkz, progress=progress)
            for candidate in _folded_key_candidates(
                    reduced, folded_h, q, df, dg, previous):
                key = tuple(candidate)
                if key not in seen:
                    seen.add(key)
                    next_candidates.append(candidate)
        if not next_candidates:
            raise RuntimeError(
                f"No valid folded key found at degree {degree}; "
                "try a stronger BKZ backend or a different starting fold")
        progress(f"[NTRU-FOLD] Degree {degree}: {len(next_candidates)} key candidates")
        if degree == n:
            results = []
            for key in next_candidates:
                plaintext = decrypt_with_private_key(key, h, ct, p, q, df, dg)
                if plaintext is not None:
                    results.append({
                        "plaintext": plaintext,
                        "private_f": key,
                        "public_relation_verified": True,
                        "flag_shaped": bool(__import__("re").search(
                            rb"[A-Za-z0-9_]{1,30}\{[^\r\n{}]{1,180}\}", plaintext)),
                    })
            return results
        candidates = next_candidates
        degree *= 2
