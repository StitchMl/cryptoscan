"""Optional sparse NTRU key recovery via a source-parameterized lattice.

No challenge names/flags/keys are embedded. Reduction at large dimensions can
take substantial time and does not guarantee success. Proof checks reject
spurious candidate keys.
"""
from __future__ import annotations

import re
import sys
from typing import Any, Callable


def cyclic_mul(a: list[int], b: list[int], mod: int | None = None) -> list[int]:
    n = len(a)
    if n != len(b):
        raise ValueError("polynomial lengths differ")
    out = [0] * n
    for i, value in enumerate(a):
        if value:
            for j, other in enumerate(b):
                out[(i + j) % n] += int(value) * int(other)
    return [value % mod for value in out] if mod else out


def binary_inverse(f: list[int]) -> list[int]:
    n = len(f)
    if not n or any(value not in (0, 1) for value in f):
        raise ValueError("a binary polynomial is required")
    u = sum(int(value) << i for i, value in enumerate(f))
    v = (1 << n) | 1
    a, b = 1, 0
    while u != 1:
        if not u:
            raise ValueError("private polynomial is not invertible mod 2")
        shift = u.bit_length() - v.bit_length()
        if shift < 0:
            u, v = v, u
            a, b = b, a
            shift = -shift
        u ^= v << shift
        a ^= b << shift
    while a.bit_length() > n:
        a ^= ((1 << n) | 1) << (a.bit_length() - n - 1)
    inverse = [(a >> i) & 1 for i in range(n)]
    if cyclic_mul(f, inverse, 2) != [1] + [0] * (n - 1):
        raise ValueError("polynomial inverse verification failed")
    return inverse


def constrained_basis(h: list[int], q: int, df: int, dg: int) -> list[list[int]]:
    """Force f(1)=df, g(1)=dg; avoids the many shorter rotation differences."""
    n = len(h)
    if not 2 <= n <= 2048:
        raise ValueError("unsupported NTRU degree")
    if (dg - df * sum(h)) % q:
        raise ValueError("public key violates source-derived f/g weight relation")
    rows = []
    for i in range(1, n):
        row = [0] * (2 * n + 1)
        row[i], row[0] = 1, -1
        for j, value in enumerate(h):
            row[n + (i + j) % n] += value
            row[n + j] -= value
        rows.append(row)
    for j in range(1, n):
        row = [0] * (2 * n + 1)
        row[n + j], row[n] = q, -q
        rows.append(row)
    row = [0] * (2 * n + 1)
    row[0] = df
    for j, value in enumerate(h):
        row[n + j] = df * value
    row[n] += dg - df * sum(h)
    row[-1] = 1
    rows.append(row)
    return rows


def reduce_basis(
    h: list[int], q: int, df: int, dg: int,
    *, backend: str = "auto", bkz: int = 0,
    progress: Callable[[str], None] = print,
) -> list[list[int]]:
    n = len(h)
    if backend == "auto":
        if n <= 32:
            backend = "sympy"
        elif sys.platform == "win32":
            backend = "flint"
        else:
            # Prefer an installed fpylll (supports BKZ), then python-flint.
            try:
                import fpylll  # noqa: F401
            except ImportError:
                backend = "flint"
            else:
                backend = "fpylll"
    if backend not in {"sympy", "fpylll", "flint"}:
        raise ValueError("backend must be auto, sympy, flint or fpylll")
    if bkz and backend != "fpylll":
        raise RuntimeError(
            "BKZ is available only with the fpylll backend. "
            "Use BKZ block size 0 for native Windows FLINT LLL."
        )
    if backend == "sympy" and n > 32:
        raise RuntimeError(
            "SymPy lattice backend limited to degree <=32; "
            "install python-flint for native Windows LLL"
        )
    if backend == "flint":
        try:
            from flint import fmpz_mat
        except ImportError as exc:
            raise RuntimeError(
                "Native LLL backend python-flint is unavailable in "
                + sys.executable
                + '. Install using: "' + sys.executable
                + '" -m pip install --upgrade python-flint'
            ) from exc
        rows = constrained_basis(h, q, df, dg)
        progress(
            f"FLINT native LLL, lattice dimension {len(rows)} "
            f"({len(rows[0])} columns); may require significant RAM/CPU"
        )
        matrix = fmpz_mat(rows).lll()
        if matrix.nrows() != len(rows) or matrix.ncols() != len(rows[0]):
            raise ValueError("FLINT returned unexpected lattice dimensions")
        return [
            [int(matrix[i, j]) for j in range(matrix.ncols())]
            for i in range(matrix.nrows())
        ]
    rows = constrained_basis(h, q, df, dg)
    if backend == "sympy":
        from sympy import Matrix
        progress(f"SymPy LLL, lattice dimension {len(rows)}")
        return [[int(value) for value in row] for row in Matrix(rows).lll().tolist()]
    try:
        from fpylll import IntegerMatrix, LLL, BKZ
    except ImportError as exc:
        raise RuntimeError(
            "The optional fpylll backend is not installed. "
            "Use the flint backend on Windows (python -m pip install python-flint)."
        ) from exc
    count, width = len(rows), len(rows[0])
    matrix = IntegerMatrix(count, width)
    for i, row in enumerate(rows):
        for j, value in enumerate(row):
            if value:
                matrix[i, j] = int(value)
    progress(f"fpylll LLL reduction in dimension {count}: this may be expensive")
    LLL.reduction(matrix)
    if bkz:
        if not 2 <= bkz <= min(60, count):
            raise ValueError("BKZ block size must be between 2 and 60")
        progress(f"BKZ block size {bkz}: may take considerably longer")
        BKZ.reduction(matrix, BKZ.Param(block_size=bkz))
    return [[int(matrix[i, j]) for j in range(width)] for i in range(count)]


def verify_and_decrypt(
    reduced_rows: list[list[int]], h: list[int], ct: list[int],
    p: int, q: int, df: int, dg: int,
) -> list[dict[str, Any]]:
    """Validate recovered private polynomial and decode source-defined bit order."""
    n = len(h)
    answers: list[dict[str, Any]] = []
    if p != 2:
        raise ValueError("this decoder currently supports binary plaintext p=2 only")
    for row in reduced_rows:
        if len(row) != 2 * n + 1 or abs(int(row[-1])) != 1:
            continue
        sign = int(row[-1])
        f = [sign * int(value) for value in row[:n]]
        if set(f) - {0, 1} or sum(f) != df:
            continue
        g = cyclic_mul(f, h, q)
        if set(g) - {0, 1} or sum(g) != dg:
            continue
        if any((sign * int(row[n + i]) - g[i]) % q for i in range(n)):
            continue
        try:
            inverse = binary_inverse(f)
        except ValueError:
            continue
        product = cyclic_mul(f, ct, q)
        centered = [value - q if value > q // 2 else value for value in product]
        message_bits = cyclic_mul(inverse, [value % 2 for value in centered], 2)
        number = sum(bit << i for i, bit in enumerate(message_bits))
        plaintext = number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")
        if not plaintext or not all(32 <= byte <= 126 for byte in plaintext):
            continue
        if any(item["plaintext"] == plaintext for item in answers):
            continue
        answers.append({
            "plaintext": plaintext,
            "private_f": f,
            "private_g": g,
            "public_relation_verified": True,
            "flag_shaped": bool(re.search(
                rb"[A-Za-z0-9_]{1,30}\{[\x20-\x7e]{1,180}\}", plaintext
            )),
        })
    return answers


def solve(
    h: list[int], ct: list[int], n: int, p: int, q: int,
    df: int, dg: int, *, backend: str = "auto", bkz: int = 0,
    progress: Callable[[str], None] = print,
) -> list[dict[str, Any]]:
    if len(h) != n or len(ct) != n or any(
        type(value) is not int or not 0 <= value < q for value in h + ct
    ):
        raise ValueError("public key/ciphertext do not match analyzed NTRU parameters")
    rows = reduce_basis(h, q, df, dg, backend=backend, bkz=bkz, progress=progress)
    return verify_and_decrypt(rows, h, ct, p, q, df, dg)
