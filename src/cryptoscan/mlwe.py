"""Source-derived, bounded MLWE distinguisher for quotient rings with x - 1 factor.

No Sage evaluation, challenge-specific constants, guessed results, or AI.
Sympy is imported only when running an actual lattice calculation.
"""
from __future__ import annotations

import ast
import base64
import gzip
import io
import math
import re
import sys
from dataclasses import dataclass
from typing import Any, Sequence

from .parser import Document

MAX_COMPRESSED = 2_000_000
MAX_UNCOMPRESSED = 5_000_000


@dataclass(frozen=True)
class MLWEContext:
    path: str
    line: int
    scope: str
    modulus: int
    rank: int
    rows: int
    columns: int
    eta: int


def _scalar(source: str, name: str) -> int | None:
    values = re.findall(rf"(?m)^\s*{re.escape(name)}\s*=\s*(\d+)\s*(?:#.*)?$", source)
    if len(set(values)) != 1:
        return None
    return int(values[0])


def recognize_weak_mlwe_ring(documents: Sequence[Document]) -> list[MLWEContext]:
    """Require reducible x^N-1 modulus plus short-secret MLWE vs uniform code."""
    scopes: dict[str, list[Document]] = {}
    for document in documents:
        if document.path.lower().endswith((".sage", ".py")):
            scopes.setdefault(document.scope, []).append(document)
    findings = []
    for scope, docs in scopes.items():
        source = "\n".join(document.text for document in docs)
        if not (
            re.search(r"\b(?:is_mlwe|mlwe|lwe)\b", source, re.I)
            and re.search(r"\b(?:rnd_vec|small_vector|small_poly|short_vector)\b", source)
            and re.search(r"\b(?:random_vector|uniform_vector)\s*\(", source)
            and re.search(r"\bt\s*=\s*A\s*\*\s*s\s*\+\s*e\b", source)
        ):
            continue
        q = _scalar(source, "q")
        rank = _scalar(source, "RING_RANK")
        eta = _scalar(source, "eta")
        shape = re.search(r"(?m)^\s*k\s*,\s*l\s*=\s*(\d+)\s*,\s*(\d+)\s*(?:#.*)?$", source)
        if not all((q, rank, eta, shape)):
            continue
        rows, columns = int(shape[1]), int(shape[2])
        if not (
            2 <= rows <= 64 and 1 <= columns < rows
            and 2 <= rank <= 8192 and 1 <= eta <= 100 and q > 2
        ):
            continue
        pattern = (
            rf"quotient_ring\s*\(\s*(?:x\s*\^\s*(?:RING_RANK|{rank})"
            rf"|x\s*\*\*\s*(?:RING_RANK|{rank}))\s*-\s*1\s*\)"
        )
        for doc in docs:
            match = re.search(pattern, doc.text)
            if match:
                findings.append(MLWEContext(
                    doc.path, doc.text.count("\n", 0, match.start()) + 1,
                    scope, q, rank, rows, columns, eta
                ))
    return findings


def _decode(encoded: str) -> Any:
    """Decode only bounded gzip/base64 Python literals, never execute them."""
    if len(encoded) > MAX_COMPRESSED * 4 // 3 + 32:
        raise ValueError("encoded sample is too large")
    try:
        compressed = base64.b64decode(encoded, validate=True)
        if len(compressed) > MAX_COMPRESSED:
            raise ValueError("compressed sample is too large")
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            plain = stream.read(MAX_UNCOMPRESSED + 1)
        if len(plain) > MAX_UNCOMPRESSED:
            raise ValueError("uncompressed sample is too large")
        return ast.literal_eval(plain.decode("utf8"))
    except (OSError, UnicodeDecodeError, SyntaxError, ValueError,
            TypeError, RecursionError, OverflowError) as exc:
        raise ValueError("invalid bounded gzip/base64/literal sample") from exc


def parse_mlwe_capture(
    capture: str, context: MLWEContext
) -> tuple[list[list[int]], list[int]]:
    """Parse compressed polynomial samples and evaluate them at x=1 mod q."""
    patterns = (
        r"sanitize_mat\(A\)\s*=\s*['\"]([a-zA-Z0-9+/=]+)['\"]",
        r"sanitize_vec\(t\)\s*=\s*['\"]([a-zA-Z0-9+/=]+)['\"]",
    )
    values = []
    for pattern in patterns:
        match = re.search(pattern, capture)
        if not match:
            raise ValueError("capture needs both sanitize_mat(A) and sanitize_vec(t)")
        values.append(_decode(match.group(1)))
    matrix, vector = values
    if not (
        isinstance(matrix, list) and len(matrix) == context.rows
        and isinstance(vector, list) and len(vector) == context.rows
    ):
        raise ValueError("sample shape is not compatible with analyzed source")
    def valid_poly(poly: Any) -> bool:
        return (
            isinstance(poly, list) and len(poly) == context.rank
            and all(type(v) is int and 0 <= v < context.modulus for v in poly)
        )
    if any(
        not isinstance(row, list) or len(row) != context.columns
        or any(not valid_poly(poly) for poly in row) for row in matrix
    ) or any(not valid_poly(poly) for poly in vector):
        raise ValueError("sample dimensions or coefficients differ from source")
    return (
        [[sum(poly) % context.modulus for poly in row] for row in matrix],
        [sum(poly) % context.modulus for poly in vector],
    )


def _babai_residual(basis: list[list[int]], target: list[int]) -> list[int]:
    orthogonal: list[list[float]] = []
    squared_norms: list[float] = []
    for row in basis:
        vector = [float(v) for v in row]
        for prior, squared_norm in zip(orthogonal, squared_norms):
            coefficient = sum(a * b for a, b in zip(row, prior)) / squared_norm
            vector = [a - coefficient * b for a, b in zip(vector, prior)]
        squared_norm = sum(v * v for v in vector)
        if squared_norm < 1e-15:
            raise ValueError("degenerate lattice basis")
        orthogonal.append(vector)
        squared_norms.append(squared_norm)
    residual = target[:]
    for row, orth, squared_norm in reversed(
        list(zip(basis, orthogonal, squared_norms))
    ):
        nearest = round(sum(a * b for a, b in zip(residual, orth)) / squared_norm)
        residual = [a - nearest * b for a, b in zip(residual, row)]
    return residual


@dataclass(frozen=True)
class MLWEResult:
    answer: int
    error_max: int
    norm: float
    verified: bool
    note: str


def distinguish_mlwe(
    matrix: list[list[int]], vector: list[int], context: MLWEContext
) -> MLWEResult:
    try:
        from sympy import Matrix
    except ImportError as exc:
        raise RuntimeError(
            "MLWE dependencies failed to import. Runtime interpreter: "
            + sys.executable + ". Error: " + str(exc)
            + ". Repair SymPy/mpmath in that interpreter using: \""
            + sys.executable + "\" -m pip install --no-cache-dir --force-reinstall sympy mpmath. "
            "Run cryptoscan doctor for diagnostic details."
        ) from exc
    n, m, q = context.rows, context.columns, context.modulus
    if len(matrix) != n or len(vector) != n or any(len(row) != m for row in matrix):
        raise ValueError("invalid matrix/vector dimensions")
    if n + m > 32:
        raise ValueError("lattice dimension exceeds bounded solver limit")
    basis = (
        [[q * int(i == j) for j in range(n)] + [0] * m for i in range(n)]
        + [
            [matrix[i][j] for i in range(n)] + [int(k == j) for k in range(m)]
            for j in range(m)
        ]
    )
    reduced = Matrix(basis).lll(delta=3/4)
    residual = _babai_residual(
        [[int(v) for v in row] for row in reduced.tolist()],
        vector + [0] * m,
    )
    error, secret = residual[:n], [-v for v in residual[n:]]
    verified = all(
        (sum(matrix[i][j] * secret[j] for j in range(m)) + error[i] - vector[i]) % q == 0
        for i in range(n)
    )
    sigma = math.sqrt(context.rank * context.eta * (context.eta + 1) / 3)
    cutoff = max(1, math.ceil(8 * sigma))
    maximum = max(abs(v) for v in residual)
    answer = int(verified and maximum <= cutoff)
    return MLWEResult(
        answer, maximum, math.sqrt(sum(v * v for v in residual)), verified,
        f"x=1 quotient projection, per-coordinate shortness threshold {cutoff}",
    )


def classify_capture(capture: str, context: MLWEContext) -> MLWEResult:
    matrix, vector = parse_mlwe_capture(capture, context)
    return distinguish_mlwe(matrix, vector, context)
