"""Conservative NTRU polynomial-ring analysis; never interpret coefficients as bytes.

Recognizes a source-proven NTRU algebraic relation and reports only exact,
reproducible information leaks; it does not claim to recover a private key or flag.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Sequence

from .parser import Document


@dataclass(frozen=True)
class NTRUContext:
    path: str
    line: int
    scope: str
    degree: int
    plaintext_modulus: int
    ciphertext_modulus: int
    f_weight: int
    g_weight: int
    r_weight: int


def recognize_ntru(documents: Sequence[Document]) -> list[NTRUContext]:
    """Require an actual sparse-polynomial NTRU key-generation/encryption path."""
    found = []
    for doc in documents:
        if not doc.path.lower().endswith((".sage", ".py")):
            continue
        text = doc.text
        parameters = re.search(
            r"(?m)^\s*n\s*,\s*p\s*,\s*q\s*,\s*df\s*,\s*dg\s*,\s*dr\s*=\s*\["
            r"\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\]",
            text,
        )
        if parameters is None:
            continue
        n, p, q, df, dg, dr = map(int, parameters.groups())
        if not (8 <= n <= 16384 and 2 <= p < q <= 2**31 and 1 <= min(df, dg, dr) <= n):
            continue
        quotient = re.search(r"quotient\s*\(\s*\w+\s*\^\s*n\s*-\s*1\s*\)", text)
        if quotient is None:
            continue
        has_sparse_sampler = bool(re.search(
            r"for\s+\w+\s+in\s+sample\s*\(\s*range\s*\(\s*n\s*\)\s*,\s*d\s*\)", text
        ))
        has_pk = bool(re.search(r"\b\w+\s*=\s*Rqn\s*\(\s*g\s*\)\s*/\s*Rqn\s*\(\s*f\s*\)", text)
        )
        has_ct = bool(re.search(
            r"\b\w+\s*=\s*p\s*\*\s*h\s*\*\s*Rqn\s*\(\s*r\s*\)\s*\+\s*Rqn\s*\(\s*m\s*\)",
            text,
        ))
        if not (has_sparse_sampler and has_pk and has_ct):
            continue
        found.append(NTRUContext(
            doc.path, text.count("\n", 0, quotient.start()) + 1,
            doc.scope, n, p, q, df, dg, dr,
        ))
    return found


def is_polynomial_coefficients(
    value: Any, context: NTRUContext
) -> bool:
    return (
        isinstance(value, list)
        and len(value) == context.degree
        and all(type(x) is int and 0 <= x < context.ciphertext_modulus for x in value)
    )


@dataclass(frozen=True)
class NTRUProjection:
    public_evaluation: int
    expected_public_evaluation: int
    ciphertext_evaluation: int
    message_weight_residue: int
    possible_weights: tuple[int, ...]
    public_relation_verified: bool


def analyze_ntru_vectors(
    public_coefficients: Any,
    ciphertext_coefficients: Any,
    context: NTRUContext,
) -> NTRUProjection:
    if not is_polynomial_coefficients(public_coefficients, context):
        raise ValueError("public polynomial coefficients differ from source-derived shape")
    if not is_polynomial_coefficients(ciphertext_coefficients, context):
        raise ValueError("ciphertext coefficients differ from source-derived shape")
    q = context.ciphertext_modulus
    public_evaluation = sum(public_coefficients) % q
    try:
        expected = (context.g_weight * pow(context.f_weight, -1, q)) % q
    except ValueError as exc:
        raise ValueError("f(1) is not invertible modulo q; no x=1 key relation") from exc
    ciphertext_evaluation = sum(ciphertext_coefficients) % q
    message_weight_residue = (
        ciphertext_evaluation
        - context.plaintext_modulus * public_evaluation * context.r_weight
    ) % q
    candidate_weights = tuple(
        weight for weight in range(message_weight_residue, context.degree + 1, q)
    )
    return NTRUProjection(
        public_evaluation,
        expected,
        ciphertext_evaluation,
        message_weight_residue,
        candidate_weights,
        public_evaluation == expected,
    )


def pair_ntru_records(
    records: Sequence[dict[str, Any]], context: NTRUContext
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Match public/ciphertext polynomial vectors from one evidence object."""
    pairs = []
    for record in records:
        if record["scope"] != context.scope:
            continue
        obj = record["object"]
        if not isinstance(obj, dict):
            continue
        public = obj.get("pk") or obj.get("public_key") or obj.get("public")
        ciphertext = obj.get("ct") or obj.get("ciphertext")
        if (is_polynomial_coefficients(public, context)
                and is_polynomial_coefficients(ciphertext, context)):
            pairs.append(({"record": record, "value": public},
                          {"record": record, "value": ciphertext}))
    return pairs
