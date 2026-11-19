"""Offline recovery dispatcher for source-verified sparse NTRU instances.

The attack is optional and computationally expensive. It interprets
public parameters and output vectors from each challenge scope, invokes
the isolated native lattice worker, and reports only a flag found in a
plaintext decrypted with a separately verified private key.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Sequence

from .ntru import recognize_ntru, pair_ntru_records
from .ntru_isolation import solve_isolated
from .parser import Document, scalar_records

FLAG_RE = re.compile(rb"\w{2,30}\{[\x20-\x7e]{1,180}\}")


def instances(documents: Sequence[Document]) -> list[tuple]:
    records = []
    for document in documents:
        for record in scalar_records(document.text):
            records.append({
                "scope": document.scope,
                "location": document.path + ":assignments",
                "object": record,
            })
    result = []
    for context in recognize_ntru(documents):
        for public, encrypted in pair_ntru_records(records, context):
            if (sum(public["value"]) * context.f_weight - context.g_weight
                    ) % context.ciphertext_modulus:
                continue
            result.append((context, public["value"], encrypted["value"]))
    return result


def _flag_from_results(results: Sequence[dict]) -> str | None:
    for candidate in results:
        plaintext = candidate["plaintext"]
        if not candidate["public_relation_verified"]:
            continue
        if FLAG_RE.fullmatch(plaintext):
            return plaintext.decode("ascii")
    return None


def recover_flag(
    documents: Sequence[Document], *,
    bkz: int = 20,
    backend: str = "auto",
    initial_degree: int = 64,
    timeout_seconds: int = 900,
    progress: Callable[[str], None] = print,
) -> str:
    matches = instances(documents)
    if not matches:
        raise ValueError("No source-verified NTRU key/ciphertext pair found")
    if not 0 <= bkz <= 60:
        raise ValueError("BKZ block size must be 0..60")
    if not 1 <= len(matches) <= 8:
        raise ValueError("Too many matching NTRU instances; scan one challenge folder")
    if not 1 <= timeout_seconds <= 3600:
        raise ValueError("Lattice worker timeout must be 1..3600 seconds")
    for context, public, encrypted in matches:
        n = context.degree
        if (n < 16 or n % initial_degree or
                (n // initial_degree) & ((n // initial_degree) - 1)):
            progress(f"[NTRU-FOLD] Unsupported degree/fold ratio for n={n}")
            continue
        progress(
            f"[NTRU-FOLD] n={n}, q={context.ciphertext_modulus}, "
            f"df={context.f_weight}, dg={context.g_weight}; "
            f"initial fold={initial_degree}, BKZ={bkz}"
        )
        results = solve_isolated(
            public, encrypted,
            context.plaintext_modulus, context.ciphertext_modulus,
            context.f_weight, context.g_weight,
            method="fold", backend=backend, bkz=bkz,
            initial_degree=initial_degree, timeout_seconds=timeout_seconds,
            stream=True, progress=progress,
        )
        flag = _flag_from_results(results)
        if flag is not None:
            progress("[NTRU-FOLD] Binary private key and plaintext independently verified")
            return flag
    raise RuntimeError("No verified flag recovered; try stronger BKZ or another fold degree")
