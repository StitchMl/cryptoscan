"""Offline RSA PKCS#1 v1.5 positive-padding transcript cryptanalysis.

A verifier that publicly identifies PKCS#1 v1.5 conformant decryptions
provides interval constraints on RSA plaintext representatives. Given
sufficient *known-positive* multipliers, recover by Kannan embedding and
LLL; always verify RSA re-encryption and every source-derived interval.
No network access, guessing, or hardcoded CTF samples.
"""
from __future__ import annotations

import ast
import math
import re
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from .parser import Document, pem_rsa_public_keys, scalar_records


@dataclass(frozen=True)
class OracleEvidence:
    source_path: str
    source_line: int
    scope: str
    modulus: int
    exponent: int
    ciphertext: int
    positive_multipliers: tuple[int, ...]


def _source_names(source: str) -> tuple[str, str, int] | None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    if not ("PKCS1_v1_5.new" in source
            and "RSA.import_key" in source
            and ".decrypt(" in source):
        return None
    # Require sentinel-based decrypt success as a Boolean padding oracle.
    sentinel_check = False
    for fn in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
        if fn.name not in {"verify", "check", "valid", "is_valid"}:
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Compare) and any(
                isinstance(op, (ast.NotEq, ast.Eq)) for op in node.ops
            ) and any(
                isinstance(part, ast.Call)
                and isinstance(part.func, ast.Attribute)
                and part.func.attr == "decrypt"
                for part in ast.walk(node)
            ):
                sentinel_check = True
    if not sentinel_check:
        return None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert):
            continue
        all_calls = [
            call for call in ast.walk(node.test)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            and call.func.id == "all"
        ]
        for call in all_calls:
            if len(call.args) != 1 or not isinstance(call.args[0], ast.GeneratorExp):
                continue
            generator = call.args[0]
            if len(generator.generators) != 1 or not isinstance(generator.generators[0].iter, ast.Name):
                continue
            multiplier_name = generator.generators[0].iter.id
            expression = generator.elt
            if not any(
                isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                and sub.func.attr in {"verify", "check", "valid", "is_valid"}
                for sub in ast.walk(expression)
            ):
                continue
            if not any(
                isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                and sub.func.id == "pow" and len(sub.args) == 3
                for sub in ast.walk(expression)
            ):
                continue
            if not any(
                isinstance(sub, ast.Attribute) and sub.attr == "e"
                for sub in ast.walk(expression)
            ):
                continue
            candidates = []
            for sub in ast.walk(expression):
                if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                    and sub.func.id == "int" and len(sub.args) == 2
                    and isinstance(sub.args[0], ast.Name)
                    and isinstance(sub.args[1], ast.Constant)
                    and sub.args[1].value == 16):
                    candidates.append(sub.args[0].id)
            if len(set(candidates)) == 1:
                return candidates[0], multiplier_name, node.lineno
    return None


def discover_positive_padding_oracles(documents: Sequence[Document]) -> list[OracleEvidence]:
    by_scope: dict[str, list[Document]] = {}
    for document in documents:
        by_scope.setdefault(document.scope, []).append(document)
    result = []
    for scope, docs in by_scope.items():
        sources = [
            (doc, names)
            for doc in docs
            if doc.path.endswith(".py")
            if (names := _source_names(doc.text)) is not None
        ]
        if len(sources) != 1:
            continue
        doc, (cipher_name, multiplier_name, line) = sources[0]
        public = [
            key for document in docs for key in pem_rsa_public_keys(document.text)
            if isinstance(key.get("n"), int) and isinstance(key.get("e"), int)
        ]
        if len(public) != 1:
            continue
        n, e = public[0]["n"], public[0]["e"]
        if not (256 <= n.bit_length() <= 4096 and e > 1 and e % 2):
            # A tiny RSA modulus may still be used in tests, but is not the
            # supported PKCS#1 padding-oracle cryptanalytic case.
            continue
        transcripts = []
        for document in docs:
            if document.path == doc.path:
                continue
            for obj in scalar_records(document.text):
                if cipher_name not in obj or multiplier_name not in obj:
                    continue
                raw_cipher = obj[cipher_name]
                multipliers = obj[multiplier_name]
                if not isinstance(raw_cipher, str) or not re.fullmatch(
                    r"[0-9a-fA-F]+", raw_cipher
                ):
                    continue
                try:
                    ciphertext = int(raw_cipher, 16)
                except ValueError:
                    continue
                if (not isinstance(multipliers, list)
                    or not 4 <= len(multipliers) <= 256
                    or any(type(v) is not int or not 0 < v < n for v in multipliers)
                    or not 0 < ciphertext < n):
                    continue
                transcripts.append((ciphertext, tuple(dict.fromkeys(multipliers))))
        if len(transcripts) == 1:
            c, multipliers = transcripts[0]
            result.append(OracleEvidence(doc.path, line, scope, n, e, c, multipliers))
    return result


def _is_pkcs1_v15_em(encoded: bytes) -> bool:
    if len(encoded) < 11 or encoded[:2] != b"\x00\x02":
        return False
    try:
        separator = encoded.index(0, 2)
    except ValueError:
        return False
    return separator >= 10 and all(x != 0 for x in encoded[2:separator])


def _check_candidate(m: int, evidence: OracleEvidence) -> bytes | None:
    n, e, c = evidence.modulus, evidence.exponent, evidence.ciphertext
    key_bytes = (n.bit_length() + 7) // 8
    B = 1 << (8 * (key_bytes - 2))
    if not 2 * B <= m < 3 * B:
        return None
    if pow(m, e, n) != c:
        return None
    for r in evidence.positive_multipliers:
        padded = m * r % n
        if not 2 * B <= padded < 3 * B:
            return None
    encoded = m.to_bytes(key_bytes, "big")
    if not _is_pkcs1_v15_em(encoded):
        return None
    return encoded[encoded.index(0, 2) + 1:]


def _embedding(evidence: OracleEvidence, count: int) -> tuple[list[list[int]], int, int]:
    n = evidence.modulus
    key_bytes = (n.bit_length() + 7) // 8
    B = 1 << (8 * (key_bytes - 2))
    target = 2 * B + B // 2
    multipliers = evidence.positive_multipliers[:count]
    dimension = len(multipliers) + 2
    rows: list[list[int]] = []
    for index in range(len(multipliers)):
        row = [0] * dimension
        row[index] = n
        rows.append(row)
    rows.append(list(multipliers) + [1, 0])
    rows.append([target] * (len(multipliers) + 1) + [B])
    return rows, target, B


def _extract(reduced: list[list[int]], evidence: OracleEvidence,
             target: int, B: int) -> list[dict[str, Any]]:
    answers = []
    seen = set()
    # The embedding target coefficient must be +/-1. A reduced basis may
    # expose it directly or by adding a short zero-target row.
    promising = [row for row in reduced if abs(row[-1]) == B]
    zero = sorted(
        (row for row in reduced if row[-1] == 0),
        key=lambda row: sum(x * x for x in row)
    )[:12]
    candidates = promising[:]
    for row in promising[:8]:
        for other in zero:
            for sign in (-1, 1):
                candidates.append([a + sign * b for a, b in zip(row, other)])
    for row in candidates:
        if abs(row[-1]) != B:
            continue
        m = target - row[-2] * (row[-1] // B)
        if m in seen:
            continue
        seen.add(m)
        plaintext = _check_candidate(m, evidence)
        if plaintext is not None:
            answers.append({
                "plaintext": plaintext,
                "plaintext_hex": plaintext.hex(),
                "plaintext_utf8": plaintext.decode("utf8", "replace"),
                "representative": m,
                "reencryption_verified": True,
                "positive_constraints_verified": len(evidence.positive_multipliers),
            })
    return answers


def recover_pkcs1_positive_padding(
    evidence: OracleEvidence, *, backend: str = "auto",
    progress: Callable[[str], Any] = print,
    counts: tuple[int, ...] | None = None,
) -> list[dict[str, Any]]:
    if backend not in {"auto", "flint", "sympy"}:
        raise ValueError("backend must be auto, flint or sympy")
    if counts is None:
        upper = min(len(evidence.positive_multipliers), 80)
        counts = tuple(dict.fromkeys([max(4, upper - 10), upper]))
    for count in counts:
        if not 4 <= count <= len(evidence.positive_multipliers):
            raise ValueError("invalid positive-multiplier count")
        lattice, target, B = _embedding(evidence, count)
        chosen = backend if backend != "auto" else (
            "flint" if len(lattice) > 28 else "sympy"
        )
        progress(f"PKCS#1 v1.5 positive-sample lattice: {count} constraints, "
                 f"dimension {len(lattice)}, backend {chosen}")
        if chosen == "flint":
            try:
                from flint import fmpz_mat
            except ImportError as exc:
                raise RuntimeError(
                    "The large RSA positive-padding lattice needs python-flint. "
                    "On Windows install: py -3.12 -m pip install python-flint"
                ) from exc
            reduced_mat = fmpz_mat(lattice).lll()
            reduced = [
                [int(reduced_mat[i, j]) for j in range(reduced_mat.ncols())]
                for i in range(reduced_mat.nrows())
            ]
        else:
            if len(lattice) > 28:
                raise RuntimeError("SymPy backend is bounded to dimension 28")
            from sympy import Matrix
            reduced = [
                [int(v) for v in row] for row in Matrix(lattice).lll().tolist()
            ]
        answers = _extract(reduced, evidence, target, B)
        if answers:
            return answers
    return []
