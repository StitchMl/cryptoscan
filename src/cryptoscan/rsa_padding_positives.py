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


def _is_sentinel_padding_oracle(tree: ast.Module) -> bool:
    """A verifier compares the outcome of decrypt() against a sentinel."""
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef):
            continue
        if function.name not in {"verify", "check", "valid", "is_valid"}:
            continue
        for node in ast.walk(function):
            if not isinstance(node, ast.Compare):
                continue
            compares_sentinel = any(
                isinstance(op, (ast.NotEq, ast.Eq)) for op in node.ops
            )
            checks_decrypt = any(
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "decrypt"
                for call in ast.walk(node)
            )
            if compares_sentinel and checks_decrypt:
                return True
    return False


def _extract_positive_assertion(node: ast.Assert) -> tuple[str, str] | None:
    for call in ast.walk(node.test):
        if not (isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "all" and len(call.args) == 1
                and isinstance(call.args[0], ast.GeneratorExp)):
            continue
        generator = call.args[0]
        if not (len(generator.generators) == 1
                and isinstance(generator.generators[0].iter, ast.Name)):
            continue
        expression = generator.elt
        calls = [part for part in ast.walk(expression)
                 if isinstance(part, ast.Call)]
        has_oracle = any(
            isinstance(part.func, ast.Attribute)
            and part.func.attr in {"verify", "check", "valid", "is_valid"}
            for part in calls
        )
        has_pow = any(
            isinstance(part.func, ast.Name)
            and part.func.id == "pow" and len(part.args) == 3
            for part in calls
        )
        has_exponent = any(
            isinstance(part, ast.Attribute) and part.attr == "e"
            for part in ast.walk(expression)
        )
        if not (has_oracle and has_pow and has_exponent):
            continue
        candidates = [
            part.args[0].id for part in calls
            if isinstance(part.func, ast.Name)
            and part.func.id == "int" and len(part.args) == 2
            and isinstance(part.args[0], ast.Name)
            and isinstance(part.args[1], ast.Constant)
            and part.args[1].value == 16
        ]
        if len(set(candidates)) == 1 and candidates:
            return candidates[0], generator.generators[0].iter.id
    return None


def _source_names(source: str) -> tuple[str, str, int] | None:
    if not all(token in source for token in (
            "PKCS1_v1_5.new", "RSA.import_key", ".decrypt(")):
        return None
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    if not _is_sentinel_padding_oracle(tree):
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            parameters = _extract_positive_assertion(node)
            if parameters is not None:
                return (*parameters, node.lineno)
    return None


def _positive_samples(
    docs: Sequence[Document], source_path: str,
    cipher_name: str, multiplier_name: str, modulus: int,
) -> list[tuple[int, tuple[int, ...]]]:
    transcripts: list[tuple[int, tuple[int, ...]]] = []
    cipher_key, multiplier_key = cipher_name.casefold(), multiplier_name.casefold()
    for document in docs:
        if document.path == source_path:
            continue
        for item in scalar_records(document.text):
            if cipher_key not in item or multiplier_key not in item:
                continue
            raw_cipher, multipliers = item[cipher_key], item[multiplier_key]
            if not isinstance(raw_cipher, str) or not re.fullmatch(
                    r"[0-9a-fA-F]+", raw_cipher):
                continue
            ciphertext = int(raw_cipher, 16)
            if (not isinstance(multipliers, list)
                    or not 4 <= len(multipliers) <= 256
                    or any(type(v) is not int or not 0 < v < modulus
                           for v in multipliers)
                    or not 0 < ciphertext < modulus):
                continue
            transcripts.append((
                ciphertext, tuple(dict.fromkeys(multipliers)),
            ))
    return transcripts


def discover_positive_padding_oracles(
    documents: Sequence[Document],
) -> list[OracleEvidence]:
    by_scope: dict[str, list[Document]] = {}
    for document in documents:
        by_scope.setdefault(document.scope, []).append(document)
    results = []
    for scope, docs in by_scope.items():
        sources = [
            (doc, names) for doc in docs
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
        modulus, exponent = public[0]["n"], public[0]["e"]
        if not (256 <= modulus.bit_length() <= 4096
                and exponent > 1 and exponent % 2):
            continue
        transcripts = _positive_samples(
            docs, doc.path, cipher_name, multiplier_name, modulus,
        )
        if len(transcripts) == 1:
            ciphertext, multipliers = transcripts[0]
            results.append(OracleEvidence(
                doc.path, line, scope, modulus, exponent,
                ciphertext, multipliers,
            ))
    return results


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
             target: int, block_scale: int) -> list[dict[str, Any]]:
    answers = []
    seen = set()
    # The embedding target coefficient must be +/-1. A reduced basis may
    # expose it directly or by adding a short zero-target row.
    promising = [row for row in reduced if abs(row[-1]) == block_scale]
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
        if abs(row[-1]) != block_scale:
            continue
        m = target - row[-2] * (row[-1] // block_scale)
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


def _reduce_positive_lattice(
    lattice: list[list[int]], chosen: str,
) -> list[list[int]]:
    if chosen == "flint":
        try:
            from flint import fmpz_mat
        except ImportError as exc:
            raise RuntimeError(
                "The large RSA positive-padding lattice needs python-flint. "
                "On Windows install: py -3.12 -m pip install python-flint"
            ) from exc
        matrix = fmpz_mat(lattice).lll()
        return [
            [int(matrix[i, j]) for j in range(matrix.ncols())]
            for i in range(matrix.nrows())
        ]
    if len(lattice) > 28:
        raise RuntimeError("SymPy backend is bounded to dimension 28")
    from sympy import Matrix
    return [[int(v) for v in row] for row in Matrix(lattice).lll().tolist()]


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
        lattice, target, block_scale = _embedding(evidence, count)
        chosen = backend if backend != "auto" else (
            "flint" if len(lattice) > 28 else "sympy"
        )
        progress(
            f"PKCS#1 v1.5 positive-sample lattice: {count} constraints, "
            f"dimension {len(lattice)}, backend {chosen}"
        )
        reduced = _reduce_positive_lattice(lattice, chosen)
        answers = _extract(reduced, evidence, target, block_scale)
        if answers:
            return answers
    return []
