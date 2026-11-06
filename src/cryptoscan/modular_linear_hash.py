"""Source-derived modular linear hash analysis with bounded small-alphabet inversion.

Recognizes an integer-to-base-B, truncated, small-alphabet vector multiplied
by a known matrix modulo q. Never treats Zmod(q) as an RSA key.
No Sage execution and no challenge-specific answers or matrices.
"""
from __future__ import annotations

import ast
import itertools
import math
import re
from dataclasses import dataclass
from typing import Sequence, Any

from .parser import Document


@dataclass(frozen=True)
class LinearHashContext:
    path: str
    scope: str
    line: int
    modulus: int
    rows: int
    columns: int
    block_bytes: int
    secret_bytes: int
    alphabet: tuple[int, ...]
    flag_regex: str


@dataclass(frozen=True)
class LinearHashResult:
    recovered: tuple[str, ...]
    alphabet_solutions: int
    modular_rank: int
    free_variables: int
    verified: bool


def _constant(text: str, name: str) -> int | None:
    matches = re.findall(
        rf"(?m)^\s*{re.escape(name)}\s*=\s*(\d+)\s*(?:#.*)?$", text
    )
    return int(matches[0]) if len(matches) == 1 else None


def recognize_linear_hash(documents: Sequence[Document]) -> list[LinearHashContext]:
    scopes: dict[str, list[Document]] = {}
    for document in documents:
        if document.path.lower().endswith((".sage", ".py")):
            scopes.setdefault(document.scope, []).append(document)
    found = []
    for scope, docs in scopes.items():
        all_text = "\n".join(doc.text for doc in docs)
        core = next((
            doc for doc in docs
            if "Zmod(n)" in doc.text
            and re.search(r"\bMatrix\s*\(\s*Zn\s*,\s*k\s*,\s*l\s*,", doc.text)
            and re.search(r"\bbytes\s*\(\s*A\s*\*\s*x\s*\)", doc.text)
        ), None)
        if core is None:
            continue
        utility = next((
            doc for doc in docs
            if "charset" in doc.text
            and "btq" in doc.text
            and re.search(r"\b256\s*\*\*\s*i\b", doc.text)
            and re.search(r"\bpad\s*\(\s*a\s*,\s*BLOCK_LEN\s*\)", doc.text)
            and re.search(r"\bxor\s*\(\s*out\s*,", doc.text)
            and re.search(r"\bbtq\s*\(\s*out\s*\)\s*\[\s*:\s*l\s*\]", doc.text)
        ), None)
        if utility is None:
            continue
        n = _constant(core.text, "n")
        shape = re.search(r"\bk\s*,\s*l\s*=\s*(\d+)\s*,\s*(\d+)", core.text)
        block = _constant(utility.text, "BLOCK_LEN")
        secret = re.search(
            r"assert\s+len\s*\(\s*FLAG\s*\)\s*==\s*(\d+)", core.text
        )
        alphabet_match = re.search(r"(?m)^\s*charset\s*=\s*(\[[^\r\n]*\])", utility.text)
        pattern = re.search(
            r"\bmatch\s*\(\s*r?(['\"])(.*?)\1\s*,\s*FLAG\s*\)",
            core.text,
        )
        if not all((n, shape, block, secret, alphabet_match, pattern)):
            continue
        try:
            charset = ast.literal_eval(alphabet_match.group(1))
        except (SyntaxError, ValueError):
            continue
        if not (isinstance(charset, list)
                and all(type(item) is int for item in charset)
                and len(set(charset)) == len(charset)):
            continue
        rows, columns = map(int, shape.groups())
        secret_length = int(secret.group(1))
        if not (2 <= n <= 65536
                and 1 <= rows <= 256 and rows <= columns <= 256
                and 1 <= block <= 32 and secret_length == block
                and 2 <= len(charset) <= 16):
            continue
        flag_regex = pattern.group(2)
        try:
            compiled = re.compile(flag_regex)
        except re.error:
            continue
        if not flag_regex.startswith("^") or not flag_regex.endswith("$"):
            continue
        location = core.text.find("Zmod(n)")
        found.append(LinearHashContext(
            core.path, scope, core.text.count("\n", 0, location) + 1,
            n, rows, columns, block, secret_length,
            tuple(charset), flag_regex,
        ))
    return found


def find_linear_hash_data(
    documents: Sequence[Document], context: LinearHashContext
) -> tuple[list[list[int]], bytes] | None:
    matrices: list[list[list[int]]] = []
    outputs: list[bytes] = []
    for doc in documents:
        if doc.scope != context.scope:
            continue
        text = doc.text.strip()
        if doc.path.lower().endswith((".txt", ".json")) and text.startswith("["):
            try:
                candidate = ast.literal_eval(text)
            except (ValueError, SyntaxError, RecursionError):
                continue
            if (isinstance(candidate, list)
                and len(candidate) == context.rows
                and all(isinstance(row, list)
                        and len(row) == context.columns
                        and all(type(value) is int
                                and 0 <= value < context.modulus for value in row)
                        for row in candidate)):
                matrices.append(candidate)
        if (doc.path.lower().endswith(".txt")
                and re.fullmatch(r"[0-9a-fA-F]+", text)
                and len(text) == 2 * context.rows):
            outputs.append(bytes.fromhex(text))
    if len(matrices) != 1 or len(outputs) != 1:
        return None
    return matrices[0], outputs[0]


def recover_small_alphabet_vectors(
    matrix: list[list[int]], output: bytes, modulus: int,
    alphabet: tuple[int, ...], *, max_guesses: int = 250_000,
) -> tuple[list[list[int]], int]:
    """Unit-pivot modular elimination, then enumerate bounded free variables."""
    rows = len(matrix)
    columns = len(matrix[0]) if matrix else 0
    if not rows or not columns or any(len(row) != columns for row in matrix):
        raise ValueError("invalid matrix")
    if len(output) != rows:
        raise ValueError("output does not match matrix row count")
    augmented = [[int(x) % modulus for x in row] + [out % modulus]
                 for row, out in zip(matrix, output)]
    perm = list(range(columns))
    rank = 0
    for position in range(min(rows, columns)):
        selected = next((
            (i, j)
            for j in range(position, columns)
            for i in range(position, rows)
            if math.gcd(augmented[i][j], modulus) == 1
        ), None)
        if selected is None:
            break
        i, j = selected
        augmented[position], augmented[i] = augmented[i], augmented[position]
        for row in augmented:
            row[position], row[j] = row[j], row[position]
        perm[position], perm[j] = perm[j], perm[position]
        inverse = pow(augmented[position][position], -1, modulus)
        augmented[position] = [
            value * inverse % modulus for value in augmented[position]
        ]
        for i in range(rows):
            if i == position:
                continue
            multiplier = augmented[i][position]
            if multiplier:
                augmented[i] = [
                    (a - multiplier * b) % modulus
                    for a, b in zip(augmented[i], augmented[position])
                ]
        rank += 1
    free_count = columns - rank
    if len(alphabet) ** free_count > max_guesses:
        raise ValueError(
            f"free-variable search exceeds limit: {free_count} variables "
            f"over {len(alphabet)} values"
        )
    permitted = {value % modulus: value for value in alphabet}
    solutions: list[list[int]] = []
    for free_values in itertools.product(alphabet, repeat=free_count):
        values = [0] * columns
        for j, value in enumerate(free_values, start=rank):
            values[j] = value
        for i in range(rank):
            residual = (
                augmented[i][-1]
                - sum(augmented[i][j] * values[j]
                      for j in range(rank, columns))
            ) % modulus
            if residual not in permitted:
                break
            values[i] = permitted[residual]
        else:
            candidate = [0] * columns
            for j, original in enumerate(perm):
                candidate[original] = values[j]
            if all(
                sum(a * x for a, x in zip(row, candidate)) % modulus == out
                for row, out in zip(matrix, output)
            ):
                solutions.append(candidate)
    return solutions, rank


def solve_linear_hash(
    documents: Sequence[Document], context: LinearHashContext,
) -> LinearHashResult:
    data = find_linear_hash_data(documents, context)
    if data is None:
        raise ValueError("need exactly one matrix and one matching hex output")
    matrix, output = data
    solutions, rank = recover_small_alphabet_vectors(
        matrix, output, context.modulus, context.alphabet,
    )
    base = len(context.alphabet)
    low_modulus = base ** context.columns
    full_max = 1 << (8 * context.secret_bytes)
    if full_max // low_modulus > 1_000_000:
        raise ValueError("lost high base digits exceed search limit")
    expression = re.compile(context.flag_regex)
    answers = set()
    for solution in solutions:
        low = sum(
            context.alphabet.index(value) * base ** index
            for index, value in enumerate(solution)
        )
        for multiple in range((full_max - 1 - low) // low_modulus + 1):
            number = low + multiple * low_modulus
            padded_xor = number.to_bytes(context.secret_bytes, "little")
            secret = bytes(byte ^ context.block_bytes for byte in padded_xor)
            try:
                decoded = secret.decode("ascii")
            except UnicodeDecodeError:
                continue
            # Get prefix/suffix from the *observed source regex*, not a CTF name.
            prefix = re.match(r"^\^([A-Za-z_][A-Za-z_0-9]*)\\\{", context.flag_regex)
            if prefix is None:
                continue
            possible = prefix.group(1) + "{" + decoded + "}"
            if not expression.fullmatch(possible):
                continue
            # Check the whole source-defined serialization independently.
            raw = bytes(byte ^ context.block_bytes for byte in secret)
            integer = int.from_bytes(raw, "little")
            digits = []
            for _ in range(context.columns):
                digits.append(context.alphabet[integer % base])
                integer //= base
            if all(
                sum(a * d for a, d in zip(row, digits)) % context.modulus == out
                for row, out in zip(matrix, output)
            ):
                answers.add(possible)
    return LinearHashResult(
        tuple(sorted(answers)), len(solutions), rank,
        context.columns - rank, True,
    )
