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


def _is_linear_core(doc: Document) -> bool:
    return (
        "Zmod(n)" in doc.text
        and bool(re.search(r"\bMatrix\s*\(\s*Zn\s*,\s*k\s*,\s*l\s*,", doc.text))
        and bool(re.search(r"\bbytes\s*\(\s*A\s*\*\s*x\s*\)", doc.text))
    )


def _is_linear_utility(doc: Document) -> bool:
    required = (
        r"\b256\s*\*\*\s*i\b",
        r"\bpad\s*\(\s*a\s*,\s*BLOCK_LEN\s*\)",
        r"\bxor\s*\(\s*out\s*,",
        r"\bbtq\s*\(\s*out\s*\)\s*\[\s*:\s*l\s*\]",
    )
    return (
        "charset" in doc.text and "btq" in doc.text
        and all(re.search(pattern, doc.text) for pattern in required)
    )


def _analyze_linear_hash_pair(
    scope: str, core: Document, utility: Document,
) -> LinearHashContext | None:
    modulus = _constant(core.text, "n")
    shape = re.search(r"\bk\s*,\s*l\s*=\s*(\d+)\s*,\s*(\d+)", core.text)
    block_bytes = _constant(utility.text, "BLOCK_LEN")
    secret = re.search(
        r"assert\s+len\s*\(\s*FLAG\s*\)\s*==\s*(\d+)", core.text,
    )
    alphabet_match = re.search(
        r"(?m)^\s*charset\s*=\s*(\[[^\r\n]*\])", utility.text,
    )
    pattern = re.search(
        r"\bmatch\s*\(\s*r?(['\"])(.*?)\1\s*,\s*FLAG\s*\)",
        core.text,
    )
    if not all((modulus, shape, block_bytes, secret, alphabet_match, pattern)):
        return None
    try:
        alphabet = ast.literal_eval(alphabet_match.group(1))
    except (SyntaxError, ValueError):
        return None
    if not (isinstance(alphabet, list)
            and all(type(value) is int for value in alphabet)
            and len(set(alphabet)) == len(alphabet)):
        return None
    rows, columns = map(int, shape.groups())
    secret_bytes = int(secret.group(1))
    if not (
        2 <= modulus <= 65536
        and 1 <= rows <= 256 and rows <= columns <= 256
        and 1 <= block_bytes <= 32 and secret_bytes == block_bytes
        and 2 <= len(alphabet) <= 16
    ):
        return None
    flag_regex = pattern.group(2)
    try:
        re.compile(flag_regex)
    except re.error:
        return None
    if not flag_regex.startswith("^") or not flag_regex.endswith("$"):
        return None
    location = core.text.find("Zmod(n)")
    return LinearHashContext(
        core.path, scope, core.text.count("\n", 0, location) + 1,
        modulus, rows, columns, block_bytes, secret_bytes,
        tuple(alphabet), flag_regex,
    )


def recognize_linear_hash(
    documents: Sequence[Document],
) -> list[LinearHashContext]:
    scopes: dict[str, list[Document]] = {}
    for document in documents:
        if document.path.lower().endswith((".sage", ".py")):
            scopes.setdefault(document.scope, []).append(document)
    found = []
    for scope, docs in scopes.items():
        core = next((doc for doc in docs if _is_linear_core(doc)), None)
        utility = next((doc for doc in docs if _is_linear_utility(doc)), None)
        if core is None or utility is None:
            continue
        context = _analyze_linear_hash_pair(scope, core, utility)
        if context is not None:
            found.append(context)
    return found


def _matrix_from_literal(doc: Document, context: LinearHashContext) -> list[list[int]] | None:
    if not doc.path.lower().endswith((".txt", ".json")):
        return None
    text = doc.text.strip()
    if not text.startswith("["):
        return None
    try:
        candidate = ast.literal_eval(text)
    except (ValueError, SyntaxError, RecursionError):
        return None
    if not isinstance(candidate, list) or len(candidate) != context.rows:
        return None
    if not all(
        isinstance(row, list) and len(row) == context.columns
        and all(type(value) is int and 0 <= value < context.modulus
                for value in row)
        for row in candidate
    ):
        return None
    return candidate


def find_linear_hash_data(
    documents: Sequence[Document], context: LinearHashContext
) -> tuple[list[list[int]], bytes] | None:
    matrices: list[list[list[int]]] = []
    outputs: list[bytes] = []
    for doc in documents:
        if doc.scope != context.scope:
            continue
        candidate = _matrix_from_literal(doc, context)
        if candidate is not None:
            matrices.append(candidate)
        text = doc.text.strip()
        if (doc.path.lower().endswith(".txt")
                and re.fullmatch(r"[0-9a-fA-F]+", text)
                and len(text) == 2 * context.rows):
            outputs.append(bytes.fromhex(text))
    if len(matrices) != 1 or len(outputs) != 1:
        return None
    return matrices[0], outputs[0]


def _modular_elimination(
    matrix: list[list[int]], output: bytes, modulus: int,
) -> tuple[list[list[int]], list[int], int]:
    rows, columns = len(matrix), len(matrix[0])
    augmented = [
        [int(value) % modulus for value in row] + [out % modulus]
        for row, out in zip(matrix, output)
    ]
    permutation = list(range(columns))
    rank = 0
    for position in range(min(rows, columns)):
        selected = next((
            (i, j) for j in range(position, columns)
            for i in range(position, rows)
            if math.gcd(augmented[i][j], modulus) == 1
        ), None)
        if selected is None:
            break
        i, j = selected
        augmented[position], augmented[i] = augmented[i], augmented[position]
        for row in augmented:
            row[position], row[j] = row[j], row[position]
        permutation[position], permutation[j] = permutation[j], permutation[position]
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
    return augmented, permutation, rank


def _candidate_from_free_variables(
    free_values: tuple[int, ...], augmented: list[list[int]],
    permutation: list[int], rank: int, modulus: int,
    permitted: dict[int, int],
) -> list[int] | None:
    columns = len(permutation)
    values = [0] * columns
    for index, value in enumerate(free_values, start=rank):
        values[index] = value
    for index in range(rank):
        residual = (
            augmented[index][-1]
            - sum(augmented[index][j] * values[j]
                  for j in range(rank, columns))
        ) % modulus
        if residual not in permitted:
            return None
        values[index] = permitted[residual]
    candidate = [0] * columns
    for index, original in enumerate(permutation):
        candidate[original] = values[index]
    return candidate


def _satisfies_linear_hash(
    matrix: list[list[int]], output: bytes,
    candidate: list[int], modulus: int,
) -> bool:
    return all(
        sum(a * x for a, x in zip(row, candidate)) % modulus == out
        for row, out in zip(matrix, output)
    )


def recover_small_alphabet_vectors(
    matrix: list[list[int]], output: bytes, modulus: int,
    alphabet: tuple[int, ...], *, max_guesses: int = 250_000,
) -> tuple[list[list[int]], int]:
    """Unit-pivot elimination followed by bounded free-variable enumeration."""
    rows = len(matrix)
    columns = len(matrix[0]) if matrix else 0
    if not rows or not columns or any(len(row) != columns for row in matrix):
        raise ValueError("invalid matrix")
    if len(output) != rows:
        raise ValueError("output does not match matrix row count")
    augmented, permutation, rank = _modular_elimination(matrix, output, modulus)
    free_count = columns - rank
    if len(alphabet) ** free_count > max_guesses:
        raise ValueError(
            f"free-variable search exceeds limit: {free_count} variables "
            f"over {len(alphabet)} values"
        )
    permitted = {value % modulus: value for value in alphabet}
    solutions = []
    for free_values in itertools.product(alphabet, repeat=free_count):
        candidate = _candidate_from_free_variables(
            free_values, augmented, permutation, rank, modulus, permitted,
        )
        if candidate is not None and _satisfies_linear_hash(
                matrix, output, candidate, modulus):
            solutions.append(candidate)
    return solutions, rank


def _verify_linear_hash_flag(
    number: int, context: LinearHashContext,
    expression: re.Pattern[str], prefix: str,
    matrix: list[list[int]], output: bytes,
) -> str | None:
    padded_xor = number.to_bytes(context.secret_bytes, "little")
    secret = bytes(byte ^ context.block_bytes for byte in padded_xor)
    try:
        decoded = secret.decode("ascii")
    except UnicodeDecodeError:
        return None
    candidate = prefix + "{" + decoded + "}"
    if not expression.fullmatch(candidate):
        return None
    # Independently reconstruct the complete source-defined serialization.
    raw = bytes(byte ^ context.block_bytes for byte in secret)
    integer = int.from_bytes(raw, "little")
    base = len(context.alphabet)
    digits = []
    for _ in range(context.columns):
        digits.append(context.alphabet[integer % base])
        integer //= base
    if _satisfies_linear_hash(matrix, output, digits, context.modulus):
        return candidate
    return None


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
    prefix = re.match(r"^\^([A-Za-z_][A-Za-z_0-9]*)\\\{", context.flag_regex)
    answers: set[str] = set()
    if prefix is not None:
        for solution in solutions:
            low = sum(
                context.alphabet.index(value) * base ** index
                for index, value in enumerate(solution)
            )
            for multiple in range((full_max - 1 - low) // low_modulus + 1):
                candidate = _verify_linear_hash_flag(
                    low + multiple * low_modulus, context,
                    expression, prefix.group(1), matrix, output,
                )
                if candidate is not None:
                    answers.add(candidate)
    return LinearHashResult(
        tuple(sorted(answers)), len(solutions), rank,
        context.columns - rank, True,
    )
