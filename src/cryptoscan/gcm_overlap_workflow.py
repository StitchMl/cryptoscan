"""Source-linked offline workflow for an overlapping-GCTR GCM implementation.

Discovers JSON fields and authorization conditions by AST; no challenge-specific
names, literals, stored cookies, or network access.
"""
from __future__ import annotations

import ast
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from .parser import Document
from .source_context import _is_json_payload, _required_equality_checks, _gcm_iv_signature
from .gcm_overlap_math import compute_counter_overlap_candidates
from .gcm_overlap_detector import counter_overlap_lines
from .http_cookie import cookie_request_header, local_cookie_parse_check


@dataclass(frozen=True)
class OverlapRecipe:
    codec_path: str
    crypto_path: str
    plaintext_fields: tuple[str, ...]
    required_values: tuple[tuple[str, str], ...]
    cookie_name: str | None


def _functions(doc: Document) -> list[ast.FunctionDef]:
    try:
        tree = ast.parse(doc.text)
    except SyntaxError:
        return []
    return [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]


def _builder_fields(function: ast.FunctionDef) -> tuple[str, ...] | None:
    fields = None
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            parsed = _is_json_payload(node.value)
            if parsed is not None:
                if fields is not None and parsed != fields:
                    return None
                fields = parsed
    if fields is None or _gcm_iv_signature(function) is None:
        return None
    calls = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    encrypted = any(node.func.attr == "encrypt" and len(node.args) == 1 for node in calls)
    serialized = any(
        node.func.attr == "join" and isinstance(node.func.value, ast.Constant)
        and node.func.value.value == ";"
        and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple))
        and len(node.args[0].elts) == 2
        and all(
            isinstance(part, ast.Call) and isinstance(part.func, ast.Attribute)
            and part.func.attr == "hex" for part in node.args[0].elts
        ) for node in calls
    )
    return fields if encrypted and serialized else None


def _verifier_checks(function: ast.FunctionDef) -> tuple[tuple[str, str], ...] | None:
    if _gcm_iv_signature(function) is None:
        return None
    has_decrypt = any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "decrypt"
        for node in ast.walk(function)
    )
    has_token_split = any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "split" and node.args
        and isinstance(node.args[0], ast.Constant) and node.args[0].value == ";"
        for node in ast.walk(function)
    )
    if not (has_decrypt and has_token_split):
        return None
    return _required_equality_checks(function)


def _cookie_name(documents: Sequence[Document], scope: str) -> str | None:
    names = set()
    for doc in documents:
        if doc.scope != scope or not doc.path.endswith(".py"):
            continue
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "set_cookie" and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                names.add(node.args[0].value)
    return next(iter(names)) if len(names) == 1 else None


def find_overlap_recipe(
    documents: Sequence[Document], finding_location: str
) -> OverlapRecipe | None:
    """Tie implementation, token builder, verifier and cookie to same scan scope."""
    source_path = finding_location.rsplit(":", 1)[0]
    implementations = [
        doc for doc in documents
        if doc.path == source_path and counter_overlap_lines(doc.text)
    ]
    if len(implementations) != 1:
        return None
    implementation = implementations[0]
    results = []
    for doc in documents:
        if doc.scope != implementation.scope or doc.path == implementation.path:
            continue
        if not doc.path.lower().endswith(".py"):
            continue
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        # Explicitly require import of the custom implementation API.
        importing = any(
            isinstance(node, ast.ImportFrom) and node.module
            and node.module.split(".")[0] == "gcm"
            and any(alias.name == "GCM" for alias in node.names)
            for node in tree.body
        )
        if not importing:
            continue
        functions = _functions(doc)
        builders = [(fn, fields) for fn in functions
                    if (fields := _builder_fields(fn)) is not None]
        verifiers = [(fn, checks) for fn in functions
                     if (checks := _verifier_checks(fn)) is not None]
        for builder, fields in builders:
            for verifier, checks in verifiers:
                if builder is verifier or _gcm_iv_signature(builder) != _gcm_iv_signature(verifier):
                    continue
                if not all(key in fields for key, _ in checks):
                    continue
                results.append(OverlapRecipe(
                    doc.path, implementation.path, fields, checks,
                    _cookie_name(documents, implementation.scope)
                ))
    return results[0] if len(results) == 1 else None


def guided_overlap_workflow(
    finding: Any, documents: Sequence[Document],
    read: Callable[[str], str] = input,
    write: Callable[[str], Any] = print,
) -> None:
    recipe = find_overlap_recipe(documents, finding.location)
    if recipe is None:
        write("No unique source-verified token builder/verifier linked to this GCM implementation.")
        write("Cannot calculate a candidate automatically. Inspect source or supply more evidence.")
        return
    write("Counter-overlap implementation: " + recipe.crypto_path)
    write("Token builder/verifier: " + recipe.codec_path)
    write("Source-derived plaintext fields: " + ", ".join(recipe.plaintext_fields))
    write("Verifier constraints: " + repr(dict(recipe.required_values)))
    write("A fresh cookie from this challenge and current key is required.")
    observed = {
        field: read("Observed " + field + " (exact): ").strip()
        for field in recipe.plaintext_fields
    }
    cookie = read("Fresh token (ciphertext_hex;tag_hex): ").strip()
    old = json.dumps(observed).encode()
    desired = json.dumps(dict(recipe.required_values)).encode()
    try:
        candidates = compute_counter_overlap_candidates(cookie, old, desired)
    except ValueError as exc:
        write("Cannot derive candidates: " + str(exc))
        return
    if not candidates:
        write("No compatible GHASH subkey root. Check plaintext, tag, key age and source assumptions.")
        return
    write(f"Computed {len(candidates)} locally consistent candidate(s).")
    for index, candidate in enumerate(candidates, 1):
        write(f"Candidate {index}: {candidate.token}")
        if recipe.cookie_name:
            write(f"HTTP Cookie header {index}: " + cookie_request_header(recipe.cookie_name, candidate.token))
            if not local_cookie_parse_check(recipe.cookie_name, candidate.token):
                write("Warning: HTTP parser roundtrip failed for this header.")
    write("Proof: each candidate reproduces the captured GHASH tag algebraically.")
    write("Not proof that a remote server accepted it. Multiple candidates may need testing.")
