"""Source-content adapters for filename-independent cryptographic detectors.

A source's filename, extension and directory layout are not evidence of a
vulnerability. Parsing a grammar is; all probes are bounded and never execute
input code. Scope is used only to prevent joining unrelated transcripts.
"""
from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Iterator

from .parser import Document

MAX_SOURCE_LENGTH = 2_000_000


def parse_python(document: Document) -> ast.Module | None:
    source = document.text
    if not source or len(source) > MAX_SOURCE_LENGTH or "\0" in source:
        return None
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def python_sources(documents: Iterable[Document]) -> Iterator[tuple[Document, ast.Module]]:
    for document in documents:
        tree = parse_python(document)
        if tree is not None:
            yield document, tree


def rust_sources(documents: Iterable[Document]) -> Iterator[Document]:
    for document in documents:
        source = document.text
        if (not source or len(source) > MAX_SOURCE_LENGTH or "\0" in source):
            continue
        # Structural Rust grammar markers, rather than an .rs suffix.
        if (re.search(r"\b(?:fn|impl|enum|struct|use|mod|match|const)\s+[A-Za-z_]", source)
                and ("{" in source and "}" in source)):
            yield document


def unique_by_scope(matches: Iterable[tuple[Document, object]]):
    """One model per independent scope, not one per arbitrary filename.

    Duplicate content in the same scope is ignored; distinct matching
    instances remain ambiguous and must not silently select a network target.
    """
    result: dict[tuple[str, str], tuple[Document, object]] = {}
    for document, model in matches:
        signature = document.digest or document.text
        result.setdefault((document.scope, signature), (document, model))
    return list(result.values())
