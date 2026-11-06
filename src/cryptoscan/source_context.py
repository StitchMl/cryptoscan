"""Conservative source-grounding for the interactive cryptanalysis assistant.

Never executes challenge code. Recipes are enabled only when exact source
structures establish the token serialization, encryption and verification.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Any, Sequence

from .parser import Document


@dataclass(frozen=True)
class SourceContext:
    path: str
    function: str
    line: int
    excerpt: str


@dataclass(frozen=True)
class TokenRecipe:
    build: SourceContext
    verify: SourceContext
    fields: tuple[str, ...]
    cookie_name: str | None
    ignore_authentication: bool
    format: str


def _functions(documents: Sequence[Document]):
    for document in documents:
        if not document.path.lower().endswith(".py"):
            continue
        try:
            tree = ast.parse(document.text)
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield document, node


def _context(doc: Document, node: ast.AST) -> SourceContext:
    snippet = doc.text.splitlines()[node.lineno - 1].strip()
    return SourceContext(doc.path, getattr(node, "name", "<unknown>"), node.lineno, snippet[:160])


def relevant_source(finding: Any, documents: Sequence[Document]) -> list[SourceContext]:
    """Resolve a finding to its actual document and enclosing functions, if any."""
    path = finding.location.split(":", 1)[0].split(" + ", 1)[0]
    matched = [document for document in documents if document.path == path]
    contexts: list[SourceContext] = []
    for document in matched:
        try:
            line = int(finding.location[len(path) + 1:].split(" ", 1)[0])
        except (ValueError, IndexError):
            line = None
        if line is None:
            continue
        lines = document.text.splitlines()
        if not 1 <= line <= len(lines):
            continue
        owner = "<module>"
        try:
            tree = ast.parse(document.text)
            nodes = [
                n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.lineno <= line <= getattr(n, "end_lineno", n.lineno)
            ]
            if nodes:
                owner = min(nodes, key=lambda n: n.end_lineno - n.lineno).name
        except (SyntaxError, ValueError):
            pass
        contexts.append(SourceContext(document.path, owner, line, lines[line - 1].strip()[:160]))
    return contexts


def _is_json_payload(node: ast.AST) -> tuple[str, ...] | None:
    """Check a json.dumps({constant-string-key: variable, ...}).encode() chain."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "encode" and isinstance(node.func.value, ast.Call)):
        return None
    dumps = node.func.value
    if not (isinstance(dumps.func, ast.Name) and dumps.func.id == "dumps"
            or isinstance(dumps.func, ast.Attribute) and dumps.func.attr == "dumps"):
        return None
    if not dumps.args or not isinstance(dumps.args[0], ast.Dict):
        return None
    payload = dumps.args[0]
    if not payload.keys or not all(isinstance(key, ast.Constant) and isinstance(key.value, str)
                                    for key in payload.keys):
        return None
    if not all(isinstance(value, ast.Name) for value in payload.values):
        return None
    keys = tuple(key.value for key in payload.keys)
    values = tuple(value.id for value in payload.values)
    if keys != values:
        return None
    return keys


def _build_signature(doc: Document, node: ast.FunctionDef) -> tuple[str, ...] | None:
    """Recognize the supplied custom GCM token layout, not arbitrary GCM use."""
    fields = None
    encrypted = False
    returned_pair = False
    for statement in ast.walk(node):
        if isinstance(statement, ast.Assign):
            result = _is_json_payload(statement.value)
            if result:
                fields = result
        if isinstance(statement, ast.Call) and isinstance(statement.func, ast.Attribute):
            if statement.func.attr == "encrypt" and len(statement.args) == 1:
                encrypted = True
            if statement.func.attr == "join" and statement.func.value and isinstance(statement.func.value, ast.Constant) and statement.func.value.value == ";":
                if statement.args and isinstance(statement.args[0], (ast.List, ast.Tuple)):
                    elements = statement.args[0].elts
                    if len(elements) == 2 and all(isinstance(part, ast.Call) and isinstance(part.func, ast.Attribute)
                                                  and part.func.attr == "hex" for part in elements):
                        returned_pair = True
    return fields if fields and encrypted and returned_pair else None


def _verification_signature(node: ast.FunctionDef) -> bool:
    decrypted = False
    uses_auth = False
    parses_role = False
    status_names: set[str] = set()
    for part in ast.walk(node):
        if isinstance(part, ast.Assign) and isinstance(part.value, ast.Call) and isinstance(part.value.func, ast.Attribute):
            if part.value.func.attr == "decrypt" and len(part.targets) == 1 and isinstance(part.targets[0], ast.Tuple):
                target = part.targets[0]
                if len(target.elts) == 2 and isinstance(target.elts[1], ast.Name):
                    decrypted = True
                    status_names.add(target.elts[1].id)
        if isinstance(part, ast.Subscript) and isinstance(part.slice, ast.Constant) and part.slice.value == "role":
            parses_role = True
    if not (decrypted and parses_role and status_names):
        return False
    for part in ast.walk(node):
        if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Load) and part.id in status_names:
            uses_auth = True
    return not uses_auth


def discover_token_recipes(documents: Sequence[Document]) -> list[TokenRecipe]:
    """Require a matching builder AND verifier in the same challenge scope."""
    builders = []
    verifiers = []
    for doc, function in _functions(documents):
        if function.name == "build_token":
            fields = _build_signature(doc, function)
            if fields:
                builders.append((doc, function, fields))
        if function.name == "verif_token" and _verification_signature(function):
            verifiers.append((doc, function))
    cookie_names: dict[str, str] = {}
    for doc in documents:
        matches = re.findall(r"\\.set_cookie\\(\\s*['\"]([^'\"]+)['\"]", doc.text)
        if len(set(matches)) == 1:
            cookie_names[doc.scope] = matches[0]
    recipes = []
    for doc, function, fields in builders:
        for other, verifier in verifiers:
            if doc.scope != other.scope:
                continue
            if doc.path != other.path:
                continue
            recipes.append(TokenRecipe(
                _context(doc, function), _context(other, verifier), fields,
                cookie_names.get(doc.scope), True, "json-utf8/hex-ct-semicolon-hex-tag"
            ))
    return recipes


def linked_recipe(finding: Any, recipes: Sequence[TokenRecipe]) -> TokenRecipe | None:
    """Only link the source-verified token recipe to relevant findings."""
    if finding.rule not in {"AEAD-AUTH-RESULT-IGNORED", "NONCE-CONSTANT", "GCM-NONCE-REUSE"}:
        return None
    for recipe in recipes:
        if finding.location.startswith(recipe.build.path + ":") or finding.location.startswith(recipe.verify.path + ":"):
            return recipe
    return None
