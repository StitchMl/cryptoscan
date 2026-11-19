"""Conservative AST check of overlap between custom GCM counter uses."""
from __future__ import annotations

import ast


def _calls(function: ast.FunctionDef, method: str) -> list[ast.Call]:
    return [
        node for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == method
    ]


def _overlapping_call(
    encrypt: ast.FunctionDef, build_tag: ast.FunctionDef,
) -> int | None:
    if not _calls(build_tag, "ghash"):
        return None
    builder_calls = _calls(encrypt, "build_tag")
    tag_counters = _calls(build_tag, "gctr")
    for call in _calls(encrypt, "gctr"):
        if not call.args or not isinstance(call.args[0], ast.Name):
            continue
        counter_name = call.args[0].id
        linked = any(
            len(other.args) >= 3
            and isinstance(other.args[2], ast.Name)
            and other.args[2].id == counter_name
            for other in builder_calls
        )
        same_counter = any(
            other.args and isinstance(other.args[0], ast.Name)
            and other.args[0].id == counter_name
            for other in tag_counters
        )
        if linked and same_counter:
            return call.lineno
    return None


def counter_overlap_lines(source: str) -> list[int]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    matches = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        functions = {
            node.name: node for node in cls.body
            if isinstance(node, ast.FunctionDef)
        }
        encrypt, build_tag = functions.get("encrypt"), functions.get("build_tag")
        if encrypt is None or build_tag is None:
            continue
        line = _overlapping_call(encrypt, build_tag)
        if line is not None:
            matches.append(line)
    return matches
