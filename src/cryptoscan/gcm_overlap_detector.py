"""Conservative AST check of overlap between custom GCM counter uses."""
from __future__ import annotations

import ast


def counter_overlap_lines(source: str) -> list[int]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    matches = []
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        functions = {node.name: node for node in cls.body if isinstance(node, ast.FunctionDef)}
        encrypt, tag = functions.get("encrypt"), functions.get("build_tag")
        if encrypt is None or tag is None:
            continue

        def calls(fn, method):
            return [
                node for node in ast.walk(fn)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == method
            ]

        if not calls(tag, "ghash"):
            continue
        for call in calls(encrypt, "gctr"):
            if not call.args or not isinstance(call.args[0], ast.Name):
                continue
            counter = call.args[0].id
            linked = any(
                len(other.args) >= 3
                and isinstance(other.args[2], ast.Name)
                and other.args[2].id == counter
                for other in calls(encrypt, "build_tag")
            )
            if not linked:
                continue
            if any(
                other.args and isinstance(other.args[0], ast.Name)
                and other.args[0].id == counter
                for other in calls(tag, "gctr")
            ):
                matches.append(call.lineno)
                break
    return matches
