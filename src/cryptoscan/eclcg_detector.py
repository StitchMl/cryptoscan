"""Source-level correlation of LCG-generated ECDSA nonces with encrypted flags.

This module only diagnoses the structural condition. It does not attempt to
infer a private key from arbitrary ECDSA signatures, or claim a recovered flag.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

from .parser import Document


@dataclass(frozen=True)
class ECLCGContext:
    path: str
    line: int
    signature_count: int | None


def _is_generator(node: ast.FunctionDef, src: str) -> bool:
    return ("yield" in src and "%" in src and "*" in src and "+" in src
            and any(isinstance(child, ast.Yield) for child in ast.walk(node)))


def _is_signer(node: ast.FunctionDef, normalized: str) -> bool:
    return ("pow(k,-1," in normalized
            and any(isinstance(child, ast.Tuple) and len(child.elts) == 2
                    for child in ast.walk(node)))


def _classify_functions(functions: dict[str, ast.FunctionDef]) -> tuple[set[str], set[str]]:
    generators: set[str] = set()
    signers: set[str] = set()
    for name, node in functions.items():
        src = ast.unparse(node)
        if _is_generator(node, src):
            generators.add(name)
        if _is_signer(node, "".join(src.split())):
            signers.add(name)
    return generators, signers


def _generator_variables(tree: ast.AST, generators: set[str]) -> set[str]:
    generator_vars: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        val = node.value
        if not isinstance(val, ast.Call) or not isinstance(val.func, ast.Name):
            continue
        if val.func.id not in generators:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        generator_vars.update(t.id for t in targets if isinstance(t, ast.Name))
    return generator_vars


def _zips_generator(calls: list[ast.Call], generator_vars: set[str]) -> bool:
    return any(
        isinstance(call.func, ast.Name) and call.func.id == "zip"
        and any(isinstance(arg, ast.Name) and arg.id in generator_vars for arg in call.args)
        for call in calls
    )


def _message_count(tree: ast.AST) -> int | None:
    signatures = None
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "msgs" for t in node.targets)
                and isinstance(node.value, (ast.List, ast.Tuple))):
            signatures = len(node.value.elts)
    return signatures


def _detect_in_tree(doc: Document, tree: ast.Module) -> ECLCGContext | None:
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    generators, signers = _classify_functions(functions)
    if not generators or not signers:
        return None
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    generator_vars = _generator_variables(tree, generators)
    if not generator_vars:
        return None
    if not _zips_generator(calls, generator_vars):
        return None
    if not any(isinstance(c.func, ast.Name) and c.func.id in signers for c in calls):
        return None
    text = ast.unparse(tree)
    if not ("MODE_CTR" in text and "sha256" in text and "sigs" in text):
        return None
    line = min(functions[name].lineno for name in generators)
    return ECLCGContext(doc.path, line, _message_count(tree))


def detect_ec_lcg(documents: list[Document]) -> list[ECLCGContext]:
    results: list[ECLCGContext] = []
    for doc in documents:
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        context = _detect_in_tree(doc, tree)
        if context is not None:
            results.append(context)
    return results
