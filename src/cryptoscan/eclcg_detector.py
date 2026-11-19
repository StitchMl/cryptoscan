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


def _function_roles(tree: ast.Module) -> tuple[dict, set[str], set[str]]:
    functions = {
        node.name: node for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    generators, signers = set(), set()
    for name, node in functions.items():
        source = ast.unparse(node)
        normalized = "".join(source.split())
        if ("yield" in source and "%" in source and "*" in source
                and "+" in source and any(
                    isinstance(child, ast.Yield) for child in ast.walk(node)
                )):
            generators.add(name)
        if "pow(k,-1," in normalized and any(
            isinstance(child, ast.Tuple) and len(child.elts) == 2
            for child in ast.walk(node)
        ):
            signers.add(name)
    return functions, generators, signers


def _generator_variables(tree: ast.Module, generators: set[str]) -> set[str]:
    variables = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id in generators):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
        variables.update(target.id for target in targets
                         if isinstance(target, ast.Name))
    return variables


def _correlated_nonce_signatures(
    tree: ast.Module, variables: set[str], signers: set[str],
) -> bool:
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    coupled = any(
        call.func.id == "zip"
        and any(isinstance(arg, ast.Name) and arg.id in variables
                for arg in call.args)
        for call in calls
    )
    signed = any(call.func.id in signers for call in calls)
    return coupled and signed


def _message_count(tree: ast.Module) -> int | None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == "msgs"
               for target in node.targets):
            if isinstance(node.value, (ast.List, ast.Tuple)):
                return len(node.value.elts)
    return None


def _detect_source(doc: Document) -> ECLCGContext | None:
    try:
        tree = ast.parse(doc.text)
    except SyntaxError:
        return None
    functions, generators, signers = _function_roles(tree)
    if not generators or not signers:
        return None
    variables = _generator_variables(tree, generators)
    if not variables or not _correlated_nonce_signatures(tree, variables, signers):
        return None
    source = ast.unparse(tree)
    if not ("MODE_CTR" in source and "sha256" in source and "sigs" in source):
        return None
    line = min(functions[name].lineno for name in generators)
    return ECLCGContext(doc.path, line, _message_count(tree))


def detect_ec_lcg(documents: list[Document]) -> list[ECLCGContext]:
    return [
        context for doc in documents
        if (context := _detect_source(doc)) is not None
    ]
