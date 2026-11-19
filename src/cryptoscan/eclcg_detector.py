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


def detect_ec_lcg(documents: list[Document]) -> list[ECLCGContext]:
    results: list[ECLCGContext] = []
    for doc in documents:
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        generators = set()
        signers = set()
        for name, node in functions.items():
            src = ast.unparse(node)
            normalized = "".join(src.split())
            if ("yield" in src and "%" in src and "*" in src and "+" in src
                    and any(isinstance(child, ast.Yield) for child in ast.walk(node))):
                generators.add(name)
            if ("pow(k,-1," in normalized
                    and any(isinstance(child, ast.Tuple) and len(child.elts) == 2
                            for child in ast.walk(node))):
                signers.add(name)
        if not generators or not signers:
            continue
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        generator_vars = set()
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
        if not generator_vars:
            continue
        correlated = False
        for call in calls:
            if not isinstance(call.func, ast.Name) or call.func.id != "zip":
                continue
            if any(isinstance(arg, ast.Name) and arg.id in generator_vars for arg in call.args):
                correlated = True
        if not correlated or not any(isinstance(c.func, ast.Name) and c.func.id in signers for c in calls):
            continue
        text = ast.unparse(tree)
        if not ("MODE_CTR" in text and "sha256" in text and "sigs" in text):
            continue
        signatures = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "msgs" for t in node.targets):
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    signatures = len(node.value.elts)
        line = min(functions[name].lineno for name in generators)
        results.append(ECLCGContext(doc.path, line, signatures))
    return results
