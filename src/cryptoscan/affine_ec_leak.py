"""Offline recovery from affine combinations of elliptic-curve points.

If public R_i = u_i P + v_i Q and Q = secret*P, recover P,Q from
independent observations and solve a feasible subgroup discrete log.
No named challenge parameters, endpoints, or flag values are embedded.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Sequence

from .parser import Document
from .unramified_ring_oracle import _SageWorker

_SOURCE_CURVE = re.compile(
    r"EllipticCurve\(\s*(\w+)\s*,\s*\[\s*(\w+)\s*,\s*(\w+)\s*\]\s*\)"
)
_OUTPUT_ROW = re.compile(
    r"\(\s*(\d+)\s*,\s*(\d+)\s*,\s*\(\s*(\d+)\s*:\s*(\d+)\s*:\s*(\d+)\s*\)\s*\)"
)
_ASSIGNMENT = re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*(\d[\d_]*)\s*(?:#.*)?$")


@dataclass(frozen=True)
class AffineECLeak:
    prime: int
    curve_a: int
    curve_b: int
    records: tuple[tuple[int, int, tuple[int, int, int]], ...]
    prefix: str
    suffix: str


def _mult_terms(expression):
    terms = []
    for term in (expression.left, expression.right):
        if not (isinstance(term, ast.BinOp)
                and isinstance(term.op, ast.Mult)
                and isinstance(term.left, ast.Name)
                and isinstance(term.right, ast.Name)):
            break
        terms.append((term.left.id, term.right.id))
    return terms


def _is_affine_append(node, base, hidden):
    if not (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "append"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Tuple)
            and len(node.args[0].elts) == 3):
        return False
    first, second, expression = node.args[0].elts
    if not (isinstance(first, ast.Name) and isinstance(second, ast.Name)
            and isinstance(expression, ast.BinOp)
            and isinstance(expression.op, ast.Add)):
        return False
    terms = _mult_terms(expression)
    return len(terms) == 2 and set(terms) == {
        (first.id, base), (second.id, hidden)}


def _affine_append_roles(source, base, hidden):
    """Read public affine equations from Sage source using AST where possible.

    Preparse only Sage generator declarations. The source is NEVER executed.
    The fallback below preserves support for unparseable Sage constructs.
    """
    normalized = re.sub(
        r"(?m)^(\s*[A-Za-z_]\w*)\.<[A-Za-z_]\w*>\s*=",
        r"\1 =", source,
    )
    try:
        tree = ast.parse(normalized)
    except (SyntaxError, ValueError, RecursionError):
        return None
    candidates = [node for node in ast.walk(tree)
                  if _is_affine_append(node, base, hidden)]
    return len(candidates) == 1 if candidates else False


def _affine_source_consistent(source, base_name, hidden_name):
    affine_ast = _affine_append_roles(source, base_name, hidden_name)
    if affine_ast is True:
        return True
    # Fallback for Sage constructs outside the supported Python AST.
    # Never let a syntactically valid but semantically mismatched AST
    # bypass the source consistency check.
    if affine_ast is False:
        return False
    combinations = re.findall(
        r"\\.append\\(\\(\\s*(\\w+)\\s*,\\s*(\\w+)\\s*,\\s*"
        r"(\\w+)\\s*\\*\\s*(\\w+)\\s*\\+\\s*"
        r"(\\w+)\\s*\\*\\s*(\\w+)\\s*\\)\\)",
        source,
    )
    if len(combinations) != 1:
        return False
    first, second, u, u_point, v, v_point = combinations[0]
    return {(u, u_point), (v, v_point)} == {
        (first, base_name), (second, hidden_name),
    }


def _curve_parameters(source, p_name, a_name, b_name):
    names = {}
    for name, value in _ASSIGNMENT.findall(source):
        names.setdefault(name, int(value.replace("_", "")))
    p, a, b = (names.get(name) for name in (p_name, a_name, b_name))
    if any(v is None for v in (p, a, b)):
        return None, None, None
    if not (5 <= p.bit_length() <= 512 and 0 <= a < p and 0 <= b < p):
        return None, None, None
    if (4*a**3 + 27*b**2) % p == 0:
        return None, None, None
    return p, a, b


def _source_profile(source: str):
    """Require the source-defined affine leakage and secret-scalar relation."""
    if len(source) > 1_000_000 or not all(token in source for token in (
        "EllipticCurve(", "GF(", "bytes_to_long(", ".append(",
    )):
        return None
    curve = _SOURCE_CURVE.search(source)
    generator = re.search(r"\b\w+\.<(\w+)>\s*=\s*EllipticCurve\(", source)
    if curve is None or generator is None:
        return None
    field, a_name, b_name = curve.groups()
    generator_name = generator.group(1)
    points = re.search(
        rf"(?m)^\s*(\w+)\s*=\s*\w+\s*\*\s*{re.escape(generator_name)}\s*$",
        source,
    )
    if points is None:
        return None
    base_name = points.group(1)
    second = re.search(
        rf"(?m)^\s*(\w+)\s*=\s*(\w+)\s*\*\s*{re.escape(base_name)}\s*$",
        source,
    )
    if second is None:
        return None
    hidden_name, secret_name = second.groups()
    if not re.search(rf"\b{re.escape(secret_name)}\s*=\s*bytes_to_long\(", source):
        return None
    if not _affine_source_consistent(source, base_name, hidden_name):
        return None
    field_match = re.search(
        rf"\b{re.escape(field)}\s*=\s*GF\(\s*(\w+)\s*\)", source,
    )
    if field_match is None:
        return None
    p, a, b = _curve_parameters(source, field_match.group(1), a_name, b_name)
    if p is None:
        return None
    framing = re.search(
        r'\[\s*len\(\s*([\'"])([^\'"]{1,40})\1\s*\)\s*:\s*-1\s*\]',
        source,
    )
    prefix = framing.group(2) if framing else ""
    suffix = "}" if prefix.endswith("{") else ""
    return p, a, b, prefix, suffix


def _records(text: str, prime: int):
    if len(text) > 5_000_000:
        return ()
    parsed = []
    for match in _OUTPUT_ROW.finditer(text):
        u, v, x, y, z = map(int, match.groups())
        if not (0 <= x < prime and 0 <= y < prime and 0 <= z < prime):
            return ()
        parsed.append((u, v, (x, y, z)))
        if len(parsed) > 512:
            return ()
    return tuple(parsed) if len(parsed) >= 3 else ()


def extract_instance(documents: Sequence[Document]) -> AffineECLeak | None:
    candidates = []
    for source in documents:
        model = _source_profile(source.text)
        if model is None:
            continue
        prime, a, b, prefix, suffix = model
        for output in documents:
            if output is source or output.scope != source.scope:
                continue
            rows = _records(output.text, prime)
            if rows:
                candidates.append(AffineECLeak(prime, a, b, rows, prefix, suffix))
    return candidates[0] if len(candidates) == 1 else None


def recover_flag(documents: Sequence[Document]) -> str:
    model = extract_instance(documents)
    if model is None:
        raise ValueError("no supported affine EC point-combination leakage corpus")
    worker = _SageWorker("sage_affine_ec_leak_worker.py")
    try:
        result = worker.ask({
            "mode": "recover_affine_ec_log",
            "prime": model.prime, "a": model.curve_a, "b": model.curve_b,
            "rows": [[u, v, list(point)] for u, v, point in model.records],
        })
    finally:
        worker.close()
    scalar = int(result["scalar"])
    if not 0 < scalar < 1 << 4096:
        raise ValueError("invalid recovered discrete logarithm")
    raw = scalar.to_bytes((scalar.bit_length() + 7) // 8, "big")
    try:
        plaintext = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("recovered EC scalar is not UTF-8 encoded") from exc
    if not plaintext.isprintable():
        raise ValueError("recovered EC scalar does not represent printable text")
    return model.prefix + plaintext + model.suffix
