"""Source-gated recovery for controlled polynomial-GCD prefix oracles.

The source must explicitly read one integer, use it in two polynomial
expressions passed to gcd, and slice a printed secret by that gcd.
When a linear subresultant has a unit leading coefficient modulo the
resultant, its modular root forces a large common divisor.
"""
from __future__ import annotations

import ast
import math
import re
import socket
from dataclasses import dataclass
from typing import Sequence

from sympy import Poly, Symbol, subresultants

from .network_policy import connect_authorized
from .parser import Document
from .source_units import parse_python

VAR = Symbol("controlled_input")


@dataclass(frozen=True)
class PolynomialGCDPrefix:
    first: Poly
    second: Poly
    prompt: str
    variable: str


def _is_int_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) is int


def _polynomial_binop(node: ast.BinOp, variable: str, bindings, seen) -> Poly:
    if isinstance(node.op, ast.Pow):
        if not (_is_int_constant(node.right) and 0 <= node.right.value <= 64):
            raise ValueError("unsupported exponent")
        result = _polynomial(node.left, variable, bindings, seen) ** node.right.value
    else:
        left = _polynomial(node.left, variable, bindings, seen)
        right = _polynomial(node.right, variable, bindings, seen)
        if isinstance(node.op, ast.Add):
            result = left + right
        elif isinstance(node.op, ast.Sub):
            result = left - right
        elif isinstance(node.op, ast.Mult):
            result = left * right
        else:
            raise ValueError("unsupported polynomial operation")
    if result.degree() > 64 or any(
        abs(int(c)).bit_length() > 4096 for c in result.all_coeffs()
    ):
        raise ValueError("polynomial exceeds computational limits")
    return result


def _polynomial(node: ast.AST, variable: str, bindings=None, seen=frozenset()) -> Poly:
    """Interpret a bounded arithmetic AST, never eval arbitrary source."""
    if _is_int_constant(node):
        if abs(node.value).bit_length() > 4096:
            raise ValueError("coefficient too large")
        return Poly(node.value, VAR, domain="ZZ")
    if isinstance(node, ast.Name) and node.id == variable:
        return Poly(VAR, VAR, domain="ZZ")
    if isinstance(node, ast.Name) and bindings and node.id in bindings:
        if node.id in seen:
            raise ValueError("cyclic polynomial source alias")
        return _polynomial(
            bindings[node.id], variable, bindings, seen | {node.id},
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_polynomial(node.operand, variable, bindings, seen)
    if isinstance(node, ast.BinOp):
        return _polynomial_binop(node, variable, bindings, seen)
    raise ValueError("not a supported polynomial expression")


def _is_name_call(node: ast.AST, name: str) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == name)


def _single_name_assign(node: ast.AST) -> bool:
    return (isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name))


def _input_prompt(value: ast.AST):
    """Return the prompt of int(input(...)), or None when not that shape."""
    if not (_is_name_call(value, "int") and len(value.args) == 1):
        return None
    call = value.args[0]
    if not (_is_name_call(call, "input") and len(call.args) <= 1):
        return None
    try:
        prompt = ast.literal_eval(call.args[0]) if call.args else ""
    except (TypeError, SyntaxError, ValueError):
        return None
    return prompt if isinstance(prompt, str) and len(prompt) <= 80 else None


def _controlled_input(tree: ast.Module):
    results = []
    for node in ast.walk(tree):
        if not _single_name_assign(node):
            continue
        prompt = _input_prompt(node.value)
        if prompt is not None:
            results.append((node.targets[0].id, prompt))
    return results


def _slice_is_printed(tree: ast.Module, length_name: str):
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and
                isinstance(node.func, ast.Name) and node.func.id == "print"):
            continue
        for arg in node.args:
            if (isinstance(arg, ast.Subscript)
                    and isinstance(arg.slice, ast.Slice)
                    and arg.slice.lower is None
                    and isinstance(arg.slice.upper, ast.Name)
                    and arg.slice.upper.id == length_name):
                return True
    return False


def _gcd_call_names(tree: ast.Module):
    """Resolve imported gcd aliases without interpreting source code."""
    direct = set()
    modules = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "math":
            direct.update(
                alias.asname or alias.name
                for alias in node.names if alias.name == "gcd"
            )
        elif isinstance(node, ast.Import):
            modules.update(
                alias.asname or alias.name
                for alias in node.names if alias.name == "math"
            )
    return direct, modules


def _is_math_gcd_call(node, direct, modules):
    if not isinstance(node, ast.Call) or len(node.args) != 2:
        return False
    func = node.func
    return (
        isinstance(func, ast.Name) and func.id in direct
    ) or (
        isinstance(func, ast.Attribute) and func.attr == "gcd"
        and isinstance(func.value, ast.Name) and func.value.id in modules
    )


def _prior_polynomial_bindings(tree, consumer):
    """Resolve unambiguous assignments made before a GCD expression.

    An alias is accepted only when it has exactly one definition before
    the use site. Cycles, unknown calls, and unsupported operations are
    rejected by the bounded polynomial interpreter.
    """
    definitions = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.lineno < consumer.lineno):
            name = node.targets[0].id
            definitions.setdefault(name, []).append(node.value)
    return {
        name: values[0] for name, values in definitions.items()
        if len(values) == 1
    }


def _gcd_instance(tree, node, direct, modules, variable, prompt):
    call = node.value
    if not (_is_math_gcd_call(call, direct, modules)
            and _slice_is_printed(tree, node.targets[0].id)):
        return None
    bindings = _prior_polynomial_bindings(tree, node)
    try:
        left = _polynomial(call.args[0], variable, bindings)
        right = _polynomial(call.args[1], variable, bindings)
    except (ValueError, TypeError, ArithmeticError):
        return None
    if (1 <= left.degree() <= 64 and 1 <= right.degree() <= 64
            and left.gcd(right).degree() == 0):
        return PolynomialGCDPrefix(left, right, prompt, variable)
    return None


def _source_profile(document: Document):
    if len(document.text) > 1_000_000:
        return None
    tree = parse_python(document)
    if tree is None:
        return None
    direct, modules = _gcd_call_names(tree)
    found = []
    for variable, prompt in _controlled_input(tree):
        for node in ast.walk(tree):
            if not _single_name_assign(node):
                continue
            item = _gcd_instance(tree, node, direct, modules, variable, prompt)
            if item is not None:
                found.append(item)
    return found[0] if len(found) == 1 else None


def extract_instance(documents: Sequence[Document]) -> PolynomialGCDPrefix | None:
    found = [value for document in documents
             if (value := _source_profile(document)) is not None]
    return found[0] if len(found) == 1 else None


def construct_input(instance: PolynomialGCDPrefix) -> tuple[int, int]:
    """Use the last linear subresultant to obtain a common modular root."""
    first, second = instance.first, instance.second
    resultants = subresultants(first, second)
    if len(resultants) < 3 or resultants[-1].degree() != 0:
        raise RuntimeError("polynomial pair has no nonzero integer resultant")
    modulus = abs(int(resultants[-1].nth(0)))
    if modulus <= 256:
        raise RuntimeError("resultant cannot expose a useful secret prefix")
    linear = next((polynomial for polynomial in reversed(resultants[:-1])
                   if polynomial.degree() == 1), None)
    if linear is None:
        raise RuntimeError("no linear subresultant for modular root recovery")
    a, b = int(linear.nth(1)), int(linear.nth(0))
    divisor = math.gcd(a, modulus)
    if b % divisor:
        raise RuntimeError("linear subresultant congruence has no solution")
    reduced_modulus = modulus // divisor
    if reduced_modulus <= 256:
        raise RuntimeError("subresultant congruence has insufficient modulus")
    # A nonunit linear coefficient may still give a useful common root
    # modulo R / gcd(a, R). No integer factorization is needed.
    root = (
        -(b // divisor) * pow(a // divisor, -1, reduced_modulus)
    ) % reduced_modulus
    candidates = (
        root + lift * reduced_modulus for lift in range(min(divisor, 16))
    )
    verified = [
        (
            math.gcd(int(first.eval(candidate)), int(second.eval(candidate))),
            candidate,
        )
        for candidate in candidates
    ]
    measured, candidate = max(verified)
    if measured < 256:
        raise RuntimeError("subresultant candidate failed the gcd certificate")
    return candidate, measured


def _await_prompt(conn, prompt: bytes) -> None:
    received = bytearray()
    while prompt not in received:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("remote GCD oracle closed before input")
        received.extend(chunk)
        if len(received) > 16384:
            raise ValueError("oversized GCD oracle prompt")


def _read_response(conn) -> bytearray:
    chunks = bytearray()
    while len(chunks) < 16384:
        try:
            block = conn.recv(4096)
        except socket.timeout:
            break
        if not block:
            break
        chunks.extend(block)
    return chunks


def recover_flag(documents: Sequence[Document], host: str, port: int, *,
                 timeout: float = 30.0) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("no supported source-verified polynomial GCD prefix oracle")
    candidate, _ = construct_input(instance)
    with connect_authorized(host, port, timeout) as conn:
        conn.settimeout(timeout)
        prompt = instance.prompt.encode("utf-8")
        if prompt:
            _await_prompt(conn, prompt)
        conn.sendall(str(candidate).encode("ascii") + b"\n")
        chunks = _read_response(conn)
    text = chunks.decode("utf-8", errors="replace")
    flags = re.findall(r"\b\w{2,32}\{[^{}\r\n]{1,256}\}", text)
    if len(flags) != 1:
        raise RuntimeError("remote response did not include exactly one full flag: "
                           + text[-300:])
    return flags[0]
