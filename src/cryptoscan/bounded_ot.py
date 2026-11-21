"""Source-gated encrypted-choice attacks against bounded EC-ElGamal OT.

Recognizes a homomorphic selector without a bit-membership proof. All group
parameters, plaintext bounds, round count and wire prompts come from input
source. No challenge fixture, known secret, flag or public point is embedded.
"""
from __future__ import annotations

from .source_units import parse_python

import ast
import json
import re
import socket
from dataclasses import dataclass
from typing import Sequence

from .parser import Document


@dataclass(frozen=True)
class BoundedOT:
    source: str
    gx: int
    gy: int
    modulus: int
    order: int
    low0: int
    high0: int
    low1: int
    high1: int
    rounds: int
    prompts: tuple[str, str, str]


def _constants(tree: ast.Module) -> dict[str, int]:
    values: dict[str, int] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        if not isinstance(node.targets[0], ast.Name):
            continue
        if isinstance(node.value, ast.Constant) and type(node.value.value) is int:
            values[node.targets[0].id] = node.value.value
    return values


def _names(node: ast.AST) -> set[str]:
    return {part.id for part in ast.walk(node) if isinstance(part, ast.Name)}


def _choice_from_difference(node: ast.AST) -> str | None:
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub)
            and isinstance(node.left, ast.Constant) and node.left.value == 1
            and isinstance(node.right, ast.Name)):
        return node.right.id
    return None


def _multiplication_factors(node: ast.AST) -> tuple[ast.expr, ast.expr] | None:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        return node.left, node.right
    return None


def _match_selection(left: ast.expr, right: ast.expr) -> tuple[str, str, str] | None:
    first = _multiplication_factors(left)
    second = _multiplication_factors(right)
    if first is None or second is None:
        return None
    for x, difference in (first, first[::-1]):
        if not isinstance(x, ast.Name):
            continue
        choice = _choice_from_difference(difference)
        if choice is None:
            continue
        for y, candidate in (second, second[::-1]):
            if (isinstance(y, ast.Name) and isinstance(candidate, ast.Name)
                    and candidate.id == choice and x.id != y.id):
                return x.id, y.id, choice
    return None


def _selection(node: ast.AST) -> tuple[str, str, str] | None:
    """Recognize x*(1-choice)+y*choice regardless of variable names."""
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
        return None
    return (_match_selection(node.left, node.right)
            or _match_selection(node.right, node.left))


def _bounded_assignments(fn: ast.FunctionDef) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for stmt in fn.body:
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
            continue
        target = stmt.targets[0]
        call = stmt.value
        if not (isinstance(target, ast.Name) and isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "randint" and len(call.args) == 2
                and all(isinstance(v, ast.Constant) and type(v.value) is int
                        for v in call.args)):
            continue
        lo, hi = (int(v.value) for v in call.args)
        if lo <= hi:
            result[target.id] = (lo, hi)
    return result


def _literal_range(node: ast.AST) -> int | None:
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "range" and len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
            and type(node.args[0].value) is int):
        return None
    return node.args[0].value


def _calls_function(statements: list[ast.stmt], name: str) -> bool:
    return any(isinstance(part, ast.Call) and isinstance(part.func, ast.Name)
               and part.func.id == name
               for stmt in statements for part in ast.walk(stmt))


def _round_count(tree: ast.Module, fn_name: str) -> int | None:
    loops = (node for fn in tree.body if isinstance(fn, ast.FunctionDef)
             for node in ast.walk(fn) if isinstance(node, ast.For))
    for loop in loops:
        count = _literal_range(loop.iter)
        if count is not None and _calls_function(loop.body, fn_name):
            return count
    return None


def _prompts(tree: ast.Module) -> tuple[str, str, str] | None:
    """Find public-key and two-round prompts by their function structure."""
    prompt_groups: dict[str, list[str]] = {}
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        values = []
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "input" and len(node.args) == 1
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                values.append((node.lineno, node.args[0].value))
        if values:
            prompt_groups[fn.name] = [value for _, value in sorted(values)]
    single = [v[0] for v in prompt_groups.values() if len(v) == 1]
    double = [v for v in prompt_groups.values() if len(v) == 2]
    if len(single) != 1 or len(double) != 1:
        return None
    result = (single[0], *double[0])
    return result if all(value and len(value) <= 128 for value in result) else None


def _source_model(doc: Document) -> tuple[ast.Module, dict[str, int]] | None:
    tree = parse_python(doc)
    if tree is None:
        return None
    symbols = _constants(tree)
    if not {"p", "q", "Gx", "Gy"} <= symbols.keys():
        return None
    classes = (node for node in tree.body if isinstance(node, ast.ClassDef))
    required = {"from_pt", "__add__", "__rmul__", "__sub__"}
    if not any(required <= {method.name for method in cls.body
                            if isinstance(method, ast.FunctionDef)}
               for cls in classes):
        return None
    if not {"EccPoint", "json", "random"} <= _names(tree):
        return None
    return tree, symbols


def _unvalidated_selections(fn: ast.FunctionDef):
    bounds = _bounded_assignments(fn)
    for statement in ast.walk(fn):
        if not isinstance(statement, ast.Assign):
            continue
        selection = _selection(statement.value)
        if selection is None:
            continue
        first, second, choice = selection
        if first not in bounds or second not in bounds:
            continue
        # A membership check may constrain the choice to a bit.
        if any(isinstance(node, (ast.If, ast.Assert, ast.Raise))
               and choice in _names(node) for node in ast.walk(fn)):
            continue
        yield bounds[first], bounds[second]


def _build_instance(doc: Document, tree: ast.Module,
                    symbols: dict[str, int], fn: ast.FunctionDef,
                    bounds: tuple[tuple[int, int], tuple[int, int]]) -> BoundedOT | None:
    rounds, prompts = _round_count(tree, fn.name), _prompts(tree)
    if rounds is None or prompts is None or not 1 <= rounds <= 4096:
        return None
    (lo0, hi0), (lo1, hi1) = bounds
    if (hi0 - lo0 + 1) * (hi1 - lo1 + 1) > 4096:
        return None
    p, q, gx, gy = (symbols[name] for name in ("p", "q", "Gx", "Gy"))
    if not (p > 3 and q > 3 and 0 <= gx < p and 0 <= gy < p
            and p.bit_length() <= 1024 and q.bit_length() <= 1024):
        return None
    return BoundedOT(doc.text, gx, gy, p, q, lo0, hi0, lo1, hi1, rounds, prompts)


def extract_instance(documents: Sequence[Document]) -> BoundedOT | None:
    matches = []
    for doc in documents:
        model = _source_model(doc)
        if model is None:
            continue
        tree, symbols = model
        for fn in (node for node in tree.body if isinstance(node, ast.FunctionDef)):
            for bounds in _unvalidated_selections(fn):
                instance = _build_instance(doc, tree, symbols, fn, bounds)
                if instance is not None:
                    matches.append(instance)
    return matches[0] if len(matches) == 1 else None


def _encoding_table(generator, base: int, instance: BoundedOT) -> dict[tuple[int, int], tuple[int, int]]:
    table = {}
    for m0 in range(instance.low0, instance.high0 + 1):
        for m1 in range(instance.low1, instance.high1 + 1):
            coefficient = (m0 + base * (m1 - m0)) % instance.order
            point = coefficient * generator
            # The point at infinity has no affine coordinates; the public
            # ciphertext response is expected to be rerandomized, but its
            # decrypted representative may be infinity.
            key = (int(point.x), int(point.y)) if not point.is_point_at_infinity() else (-1, -1)
            if key in table:
                raise ValueError("encoding collisions: incompatible message ranges/order")
            table[key] = (m0, m1)
    return table


class _Socket:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = bytearray()

    def until(self, marker: str) -> str:
        needle = marker.encode()
        while needle not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("remote closed before expected input prompt")
            self.buffer.extend(chunk)
            if len(self.buffer) > 262144:
                raise ValueError("remote output too long")
        end = self.buffer.index(needle) + len(needle)
        message = bytes(self.buffer[:end]).decode("utf-8", "replace")
        del self.buffer[:end]
        return message

    def line(self) -> str:
        return self.until("\n").strip()

    def send(self, value: dict[str, int]) -> None:
        self.sock.sendall(json.dumps(value, separators=(",", ":")).encode() + b"\n")


def _recover_reply(wire: _Socket, ecc_point, secret: int,
                   table: dict[tuple[int, int], tuple[int, int]]) -> tuple[int, int]:
    raw = wire.line()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "OT response is not JSON; remote may have rejected the public key "
            f"or ciphertext (response prefix: {raw[:160]!r})"
        ) from exc
    try:
        left = ecc_point(int(value["Rx"]), int(value["Ry"]))
        right = ecc_point(int(value["Sx"]), int(value["Sy"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "OT response is missing valid elliptic-curve coordinates: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    point = right + (-(secret * left))
    address = ((int(point.x), int(point.y))
               if not point.is_point_at_infinity() else (-1, -1))
    messages = table.get(address)
    if messages is None:
        raise RuntimeError(
            "OT decrypted point is outside the expected bounded-message "
            "encoding; source model or chosen-key relation may differ"
        )
    return messages


def _drain(wire: _Socket, sock: socket.socket) -> str:
    result = bytearray(wire.buffer)
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        result.extend(chunk)
        if len(result) > 65536:
            raise RuntimeError("oversized final service response")
    return result.decode("utf-8", "replace")


def _chosen_key_and_ciphertext(generator, secret: int, base: int):
    public = secret * generator
    encrypted = (secret + base) * generator
    key = {"Hx": int(public.x), "Hy": int(public.y)}
    chosen = {"Rx": int(generator.x), "Ry": int(generator.y),
              "Sx": int(encrypted.x), "Sy": int(encrypted.y)}
    return key, chosen


def _parameters(instance: BoundedOT, generator):
    if (int(generator.x), int(generator.y)) != (instance.gx, instance.gy):
        raise ValueError("unsupported EC generator")
    if not (instance.order * generator).is_point_at_infinity():
        raise ValueError("generator order does not match source")
    secret = 2
    base = instance.high0 - instance.low0 + 1
    if base * (instance.high1 - instance.low1 + instance.high0 - instance.low0 + 2) >= instance.order:
        raise ValueError("message domain too large for injective encoding")
    table = _encoding_table(generator, base, instance)
    key, chosen = _chosen_key_and_ciphertext(generator, secret, base)
    return secret, table, key, chosen


def _serve_rounds(wire: _Socket, instance: BoundedOT, ecc_point, secret: int,
                  table, chosen: dict[str, int]) -> None:
    for _ in range(instance.rounds):
        wire.until(instance.prompts[1])
        wire.send(chosen)
        first, second = _recover_reply(wire, ecc_point, secret, table)
        wire.until(instance.prompts[2])
        wire.send({"m0": first, "m1": second})


def recover_flag(documents: Sequence[Document], host: str, port: int, *,
                 timeout: float = 30.0) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("unsupported bounded EC-ElGamal OT source")
    try:
        from Crypto.PublicKey.ECC import EccPoint
    except ImportError as exc:
        raise RuntimeError("requires pycryptodome: py -m pip install --user pycryptodome") from exc
    generator = EccPoint(instance.gx, instance.gy)
    secret, table, key, chosen = _parameters(instance, generator)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        wire = _Socket(sock)
        wire.until(instance.prompts[0])
        wire.send(key)
        _serve_rounds(wire, instance, EccPoint, secret, table, chosen)
        response = _drain(wire, sock)
    match = re.search(r"(\w{2,32}\{[^\r\n}]{1,180}\})", response)
    if match is None:
        raise RuntimeError("no flag returned after all OT rounds: " + response[-300:])
    return match.group(1)
