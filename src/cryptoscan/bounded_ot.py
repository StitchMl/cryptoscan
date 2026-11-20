"""Source-gated encrypted-choice attacks against bounded EC-ElGamal OT.

Recognizes a homomorphic selector without a bit-membership proof. All group
parameters, plaintext bounds, round count and wire prompts come from input
source. No challenge fixture, known secret, flag or public point is embedded.
"""
from __future__ import annotations

import ast
import json
import re
import secrets
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


def _selection(node: ast.AST) -> tuple[str, str, str] | None:
    """Recognize x*(1-choice)+y*choice regardless of variable names."""
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
        return None
    for left, right in ((node.left, node.right), (node.right, node.left)):
        if not (isinstance(left, ast.BinOp) and isinstance(left.op, ast.Mult)
                and isinstance(right, ast.BinOp) and isinstance(right.op, ast.Mult)):
            continue
        for x, one_minus in ((left.left, left.right), (left.right, left.left)):
            if not isinstance(x, ast.Name):
                continue
            if not (isinstance(one_minus, ast.BinOp)
                    and isinstance(one_minus.op, ast.Sub)
                    and isinstance(one_minus.left, ast.Constant)
                    and one_minus.left.value == 1
                    and isinstance(one_minus.right, ast.Name)):
                continue
            choice = one_minus.right.id
            for y, c in ((right.left, right.right), (right.right, right.left)):
                if (isinstance(y, ast.Name) and isinstance(c, ast.Name)
                        and c.id == choice and x.id != y.id):
                    return x.id, y.id, choice
    return None


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


def _round_count(tree: ast.Module, fn_name: str) -> int | None:
    for func in tree.body:
        if not isinstance(func, ast.FunctionDef):
            continue
        for node in ast.walk(func):
            if not isinstance(node, ast.For):
                continue
            if not (isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name)
                    and node.iter.func.id == "range" and len(node.iter.args) == 1
                    and isinstance(node.iter.args[0], ast.Constant)
                    and type(node.iter.args[0].value) is int):
                continue
            if any(isinstance(part, ast.Call) and isinstance(part.func, ast.Name)
                   and part.func.id == fn_name for stmt in node.body for part in ast.walk(stmt)):
                return node.iter.args[0].value
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


def extract_instance(documents: Sequence[Document]) -> BoundedOT | None:
    matches = []
    for doc in documents:
        if not doc.path.lower().endswith(".py"):
            continue
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        symbols = _constants(tree)
        if not all(name in symbols for name in ("p", "q", "Gx", "Gy")):
            continue
        # Require EC-ElGamal source, not just an unrelated arithmetic expression.
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
        if not any({"from_pt", "__add__", "__rmul__", "__sub__"} <=
                   {m.name for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
                   for cls in classes):
            continue
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        if not {"EccPoint", "json", "random"} <= names:
            continue
        for fn in (x for x in tree.body if isinstance(x, ast.FunctionDef)):
            choices = [(stmt.value, _selection(stmt.value))
                       for stmt in ast.walk(fn) if isinstance(stmt, ast.Assign)]
            bounded = _bounded_assignments(fn)
            for _, selection in choices:
                if selection is None:
                    continue
                a, b, choice = selection
                if a not in bounded or b not in bounded:
                    continue
                if any(n not in names for n in (a, b, choice)):
                    continue
                rounds = _round_count(tree, fn.name)
                prompts = _prompts(tree)
                if rounds is None or prompts is None or not 1 <= rounds <= 4096:
                    continue
                lo0, hi0 = bounded[a]
                lo1, hi1 = bounded[b]
                if (hi0 - lo0 + 1) * (hi1 - lo1 + 1) > 4096:
                    continue
                p, q, gx, gy = (symbols[n] for n in ("p", "q", "Gx", "Gy"))
                if not (p > 3 and q > 3 and 0 <= gx < p and 0 <= gy < p
                        and p.bit_length() <= 1024 and q.bit_length() <= 1024):
                    continue
                matches.append(BoundedOT(doc.text, gx, gy, p, q,
                                         lo0, hi0, lo1, hi1, rounds, prompts))
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
    if int(generator.x) != instance.gx or int(generator.y) != instance.gy:
        raise ValueError("unsupported EC generator")
    if not (instance.order * generator).is_point_at_infinity():
        raise ValueError("generator order does not match source")
    # Chosen public key H = secret*G, with a locally known nontrivial secret.
    secret = 2
    public = secret * generator
    # Choose an integer outside the bit domain, but safely within the group.
    base = instance.high0 - instance.low0 + 1
    if base * (instance.high1 - instance.low1 + instance.high0 - instance.low0 + 2) >= instance.order:
        raise ValueError("message domain too large for injective encoding")
    table = _encoding_table(generator, base, instance)
    encrypted_choice_r = generator
    encrypted_choice_s = (secret + base) * generator
    key = {"Hx": int(public.x), "Hy": int(public.y)}
    chosen = {"Rx": int(encrypted_choice_r.x), "Ry": int(encrypted_choice_r.y),
              "Sx": int(encrypted_choice_s.x), "Sy": int(encrypted_choice_s.y)}
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        wire = _Socket(sock)
        wire.until(instance.prompts[0])
        wire.send(key)
        for _ in range(instance.rounds):
            wire.until(instance.prompts[1])
            wire.send(chosen)
            line = wire.line()
            try:
                value = json.loads(line)
                R = EccPoint(int(value["Rx"]), int(value["Ry"]))
                S = EccPoint(int(value["Sx"]), int(value["Sy"]))
                decrypted = S - secret * R
                point = ((int(decrypted.x), int(decrypted.y))
                         if not decrypted.is_point_at_infinity() else (-1, -1))
                messages = table[point]
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError("invalid/unrecognized encrypted OT response") from exc
            wire.until(instance.prompts[2])
            wire.send({"m0": messages[0], "m1": messages[1]})
        remaining = bytearray(wire.buffer)
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            remaining.extend(chunk)
            if len(remaining) > 65536:
                raise RuntimeError("oversized final service response")
        response = remaining.decode("utf-8", "replace")
        match = re.search(r"([A-Za-z0-9_]{2,32}\{[^\r\n}]{1,180}\})", response)
        if not match:
            raise RuntimeError("no flag returned after all OT rounds: " + response[-300:])
        return match.group(1)
