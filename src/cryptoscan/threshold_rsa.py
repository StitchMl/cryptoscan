"""Generic truncated-polynomial RSA share recovery; pure Python kernel."""
from __future__ import annotations

import ast
import math
import re
import socket
from dataclasses import dataclass
from fractions import Fraction
from functools import reduce
from typing import Sequence

from .parser import Document


@dataclass(frozen=True)
class TruncatedShareRSA:
    coefficient_count: int
    maximum_friends: int


def _literal_count(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None


def _coefficient_count(tree: ast.Module) -> int | None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.BinOp):
            continue
        expr = node.value
        if not isinstance(expr.op, ast.Add) or not isinstance(expr.left, ast.List):
            continue
        if len(expr.left.elts) != 1 or not isinstance(expr.right, ast.ListComp):
            continue
        generators = [item for item in ast.walk(expr.right.elt)
                      if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute)
                      and item.func.attr == "getrandbits"]
        if not generators or len(expr.right.generators) != 1:
            continue
        source = expr.right.generators[0].iter
        if not (isinstance(source, ast.Call) and isinstance(source.func, ast.Name)
                and source.func.id == "range" and len(source.args) == 1):
            continue
        count = _literal_count(source.args[0])
        if count is not None and 1 <= count <= 256:
            return count + 1
    return None


def _maximum_friends(tree: ast.Module) -> int | None:
    candidates = {
        node.args[0].left.id for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr == "pop"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.BinOp)
        and isinstance(node.args[0].op, ast.Sub)
        and isinstance(node.args[0].left, ast.Name)
        and _literal_count(node.args[0].right) == 2
    }
    incremented = {
        node.target.id for node in ast.walk(tree)
        if isinstance(node, ast.AugAssign)
        and isinstance(node.target, ast.Name)
        and isinstance(node.op, ast.Add)
        and _literal_count(node.value) == 1
    }
    if len(candidates & incremented) != 1:
        return None
    count_name = next(iter(candidates & incremented))
    maxima = [
        _literal_count(node.comparators[0]) for node in ast.walk(tree)
        if isinstance(node, ast.Compare) and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Gt)
        and isinstance(node.left, ast.Name) and node.left.id == count_name
        and len(node.comparators) == 1
    ]
    return maxima[0] if len(maxima) == 1 else None


def _structurally_supported(tree: ast.Module) -> bool:
    call_attrs = {node.func.attr for node in ast.walk(tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    call_names = {node.func.id for node in ast.walk(tree)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    if not {"getPrime", "input", "pow", "matrix"} <= call_names:
        return False
    if not {"solve_left", "pop"} <= call_attrs:
        return False
    return (any(isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice)
                for node in ast.walk(tree))
            and any(isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
                    for node in ast.walk(tree))
            and any(isinstance(node, ast.While) for node in tree.body))


def extract_instance(documents: Sequence[Document]) -> TruncatedShareRSA | None:
    matches = []
    for document in documents:
        if not document.path.lower().endswith((".sage", ".py")):
            continue
        try:
            tree = ast.parse(document.text)
        except SyntaxError:
            continue
        if not _structurally_supported(tree):
            continue
        count = _coefficient_count(tree)
        maximum = _maximum_friends(tree)
        if (count is not None and maximum is not None
                and maximum >= count + 1 and count <= 128):
            matches.append(TruncatedShareRSA(count, maximum))
    return matches[0] if len(matches) == 1 else None


def _two_nullspace_seeds(degree: int):
    """Solve the nonconstant columns of a truncated Vandermonde system."""
    seeds = []
    for active in (degree, degree + 1):
        row = [Fraction(0)] * (degree + 2)
        row[active] = Fraction(1)
        for exponent in range(degree - 1, 0, -1):
            total = sum((row[t] * pow(t, exponent)
                         for t in range(exponent + 1, degree + 2)), Fraction(0))
            row[exponent] = -total / pow(exponent, exponent)
        seeds.append((row, sum(row[1:])))
    return seeds


def interpolation_kernel(coefficient_count: int) -> tuple[int, ...]:
    """Primitive integer left-kernel for reshares with truncated polynomials.

    At threshold t+1, the disclosed share is evaluated at x=t and has
    Lagrange weight (-1)^(t-1)*(t+1), for t=1..coefficient_count+1.
    """
    if not 2 <= coefficient_count <= 128:
        raise ValueError("unsupported coefficient count")
    (first, first_sum), (second, second_sum) = _two_nullspace_seeds(coefficient_count)
    unweighted = [second_sum * first[t] - first_sum * second[t]
                  for t in range(1, coefficient_count + 2)]
    if not any(unweighted):
        raise ValueError("degenerate interpolation kernel")
    rational = [value / (((-1) ** t) * (t + 2))
                for t, value in enumerate(unweighted)]
    factor = 1
    for value in rational:
        factor = math.lcm(factor, value.denominator)
    result = [int(value * factor) for value in rational]
    divisor = reduce(math.gcd, result)
    if divisor < 1:
        raise ValueError("empty interpolation kernel")
    result = [value // divisor for value in result]
    for exponent in range(coefficient_count):
        if sum(result[t - 1] * (((-1) ** (t - 1)) * (t + 1))
               * pow(t, exponent)
               for t in range(max(1, exponent), coefficient_count + 2)):
            raise ValueError("interpolation kernel verification failed")
    return tuple(result)


def recover_private_exponent(n: int, e: int, shares: Sequence[int], *,
                             relation: Sequence[int] | None = None) -> int:
    if n <= 3 or e <= 1 or not 3 <= len(shares) <= 129:
        raise ValueError("unsupported RSA sharing parameters")
    if relation is None:
        relation = interpolation_kernel(len(shares) - 1)
    if len(relation) != len(shares):
        raise ValueError("mismatched interpolation relation")
    multiple = abs(sum(weight * share for weight, share in zip(relation, shares, strict=True)))
    if multiple == 0:
        raise ValueError("zero totient multiple")
    while (common := math.gcd(e, multiple)) != 1:
        multiple //= common
    exponent = pow(e, -1, multiple)
    if any(pow(base, e * exponent, n) != base % n for base in (2, 3, 5)):
        raise ValueError("the share relation does not yield an RSA decryption exponent")
    return exponent


class _Stream:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = bytearray()

    def until(self, token: bytes, limit: int = 16384) -> str:
        while token not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError(
                    f"RSA service closed awaiting {token!r}; tail={self.buffer[-160:]!r}"
                )
            self.buffer.extend(chunk)
            if len(self.buffer) > limit:
                raise ValueError("oversized RSA protocol response")
        end = self.buffer.index(token) + len(token)
        data = bytes(self.buffer[:end])
        del self.buffer[:end]
        return data.decode("utf-8", "replace")

    def line(self) -> str:
        return self.until(b"\n").strip()

    def send(self, value: int) -> None:
        self.sock.sendall(f"{value}\n".encode("ascii"))


def _parsed_number(line: str, label: str) -> int:
    if label == "part":
        match = re.search(r"part:\s*(\d+)$", line)
    else:
        match = re.fullmatch(re.escape(label) + r"\s*=\s*(\d+)", line)
    if match is None:
        raise RuntimeError(f"unexpected {label} response: {line[:160]!r}")
    return int(match.group(1))


def recover_flag(documents: Sequence[Document], host: str, port: int, *,
                 timeout: float = 60.0) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("source is not an overdetermined truncated-share RSA oracle")
    weights = interpolation_kernel(instance.coefficient_count)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        wire = _Stream(sock)
        modulus = _parsed_number(wire.line(), "n")
        public_exponent = _parsed_number(wire.line(), "e")
        shares = []
        for count in range(1, instance.coefficient_count + 2):
            if count > 1:
                wire.until(b"> ")
                wire.send(2)
            wire.until(b"? ")
            wire.send(count)
            shares.append(_parsed_number(wire.line(), "part"))
        exponent = recover_private_exponent(
            modulus, public_exponent, shares, relation=weights
        )
        wire.until(b"> ")
        wire.send(3)
        announcement = wire.line()
        if "Bye" not in announcement:
            raise RuntimeError(f"unexpected RSA completion: {announcement[:120]!r}")
        ciphertext = int(wire.line())
        raw = pow(ciphertext, exponent, modulus)
    payload = raw.to_bytes((raw.bit_length() + 7) // 8, "big")
    candidate = re.search(rb"([A-Za-z0-9_]{2,32}\{[^\r\n{}]{1,180}\})$", payload)
    if not candidate:
        raise RuntimeError("RSA plaintext did not end in a flag-shaped suffix")
    return candidate.group(1).decode("utf-8", "replace")
