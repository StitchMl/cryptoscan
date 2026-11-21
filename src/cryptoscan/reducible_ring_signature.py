"""General cyclic-ring GLP-like short-secret signature forgery.

A source-derived protocol adapter with no challenge names, paths, private
parameters or expected flags. Heavy lattice recovery is delegated to Sage.
"""
from __future__ import annotations

import ast
import hashlib
import re
import socket
from dataclasses import dataclass
from typing import Sequence

from .parser import Document
from .source_units import parse_python
from .unramified_ring_oracle import _SageWorker


@dataclass(frozen=True)
class ReducibleRingSignature:
    modulus: int
    dimension: int
    short_bound: int
    slack: int
    encoding_width: int
    message: bytes
    public_labels: tuple[str, str]
    prompt_labels: tuple[str, str, str]


def _integer(node, names):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.Name) and node.id in names:
        return names[node.id]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_integer(node.operand, names)
    if isinstance(node, ast.BinOp):
        left, right = _integer(node.left, names), _integer(node.right, names)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.FloorDiv) and right:
            return left // right
        if isinstance(node.op, (ast.Pow, ast.BitXor)):
            if 0 <= right <= 2048 and 0 <= left <= (1 << 40):
                return left ** right
    raise ValueError("unsupported integer source parameter")


def _constants(tree):
    values = {}
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            continue
        try:
            values[node.targets[0].id] = _integer(node.value, values)
        except (ValueError, OverflowError, ZeroDivisionError):
            pass
    return values


def _cyclic_ring(tree, values):
    zmods = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "Zmod" and len(node.args) == 1
    ]
    quotients = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("quotient", "quo")
    ]
    if len(zmods) != 1 or not quotients:
        return None
    for assignment in (node for node in ast.walk(tree)
                       if isinstance(node, ast.Assign)):
        expression = assignment.value
        if not (isinstance(expression, ast.BinOp)
                and isinstance(expression.op, ast.Sub)
                and isinstance(expression.right, ast.Constant)
                and expression.right.value == 1
                and isinstance(expression.left, ast.BinOp)
                and isinstance(expression.left.op, (ast.Pow, ast.BitXor))):
            continue
        try:
            n = _integer(expression.left.right, values)
            q = _integer(zmods[0].args[0], values)
        except (ValueError, OverflowError):
            continue
        if 16 <= n <= 1024 and 3 <= q < (1 << 40):
            return q, n
    return None


def _sampled_secret_names(fn, samplers, constants):
    sampled = set()
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id in samplers
                and len(node.value.args) == 1):
            continue
        try:
            value = _integer(node.value.args[0], constants)
        except ValueError:
            continue
        if value == 1:
            sampled.add(node.targets[0].id)
    return sampled


def _key_equations(fn, sampled):
    equations = []
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Assign)
                and isinstance(node.value, ast.BinOp)
                and isinstance(node.value.op, ast.Add)
                and isinstance(node.value.left, ast.BinOp)
                and isinstance(node.value.left.op, ast.Mult)
                and isinstance(node.value.left.right, ast.Name)
                and isinstance(node.value.right, ast.Name)):
            continue
        secret, noise = node.value.left.right.id, node.value.right.id
        if secret != noise and {secret, noise} <= sampled:
            equations.append((secret, noise))
    return equations


def _verification_bounds(tree, values):
    pairs = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Compare) and len(node.ops) == 1
                and isinstance(node.ops[0], ast.Gt)
                and len(node.comparators) == 1):
            continue
        expression = node.comparators[0]
        if (isinstance(expression, ast.BinOp)
                and isinstance(expression.op, ast.Sub)
                and isinstance(expression.left, ast.Name)
                and isinstance(expression.right, ast.Name)
                and expression.left.id in values
                and expression.right.id in values):
            pairs.add((values[expression.left.id], values[expression.right.id]))
    return next(iter(pairs)) if len(pairs) == 1 else None


def _short_secret_shape(tree, values):
    samplers = {
        fn.name for fn in tree.body if isinstance(fn, ast.FunctionDef)
        and any(isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "randint" for call in ast.walk(fn))
    }
    equations = [
        relation
        for fn in tree.body if isinstance(fn, ast.FunctionDef)
        for relation in _key_equations(
            fn, _sampled_secret_names(fn, samplers, values),
        )
    ]
    if len(equations) != 1:
        return None
    return _verification_bounds(tree, values)


def _message_bytes(tree):
    constants = [
        (node.targets[0].id, node.value.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, bytes)
    ]
    matches = []
    for name, value in constants:
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == name
        ]
        if calls:
            matches.append(value)
    return matches[0] if len(matches) == 1 else None


def _protocol(tree, source):
    prompts = re.findall(
        r"input\(\s*([\"'])([^\"'\r\n]{1,80})\1\s*\)", source,
    )
    public = re.findall(
        r"print\(\s*f([\"'])([A-Za-z_]\w*) = \{[^{}]+\.hex\(\)\}\1\s*\)",
        source,
    )
    widths = re.findall(
        r"long_to_bytes\(\s*int\([^()]+\)\s*,\s*(\d+)\s*\)", source,
    )
    message = _message_bytes(tree)
    if (len(prompts) != 3 or len(public) != 2 or not widths
            or len(set(widths)) != 1 or message is None):
        return None
    width = int(widths[0])
    if not 1 <= width <= 16:
        return None
    return (
        width, message, tuple(name for _, name in public),
        tuple(prompt for _, prompt in prompts),
    )


def extract_instance(documents: Sequence[Document]) -> ReducibleRingSignature | None:
    matches = []
    for document in documents:
        tree = parse_python(document)
        source = document.text
        if tree is None or not all(token in source for token in (
            "sha256(", "long_to_bytes(", "bytes.fromhex(", ".hex()",
        )):
            continue
        values = _constants(tree)
        ring = _cyclic_ring(tree, values)
        short = _short_secret_shape(tree, values)
        protocol = _protocol(tree, source)
        if ring is None or short is None or protocol is None:
            continue
        q, n = ring
        bound, slack = short
        width, message, public, prompts = protocol
        if not (0 < slack < bound < q // 2 and q < (1 << (width * 8))):
            continue
        matches.append(ReducibleRingSignature(
            q, n, bound, slack, width, message, public, prompts,
        ))
    return matches[0] if len(matches) == 1 else None


def _pack(coefficients, width):
    return b"".join(int(coefficient).to_bytes(width, "big")
                    for coefficient in coefficients)


def _unpack(encoded, dimension, width):
    raw = bytes.fromhex(encoded)
    if len(raw) != dimension * width:
        raise ValueError("wrong public polynomial byte count")
    return [int.from_bytes(raw[i:i + width], "big")
            for i in range(0, len(raw), width)]


def _cyclic_product(left, right, modulus):
    size = len(left)
    result = [0] * size
    for i, coefficient in enumerate(left):
        if coefficient:
            for j, other in enumerate(right):
                if other:
                    result[(i + j) % size] += coefficient * other
    return [value % modulus for value in result]


def forge_signature(instance, public_a, public_t, secret, error):
    n, q, width = instance.dimension, instance.modulus, instance.encoding_width
    if any(len(seq) != n for seq in (public_a, public_t, secret, error)):
        raise ValueError("invalid recovered ring dimension")
    if any(value % q not in {0, 1, q - 1} for value in secret + error):
        raise ValueError("recovered secret is not ternary")
    product = _cyclic_product(public_a, secret, q)
    if any((a + e - t) % q for a, e, t in zip(
            product, error, public_t, strict=True)):
        raise ValueError("recovered secret does not satisfy the public equation")
    zero = [0] * n
    digest = hashlib.sha256(_pack(zero, width) + instance.message).digest()
    bits = int.from_bytes(digest, "big")
    challenge = [(bits >> i) & 1 for i in range(n)]
    first = _cyclic_product(secret, challenge, q)
    second = _cyclic_product(error, challenge, q)
    if any(min(value, q - value) > instance.short_bound - instance.slack
           for value in first + second):
        raise ValueError("forged signature violates shortness condition")
    verification = [
        (a + b - c) % q
        for a, b, c in zip(
            _cyclic_product(public_a, first, q), second,
            _cyclic_product(public_t, challenge, q), strict=True,
        )
    ]
    if verification != zero:
        raise ValueError("forged signature fails the public verification equation")
    return tuple(_pack(row, width).hex()
                 for row in (first, second, challenge))


class _Wire:
    def __init__(self, connection):
        self.connection = connection
        self.buffer = bytearray()

    def until(self, token):
        while token not in self.buffer:
            chunk = self.connection.recv(16384)
            if not chunk:
                raise ConnectionError("remote signature verifier closed early")
            self.buffer.extend(chunk)
            if len(self.buffer) > 100_000:
                raise ValueError("oversized signature service transcript")
        end = self.buffer.index(token) + len(token)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def line(self):
        return self.until(b"\n").decode("utf-8", "replace").strip()

    def send(self, value):
        self.connection.sendall(value.encode("ascii") + b"\n")


def _public_keys(wire, instance):
    values = []
    for label in instance.public_labels:
        line = wire.line()
        lhs, separator, rhs = line.partition(" = ")
        if not separator or lhs != label:
            raise RuntimeError(f"unexpected public polynomial: {line[:100]!r}")
        coefficients = _unpack(rhs, instance.dimension, instance.encoding_width)
        if any(not 0 <= value < instance.modulus for value in coefficients):
            raise ValueError("noncanonical public polynomial coefficient")
        values.append(coefficients)
    return values


def recover_flag(documents: Sequence[Document], host: str, port: int, *,
                 timeout: float = 600.0) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("no supported source-verified short-secret ring signature")
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        wire = _Wire(connection)
        public_a, public_t = _public_keys(wire, instance)
        worker = _SageWorker("sage_reducible_ring_worker.py")
        try:
            private = worker.ask({
                "mode": "recover_short_secret",
                "dimension": instance.dimension,
                "modulus": instance.modulus,
                "public_a": public_a,
                "public_t": public_t,
                "coefficient_bound": 1,
            })
            proof = forge_signature(
                instance, public_a, public_t,
                private["secret"], private["error"],
            )
        finally:
            worker.close()
        for prompt, value in zip(instance.prompt_labels, proof, strict=True):
            wire.until(prompt.encode("utf-8"))
            wire.send(value)
        tail = bytearray(wire.buffer)
        while len(tail) < 20_000:
            try:
                part = connection.recv(4096)
            except socket.timeout:
                break
            if not part:
                break
            tail.extend(part)
        output = tail.decode("utf-8", "replace")
    match = re.search(r"\w{2,32}\{[^\r\n{}]{1,256}\}", output)
    if match is None:
        raise RuntimeError("remote verification refused signature: " + output[-250:])
    return match.group(0)
