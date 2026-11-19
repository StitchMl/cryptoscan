"""Source-driven correlation attack on XOR-clocked LFSR stream combiners.

No challenge name, known state, taps or flag is embedded. This adapter
extracts public circuit parameters and pairs them with a known-zero
keystream and subsequent ciphertext from the same challenge scope.
"""
from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from itertools import product

from .lfsr_correlation import (
    correlation_recover, lfsr_bits, low_weight_trinomials,
    polynomial_remainders, solve_gf2,
)
from .parser import Document

FLAG = re.compile(rb"[a-zA-Z0-9_]{2,32}\{[\x20-\x7e]{1,180}\}")


def _integer_expression(node: ast.expr, variables: dict[str, int]) -> int:
    """Evaluate only the arithmetic AST nodes in the SHA input."""
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.Name) and node.id in variables:
        return variables[node.id]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_integer_expression(node.operand, variables)
    if isinstance(node, ast.BinOp):
        left = _integer_expression(node.left, variables)
        right = _integer_expression(node.right, variables)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.BitXor):
            return left ^ right
    raise ValueError("Unsupported SHA combiner arithmetic")


@dataclass(frozen=True)
class StreamCombiner:
    degree: int
    masks: tuple[int, ...]
    clocks: tuple[int, ...]
    symbols: tuple[str, ...]
    arithmetic: ast.expr
    path: str

    def mix(self, bits: Sequence[int]) -> int:
        variables = dict(zip(self.symbols, bits, strict=True))
        value = _integer_expression(self.arithmetic, variables)
        return hashlib.sha256(str(value).encode("ascii")).digest()[0] & 1


@dataclass(frozen=True)
class StreamCipherInstance:
    model: StreamCombiner
    known_stream: bytes
    ciphertext: bytes


def _constants(tree: ast.Module) -> dict[str, int]:
    result = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, SyntaxError, TypeError):
            continue
        if type(value) is int:
            result[target.id] = value
    return result


def _registers(tree: ast.Module) -> tuple[int, dict[str, int]] | None:
    constants = _constants(tree)
    for cls in tree.body:
        if not isinstance(cls, ast.ClassDef):
            continue
        for method in cls.body:
            if not isinstance(method, ast.FunctionDef) or method.name != "__init__":
                continue
            regs: dict[str, int] = {}
            degrees: set[int] = set()
            for node in ast.walk(method):
                if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                    continue
                target, value = node.targets[0], node.value
                if not (isinstance(target, ast.Attribute)
                        and isinstance(value, ast.Call)
                        and isinstance(value.func, ast.Name)
                        and len(value.args) == 3
                        and isinstance(value.args[0], ast.Constant)
                        and isinstance(value.args[2], ast.Name)
                        and value.args[2].id in constants):
                    continue
                degrees.add(value.args[0].value)
                regs[target.attr] = constants[value.args[2].id]
            if len(regs) >= 2 and len(degrees) == 1:
                return degrees.pop(), regs
    return None


def _clock_calls(expr: ast.expr) -> tuple[str, int] | None:
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.BitXor):
        left = _clock_calls(expr.left)
        right = _clock_calls(expr.right)
        if left is not None and right is not None and left[0] == right[0]:
            return left[0], left[1] + right[1]
    if (isinstance(expr, ast.Call) and not expr.args
            and isinstance(expr.func, ast.Attribute)
            and isinstance(expr.func.value, ast.Name)
            and expr.func.value.id == "self"):
        return expr.func.attr, 1
    return None


def _hash_input(method: ast.FunctionDef) -> ast.expr | None:
    for node in ast.walk(method):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "sha256" and len(node.args) == 1):
            continue
        encoded = node.args[0]
        if not (isinstance(encoded, ast.Call)
                and isinstance(encoded.func, ast.Attribute)
                and encoded.func.attr == "encode"):
            continue
        stringify = encoded.func.value
        if (isinstance(stringify, ast.Call)
                and isinstance(stringify.func, ast.Name)
                and stringify.func.id == "str" and len(stringify.args) == 1):
            return stringify.args[0]
    return None


def _combiner_from_method(
    method: ast.FunctionDef, registers: dict[str, int],
    degree: int, path: str,
) -> StreamCombiner | None:
    expression = _hash_input(method)
    if expression is None:
        return None
    symbols: list[str] = []
    masks: list[int] = []
    clocks: list[int] = []
    for node in method.body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            continue
        calls = _clock_calls(node.value)
        if calls is None or calls[0] not in registers:
            continue
        symbols.append(node.targets[0].id)
        masks.append(registers[calls[0]])
        clocks.append(calls[1])
    if not 2 <= len(symbols) <= 6 or len(set(symbols)) != len(symbols):
        return None
    try:
        _integer_expression(expression, dict.fromkeys(symbols, 0))
        _integer_expression(expression, dict.fromkeys(symbols, 1))
    except ValueError:
        return None
    return StreamCombiner(degree, tuple(masks), tuple(clocks),
                          tuple(symbols), expression, path)


def parse_stream_combiner(source: str, path: str) -> StreamCombiner | None:
    """Inspect Python AST without importing or executing challenge code."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    data = _registers(tree)
    if data is None:
        return None
    degree, registers = data
    if not 8 <= degree <= 256:
        return None
    # Require a right-shift LFSR with parity feedback and one-bit output.
    if not any(
        isinstance(node, ast.Attribute) and node.attr == "bit_count"
        for node in ast.walk(tree)
    ):
        return None
    for cls in tree.body:
        if not isinstance(cls, ast.ClassDef):
            continue
        for method in cls.body:
            if isinstance(method, ast.FunctionDef) and method.name == "bit":
                result = _combiner_from_method(method, registers, degree, path)
                if result is not None:
                    return result
    return None


def _hex_pair(document: Document) -> tuple[bytes, bytes] | None:
    lines = [line.strip() for line in document.text.splitlines() if line.strip()]
    if len(lines) != 2 or not all(re.fullmatch(r"(?:[0-9a-fA-F]{2})+", line)
                                  for line in lines):
        return None
    if len(lines[0]) < 1024 or len(lines[1]) < 4:
        return None
    return bytes.fromhex(lines[0]), bytes.fromhex(lines[1])


def _known_zero_input(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    return any(isinstance(node, ast.Constant) and isinstance(node.value, bytes)
               and node.value == b"\0" for node in ast.walk(tree))


def recognize_stream_cipher(documents: Sequence[Document]) -> list[StreamCipherInstance]:
    """Pair a recognizable public stream cipher with same-scope hex output."""
    found = []
    for doc in documents:
        if not doc.path.lower().endswith(".py") or not _known_zero_input(doc.text):
            continue
        model = parse_stream_combiner(doc.text, doc.path)
        if model is None or len(model.masks) != 4:
            continue
        for output in documents:
            if output.scope != doc.scope or output.path == doc.path:
                continue
            pair = _hex_pair(output)
            if pair is None:
                continue
            known, encrypted = pair
            if len(known) * 8 >= 16 * model.degree:
                found.append(StreamCipherInstance(model, known, encrypted))
    return found


def unpack_bits(value: bytes) -> list[int]:
    return [byte >> shift & 1 for byte in value for shift in range(7, -1, -1)]


def pack_bits(bits: Sequence[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("Unaligned bitstream")
    return bytes(
        sum(bits[i + j] << (7 - j) for j in range(8))
        for i in range(0, len(bits), 8)
    )


def _affinities(model: StreamCombiner) -> list[tuple[float, int]]:
    size = len(model.masks)
    truth = [model.mix(row) for row in product((0, 1), repeat=size)]
    return [
        (sum(bit == (index >> (size - reg - 1) & 1)
             for index, bit in enumerate(truth)) / len(truth), reg)
        for reg in range(size)
    ]


def _linear_branch(
    model: StreamCombiner, recovered: dict[int, list[int]], index: int,
) -> tuple[list[int], int] | None:
    unknown = [i for i in range(len(model.masks)) if i not in recovered]
    if len(unknown) != 2:
        return None
    state = [recovered[i][index] if i in recovered else 0
             for i in range(len(model.masks))]
    outcomes = []
    for values in product((0, 1), repeat=2):
        inputs = state[:]
        for variable, bit in zip(unknown, values, strict=True):
            inputs[variable] = bit
        outcomes.append(model.mix(inputs))
    if outcomes[0] ^ outcomes[1] ^ outcomes[2] ^ outcomes[3]:
        return None
    if [outcomes[2] ^ outcomes[0], outcomes[1] ^ outcomes[0]] != [1, 1]:
        return None
    return unknown, outcomes[0]


def _solve_remaining_states(
    model: StreamCombiner, observed: list[int], recovered: dict[int, list[int]],
) -> dict[int, int]:
    unknown = [i for i in range(len(model.masks)) if i not in recovered]
    if len(unknown) != 2:
        raise ValueError("Exactly two additional registers required")
    degree = model.degree
    taps = {
        i: polynomial_remainders(model.masks[i], degree,
                                 len(observed) * model.clocks[i])
        for i in unknown
    }
    equations = []
    for index, bit in enumerate(observed):
        branch = _linear_branch(model, recovered, index)
        if branch is None:
            continue
        indices, constant = branch
        row = 0
        for shift, variable in enumerate(indices):
            clocks = model.clocks[variable]
            source = taps[variable]
            contribution = 0
            for offset in range(clocks):
                contribution ^= source[index * clocks + offset]
            row ^= contribution << (shift * degree)
        equations.append((row, bit ^ constant))
        if len(equations) >= degree * 5:
            break
    result = solve_gf2(equations, degree * 2)
    if result is None:
        raise RuntimeError("Insufficient independent affine combiner samples")
    return {unknown[0]: result & ((1 << degree) - 1),
            unknown[1]: result >> degree}


def _full_keystream(
    model: StreamCombiner, seeds: dict[int, int],
    length: int, effective: set[int],
) -> list[int]:
    streams = {}
    for index, seed in seeds.items():
        clocks = 1 if index in effective else model.clocks[index]
        bits = lfsr_bits(seed, model.masks[index], model.degree, length * clocks)
        if clocks > 1:
            bits = [
                sum(bits[position * clocks + offset] for offset in range(clocks)) & 1
                for position in range(length)
            ]
        streams[index] = bits
    return [
        model.mix([streams[i][position] for i in range(len(model.masks))])
        for position in range(length)
    ]


def recover_stream_cipher(
    instance: StreamCipherInstance, *,
    progress: Callable[[str], None] = print,
    max_iterations: int = 100,
) -> str:
    """Recover a flag only after exact full-keystream reconstruction."""
    model = instance.model
    observed = unpack_bits(instance.known_stream)
    if len(model.masks) != 4 or len(observed) < 16 * model.degree:
        raise ValueError("Unsupported short or non-four-register instance")
    candidates = []
    for probability, index in _affinities(model):
        if abs(probability - 0.5) < 0.05:
            continue
        multiples = low_weight_trinomials(
            model.masks[index], model.degree,
            maximum_degree=min(2048, len(observed) - 1),
        )
        if multiples:
            candidates.append((min(pair[0] for pair in multiples),
                               index, probability, multiples[0]))
    if len(candidates) < 2:
        raise RuntimeError("Not enough biased LFSR outputs with sparse feedback multiples")
    seeds: dict[int, int] = {}
    recovered: dict[int, list[int]] = {}
    for _, index, probability, triple in sorted(candidates)[:2]:
        correlation = correlation_recover(
            observed, model.masks[index], model.degree, probability, triple,
            max_iterations=max_iterations, progress=progress,
        )
        seeds[index] = correlation.initial_state
        recovered[index] = lfsr_bits(
            correlation.initial_state, model.masks[index],
            model.degree, len(observed),
        )
    seeds.update(_solve_remaining_states(model, observed, recovered))
    generated = _full_keystream(
        model, seeds, len(observed) + len(instance.ciphertext) * 8,
        set(recovered),
    )
    if generated[:len(observed)] != observed:
        raise RuntimeError("Recovered LFSRs do not reproduce full known keystream")
    secret_stream = pack_bits(generated[len(observed):])
    plaintext = bytes(a ^ b for a, b in
                      zip(instance.ciphertext, secret_stream, strict=True))
    if not FLAG.fullmatch(plaintext):
        raise RuntimeError("Full keystream verified, but plaintext is not flag-shaped")
    progress("[LFSR] All known keystream bits independently verified")
    return plaintext.decode("ascii")
