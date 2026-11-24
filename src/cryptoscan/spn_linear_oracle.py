"""Chosen-plaintext recovery for linear/S-box/linear byte permutations.

Input sources are parsed as AST, never executed. The decoder learns the actual
permutation through a single multi-block oracle query. No challenge constants,
secrets, fixtures or known plaintext/ciphertext pairs are included.
"""
from __future__ import annotations

import ast
import random
import re
import secrets
import socket
from dataclasses import dataclass
from typing import Sequence

from .network_policy import connect_authorized
from .parser import Document
from .source_units import parse_python


@dataclass(frozen=True)
class LinearSPN:
    block_bytes: int
    rounds: int
    message_bytes: int
    first_prompt: str
    guess_prompt: str


def _call_names(node: ast.AST) -> list[tuple[int, str]]:
    return sorted((call.lineno, call.func.id) for call in ast.walk(node)
                  if isinstance(call, ast.Call) and isinstance(call.func, ast.Name))


def _call_attribute(node: ast.AST, method: str) -> bool:
    return any(isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
               and call.func.attr == method for call in ast.walk(node))


def _simple_assignment_name(statement: ast.stmt) -> str | None:
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return None
    target = statement.targets[0]
    return target.id if isinstance(target, ast.Name) else None


def _byte_permutation(value: ast.expr) -> bool:
    if not isinstance(value, (ast.List, ast.Tuple)):
        return False
    elements = value.elts
    return (len(elements) == 256 and all(isinstance(e, ast.Constant)
            and type(e.value) is int for e in elements)
            and {e.value for e in elements} == set(range(256)))


def _constant_values(tree: ast.Module) -> tuple[dict[str, int], set[str]]:
    integers = {}
    tables = set()
    for statement in tree.body:
        name = _simple_assignment_name(statement)
        if name is None:
            continue
        value = statement.value
        if isinstance(value, ast.Constant) and type(value.value) is int:
            integers[name] = value.value
        if _byte_permutation(value):
            tables.add(name)
    return integers, tables


def _classify_transformations(funcs, tables: set[str]):
    xor = {name for name, fn in funcs.items()
           if any(isinstance(n, ast.BitXor) for n in ast.walk(fn))}
    rotates = {name for name, fn in funcs.items()
               if all(any(isinstance(n, operation) for n in ast.walk(fn))
                      for operation in (ast.RShift, ast.LShift, ast.BitOr))}
    mixes = set()
    substitutions = set()
    for name, fn in funcs.items():
        calls = {called for _, called in _call_names(fn)}
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        if (_call_attribute(fn, 'seed') and _call_attribute(fn, 'randint')
                and calls & xor and calls & rotates):
            mixes.add(name)
        if (names & tables and any(isinstance(n, ast.Mod) for n in ast.walk(fn))
                and any(isinstance(n, ast.Constant) and n.value == 256
                        for n in ast.walk(fn))):
            substitutions.add(name)
    return mixes, substitutions


def _has_spn_sandwich(fn, mixes, substitutions) -> bool:
    if not any(name == 'pad' for _, name in _call_names(fn)):
        return False
    calls = [name for _, name in _call_names(fn)
             if name in mixes or name in substitutions]
    return (len(calls) == 3 and calls[0] == calls[2] in mixes
            and calls[1] in substitutions and _independent_blocks(fn))


def _algebraic_functions(tree: ast.Module, tables: set[str]) -> bool:
    funcs = {fn.name: fn for fn in tree.body if isinstance(fn, ast.FunctionDef)}
    mixes, substitutions = _classify_transformations(funcs, tables)
    return bool(mixes and substitutions and any(
        _has_spn_sandwich(fn, mixes, substitutions) for fn in funcs.values()
    ))


def _independent_blocks(fn: ast.FunctionDef) -> bool:
    # Require key derivation inside the block loop from the original key
    # argument, rather than a chaining variable from earlier blocks.
    key_names = {a.arg for a in fn.args.args[1:]}
    for loop in (n for n in ast.walk(fn) if isinstance(n, ast.For)):
        for stmt in loop.body:
            if not isinstance(stmt, ast.Assign):
                continue
            value = stmt.value
            if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                    and any(isinstance(arg, ast.Name) and arg.id in key_names
                            for arg in value.args)):
                return True
    return False


def _message_bytes(node: ast.AST, constants: dict[str, int]) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub)
            and isinstance(node.left, ast.Name)
            and isinstance(node.right, ast.Constant)
            and type(node.right.value) is int):
        return constants.get(node.left.id, 0) - node.right.value
    return None


def _interactive_challenge(tree: ast.Module, constants: dict[str, int]):
    first = None
    for node in tree.body:
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == 'input' and node.value.args
                and isinstance(node.value.args[0], ast.Constant)
                and isinstance(node.value.args[0].value, str)):
            first = node.value.args[0].value
        if not isinstance(node, ast.For) or first is None:
            continue
        iterator = node.iter
        if not (isinstance(iterator, ast.Call) and isinstance(iterator.func, ast.Name)
                and iterator.func.id == 'range' and len(iterator.args) == 1
                and isinstance(iterator.args[0], ast.Constant)
                and type(iterator.args[0].value) is int):
            continue
        calls = [c for c in ast.walk(node) if isinstance(c, ast.Call)]
        guesses = [c.args[0].value for c in calls
                   if isinstance(c.func, ast.Name) and c.func.id == 'input'
                   and c.args and isinstance(c.args[0], ast.Constant)
                   and isinstance(c.args[0].value, str)]
        message_lengths = [_message_bytes(c.args[0], constants) for c in calls
                           if isinstance(c.func, ast.Attribute)
                           and c.func.attr == 'urandom' and len(c.args) == 1]
        if len(guesses) == 1 and len(message_lengths) == 1:
            return iterator.args[0].value, message_lengths[0], first, guesses[0]
    return None


def _padded_block_size(tree: ast.Module, constants: dict[str, int]) -> int | None:
    lengths = {constants[arg.id] for node in ast.walk(tree)
               if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id == 'pad' and len(node.args) >= 2
               for arg in (node.args[1],)
               if isinstance(arg, ast.Name) and arg.id in constants}
    return next(iter(lengths)) if len(lengths) == 1 else None


def _source_candidate(doc: Document) -> LinearSPN | None:
    tree = parse_python(doc)
    if tree is None:
        return None
    constants, tables = _constant_values(tree)
    if not tables or not _algebraic_functions(tree, tables):
        return None
    protocol = _interactive_challenge(tree, constants)
    if protocol is None:
        return None
    rounds, message_bytes, first_prompt, guess_prompt = protocol
    block_bytes = _padded_block_size(tree, constants)
    if (block_bytes != 16 or not isinstance(message_bytes, int)
            or not 1 <= rounds <= 4096 or not 1 <= message_bytes < block_bytes
            or not first_prompt or not guess_prompt):
        return None
    return LinearSPN(block_bytes, rounds, message_bytes, first_prompt, guess_prompt)


def extract_instance(documents: Sequence[Document]) -> LinearSPN | None:
    found = [model for doc in documents if (model := _source_candidate(doc)) is not None]
    return found[0] if len(found) == 1 else None


def _basis(values):
    pivots = {}
    for item in values:
        value = item
        while value:
            pivot = value.bit_length() - 1
            if pivot in pivots:
                value ^= pivots[pivot]
            else:
                pivots[pivot] = value
                break
    return pivots


def _orthogonal(basis, bits: int) -> tuple[int, ...]:
    result = []
    for free in range(bits):
        if free in basis:
            continue
        vector = 1 << free
        for pivot in sorted(basis):
            if (vector & basis[pivot]).bit_count() & 1:
                vector ^= 1 << pivot
        result.append(vector)
    return tuple(result)


def _canonical(vectors) -> tuple[int, ...]:
    basis = _basis(vectors)
    for low in sorted(basis):
        for high in basis:
            if high > low and (basis[high] >> low) & 1:
                basis[high] ^= basis[low]
    return tuple(basis[key] for key in sorted(basis))


def _project(masks: Sequence[int], vector: int) -> int:
    return sum(((vector & mask).bit_count() & 1) << i
               for i, mask in enumerate(masks))


def _derivative_groups(oracle: Sequence[int], slots: int, bits_per_slot: int):
    rng = random.Random(0x41C713)
    count = len(oracle)
    expected = slots * bits_per_slot - bits_per_slot
    samples = rng.sample(range(count), min(count, slots * bits_per_slot + 64))
    candidates = rng.sample(range(1, count), min(count - 1, max(1500, slots * 900)))
    groups: dict[tuple[int, ...], list[int]] = {}
    for direction in candidates:
        span = _basis(oracle[x] ^ oracle[x ^ direction] for x in samples)
        if len(span) != expected:
            continue
        dual = _orthogonal(span, slots * bits_per_slot)
        if len(dual) == bits_per_slot:
            groups.setdefault(_canonical(dual), []).append(direction)
    return groups


def _component_table(oracle, output_forms, input_forms, bits_per_slot: int):
    inverse = [None] * (1 << bits_per_slot)
    for index, ciphertext in enumerate(oracle):
        image = _project(output_forms, ciphertext ^ oracle[0])
        preimage = _project(input_forms, index)
        if inverse[image] is None:
            inverse[image] = preimage
        elif inverse[image] != preimage:
            raise ValueError('nonseparable nonlinear substitution')
    if set(inverse) != set(range(1 << bits_per_slot)):
        raise ValueError('nonbijective local substitution')
    return tuple(inverse)


def _component(oracle, output_forms, directions, dimension, bits_per_slot):
    kernel = _basis(directions)
    if len(kernel) != dimension - bits_per_slot:
        raise ValueError('insufficient input-kernel rank')
    input_forms = _orthogonal(kernel, dimension)
    if len(input_forms) != bits_per_slot:
        raise ValueError('invalid input quotient dimension')
    return output_forms, _component_table(oracle, output_forms, input_forms, bits_per_slot)


def _recover_components(oracle: Sequence[int], *, slots: int = 16,
                        bits_per_slot: int = 8, dimension: int = 13):
    groups = _derivative_groups(oracle, slots, bits_per_slot)
    if len(groups) != slots:
        raise ValueError(f'derivative decomposition found {len(groups)} of {slots} byte spaces')
    components = [
        _component(oracle, forms, directions, dimension, bits_per_slot)
        for forms, directions in groups.items()
    ]
    if len(_basis(mask for forms, _ in components for mask in forms)) != slots * bits_per_slot:
        raise ValueError('dependent recovered output projections')
    return components


def _local_coordinates(ciphertext: int, origin: int, components) -> int:
    result = 0
    for index, (output_forms, inverse) in enumerate(components):
        result |= inverse[_project(output_forms, ciphertext ^ origin)] << (8 * index)
    return result


def _invert_linear_columns(columns: Sequence[int]):
    if len(_basis(columns)) != len(columns):
        raise ValueError('recovered linear input transform is singular')
    pivots = {}
    origins = {}
    for index, column in enumerate(columns):
        vector = column
        original = 1 << index
        while vector:
            pivot = vector.bit_length() - 1
            if pivot not in pivots:
                pivots[pivot] = vector
                origins[pivot] = original
                break
            vector ^= pivots[pivot]
            original ^= origins[pivot]

    def invert(coordinate: int) -> int:
        plaintext = 0
        while coordinate:
            pivot = coordinate.bit_length() - 1
            if pivot not in pivots:
                raise ValueError('ciphertext outside reconstructed permutation')
            coordinate ^= pivots[pivot]
            plaintext ^= origins[pivot]
        return plaintext

    return invert


def recover_permutation(oracle: Sequence[int], basis_outputs: Sequence[int],
                        verification: Sequence[tuple[int, int]]):
    """Build a validated cipher-to-plaintext decoder from a 2^13 affine oracle."""
    if len(oracle) != 1 << 13 or len(basis_outputs) != 128:
        raise ValueError('incorrect chosen-plaintext oracle dimensions')
    components = _recover_components(oracle)
    columns = [_local_coordinates(cipher, oracle[0], components)
               for cipher in basis_outputs]
    invert = _invert_linear_columns(columns)

    def decrypt(ciphertext: int) -> int:
        coordinates = _local_coordinates(ciphertext, oracle[0], components)
        return invert(coordinates)

    if not verification or any(decrypt(cipher) != plain for plain, cipher in verification):
        raise ValueError('independent known-plaintext verification failed')
    return decrypt


def _subspace(rng: random.Random, dimension: int = 13) -> list[int]:
    result = []
    while len(result) < dimension:
        candidate = rng.getrandbits(128)
        if len(_basis((*result, candidate))) == len(result) + 1:
            result.append(candidate)
    vectors = [0] * (1 << dimension)
    for index in range(1, len(vectors)):
        bit = index & -index
        vectors[index] = vectors[index ^ bit] ^ result[bit.bit_length() - 1]
    return vectors


def _probes():
    rng = random.Random(secrets.randbits(64))
    subsets = tuple(_subspace(rng) for _ in range(3))
    verification = tuple(rng.getrandbits(128) for _ in range(24))
    plaintext = (*subsets[0], *subsets[1], *subsets[2],
                 *(1 << bit for bit in range(128)), *verification)
    return plaintext, verification


class _Dialogue:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = bytearray()
        self.stage = 'waiting for initial prompt'

    def until(self, marker: str, limit: int = 8192) -> str:
        needle = marker.encode()
        while needle not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                preview = bytes(self.buffer[-160:]).decode('utf-8', 'replace')
                raise ConnectionError(
                    f'service closed during {self.stage}; expected {marker!r}; '
                    f'buffered output suffix={preview!r}'
                )
            self.buffer.extend(chunk)
            if len(self.buffer) > limit:
                raise ValueError('unbounded service response')
        end = self.buffer.index(needle) + len(needle)
        message = bytes(self.buffer[:end]).decode('utf-8', 'replace')
        del self.buffer[:end]
        return message

    def line(self, limit: int = 8192) -> str:
        return self.until('\n', limit).strip()

    def send(self, value: bytes) -> None:
        self.sock.sendall(value + b'\n')


def _oracle_ciphertexts(wire: _Dialogue, total: int, block_bytes: int) -> list[int]:
    line = wire.line(limit=(total + 1) * block_bytes * 2 + 4096)
    try:
        data = bytes.fromhex(line)
    except ValueError as exc:
        raise RuntimeError('first encryption response is not hex') from exc
    if len(data) != (total + 1) * block_bytes:
        raise RuntimeError(f'expected {total+1} encrypted blocks, received {len(data)//block_bytes}')
    return [int.from_bytes(data[i:i + block_bytes], 'big')
            for i in range(0, total * block_bytes, block_bytes)]


def _challenge_ciphertext(wire: _Dialogue, block_bytes: int) -> int:
    for _ in range(3):
        line = wire.line()
        if re.fullmatch(r'[0-9a-fA-F]{' + str(2 * block_bytes) + r'}', line):
            return int(line, 16)
        if 'Wrong!' in line:
            raise RuntimeError('service rejected a recovered plaintext')
    raise RuntimeError('expected encrypted challenge block')


def _prepare_decoder(ciphertexts: Sequence[int], verification_plain: Sequence[int]):
    subspace_size = 1 << 13
    offset = 3 * subspace_size
    basis = ciphertexts[offset:offset + 128]
    verification_cipher = ciphertexts[offset + 128:]
    checks = list(zip(verification_plain, verification_cipher, strict=True))
    for attempt in range(3):
        subspace = ciphertexts[attempt * subspace_size:(attempt + 1) * subspace_size]
        try:
            return recover_permutation(subspace, basis, checks)
        except ValueError:
            continue
    raise RuntimeError('three independent chosen-input spaces failed decomposition')


def recover_flag(documents: Sequence[Document], host: str, port: int, *,
                 timeout: float = 300.0) -> str:
    model = extract_instance(documents)
    if model is None:
        raise ValueError('unsupported seeded-linear/substitution/linear source model')
    plaintexts, verification = _probes()
    chosen = b''.join(value.to_bytes(model.block_bytes, 'big') for value in plaintexts)
    with connect_authorized(host, port, timeout) as sock:
        sock.settimeout(timeout)
        wire = _Dialogue(sock)
        wire.until(model.first_prompt)
        wire.stage = 'sending chosen plaintext'
        wire.send(chosen.hex().encode('ascii'))
        wire.stage = 'waiting for bulk encryption response'
        cipher = _oracle_ciphertexts(wire, len(plaintexts), model.block_bytes)
        decoder = _prepare_decoder(cipher, verification)
        for round_index in range(model.rounds):
            wire.stage = f'challenge round {round_index + 1} of {model.rounds}'
            encrypted = _challenge_ciphertext(wire, model.block_bytes)
            wire.until(model.guess_prompt)
            decoded = decoder(encrypted).to_bytes(model.block_bytes, 'big')
            # The service encrypts a fixed-size message padded by PKCS#7.
            pad_length = model.block_bytes - model.message_bytes
            if decoded[-pad_length:] != bytes([pad_length]) * pad_length:
                raise RuntimeError('recovered message failed PKCS#7 validation')
            wire.send(decoded[:model.message_bytes].hex().encode('ascii'))
        wire.stage = 'waiting for final verification result'
        final = wire.line()
        match = re.search(r'(\w{2,32}\{[^\r\n}]{1,180}\})', final)
        if not match:
            raise RuntimeError('protocol completed without a flag-shaped response')
        return match.group(1)
