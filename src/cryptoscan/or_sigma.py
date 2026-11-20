"""Reusable Schnorr OR-proof arithmetic and source-gated interactive workflow.

The challenge source is parsed as data, never imported or executed.
No CTF fixtures, parameters, witness values, or flags are embedded.
"""
from __future__ import annotations

import ast
import operator
import re
import secrets
import socket
from dataclasses import dataclass
from typing import Sequence

from .parser import Document


@dataclass(frozen=True)
class OrSchnorr:
    p: int
    q: int
    g: int
    publics: tuple[int, int]
    witness_branch: int
    witness: int


@dataclass(frozen=True)
class Transcript:
    commitments: tuple[int, int]
    challenges: tuple[int, int]
    responses: tuple[int, int]


_OPERATIONS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv,
    ast.Pow: operator.pow,
    ast.LShift: operator.lshift,
}
FIRST_TRANSCRIPT = "transcript 1:"
SECOND_TRANSCRIPT = "transcript 2:"


def _limited_operation(node: ast.BinOp, variables: dict[str, int]) -> int:
    left = _evaluate_constant(node.left, variables)
    right = _evaluate_constant(node.right, variables)
    if max(abs(left).bit_length(), abs(right).bit_length()) > 8192:
        raise ValueError("oversized expression")
    if isinstance(node.op, ast.Pow) and not 0 <= right <= 1024:
        raise ValueError("oversized exponent")
    if isinstance(node.op, ast.LShift) and not 0 <= right <= 8192:
        raise ValueError("oversized shift")
    result = _OPERATIONS[type(node.op)](left, right)
    if abs(result).bit_length() > 8192:
        raise ValueError("oversized expression")
    return result


def _evaluate_constant(expr: ast.expr, variables: dict[str, int]) -> int:
    if isinstance(expr, ast.Constant) and type(expr.value) is int:
        return expr.value
    if isinstance(expr, ast.Name) and expr.id in variables:
        return variables[expr.id]
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.USub):
        return -_evaluate_constant(expr.operand, variables)
    if isinstance(expr, ast.BinOp) and type(expr.op) in _OPERATIONS:
        return _limited_operation(expr, variables)
    raise ValueError("nonconstant expression")


def _simple_assignment(node: ast.stmt) -> tuple[str, ast.expr] | None:
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
        value = node.value
    elif isinstance(node, ast.AnnAssign):
        target = node.target
        value = node.value
    else:
        return None
    if isinstance(target, ast.Name) and value is not None:
        return target.id, value
    return None


def _constants(source: str) -> dict[str, int]:
    tree = ast.parse(source)
    values: dict[str, int] = {}
    for statement in tree.body:
        assignment = _simple_assignment(statement)
        if assignment is None:
            continue
        name, expression = assignment
        try:
            values[name] = _evaluate_constant(expression, values)
        except (ValueError, ArithmeticError):
            pass
    return values


def _verifier(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    comparisons = [node for node in ast.walk(tree)
                   if isinstance(node, ast.Compare) and len(node.ops) == 1
                   and isinstance(node.ops[0], ast.Eq)]
    has_xor = any(isinstance(part, ast.BinOp) and isinstance(part.op, ast.BitXor)
                  for compare in comparisons for part in (compare.left, *compare.comparators))
    checks = sum(sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                     and node.func.id == "pow" and len(node.args) == 3
                     for node in ast.walk(compare)) >= 2
                 for compare in comparisons)
    return has_xor and checks >= 2


def _merged_source_constants(sources: list[str]) -> dict[str, int] | None:
    merged: dict[str, int] = {}
    try:
        for source in sources:
            for key, value in _constants(source).items():
                if key in merged and merged[key] != value:
                    return None
                merged[key] = value
    except SyntaxError:
        return None
    return merged


def _valid_or_group(p: int, q: int, g: int,
                    publics: tuple[int, int]) -> bool:
    if not (7 < q < p and 1 < g < p and p.bit_length() <= 8192):
        return False
    if (p - 1) % q or pow(g, q, p) != 1:
        return False
    return all(1 <= y < p and pow(y, q, p) == 1 for y in publics)


def extract_instance(documents: Sequence[Document]) -> OrSchnorr | None:
    sources = [doc.text for doc in documents if doc.path.lower().endswith(".py")]
    if sum(_verifier(source) for source in sources) != 1:
        return None
    merged = _merged_source_constants(sources)
    if merged is None:
        return None
    try:
        p, q, g = (merged[name] for name in ("p", "q", "g"))
        publics = (merged["y0"], merged["y1"])
    except KeyError:
        return None
    if not _valid_or_group(p, q, g, publics):
        return None
    for branch in (0, 1):
        witness = merged.get(f"w{branch}")
        if type(witness) is int and witness >= 0 and pow(g, witness, p) == publics[branch]:
            return OrSchnorr(p, q, g, publics, branch, witness)
    return None


def verify(p: int, g: int, publics: tuple[int, int], transcript: Transcript,
           challenge: int) -> bool:
    a, e, z = transcript.commitments, transcript.challenges, transcript.responses
    return e[0] ^ e[1] == challenge and all(
        pow(g, z[i], p) == a[i] * pow(publics[i], e[i], p) % p for i in (0, 1))


def simulate(p: int, q: int, g: int, publics: tuple[int, int],
             challenge: int, bits: int) -> Transcript:
    if not 1 <= bits <= 4096 or not 0 <= challenge < (1 << bits):
        raise ValueError("challenge outside declared space")
    e0 = secrets.randbelow(1 << bits)
    e = (e0, e0 ^ challenge)
    z = (secrets.randbelow(q), secrets.randbelow(q))
    a = tuple(pow(g, zi, p) * pow(pow(yi, ei, p), -1, p) % p
              for yi, ei, zi in zip(publics, e, z, strict=True))
    return Transcript(a, e, z)


def first_round(instance: OrSchnorr, bits: int) -> tuple[Transcript, int]:
    real = instance.witness_branch
    fake = 1 - real
    r = secrets.randbelow(instance.q)
    e, z, a = [0, 0], [0, 0], [0, 0]
    e[fake] = secrets.randbelow(1 << bits)
    z[fake] = secrets.randbelow(instance.q)
    a[real] = pow(instance.g, r, instance.p)
    a[fake] = (pow(instance.g, z[fake], instance.p)
               * pow(pow(instance.publics[fake], e[fake], instance.p),
                     -1, instance.p)) % instance.p
    return Transcript(tuple(a), tuple(e), tuple(z)), r


def respond(instance: OrSchnorr, first: Transcript, randomizer: int,
            challenge: int) -> Transcript:
    real, fake = instance.witness_branch, 1 - instance.witness_branch
    e, z = list(first.challenges), list(first.responses)
    e[real] = challenge ^ e[fake]
    z[real] = (randomizer + e[real] * instance.witness) % instance.q
    proof = Transcript(first.commitments, tuple(e), tuple(z))
    if not verify(instance.p, instance.g, instance.publics, proof, challenge):
        raise RuntimeError("locally constructed proof failed verification")
    return proof


def extract_witness(p: int, q: int, g: int, publics: tuple[int, int],
                    challenge1: int, t1: Transcript,
                    challenge2: int, t2: Transcript) -> int:
    if t1.commitments != t2.commitments or challenge1 == challenge2:
        raise ValueError("rewound proofs need same commitments and distinct challenges")
    if not verify(p, g, publics, t1, challenge1) or not verify(p, g, publics, t2, challenge2):
        raise ValueError("invalid rewound proof")
    for branch in (0, 1):
        delta = (t2.challenges[branch] - t1.challenges[branch]) % q
        if not delta:
            continue
        try:
            witness = ((t2.responses[branch] - t1.responses[branch])
                       * pow(delta, -1, q)) % q
        except ValueError:
            continue
        if pow(g, witness, p) == publics[branch]:
            return witness
    raise ValueError("no extractable witness")


class _Dialogue:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = bytearray()

    def read_to(self, marker: bytes) -> str:
        while marker not in self.buffer:
            data = self.sock.recv(4096)
            if not data:
                raise ConnectionError("server closed before prompt " + repr(marker))
            self.buffer.extend(data)
            if len(self.buffer) > 262144:
                raise ValueError("oversized server response")
        end = self.buffer.index(marker) + len(marker)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result.decode("utf-8", "replace")

    def send(self, value: int) -> None:
        self.sock.sendall(f"{value}\n".encode("ascii"))


def _transcript(section: str, starred: bool) -> Transcript:
    values = {}
    for field in ("a0", "a1", "e0", "e1", "z0", "z1"):
        label = field + ("*" if starred and field[0] != "a" else "")
        found = re.findall(r"(?m)^\s*" + re.escape(label) + r"\s*=\s*(\d+)\s*$", section)
        if len(found) != 1:
            raise ValueError("missing or ambiguous field " + label)
        values[field] = int(found[0])
    return Transcript((values["a0"], values["a1"]),
                      (values["e0"], values["e1"]), (values["z0"], values["z1"]))


def _publics(section: str) -> tuple[int, int]:
    pairs = re.findall(r"(?m)^\s*y([01])\s*=\s*(\d+)\s*$", section)
    if len(pairs) != 2:
        raise ValueError("missing or ambiguous public values")
    mapping = {int(index): int(value) for index, value in pairs}
    return mapping[0], mapping[1]


def _challenge_bits(source: str) -> int:
    required = ("Special Soundness!", FIRST_TRANSCRIPT, SECOND_TRANSCRIPT,
                "give me a witness!", "give me satisfying transcript")
    if not all(fragment in source for fragment in required):
        raise ValueError("unsupported interactive protocol")
    widths = [int(number) for number in
              re.findall(r"2\s*\*\*\s*(\d+)\s*-\s*1", source)]
    if not widths or len(set(widths)) != 1 or not 1 <= widths[0] <= 4096:
        raise ValueError("unsupported challenge domain")
    return widths[0]


def _send_sequence(wire: _Dialogue, exchanges: Sequence[tuple[bytes, int]]) -> None:
    for prompt, value in exchanges:
        wire.read_to(prompt)
        wire.send(value)


def _correctness_phase(wire: _Dialogue, instance: OrSchnorr, bits: int) -> None:
    wire.read_to(b"a0:")
    first, randomizer = first_round(instance, bits)
    wire.send(first.commitments[0])
    wire.read_to(b"a1:")
    wire.send(first.commitments[1])
    message = wire.read_to(b"e0:")
    match = re.search(r"verifier sends s\s*=\s*(\d+)", message)
    if match is None:
        raise ValueError("missing initial challenge")
    proof = respond(instance, first, randomizer, int(match.group(1)))
    wire.send(proof.challenges[0])
    _send_sequence(wire, (
        (b"e1:", proof.challenges[1]),
        (b"z0:", proof.responses[0]),
        (b"z1:", proof.responses[1]),
    ))


def _rewind_fields(segment: str):
    if FIRST_TRANSCRIPT not in segment or SECOND_TRANSCRIPT not in segment:
        raise ValueError("missing rewound transcripts")
    pre, rest = segment.split(FIRST_TRANSCRIPT, 1)
    left, right = rest.split(SECOND_TRANSCRIPT, 1)
    c1 = re.search(r"(?m)^\s*s\s*=\s*(\d+)\s*$", left)
    c2 = re.search(r"(?m)^\s*s\*\s*=\s*(\d+)\s*$", right)
    if c1 is None or c2 is None:
        raise ValueError("missing rewind challenges")
    return (_publics(pre), int(c1.group(1)), _transcript(left, False),
            int(c2.group(1)), _transcript(right, True))


def _soundness_phase(wire: _Dialogue, instance: OrSchnorr) -> None:
    segment = wire.read_to(b"give me a witness!")
    publics, challenge1, transcript1, challenge2, transcript2 = _rewind_fields(segment)
    witness = extract_witness(instance.p, instance.q, instance.g, publics,
                              challenge1, transcript1, challenge2, transcript2)
    wire.send(witness)


def _simulator_phase(wire: _Dialogue, instance: OrSchnorr, bits: int) -> None:
    segment = wire.read_to(b"a0:")
    match = re.search(r"give me satisfying transcript for s\s*=\s*(\d+)", segment)
    if match is None:
        raise ValueError("missing simulator challenge")
    publics = _publics(segment)
    challenge = int(match.group(1))
    proof = simulate(instance.p, instance.q, instance.g, publics, challenge, bits)
    if not verify(instance.p, instance.g, publics, proof, challenge):
        raise RuntimeError("invalid locally simulated transcript")
    wire.send(proof.commitments[0])
    _send_sequence(wire, (
        (b"a1:", proof.commitments[1]),
        (b"e0:", proof.challenges[0]),
        (b"e1:", proof.challenges[1]),
        (b"z0:", proof.responses[0]),
        (b"z1:", proof.responses[1]),
    ))


def _final_server_response(wire: _Dialogue, sock: socket.socket) -> str:
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
            raise ValueError("oversized final response")
    return result.decode("utf-8", "replace")


def recover_flag(documents: Sequence[Document], host: str, port: int, *,
                 timeout: float = 30.0) -> str:
    """Network adapter only for a source-confirmed three-stage wire profile."""
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("unsupported source model")
    source = "\n".join(d.text for d in documents if d.path.lower().endswith(".py"))
    bits = _challenge_bits(source)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        wire = _Dialogue(sock)
        _correctness_phase(wire, instance, bits)
        _soundness_phase(wire, instance)
        _simulator_phase(wire, instance, bits)
        response = _final_server_response(wire, sock)
    if "well done!" not in response:
        raise RuntimeError("verifier did not complete: " + response[-300:])
    flag = re.search(r"(\w{2,32}\{[^\r\n}]{1,180}\})", response)
    if flag is None:
        raise RuntimeError("protocol completed without flag-shaped response")
    return flag.group(1)
