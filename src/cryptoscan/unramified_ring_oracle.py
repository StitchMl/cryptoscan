"""Source-gated oracle adapter for polynomial evaluation across unramified rings.

All extension parameters and polynomials come from the inspected source and
remote service. Requires an independently installed SageMath runtime.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .parser import Document


@dataclass(frozen=True)
class UnramifiedRingOracle:
    rounds: tuple[tuple[int, tuple[int, ...]], ...]


def _round_call(node: ast.stmt, function_name: str):
    if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == function_name
            and len(node.value.args) == 2):
        return None
    try:
        precision, degrees = (ast.literal_eval(arg) for arg in node.value.args)
    except (ValueError, TypeError, SyntaxError):
        return None
    if (type(precision) is not int or not 1 <= precision <= 128
            or not isinstance(degrees, list)
            or not 1 <= len(degrees) <= 6
            or not all(type(d) is int and 2 <= d <= 16 for d in degrees)):
        return None
    total = 1
    for degree in degrees:
        total *= degree
    return (precision, tuple(degrees)) if total <= 128 else None


def _literal_rounds(tree: ast.Module, function_name: str):
    rounds = [_round_call(node, function_name)
              for branch in tree.body if isinstance(branch, ast.If)
              for node in branch.body]
    return tuple(value for value in rounds if value is not None) or None


def _function_roles(functions):
    builders, evaluations = set(), set()
    for name, fn in functions.items():
        calls = [node for node in ast.walk(fn) if isinstance(node, ast.Call)]
        names = {node.func.id for node in calls if isinstance(node.func, ast.Name)}
        attrs = {node.func.attr for node in calls if isinstance(node.func, ast.Attribute)}
        if {"Zmod", "GF"} <= names and {"quo", "is_irreducible"} <= attrs:
            builders.add(name)
        if (any(isinstance(node, ast.Attribute) and node.attr == "parent"
                for node in ast.walk(fn))
                and any(isinstance(node, ast.keyword) and node.arg is not None
                        for node in ast.walk(fn))):
            evaluations.add(name)
    return builders, evaluations


def _connects_rings_to_oracle(fn, builders, evaluations) -> bool:
    calls = [node for node in ast.walk(fn) if isinstance(node, ast.Call)]
    names = {node.func.id for node in calls if isinstance(node.func, ast.Name)}
    identifiers = {node.id for node in ast.walk(fn) if isinstance(node, ast.Name)}
    has_random = any(isinstance(node, ast.Attribute) and node.attr == "randbelow"
                     for node in ast.walk(fn))
    return (bool(names & builders) and bool(names & evaluations)
            and "input" in names and "secrets" in identifiers and has_random)


def _has_algebraic_oracle(tree: ast.Module) -> bool:
    functions = {node.name: node for node in tree.body
                 if isinstance(node, ast.FunctionDef)}
    builders, evaluations = _function_roles(functions)
    return bool(builders and evaluations and any(
        _connects_rings_to_oracle(fn, builders, evaluations)
        for fn in functions.values()
    ))


def _source_rounds(document: Document):
    if not document.path.lower().endswith((".sage", ".py")):
        return None
    try:
        tree = ast.parse(document.text)
    except SyntaxError:
        return None
    if not _has_algebraic_oracle(tree):
        return None
    for fn in (node for node in tree.body if isinstance(node, ast.FunctionDef)):
        calls = {node.func.id for node in ast.walk(fn)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        if {"input", "print"} <= calls:
            rounds = _literal_rounds(tree, fn.name)
            if rounds:
                return rounds
    return None


def extract_instance(documents: Sequence[Document]) -> UnramifiedRingOracle | None:
    matches = [rounds for document in documents
               if (rounds := _source_rounds(document)) is not None]
    return UnramifiedRingOracle(matches[0]) if len(matches) == 1 else None


class _Socket:
    def __init__(self, connection: socket.socket):
        self.connection = connection
        self.buffer = bytearray()

    def until(self, token: bytes) -> bytes:
        while token not in self.buffer:
            block = self.connection.recv(65536)
            if not block:
                raise ConnectionError(
                    f"ring oracle closed before {token!r}; tail {bytes(self.buffer[-150:])!r}"
                )
            self.buffer.extend(block)
            if len(self.buffer) > 65536:
                raise ValueError("oversized ring-oracle banner")
        end = self.buffer.index(token) + len(token)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def line(self) -> str:
        return self.until(b"\n").decode("utf-8", "replace").strip()

    def send(self, line: str) -> None:
        self.connection.sendall(line.encode("ascii") + b"\n")


class _SageWorker:
    def __init__(self):
        executable = os.getenv("CRYPTOSCAN_SAGE") or shutil.which("sage")
        if not executable:
            raise RuntimeError(
                "This unramified-extension workflow requires SageMath. "
                "Run CryptoScan in a Sage-enabled Linux/WSL environment, "
                "or set CRYPTOSCAN_SAGE to its executable."
            )
        worker = Path(__file__).with_name("sage_ring_iso_worker.py")
        self.process = subprocess.Popen(
            [executable, "-python", str(worker)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", bufsize=1,
        )

    def ask(self, message: dict) -> dict:
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("Sage worker pipes unavailable")
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        response = self.process.stdout.readline()
        if not response:
            raise RuntimeError("Sage worker terminated before replying")
        try:
            result = json.loads(response)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Unexpected Sage worker output") from exc
        if "error" in result:
            raise RuntimeError("Sage ring mapping failed: " + str(result["error"]))
        return result

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()


def _integers(line: str, count: int) -> list[int]:
    fields = line.split(",")
    if len(fields) != count:
        raise ValueError(f"expected {count} ring coefficients, got {len(fields)}")
    try:
        return [int(field) for field in fields]
    except ValueError as exc:
        raise ValueError("non-integer ring coefficient") from exc


def _read_parameters(wire: _Socket, degrees: tuple[int, ...]):
    # Each layer's defining polynomial, the flat defining polynomial,
    # then the point coordinates and the input prompt.
    polynomials = [wire.line() for _ in range(len(degrees) + 1)]
    dimension = 1
    for degree in degrees:
        dimension *= degree
    point = _integers(wire.line(), dimension)
    wire.until(b"> ")
    return polynomials, point


def recover_flag(documents: Sequence[Document], host: str, port: int, *,
                 timeout: float = 600.0) -> str:
    model = extract_instance(documents)
    if model is None:
        raise ValueError("unsupported unramified ring evaluation source")
    worker = _SageWorker()
    collected = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            wire = _Socket(connection)
            for k, degrees in model.rounds:
                polynomials, point = _read_parameters(wire, degrees)
                first = worker.ask({"mode": "begin", "k": k, "degrees": degrees,
                                    "polynomials": polynomials, "point": point})
                wire.send(",".join(str(int(value)) for value in first["point"]))
                answer = _integers(wire.line(), len(point))
                second = worker.ask({"mode": "evaluate", "point": answer})
                collected.extend(second["coefficients"])
            final = wire.line().split()
    finally:
        worker.close()
    if len(final) != 2:
        raise RuntimeError("missing IV and ciphertext after ring challenges")
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    key = hashlib.sha256("||".join(map(str, collected)).encode()).digest()
    try:
        iv, ciphertext = map(bytes.fromhex, final)
        # This is decrypt-only compatibility with a remote legacy CBC format;\n        # no user-controlled data is encrypted or authenticated by CryptoScan.\n        plaintext = unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext),  # NOSONAR: legacy CBC decryption only\n                          AES.block_size)
    except ValueError as exc:
        raise RuntimeError("ring-derived AES key did not decrypt the ciphertext") from exc
    result = plaintext.decode("utf-8", errors="replace")
    if not re.fullmatch(r"\w{2,32}\{[^\r\n}]{1,180}\}", result):
        raise RuntimeError("decrypted data did not match flag-shaped plaintext")
    return result
