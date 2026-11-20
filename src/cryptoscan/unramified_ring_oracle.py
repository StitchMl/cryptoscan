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


def _literal_rounds(tree: ast.Module, function_name: str):
    rounds = []
    for statement in tree.body:
        if not isinstance(statement, ast.If):
            continue
        for item in statement.body:
            if not (isinstance(item, ast.Expr) and isinstance(item.value, ast.Call)
                    and isinstance(item.value.func, ast.Name)
                    and item.value.func.id == function_name
                    and len(item.value.args) == 2):
                continue
            try:
                k, degrees = (ast.literal_eval(arg) for arg in item.value.args)
            except (ValueError, TypeError, SyntaxError):
                continue
            if (type(k) is not int or not 1 <= k <= 128
                    or not isinstance(degrees, list)
                    or not 1 <= len(degrees) <= 6
                    or not all(type(d) is int and 2 <= d <= 16 for d in degrees)):
                return None
            total = 1
            for degree in degrees:
                total *= degree
            if total > 128:
                return None
            rounds.append((k, tuple(degrees)))
    return tuple(rounds) if rounds else None


def _has_algebraic_oracle(tree: ast.Module) -> bool:
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    builders = set()
    evaluations = set()
    for name, fn in functions.items():
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
        names = {n.func.id for n in calls if isinstance(n.func, ast.Name)}
        attrs = {n.func.attr for n in calls if isinstance(n.func, ast.Attribute)}
        if {"Zmod", "GF"} <= names and {"quo", "is_irreducible"} <= attrs:
            builders.add(name)
        if ("poly" in {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
                and any(isinstance(n, ast.Attribute) and n.attr == "parent"
                        for n in ast.walk(fn))):
            evaluations.add(name)
    if not builders or not evaluations:
        return False
    for fn in functions.values():
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
        names = {n.func.id for n in calls if isinstance(n.func, ast.Name)}
        identifiers = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        if (not names.intersection(builders) or "input" not in names
                or "secrets" not in identifiers
                or not any(isinstance(n, ast.Attribute) and n.attr == "randbelow"
                           for n in ast.walk(fn))):
            continue
        if names.intersection(evaluations):
            return True
    return False


def extract_instance(documents: Sequence[Document]) -> UnramifiedRingOracle | None:
    matches = []
    for document in documents:
        if not document.path.lower().endswith((".sage", ".py")):
            continue
        try:
            tree = ast.parse(document.text)
        except SyntaxError:
            continue
        if not _has_algebraic_oracle(tree):
            continue
        for fn in (n for n in tree.body if isinstance(n, ast.FunctionDef)):
            calls = {n.func.id for n in ast.walk(fn)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            if not {"input", "print"} <= calls:
                continue
            rounds = _literal_rounds(tree, fn.name)
            if rounds:
                matches.append(UnramifiedRingOracle(rounds))
    return matches[0] if len(matches) == 1 else None


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
        plaintext = unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext),
                          AES.block_size)
    except ValueError as exc:
        raise RuntimeError("ring-derived AES key did not decrypt the ciphertext") from exc
    result = plaintext.decode("utf-8", errors="replace")
    if not re.fullmatch(r"\w{2,32}\{[^\r\n}]{1,180}\}", result):
        raise RuntimeError("decrypted data did not match flag-shaped plaintext")
    return result
