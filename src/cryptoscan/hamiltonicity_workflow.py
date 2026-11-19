"""AST-grounded identification of grindable Fiat-Shamir graph proofs.

The underlying grinding and Pedersen operations are generic and implemented
in fiat_shamir_grinding.py. This module only extracts a supported instance
and adapts an explicitly authorized TCP service protocol.
"""
from __future__ import annotations

import ast
import json
import re
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .fiat_shamir_grinding import (
    grind_pedersen_graph_opening,
    verify_pedersen_graph_opening,
)
from .network_policy import connect_authorized
from .parser import Document


@dataclass(frozen=True)
class HamiltonicityInstance:
    source_path: str
    graph: list[list[int]]
    pedersen_params: tuple[int, int, int, int]
    rounds: int
    prompt: bytes


def _literal_module_values(tree: ast.Module) -> dict[str, object]:
    """Interpret top-level literal assignments, not arbitrary challenge code."""
    values: dict[str, object] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        if not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        try:
            values[name] = ast.literal_eval(node.value)
        except (TypeError, SyntaxError, ValueError, MemoryError):
            pass
    return values


def _graph_from_source(tree: ast.Module) -> list[list[int]] | None:
    values = _literal_module_values(tree)
    if isinstance(values.get("G"), list):
        return values["G"]
    # Respect a literal Boolean configuration selecting one graph definition.
    for node in tree.body:
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Name):
            continue
        condition = values.get(node.test.id)
        if type(condition) is not bool:
            continue
        branch = node.body if condition else node.orelse
        for statement in branch:
            if (isinstance(statement, ast.Assign)
                    and len(statement.targets) == 1
                    and isinstance(statement.targets[0], ast.Name)
                    and statement.targets[0].id == "G"):
                try:
                    graph = ast.literal_eval(statement.value)
                except (SyntaxError, ValueError, TypeError):
                    return None
                return graph if isinstance(graph, list) else None
    return None


def _pedersen_parameters(documents: Sequence[Document]) -> tuple[int, int, int, int] | None:
    for doc in documents:
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        values = _literal_module_values(tree)
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            if not isinstance(node.targets[0], ast.Name) or node.targets[0].id != "comm_params":
                continue
            if not isinstance(node.value, (ast.Tuple, ast.List)):
                continue
            elements = []
            for element in node.value.elts:
                if isinstance(element, ast.Name):
                    elements.append(values.get(element.id))
                else:
                    try:
                        elements.append(ast.literal_eval(element))
                    except (SyntaxError, ValueError, TypeError):
                        break
            if len(elements) == 4 and all(type(x) is int and x > 0 for x in elements):
                return tuple(elements)
    return None


def _hash_function_names(documents: Sequence[Document]) -> set[str]:
    names: set[str] = set()
    for doc in documents:
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        for func in tree.body:
            if not isinstance(func, ast.FunctionDef):
                continue
            text = ast.unparse(func)
            # Verify that the state is fed into SHA256 and the graph is
            # hashed in matrix order. Without this structure, guessing the
            # challenge bit from the commitments would be unjustified.
            if (("sha256(" in text
                    and ".update(state)" in text
                    and "digest()" in text
                    and "str(x)" in text
                    and "for xs in G" in text)
                    or ("sha256(" in text
                        and ".update(state)" in text
                        and "digest()" in text
                        and "str(x)" in text
                        and "for row in G" in text)):
                names.add(func.name)
    return names


def _fs_challenge_names(tree: ast.Module, hash_functions: set[str]) -> set[str]:
    """Find one-bit challenge assignments derived from the hash state.

    Identifier names are irrelevant: trace the hash call's assigned state
    into its low-bit extraction, then into the verifier's branch condition.
    """
    state_names: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id in hash_functions):
            state_names.add(node.targets[0].id)
    result: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.BinOp)
                and isinstance(node.value.op, ast.BitAnd)
                and isinstance(node.value.left, ast.Subscript)
                and isinstance(node.value.left.value, ast.Name)
                and node.value.left.value.id in state_names
                and isinstance(node.value.right, ast.Constant)
                and node.value.right.value == 1):
            continue
        sub = node.value.left.slice
        if (isinstance(sub, ast.UnaryOp) and isinstance(sub.op, ast.USub)
                and isinstance(sub.operand, ast.Constant)
                and sub.operand.value == 1):
            result.add(node.targets[0].id)
    return result


def extract_instance(documents: Sequence[Document]) -> HamiltonicityInstance | None:
    for doc in documents:
        if not doc.path.casefold().endswith(".py"):
            continue
        # Never combine a prover from one challenge with group parameters
        # or a hash recipe from an unrelated directory/archive.
        scoped = [candidate for candidate in documents
                  if candidate.scope == doc.scope]
        params = _pedersen_parameters(scoped)
        hash_functions = _hash_function_names(scoped)
        if params is None or not hash_functions:
            continue
        p, q, h1, h2 = params
        if p <= q or min(h1, h2) <= 0 or max(h1, h2) >= p:
            continue
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        src = ast.unparse(tree)
        # Detect the challenge by following data flow from a SHA-256 graph
        # hash into the extracted low bit, not by its Python identifier.
        challenge_vars = _fs_challenge_names(tree, hash_functions)
        if not (challenge_vars and "testcycle(" in src
                and "open_graph(" in src and "permute_graph(" in src):
            continue
        # The unblinded branch must actually be an acceptance path.
        branch_verified = any(
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id in challenge_vars
            and any(isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "open_graph"
                    for child in node.orelse
                    for call in ast.walk(child))
            for node in ast.walk(tree)
        )
        if not branch_verified:
            continue
        values = _literal_module_values(tree)
        rounds = values.get("numrounds")
        graph = _graph_from_source(tree)
        if type(rounds) is not int or not (1 <= rounds <= 4096):
            continue
        if (not isinstance(graph, list) or not graph
                or not all(isinstance(row, list) and len(row) == len(graph) for row in graph)
                or any(type(v) is not int or v not in (0, 1) for row in graph for v in row)):
            continue
        prompts = [
            argument.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "input"
            for argument in node.args
            if isinstance(argument, ast.Constant) and isinstance(argument.value, (bytes, str))
        ]
        chosen = next((item for item in prompts if b"proof" in
                       (item if isinstance(item, bytes) else item.encode()).lower()), None)
        if chosen is None:
            continue
        prompt = chosen if isinstance(chosen, bytes) else chosen.encode()
        if not prompt or len(prompt) > 128:
            continue
        return HamiltonicityInstance(doc.path, graph, params, rounds, prompt)
    return None


class _Connection:
    def __init__(self, host: str, port: int, timeout: float):
        self.sock = connect_authorized(host, port, timeout)
        self.sock.settimeout(timeout)
        self.buffer = b""

    def until(self, marker: bytes) -> bytes:
        while marker not in self.buffer:
            block = self.sock.recv(8192)
            if not block:
                raise ConnectionError("Server ended session before expected response")
            self.buffer += block
            if len(self.buffer) > 400_000:
                raise ValueError("Unexpectedly large server response")
        i = self.buffer.index(marker) + len(marker)
        result, self.buffer = self.buffer[:i], self.buffer[i:]
        return result

    def send(self, message: bytes) -> None:
        self.sock.sendall(message)

    def rest(self) -> bytes:
        answer = self.buffer
        self.buffer = b""
        while True:
            try:
                chunk = self.sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            answer += chunk
            if len(answer) > 400_000:
                raise ValueError("Unexpectedly large final server response")
        return answer

    def close(self) -> None:
        self.sock.close()


def recover_flag(
    documents: Sequence[Document],
    host: str,
    port: int,
    *,
    timeout: float = 30.0,
    max_trials_per_round: int = 128,
    progress: Callable[[str], object] = print,
) -> str:
    """Produce and verify every accepted proof; print only a remotely served flag."""
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("Unsupported Fiat-Shamir graph proof or missing public parameters")
    if not (1 <= port <= 65535 and 0 < timeout <= 120 and 1 <= max_trials_per_round <= 100000):
        raise ValueError("Invalid network or grinding limits")
    conn = _Connection(host, port, timeout)
    try:
        conn.until(instance.prompt)
        state = b""
        total_trials = 0
        for round_no in range(instance.rounds):
            commitments, opening, new_state, attempts = grind_pedersen_graph_opening(
                instance.graph, instance.pedersen_params, state,
                max_trials=max_trials_per_round,
            )
            if (new_state[-1] & 1 or not verify_pedersen_graph_opening(
                    commitments, opening, instance.graph, instance.pedersen_params)):
                raise RuntimeError("Internally generated graph proof failed verification")
            conn.send(json.dumps({"A": commitments, "z": opening},
                                 separators=(",", ":")).encode() + b"\n")
            accepted = conn.until(b"accepted\n")
            if b"accepted" not in accepted:
                raise RuntimeError("Verifier rejected the locally checked proof")
            state = new_state
            total_trials += attempts
            if round_no + 1 < instance.rounds:
                conn.until(instance.prompt)
            if (round_no+1) % 16 == 0 or round_no + 1 == instance.rounds:
                progress(f"[FIAT-SHAMIR] Accepted {round_no+1}/{instance.rounds} rounds")
        reply = conn.rest()
        colored = re.sub(rb"\x1b\[[0-9;]*m", b"", reply)
        match = re.search(rb"[a-zA-Z0-9_]{2,32}\{[^\r\n{}]{1,256}\}", colored)
        if not match:
            raise RuntimeError("All rounds accepted, but server did not return a recognizable flag")
        progress(f"[FIAT-SHAMIR] All rounds passed after {total_trials} commitment trials")
        return match.group(0).decode("utf-8", errors="replace")
    finally:
        conn.close()
