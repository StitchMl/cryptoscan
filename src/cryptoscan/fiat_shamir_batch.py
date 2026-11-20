"""Source-verified batch Fiat-Shamir graph proof adapter.

Keep the vulnerability separate from the concrete network protocol:
integer-concatenation collisions are provided by fiat_shamir_encoding.
This adapter handles batch verification after all commitments have been
received, unlike round-by-round Fiat-Shamir grinding.
"""
from __future__ import annotations

import ast
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .fiat_shamir_encoding import (
    EquivocalGraphProof, construct_equivocal_pedersen_graph,
    decimal_transcript, verify_equivocal_graph_proof,
)
from .fiat_shamir_grinding import iterated_graph_hash
from .hamiltonicity_workflow import (
    _Connection, _graph_from_source, _hash_function_names,
    _literal_module_values, _pedersen_parameters,
)
from .parser import Document


@dataclass(frozen=True)
class BatchFiatShamirInstance:
    source_path: str
    graph: list[list[int]]
    pedersen_params: tuple[int, int, int, int]
    rounds: int
    prompt: bytes


def _unframed_decimal_hash(documents: Sequence[Document],
                           functions: set[str]) -> bool:
    for doc in documents:
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef) or node.name not in functions:
                continue
            if any(
                isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr == "join"
                and isinstance(call.func.value, ast.Constant)
                and call.func.value.value == ""
                and call.args and any(
                    isinstance(item, ast.Call)
                    and isinstance(item.func, ast.Name)
                    and item.func.id == "str"
                    for item in ast.walk(call.args[0])
                )
                for call in ast.walk(node)
            ):
                return True
    return False


def _is_append_call(call: ast.Call) -> bool:
    return (isinstance(call.func, ast.Attribute)
            and call.func.attr == "append"
            and isinstance(call.func.value, ast.Name))


def _is_matrix_hash_call(call: ast.Call, hash_functions: set[str]) -> bool:
    return (isinstance(call.func, ast.Name)
            and call.func.id in hash_functions and bool(call.args)
            and isinstance(call.args[0], ast.Subscript)
            and isinstance(call.args[0].value, ast.Name))


def _has_terminal_bits(post_hash: list[ast.stmt]) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and node.func.id == "bin"
        and any(isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "from_bytes"
                for inner in ast.walk(node))
        for statement in post_hash for node in ast.walk(statement)
    )


def _scan_loop_statement(
    statement: ast.stmt, hash_functions: set[str],
    append_lists: dict[str, int], hash_matrix_lists: set[str], index: int,
) -> int | None:
    """Return the earliest matrix-hash position found in this statement, if any."""
    first_hash_position = None
    for call in ast.walk(statement):
        if not isinstance(call, ast.Call):
            continue
        if _is_append_call(call):
            append_lists.setdefault(call.func.value.id, index)
        if _is_matrix_hash_call(call, hash_functions):
            first_hash_position = (index if first_hash_position is None
                                   else min(first_hash_position, index))
            hash_matrix_lists.add(call.args[0].value.id)
    return first_hash_position


def _locate_hash_chain(
    tree: ast.Module, hash_functions: set[str],
) -> tuple[int | None, dict[str, int], set[str]]:
    append_lists: dict[str, int] = {}
    first_hash_position: int | None = None
    hash_matrix_lists: set[str] = set()
    for index, statement in enumerate(tree.body):
        if not isinstance(statement, (ast.For, ast.While)):
            continue
        found = _scan_loop_statement(
            statement, hash_functions, append_lists, hash_matrix_lists, index,
        )
        if found is not None:
            first_hash_position = (found if first_hash_position is None
                                   else min(first_hash_position, found))
    return first_hash_position, append_lists, hash_matrix_lists


def _batched_chain_before_challenges(tree: ast.Module,
                                     hash_functions: set[str]) -> bool:
    """Prove every commitment is collected before the terminal hash chain."""
    first_hash_position, append_lists, hash_matrix_lists = _locate_hash_chain(
        tree, hash_functions,
    )
    if first_hash_position is None:
        return False
    if not any(index < first_hash_position for name, index in append_lists.items()
               if name in hash_matrix_lists):
        return False
    # Challenge bits must be determined after hashing the complete sequence,
    # not independently from each intermediate state.
    return _has_terminal_bits(tree.body[first_hash_position + 1:])


def _is_shape_only_check(function: ast.FunctionDef) -> bool:
    body = ast.unparse(function)
    return ("len(G)" in body and "len(r)" in body and
            not any(fragment in body for fragment in
                    ("isinstance(", "int(", "0 <=", "0<=", "value <", "x <")))


def _is_modular_pedersen_open(function: ast.FunctionDef) -> bool:
    body = ast.unparse(function)
    return ("commitment" in body and "pow(" in body and
            "% P" in body and "== 1" in body)


def _verifier_accepts_noncanonical_commitments(documents: Sequence[Document]) -> bool:
    """Refuse this attack when graph/commitment ranges are validated."""
    has_shape_only_check = False
    has_modular_pedersen_open = False
    for doc in documents:
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        for function in tree.body:
            if not isinstance(function, ast.FunctionDef):
                continue
            if function.name == "check_graph":
                has_shape_only_check |= _is_shape_only_check(function)
            if function.name == "pedersen_open":
                has_modular_pedersen_open |= _is_modular_pedersen_open(function)
    return has_shape_only_check and has_modular_pedersen_open


def _calls_function(statements: list[ast.stmt], name: str) -> bool:
    return any(isinstance(call, ast.Call)
               and isinstance(call.func, ast.Name)
               and call.func.id == name
               for statement in statements for call in ast.walk(statement))


def _has_proof_structure(tree: ast.Module) -> bool:
    # The same graph proof must offer both full-graph and cycle openings.
    called_functions = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    if not {"check_graph", "testcycle", "open_graph", "permute_graph"} <= called_functions:
        return False
    # Detect the two verification branches by their semantics rather
    # than names such as 'challenge' or 'challenge_bits'.
    return any(
        isinstance(node, ast.If)
        and _calls_function(node.body, "testcycle")
        and _calls_function(node.orelse, "open_graph")
        for node in ast.walk(tree)
    )


def _valid_graph(graph: object) -> bool:
    if not isinstance(graph, list) or not 2 <= len(graph) <= 12:
        return False
    if any(not isinstance(row, list) or len(row) != len(graph) for row in graph):
        return False
    return all(type(v) is int and v in (0, 1) for row in graph for v in row)


def _proof_prompt(tree: ast.Module) -> bytes | None:
    prompts = [
        arg.value for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "input"
        for arg in node.args
        if isinstance(arg, ast.Constant) and isinstance(arg.value, (bytes, str))
    ]
    return next((
        item if isinstance(item, bytes) else item.encode()
        for item in prompts
        if "proof" in str(item).lower()
    ), None)


def _instance_from_document(
    doc: Document, documents: Sequence[Document],
) -> BatchFiatShamirInstance | None:
    scoped = [item for item in documents if item.scope == doc.scope]
    params = _pedersen_parameters(scoped)
    hash_functions = _hash_function_names(scoped)
    if (params is None or not hash_functions or
            not _unframed_decimal_hash(scoped, hash_functions) or
            not _verifier_accepts_noncanonical_commitments(scoped)):
        return None
    try:
        tree = ast.parse(doc.text)
    except SyntaxError:
        return None
    if not _batched_chain_before_challenges(tree, hash_functions):
        return None
    if not _has_proof_structure(tree):
        return None
    rounds = _literal_module_values(tree).get("numrounds")
    graph = _graph_from_source(tree)
    if type(rounds) is not int or not (1 <= rounds <= 256):
        return None
    if not _valid_graph(graph):
        return None
    prompt = _proof_prompt(tree)
    if not prompt:
        return None
    return BatchFiatShamirInstance(doc.path, graph, params, rounds, prompt)


def extract_instance(documents: Sequence[Document]) -> BatchFiatShamirInstance | None:
    for doc in documents:
        if not doc.path.casefold().endswith(".py"):
            continue
        instance = _instance_from_document(doc, documents)
        if instance is not None:
            return instance
    return None


def _select_commitments(
    collision: EquivocalGraphProof,
    rounds: int,
    params: tuple[int, int, int, int],
) -> tuple[list[dict[str, object]], list[int]]:
    """Determine final challenges from the common transcript, then choose z."""
    state = b""
    for _ in range(rounds):
        state = iterated_graph_hash(collision.zero_matrix, state, params)
    # Mirrors Python's bin(int.from_bytes(...))[-numrounds:]. For a 256-bit
    # digest and 128 rounds this is exactly the 128 lowest-order bits.
    bits = format(int.from_bytes(state, "big"), "b")[-rounds:].zfill(rounds)
    payloads = [
        {
            "A": collision.one_matrix if bit == "1" else collision.zero_matrix,
            "z": collision.one_opening if bit == "1" else collision.zero_opening,
        }
        for bit in bits
    ]
    return payloads, [int(bit) for bit in bits]


def recover_flag(
    documents: Sequence[Document], host: str, port: int,
    *, timeout: float = 30.0,
    progress: Callable[[str], object] = print,
) -> str:
    """Return the flag only after the authorized remote verifier emits it."""
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("No verified vulnerable batch Fiat-Shamir graph protocol")
    if not 1 <= port <= 65535 or not 0 < timeout <= 120:
        raise ValueError("Invalid connection settings")
    collision = construct_equivocal_pedersen_graph(
        instance.graph, instance.pedersen_params,
    )
    if not verify_equivocal_graph_proof(
        collision.zero_matrix, collision.zero_opening,
        collision.one_matrix, collision.one_opening,
        instance.graph, instance.pedersen_params,
    ):
        raise RuntimeError("Locally generated proof equivocation did not verify")
    payloads, bits = _select_commitments(
        collision, instance.rounds, instance.pedersen_params,
    )
    progress(
        f"[FIAT-SHAMIR] Matched transcript preimages for {instance.rounds} rounds; "
        f"{sum(bits)} cycle openings and {len(bits)-sum(bits)} full-graph openings"
    )
    conn = _Connection(host, port, timeout)
    try:
        conn.until(instance.prompt)
        for index, payload in enumerate(payloads):
            conn.send(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
            if (index + 1) % 16 == 0 or index + 1 == instance.rounds:
                progress(f"[FIAT-SHAMIR] Submitted {index + 1}/{instance.rounds} proofs")
            if index + 1 < instance.rounds:
                conn.until(instance.prompt)
        response = conn.rest()
        cleaned = re.sub(rb"\x1b\[[0-9;]*m", b"", response)
        flag = re.search(rb"\w{2,32}\{[^\r\n{}]{1,256}\}", cleaned)
        if flag is None:
            raise RuntimeError("Verifier did not return a flag after batch proof submission")
        progress("[FIAT-SHAMIR] Flag received from remote verifier")
        return flag.group(0).decode("ascii")
    finally:
        conn.close()
