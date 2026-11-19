"""Structural detection of fixed-nonce AES-GCM tag oracles with hidden mutable input.

This is a detection and GHASH analysis primitive, not a flag-recovery solver.
The CODEGATE challenge additionally requires solving an underdetermined
GF(2) system against hidden AAD and plaintext, and completing a PoW.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from collections.abc import Sequence

from .parser import Document

R = 0xE1000000000000000000000000000000


def gf128_mul(a: int, b: int) -> int:
    """Multiply GHASH elements represented in NIST network/bit order."""
    if not 0 <= a < (1 << 128) or not 0 <= b < (1 << 128):
        raise ValueError("GHASH operands must fit into 128 bits")
    result = 0
    v = b
    for i in range(128):
        if (a >> (127 - i)) & 1:
            result ^= v
        v = (v >> 1) ^ (R if v & 1 else 0)
    return result


def gf128_ghash(h: int, aad: bytes, ciphertext: bytes) -> int:
    """Compute GHASH_H(AAD, ciphertext), including the GCM length block."""
    def blocks(data: bytes):
        for i in range(0, len(data), 16):
            yield int.from_bytes(data[i:i+16].ljust(16, b"\x00"), "big")

    x = 0
    for word in (*blocks(aad), *blocks(ciphertext)):
        x = gf128_mul(x ^ word, h)
    lengths = (len(aad)*8 << 64) | (len(ciphertext)*8)
    return gf128_mul(x ^ lengths, h)


@dataclass(frozen=True)
class GCMTagOracle:
    path: str
    line: int
    timeout_seconds: int | None
    pow_difficulty: int | None


def _call_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _subscript_state(arg: ast.expr) -> tuple[str, str] | None:
    """Return a shared container and statically determined index."""
    if not isinstance(arg, ast.Subscript) or not isinstance(arg.value, ast.Name):
        return None
    try:
        index = ast.literal_eval(arg.slice)
    except (ValueError, TypeError):
        return None
    if type(index) is not int:
        return None
    return (arg.value.id, str(index))


def _module_bound_names(tree: ast.Module) -> set[str]:
    bound: set[str] = set()
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
        for target in targets:
            for child in ast.walk(target):
                if isinstance(child, ast.Name):
                    bound.add(child.id)
    return bound


def _candidate_factories(node: ast.stmt) -> list[tuple[str, ast.expr, ast.FunctionDef | None]]:
    """List (name, return-expression, enclosing function) triples for node."""
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda):
        return [(target.id, node.value.body, None)
                for target in node.targets if isinstance(target, ast.Name)]
    if isinstance(node, ast.FunctionDef):
        returns = [child.value for child in ast.walk(node)
                   if isinstance(child, ast.Return)]
        return [(node.name, expression, node) for expression in returns]
    return []


def _gcm_nonce_argument(expression: ast.expr, module_names: set[str]) -> ast.Name | None:
    if not isinstance(expression, ast.Call):
        return None
    if not (isinstance(expression.func, ast.Attribute)
            and expression.func.attr == "new"
            and len(expression.args) >= 3
            and isinstance(expression.args[1], ast.Attribute)
            and expression.args[1].attr == "MODE_GCM"):
        return None
    nonce = expression.args[2]
    if not isinstance(nonce, ast.Name) or nonce.id not in module_names:
        return None
    return nonce


def _write_count(tree: ast.Module, name: str) -> int:
    writes = 0
    for assignment in ast.walk(tree):
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            continue
        targets = (assignment.targets if isinstance(assignment, ast.Assign)
                   else (assignment.target,))
        if any(isinstance(child, ast.Name) and child.id == name
               for target in targets for child in ast.walk(target)):
            writes += 1
    return writes


def _local_write_names(function: ast.FunctionDef) -> set[str]:
    local_writes: set[str] = set()
    for child in ast.walk(function):
        if isinstance(child, (ast.Assign, ast.AnnAssign)):
            targets = child.targets if isinstance(child, ast.Assign) else (child.target,)
            for target in targets:
                local_writes.update(inner.id for inner in ast.walk(target)
                                    if isinstance(inner, ast.Name))
    return local_writes


def _is_persistent_nonce_factory(
    expression: ast.expr, function: ast.FunctionDef | None,
    tree: ast.Module, module_names: set[str],
) -> bool:
    """A factory qualifies only if its module-scoped nonce is never refreshed.

    This deliberately refuses nonces generated inline and nonces refreshed
    inside the cipher factory: they are not evidence of nonce reuse.
    """
    nonce = _gcm_nonce_argument(expression, module_names)
    if nonce is None:
        return False
    # An initial module-level nonce is not proof of reuse if the
    # same variable is refreshed later (including inside a loop).
    if _write_count(tree, nonce.id) != 1:
        return False
    if function is not None and nonce.id in _local_write_names(function):
        return False
    return True


def _gcm_factories(tree: ast.Module) -> set[str]:
    """Identify factories returning a GCM cipher under a module-scoped nonce."""
    module_names = _module_bound_names(tree)
    factory_names: set[str] = set()
    for node in tree.body:
        for name, expression, function in _candidate_factories(node):
            if _is_persistent_nonce_factory(expression, function, tree, module_names):
                factory_names.add(name)
    return factory_names


def _cipher_calls(tree: ast.Module, cipher_names: set[str]) -> tuple[dict[str, set[tuple[str, str]]], bool]:
    called: dict[str, set[tuple[str, str]]] = {"update": set(), "encrypt": set()}
    digest_seen = False
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
            continue
        receiver = call.func.value
        if not isinstance(receiver, ast.Name) or receiver.id not in cipher_names:
            continue
        if call.func.attr in called and call.args:
            state = _subscript_state(call.args[0])
            if state is not None:
                called[call.func.attr].add(state)
        elif call.func.attr == "digest":
            digest_seen = True
    return called, digest_seen


def _states_for_cipher(tree: ast.Module, node: ast.Assign) -> set[str]:
    cipher_names = {target.id for target in node.targets
                    if isinstance(target, ast.Name)}
    if not cipher_names:
        return set()
    called, digest_seen = _cipher_calls(tree, cipher_names)
    if not digest_seen:
        return set()
    return {aad for aad, _ in called["update"]
            if any(state == aad for state, _ in called["encrypt"])}


def _authentication_states(tree: ast.Module, factories: set[str]) -> set[str]:
    """Identify two-field hidden state authenticated by one GCM cipher."""
    states: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if _call_name(node.value) not in factories:
            continue
        states |= _states_for_cipher(tree, node)
    return states


def _dynamic_subscript_targets(node: ast.stmt) -> tuple[list[ast.expr], bool] | None:
    """Return (targets, is_increment) for an assignment, or None if N/A."""
    if isinstance(node, ast.Assign):
        return node.targets, False
    if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
        return [node.target], True
    return None


def _has_static_index(target: ast.Subscript) -> bool:
    try:
        ast.literal_eval(target.slice)
        return True
    except (ValueError, TypeError):
        return False


def _mutated_states(tree: ast.Module) -> set[str]:
    """Require both replacement and extension of a random-indexed state."""
    resets: set[str] = set()
    extensions: set[str] = set()
    for node in ast.walk(tree):
        parsed = _dynamic_subscript_targets(node)
        if parsed is None:
            continue
        targets, increment = parsed
        for target in targets:
            if not isinstance(target, ast.Subscript) or not isinstance(target.value, ast.Name):
                continue
            # Random/unknown index: not one statically known selected slot.
            if _has_static_index(target):
                continue
            (extensions if increment else resets).add(target.value.id)
    return resets & extensions


def _is_empty_tag_compare(node: ast.Compare, factories: set[str]) -> bool:
    for call in ast.walk(node):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
            continue
        if call.func.attr != "digest":
            continue
        receiver = call.func.value
        if isinstance(receiver, ast.Call) and _call_name(receiver) in factories:
            return True
    return False


def _empty_tag_targets(tree: ast.Module, factories: set[str]) -> bool:
    return any(
        _is_empty_tag_compare(node, factories)
        for node in ast.walk(tree) if isinstance(node, ast.Compare)
    )


def _literal_call_arg(node: ast.Call) -> int | None:
    try:
        value = ast.literal_eval(node.args[0])
    except (ValueError, TypeError):
        return None
    return value


def _timeout_and_pow(tree: ast.Module) -> tuple[int | None, int | None]:
    timeout = pow_bits = None
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.args):
            continue
        if node.func.id == "alarm":
            timeout = _literal_call_arg(node)
        if node.func.id == "PoW":
            pow_bits = _literal_call_arg(node)
    return (
        timeout if type(timeout) is int and timeout > 0 else None,
        pow_bits if type(pow_bits) is int and pow_bits > 0 else None,
    )


def _oracle_for_document(doc: Document) -> GCMTagOracle | None:
    try:
        tree = ast.parse(doc.text)
    except SyntaxError:
        return None
    factories = _gcm_factories(tree)
    if not factories:
        return None
    states = _authentication_states(tree, factories) & _mutated_states(tree)
    if not states or not _empty_tag_targets(tree, factories):
        return None
    timeout, pow_bits = _timeout_and_pow(tree)
    line = next((node.lineno for node in ast.walk(tree)
                 if isinstance(node, ast.Attribute)
                 and node.attr == "MODE_GCM"), 1)
    return GCMTagOracle(doc.path, line, timeout, pow_bits)


def recognize_gcm_tag_oracle(documents: Sequence[Document]) -> list[GCMTagOracle]:
    """Recognize the source-level weakness without assuming challenge command names.

    Only the combination of a persistent nonce, an authenticated hidden
    two-field state, replacement and extension of that state, an exposed
    digest, and an empty-message tag comparison is actionable evidence.
    """
    matches = []
    for doc in documents:
        if not doc.path.casefold().endswith(".py"):
            continue
        oracle = _oracle_for_document(doc)
        if oracle is not None:
            matches.append(oracle)
    return matches


def gf128_pow(base: int, exponent: int) -> int:
    """Exponentiation in GHASH field; 0x8000... is multiplicative one."""
    if exponent < 0:
        raise ValueError("GF(2^128) exponent must be non-negative")
    result = 1 << 127
    while exponent:
        if exponent & 1:
            result = gf128_mul(result, base)
        base = gf128_mul(base, base)
        exponent >>= 1
    return result


def _linear_rows_for_12_byte_delta(tag_delta: int) -> list[int]:
    # A 12-byte update is followed by four zero padding bytes; hence
    # 32 low-order GHASH bits must vanish after multiplying the delta
    # by H^-2 (ciphertext update) or H^-3 (AAD update).
    products = [gf128_mul(tag_delta, 1 << i) & ((1 << 32)-1)
                for i in range(128)]
    return [sum(1 << j for j, word in enumerate(products) if word & (1 << i))
            for i in range(32)]


def _one_dimensional_gf2_kernel(rows: list[int]) -> int | None:
    """Return a unique nonzero 128-bit right-kernel vector, or None."""
    pivots: dict[int, int] = {}
    for item in rows:
        row = item
        while row:
            pivot = row.bit_length()-1
            if pivot in pivots:
                row ^= pivots[pivot]
            else:
                pivots[pivot] = row
                break
    if len(pivots) != 127:
        return None
    free = next(i for i in range(128) if i not in pivots)
    solution = 1 << free
    for pivot in sorted(pivots):
        if (pivots[pivot] & solution).bit_count() & 1:
            solution |= 1 << pivot
    return solution


def _candidate_key_from_pair(u: int, v: int, deltas: list[int]) -> int | None:
    """Check whether (u, v) are H^-2 and H^-3 for a common H, and return H."""
    h = gf128_mul(u, gf128_pow(v, (1 << 128)-2))
    if (not h or
            gf128_pow(h, (1 << 128)-1-2) != u or
            gf128_pow(h, (1 << 128)-1-3) != v):
        return None
    if all(
        (gf128_mul(delta, u) & ((1 << 32)-1)) == 0 or
        (gf128_mul(delta, v) & ((1 << 32)-1)) == 0
        for delta in deltas
    ):
        return h
    return None


def _search_key_pairs(found: set[int], deltas: list[int]) -> int | None:
    # H^-2 and H^-3, respectively, reveal H by their quotient.
    pairs = list(found)
    for i in range(len(pairs)):
        for j in range(len(pairs)):
            if i == j:
                continue
            key = _candidate_key_from_pair(pairs[i], pairs[j], deltas)
            if key is not None:
                return key
    return None


def recover_ghash_key_from_u1_tag_differences(
    tag_differences: Sequence[bytes], *,
    max_trials: int = 1500, seed: int = 0
) -> int:
    """Recover H from 12-byte u1 changes under a *fixed* key and nonce.

    Success requires enough changes confined to each of the two hidden
    variables. Every candidate is validated against *all* supplied tag
    differences; a failed sample raises rather than returning a guess.

    This only recovers the GHASH subkey H, not the empty-message tag/flag.
    """
    import random

    if max_trials < 1:
        raise ValueError("max_trials must be positive")
    if len(tag_differences) < 40 or not all(isinstance(d, bytes) and len(d) == 16
                                              for d in tag_differences):
        raise ValueError("Need at least 40 sixteen-byte tag differences")
    deltas = [int.from_bytes(diff, "big") for diff in tag_differences]
    rows = [_linear_rows_for_12_byte_delta(delta) for delta in deltas if delta]
    if len(rows) < 40:
        raise ValueError("Not enough nonzero tag differences")
    rng = random.Random(seed)
    found: set[int] = set()
    for _ in range(max_trials):
        indices = rng.sample(range(len(rows)), 5)
        candidate = _one_dimensional_gf2_kernel([row for i in indices for row in rows[i]])
        if candidate:
            found.add(candidate)
        if len(found) < 2:
            continue
        key = _search_key_pairs(found, deltas)
        if key is not None:
            return key
    raise RuntimeError("Not enough linearly independent single-state changes to recover GHASH key")
