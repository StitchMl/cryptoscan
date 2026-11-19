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


def _gcm_factory_declarations(tree: ast.Module):
    """Return source-visible functions and lambdas that build cipher objects."""
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    yield target.id, node.value.body, None
        elif isinstance(node, ast.FunctionDef):
            for child in ast.walk(node):
                if isinstance(child, ast.Return):
                    yield node.name, child.value, node


def _gcm_factory_nonce(expression: ast.AST) -> str | None:
    if not isinstance(expression, ast.Call):
        return None
    if not (isinstance(expression.func, ast.Attribute)
            and expression.func.attr == "new" and len(expression.args) >= 3
            and isinstance(expression.args[1], ast.Attribute)
            and expression.args[1].attr == "MODE_GCM"):
        return None
    nonce = expression.args[2]
    return nonce.id if isinstance(nonce, ast.Name) else None


def _written_names(tree: ast.AST):
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
        for target in targets:
            for child in ast.walk(target):
                if isinstance(child, ast.Name):
                    yield child.id


def _gcm_factories(tree: ast.Module) -> set[str]:
    """Only factories with a single, module-scoped, stable nonce qualify."""
    module_names = _module_bound_names(tree)
    written = list(_written_names(tree))
    names: set[str] = set()
    for name, expression, function in _gcm_factory_declarations(tree):
        nonce = _gcm_factory_nonce(expression)
        if nonce is None or nonce not in module_names:
            continue
        if written.count(nonce) != 1:
            continue
        if function is not None and nonce in set(_written_names(function)):
            continue
        names.add(name)
    return names


def _authentication_states(tree: ast.Module, factories: set[str]) -> set[str]:
    """Identify two-field hidden state authenticated by one GCM cipher."""
    states: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if _call_name(node.value) not in factories:
            continue
        cipher_names = {target.id for target in node.targets
                        if isinstance(target, ast.Name)}
        if not cipher_names:
            continue
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
        if not digest_seen:
            continue
        for aad, _ in called["update"]:
            if any(state == aad for state, _ in called["encrypt"]):
                states.add(aad)
    return states


def _mutated_states(tree: ast.Module) -> set[str]:
    """Require both replacement and extension of a random-indexed state."""
    resets: set[str] = set()
    extensions: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, increment = node.targets, False
        elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
            targets, increment = (node.target,), True
        else:
            continue
        for target in targets:
            if not isinstance(target, ast.Subscript) or not isinstance(target.value, ast.Name):
                continue
            # Random/unknown index: not one statically known selected slot.
            try:
                ast.literal_eval(target.slice)
                continue
            except (ValueError, TypeError):
                pass
            (extensions if increment else resets).add(target.value.id)
    return resets & extensions


def _empty_tag_targets(tree: ast.Module, factories: set[str]) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for call in ast.walk(node):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr != "digest":
                continue
            receiver = call.func.value
            if isinstance(receiver, ast.Call) and _call_name(receiver) in factories:
                return True
    return False


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
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        factories = _gcm_factories(tree)
        if not factories:
            continue
        states = _authentication_states(tree, factories) & _mutated_states(tree)
        if not states or not _empty_tag_targets(tree, factories):
            continue
        timeout = pow_bits = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "alarm" and node.args:
                    try:
                        timeout = ast.literal_eval(node.args[0])
                    except (ValueError, TypeError):
                        pass
                if node.func.id == "PoW" and node.args:
                    try:
                        pow_bits = ast.literal_eval(node.args[0])
                    except (ValueError, TypeError):
                        pass
        line = next((node.lineno for node in ast.walk(tree)
                     if isinstance(node, ast.Attribute)
                     and node.attr == "MODE_GCM"), 1)
        matches.append(GCMTagOracle(
            doc.path, line,
            timeout if type(timeout) is int and timeout > 0 else None,
            pow_bits if type(pow_bits) is int and pow_bits > 0 else None,
        ))
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
        # H^-2 and H^-3, respectively, reveal H by their quotient.
        pairs = list(found)
        for i in range(len(pairs)):
            for j in range(len(pairs)):
                if i == j:
                    continue
                u, v = pairs[i], pairs[j]
                h = gf128_mul(u, gf128_pow(v, (1 << 128)-2))
                if (not h or
                        gf128_pow(h, (1 << 128)-1-2) != u or
                        gf128_pow(h, (1 << 128)-1-3) != v):
                    continue
                if all(
                    (gf128_mul(delta, u) & ((1 << 32)-1)) == 0 or
                    (gf128_mul(delta, v) & ((1 << 32)-1)) == 0
                    for delta in deltas
                ):
                    return h
    raise RuntimeError("Not enough linearly independent single-state changes to recover GHASH key")
