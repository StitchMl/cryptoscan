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


def recognize_gcm_tag_oracle(documents: Sequence[Document]) -> list[GCMTagOracle]:
    matches = []
    for doc in documents:
        if not doc.path.casefold().endswith(".py"):
            continue
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        # Match code structure rather than comments or arbitrary words in output files.
        normalized = "".join(ast.unparse(tree).split())
        has_aes = "AES.new(key,AES.MODE_GCM,nonce)" in normalized
        has_tag_path = all(x in normalized for x in (
            'cmd=="tag"', "cipher=new()", "cipher.update(s[0])",
            "cipher.encrypt(s[1])", "cipher.digest().hex()"
        ))
        has_mutation = all(x in normalized for x in (
            'cmd=="u1"', 'cmd=="u2"', "s[randbit()]=gen()",
            "s[randbit()]+=gen()"
        ))
        has_target = "new().digest().hex()" in normalized
        has_random_state = "s=[gen(),gen()]" in normalized
        if not (has_aes and has_tag_path and has_mutation
                and has_target and has_random_state):
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
                     if isinstance(node, ast.Lambda)
                     and "AES.new" in ast.unparse(node)
                     and "MODE_GCM" in ast.unparse(node)), 1)
        matches.append(GCMTagOracle(
            doc.path, line,
            timeout if type(timeout) is int and timeout > 0 else None,
            pow_bits if type(pow_bits) is int and pow_bits > 0 else None,
        ))
    return matches
