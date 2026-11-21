"""Offline ECDSA-LCG lattice solver. Requires python-flint and pycryptodome."""
from __future__ import annotations
import ast
import hashlib
import math
import re
from dataclasses import dataclass
from typing import Sequence
from .eclcg_detector import detect_ec_lcg

Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,
     32670510020758816978083085130507043184471273380659243275938904335757337482424)

@dataclass(frozen=True)
class Instance:
    messages: tuple[bytes, ...]
    signatures: tuple[tuple[int, int], ...]
    ct: bytes
    nonce: bytes

def _literals(text):
    found = {}
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                found[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, SyntaxError, TypeError, RecursionError):
                pass
    return found

def _source_messages(source) -> list | None:
    try:
        msgs = _literals(source.text).get("msgs")
    except SyntaxError:
        return None
    if not isinstance(msgs, list) or not 8 <= len(msgs) <= 64 or not all(isinstance(m, bytes) for m in msgs):
        return None
    return msgs


def _matching_output(output, msgs: list) -> Instance | None:
    try:
        data = _literals(output.text)
    except SyntaxError:
        return None
    sigs, ct, nonce = data.get("sigs"), data.get("ct"), data.get("nonce")
    valid = (isinstance(sigs, list) and len(sigs) == len(msgs)
             and all(isinstance(sig, tuple) and len(sig) == 2
                     and all(type(x) is int and 0 < x < Q for x in sig) for sig in sigs))
    if valid and isinstance(ct, bytes) and ct and isinstance(nonce, bytes) and 1 <= len(nonce) <= 15:
        return Instance(tuple(msgs), tuple(sigs), ct, nonce)
    return None


def extract_instance(documents: Sequence) -> Instance | None:
    matches = []
    for source in documents:
        if not detect_ec_lcg([source]):
            continue
        msgs = _source_messages(source)
        if msgs is None:
            continue
        for output in documents:
            if output.path == source.path or output.scope != source.scope:
                continue
            instance = _matching_output(output, msgs)
            if instance is not None:
                matches.append(instance)
    # Never silently choose the first of several plausible public outputs.
    return matches[0] if len(matches) == 1 else None


def _orthogonal(vectors, modulus):
    from flint import fmpz_mat
    n, k = len(vectors[0]), len(vectors)
    if not all(len(v) == n for v in vectors):
        raise ValueError("Mismatched vectors")
    # [modulus * V^T | I] with [modulus^2 * I | 0].
    rows = [[modulus * int(vectors[j][i]) for j in range(k)]
            + [int(i == j) for j in range(n)] for i in range(n)]
    rows += [[modulus * modulus * int(i == j) for j in range(k)] + [0] * n for i in range(k)]
    reduced = fmpz_mat(rows).lll()
    return [[int(reduced[i, k+j]) for j in range(n)] for i in range(n+k)
            if all(int(reduced[i, j]) == 0 for j in range(k))]

def _kernel_diff(part, n):
    from sympy import Matrix
    matrix = Matrix([row + [0] for row in part] + [[0] + row for row in part])
    if matrix.rank() != n-2:
        return None
    kernel = matrix.nullspace()
    if len(kernel) != 1:
        return None
    scale = math.lcm(*(int(x.q) for x in kernel[0]))
    diff = [int(x * scale) for x in kernel[0]]
    gcd = math.gcd(*diff)
    if not gcd:
        return None
    return [x // gcd for x in diff]


def _candidate_keys(diff, v1, v2, n):
    for sign in (-1, 1):
        try:
            d = ((sign*diff[0]-v1[0])*pow(v2[0], -1, Q)) % Q
        except ValueError:
            continue
        if d and all((v1[i]+v2[i]*d-sign*diff[i]) % Q == 0 for i in range(n-1)):
            yield d


def _keys(instance):
    n = len(instance.signatures)
    hashes = [int.from_bytes(hashlib.sha256(m).digest(), "big") % Q for m in instance.messages]
    inv = [pow(s, -1, Q) for _, s in instance.signatures]
    v1 = [(inv[i]*hashes[i] - inv[i+1]*hashes[i+1]) % Q for i in range(n-1)]
    v2 = [(inv[i]*instance.signatures[i][0] - inv[i+1]*instance.signatures[i+1][0]) % Q
          for i in range(n-1)]
    orth = _orthogonal((v1[:-1], v2[:-1], v1[1:], v2[1:]), Q)
    if len(orth) < 5:
        raise RuntimeError("LLL produced too few short orthogonal relations")
    for keep in range(max(3, len(orth)-3), len(orth)):
        diff = _kernel_diff(orth[:keep], n)
        if diff is None:
            continue
        yield from _candidate_keys(diff, v1, v2, n)

def _add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1]+b[1]) % P == 0: return None
    if a == b:
        slope = 3*a[0]**2*pow(2*a[1], -1, P) % P
    else:
        slope = (b[1]-a[1])*pow(b[0]-a[0], -1, P) % P
    x = (slope*slope-a[0]-b[0]) % P
    return (x, (slope*(a[0]-x)-a[1]) % P)

def _mul(k, point=G):
    result = None
    while k:
        if k & 1: result = _add(result, point)
        point = _add(point, point)
        k >>= 1
    return result

def _verify(d, instance):
    for message, (r, s) in zip(instance.messages, instance.signatures):
        z = int.from_bytes(hashlib.sha256(message).digest(), "big") % Q
        k = ((z+r*d)*pow(s, -1, Q)) % Q
        if not k or (_mul(k) or (None,))[0] != r:
            return False
    return True

def recover_flag(documents, progress=print):
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("No matching ECDSA-LCG source and signature corpus")
    try:
        from Crypto.Cipher import AES
        from flint import fmpz_mat  # noqa: F401
    except ImportError as exc:
        raise RuntimeError("Install python-flint and pycryptodome for ECDSA-LCG solving") from exc
    progress(f"[ECLCG] Parsed {len(instance.signatures)} signatures, starting lattice recovery")
    for d in _keys(instance):
        if not _verify(d, instance):
            continue
        key = hashlib.sha256(str(d).encode()).digest()
        plaintext = AES.new(key, AES.MODE_CTR, nonce=instance.nonce).decrypt(instance.ct)
        match = re.search(rb"\w{2,32}\{[^\r\n]{1,200}\}", plaintext)
        if match:
            progress("[ECLCG] Recovered key independently checked against all signatures")
            return match.group(0).decode("ascii")
    raise RuntimeError("No ECDSA-verified private key recovered from the available lattice basis")
