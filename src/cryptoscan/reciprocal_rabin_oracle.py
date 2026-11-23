"""Chosen-ciphertext CRT inconsistency attack on reciprocal Rabin encryption.

In a reciprocal Rabin construction r = m + c/m (mod n), decryption
solves X^2-rX+c separately modulo each RSA prime and combines roots
using CRT. If a faulty root solver returns a plausible but incorrect
root when the quadratic has no root in one field, re-encryption may
produce several distinct r' values for the *same supplied r*.

Each difference r'_i-r'_j is divisible by the prime component where
the reconstruction was consistent. Pairwise GCDs of independent
differences recover the formerly hidden RSA primes. The unknown public
parameter c then follows from two re-encryption residues modulo each
recovered prime:
    x+y = r, A = x+c/x, B = y+c/y
    (2*r-A-B)*x = r*(r-B) mod p
    c = A*x-x^2 mod p.

This model neither stores challenge values nor executes source text.
The only online action is an explicitly authorized CTF TCP oracle.
"""
from __future__ import annotations

import ast
import math
import re
import socket
from dataclasses import dataclass
from typing import Sequence

from .parser import Document
from .source_units import parse_python

_MAX_SOURCE = 500_000
_TRIPLE = re.compile(
    rb"(?m)^[ \t]*([A-Za-z_]\w*)\s*=\s*([+-]?\d+)\s*$"
)
_FLAG = re.compile(rb"^[A-Za-z][A-Za-z0-9_]{1,39}\{[^{}\r\n]{1,256}\}")


@dataclass(frozen=True)
class ReciprocalRabinOracle:
    factor_bits: int
    ciphertext_labels: tuple[str, str, str]
    input_prompt: str
    ciphertext_header: str
    result_header: str
    failure_marker: str


@dataclass(frozen=True)
class OracleResult:
    modulus: int
    factors: tuple[int, int]
    reciprocal_constant: int
    plaintext: bytes
    secret: str
    probes: int


def _name(node):
    return node.id if isinstance(node, ast.Name) else None


def _member(node):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr
    return None


def _calls(node, name):
    return [
        x for x in ast.walk(node)
        if isinstance(x, ast.Call)
        and (_name(x.func) == name or
             isinstance(x.func, ast.Attribute) and x.func.attr == name)
    ]


def _reciprocal_encryption(tree):
    """Recognize m+c*m^-1 mod n with Jacobi and ordering disambiguation."""
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef) or len(fn.args.args) < 2:
            continue
        message = fn.args.args[0].arg
        modulus, constant = None, None
        for expression in ast.walk(fn):
            if not (isinstance(expression, ast.BinOp)
                    and isinstance(expression.op, ast.Mod)
                    and isinstance(expression.left, ast.BinOp)
                    and isinstance(expression.left.op, ast.Add)):
                continue
            parts = (expression.left.left, expression.left.right)
            if _name(parts[0]) == message:
                reciprocal = parts[1]
            elif _name(parts[1]) == message:
                reciprocal = parts[0]
            else:
                continue
            if not (isinstance(reciprocal, ast.BinOp)
                    and isinstance(reciprocal.op, ast.Mult)):
                continue
            inv = next(
                (part for part in (reciprocal.left, reciprocal.right)
                 if isinstance(part, ast.Call)
                 and _name(part.func) == "pow"
                 and len(part.args) == 3
                 and _name(part.args[0]) == message
                 and isinstance(part.args[1], ast.UnaryOp)
                 and isinstance(part.args[1].op, ast.USub)
                 and isinstance(part.args[1].operand, ast.Constant)
                 and part.args[1].operand.value == 1),
                None,
            )
            if inv is None or ast.dump(inv.args[2]) != ast.dump(expression.right):
                continue
            other = reciprocal.left if reciprocal.right is inv else reciprocal.right
            constant = _member(other)
            modulus = _member(expression.right)
            if not constant or not modulus or constant[0] != modulus[0]:
                continue
            if not any(
                len(call.args) == 2
                and _name(call.args[0]) == message
                and ast.dump(call.args[1]) == ast.dump(expression.right)
                for call in _calls(fn, "jacobi")
            ):
                continue
            if not any(
                isinstance(node, ast.Compare)
                and any(isinstance(op, ast.Lt) for op in node.ops)
                and any(_name(x) == message for x in
                        [node.left, *node.comparators])
                for node in ast.walk(fn)
            ):
                continue
            return fn.name, modulus[1], constant[1]
    return None


def _quadratic_decrypt(tree, encryption):
    """Match a CRT combination of independently inverted quadratic roots.

    The implementation may use a hand-written quotient-ring exponentiation
    instead of a literal x**2 in source: accept the inverse of the linear
    coefficient and the complementary root r-a, then verify two private
    prime calls and CRT in the surrounding decryptor.
    """
    solver_names = set()
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        modular_inverses = [
            call for call in _calls(fn, "pow")
            if len(call.args) == 3
            and isinstance(call.args[1], ast.UnaryOp)
            and isinstance(call.args[1].op, ast.USub)
            and isinstance(call.args[1].operand, ast.Constant)
            and call.args[1].operand.value == 1
            and isinstance(call.args[2], ast.Name)
        ]
        if not modular_inverses:
            continue
        has_complementary_root = any(
            isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub)
            and any(isinstance(child, ast.Name)
                    for child in (node.left, node.right))
            for node in ast.walk(fn)
        )
        has_pair = any(
            isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple)
            and len(node.value.elts) == 2
            for node in ast.walk(fn)
        )
        if has_pair and has_complementary_root:
            solver_names.add(fn.name)
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef) or fn.name == encryption:
            continue
        invoked = [
            node for node in ast.walk(fn)
            if isinstance(node, ast.Call)
            and _name(node.func) in solver_names
        ]
        if len(invoked) < 2:
            continue
        moduli = {
            member for call in invoked for arg in call.args
            if (member := _member(arg)) is not None
        }
        if (len(moduli) >= 2 and _calls(fn, "crt")
                and _calls(fn, "jacobi")):
            return fn.name
    return None


def _protocol_profile(tree, encrypt, decrypt):
    for loop in ast.walk(tree):
        if not isinstance(loop, ast.While):
            continue
        prompts = [
            node.args[0].value for node in ast.walk(loop)
            if isinstance(node, ast.Call) and _name(node.func) == "input"
            and len(node.args) == 1 and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ]
        if len(set(prompts)) != 1:
            continue
        nested = [
            call for call in ast.walk(loop)
            if isinstance(call, ast.Call)
            and _name(call.func) == encrypt
            and call.args and isinstance(call.args[0], ast.Call)
            and _name(call.args[0].func) == decrypt
        ]
        if not nested:
            continue
        prints = [
            node.args[0].value for node in ast.walk(loop)
            if isinstance(node, ast.Call) and _name(node.func) == "print"
            and len(node.args) == 1 and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ]
        marker = next(
            (s for s in prints if "wrong" in s.lower() or "error" in s.lower()
             or "something" in s.lower()), None
        )
        success = [s for s in prints if s != marker]
        if marker is None or len(success) != 1:
            continue
        # The exception handler is part of the oracle side channel.
        if not any(
            isinstance(node, ast.ExceptHandler)
            and any(isinstance(call, ast.Call) and _name(call.func) == "print"
                    and any(isinstance(arg, ast.Constant)
                            and arg.value == marker for arg in call.args)
                    for call in ast.walk(node))
            for node in ast.walk(loop)
        ):
            continue
        # Some services put their banner directly at module scope;
        # others guard startup under if __name__ == "__main__".
        # The relevant invariant is that the banner is printed outside
        # the interactive oracle loop.
        loop_nodes = {id(node) for node in ast.walk(loop)}
        banners = [
            call.args[0].value for call in ast.walk(tree)
            if id(call) not in loop_nodes
            and isinstance(call, ast.Call) and _name(call.func) == "print"
            and len(call.args) == 1
            and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str)
        ]
        banners = [s for s in banners if s not in prints]
        if len(banners) != 1:
            continue
        return prompts[0], banners[0], success[0], marker
    return None


def _source_profile(document):
    if not document.text or len(document.text) > _MAX_SOURCE:
        return None
    tree = parse_python(document)
    if tree is None:
        return None
    encryption = _reciprocal_encryption(tree)
    if encryption is None:
        return None
    encrypt, modulus_field, constant_field = encryption
    if _quadratic_decrypt(tree, encrypt) is None:
        return None
    decrypt = _quadratic_decrypt(tree, encrypt)
    protocol = _protocol_profile(tree, encrypt, decrypt)
    if protocol is None:
        return None
    definitions = {}
    for stmt in ast.walk(tree):
        if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and isinstance(stmt.value, ast.Constant)
                and type(stmt.value.value) is int):
            definitions[stmt.targets[0].id] = stmt.value.value
    functions = {
        fn.name: fn for fn in tree.body if isinstance(fn, ast.FunctionDef)
    }
    # Resolve generator bit length across arbitrary finite chains of wrapper
    # functions and positional arguments. This is symbolic source dataflow,
    # never execution of the user's Python.
    bits = None
    for fn in functions.values():
        if not _calls(fn, "getPrime"):
            continue
        parameters = [arg.arg for arg in fn.args.args]
        prime_widths = [
            call.args[0] for call in _calls(fn, "getPrime") if call.args
        ]
        if len(prime_widths) != 1:
            continue
        width = prime_widths[0]
        if isinstance(width, ast.Constant) and type(width.value) is int:
            bits = width.value
            break
        parameter = _name(width)
        if parameter not in parameters:
            continue
        current_function = fn.name
        parameter_index = parameters.index(parameter)
        for _ in range(5):
            calls = [
                call for call in ast.walk(tree)
                if isinstance(call, ast.Call)
                and _name(call.func) == current_function
                and len(call.args) > parameter_index
            ]
            if len(calls) == 0:
                break
            arguments = [call.args[parameter_index] for call in calls]
            values = [
                arg.value if isinstance(arg, ast.Constant) else
                definitions.get(_name(arg))
                for arg in arguments
            ]
            numbers = [
                value for value in values
                if type(value) is int
            ]
            if numbers and len(set(numbers)) == 1:
                bits = numbers[0]
                break
            # Follow a name forwarded from an enclosing function.
            names = {_name(arg) for arg in arguments}
            if len(names) != 1 or None in names:
                break
            forward = next(iter(names))
            owners = [
                owner for owner in functions.values()
                if forward in [arg.arg for arg in owner.args.args]
                and any(child is calls[0] for child in ast.walk(owner))
            ]
            if len(owners) != 1:
                break
            owner = owners[0]
            current_function = owner.name
            parameter_index = [arg.arg for arg in owner.args.args].index(forward)
        if bits is not None:
            break
    if bits is None or not isinstance(bits, int) or not 16 <= bits <= 4096:
        return None
    # The source must generate odd primes in a known congruence class.
    if not any(
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.BinOp)
        and isinstance(node.left.op, ast.Mod)
        and isinstance(node.left.right, ast.Constant)
        and node.left.right.value == 4
        and any(isinstance(comparator, ast.Constant)
                and comparator.value == 3
                for comparator in node.comparators)
        for node in ast.walk(tree)
    ):
        return None
    # Parse the field names from the representation class, not from
    # hard-coded r/s/t symbols.
    enc_types = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        fields = [
            stmt.target.id for stmt in node.body
            if isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
        ]
        if len(fields) == 3:
            enc_types.append(tuple(fields))
    if len(enc_types) != 1:
        return None
    return ReciprocalRabinOracle(
        bits, enc_types[0], protocol[0], protocol[1],
        protocol[2], protocol[3],
    )


def extract_instance(documents: Sequence[Document]):
    models = [
        profile for doc in documents
        if (profile := _source_profile(doc)) is not None
    ]
    return models[0] if len(models) == 1 else None


def _records_to_factors(records, minimum_factor_bits):
    from sympy import isprime
    deltas = [
        abs(a-b) for _, outputs in records if len(outputs) == 2
        for a,b in (tuple(sorted(outputs)),) if a != b
    ]
    factors = set()
    # Repeated independent deltas share the hidden prime, with
    # accidental small co-factors removed by intersection.
    for i, left in enumerate(deltas):
        for right in deltas[i+1:]:
            factor = math.gcd(left, right)
            if factor.bit_length() < minimum_factor_bits:
                continue
            if isprime(factor):
                factors.add(factor)
            if len(factors) >= 2:
                primes = sorted(factors)
                if primes[0] != primes[1]:
                    return tuple(primes[:2])
    return None


def _recover_constant(records, factors):
    p, q = factors
    n = p*q
    residues = {}
    for r, values in records:
        if len(values) != 2:
            continue
        A, B = sorted(values)
        shared = math.gcd(abs(A-B), n)
        if shared not in (p,q):
            continue
        target = n//shared
        denominator = (2*r-A-B) % target
        if math.gcd(denominator, target) != 1:
            continue
        x = (r*(r-B)*pow(denominator, -1, target)) % target
        c = (A*x-x*x) % target
        residues.setdefault(target, []).append(c)
    if not all(prime in residues for prime in factors):
        return None
    chosen = {}
    for prime in factors:
        counts = {}
        for residue in residues[prime]:
            counts[residue] = counts.get(residue, 0) + 1
        ordered = sorted(counts, key=lambda value: (-counts[value], value))
        if not ordered:
            return None
        # At least two independently obtained observations must agree.
        if counts[ordered[0]] < 2:
            return None
        chosen[prime] = ordered[0]
    return (
        chosen[p] + p*((chosen[q]-chosen[p])*pow(p,-1,q)%q)
    ) % n


def _jacobi(a, modulus):
    if modulus < 3 or modulus % 2 == 0:
        raise ValueError("Jacobi modulus must be odd")
    result = 1
    a %= modulus
    while a:
        while not a % 2:
            a //= 2
            if modulus % 8 in (3,5):
                result = -result
        a, modulus = modulus, a
        if a % 4 == modulus % 4 == 3:
            result = -result
        a %= modulus
    return result if modulus == 1 else 0


def _encrypt(m, n, c):
    if not 0 < m < n or math.gcd(m,n) != 1:
        return None
    reciprocal = c*pow(m,-1,n) % n
    return ((m+reciprocal)%n, _jacobi(m,n), int(reciprocal < m))


def _decrypt_candidates(ciphertext, p, q, c):
    """CRT four quadratic roots; verify every candidate by re-encryption."""
    n = p*q
    r, s, t = ciphertext
    from sympy import sqrt_mod
    roots = []
    for prime in (p,q):
        discr = (r*r-4*c) % prime
        value = sqrt_mod(discr, prime)
        if value is None:
            return []
        inv2 = pow(2,-1,prime)
        roots.append(tuple(set(((r+int(value))*inv2 % prime,
                                (r-int(value))*inv2 % prime))))
    candidates = []
    for a in roots[0]:
        for b in roots[1]:
            m = (a + p*((b-a)*pow(p,-1,q)%q)) % n
            if _encrypt(m,n,c) == ciphertext:
                candidates.append(m)
    return sorted(set(candidates))


def _decode_flag(m):
    raw = m.to_bytes((m.bit_length()+7)//8, "big")
    # The source may append random bytes to the plaintext. Only the
    # complete ASCII marker is interpreted as a flag.
    found = _FLAG.match(raw)
    if found is None:
        raise RuntimeError("recovered integer has no leading verified CTF flag")
    return found.group().decode("ascii"), raw


class TextOracle:
    """Bounded prompt-driven TCP adapter for triple ciphertext responses."""
    def __init__(self, conn, profile):
        self.conn = conn
        self.profile = profile
        self.buffer = b""
        self.probes = 0

    def _until_prompt(self):
        marker = self.profile.input_prompt.encode()
        while marker not in self.buffer:
            if len(self.buffer) > 65536:
                raise RuntimeError("oversized oracle response")
            packet = self.conn.recv(8192)
            if not packet:
                raise ConnectionError("oracle session closed")
            self.buffer += packet
        before, self.buffer = self.buffer.split(marker, 1)
        return before

    def initial(self):
        banner = self._until_prompt()
        if self.profile.ciphertext_header.encode() not in banner:
            raise RuntimeError("missing source-defined initial ciphertext header")
        return self._triple(banner)

    def _triple(self, data):
        labels = self.profile.ciphertext_labels
        observed = {}
        for label, value in _TRIPLE.findall(data):
            name = label.decode("ascii")
            if name in labels:
                if name in observed:
                    raise ValueError("ambiguous duplicated ciphertext attribute")
                observed[name] = int(value)
        if set(observed) != set(labels):
            raise ValueError("incomplete ciphertext triple")
        return tuple(observed[label] for label in labels)

    def query(self, r,s,t):
        self.conn.sendall(f"{r},{s},{t}\n".encode())
        self.probes += 1
        message = self._until_prompt()
        if self.profile.failure_marker.encode() in message:
            return None
        if self.profile.result_header.encode() not in message:
            raise RuntimeError("unexpected oracle response")
        return self._triple(message)


def recover_details(documents, host, port, *, timeout=30.0, max_queries=320):
    profile = extract_instance(documents)
    if profile is None:
        raise ValueError("source does not establish reciprocal Rabin CRT oracle")
    if not 8 <= max_queries <= 2048:
        raise ValueError("unsupported chosen-ciphertext query budget")
    records = []
    with socket.create_connection((host,port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        oracle = TextOracle(conn, profile)
        encrypted_flag = oracle.initial()
        factors = None
        c = None
        for r in range(1, max_queries//4+1):
            observations = [
                oracle.query(r,s,t) for s in (-1,1) for t in (0,1)
            ]
            if any(value is None for value in observations):
                continue
            values = frozenset(value[0] for value in observations)
            if len(values) != 2:
                continue
            records.append((r, values))
            if factors is None:
                factors = _records_to_factors(
                    records, max(16,profile.factor_bits-2),
                )
            if factors is not None and c is None:
                c = _recover_constant(records, factors)
                if c is not None:
                    break
    if factors is None or c is None:
        raise RuntimeError(
            "bounded reciprocal-Rabin oracle probes did not reveal "
            "two independent CRT factors and the public constant"
        )
    p,q = factors
    n = p*q
    if not 0 <= encrypted_flag[0] < n:
        raise RuntimeError("encrypted flag is inconsistent with reconstructed modulus")
    if _jacobi(c,p) != -1 or _jacobi(c,q) != -1:
        raise RuntimeError("recovered public constant violates source key generation")
    candidates = _decrypt_candidates(encrypted_flag,p,q,c)
    if len(candidates) != 1:
        raise RuntimeError("encrypted flag does not have a unique verified decryption")
    flag, plaintext = _decode_flag(candidates[0])
    if _encrypt(candidates[0],n,c) != encrypted_flag:
        raise RuntimeError("plaintext failed source-defined re-encryption")
    return OracleResult(n,(p,q),c,plaintext,flag,oracle.probes)


def recover_flag(documents, host, port, *, timeout=30.0):
    return recover_details(documents,host,port,timeout=timeout).secret
