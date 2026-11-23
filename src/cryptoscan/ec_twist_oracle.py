"""Chosen-coordinate quadratic-twist small-subgroup recovery for x-only EC oracles.

When an x-only short-Weierstrass scalar multiplication accepts arbitrary
coordinates, it also operates on the quadratic twist. Factor the twist
order, choose a full-order twist point, query the x-only oracle, and use
Pohlig-Hellman with bounded BSGS to recover a scalar residue. The server's
x-coordinate makes the result ambiguous up to sign. Never claim a full
plaintext when the residue does not uniquely determine its byte string.
Source is interpreted through AST only; it is never executed.
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

_MAX_SOURCE = 300000
_FLAG = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,31}\{[ -~]{1,256}\}")


@dataclass(frozen=True)
class TwistOracle:
    field_prime: int
    curve_a: int
    curve_b: int
    curve_order: int | None
    input_prompt: str
    flag_prefix: str | None
    flag_suffix: str


def _name(node):
    return node.id if isinstance(node, ast.Name) else None


def _constant(node, definitions=None, seen=frozenset()):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.Name) and definitions is not None:
        if node.id in seen or node.id not in definitions:
            return None
        return _constant(definitions[node.id], definitions, seen | {node.id})
    if not isinstance(node, ast.BinOp):
        return None
    left = _constant(node.left, definitions, seen)
    right = _constant(node.right, definitions, seen)
    if left is None or right is None:
        return None
    if isinstance(node.op, ast.Pow) and 0 <= right <= 256 and 0 <= left <= 65536:
        value = left ** right
    elif isinstance(node.op, ast.Add):
        value = left + right
    elif isinstance(node.op, ast.Sub):
        value = left - right
    elif isinstance(node.op, ast.Mult):
        value = left * right
    elif isinstance(node.op, ast.LShift) and 0 <= right <= 256:
        value = left << right
    else:
        return None
    return value if abs(value).bit_length() <= 2048 else None


def _x_only_source(tree):
    """Find an x/z scalar-multiplication oracle, rather than a generic EC call."""
    functions = {
        fn.name: fn for fn in tree.body if isinstance(fn, ast.FunctionDef)
    }
    ladders = {
        name for name, fn in functions.items()
        if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
               and n.func.id in functions and n.func.id != name
               for n in ast.walk(fn))
        and any(isinstance(n, ast.BinOp) and isinstance(n.op, ast.RShift)
                for n in ast.walk(fn))
    }
    if not ladders:
        return None
    for fn in functions.values():
        if len(fn.args.args) < 2:
            continue
        arguments = [arg.arg for arg in fn.args.args]
        pairs = set()
        for n in ast.walk(fn):
            if (isinstance(n, ast.Assign) and len(n.targets) == 1
                    and (target := _name(n.targets[0])) is not None
                    and isinstance(n.value, ast.Tuple)
                    and len(n.value.elts) == 2
                    and _name(n.value.elts[0]) == arguments[0]
                    and isinstance(n.value.elts[1], ast.Constant)
                    and n.value.elts[1].value == 1):
                pairs.add(target)
        if not pairs:
            continue
        if not any(
            isinstance(n, ast.Call) and _name(n.func) in ladders
            and len(n.args) == 2 and _name(n.args[0]) in pairs
            and _name(n.args[1]) == arguments[1]
            for n in ast.walk(fn)
        ):
            continue
        if any(
            isinstance(n, ast.Return)
            and any(isinstance(c, ast.Call) and _name(c.func) == "pow"
                    and len(c.args) == 3
                    and isinstance(c.args[1], ast.UnaryOp)
                    and isinstance(c.args[1].op, ast.USub)
                    and isinstance(c.args[1].operand, ast.Constant)
                    and c.args[1].operand.value == 1
                    for c in ast.walk(n))
            for n in ast.walk(fn)
        ):
            return fn.name
    return None


def _source_profile(document):
    source = document.text
    if not source or len(source) > _MAX_SOURCE:
        return None
    tree = parse_python(document)
    if tree is None:
        return None
    assignments = {
        stmt.targets[0].id: stmt.value for stmt in tree.body
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
    }
    constants = {
        name: _constant(value, assignments)
        for name, value in assignments.items()
    }
    wrapper = _x_only_source(tree)
    if wrapper is None:
        return None
    fn = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == wrapper
    )
    moduli = {
        _name(node.right)
        for node in ast.walk(fn)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
        and _name(node.right) in constants
    }
    primes = [
        (name, value) for name, value in constants.items()
        if name in moduli and value is not None
        and 16 <= value.bit_length() <= 512 and value % 2 == 1
    ]
    if len(primes) != 1:
        return None
    modulus_name, q = primes[0]
    operations = [
        fn for fn in tree.body if isinstance(fn, ast.FunctionDef)
        and any(isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow)
                for node in ast.walk(fn))
        and any(isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult)
                for node in ast.walk(fn))
    ]
    curve_constants = {
        name: value for name, value in constants.items()
        if value is not None and 0 <= value <= 1 << 20
        and name != modulus_name
        and any(any(isinstance(node, ast.Name) and node.id == name
                    for node in ast.walk(fn)) for fn in operations)
    }
    if len(curve_constants) != 2:
        return None
    # Identify a in (X**2 - a*Z**2), not in an enclosing square.
    first_coefficient = set()
    for operation in operations:
        for expression in ast.walk(operation):
            if (isinstance(expression, ast.BinOp)
                    and isinstance(expression.op, ast.Sub)
                    and isinstance(expression.left, ast.BinOp)
                    and isinstance(expression.left.op, ast.Pow)
                    and isinstance(expression.left.left, ast.Name)
                    and isinstance(expression.right, ast.BinOp)
                    and isinstance(expression.right.op, ast.Mult)):
                first_coefficient.update(
                    child.id for child in ast.walk(expression.right)
                    if isinstance(child, ast.Name)
                    and child.id in curve_constants
                )
    if len(first_coefficient) != 1:
        return None
    a_name = next(iter(first_coefficient))
    a = curve_constants[a_name]
    b = next(value for name, value in curve_constants.items()
             if name != a_name)
    if (4 * a**3 + 27 * b**2) % q == 0:
        return None
    prompts = {
        node.args[0].value for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _name(node.func) == "input"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }
    if len(prompts) != 1:
        return None
    # The adversarial coordinate must reach the same scalar wrapper.
    interactive = False
    for loop in ast.walk(tree):
        if not isinstance(loop, ast.While):
            continue
        inputs = {
            _name(stmt.targets[0])
            for stmt in ast.walk(loop)
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
            and isinstance(stmt.value, ast.Call)
            and _name(stmt.value.func) == "int"
            and any(isinstance(n, ast.Call) and _name(n.func) == "input"
                    for n in ast.walk(stmt.value))
        }
        if any(isinstance(n, ast.Call) and _name(n.func) == wrapper
               and n.args and _name(n.args[0]) in inputs
               for n in ast.walk(loop)):
            interactive = True
    if not interactive:
        return None
    # An order published in a source docstring is optional information;
    # without it the analyzer still reports the issue but solving needs
    # an independent point-counting backend.
    orders = re.findall(
        r"(?m)^\s*(?:n|order|curve_order)\s*=\s*(\d{5,160})\s*$",
        source,
    )
    order = int(orders[0]) if len(orders) == 1 else None
    prefix = None
    for fn in tree.body:
        if isinstance(fn, ast.FunctionDef):
            for expression in ast.walk(fn):
                if (isinstance(expression, ast.Call)
                        and isinstance(expression.func, ast.Attribute)
                        and expression.func.attr in ("removeprefix", "lstrip")
                        and len(expression.args) == 1
                        and isinstance(expression.args[0], ast.Constant)
                        and isinstance(expression.args[0].value, str)
                        and expression.args[0].value.endswith("{")):
                    prefix = expression.args[0].value
    return TwistOracle(q, a, b, order, next(iter(prompts)), prefix, "}")


def extract_instance(documents: Sequence[Document]):
    matches = [
        profile for doc in documents
        if (profile := _source_profile(doc)) is not None
    ]
    return matches[0] if len(matches) == 1 else None


class Curve:
    def __init__(self, p, a, b):
        self.p, self.a, self.b = p, a % p, b % p

    def rhs(self, x):
        return (x*x*x + self.a*x + self.b) % self.p

    def neg(self, point):
        return None if point is None else (point[0], -point[1] % self.p)

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        p = self.p
        x, y = P
        xx, yy = Q
        if x == xx and (y + yy) % p == 0:
            return None
        if P == Q:
            if y == 0:
                return None
            slope = (3*x*x + self.a) * pow(2*y, -1, p) % p
        else:
            slope = (yy-y) * pow(xx-x, -1, p) % p
        new_x = (slope*slope - x - xx) % p
        return new_x, (slope*(x-new_x)-y) % p

    def mul(self, point, scalar):
        if scalar < 0:
            return self.mul(self.neg(point), -scalar)
        result = None
        while scalar:
            if scalar & 1:
                result = self.add(result, point)
            point = self.add(point, point)
            scalar >>= 1
        return result


def _nonsquare(p):
    for value in range(2, 100):
        if pow(value, (p-1)//2, p) == p-1:
            return value
    raise RuntimeError("no bounded quadratic nonresidue")


def _crt(congruences):
    result, modulus = 0, 1
    for residue, factor in congruences:
        result += modulus * (
            (residue-result) * pow(modulus, -1, factor) % factor
        )
        modulus *= factor
        result %= modulus
    return result, modulus


def _bsgs(curve, base, target, order, *, step_limit=500_000):
    if order == 1:
        return 0
    step = math.isqrt(order)+1
    if step > step_limit:
        raise RuntimeError("subgroup DLP exceeds bounded baby-step budget")
    baby = {}
    point = None
    for j in range(step):
        baby.setdefault(point, j)
        point = curve.add(point, base)
    step_point = curve.mul(base, -step)
    point = target
    for i in range(step+1):
        if point in baby:
            candidate = i*step+baby[point]
            if candidate < order and curve.mul(base, candidate) == target:
                return candidate
        point = curve.add(point, step_point)
    raise RuntimeError("no subgroup discrete logarithm matches target")


def twist_generator(model, factors):
    """Find a full-order twist point using *derived* parameters only."""
    from sympy import sqrt_mod
    q, a, b = model.field_prime, model.curve_a, model.curve_b
    twist_order = 2*(q+1)-model.curve_order
    nonsquare = _nonsquare(q)
    twist = Curve(q, a*nonsquare*nonsquare, b*nonsquare**3)
    for input_x in range(1, 4096):
        rhs = (input_x**3 + a*input_x + b) % q
        if rhs == 0 or pow(rhs, (q-1)//2, q) != q-1:
            continue
        X = nonsquare*input_x % q
        y = sqrt_mod(twist.rhs(X), q)
        if y is None:
            continue
        point = X, int(y)
        if twist.mul(point, twist_order) is not None:
            continue
        if all(twist.mul(point, twist_order//int(p)) is not None
               for p in factors):
            return twist, nonsquare, point, input_x
    raise RuntimeError("no full-order twist generator in bounded search")


def recover_residue(model, oracle_x, *, max_bsgs_steps=500_000):
    from sympy import factorint, isprime, sqrt_mod
    q = model.field_prime
    if not isprime(q):
        raise RuntimeError("the source field modulus is not prime")
    if model.curve_order is None or not 1 <= model.curve_order <= 2*q+2:
        raise RuntimeError("curve order is missing; point counting needed")
    order = 2*(q+1)-model.curve_order
    factors = factorint(order, limit=1_000_000)
    if math.prod(int(p)**int(e) for p,e in factors.items()) != order:
        raise RuntimeError("twist order factorization is incomplete")
    curve, nonsquare, point, input_x = twist_generator(model, factors)
    X = nonsquare*(oracle_x % q) % q
    Y = sqrt_mod(curve.rhs(X), q)
    if Y is None:
        raise RuntimeError("oracle reply does not lie on the twist")
    target = X, int(Y)
    congruences = []
    for factor, exponent in sorted(factors.items()):
        component = int(factor)**int(exponent)
        H = curve.mul(point, order//component)
        T = curve.mul(target, order//component)
        residue = _bsgs(curve, H, T, component,
                        step_limit=max_bsgs_steps)
        congruences.append((residue, component))
    residue, modulus = _crt(congruences)
    if modulus != order or curve.mul(point, residue) != target:
        raise RuntimeError("twist discrete-log certificate failed")
    return residue, modulus, input_x


def candidate_texts(residue, modulus, prefix, suffix,
                    *, max_length=24, max_lifts=500_000):
    """Enumerate only bounded representatives; never guess missing bits."""
    candidates = set()
    for representative in set((residue, -residue % modulus)):
        for length in range(1, max_length+1):
            max_value = 1 << (8*length)
            if representative >= max_value:
                continue
            count = (max_value-1-representative)//modulus+1
            if count > max_lifts:
                continue
            for k in range(count):
                value = representative+k*modulus
                if value.bit_length() > 8*length:
                    break
                raw = value.to_bytes(length, "big")
                if raw[0] == 0 or not all(32 <= c <= 126 for c in raw):
                    continue
                decoded = raw.decode("ascii")
                wrapped = (prefix or "") + decoded + suffix
                if _FLAG.fullmatch(wrapped):
                    candidates.add(wrapped)
    return sorted(candidates)


def recover_flag(documents: Sequence[Document], host: str, port: int,
                 *, timeout=30.0):
    from sympy import factorint, isprime
    model = extract_instance(documents)
    if model is None:
        raise ValueError("no source-proven arbitrary-x scalar oracle")
    q = model.field_prime
    if not isprime(q) or model.curve_order is None:
        raise RuntimeError("twist attack requires a prime field and curve order")
    order = 2*(q+1)-model.curve_order
    factors = factorint(order, limit=1_000_000)
    _, _, _, input_x = twist_generator(model, factors)
    prompt = model.input_prompt.encode()
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        response = bytearray()
        while prompt not in response and len(response) < 16384:
            packet = conn.recv(4096)
            if not packet:
                raise ConnectionError("no coordinate prompt")
            response.extend(packet)
        if prompt not in response:
            raise RuntimeError("unexpected oracle prompt")
        conn.sendall(f"{input_x}\n".encode("ascii"))
        response = bytearray(response.split(prompt, 1)[1])
        while prompt not in response and len(response) < 16384:
            packet = conn.recv(4096)
            if not packet:
                break
            response.extend(packet)
    outputs = [
        int(line.strip())
        for line in response.decode("utf-8", "replace").splitlines()
        if line.strip().isdigit()
    ]
    if len(outputs) != 1:
        raise RuntimeError("no unique integer oracle response")
    residue, modulus, _ = recover_residue(model, outputs[0])
    possibilities = candidate_texts(
        residue, modulus, model.flag_prefix, model.flag_suffix,
    )
    if len(possibilities) != 1:
        raise RuntimeError(
            "twist reveals a scalar residue only: "
            f"{len(possibilities)} bounded printable candidates; "
            "full secret is not uniquely certified"
        )
    return possibilities[0]
