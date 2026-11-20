"""Generic Sage worker for an unsound pairing-based confirmation proof.

Accepts public curve parameters and public protocol data as JSON. It neither
executes inspected source nor stores any challenge-specific constants.
"""
from __future__ import annotations

import ast
import hashlib
import json
import sys

from sage.all import EllipticCurve, GF, PolynomialRing


def _safe_field_expression(source, symbols):
    expression = ast.parse(source.replace("^", "**"), mode="eval").body

    def evaluate(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name) and node.id in symbols:
            return symbols[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -evaluate(node.operand)
        if isinstance(node, ast.BinOp):
            left, right = evaluate(node.left), evaluate(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Pow) and isinstance(node.right, ast.Constant):
                power = node.right.value
                if type(power) is int and 0 <= power <= 32:
                    return left ** power
        raise ValueError("unsupported finite-field expression")

    return evaluate(expression)


class PairingProof:
    def __init__(self, payload):
        p, b, k = int(payload["prime"]), int(payload["b"]), int(payload["k"])
        if p <= 3 or p.bit_length() > 512 or k < 2 or k > 24:
            raise ValueError("unsupported curve arithmetic")
        self.field = GF(p)
        self.g1 = EllipticCurve(self.field, [0, b])
        self.modulus = self.g1.order()
        self.trace = self.g1.trace_of_frobenius()
        self.degree = k
        self.p = p
        self.f2 = GF(p ** 2, "a")
        self.a = self.f2.gen()
        c1, c0 = map(int, payload["eps"])
        self.epsilon = self.f2(c1) * self.a + self.f2(c0)
        self.g2 = EllipticCurve(self.f2, [0, self.f2(b) / self.epsilon])
        self.cofactor = self.g2.order() // self.modulus
        ring = PolynomialRing(self.f2, "u")
        self.f12 = (ring.gen() ** 6 - self.epsilon).root_field("z")
        self.z = self.f12.gen()
        self.e12 = EllipticCurve(self.f12, [0, b])
        params = payload["public"]
        self.P = self.g1([int(v) for v in params["P_G1"]])
        self.Q = self.g1([int(v) for v in params["Q"]])
        self.P2 = self.g2([self.element(v) for v in params["P_G2"]])
        self.message = payload["message"]
        self.target = self.hash_to_g2(payload["identity"])

    def element(self, expression):
        if not isinstance(expression, str) or len(expression) > 1024:
            raise ValueError("invalid public Fp2 coordinate")
        return self.f2(_safe_field_expression(expression, {"a": self.a}))

    def hash_to_g2(self, identity):
        seed = int.from_bytes(
            hashlib.sha256(identity.encode()).digest(), "big"
        ) % self.p
        origin = self.g2(0)
        for offset in range(1, 10000):
            try:
                point = self.cofactor * self.g2.lift_x(self.f2(seed + offset))
                if point != origin and self.modulus * point == origin:
                    return point
            except (ArithmeticError, ValueError, TypeError):
                continue
        raise ValueError("hash-to-curve did not find a subgroup point")

    def pairing(self, first, second):
        if first == self.g1(0) or second == self.g2(0):
            raise ValueError("pairing input is the identity point")
        x, y = second.xy()
        twisted = self.e12(self.z ** 2 * x, self.z ** 3 * y)
        return self.e12(first).ate_pairing(
            twisted, self.modulus, self.degree, self.trace, self.p,
        )

    def begin(self):
        digest = hashlib.sha256(self.message.encode()).digest()
        width = (self.p.bit_length() + 7) // 8
        message_hash = int.from_bytes(digest[:width], "big") % self.modulus
        if message_hash == 0:
            raise ValueError("invalid zero message hash")
        self.signature_point = self.target + message_hash * self.P2
        if self.signature_point == self.g2(0):
            raise ValueError("invalid signature point")
        return [list(map(int, self.Q.xy())),
                list(map(str, self.signature_point.xy()))]

    def challenge(self, point):
        challenge = self.g1([int(v) for v in point])
        r = self.pairing(challenge, self.P2)
        t = self.pairing(self.Q, self.P2) / self.pairing(self.P, self.target)
        if r == 1 or t == 1 or r ** self.modulus != 1 or t ** self.modulus != 1:
            raise ValueError("forgery left the expected pairing subgroup")
        return [str(t), str(r)]


def main():
    active = None
    for line in sys.stdin:
        try:
            message = json.loads(line)
            if message.get("mode") == "begin":
                active = PairingProof(message)
                result = {"signature": active.begin()}
            elif message.get("mode") == "challenge" and active is not None:
                result = {"response": active.challenge(message["point"])}
                active = None
            else:
                raise ValueError("unexpected pairing worker state")
        except Exception as exc:
            active = None
            result = {"error": f"{type(exc).__name__}: {exc}"}
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
