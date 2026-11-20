"""Generic SageMath worker for changing bases in unramified 2-adic rings.

Processes JSON over standard input/output; never evaluates submitted source
as executable Python. No parameters, messages or flags from a challenge.
"""
from __future__ import annotations

import ast
import json
import sys

from sage.all import GF, PolynomialRing, Zmod, matrix


def safe_expression(source, variables):
    expression = ast.parse(source.replace("^", "**"), mode="eval").body

    def parse(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name) and node.id in variables:
            return variables[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -parse(node.operand)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd):
            return parse(node.operand)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return parse(node.left) + parse(node.right)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
            return parse(node.left) - parse(node.right)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            return parse(node.left) * parse(node.right)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
            if (not isinstance(node.right, ast.Constant)
                    or type(node.right.value) is not int
                    or not 0 <= node.right.value <= 64):
                raise ValueError("invalid polynomial power")
            return parse(node.left) ** node.right.value
        raise ValueError("unsupported polynomial expression")

    return parse(expression)


class RingIsomorphism:
    def __init__(self, precision, degrees, printed):
        self.precision = precision
        self.degrees = degrees
        self.dimension = 1
        for degree in degrees:
            self.dimension *= degree
        if not 1 <= precision <= 128 or not 1 <= self.dimension <= 128:
            raise ValueError("unsupported extension dimensions")
        if len(printed) != len(degrees) + 1:
            raise ValueError("wrong number of polynomial definitions")
        self.base = Zmod(2 ** precision)
        flat_ring = PolynomialRing(self.base, "b0")
        flat_modulus = flat_ring(safe_expression(
            printed[-1], {"b0": flat_ring.gen()}))
        if flat_modulus.degree() != self.dimension or not flat_modulus.is_monic():
            raise ValueError("invalid flat extension polynomial")
        self.flat = flat_ring.quotient(flat_modulus, names="z")
        self.generator = self.flat.gen()
        binary_ring = PolynomialRing(GF(2), "x")
        binary_modulus = binary_ring([int(c) % 2 for c in flat_modulus.list()])
        self.field = GF(2 ** self.dimension, "alpha", modulus=binary_modulus)
        self.alpha = self.field.gen()

        roots = []
        for index, (degree, expression) in enumerate(zip(degrees, printed)):
            polynomial_ring = PolynomialRing(self.flat, "t")
            symbols = {}
            for previous, root in enumerate(roots):
                symbols[f"b{previous}"] = root
                symbols[f"b{previous}bar"] = root
                symbols[f"b{previous}_bar"] = root
            symbols[f"b{index}"] = polynomial_ring.gen()
            polynomial = polynomial_ring(safe_expression(expression, symbols))
            if polynomial.degree() != degree or not polynomial.is_monic():
                raise ValueError("invalid tower polynomial")
            roots.append(self._hensel_root(polynomial))

        basis = [self.flat.one()]
        for root, degree in zip(roots, degrees):
            basis = [entry * root ** exponent
                     for exponent in range(degree) for entry in basis]
        columns = [self._coordinates(value) for value in basis]
        self.change = matrix(self.base, self.dimension, self.dimension,
                             lambda i, j: columns[j][i])
        self.inverse = self.change.inverse()
        if self.inverse * self.change != matrix.identity(self.base, self.dimension):
            raise ValueError("basis matrix is not invertible")

    def _coordinates(self, element):
        coefficients = [int(x) for x in element.list()]
        return coefficients + [0] * (self.dimension - len(coefficients))

    def _residue(self, element):
        result = self.field.zero()
        for coefficient in reversed(self._coordinates(element)):
            result = result * self.alpha + (coefficient & 1)
        return result

    def _lift(self, element):
        return self.flat([int(c) for c in element.polynomial().list()])

    def _hensel_root(self, polynomial):
        field_ring = PolynomialRing(self.field, "w")
        modulo_two = field_ring([
            self._residue(coefficient) for coefficient in polynomial.list()
        ])
        roots = modulo_two.roots(multiplicities=False)
        if not roots:
            raise ValueError("tower polynomial has no root in flat residue field")
        root = self._lift(roots[0])
        derivative = polynomial.derivative()
        for _ in range(self.precision.bit_length() + 2):
            if polynomial(root) == 0:
                break
            root -= polynomial(root) * (~derivative(root))
        if polynomial(root) != 0:
            raise ValueError("Hensel root lifting failed")
        return root

    def to_flat(self, point):
        if len(point) != self.dimension:
            raise ValueError("invalid tower coordinate count")
        vector = matrix(self.base, self.dimension, 1, point)
        converted = (self.change * vector).column(0)
        return self._coordinates(self.flat(list(converted)))

    def to_tower(self, point):
        if len(point) != self.dimension:
            raise ValueError("invalid flat coordinate count")
        vector = matrix(self.base, self.dimension, 1, point)
        return [int(coefficient)
                for coefficient in (self.inverse * vector).column(0)]


def main():
    active = None
    for line in sys.stdin:
        try:
            message = json.loads(line)
            if message["mode"] == "begin":
                active = RingIsomorphism(
                    int(message["k"]), [int(x) for x in message["degrees"]],
                    list(message["polynomials"]))
                reply = {"point": active.to_flat([int(x) for x in message["point"]])}
            elif message["mode"] == "evaluate" and active is not None:
                reply = {"coefficients": active.to_tower(
                    [int(x) for x in message["point"]])}
                active = None
            else:
                raise ValueError("unexpected Sage operation")
        except Exception as exc:
            active = None
            reply = {"error": f"{type(exc).__name__}: {exc}"}
        print(json.dumps(reply), flush=True)


if __name__ == "__main__":
    main()
