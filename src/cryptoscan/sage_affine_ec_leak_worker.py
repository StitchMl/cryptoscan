"""Sage worker for source-derived affine elliptic-curve point leakage.

All parameters and observations are received as JSON. No untrusted source
is evaluated. Recovery is verified against every observed combination.
"""
from __future__ import annotations

import json
import math
import sys

from sage.all import EllipticCurve, GF, ZZ, proof
from sage.groups.generic import discrete_log


def _recover(message):
    prime = int(message["prime"])
    a = int(message["a"])
    b = int(message["b"])
    rows = message["rows"]
    if not (5 <= prime.bit_length() <= 512 and ZZ(prime).is_prime()):
        raise ValueError("expected a supported prime finite field")
    if not (0 <= a < prime and 0 <= b < prime):
        raise ValueError("invalid Weierstrass coefficients")
    if not 3 <= len(rows) <= 512:
        raise ValueError("expected multiple public affine point combinations")
    proof.arithmetic(False)
    curve = EllipticCurve(GF(prime), [a, b])
    samples = []
    for row in rows:
        if len(row) != 3 or len(row[2]) != 3:
            raise ValueError("malformed EC point combination")
        u, v = int(row[0]), int(row[1])
        x, y, z = map(int, row[2])
        if any(not 0 <= w < prime for w in (x, y, z)):
            raise ValueError("out-of-field projective point coordinate")
        samples.append((u, v, curve([x, y, z])))
    group_order = int(curve.cardinality())
    if group_order <= 1:
        raise ValueError("invalid elliptic curve group order")
    # Invert a 2-by-2 public scalar matrix in the entire EC group.
    # A unit determinant modulo the group order gives unique P and Q.
    recovered = None
    for index, (u, v, point) in enumerate(samples[:-1]):
        for w, z, other in samples[index + 1:]:
            determinant = (u * z - w * v) % group_order
            if math.gcd(determinant, group_order) != 1:
                continue
            inverse = pow(determinant, -1, group_order)
            base = inverse * (z * point - v * other)
            hidden = inverse * (u * other - w * point)
            if base.is_zero():
                continue
            if all(u0 * base + v0 * hidden == observed
                   for u0, v0, observed in samples):
                recovered = (base, hidden)
                break
        if recovered is not None:
            break
    if recovered is None:
        raise ValueError("no invertible pair of public affine point combinations")
    base, hidden = recovered
    order = int(base.order())
    if order < 2:
        raise ValueError("degenerate recovered base point")
    factors = list(ZZ(order).factor())
    # Bounded generic discrete log; no assumption about specific curve primes.
    if any(int(p).bit_length() > 46 for p, _ in factors):
        raise ValueError("subgroup order is not sufficiently smooth for bounded ECDLP")
    scalar = int(discrete_log(hidden, base, ord=order, operation="+"))
    if scalar * base != hidden:
        raise RuntimeError("discrete logarithm did not verify")
    if not all(u * base + v * (scalar * base) == point
               for u, v, point in samples):
        raise RuntimeError("recovered scalar fails independent public equations")
    return {"scalar": scalar, "subgroup_bits": order.bit_length(),
            "factor_count": len(factors)}


def main():
    for line in sys.stdin:
        try:
            message = json.loads(line)
            if message.get("mode") != "recover_affine_ec_log":
                raise ValueError("unsupported Sage operation")
            result = _recover(message)
        except Exception as exc:
            result = {"error": f"{type(exc).__name__}: {exc}"}
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
