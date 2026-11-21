"""Sage worker for short secret recovery over reducible cyclic polynomial rings.

The worker receives JSON parameters, never imports or executes input source,
and discovers polynomial factors from the algebraic structure at runtime.
"""
from __future__ import annotations

import json
import os
import math
import re
import shutil
import subprocess
import sys

from sage.all import GF, PolynomialRing, ZZ, crt, matrix


def _center(value, modulus):
    number = int(value) % modulus
    return number if number <= modulus // 2 else number - modulus


def _factor_groups(factors, maximum_degree):
    """Pack arbitrary integral factors; never embed a fixed factorization."""
    groups = []
    for factor in sorted(factors, key=lambda item: item.degree(), reverse=True):
        degree = factor.degree()
        target = next(
            (group for group in groups if group[1] + degree <= maximum_degree),
            None,
        )
        if target is None:
            groups.append([[factor], degree])
        else:
            target[0].append(factor)
            target[1] += degree
    return [math.prod(group) for group, _ in groups]


def _reduce_lattice(basis):
    """Prefer an installed fast lattice reducer; fall back to Sage LLL."""
    backend = os.environ.get("CRYPTOSCAN_FLATTER") or shutil.which("flatter")
    if backend is not None:
        serialized = "[[" + "]\n[".join(
            " ".join(map(str, row)) for row in basis
        ) + "]]"
        try:
            completed = subprocess.run(
                [backend], input=serialized, text=True,
                capture_output=True, check=True, timeout=240,
            )
            entries = [
                int(value) for value in re.findall(r"-?\d+", completed.stdout)
            ]
            if len(entries) == basis.nrows() * basis.ncols():
                return matrix(ZZ, basis.nrows(), basis.ncols(), entries)
        except (OSError, subprocess.SubprocessError):
            pass
    if basis.nrows() >= 85 and os.environ.get("CRYPTOSCAN_SLOW_LLL") != "1":
        raise RuntimeError(
            "Fast lattice reducer 'flatter' is not installed or failed. "
            "Large cyclic-ring lattices require flatter for reliable runtime. "
            "Install it in WSL, then verify 'wsl --exec which flatter'. "
            "Set CRYPTOSCAN_SLOW_LLL=1 inside WSL to explicitly permit "
            "the slower Sage LLL fallback."
        )
    return basis.LLL(delta=0.99)


def _projection(polynomial, factor, dimension, modulus):
    residue = polynomial % factor
    return [_center(residue[index], modulus) for index in range(dimension)]


def _lattice_for_quotient(a, t, factor, modulus, embedding, shortened):
    """Embedded CVP lattice for a*s + e = t, optionally fewer error columns."""
    polynomial_ring = a.parent()
    divisor = polynomial_ring(factor)
    degree = divisor.degree()
    size = 2 * degree + 1
    basis = matrix(ZZ, size, size)
    for index in range(degree):
        basis[index, index] = 1
        for column, value in enumerate(_projection(
                -a * polynomial_ring.gen() ** index, divisor, degree, modulus)):
            basis[index, degree + column] = value
        basis[degree + index, degree + index] = modulus
    for index, value in enumerate(_projection(t, divisor, degree, modulus)):
        basis[2 * degree, degree + index] = value
    basis[2 * degree, 2 * degree] = embedding
    removed = degree // 3 if shortened else 0
    if removed:
        keep = list(range(degree)) + list(range(degree + removed, size))
        basis = basis.matrix_from_rows_and_columns(keep, keep)
    return basis, removed, divisor


def _recover_component(a, t, factor, modulus, embedding, shortened):
    basis, removed, divisor = _lattice_for_quotient(
        a, t, factor, modulus, embedding, shortened,
    )
    degree = divisor.degree()
    reduced = _reduce_lattice(basis)
    coefficient_limit = max(32, 4 * math.isqrt(modulus))
    for row in reduced.rows():
        if abs(int(row[-1])) != embedding:
            continue
        sign = 1 if row[-1] > 0 else -1
        secret = a.parent()([int(sign * value) for value in row[:degree]])
        noise = (t - a * secret) % divisor
        if any(
            abs(_center(secret[index], modulus)) > coefficient_limit
            or abs(_center(noise[index], modulus)) > coefficient_limit
            for index in range(degree)
        ):
            continue
        if all(
            _center(noise[index], modulus)
            == sign * int(row[degree + index - removed])
            for index in range(removed, degree)
        ):
            return secret
    raise RuntimeError(f"lattice did not recover short component (degree {degree})")


def _candidate_component(a, t, factor, modulus):
    for shortened in (True, False):
        # The modulus-sized embedding is the natural first choice: it
        # keeps the secret/error solution in the distinguished tail row.
        for embedding in (modulus, 128, 64, 32):
            try:
                return _recover_component(
                    a, t, factor, modulus, embedding, shortened,
                )
            except RuntimeError:
                continue
    raise RuntimeError(
        f"lattice reduction did not recover short secret modulo degree-{factor.degree()} factor"
    )


def _public_ring(message):
    size, modulus = int(message["dimension"]), int(message["modulus"])
    bound = int(message["coefficient_bound"])
    if not 8 <= size <= 1024 or not 3 <= modulus < (1 << 40):
        raise ValueError("invalid cyclic ring dimensions")
    if not ZZ(modulus).is_prime() or not 0 < bound <= 8:
        raise ValueError("expected a prime modulus and small secret coefficients")
    public_a = [int(value) for value in message["public_a"]]
    public_t = [int(value) for value in message["public_t"]]
    if len(public_a) != size or len(public_t) != size:
        raise ValueError("wrong number of public coefficients")
    if any(not 0 <= value < modulus for value in public_a + public_t):
        raise ValueError("invalid public polynomial coefficient")
    ring = PolynomialRing(GF(modulus), "x")
    return ring, modulus, size, bound, ring(public_a), ring(public_t)


def _integral_factor_groups(dimension):
    ring = PolynomialRing(ZZ, "x")
    polynomial = ring.gen() ** dimension - 1
    factors = [
        divisor for divisor, count in polynomial.factor()
        for _ in range(count)
    ]
    if len(factors) < 2:
        raise ValueError("polynomial not decomposable over integers")
    if any(divisor.degree() > 128 for divisor in factors):
        raise ValueError("factor degree exceeds supported lattice dimension")
    # Work in irreducible integer factors individually: arbitrary products
    # may amplify projected small coefficients and reduce lattice reliability.
    return factors


def _preflight(message):
    dimension = int(message["dimension"])
    if not 8 <= dimension <= 1024:
        raise ValueError("unsupported ring dimension")
    groups = _integral_factor_groups(dimension)
    max_degree = max(factor.degree() for factor in groups)
    backend = os.environ.get("CRYPTOSCAN_FLATTER") or shutil.which("flatter")
    if max_degree >= 42 and not backend and os.environ.get("CRYPTOSCAN_SLOW_LLL") != "1":
        raise RuntimeError(
            "The cyclic ring has a high-degree lattice component "
            f"(degree {max_degree}); fast reducer 'flatter' is required "
            "for this time-limited attack. Install flatter inside Ubuntu "
            "WSL (https://github.com/keeganryan/flatter), then run "
            "'wsl --exec which flatter' from PowerShell. "
            "Sage LLL fallback can be enabled with CRYPTOSCAN_SLOW_LLL=1 "
            "inside the WSL environment, but may exceed the service timeout."
        )
    return {"backend": "flatter" if backend else "sage-lll",
            "max_factor_degree": max_degree}


def _recover(message):
    ring, q, n, bound, a, t = _public_ring(message)
    full = ring.gen() ** n - 1
    groups = _integral_factor_groups(n)
    components = [
        (ring(factor), _candidate_component(a, t, factor, q))
        for factor in groups
    ]
    moduli = [modulus for modulus, _ in components]
    if any(
        moduli[i].gcd(moduli[j]).degree() > 0
        for i in range(len(moduli)) for j in range(i + 1, len(moduli))
    ):
        raise ValueError("integral factors become noncoprime modulo q")
    recovered = crt(
        [residue for _, residue in components], moduli,
    ) % full
    noise = (t - a * recovered) % full
    secret_coefficients = [int(recovered[index]) for index in range(n)]
    error_coefficients = [int(noise[index]) for index in range(n)]
    allowed = {0, *range(1, bound + 1), *range(q - bound, q)}
    if any(value not in allowed
           for value in secret_coefficients + error_coefficients):
        raise RuntimeError("CRT result is not a short private key")
    if (a * recovered + noise - t) % full != 0:
        raise RuntimeError("recovered key violates public ring equation")
    return {
        "secret": secret_coefficients,
        "error": error_coefficients,
        "factor_degrees": [factor.degree() for factor in groups],
    }


def main():
    for line in sys.stdin:
        try:
            request = json.loads(line)
            mode = request.get("mode")
            if mode == "preflight":
                response = _preflight(request)
            elif mode == "recover_short_secret":
                _preflight(request)
                response = _recover(request)
            else:
                raise ValueError("unsupported Sage operation")
        except Exception as exc:
            response = {"error": f"{type(exc).__name__}: {exc}"}
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
