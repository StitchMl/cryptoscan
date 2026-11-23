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
import time

from sage.all import GF, PolynomialRing, ZZ, crt, matrix


class LatticeBackendError(RuntimeError):
    """The external reduction backend could not complete the operation."""


class ComponentNotRecovered(RuntimeError):
    """The reduced lattice did not expose a verified short component."""


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


def _fast_reducer():
    """Select installed lattice backends without importing user source."""
    custom = os.environ.get("CRYPTOSCAN_FLATTER")
    if custom:
        return [custom], "flatter"
    flatter = shutil.which("flatter")
    if flatter:
        return [flatter], "flatter"
    fplll = shutil.which("fplll")
    if fplll:
        return [fplll, "-a", "lll"], "fplll"
    return None, "sage-lll"


def _reduce_lattice(basis, deadline=None):
    """Prefer an installed fast lattice reducer; fall back to Sage LLL."""
    command, _ = _fast_reducer()
    if command is not None:
        serialized = "[[" + "]\n[".join(
            " ".join(map(str, row)) for row in basis
        ) + "]]"
        try:
            remaining = (
                240 if deadline is None
                else max(1, min(240, deadline - time.monotonic()))
            )
            completed = subprocess.run(
                command, input=serialized, text=True,
                capture_output=True, check=True, timeout=remaining,
            )
            entries = [
                int(value) for value in re.findall(r"-?\d+", completed.stdout)
            ]
            if len(entries) == basis.nrows() * basis.ncols():
                return matrix(ZZ, basis.nrows(), basis.ncols(), entries)
        except (OSError, subprocess.SubprocessError) as exc:
            if basis.nrows() >= 85 and os.environ.get("CRYPTOSCAN_SLOW_LLL") != "1":
                raise LatticeBackendError(
                    f"fast lattice reducer failed on {basis.nrows()}x{basis.ncols()} "
                    f"matrix: {type(exc).__name__}: {exc}. "
                    "Check flatter installation and its runtime libraries in WSL."
                ) from exc
    if basis.nrows() >= 85 and os.environ.get("CRYPTOSCAN_SLOW_LLL") != "1":
        raise LatticeBackendError(
            "No working accelerated lattice reducer (flatter or fplll). "
            "In Ubuntu WSL run 'sudo apt install fplll-tools' or install flatter. "
            "Use CRYPTOSCAN_SLOW_LLL=1 inside WSL only to opt into slow Sage LLL."
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


def _recover_component(a, t, factor, modulus, embedding, shortened, deadline=None):
    basis, removed, divisor = _lattice_for_quotient(
        a, t, factor, modulus, embedding, shortened,
    )
    degree = divisor.degree()
    reduced = _reduce_lattice(basis, deadline)
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
    raise ComponentNotRecovered(
        f"lattice did not recover short component (degree {degree})"
    )


def _candidate_component(a, t, factor, modulus, deadline=None, validator=None):
    degree = factor.degree()
    # A q-sized embedding can bury the desired affine-coset vector among
    # shorter homogeneous vectors. Try a balanced, parameter-derived scale
    # before the legacy q-sized embedding. No challenge constants are used.
    balanced = max(1, math.isqrt(modulus) // max(1, math.isqrt(degree)))
    strengths = list(dict.fromkeys((balanced, modulus)))
    strategies = [
        (shortened, embedding)
        for embedding in strengths
        for shortened in (True, False)
    ]
    for shortened, embedding in strategies:
        if deadline is not None and time.monotonic() >= deadline:
            raise LatticeBackendError(
                "Cyclic-ring recovery exhausted the allotted lattice time budget"
            )
        try:
            candidate = _recover_component(
                a, t, factor, modulus, embedding, shortened, deadline,
            )
            return validator(candidate) if validator is not None else candidate
        except ComponentNotRecovered:
            continue
    raise ComponentNotRecovered(
        f"No verified short component modulo a factor of degree {degree}"
    )




def _projected_coefficient_limits(factor, dimension, secret_bound, modulus):
    """Exact coordinate bounds for a short polynomial reduced modulo factor.

    Every source coefficient contributes at most secret_bound times the
    absolute coefficient of x**i mod factor. Summing these contributions
    gives a necessary bound for BOTH the secret and error residues.
    Operates on the integral factor, not coefficients reduced modulo q.
    """
    degree = int(factor.degree())
    if degree < 1 or dimension < degree:
        raise ValueError("invalid quotient projection dimensions")
    coefficients = [int(factor[i]) for i in range(degree)]
    if int(factor[degree]) != 1:
        raise ValueError("expected monic integral factor")
    running = [1] + [0] * (degree - 1)
    totals = [0] * degree
    for _ in range(dimension):
        for index, value in enumerate(running):
            totals[index] += abs(value)
        lead = running[-1]
        running = [0] + running[:-1]
        if lead:
            running = [
                value - lead * coefficients[index]
                for index, value in enumerate(running)
            ]
    return [
        min(modulus // 2, int(secret_bound) * total)
        for total in totals
    ]


def _verified_projected_candidate(a, t, factor, modulus, candidate,
                                  dimension, coefficient_bound):
    """Reject locally plausible vectors inconsistent with short input keys."""
    limits = _projected_coefficient_limits(
        factor, dimension, coefficient_bound, modulus,
    )
    divisor = a.parent()(factor)
    noise = (t - a * candidate) % divisor
    if any(
        abs(_center(candidate[index], modulus)) > limit
        or abs(_center(noise[index], modulus)) > limit
        for index, limit in enumerate(limits)
    ):
        raise ComponentNotRecovered(
            f"candidate violates source-derived short projection bounds "
            f"(factor degree {int(factor.degree())})"
        )
    return candidate


def _recover_factor_components(a, t, factor, modulus, deadline=None,
                               dimension=None, coefficient_bound=None):
    """Recover a quotient or refine a failed composite quotient.

    Grouped factors reduce the number of lattice calls, but their coefficient
    growth can obscure a short vector. An unsuccessful composite quotient is
    therefore split into its integral irreducible factors, without relying on
    any challenge-specific factorization or coefficients.
    """
    try:
        if dimension is not None and coefficient_bound is not None:
            def validate(candidate):
                return _verified_projected_candidate(
                    a, t, factor, modulus, candidate, dimension,
                    coefficient_bound,
                )
            candidate = _candidate_component(
                a, t, factor, modulus, deadline, validator=validate,
            )
        else:
            candidate = _candidate_component(a, t, factor, modulus, deadline)
        return [(a.parent()(factor), candidate)]
    except ComponentNotRecovered as exc:
        factors = [
            divisor for divisor, multiplicity in factor.factor()
            for _ in range(multiplicity)
        ]
        if len(factors) <= 1:
            raise ComponentNotRecovered(
                f"No verified component for irreducible factor of degree "
                f"{int(factor.degree())}: {exc}"
            ) from exc
        print(
            f"[CYCLIC-LATTICE] refining failed composite factor "
            f"degree {int(factor.degree())} into "
            f"{len(factors)} integral factors",
            file=sys.stderr, flush=True,
        )
        recovered = []
        for divisor in factors:
            if deadline is not None and time.monotonic() >= deadline:
                raise LatticeBackendError(
                    "Cyclic-ring recovery exhausted the allotted lattice "
                    "time budget during factor refinement"
                )
            recovered.extend(_recover_factor_components(
                a, t, divisor, modulus, deadline,
                dimension=dimension, coefficient_bound=coefficient_bound,
            ))
        return recovered


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
    # High-degree factors are treated separately to keep their residues
    # sparse. Pack the smaller coprime factors into balanced quotient rings,
    # reducing the number of expensive lattice jobs without relying on
    # precomputed factors for any particular ring dimension.
    largest = max(factor.degree() for factor in factors)
    threshold = max(2, largest // 2)
    major = [factor for factor in factors if factor.degree() >= threshold]
    minor = [factor for factor in factors if factor.degree() < threshold]
    capacity = min(96, max(32, 3 * largest // 4))
    packed = _factor_groups(minor, capacity) if minor else []
    result = major + packed
    if len(result) == 1:
        return factors
    return sorted(result, key=lambda factor: factor.degree(), reverse=True)


def _preflight(message):
    dimension = int(message["dimension"])
    if not 8 <= dimension <= 1024:
        raise ValueError("unsupported ring dimension")
    groups = _integral_factor_groups(dimension)
    max_degree = max(int(factor.degree()) for factor in groups)
    command, backend = _fast_reducer()
    if max_degree >= 42 and command is None and os.environ.get("CRYPTOSCAN_SLOW_LLL") != "1":
        raise LatticeBackendError(
            f"Cyclic-ring lattice factor degree {max_degree} needs an "
            "accelerated reducer. In Ubuntu WSL install 'fplll-tools' "
            "with 'sudo apt install fplll-tools', or build flatter "
            "(https://github.com/keeganryan/flatter). Verify from "
            "PowerShell with 'wsl --exec which fplll' or "
            "'wsl --exec which flatter'. Set CRYPTOSCAN_SLOW_LLL=1 "
            "inside WSL only to opt into a potentially very slow fallback."
        )
    return {"backend": backend,
            "max_factor_degree": max_degree}


def _recover(message):
    ring, q, n, bound, a, t = _public_ring(message)
    full = ring.gen() ** n - 1
    groups = _integral_factor_groups(n)
    budget = int(message.get("budget_seconds", 540))
    if not 10 <= budget <= 3600:
        raise ValueError("invalid lattice time budget")
    deadline = time.monotonic() + budget
    components = []
    for position, factor in enumerate(groups, start=1):
        print(
            f"[CYCLIC-LATTICE] component {position}/{len(groups)}, "
            f"factor degree {factor.degree()}",
            file=sys.stderr, flush=True,
        )
        components.extend(
            _recover_factor_components(
                a, t, factor, q, deadline,
                dimension=n, coefficient_bound=bound,
            )
        )
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
        "factor_degrees": [int(factor.degree()) for factor, _ in components],
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
