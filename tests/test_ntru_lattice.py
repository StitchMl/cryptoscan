"""Independent NTRU sparse-key lattice tests, not tied to challenge values."""
from random import Random

import pytest
from sympy import Poly, invert, symbols

from cryptoscan.ntru_lattice import (
    binary_inverse, constrained_basis, cyclic_mul, solve,
)
from cryptoscan.ntru_workflow import ntru_lattice_workflow
from cryptoscan.parser import Document
from cryptoscan.scanner import scan


def synthetic(n=16, seed=87):
    rand = Random(seed)
    p, q, df, dg, dr = 2, 127, 3, 3, 2
    x = symbols("x")
    for _ in range(30):
        positions = set(rand.sample(range(n), df))
        f = [int(i in positions) for i in range(n)]
        positions = set(rand.sample(range(n), dg))
        g = [int(i in positions) for i in range(n)]
        positions = set(rand.sample(range(n), dr))
        r = [int(i in positions) for i in range(n)]
        try:
            finv = invert(
                Poly(sum(value * x**i for i, value in enumerate(f)), x, modulus=q),
                Poly(x**n - 1, x, modulus=q),
            )
        except Exception:
            continue
        h = cyclic_mul(g, [int(finv.nth(i)) % q for i in range(n)], q)
        plaintext = b"A"
        value = int.from_bytes(plaintext, "big")
        message = [(value >> i) & 1 for i in range(n)]
        ct = [(p * a + b) % q for a, b in zip(cyclic_mul(h, r, q), message)]
        return n, p, q, df, dg, dr, h, ct, plaintext, f
    raise AssertionError("failed to construct synthetic NTRU key")


def test_binary_inverse_roundtrip():
    f = [1, 1, 1] + [0] * 13
    inverse = binary_inverse(f)
    assert cyclic_mul(f, inverse, 2) == [1] + [0] * 15


def test_constrained_lattice_matches_public_key_weights():
    n, p, q, df, dg, dr, h, ct, plaintext, f = synthetic()
    basis = constrained_basis(h, q, df, dg)
    assert len(basis) == 2*n - 1
    assert len(basis[0]) == 2*n + 1
    assert basis[-1][-1] == 1


@pytest.mark.parametrize("n", [8, 16, 32])
def test_lattice_recovers_synthetic_plaintext(n):
    params = synthetic(n=n, seed=n+67)
    n, p, q, df, dg, dr, h, ct, plaintext, f = params
    result = solve(h, ct, n, p, q, df, dg, backend="sympy", progress=lambda _: None)
    assert any(item["plaintext"] == plaintext and item["public_relation_verified"]
               for item in result)


def test_lattice_refuses_mismatched_public_weights():
    n, p, q, df, dg, dr, h, ct, plaintext, f = synthetic()
    altered = h[:]
    altered[0] = (altered[0] + 1) % q
    with pytest.raises(ValueError, match="public key violates"):
        constrained_basis(altered, q, df, dg)


def test_no_large_degree_sympy_claim():
    with pytest.raises(RuntimeError, match="limited"):
        from cryptoscan.ntru_lattice import reduce_basis
        reduce_basis([0] * 64, 127, 3, 3, backend="sympy", progress=lambda _: None)


def test_source_guided_workflow_recovers_small_instance():
    n, p, q, df, dg, dr, h, ct, plaintext, f = synthetic()
    source = f"""
n,p,q,df,dg,dr=[{n},{p},{q},{df},{dg},{dr}]
R.<x> = ZZ[]
Rqn = Integers(q)[].quotient(x^n-1)
def random_poly(d):
    for i in sample(range(n),d):
        pass
def publickey_gen(f,g):
    h = Rqn(g)/Rqn(f)
    return h
def encrypt(h,m):
    r = random_poly(dr)
    c = p * h * Rqn(r) + Rqn(m)
    return c
"""
    documents = [
        Document("case/source.sage", source, None, "case", "source"),
        Document("case/output.txt", f"pk = {h}\nct = {ct}\n", None, "case", "output"),
    ]
    finding = next(item for item in scan(documents) if item.rule == "NTRU-X1-HAMMING-LEAK")
    answers = iter(["y", "0"])
    output = []
    ntru_lattice_workflow(finding, documents, lambda _: next(answers), output.append)
    assert any("Candidate 1: A" in line for line in output)
    assert any("Public-key relation verified: YES" in line for line in output)



@pytest.mark.parametrize("n", [8, 16, 32])
def test_native_flint_backend_recovers_independent_ntru_plaintexts(n):
    pytest.importorskip("flint")
    args = synthetic(n=n, seed=n + 67)
    degree, p, q, df, dg, dr, h, ct, plaintext, _ = args
    output = []
    candidates = solve(
        h, ct, degree, p, q, df, dg,
        backend="flint", progress=output.append,
    )
    assert any(item["plaintext"] == plaintext for item in candidates)
    assert any("FLINT native LLL" in line for line in output)


def test_native_windows_auto_selects_flint_and_rejects_bkz(monkeypatch):
    flint = pytest.importorskip("flint")
    from cryptoscan import ntru_lattice
    monkeypatch.setattr(ntru_lattice.sys, "platform", "win32")
    monkeypatch.setattr(ntru_lattice, "constrained_basis", lambda *args: [[1, 0], [0, 2]])
    lines = []
    reduced = ntru_lattice.reduce_basis(
        [0] * 64, 127, 3, 3, backend="auto", progress=lines.append,
    )
    assert len(reduced) == 2
    assert any("FLINT native LLL" in line for line in lines)
    with pytest.raises(RuntimeError, match="BKZ is available only"):
        ntru_lattice.reduce_basis([0] * 64, 127, 3, 3, backend="auto", bkz=20)


def test_isolated_ntru_worker_recovers_small_synthetic_plaintext():
    from cryptoscan.ntru_isolation import solve_isolated
    degree, p, q, df, dg, dr, h, ct, plaintext, _ = synthetic(n=16, seed=83)
    output = []
    found = solve_isolated(
        h, ct, degree, p, q, df, dg,
        timeout_seconds=120, progress=output.append,
    )
    assert any(item["plaintext"] == plaintext for item in found)
    assert any("process exited" in line for line in output)


def test_isolated_worker_timeout_releases_child_process(monkeypatch):
    import subprocess
    from cryptoscan.ntru_isolation import solve_isolated

    def timeout(*args, **kwargs):
        assert kwargs["timeout"] == 1
        raise subprocess.TimeoutExpired(args[0], timeout=1)

    monkeypatch.setattr("cryptoscan.ntru_isolation.subprocess.run", timeout)
    with pytest.raises(RuntimeError, match="resources released"):
        solve_isolated([1]*64, [2]*64, 64, 2, 127, 3, 3,
                       timeout_seconds=1, progress=lambda _: None)


def test_isolated_worker_error_is_propagated(monkeypatch):
    import subprocess
    from cryptoscan.ntru_isolation import solve_isolated

    monkeypatch.setattr(
        "cryptoscan.ntru_isolation.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 2, "", "NTRU worker error: invalid lattice"
        ),
    )
    with pytest.raises(RuntimeError, match="invalid lattice"):
        solve_isolated([1]*64, [2]*64, 64, 2, 127, 3, 3,
                       progress=lambda _: None)
