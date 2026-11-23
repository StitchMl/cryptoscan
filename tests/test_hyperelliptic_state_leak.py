"""Independent regression and metamorphic tests for hyperelliptic state leakage.

The mathematical fixtures build valid Mumford divisors from newly
generated hyperelliptic polynomials over two different finite fields.
No known challenge modulus, flag, class name or state is embedded.
"""
from __future__ import annotations

import json
import random
import struct

import pytest

from cryptoscan.hyperelliptic_state_leak import (
    HyperellipticStreamLeak, _source_profile, curve_from_divisors,
    extract_instance, unpack_state,
)
from cryptoscan.parser import Document


def fresh_source(*, genus=3, variable="z", coefficient_type="H",
                 fixed_multiplier=37, known=b" public suffix"):
    degree = 2 * genus + 1
    prime = 1019 if coefficient_type == "H" else 65519
    return f'''
import os
import struct
from random import SystemRandom

secret = os.environ.get("SECRET").encode()
prime = {prime}
Ring.<{variable}> = GF(prime)[];
equation = sum([SystemRandom().randrange(0,prime)*{variable}^j
                for j in range({degree + 1})])
Hyper = HyperellipticCurve(equation, 0)
Divisors = Hyper.jacobian()

class StateGenerator(object):
    def __init__(self, scalar=0):
        self.factor = scalar if scalar != 0 else SystemRandom().randrange(5, prime)
        self.state = Divisors(Hyper(3, 7))
        self.buffer = b""

    def advance(self):
        self.state = self.factor * self.state
        return self.state

    def __call__(self):
        if not self.buffer:
            U, V = self.advance()
            coefficients = [U[j] for j in range({genus})] + [V[j] for j in range({genus})]
            self.buffer = struct.pack('<'+'{coefficient_type}'*len(coefficients), *coefficients)
        chunk, self.buffer = self.buffer[0], self.buffer[1:]
        return chunk

    def __iter__(self): return self
    def __next__(self): return self()

print(bytes(left^^right for left,right in
            zip(StateGenerator({fixed_multiplier}), secret+{known!r})).hex())
while True:
    message = bytes.fromhex(input("New ciphertext oracle: "))
    print(bytes(left^^right for left,right in zip(StateGenerator(), message)).hex())
'''


def _poly_mul(a, b, p):
    result = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            result[i+j] = (result[i+j] + x*y) % p
    return result


def _eval(coeffs, x, p):
    return sum(c*pow(x, i, p) for i,c in enumerate(coeffs)) % p


def _interpolate(points, p):
    result = [0]*len(points)
    for x,y in points:
        factor = [1]
        normalizer = 1
        for xx,_ in points:
            if x == xx:
                continue
            factor = _poly_mul(factor, [-xx % p, 1], p)
            normalizer = normalizer*(x-xx) % p
        scale = y*pow(normalizer, -1, p) % p
        for i,c in enumerate(factor):
            result[i] = (result[i] + scale*c) % p
    return result


def _valid_observations(p, genus, *, seed):
    rng = random.Random(seed)
    f = [rng.randrange(p) for _ in range(2*genus+2)]
    f[-1] = rng.randrange(1, p)
    available = []
    x = 1
    # Both fields have p ≡ 3 mod 4, allowing deterministic square roots.
    while len(available) < genus * 4:
        rhs = _eval(f, x, p)
        if rhs and pow(rhs, (p-1)//2, p) == 1:
            available.append((x, pow(rhs, (p+1)//4, p)))
        x += 1
    observations = []
    for start in range(0, genus*4, genus):
        values = available[start:start+genus]
        u = [1]
        for x,_ in values:
            u = _poly_mul(u, [-x % p, 1], p)
        v = _interpolate(values, p)
        observations.append((u,v))
    return f, observations


@pytest.mark.parametrize("genus,p,code", [
    (3, 1019, "H"),
    (7, 65519, "H"),
])
def test_mumford_polynomial_reconstruction_from_independent_states(genus,p,code):
    model = HyperellipticStreamLeak(
        prime=p, polynomial_degree_bound=2*genus+1, genus=genus,
        coefficients_per_state=2*genus, coefficient_bytes=2,
        byte_order="little", coefficient_encoding=code,
        known_plaintext_suffix=None, chosen_plaintext=True,
        scalar_multiplier_reused_for_flag=None,
    )
    polynomial, observations = _valid_observations(p, genus, seed=genus*17)
    reconstructed = []
    for u,v in observations[:3]:
        raw = struct.pack("<"+code*(2*genus), *u[:-1], *v)
        assert len(raw) == model.state_bytes
        reconstructed.append(unpack_state(raw, model))
    assert curve_from_divisors(reconstructed, model) == tuple(polynomial)


def test_insufficient_independent_divisors_not_accepted():
    p,g = 1019,3
    f, observations = _valid_observations(p,g,seed=871)
    model = HyperellipticStreamLeak(
        p,2*g+1,g,2*g,2,"little","H",None,True,73,
    )
    with pytest.raises(ValueError, match="too few"):
        curve_from_divisors(observations[:2], model)
    with pytest.raises(ValueError, match="coefficient bytes"):
        unpack_state(b"\x00"*3, model)


def test_inconsistent_divisor_constraints_are_rejected():
    p,g = 1019,3
    _, observations = _valid_observations(p,g,seed=993)
    model = HyperellipticStreamLeak(
        p,2*g+1,g,2*g,2,"little","H",None,True,73,
    )
    corrupt = list(observations)
    u,v = corrupt[-1]
    corrupt.append((u[:],[(v[0]+7)%p,*v[1:]]))
    with pytest.raises(RuntimeError, match="inconsistent"):
        curve_from_divisors(corrupt, model)


@pytest.mark.parametrize("variable,genus,fixed", [
    ("z", 3, 37),
    ("unknown_ring_generator", 7, 991),
    ("alpha", 2, 19),
])
def test_source_parser_independent_of_sage_ring_names_and_dimensions(
        variable, genus, fixed):
    source = fresh_source(genus=genus, variable=variable,
                          fixed_multiplier=fixed)
    model = extract_instance([Document("unrecognized_input.sage", source, None)])
    assert model is not None
    assert model.genus == genus
    assert model.scalar_multiplier_reused_for_flag == fixed
    assert model.chosen_plaintext
    assert model.state_bytes == 2*genus*2
    assert model.known_plaintext_suffix == b" public suffix"


def test_no_chosen_plaintext_does_not_claim_information_leak():
    source = fresh_source().replace(
        "message = bytes.fromhex(input(\"New ciphertext oracle: \"))",
        "message = b'private secret'",
    )
    assert extract_instance([Document("private_only.sage", source, None)]) is None


def test_no_serialized_mumford_coefficients_does_not_claim_weakness():
    source = fresh_source().replace(
        "self.buffer = struct.pack('<'+'H'*len(coefficients), *coefficients)",
        "self.buffer = os.urandom(2*len(coefficients))",
    )
    assert extract_instance([Document("secure_random_stream.sage",source,None)]) is None


def test_scanner_and_analysis_only_planner(tmp_path, capsys):
    from cryptoscan.cli import main

    path = tmp_path / "novel_cryptosystem.sage"
    path.write_text(fresh_source(), encoding="utf-8")
    assert main([str(path), "--plan-attacks", "--format", "json",
                 "--host", "example.invalid", "--port", "39003"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(
        item["rule"] == "HYPERELLIPTIC-MUMFORD-STATE-DISCLOSURE"
        for item in report["findings"]
    )
    assert any(
        item["family"] == "Hyperelliptic Mumford-state curve reconstruction"
        and item["status"] == "analysis-only"
        for item in report["attack_plan"]
    )
    assert not any(
        item["family"] == "Hyperelliptic Mumford-state curve reconstruction"
        and item["status"] == "applicable"
        for item in report["attack_plan"]
    )
    assert main([str(path), "--solve", "--host",
                 "example.invalid", "--port", "39003"]) == 2
    assert "FLAG:" not in capsys.readouterr().out


def test_hyperelliptic_hypothesis_on_unseen_unresolved_sage_source():
    from cryptoscan.crypto_hypotheses import inspect_hypotheses

    source = fresh_source().replace(
        "self.buffer = struct.pack('<'+'H'*len(coefficients), *coefficients)",
        "self.buffer = struct.pack('<'+'H'*len(coefficients), *coefficients)",
    ).replace(
        "self.state = self.factor * self.state",
        "self.state = nonlinear_transform(self.state, self.factor)",
    )
    doc = Document("different_state_transition.sage", source, None)
    assert extract_instance([doc]) is None
    hypotheses = inspect_hypotheses([doc])
    assert any(
        item.family ==
        "Hyperelliptic Jacobian state exposure under chosen plaintext"
        for item in hypotheses
    )


def test_analysis_plan_never_runs_an_analysis_only_executor(tmp_path, capsys):
    from cryptoscan.cli import main

    source = tmp_path / "unseen.sage"
    source.write_text(fresh_source(), encoding="utf-8")
    assert main([str(source), "--plan-attacks"]) == 0
    output = capsys.readouterr().out
    assert "Hyperelliptic Mumford-state curve reconstruction" in output
    assert "analysis only" in output
    assert main([str(source), "--solve"]) == 2
    assert "FLAG:" not in capsys.readouterr().out
