"""Independent invalid-curve/twist tests, including unseen curve parameters.

The only oracle in these tests is an in-memory scalar multiplier; there
are no known CTF flags, challenge-specific primes or captured secrets.
"""
from __future__ import annotations

import json
from dataclasses import replace

import pytest
from sympy import factorint, isprime

from cryptoscan.ec_twist_oracle import (
    Curve, TwistOracle, _source_profile, candidate_texts, extract_instance,
    recover_residue, twist_generator,
)
from cryptoscan.parser import Document


def _ec_source(field, a, b, order, *, prefix="LAB{"):
    return f'''"""
Public short Weierstrass curve:
n = {order}
"""
field = {field}
A = {a}
B = {b}

def diff_step(P, Q, PQ):
    (X1, Z1), (X2, Z2), (X3, Z3) = PQ, P, Q
    X4 = (X2**2 - A * Z2**2)**2 - 8 * B * X2 * Z2**3
    Z4 = 4 * (X2 * Z2 * (X2**2 + A * Z2**2) + B * Z2**4)
    X5 = Z1 * ((X2 * X3 - A * Z2 * Z3)**2
               - 4 * B * Z2 * Z3 * (X2 * Z3 + X3 * Z2))
    Z5 = X1 * (X2 * Z3 - X3 * Z2)**2
    return ((X4 % field, Z4 % field),
            (X5 % field, Z5 % field))

def projective_multiply(P, k):
    Q, R = (1, 0), P
    for index in reversed(range(k.bit_length() + 1)):
        if k >> index & 1:
            R, Q = Q, R
        Q, R = diff_step(Q, R, P)
        if k >> index & 1:
            R, Q = Q, R
    return Q

def hidden_scalar(token):
    data = token.lstrip("{prefix}").rstrip("}}")
    return int.from_bytes(data.encode(), "big")

def publish_x(coordinate, unknown):
    P = (coordinate, 1)
    Q = projective_multiply(P, unknown)
    return Q[0] * pow(Q[1], -1, field) % field

def interactive_loop():
    secret = hidden_scalar("LAB{{mock}}")
    while True:
        coordinate = int(input("coordinate please: "))
        print(publish_x(coordinate, secret))
'''


def _main_order(q, a, b):
    if q > 100_000:
        raise ValueError("bounded test field")
    trace = sum(
        0 if (value := (x*x*x+a*x+b) % q) == 0
        else 1 if pow(value, (q-1)//2, q) == 1 else -1
        for x in range(q)
    )
    return q + 1 + trace


@pytest.mark.parametrize("q,a,b", [
    (65537, 4, 9),
    (65519, 2, 17),
    (65521, 1, 5),
])
def test_unseen_curve_twist_scalar_residue(q, a, b):
    assert isprime(q)
    n = _main_order(q, a, b)
    source = _ec_source(q, a, b, n)
    model = _source_profile(Document("different_ec_program.py", source, None))
    assert model is not None
    assert model.field_prime == q
    assert model.curve_order == n
    order = 2*(q+1)-n
    curve, nonsquare, base, chosen = twist_generator(model, factorint(order))
    assert curve.mul(base, order) is None
    for secret in (17, 197, 4567):
        output = curve.mul(base, secret)
        assert output is not None
        output_x = output[0]*pow(nonsquare, -1, q) % q
        residue, recovered_order, query = recover_residue(model, output_x)
        assert recovered_order == order
        assert query == chosen
        assert residue in (secret % order, (-secret) % order)


def test_source_only_scanner_detects_unvalidated_x_only_scalar_oracle():
    from cryptoscan.scanner import scan

    q, a, b = 65537, 4, 9
    source = Document("unknown_ec.py", _ec_source(
        q, a, b, _main_order(q, a, b),
    ), None)
    findings = [
        f for f in scan([source])
        if f.rule == "EC-UNVALIDATED-X-QUADRATIC-TWIST"
    ]
    assert len(findings) == 1
    assert findings[0].evidence["user_supplied_coordinate"]
    assert findings[0].evidence["twist_order"] == (
        2*(q+1)-_main_order(q,a,b)
    )


def test_no_curve_order_still_reports_source_weakness():
    from cryptoscan.scanner import scan

    source = _ec_source(65537, 4, 9, 65600)
    source = source.replace("n = 65600", "order not published")
    model = extract_instance([
        Document("unseen_curve.py", source, None),
    ])
    assert model is not None
    assert model.curve_order is None
    found = [
        f for f in scan([Document("unseen_curve.py", source, None)])
        if f.rule == "EC-UNVALIDATED-X-QUADRATIC-TWIST"
    ]
    assert len(found) == 1
    assert found[0].evidence["published_main_curve_order"] is False


def test_x_coordinate_sign_ambiguity_and_incomplete_scalar_bound():
    order = 65537
    target = int.from_bytes(b"Ab", "big")
    candidates = candidate_texts(
        target, order, "LAB{", "}", max_length=2,
    )
    assert "LAB{Ab}" in candidates
    assert candidate_texts(
        target, order, "LAB{", "}", max_length=1,
    ) == []
    # A residue is not the same as full scalar recovery when multiples
    # of the curve order can also encode plausible messages.
    lifted = candidate_texts(
        target, order, "LAB{", "}", max_length=4,
    )
    assert set(candidates).issubset(set(lifted))


def test_source_requires_interactive_chosen_coordinate():
    source = _ec_source(65537, 4, 9, 65600)
    assert _source_profile(Document(
        "no_input.py", source.replace(
            'int(input("coordinate please: "))', "123",
        ), None,
    )) is None


def test_source_requires_projective_inverse_and_twist_arithmetic():
    source = _ec_source(65537, 4, 9, 65600)
    source = source.replace(
        "Q[0] * pow(Q[1], -1, field) % field",
        "Q[0] % field",
    )
    assert extract_instance([Document("not_an_xz_oracle.py", source, None)]) is None


def test_cli_detects_only_remote_attack_and_does_not_connect_during_plan(
        tmp_path, capsys):
    from cryptoscan.cli import main

    q,a,b = 65537,4,9
    path = tmp_path / "a_new_elliptic_service.py"
    path.write_text(_ec_source(q,a,b,_main_order(q,a,b)), encoding="utf-8")
    assert main([str(path), "--plan-attacks", "--format", "json"]) == 0
    offline = json.loads(capsys.readouterr().out)
    assert not any(
        item["family"].startswith("Chosen-coordinate EC")
        and item["status"] == "applicable"
        for item in offline["attack_plan"]
    )
    assert main([
        str(path), "--plan-attacks", "--format", "json",
        "--host", "example.invalid", "--port", "11718",
    ]) == 0
    remote = json.loads(capsys.readouterr().out)
    assert any(
        item["status"] == "applicable"
        and item["family"] ==
        "Chosen-coordinate EC quadratic-twist subgroup recovery"
        for item in remote["attack_plan"]
    )


def test_composite_field_order_is_never_claimed_prime():
    bogus = TwistOracle(
        65535, 4, 9, 65000, "coordinate: ", "LAB{", "}",
    )
    with pytest.raises(RuntimeError, match="not prime"):
        recover_residue(bogus, 3)


def test_preflight_excludes_unsupported_point_count_and_subgroup():
    from cryptoscan.ec_twist_oracle import feasible_twist

    q, a, b = 65519, 2, 17
    complete = TwistOracle(
        q, a, b, _main_order(q,a,b),
        "coordinate please: ", "LAB{", "}",
    )
    assert feasible_twist(complete)
    assert not feasible_twist(replace(complete, curve_order=None))
    assert not feasible_twist(replace(complete, field_prime=65535))
    assert not feasible_twist(complete, max_bsgs_steps=3)


def test_remote_solver_with_fresh_long_secret_and_mocked_x_oracle(monkeypatch):
    import cryptoscan.ec_twist_oracle as oracle

    q, a, b = 2**128-159, 1, 1494
    curve_order = 340282366920938463465004184633952524077
    source = _ec_source(q,a,b,curve_order,prefix="LAB{")
    docs = [Document("alternate_protocol.py", source, None)]
    model = extract_instance(docs)
    assert model is not None
    secret_text = "ANOTHERTESTKEY12"
    secret = int.from_bytes(secret_text.encode(), "big")
    curve, twist_constant, P, query_x = twist_generator(
        model, factorint(2*(q+1)-curve_order),
    )
    reply = curve.mul(P, secret)
    assert reply is not None
    output_x = reply[0]*pow(twist_constant,-1,q)%q

    class Oracle:
        def __init__(self):
            self.output = bytearray(model.input_prompt.encode())
            self.asked = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, seconds):
            pass

        def sendall(self, payload):
            self.asked.append(int(payload))
            self.output += (
                str(output_x) + "\n" + model.input_prompt
            ).encode()

        def recv(self, limit):
            chunk = self.output[:limit]
            del self.output[:limit]
            return bytes(chunk)

    fake = Oracle()
    monkeypatch.setattr(
        oracle.socket, "create_connection",
        lambda *args, **kwargs: fake,
    )
    assert oracle.recover_flag(
        docs, "ctf.example", 1337, timeout=10,
    ) == "LAB{" + secret_text + "}"
    assert fake.asked == [query_x]


def test_curve_membership_validation_prevents_verified_twist_finding():
    source = _ec_source(65537, 4, 9, 65600)
    source = source.replace(
        '        print(publish_x(coordinate, secret))',
        '        if not is_on_curve(coordinate):\n'
        '            continue\n'
        '        print(publish_x(coordinate, secret))',
    )
    assert extract_instance([
        Document("validated_coordinate.py", source, None),
    ]) is None


def test_assertion_guard_prevents_invalid_point_classification():
    source = _ec_source(65537, 4, 9, 65600)
    source = source.replace(
        '        print(publish_x(coordinate, secret))',
        '        assert is_on_curve(coordinate)\n'
        '        print(publish_x(coordinate, secret))',
    )
    assert extract_instance([
        Document("asserts_point_membership.py", source, None),
    ]) is None


def test_small_field_point_count_can_be_derived_without_published_order():
    from cryptoscan.ec_twist_oracle import (
        feasible_twist, resolve_point_count,
    )

    q, a, b = 65519, 2, 17
    public = TwistOracle(
        q, a, b, None, "arbitrary x: ", "LAB{", "}",
    )
    completed = resolve_point_count(public)
    assert completed.curve_order == _main_order(q, a, b)
    assert feasible_twist(public)
    assert resolve_point_count(
        replace(public, field_prime=2**128-159),
    ).curve_order is None
