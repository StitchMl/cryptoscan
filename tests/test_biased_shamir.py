"""Independent algebra and protocol tests for biased Shamir sharing.

Tests generate new polynomial coefficients, secret sizes, class names,
field primes and wire labels; no challenge instance data is embedded.
"""
from __future__ import annotations

import json
import math
import random
import socket

import pytest

from cryptoscan.biased_shamir import (
    _crt, _source_profile, candidate_secrets, extract_instance,
    recover_flag, recover_secret_from_oracle,
)
from cryptoscan.parser import Document


def new_source(secret_bytes=6, upper_offset=1, *,
               label="observations =", lower=7):
    return f'''
from Crypto.Util.number import getRandomRange, isPrime
from Crypto.Util.number import bytes_to_long
import os

class PolynomialSampler:
    def __init__(self, field, participants, hidden):
        self.modulus = field
        self.participants = participants
        self.coeffs = [hidden] + [
            getRandomRange(0, self.modulus - {upper_offset})
            for index in range(participants - 1)
        ]

    def value(self, x):
        return (
            sum(self.coeffs[i] * pow(x, i, self.modulus)
                for i in range(len(self.coeffs)))
            % self.modulus
        )

    def issue(self):
        return [
            self.value(counter + 1)
            for counter in range(self.participants)
        ]

if __name__ == "__main__":
    hidden = bytes_to_long(os.urandom({secret_bytes}))
    while True:
        field = int(input("prime: "))
        participants = int(input("size: "))
        if isPrime(field) and {lower} < participants < field:
            output = PolynomialSampler(field, participants, hidden).issue()
            print("{label}", output[:-1])
        else:
            break
    if int(input("hidden: ")) == hidden:
        print("LAB{{verified}}")
'''


def make_shares(secret, prime, *, count=None, exclude=1, rng=None):
    rng = rng or random.Random(2026)
    count = (prime - 2) if count is None else count
    coefficients = [secret % prime] + [
        rng.randrange(prime - exclude)
        for _ in range(count)
    ]
    return [
        sum(a * pow(x, degree, prime)
            for degree, a in enumerate(coefficients)) % prime
        for x in range(1, count + 1)
    ]


def test_renamed_source_and_general_sampling_interval():
    source = new_source(secret_bytes=7, upper_offset=2, label="fragments:")
    profile = _source_profile(Document("unseen_interactive.py", source, None))
    assert profile is not None
    assert profile.secret_bits == 56
    assert profile.excluded_high == 2
    assert profile.minimum_n == 7
    assert profile.prime_prompt == "prime: "
    assert profile.count_prompt == "size: "
    assert profile.secret_prompt == "hidden: "
    assert profile.shares_label == "fragments:"


@pytest.mark.parametrize("prime", [17, 23, 31, 43])
@pytest.mark.parametrize("excluded", [1, 2, 3])
def test_general_polynomial_constraint_intersection(prime, excluded):
    rng = random.Random(prime * 20 + excluded)
    secret = rng.getrandbits(80)
    possible = frozenset(range(prime))
    for _ in range(20):
        shares = make_shares(secret, prime, exclude=excluded, rng=rng)
        candidates = candidate_secrets(
            shares, prime, excluded_high=excluded,
        )
        assert secret % prime in candidates
        possible &= candidates
        if len(possible) == 1:
            break
    assert possible == {secret % prime}


def test_noncontiguous_coordinates_are_supported():
    p = 31
    points = [2, 5, 8, 11]
    secret = 26
    coefficients = [secret, 4, 3, 8, 14]
    observations = [
        sum(a * pow(x, i, p) for i, a in enumerate(coefficients)) % p
        for x in points
    ]
    candidates = candidate_secrets(
        observations, p, x_coordinates=points, excluded_high=1,
    )
    assert secret in candidates


def test_constraints_do_not_force_false_uniqueness():
    p, secret = 31, 19
    observed = make_shares(secret, p, rng=random.Random(2026))
    candidates = candidate_secrets(observed, p)
    assert secret in candidates
    assert len(candidates) > 1


def test_crt_integer_uniqueness_requires_product_exceeding_bound():
    residue, modulus = _crt({17: 3, 19: 5, 23: 7})
    assert all(residue % p == r for p, r in ((17, 3), (19, 5), (23, 7)))
    assert modulus == math.prod((17, 19, 23))
    assert modulus < 1 << 16


@pytest.mark.parametrize("replacement", [
    "getRandomRange(0, self.modulus)",
    "getRandomRange(0, self.modulus + 1)",
    "getRandomRange(0, 2**128)",
])
def test_unbiased_or_unrelated_sampler_is_not_detected(replacement):
    source = new_source().replace(
        "getRandomRange(0, self.modulus - 1)", replacement,
    )
    assert extract_instance([Document("unseen.py", source, None)]) is None


def test_missing_last_share_and_random_secret_are_required():
    source = new_source()
    assert extract_instance([
        Document("all_shares.py", source.replace("output[:-1]", "output"), None),
    ]) is None
    assert extract_instance([
        Document("constant_secret.py", source.replace(
            "bytes_to_long(os.urandom(6))", "12345",
        ), None),
    ]) is None


def test_missing_reconstruction_bound_not_claimed():
    source = new_source().replace(
        "bytes_to_long(os.urandom(6))",
        "int(input('unknown secret: '))",
    )
    assert extract_instance([Document("unknown_secret.py", source, None)]) is None


class FakeOracle:
    def __init__(self, profile, secret):
        self.profile, self.secret = profile, secret
        self.rng = random.Random(99112)
        self.sent = 0
        self.output = bytearray()
        self.verified_submission = False
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, raw):
        self.sent += 1
        numbers = [int(value) for value in raw.decode("ascii").splitlines()]
        if numbers[:2] == [0, 0]:
            self.verified_submission = numbers[2] == self.secret
            self.output.extend(
                b"LAB{independent_server_verified}\n"
                if self.verified_submission
                else b"incorrect\n"
            )
            return
        assert len(numbers) % 2 == 0
        for prime, participants in zip(numbers[::2], numbers[1::2]):
            assert participants == prime - 1
            shares = make_shares(
                self.secret, prime, exclude=self.profile.excluded_high,
                rng=self.rng,
            )
            self.output.extend(
                ("prime: size: " + self.profile.shares_label + " "
                 + repr(shares) + "\n").encode("ascii")
            )

    def recv(self, maximum):
        if not self.output:
            if self.verified_submission:
                return b""
            raise socket.timeout()
        block = self.output[:maximum]
        del self.output[:maximum]
        return bytes(block)


def test_adaptive_crt_recovers_independent_random_secret(monkeypatch):
    import cryptoscan.biased_shamir as module

    profile = _source_profile(Document("unknown.py", new_source(6), None))
    secret = random.Random(1212).getrandbits(48)
    fake = FakeOracle(profile, secret)
    monkeypatch.setattr(
        module.socket, "create_connection",
        lambda *args, **kwargs: fake,
    )
    assert recover_flag([
        Document("unknown.py", new_source(6), None),
    ], "example.invalid", 31337, timeout=10) == (
        "LAB{independent_server_verified}"
    )
    assert fake.verified_submission
    assert fake.sent > 2


def test_cli_plan_scan_and_remote_solver_gating(tmp_path, monkeypatch, capsys):
    import cryptoscan.biased_shamir as module
    from cryptoscan import cli

    source = new_source()
    (tmp_path / "new_sharing_protocol.py").write_text(
        source, encoding="utf-8",
    )
    assert cli.main([
        str(tmp_path), "--plan-attacks", "--format", "json",
        "--host", "example.invalid", "--port", "8888",
    ]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(
        result["rule"] == "SHAMIR-COEFFICIENT-SAMPLING-BIAS"
        for result in report["findings"]
    )
    assert any(
        item["family"] == "Biased Shamir coefficient inference + CRT"
        and item["status"] == "applicable"
        for item in report["attack_plan"]
    )
    assert cli.main([str(tmp_path), "--plan-attacks", "--format", "json"]) == 0
    offline = json.loads(capsys.readouterr().out)
    assert not any(
        item["status"] == "applicable"
        and item["family"] == "Biased Shamir coefficient inference + CRT"
        for item in offline["attack_plan"]
    )
    profile = _source_profile(Document("new_source", source, None))
    fake = FakeOracle(profile, random.Random(17).getrandbits(48))
    monkeypatch.setattr(
        module.socket, "create_connection",
        lambda *args, **kwargs: fake,
    )
    assert cli.main([
        str(tmp_path), "--solve", "--host", "example.invalid",
        "--port", "8888", "--timeout", "10",
    ]) == 0
    assert fake.verified_submission
    assert "FLAG: LAB{independent_server_verified}" in capsys.readouterr().out


def test_unsupported_share_points_are_rejected():
    with pytest.raises(ValueError):
        candidate_secrets([1, 2, 3], 17, x_coordinates=[1, 1, 2])
    with pytest.raises(ValueError):
        candidate_secrets([1, 2, 3], 17, x_coordinates=[0, 2, 3])


@pytest.mark.parametrize("change", [
    ("from Crypto.Util.number import getRandomRange, isPrime",
     "from Crypto.Util.number import getRandomRange as sample, isPrime",
     "getRandomRange(0, self.modulus - 1)",
     "sample(0, self.modulus - 1)"),
    ("from Crypto.Util.number import getRandomRange, isPrime",
     "import secrets\nfrom Crypto.Util.number import isPrime",
     "getRandomRange(0, self.modulus - 1)",
     "secrets.randbelow(self.modulus - 1)"),
    ("from Crypto.Util.number import getRandomRange, isPrime",
     "import random\nfrom Crypto.Util.number import isPrime",
     "getRandomRange(0, self.modulus - 1)",
     "random.randrange(self.modulus - 1)"),
    ("from Crypto.Util.number import getRandomRange, isPrime",
     "import random\nfrom Crypto.Util.number import isPrime",
     "getRandomRange(0, self.modulus - 1)",
     "random.randint(0, self.modulus - 2)"),
])
def test_equivalent_random_coefficient_sampling_imports(change):
    old_import, new_import, old_call, new_call = change
    source = new_source().replace(old_import, new_import)
    source = source.replace(old_call, new_call)
    assert extract_instance([Document("new_sampler.py", source, None)]) is not None


def test_secret_must_remain_constant_between_share_queries():
    source = new_source().replace(
        "hidden = bytes_to_long(os.urandom(6))\n    while True:",
        "while True:\n        hidden = bytes_to_long(os.urandom(6))",
    )
    assert extract_instance([Document("fresh_secret_each_round.py", source, None)]) is None


def test_share_output_must_derive_from_detected_sampler():
    source = new_source().replace(
        "print(\"observations =\", output[:-1])",
        "print(\"observations =\", unrelated[:-1])",
    )
    assert extract_instance([Document("unrelated_print.py", source, None)]) is None


def test_aliased_inclusive_sampler_retains_correct_excluded_count():
    source = new_source().replace(
        "from Crypto.Util.number import getRandomRange, isPrime",
        "from random import randint as bounded\n"
        "from Crypto.Util.number import isPrime",
    ).replace(
        "getRandomRange(0, self.modulus - 1)",
        "bounded(0, self.modulus - 2)",
    )
    profile = extract_instance([Document("different_api.py", source, None)])
    assert profile is not None
    assert profile.excluded_high == 1


def test_aliased_exclusive_sampler_retains_correct_excluded_count():
    source = new_source().replace(
        "from Crypto.Util.number import getRandomRange, isPrime",
        "from secrets import randbelow as sample\n"
        "from Crypto.Util.number import isPrime",
    ).replace(
        "getRandomRange(0, self.modulus - 1)",
        "sample(self.modulus - 1)",
    )
    profile = extract_instance([Document("different_api.py", source, None)])
    assert profile is not None
    assert profile.excluded_high == 1


def test_unknown_sharing_protocol_can_still_emit_unverified_hypothesis():
    from cryptoscan.crypto_hypotheses import inspect_hypotheses

    variant = '''
from Crypto.Util.number import getRandomRange
def distribute(field, hidden):
    coefficients = [hidden] + [getRandomRange(0, field - 2) for _ in range(10)]
    return [sum(a*pow(x,i,field) for i,a in enumerate(coefficients)) % field
            for x in range(1, 8)]
query = int(input("field> "))
print(distribute(query, secret))
'''
    doc = Document("unknown_distribution.py", variant, None)
    assert extract_instance([doc]) is None
    hypotheses = inspect_hypotheses([doc])
    assert any(
        item.family == "Potential coefficient-support leakage in polynomial secret sharing"
        for item in hypotheses
    )


def test_protocol_deadline_derived_from_its_own_source():
    source = "import signal\n" + new_source().replace(
        '    hidden = bytes_to_long(os.urandom(6))',
        '    signal.alarm(45)\n    hidden = bytes_to_long(os.urandom(6))',
    )
    model = extract_instance([Document("different_deadline.py", source, None)])
    assert model is not None
    assert model.server_alarm == 45


def test_unbounded_field_core_does_not_require_original_participant_count():
    # Small n with arbitrary evaluation points: the algebraic core is not
    # restricted to the p-1 policy used by the interactive adapter.
    p = 101
    xs = [3, 7, 11]
    secret = 72
    coeffs = [secret, 28, 30, 41]
    observed = [
        sum(v*pow(x, i, p) for i, v in enumerate(coeffs)) % p
        for x in xs
    ]
    assert secret in candidate_secrets(
        observed, p, x_coordinates=xs, excluded_high=1,
    )
