"""Synthetic, non-challenge tests for truncated RSA reshare leakage."""
import math
import random

import pytest

from cryptoscan.parser import Document
from cryptoscan.threshold_rsa import (
    extract_instance, interpolation_kernel, recover_private_exponent,
)


def _invented_source(coefficient_count=5, maximum_friends=6):
    return f'''
from Crypto.Util.number import getPrime
import random

def make_key():
    p = getPrime(120)
    q = getPrime(120)
    return p*q

def public_evaluation(polynomial, x, modulus):
    return sum((x**i)*a for i, a in enumerate(polynomial)) % modulus

def shares(modulus, polynomial):
    participants = int(input("members? "))
    if participants > {maximum_friends}:
        exit()
    participants += 1
    polynomial = polynomial[:participants]
    points = [public_evaluation(polynomial, x, modulus)
              for x in range(1, participants+1)]
    coefficients = matrix(ZZ, [[x**i for i in range(participants)]
                              for x in range(1, participants+1)]).solve_left(
        vector(ZZ, [1] + [0]*(participants-1))
    )
    owned = [(a*b)%modulus for a,b in zip(points, coefficients)]
    print(owned.pop(participants - 2))
    return owned

random = random.SystemRandom()
private = 99
polynomial = [private] + [random.getrandbits(256) for _ in range({coefficient_count - 1})]
while True:
    option = int(input("action? "))
    if option == 1:
        print(pow(2, private, make_key()))
    else:
        break
'''


def test_renamed_source_detects_truncated_shares():
    doc = Document("generic.sage", _invented_source(), None)
    instance = extract_instance([doc])
    assert instance is not None
    assert instance.coefficient_count == 5
    assert instance.maximum_friends == 6


def test_negative_source_without_reshare_not_detected():
    source = _invented_source().replace("participants += 1",
                                        "participants = participants")
    assert extract_instance([Document("other.sage", source, None)]) is None


def test_insufficient_thresholds_not_detected():
    source = _invented_source(maximum_friends=3)
    assert extract_instance([Document("other.sage", source, None)]) is None


@pytest.mark.parametrize("count", [2, 3, 5, 9, 12])
def test_kernel_zeroes_all_truncated_polynomial_columns(count):
    weights = interpolation_kernel(count)
    assert len(weights) == count + 1
    assert math.gcd(*weights) == 1
    for degree in range(count):
        assert sum(
            weights[t - 1] * (-1)**(t - 1) * (t + 1) * t**degree
            for t in range(max(1, degree), count + 2)
        ) == 0


@pytest.mark.parametrize("count", [4, 7, 11])
def test_synthetic_private_exponent_recovers_rsa_key(count):
    p, q = 1009, 1237
    n, phi, e = p*q, (p-1)*(q-1), 65537
    d = pow(e, -1, phi)
    rng = random.Random(count)
    polynomial = [d] + [rng.getrandbits(32) for _ in range(count-1)]
    shares = []
    for t in range(1, count + 2):
        value = sum(c*t**i for i, c in enumerate(polynomial[:t+1]))
        shares.append(((-1)**(t-1)*(t+1)*value) % phi)
    recovered = recover_private_exponent(n, e, shares)
    plaintext = 123456
    assert pow(pow(plaintext, e, n), recovered, n) == plaintext


def test_full_sized_kernel_is_practical_and_exact():
    weights = interpolation_kernel(100)
    assert len(weights) == 101
    assert max(abs(value).bit_length() for value in weights) < 20000
