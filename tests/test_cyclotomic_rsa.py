"""Generalization tests for cyclotomic-related multiprime RSA.

The test corpora are generated from fresh small primes, nonchallenge
variable names, and unrelated RSA ciphertexts. Nothing is copied from
a named CTF's public modulus, factors, or flag.
"""
from __future__ import annotations

import json
import random

import pytest
from Crypto.Util.number import isPrime

from cryptoscan.cyclotomic_rsa import (
    _source_profile, extract_instance, extension_multiply, extension_pow,
    recover_details, recover_flag, related_factors,
)
from cryptoscan.parser import Document


def new_corpus(*, bits=32, degree=3, comprehension="list"):
    rng = random.Random(2026 + bits * 19 + degree * 7)
    current = (1 << (bits - 1)) + rng.randrange(1 << (bits - 2))
    for _ in range(40000):
        current += 2
        if current.bit_length() != bits:
            current = (1 << (bits - 1)) + 1
        q = sum(current ** j for j in range(degree))
        if isPrime(current) and isPrime(q):
            p = current
            break
    else:
        raise AssertionError("synthetic correlated prime not found")
    extra = (1 << (bits * degree - 1)) + rng.randrange(1 << (bits * degree - 2))
    while not isPrime(extra):
        extra += 2
    n = p * q * extra
    message = b"TEST{related_prime}"
    assert int.from_bytes(message, "big") < n
    exponent = 65537
    ciphertext = pow(int.from_bytes(message, "big"), exponent, n)
    brackets = "[]" if comprehension == "list" else "()"
    expression = (
        f"sum({brackets[0]}seed**j for j in range(depth){brackets[1]})"
    )
    code = f'''
from Crypto.Util.number import getPrime, isPrime, bytes_to_long

def correlated_prime_factory(k, depth):
    while True:
        seed = getPrime(k)
        partner = {expression}
        if isPrime(partner):
            return seed, partner

first_factor, next_factor = correlated_prime_factory({bits}, {degree})
unrelated_factor = getPrime({bits * degree})
modulus = first_factor * next_factor * unrelated_factor
exponent = 65537
secret = bytes_to_long(b"TEST{{related_prime}}")
sealed = pow(secret, exponent, modulus)
print(f"{{modulus = }}")
print(f"{{exponent = }}")
print(f"{{sealed = }}")
'''
    output = f"modulus = {n}\nexponent = {exponent}\nsealed = {ciphertext}\n"
    return [
        Document("fresh_crypto.py", code, None),
        Document("fresh_numbers.dat", output, None),
    ], (p, q, extra)


@pytest.mark.parametrize("bits", [32, 40])
@pytest.mark.parametrize("comprehension", ["list", "generator"])
def test_parameterized_related_prime_recovery(bits, comprehension):
    docs, factors = new_corpus(bits=bits, comprehension=comprehension)
    model = extract_instance(docs)
    assert model is not None
    assert model.degree == 3
    assert model.prime_bits == bits
    flag, certificate = recover_details(model, attempts=48)
    assert flag == "TEST{related_prime}"
    assert certificate["factorization_verified"]
    assert certificate["reencryption_verified"]
    assert certificate["extension_degree"] == 3
    assert model.modulus == factors[0] * factors[1] * factors[2]


def test_different_extension_degree_same_attack():
    docs, factors = new_corpus(bits=32, degree=5)
    assert extract_instance(docs) is not None
    assert recover_flag(docs, attempts=64) == "TEST{related_prime}"


def test_ring_arithmetic_multiplicative_identity():
    coeffs = (4, 7, 12)
    modulus = 101
    one = (1, 0, 0)
    x = (0, 1, 0)
    xx = extension_multiply(x, x, coeffs, modulus)
    xxx = extension_multiply(xx, x, coeffs, modulus)
    assert extension_multiply(x, one, coeffs, modulus) == x
    assert xxx == ((-4) % modulus, (-7) % modulus, (-12) % modulus)
    assert extension_pow(x, 3, coeffs, modulus) == xxx


def test_source_fails_closed_on_independent_prime_factors():
    docs, _ = new_corpus()
    ordinary = docs[0].text.replace(
        "partner = sum([seed**j for j in range(depth)])",
        "partner = getPrime(k * 2)",
    )
    assert extract_instance([
        Document("independent_primes.py", ordinary, None), docs[1],
    ]) is None


def test_source_fails_closed_without_primality_check():
    docs, _ = new_corpus()
    source = docs[0].text.replace(
        "if isPrime(partner):", "if partner > 0:",
    )
    assert extract_instance([
        Document("unverified_factor.py", source, None), docs[1],
    ]) is None


def test_wrong_corpus_and_multiple_outputs_are_not_joined():
    docs, _ = new_corpus()
    assert extract_instance([
        docs[0], Document("wrong_scope.dat", docs[1].text, None, "different"),
    ]) is None
    assert extract_instance([
        *docs, Document("another_output.dat", docs[1].text, None),
    ]) is None


def test_no_cyclotomic_factor_rejected_by_certificate():
    docs, _ = new_corpus()
    model = extract_instance(docs)
    assert model is not None
    with pytest.raises(RuntimeError, match="no certified cyclotomic"):
        related_factors(101 * 103 * 107, degree=3, max_attempts=4)


def test_source_only_scanner_finding_without_solver():
    from cryptoscan.scanner import scan

    docs, _ = new_corpus()
    assert extract_instance(docs[:1]) is None
    findings = scan(docs[:1])
    matched = [
        f for f in findings if f.rule == "RSA-CYCLOTOMIC-PRIME-RELATION"
    ]
    assert len(matched) == 1
    assert matched[0].evidence["public_modulus_matched"] is False


def test_cli_plan_and_end_to_end_solver(tmp_path, capsys):
    from cryptoscan.cli import main

    docs, _ = new_corpus(bits=32)
    for document in docs:
        (tmp_path / document.path).write_text(document.text, encoding="utf-8")
    assert main([str(tmp_path), "--plan-attacks", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(
        item["status"] == "applicable"
        and item["family"] == "Cyclotomic related RSA finite-field factorization"
        for item in report["attack_plan"]
    )
    assert any(
        item["rule"] == "RSA-CYCLOTOMIC-PRIME-RELATION"
        for item in report["findings"]
    )
    assert main([str(tmp_path), "--solve"]) == 0
    assert "FLAG: TEST{related_prime}" in capsys.readouterr().out
