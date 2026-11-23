"""Metamorphic and negative tests for source-derived weak seeded RSA recovery.

All moduli and ciphertexts are freshly synthesized from unrelated labels,
sampling methods, and key sizes. No known challenge parameters are stored.
"""
from __future__ import annotations

import json
import math
import random

import pytest
from Crypto.Util.number import isPrime

from cryptoscan.parser import Document
from cryptoscan.weak_seeded_multiprime_rsa import (
    extract_instance, recover_details, recover_flag,
)


def _candidate_prime(seed, bits, sampling):
    rng = random.Random(seed)
    for _ in range(4096):
        if sampling == "getrandbits":
            value = rng.getrandbits(bits)
        elif sampling == "randrange":
            value = rng.randrange(1 << bits)
        else:
            value = rng._randbelow(1 << bits)
        candidate = value | 1
        if isPrime(candidate):
            return candidate
    raise RuntimeError("synthetic prime generation failed")


def _independent_instance(
    bits=64, sampling="_randbelow", initializer="seed_method",
    message=b"LAB{new_rsa_message_2026}",
):
    assert len(message) < 120
    if initializer == "seed_method":
        initialization = (
            "generator = random.Random()\n"
            "    generator.seed(randbelow(2**n))"
        )
    else:
        initialization = "generator = random.Random(randbelow(1 << n))"
    draw = (
        f"generator.getrandbits({bits})"
        if sampling == "getrandbits"
        else f"generator.{sampling}(2**{bits})"
    )
    code = f'''
from math import prod
from secrets import randbelow
import random
from Crypto.Util.number import *

def unrelated_random_prime(n):
    prime_value = 1
    {initialization}
    while not isPrime(prime_value):
        prime_value = {draw} | 1
    return prime_value

secret_bytes = b""
assert len(secret_bytes) == {len(message)}
modulus = prod(
    unrelated_random_prime(i) for i in range(2, len(secret_bytes))
)
print(hex(modulus), hex(pow(bytes_to_long(secret_bytes), 65537, modulus)))
'''
    factors = [
        _candidate_prime((7 * n + 3) % (1 << n), bits, sampling)
        for n in range(2, len(message))
    ]
    modulus = math.prod(factors)
    cipher = pow(int.from_bytes(message, "big"), 65537, modulus)
    return [
        Document("new_arithmetic_model.py", code, None),
        Document("unrecognized_output.log", f"Public: {modulus:#x} {cipher:#x}", None),
    ]


@pytest.mark.parametrize("sampling", ["getrandbits", "_randbelow", "randrange"])
@pytest.mark.parametrize("bits", [64, 96])
def test_parameterized_seed_recovery_and_unique_crt(sampling, bits):
    docs = _independent_instance(bits=bits, sampling=sampling)
    model = extract_instance(docs)
    assert model is not None
    assert model.prime_bits == bits
    assert model.sample_method == sampling
    plaintext, certificate = recover_details(model)
    assert plaintext == "LAB{new_rsa_message_2026}"
    assert certificate["factor_count"] >= 2
    assert certificate["crt_bits"] > certificate["plaintext_bound_bits"]
    assert certificate["reencryption_verified"] is True


def test_constructed_prng_and_renamed_source_variables():
    docs = _independent_instance(initializer="constructor")
    assert recover_flag(docs) == "LAB{new_rsa_message_2026}"


def test_source_false_positives_rejected():
    docs = _independent_instance()
    source = docs[0].text
    variants = (
        source.replace("randbelow(2**n)", "randbelow(2**256)"),
        source.replace("random.Random()", "random.SystemRandom()"),
        source.replace("while not isPrime(prime_value):",
                       "while prime_value % 2 == 0:"),
        source.replace("assert len(secret_bytes) == 25", "pass"),
        source.replace("generator.seed(randbelow(2**n))",
                       "generator.seed(123456789)"),
    )
    for changed in variants:
        assert extract_instance([
            Document("unrelated.py", changed, None), docs[1],
        ]) is None


def test_different_public_modulus_never_claims_recovery():
    docs = _independent_instance()
    model = extract_instance(docs)
    assert model is not None
    with pytest.raises(RuntimeError, match="insufficient verified factors"):
        recover_details(model, max_seeds=1)


def test_source_scope_isolation_and_ambiguous_output():
    docs = _independent_instance()
    assert extract_instance([
        docs[0], Document(docs[1].path, docs[1].text, None, "different"),
    ]) is None
    assert extract_instance([
        *docs, Document("duplicate_output.log", docs[1].text, None),
    ]) is None


def test_cli_scanner_plan_and_offline_solver(tmp_path, capsys):
    from cryptoscan.cli import main

    docs = _independent_instance(bits=64, sampling="_randbelow")
    for doc in docs:
        (tmp_path / doc.path).write_text(doc.text, encoding="utf-8")
    inputs = [str(tmp_path)]

    assert main(inputs + ["--plan-attacks", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(
        item["rule"] == "RSA-WEAK-SEEDED-PRIME-GENERATOR"
        for item in report["findings"]
    )
    assert any(
        item["family"] == "Weak-seeded RSA partial CRT"
        and item["status"] == "applicable"
        for item in report["attack_plan"]
    )

    assert main(inputs + ["--solve", "--seed-search-limit", "256"]) == 0
    output = capsys.readouterr().out
    assert "FLAG: LAB{new_rsa_message_2026}" in output


def test_cli_rejects_bad_seed_search_budget(tmp_path):
    from cryptoscan.cli import main

    source = tmp_path / "dummy.py"
    source.write_text("x = 1", encoding="utf-8")
    with pytest.raises(SystemExit):
        main([str(source), "--solve", "--seed-search-limit", "0"])


def test_semantically_equivalent_intermediate_seed_and_draw_variables():
    docs = _independent_instance(bits=64, sampling="_randbelow")
    changed = docs[0].text.replace(
        "generator.seed(randbelow(2**n))",
        "entropy = randbelow(2**n)\n    generator.seed(entropy)",
    ).replace(
        "prime_value = generator._randbelow(2**64) | 1",
        "sampled = generator._randbelow(2**64)\n"
        "        prime_value = sampled | 1",
    )
    transformed = [Document("new_control_flow.py", changed, None), docs[1]]
    assert recover_flag(transformed) == "LAB{new_rsa_message_2026}"


def test_import_aliases_and_standard_integer_encoding():
    docs = _independent_instance(bits=96, sampling="getrandbits")
    changed = docs[0].text.replace(
        "from math import prod", "from math import prod as multiply_values",
    ).replace(
        "modulus = prod(", "modulus = multiply_values(",
    ).replace(
        "from secrets import randbelow", "import secrets as entropy",
    ).replace(
        "randbelow(2**n)", "entropy.randbelow(2**n)",
    ).replace(
        "bytes_to_long(secret_bytes)", "int.from_bytes(secret_bytes, 'big')",
    )
    assert recover_flag([
        Document("different_implementation.py", changed, None),
        docs[1],
    ]) == "LAB{new_rsa_message_2026}"


def test_prime_generator_must_seed_before_its_first_candidate_draw():
    docs = _independent_instance()
    changed = docs[0].text.replace(
        "generator.seed(randbelow(2**n))",
        "",
    ).replace(
        "    return prime_value",
        "    generator.seed(randbelow(2**n))\n"
        "    return prime_value",
    )
    assert extract_instance([
        Document("late_seeding.py", changed, None),
        docs[1],
    ]) is None


def test_unrelated_prng_call_does_not_supply_prime():
    docs = _independent_instance()
    changed = docs[0].text.replace(
        "prime_value = generator._randbelow(2**64) | 1",
        "discarded = generator._randbelow(2**64)\n"
        "        prime_value = 65537",
    )
    assert extract_instance([
        Document("ignored_prng.py", changed, None), docs[1],
    ]) is None


def test_source_alone_is_a_finding_but_not_a_solvable_corpus():
    from cryptoscan.scanner import scan

    source = _independent_instance()[0]
    assert extract_instance([source]) is None
    findings = scan([source])
    relevant = [
        item for item in findings
        if item.rule == "RSA-WEAK-SEEDED-PRIME-GENERATOR"
    ]
    assert len(relevant) == 1
    assert relevant[0].evidence["public_output_matched"] is False
    assert relevant[0].recovery_status == "validation-only"
