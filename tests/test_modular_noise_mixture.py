"""Metamorphic tests: unseen mixed-LWE samplers, no known challenge constants.

Real and fake blocks are generated from independently seeded random
vectors, key lengths, noise divisibility, sampler ordering and messages.
The mathematically recoverable key is its residue modulo 2**t, not its
entire original byte value.
"""
from __future__ import annotations

import json
import random

import pytest

from cryptoscan.modular_noise_mixture import (
    _source_profile, extract_instance, recover_details, recover_flag,
)
from cryptoscan.parser import Document


def independent_corpus(*, keybytes=8, shift=1, samples=10,
                       flag=b"LAB{new_mixture_model}", orientation=0):
    rng = random.Random(923 + keybytes * 2 + shift)
    order = ("honest", "decoy") if orientation == 0 else ("decoy", "honest")
    source = f'''
import secrets

def noise_factory():
    z = 0
    for _ in range(7):
        z |= secrets.randbelow(2)
        z <<= {shift}
    return z

def key_material():
    return secrets.token_bytes({keybytes})

def inner_product(u, v):
    return sum(a * b for a, b in zip(u, v))

def honest(secret):
    vector = secrets.token_bytes(len(secret))
    delta = noise_factory() - 64
    return vector, (inner_product(vector, secret) + delta) % 256

def decoy(secret):
    vector = secrets.token_bytes(len(secret))
    return vector, secrets.randbelow(256)

def message_bits():
    bs = b''
    return [(value >> index) & 1
            for value in bs for index in range(8)]

if __name__ == "__main__":
    secret = key_material()
    for bit in message_bits():
        print([[{order[0]}, {order[1]}][bit](secret)
               for _ in range({samples})])
'''
    key = [rng.randrange(256) for _ in range(keybytes)]
    groups = []
    for byte in flag:
        for index in range(8):
            bit = (byte >> index) & 1
            authentic = bit == orientation
            group = []
            for _ in range(samples):
                vector = bytes(rng.randrange(256) for _ in range(keybytes))
                if authentic:
                    noise = (rng.getrandbits(7) << shift) - 64
                    value = (sum(a * b for a, b in zip(vector, key)) + noise) % 256
                else:
                    value = rng.randrange(256)
                group.append((vector, value))
            groups.append(group)
    documents = [
        Document("previously_unseen_program.py", source, None),
        Document("arbitrary_public_corpus.log", "\n".join(map(str, groups)), None),
    ]
    return documents, key


@pytest.mark.parametrize("keybytes", [8, 16])
@pytest.mark.parametrize("shift", [1, 2])
def test_recovers_key_residues_with_variable_dimensions(keybytes, shift):
    docs, full_key = independent_corpus(keybytes=keybytes, shift=shift)
    instance = extract_instance(docs)
    assert instance is not None
    assert instance.key_bytes == keybytes
    assert instance.noise_bits == shift
    message, evidence = recover_details(instance, trials=1024)
    assert message == "LAB{new_mixture_model}"
    assert evidence["key_residues"] == tuple(x % (1 << shift) for x in full_key)
    assert evidence["noise_divisibility"] == (1 << shift)


@pytest.mark.parametrize("orientation", [0, 1])
def test_reversing_the_real_fake_selector_preserves_recovery(orientation):
    docs, _ = independent_corpus(orientation=orientation)
    instance = extract_instance(docs)
    assert instance.true_bit == orientation
    assert recover_flag(docs) == "LAB{new_mixture_model}"


def test_renamed_functions_and_variables_are_recognized():
    docs, _ = independent_corpus()
    source = docs[0].text
    for old, new in (
        ("noise_factory", "random_even_error"),
        ("key_material", "make_secret"),
        ("inner_product", "linear_form"),
        ("honest", "authentic_sample"),
        ("decoy", "random_sample"),
        ("message_bits", "encode_bits"),
        ("vector", "public_coefficients"),
    ):
        source = source.replace(old, new)
    assert recover_flag([
        Document("different_names.py", source, None), docs[1],
    ]) == "LAB{new_mixture_model}"


@pytest.mark.parametrize("transformation", [
    lambda s: s.replace("z <<= 1", "z >>= 1"),
    lambda s: s.replace("noise_factory() - 64", "noise_factory() - 63"),
    lambda s: s.replace("secrets.randbelow(256)", "secrets.randbelow(128)"),
    lambda s: s.replace("range(8)", "range(7)"),
    lambda s: s.replace("inner_product(vector, secret)", "sum(vector)"),
])
def test_rejects_sources_without_proven_modular_linear_leak(transformation):
    docs, _ = independent_corpus()
    invalid = transformation(docs[0].text)
    assert _source_profile(invalid) is None


def test_mismatched_or_ambiguous_public_corpora_not_joined():
    docs, _ = independent_corpus()
    assert extract_instance([
        docs[0], Document("other_scope.log", docs[1].text, None, "other"),
    ]) is None
    assert extract_instance([
        *docs, Document("duplicate.log", docs[1].text, None),
    ]) is None


def test_source_only_scanner_detects_weakness_without_claiming_recovery():
    from cryptoscan.scanner import scan

    docs, _ = independent_corpus()
    assert extract_instance(docs[:1]) is None
    relevant = [
        finding for finding in scan(docs[:1])
        if finding.rule == "LWE-MODULAR-NOISE-SUBGROUP-LEAK"
    ]
    assert len(relevant) == 1
    assert relevant[0].evidence["public_transcript_matched"] is False
    assert relevant[0].evidence["noise_trailing_zero_bits"] == 1


def test_cli_finds_and_solves_independent_mixture(tmp_path, capsys):
    from cryptoscan import cli

    docs, _ = independent_corpus()
    for doc in docs:
        (tmp_path / doc.path).write_text(doc.text, encoding="utf-8")
    assert cli.main([str(tmp_path), "--plan-attacks", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(
        item["status"] == "applicable"
        and item["family"] == "Modular-noise LWE mixture linear distinguisher"
        for item in report["attack_plan"]
    )
    assert any(
        finding["rule"] == "LWE-MODULAR-NOISE-SUBGROUP-LEAK"
        for finding in report["findings"]
    )
    assert cli.main([str(tmp_path), "--solve"]) == 0
    assert "FLAG: LAB{new_mixture_model}" in capsys.readouterr().out


def test_random_decoy_only_has_no_recoverable_linear_secret():
    docs, _ = independent_corpus(flag=b"LAB{new_mixture_model}")
    model = extract_instance(docs)
    rng = random.Random(202611)
    from dataclasses import replace

    random_groups = tuple(
        tuple((vector, rng.randrange(256)) for vector, _ in group)
        for group in model.groups
    )
    modified = replace(model, groups=random_groups)
    with pytest.raises(RuntimeError, match="statistically distinguishable"):
        recover_details(modified, trials=256)


def test_unseen_shifted_linear_noise_emits_hypothesis_not_unsupported_solver():
    from cryptoscan.crypto_hypotheses import inspect_hypotheses

    code = """
from secrets import randbelow
def unknown_distribution(vector, key):
    offset = randbelow(128) << 2
    linear = sum(x*y for x,y in zip(vector, key))
    return (linear + offset) % 1024
"""
    doc = Document("unseen_variant.py", code, None)
    assert extract_instance([doc]) is None
    assert any(
        hypothesis.family == "Noise-subgroup leakage in linear modular samples"
        for hypothesis in inspect_hypotheses([doc])
    )
