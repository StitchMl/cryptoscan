"""Synthetic regression tests for bytewise SPN decomposition and source recognition.

No copied CTF program, known server parameters, challenge plaintext or flag.
"""
from __future__ import annotations

import random

from cryptoscan.parser import Document
from cryptoscan.spn_linear_oracle import (
    _basis,
    extract_instance,
    recover_permutation,
)


def _synthetic_oracle(seed: int):
    rng = random.Random(seed)

    def independent(width):
        while True:
            columns = [rng.getrandbits(width) for _ in range(width)]
            if len(_basis(columns)) == width:
                return columns

    initial, final = independent(128), independent(128)
    substitution = list(range(256))
    rng.shuffle(substitution)
    offsets = [rng.randrange(256) for _ in range(16)]
    tables = []
    for slot in range(16):
        table = []
        for value in range(256):
            shifted = (substitution[value] + offsets[slot]) & 255
            result = 0
            for bit in range(8):
                if shifted >> bit & 1:
                    result ^= final[8 * slot + bit]
            table.append(result)
        tables.append(table)

    def apply_linear(value):
        result = 0
        while value:
            bit = value & -value
            result ^= initial[bit.bit_length() - 1]
            value ^= bit
        return result

    def substitute(value):
        result = 0
        for slot in range(16):
            result ^= tables[slot][(value >> (8 * slot)) & 255]
        return result

    chosen_basis = []
    while len(chosen_basis) < 16:
        candidate = rng.getrandbits(128)
        if len(_basis((*chosen_basis, candidate))) == len(chosen_basis) + 1:
            chosen_basis.append(candidate)
    transformed = [apply_linear(x) for x in chosen_basis]
    if any(len(_basis((value >> (8 * slot)) & 255 for value in transformed)) < 8
           for slot in range(16)):
        return None

    intermediate = [0] * (1 << 13)
    for index in range(1, len(intermediate)):
        bit = index & -index
        intermediate[index] = (
            intermediate[index ^ bit] ^ transformed[bit.bit_length() - 1]
        )
    oracle = [substitute(value) for value in intermediate]
    unit_outputs = [substitute(column) for column in initial]
    independent_checks = []
    for _ in range(32):
        message = rng.getrandbits(128)
        independent_checks.append((message, substitute(apply_linear(message))))
    return oracle, unit_outputs, independent_checks


def test_recovers_unseen_randomized_linear_sbox_linear_permutation():
    result = None
    for seed in range(2027, 2037):
        result = _synthetic_oracle(seed)
        if result is not None:
            break
    assert result is not None
    decoder = recover_permutation(*result)
    for plaintext, ciphertext in result[2]:
        assert decoder(ciphertext) == plaintext


def _independent_source(table_name="lookup", width_name="length"):
    return f"""
import os
import random

{width_name} = 16
{table_name} = {list(range(256))}

def xor_value(x, y):
    return x ^ y

def rotate_value(x, n):
    return (x >> n) | (x << (8-n))

def diffuse(block, session):
    random.seed(session)
    n = random.randint(1, 8)
    return xor_value(block, rotate_value(block, n))

def replace_bytes(msg, secret):
    return bytes(({table_name}[c] + secret[i]) % 256 for i, c in enumerate(msg))

def update(secret):
    return secret

def encode(msg, key=None):
    msg = pad(msg, {width_name})
    result = []
    for block in msg:
        step = update(key)
        piece = diffuse(block, step)
        piece = replace_bytes(piece, step)
        piece = diffuse(piece, step)
        result.append(piece)
    return result

message = input("chosen message: ")
for _ in range(7):
    original = os.urandom({width_name} - 1).hex()
    challenge = encode(original)
    answer = input("guess: ")
"""


def test_source_recognition_generalizes_symbol_renaming():
    for table_name, width_name in (("lookup", "length"), ("substitution", "width")):
        doc = Document("unseen_source.py", _independent_source(table_name, width_name), None)
        model = extract_instance([doc])
        assert model is not None
        assert model.rounds == 7
        assert model.message_bytes == 15
        assert model.first_prompt == "chosen message: "
        assert model.guess_prompt == "guess: "


def test_source_rejects_missing_same_key_independence():
    text = _independent_source().replace(
        "        step = update(key)\n", ""
    )
    assert extract_instance([Document("unseen_source.py", text, None)]) is None


def test_unrelated_python_is_not_a_supported_oracle():
    assert extract_instance([Document("other.py", "import random\nprint(random.randint(0, 2))", None)]) is None
