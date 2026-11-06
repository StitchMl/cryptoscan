"""Independent PKCS#1 v1.5 known-positive padding leak regression tests.

Creates RSA keys/ciphertexts and an oracle transcript independently of any
published CTF data; a successful plaintext must pass exact re-encryption.
"""
from __future__ import annotations

import math
import random
from dataclasses import replace

from Crypto.PublicKey import RSA
from sympy import nextprime

from cryptoscan.parser import Document, scalar_records, pem_rsa_public_keys
from cryptoscan.rsa_padding_positives import (
    _check_candidate,
    _source_names,
    discover_positive_padding_oracles,
    recover_pkcs1_positive_padding,
)
from cryptoscan.rsa_padding_workflow import positive_padding_workflow
from cryptoscan.scanner import scan


def fixture(seed: int = 1711):
    rng = random.Random(seed)
    p = int(nextprime((1 << 134) + rng.getrandbits(119)))
    q = int(nextprime((1 << 134) + rng.getrandbits(119)))
    n, e = p * q, 65537
    size = (n.bit_length() + 7) // 8
    B = 1 << (8 * (size - 2))
    plaintext = b"flag{test}"
    pad = bytes(rng.randrange(1, 256) for _ in range(size - len(plaintext) - 3))
    representative = int.from_bytes(
        b"\x00\x02" + pad + b"\x00" + plaintext, "big"
    )
    assert 2 * B <= representative < 3 * B
    assert math.gcd(representative, n) == 1
    ciphertext = pow(representative, e, n)
    inverse = pow(representative, -1, n)
    positive = []
    for _ in range(24):
        pad = bytes(rng.randrange(1, 256) for _ in range(size - 3 - 6))
        payload = bytes(rng.randrange(1, 256) for _ in range(6))
        valid = int.from_bytes(b"\x00\x02" + pad + b"\x00" + payload, "big")
        assert 2 * B <= valid < 3 * B
        positive.append(valid * inverse % n)
    pubkey = RSA.construct((n, e)).public_key().export_key().decode()
    source = """
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

class Check:
    def __init__(self):
        self.key = RSA.import_key(open("privkey.pem", "rb").read())
        self.cipher = PKCS1_v1_5.new(self.key)

    def verify(self, c):
        return int(self.cipher.decrypt(c, sen := get_random_bytes(16)) != sen)

    def encrypt(self, m):
        return self.cipher.encrypt(m)

ver = Check()
enc_flag = ver.encrypt(b"example").hex()
assert all(ver.verify(pow(r, ver.key.e, ver.key.n) * int(enc_flag, 16) % ver.key.n) for r in R)
"""
    docs = [
        Document("example/source.py", source, None, "example", "s"),
        Document("example/pub.pem", pubkey, None, "example", "p"),
        Document(
            "example/output.txt",
            f"enc_flag = {ciphertext.to_bytes(size, 'big').hex()!r}\nR = {positive!r}\n",
            None, "example", "o",
        ),
    ]
    return docs, representative, plaintext


def test_source_recognizes_public_key_and_positive_transcript():
    docs, representative, plaintext = fixture()
    assert _source_names(docs[0].text) is not None, "source AST oracle detection failed"
    assert len(pem_rsa_public_keys(docs[1].text)) == 1, "PEM parsing failed"
    records = scalar_records(docs[2].text)
    assert records and "enc_flag" in records[0] and "r" in records[0], "transcript parse failed"
    matches = discover_positive_padding_oracles(docs)
    assert len(matches) == 1
    oracle = matches[0]
    assert oracle.modulus.bit_length() >= 256
    assert len(oracle.positive_multipliers) == 24
    assert _check_candidate(representative, oracle) == plaintext
    findings = scan(docs)
    oracle_findings = [f for f in findings
                       if f.rule == "RSA-PKCS1-V15-POSITIVE-PADDING-LEAK"]
    assert len(oracle_findings) == 1
    assert oracle_findings[0].recovery_status == "validation-only"


def test_kannan_embedding_recovers_rsa_plaintext_without_private_key():
    docs, representative, plaintext = fixture()
    oracle = discover_positive_padding_oracles(docs)[0]
    candidates = recover_pkcs1_positive_padding(
        oracle, backend="sympy", counts=(24,), progress=lambda _: None,
    )
    assert any(
        item["plaintext"] == plaintext
        and item["representative"] == representative
        and item["reencryption_verified"]
        and item["positive_constraints_verified"] == 24
        for item in candidates
    )


def test_native_flint_backend_matches_sympy():
    import pytest
    pytest.importorskip("flint")
    docs, representative, plaintext = fixture()
    oracle = discover_positive_padding_oracles(docs)[0]
    results = recover_pkcs1_positive_padding(
        oracle, backend="flint", counts=(24,), progress=lambda _: None
    )
    assert any(item["plaintext"] == plaintext for item in results)


def test_negative_transcript_cannot_claim_recovery():
    docs, _, _ = fixture()
    oracle = discover_positive_padding_oracles(docs)[0]
    corrupted = replace(oracle, ciphertext=(oracle.ciphertext + 1) % oracle.modulus)
    assert _check_candidate(123456789, corrupted) is None
    result = recover_pkcs1_positive_padding(
        corrupted, backend="sympy", counts=(24,), progress=lambda _: None
    )
    assert result == []


def test_without_source_proof_no_padding_oracle():
    docs, _, _ = fixture()
    bad = docs[0].text.replace("self.cipher.decrypt(c, sen", "self.cipher.encrypt(c, sen")
    replacement = Document(docs[0].path, bad, None, "example", "x")
    assert discover_positive_padding_oracles([replacement, *docs[1:]]) == []


def test_assistant_is_opt_in_and_reports_verified_plaintext():
    docs, _, plaintext = fixture()
    finding = next(f for f in scan(docs)
                   if f.rule == "RSA-PKCS1-V15-POSITIVE-PADDING-LEAK")
    messages = []
    positive_padding_workflow(finding, docs, lambda _: "n", messages.append)
    assert any("No lattice operation started" in item for item in messages)
