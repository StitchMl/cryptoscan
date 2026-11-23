"""General synthetic tests for ring-scalar distribution anonymity leaks."""
from __future__ import annotations

import json
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from cryptoscan.parser import Document
from cryptoscan.ring_scalar_anonymity import (
    extract_instance, recover_flag, signer_candidates,
)

ORDER = 2**252 + 27742317777372353535851937790883648493


def source():
    # Roles and temporary variables intentionally differ from challenge.
    return """
import random
from Crypto.Cipher import AES
from os import urandom
def sample_response():
    return random.SystemRandom().getrandbits(256)
def sign(member, group):
    responses_a = [sample_response() for _ in group]
    responses_b = [sample_response() for _ in group]
    responses_a[member] = (42 - 23) % ed25519.l
    responses_b[member] = (23 + 17) % ed25519.l
    return responses_a, responses_b
levels = []
key = bytes.fromhex("".join(level["public_keys"][level["my_key"]][0:2]
                            for level in levels))
cipher = AES.new(key, AES.MODE_CBC, urandom(16))
"""


def helper():
    return """
l = 2**252 + 27742317777372353535851937790883648493
"""


def documents(*, padded=False, ambiguous=True):
    rng = random.Random(713)
    levels, chosen = [], []
    for ring in range(16):
        actual = rng.randrange(16)
        chosen.append(actual)
        keys = [rng.randbytes(32).hex() for _ in range(16)]
        c = [(1 << 254) + i for i in range(16)]
        r = [(1 << 254) + i + 256 for i in range(16)]
        c[actual] = rng.randrange(ORDER)
        r[actual] = rng.randrange(ORDER)
        if ambiguous and ring == 1:
            fake = (actual + 1) % 16
            c[fake], r[fake] = 11, 31
        levels.append({
            "signature": ["00" * 32, c, r], "public_keys": keys,
        })
    key = bytes.fromhex("".join(level["public_keys"][idx][:2]
                                for level, idx in zip(levels, chosen)))
    iv = bytes(range(16))
    message = b"TEST{generalized_ring_signature}"
    if padded:
        message = pad(message, 16)
    assert len(message) % 16 == 0
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(message)
    return [
        Document("different_source.py", source(), None),
        Document("different_curve.py", helper(), None),
        Document("public_data.json", json.dumps({
            "levels": levels, "iv": iv.hex(), "enc": encrypted.hex(),
        }), None),
    ]


def test_source_detected_and_scalar_bounds_filter_candidates():
    docs = documents()
    model = extract_instance(docs)
    assert model is not None
    assert model.order == ORDER
    assert model.key_slice == (0, 2)
    assert len(model.levels) == 16
    options = [signer_candidates(level, ORDER) for level in model.levels]
    assert [len(option) for option in options].count(2) == 1
    assert all(len(option) <= 2 for option in options)


def test_unpadded_cbc_decrypts_and_ambiguous_signer_resolves():
    assert recover_flag(documents()) == "TEST{generalized_ring_signature}"


def test_padded_cbc_decrypts():
    assert recover_flag(documents(padded=True)) == (
        "TEST{generalized_ring_signature}"
    )


def test_no_detection_for_uniform_response_scalar_generation():
    docs = documents()
    changed = source().replace("% ed25519.l", "")
    assert extract_instance([
        Document("different_source.py", changed, None), *docs[1:],
    ]) is None


def test_no_detection_without_curve_order_or_public_data():
    docs = documents()
    assert extract_instance(docs[:2]) is None
    assert extract_instance([docs[0], docs[2]]) is None


def test_cli_dispatch(tmp_path, monkeypatch, capsys):
    import cryptoscan.cli as cli

    for doc in documents():
        (tmp_path / doc.path).write_text(doc.text, encoding="utf-8")
    calls = []

    def synthetic_solver(given_documents):
        calls.append(len(given_documents))
        return "TEST{synthetic_cli}"

    monkeypatch.setattr(cli, "recover_ring_scalar_leak_flag", synthetic_solver)
    assert cli.main([str(tmp_path), "--solve"]) == 0
    report = capsys.readouterr().out
    assert "ring signature signer anonymity leak" in report
    assert "FLAG: TEST{synthetic_cli}" in report
    assert calls == [3]
