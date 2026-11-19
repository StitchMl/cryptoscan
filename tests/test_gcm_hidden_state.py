"""CODEGATE hidden-state GCM oracle and GHASH regression tests."""
from pathlib import Path
import pytest
from cryptoscan.gcm_hidden_state import (
    gf128_mul, gf128_ghash, recognize_gcm_tag_oracle,
    recover_ghash_key_from_u1_tag_differences,
)
from cryptoscan.parser import Document, collect_documents
from cryptoscan.scanner import scan


SOURCE = """
from Crypto.Cipher import AES
from os import urandom
from signal import alarm
from secret import PoW, flag
PoW(26)
alarm(20)
gen = lambda: urandom(12)
randbit = lambda: gen()[0] & 1
key, nonce = urandom(16), gen()
new = lambda: AES.new(key, AES.MODE_GCM, nonce)
s = [gen(), gen()]
while cmd := input("> "):
    if cmd == "tag":
        cipher = new()
        cipher.update(s[0])
        cipher.encrypt(s[1])
        print(f"tag: {cipher.digest().hex()}")
    elif cmd == "u1":
        s[randbit()] = gen()
    elif cmd == "u2":
        s[randbit()] += gen()
if input(f"tag: ") == new().digest().hex():
    print(flag)
"""


def test_codegate_source_reproduces_finding():
    docs = [Document("chall.py", SOURCE, None)]
    recognized = recognize_gcm_tag_oracle(docs)
    assert len(recognized) == 1
    assert recognized[0].pow_difficulty == 26
    assert recognized[0].timeout_seconds == 20
    found = [f for f in scan(docs) if f.rule == "GCM-HIDDEN-STATE-TAG-ORACLE"]
    assert len(found) == 1
    assert found[0].recovery_status == "validation-only"
    assert found[0].solver["implemented"] is True
    assert found[0].evidence["live_server_verified"] is False


def test_no_false_positive_on_independent_nonce_or_missing_mutations():
    for changed in (SOURCE.replace("new = lambda: AES.new(key, AES.MODE_GCM, nonce)",
                                   "new = lambda: AES.new(key, AES.MODE_GCM, urandom(12))"),
                    SOURCE.replace('s[randbit()] += gen()', 'pass'),
                    SOURCE.replace('cipher.update(s[0])', 'cipher.update(b"known")')):
        assert recognize_gcm_tag_oracle([Document("chall.py", changed, None)]) == []


def test_ghash_field_arithmetic():
    identity = 1 << 127
    for a,b,c in ((123,456,789), ((1<<128)-1, 977, 6123)):
        assert gf128_mul(a, identity) == a
        assert gf128_mul(a,b^c) == gf128_mul(a,b)^gf128_mul(a,c)


def test_ghash_matches_pycryptodome_gcm():
    AES = pytest.importorskip("Crypto.Cipher.AES")
    key = bytes(range(16))
    nonce = b"0123456789ab"
    cipher_key = AES.new(key, AES.MODE_ECB)
    h = int.from_bytes(cipher_key.encrypt(bytes(16)), "big")
    pad = int.from_bytes(cipher_key.encrypt(nonce+bytes.fromhex("00000001")), "big")
    for aad, pt in ((b"",b""), (b"abcdefghijkl",b"mnopqrstuvwx"),
                    (b"A"*20,b"B"*38), (b"X"*48,b"Y"*7)):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(pt)
        assert int.from_bytes(tag, "big") == pad ^ gf128_ghash(h,aad,ciphertext)


def test_recover_ghash_key_from_real_aes_gcm_u1_tag_differences():
    import random

    AES = pytest.importorskip("Crypto.Cipher.AES")
    rng = random.Random(1319)
    key = bytes(range(16))
    nonce = b"0123456789ab"
    h = int.from_bytes(AES.new(key, AES.MODE_ECB).encrypt(bytes(16)), "big")
    aad, plaintext = (rng.randbytes(12), rng.randbytes(12))

    def tag(ad, pt):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(ad)
        cipher.encrypt(pt)
        return cipher.digest()

    previous = tag(aad, plaintext)
    differences = []
    for _ in range(150):
        if rng.randrange(2):
            aad = rng.randbytes(12)
        else:
            plaintext = rng.randbytes(12)
        now = tag(aad, plaintext)
        differences.append(bytes(a^b for a,b in zip(previous, now)))
        previous = now

    recovered = recover_ghash_key_from_u1_tag_differences(differences)
    assert recovered == h


def test_gcm_detector_survives_renamed_commands_and_variables():
    altered = (SOURCE.replace("cmd", "operation")
              .replace('"tag"', '"request_digest"')
              .replace('"u1"', '"replace_block"')
              .replace('"u2"', '"extend_block"')
              .replace("s[randbit()]", "data[randbit()]")
              .replace("s[0]", "data[0]")
              .replace("s[1]", "data[1]")
              .replace("s = [gen(), gen()]", "data = [gen(), gen()]")
              .replace("new = lambda:", "make_cipher = lambda:")
              .replace("cipher = new()", "context = make_cipher()")
              .replace("new().digest()", "make_cipher().digest()")
              .replace("cipher.update(", "context.update(")
              .replace("cipher.encrypt(", "context.encrypt(")
              .replace("cipher.digest()", "context.digest()"))
    results = recognize_gcm_tag_oracle([Document("renamed.py", altered, None)])
    assert len(results) == 1
    assert results[0].pow_difficulty == 26
    assert results[0].timeout_seconds == 20


def test_gcm_detector_ignores_new_nonce_on_each_factory_call():
    altered = SOURCE.replace(
        "new = lambda: AES.new(key, AES.MODE_GCM, nonce)",
        "def new():\\n    fresh_nonce = urandom(12)\\n"
        "    return AES.new(key, AES.MODE_GCM, fresh_nonce)"
    )
    assert not recognize_gcm_tag_oracle([Document("fresh.py", altered, None)])


def test_gcm_detector_needs_empty_message_tag_target():
    altered = SOURCE.replace("new().digest().hex()", "b'invalid'.hex()")
    assert not recognize_gcm_tag_oracle([Document("bad.py", altered, None)])


def test_generic_detector_does_not_enable_wrong_network_adapter(tmp_path, monkeypatch):
    from cryptoscan.gcm_hidden_live import supports_wire_profile
    from cryptoscan.cli import main

    source = SOURCE.replace('"u1"', '"rename_state"')
    docs = [Document("alternate.py", source, None)]
    assert len(recognize_gcm_tag_oracle(docs)) == 1
    assert not supports_wire_profile(docs)
    assert supports_wire_profile([Document("original.py", SOURCE, None)])

    def unexpected_network(*args, **kwargs):
        raise AssertionError("Wrong protocol adapter contacted the network")

    monkeypatch.setattr("cryptoscan.cli.recover_gcm_hidden_flag", unexpected_network)
    path = tmp_path / "alternate.py"
    path.write_text(source, encoding="utf-8")
    assert main([str(path), "--solve", "--host", "example.test", "--port", "2762"]) == 2
