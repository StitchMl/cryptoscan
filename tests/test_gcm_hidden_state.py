"""CODEGATE hidden-state GCM oracle and GHASH regression tests."""
from pathlib import Path
import pytest
from cryptoscan.gcm_hidden_state import (
    gf128_mul, gf128_ghash, recognize_gcm_tag_oracle,
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
    assert found[0].solver["implemented"] is False


def test_no_false_positive_on_independent_nonce_or_missing_mutations():
    for changed in (SOURCE.replace("new = lambda: AES.new(key, AES.MODE_GCM, nonce)",
                                   "new = lambda: AES.new(key, AES.MODE_GCM, urandom(12))"),
                    SOURCE.replace('elif cmd == "u2":', 'elif cmd == "unused":'),
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
