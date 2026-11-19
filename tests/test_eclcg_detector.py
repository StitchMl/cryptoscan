"""Structural ECDSA/LCG recognition: does not imply private-key recovery."""
from cryptoscan.eclcg_detector import detect_ec_lcg
from cryptoscan.parser import Document
from cryptoscan.scanner import scan

SOURCE = '''
from hashlib import sha256
from Crypto.Cipher import AES
def sign(d, z, k):
    r = (k * G).x
    s = (z + r*d)*pow(k, -1, q) % q
    return r, s
def lcg(a, b, p, x):
    while True:
        x = (a*x+b) % p
        yield x
msgs = [b"a", b"b"]
rng = lcg(a, b, p, x)
sigs = []
for m, k in zip(msgs, rng):
    z = int.from_bytes(sha256(m).digest(), "big") % q
    r, s = sign(d, z, k)
    sigs.append((r,s))
cipher = AES.new(key, AES.MODE_CTR)
'''

def test_correlated_ecdsa_lcg_detection():
    docs = [Document("chall.py", SOURCE, None)]
    matches = detect_ec_lcg(docs)
    assert len(matches) == 1
    assert matches[0].signature_count == 2
    finding = next(f for f in scan(docs) if f.rule == "ECDSA-LCG-CORRELATED-NONCES")
    assert finding.recovery_status == "validation-only"
    assert finding.solver["implemented"] is False

def test_unrelated_lcg_not_reported():
    src = SOURCE.replace("for m, k in zip(msgs, rng):", "for m, k in zip(msgs, unrelated):")
    docs = [Document("chall.py", src, None)]
    assert not detect_ec_lcg(docs)

def test_missing_aes_derivation_not_reported():
    src = SOURCE.replace("cipher = AES.new(key, AES.MODE_CTR)", "")
    assert not detect_ec_lcg([Document("chall.py", src, None)])
