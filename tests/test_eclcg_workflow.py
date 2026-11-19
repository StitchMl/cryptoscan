"""Tests for ECDSA-LCG artifact parsing, key validation and CLI wiring."""
import hashlib
from cryptoscan.eclcg_workflow import Instance, Q, _mul, _verify, extract_instance
from cryptoscan.cli import main
from cryptoscan.parser import Document

SOURCE = '''
from hashlib import sha256
from Crypto.Cipher import AES
def sign(d, z, k):
    r = (k * G).x
    s = (z + r * d) * pow(k, -1, q) % q
    return r, s
def lcg(a, b, p, x):
    while True:
        x = (a*x+b) % p
        yield x
msgs = [b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"]
rng = lcg(a, b, p, x)
sigs = []
for m, k in zip(msgs, rng):
    z = int.from_bytes(sha256(m).digest(), "big") % q
    r, s = sign(d, z, k)
    sigs.append((r, s))
cipher = AES.new(key, AES.MODE_CTR)
'''

def test_extract_ecdsa_lcg_instance():
    output = "sigs = " + repr([(i+1, i+2) for i in range(8)]) + "\nct = b'ciphertext'\nnonce = b'12345678'\n"
    instance = extract_instance([Document("chall.py", SOURCE, None), Document("output.txt", output, None)])
    assert instance is not None
    assert instance.messages == (b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h")
    assert instance.nonce == b"12345678"

def test_ecdsa_key_verification_rejects_wrong_private_key():
    d = 37
    pairs = []
    msgs = (b"a", b"b", b"c")
    for i, msg in enumerate(msgs):
        k = i+51
        r = _mul(k)[0] % Q
        z = int.from_bytes(hashlib.sha256(msg).digest(), "big") % Q
        s = ((z + r*d)*pow(k, -1, Q)) % Q
        pairs.append((r, s))
    inst = Instance(msgs, tuple(pairs), b"cipher", b"12345678")
    assert _verify(d, inst)
    assert not _verify(d+1, inst)

def test_cli_ecdsa_lcg_offline_dispatch(tmp_path, monkeypatch, capsys):
    (tmp_path / "chall.py").write_text(SOURCE, encoding="utf-8")
    (tmp_path / "output.txt").write_text(
        "sigs = " + repr([(i+1, i+2) for i in range(8)]) +
        "\nct = b'ciphertext'\nnonce = b'12345678'\n", encoding="utf-8")
    monkeypatch.setattr("cryptoscan.cli.recover_eclcg_flag", lambda docs: "hitcon{verified}")
    assert main([str(tmp_path), "--solve"]) == 0
    assert "FLAG: hitcon{verified}" in capsys.readouterr().out
