from __future__ import annotations

import json

from cryptoscan.gaussian_rsa import (
    extract_instance, gaussian_totient, recover_details, recover_flag,
)
from cryptoscan.parser import Document


SOURCE = """
from collections import namedtuple
from Crypto.Util.number import getPrime

Complex = namedtuple("Complex", ["re", "im"])

def complex_mult(c1, c2, modulus):
    return Complex(
        (c1.re * c2.re - c1.im * c2.im) % modulus,
        (c1.re * c2.im + c1.im * c2.re) % modulus,
    )

def complex_pow(c, exp, modulus):
    result = Complex(1, 0)
    while exp > 0:
        if exp & 1:
            result = complex_mult(result, c, modulus)
        c = complex_mult(c, c, modulus)
        exp >>= 1
    return result

def generate_key_pair(nbits):
    p = getPrime((nbits + 3) // 4)
    q = getPrime((nbits + 3) // 4)
    n = (p ** 2) * (q ** 2)
    return (p, q), n

def encrypt(public_key, plaintext):
    n = public_key
    m = Complex(
        int.from_bytes(plaintext[:len(plaintext) // 2], "big"),
        int.from_bytes(plaintext[len(plaintext) // 2:], "big"),
    )
    c = complex_pow(m, 17, n)
    return c.re.to_bytes((n.bit_length() + 7) // 8, "big") + c.im.to_bytes((n.bit_length() + 7) // 8, "big")
"""

OUTPUT = """private_key = (13, 7)
public_key = 8281
ciphertext = b'\\x12\\xbc\\x1f\\x0a'
"""


def test_general_gaussian_totient_and_recovery():
    docs = [
        Document("source.py", SOURCE, None),
        Document("output.txt", OUTPUT, None),
    ]
    assert gaussian_totient(((13, 2), (7, 2))) == 6912
    model = extract_instance(docs)
    assert model is not None
    assert model.modulus == 8281
    assert recover_flag(docs) == "AB"
    plaintext, certificate = recover_details(model)
    assert plaintext == "AB"
    assert certificate["reencryption_verified"] is True


def test_cli_and_scanner_report_gaussian_family(tmp_path, capsys):
    from cryptoscan.cli import main

    (tmp_path / "source.py").write_text(SOURCE, encoding="utf-8")
    (tmp_path / "output.txt").write_text(OUTPUT, encoding="utf-8")
    assert main([str(tmp_path), "--solve"]) == 0
    assert "FLAG: AB" in capsys.readouterr().out
    assert main([str(tmp_path), "--plan-attacks", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(item["rule"] == "RSA-GAUSSIAN-INTEGER-DECRYPTION"
               for item in report["findings"])
    assert any(item["family"] == "Gaussian-integer RSA decryption"
               and item["status"] == "applicable"
               for item in report["attack_plan"])
