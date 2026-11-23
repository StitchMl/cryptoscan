"""Synthetic tests for source-gated quaternion equivalent-key recovery."""
from __future__ import annotations

import hashlib
import math
import random

import pytest

from cryptoscan.parser import Document
from cryptoscan.quaternion_equivalent_key import (
    _add, _equivalent_conjugator, _inverse, _mul, _parse_output,
    _source_shape, extract_instance, recover_flag,
)


def source():
    """Intentionally rename all protocol variables from the original corpus."""
    return r'''
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime

class Q:
    def __mul__(self, o):
        return o
    def invert(self):
        return self
    def __str__(self):
        return str(self)

class Engine:
    def __init__(self):
        self.mod = getPrime(32) * getPrime(32)
        self.X = Q()
        self.A = Q()
        self.B = self.X**-1 * self.A**-1 * self.X
        r = 3
        self.G = self.X**r

    @property
    def pub(self):
        return (self.mod, self.A, self.B, self.G)

    def encrypt(self, m):
        k = Q()
        K = hashlib.sha256(str(k).encode()).digest()
        c = AES.new(K, AES.MODE_CBC, iv=b"\0" * 16).encrypt(pad(m, 16))
        exponent = 5
        D = self.G**exponent
        E = D**-1 * self.A * D
        H = D**-1 * self.B * D
        M = H * k * H
        return (c, M, E)
'''


def _pow(q, exponent, n):
    result = (1, 0, 0, 0)
    while exponent:
        if exponent & 1:
            result = _mul(result, q, n)
        q = _mul(q, q, n)
        exponent >>= 1
    return result


def _fmt(q, n):
    return "(" + ",".join(f"{x} (mod {n})" for x in q) + ")"


def synthetic_instance(message=b"TEST{synthetic_quaternion_key}"):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    n = 1009 * 1013
    rng = random.Random(2026)
    def unit():
        while True:
            candidate = tuple(rng.randrange(n) for _ in range(4))
            norm = sum(v*v for v in candidate) % n
            if math.gcd(norm, n) == 1:
                return candidate

    for _ in range(100):
        alpha, chi, k = unit(), unit(), unit()
        beta = _mul(_mul(_inverse(chi, n), _inverse(alpha, n), n), chi, n)
        gamma = _pow(chi, 3, n)
        try:
            recovered = _equivalent_conjugator(alpha, beta, gamma, n)
        except RuntimeError:
            continue
        assert _mul(recovered, beta, n) == _mul(_inverse(alpha, n), recovered, n)
        break
    else:
        pytest.fail("synthetic unit generator failed to find a usable instance")
    delta = _pow(gamma, 5, n)
    epsilon = _mul(_mul(_inverse(delta, n), alpha, n), delta, n)
    kappa = _mul(_mul(_inverse(delta, n), beta, n), delta, n)
    mu = _mul(_mul(kappa, k, n), kappa, n)
    key = hashlib.sha256(_fmt(k, n).encode()).digest()
    ciphertext = AES.new(key, AES.MODE_CBC, iv=bytes(16)).encrypt(pad(message, 16))
    output = (
        "Public key: " + str(n) + "," + ",".join(_fmt(x, n) for x in
                                                  (alpha, beta, gamma))
        + "\nEncryption: " + repr(ciphertext) + ","
        + ",".join(_fmt(x, n) for x in (mu, epsilon))
    )
    return [Document("unrelated.py", source(), None),
            Document("public_data.txt", output, None)], message


def test_source_and_output_are_matched_by_structure():
    documents, plaintext = synthetic_instance()
    profile = extract_instance(documents)
    assert profile is not None
    assert profile.modulus == 1009 * 1013
    assert profile.iv == bytes(16)
    assert len(profile.public) == 3
    assert profile.ciphertext
    assert plaintext.startswith(b"TEST{")


def test_synthetic_equivalent_key_recovers_plaintext():
    documents, message = synthetic_instance()
    assert recover_flag(documents) == message.decode()


def test_rejects_unrelated_or_perturbed_equations():
    documents, _ = synthetic_instance()
    altered = source().replace("M = H * k * H", "M = H * k")
    assert _source_shape(altered) is None
    assert extract_instance([
        Document("unrelated.py", altered, None), documents[1],
    ]) is None


def test_rejects_bad_public_modulus_and_missing_source():
    documents, _ = synthetic_instance()
    assert extract_instance([documents[1]]) is None
    invalid = documents[1].text.replace(
        "(mod 1022117)", "(mod 1022118)",
    )
    assert _parse_output(invalid) is None


def test_cli_dispatches_offline_quaternion_solver(tmp_path, monkeypatch, capsys):
    import cryptoscan.cli as cli

    documents, _ = synthetic_instance()
    (tmp_path / "renamed.py").write_text(documents[0].text, encoding="utf-8")
    (tmp_path / "data.txt").write_text(documents[1].text, encoding="utf-8")
    monkeypatch.setattr(
        cli, "recover_quaternion_flag", lambda docs: "TEST{synthetic_dispatch}",
    )
    assert cli.main([str(tmp_path), "--solve"]) == 0
    report = capsys.readouterr().out
    assert "equivalent quaternion conjugation key" in report.lower()
    assert "FLAG: TEST{synthetic_dispatch}" in report


def test_quaternion_class_renaming_is_semantically_equivalent():
    """Changing an algebra implementation's class name must not hide the leak."""
    documents, message = synthetic_instance()
    renamed = documents[0].text.replace("class Q:", "class QuaternionElement:")
    renamed = renamed.replace("Q()", "QuaternionElement()")
    revised = [
        Document(documents[0].path, renamed, None),
        documents[1],
    ]
    assert _source_shape(renamed) == bytes(16)
    assert recover_flag(revised) == message.decode()


def test_quaternion_without_inverse_method_is_not_claimed():
    source_without_inverse = source().replace("def invert(self):", "def reciprocal(self):")
    assert _source_shape(source_without_inverse) is None
