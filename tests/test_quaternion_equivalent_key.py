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


def test_quaternion_public_accessor_renaming_preserves_equivalence():
    documents, plaintext = synthetic_instance()
    rewritten = documents[0].text.replace("def pub(self):", "def exposed_values(self):")
    # Whitespace and tuple formatting changes must not alter AST roles.
    rewritten = rewritten.replace(
        "return (self.mod, self.A, self.B, self.G)",
        "return (\n            self.mod,\n            self.A,\n            self.B,\n            self.G,\n        )",
    )
    transformed = [Document("independent_case.py", rewritten, None), documents[1]]
    assert _source_shape(rewritten) == bytes(16)
    assert recover_flag(transformed) == plaintext.decode()


def test_quaternion_public_tuple_order_is_a_required_equation():
    changed = source().replace(
        "return (self.mod, self.A, self.B, self.G)",
        "return (self.mod, self.B, self.A, self.G)",
    )
    assert _source_shape(changed) is None


def test_quaternion_parenthesized_multiline_equations_are_equivalent():
    """AST normalization must ignore harmless grouping and formatting."""
    documents, plaintext = synthetic_instance()
    changed = documents[0].text
    changed = changed.replace(
        "self.B = self.X**-1 * self.A**-1 * self.X",
        "self.B = (self.X ** (-1)) * ((self.A ** (-1)) * self.X)",
    ).replace(
        "E = D**-1 * self.A * D",
        "E = (D ** (-1)) * (self.A * D)",
    ).replace(
        "H = D**-1 * self.B * D",
        "H = ((D ** (-1)) * self.B) * D",
    ).replace(
        "M = H * k * H",
        "M = H * (k * H)",
    )
    modified = [Document("unknown_quaternion_variant", changed, None), documents[1]]
    assert _source_shape(changed) == bytes(16)
    assert recover_flag(modified) == plaintext.decode()


def test_quaternion_noncommutative_operand_swap_is_rejected():
    changed = source().replace(
        "self.B = self.X**-1 * self.A**-1 * self.X",
        "self.B = self.X**-1 * self.X * self.A**-1",
    )
    assert _source_shape(changed) is None


def test_quaternion_output_tolerates_unrelated_log_lines_and_labels():
    documents, plaintext = synthetic_instance()
    rewritten = (
        "starting session\n"
        + documents[1].text.replace("Public key:", "Published parameters:")
        .replace("Encryption:", "Sealed message:")
        + "\nstatistics: completed\n"
    )
    transformed = [
        documents[0],
        Document("different_log_format", rewritten, None),
    ]
    assert extract_instance(transformed) is not None
    assert recover_flag(transformed) == plaintext.decode()


def test_quaternion_duplicate_public_records_are_ambiguous():
    documents, _ = synthetic_instance()
    first = documents[1].text.splitlines()[0]
    duplicate = first + "\n" + documents[1].text
    assert _parse_output(duplicate) is None


def test_generalized_crt_solves_noninvertible_modular_equations():
    from cryptoscan.quaternion_equivalent_key import _solve_modular_scalar_system
    # No individual coefficient is a unit modulo 15, but combined
    # constraints uniquely determine the scalar.
    residue, period = _solve_modular_scalar_system(
        [3, 5], [6, 10], 15,
    )
    assert period == 15
    assert residue == 2


def test_generalized_crt_detects_inconsistent_equations():
    from cryptoscan.quaternion_equivalent_key import _solve_modular_scalar_system
    with pytest.raises(RuntimeError, match="inconsistent"):
        _solve_modular_scalar_system([6], [5], 15)
    with pytest.raises(RuntimeError, match="incompatible"):
        _solve_modular_scalar_system([2, 2], [0, 2], 12)


def test_generalized_crt_retains_partial_solution_period():
    from cryptoscan.quaternion_equivalent_key import _solve_modular_scalar_system
    residue, period = _solve_modular_scalar_system(
        [6, 0], [6, 0], 18,
    )
    assert period == 3
    assert residue == 1
    assert all((a * residue - b) % 18 == 0
               for a, b in zip([6, 0], [6, 0]))
