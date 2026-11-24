"""Independent examples and a public regression for rotated RSA representations."""
from pathlib import Path

import pytest

from cryptoscan.parser import Document
from cryptoscan.rotated_quadratic_rsa import (
    extract_instance,
    recover_message,
    source_profiles,
)
from cryptoscan.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"


def _synthetic(exponent, p, q, first, second):
    n = p * q
    x0, y0 = first
    x1, y1 = second
    mask = x0 ^ x1 ^ y0 ^ y1
    message = ord("A")
    ciphertext = pow(message ^ mask, exponent, n)
    # Generate source from a common structure while varying identifiers.
    source = """
modulus = factor_a * factor_b
assert alpha ** 2 + public * beta ** 2 == factor_a * factor_b
assert gamma ** 2 + public * delta ** 2 == factor_a * factor_b
payload = pow(bytes_to_long(secret) ^^ alpha ^^ beta ^^ gamma ^^ delta, public, modulus)
field = RealField(300)
observed_a = vector(field, [alpha, gamma])
observed_b = vector(field, [beta, delta])
angle = field.random_element(min=-pi, max=pi)
transform = matrix(field, [[cos(angle), -sin(angle)], [sin(angle), cos(angle)]])
observed_a = transform * observed_a
observed_b = transform * observed_b
"""
    # The rational rotation has cos=3/5 and sin=4/5.
    a = ((3*x0 - 4*x1) / 5, (4*x0 + 3*x1) / 5)
    b = ((3*y0 - 4*y1) / 5, (4*y0 + 3*y1) / 5)
    output = (f"modulus = {n}\npayload = {ciphertext}\n"
              f"observed_a = {a}\nobserved_b = {b}\n")
    # Replace literal coordinate assertions with genuine symbolic relationships.
    return [Document("source-with-unknown-name", source, None),
            Document("numeric-capture", output, None)]


@pytest.mark.parametrize(
    ("exponent", "p", "q", "first", "second"),
    [
        (5, 23, 43, (12, 13), (3, 14)),
        (7, 11, 23, (15, 2), (1, 6)),
        (11, 47, 53, (40, 9), (4, 15)),
    ],
)
def test_fresh_representations(exponent, p, q, first, second):
    docs = _synthetic(exponent, p, q, first, second)
    assert len(source_profiles(docs[0])) == 1
    instance = extract_instance(docs)
    assert instance is not None
    assert recover_message(instance) == b"A"
    assert any(f.rule == "RSA-ROTATED-QUADRATIC-REPRESENTATIONS" for f in scan(docs))


def test_public_high_precision_transcript(tmp_path, capsys):
    from cryptoscan.cli import main

    source = (FIXTURES / "kaitenzushi_source.sage").read_text(encoding="utf-8")
    output = (FIXTURES / "kaitenzushi_output.txt").read_text(encoding="utf-8")
    docs = [Document("generator.sage", source, None),
            Document("capture.txt", output, None)]
    instance = extract_instance(docs)
    assert instance is not None
    result = recover_message(instance)
    assert result.startswith(b"HackTM{")
    assert result.endswith(b"}")
    assert any(f.rule == "RSA-ROTATED-QUADRATIC-REPRESENTATIONS" for f in scan(docs))
    (tmp_path / "generator.sage").write_text(source, encoding="utf-8")
    (tmp_path / "capture.txt").write_text(output, encoding="utf-8")
    assert main([str(tmp_path), "--solve"]) == 0
    assert result.decode("utf-8") in capsys.readouterr().out


def test_missing_rotation_or_second_relation_is_not_reported():
    docs = _synthetic(5, 23, 43, (12, 13), (3, 14))
    text = docs[0].text
    for altered in (
        text.replace("observed_b = transform * observed_b", ""),
        text.replace("assert gamma ** 2 + public * delta ** 2 == factor_a * factor_b", ""),
        text.replace("^^ alpha ^^ beta ^^ gamma ^^ delta", "^^ alpha ^^ beta"),
    ):
        source = Document("other", altered, None)
        assert not source_profiles(source)
        assert extract_instance([source, docs[1]]) is None


def test_scope_and_precision_guards():
    docs = _synthetic(5, 23, 43, (12, 13), (3, 14))
    unrelated = Document("different", docs[1].text, None, "another")
    assert extract_instance([docs[0], unrelated]) is None
    broken = Document("rounded", docs[1].text.replace("4.8", "400.8"), None)
    instance = extract_instance([docs[0], broken])
    assert instance is not None
    with pytest.raises(RuntimeError):
        recover_message(instance)

