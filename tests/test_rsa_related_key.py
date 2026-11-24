import pytest

from cryptoscan.parser import Document
from cryptoscan.rsa_related_key import extract_instance, recover_message, source_profiles
from cryptoscan.scanner import scan


def corpus(exponent):
    n = 101 * 113
    order = 100 * 112
    inverse = pow(exponent, -1, order)
    source = f"""
public = {exponent}
modulus = first * second
order = (first - 1) * (second - 1)
private = pow(public, -1, order)
alpha = pow(private, public, modulus)
beta = pow(order, public, modulus)
gamma = pow(secret, public, modulus)
"""
    output = f"modulus = {n}\nalpha = {pow(inverse, exponent, n)}\n"
    output += f"beta = {pow(order, exponent, n)}\ngamma = {pow(65, exponent, n)}\n"
    return [Document("renamed", source, None), Document("numbers", output, None)]


@pytest.mark.parametrize("exponent", [3, 11, 13, 17])
def test_recovery(exponent):
    docs = corpus(exponent)
    instance = extract_instance(docs)
    assert instance is not None
    assert recover_message(instance) == b"A"


def test_detection():
    docs = corpus(3)
    assert any(f.rule == "RSA-RELATED-KEY-MATERIAL" for f in scan(docs))


def test_source_only():
    docs = corpus(3)
    assert source_profiles(docs[0])
    assert extract_instance(docs[:1]) is None


def test_no_inverse():
    docs = corpus(3)
    source = docs[0].text.replace("pow(public, -1, order)", "pow(public, 1, order)")
    assert not source_profiles(Document("ordinary", source, None))


def test_unrelated_scope():
    docs = corpus(3)
    assert extract_instance([docs[0], Document("other", docs[1].text, None, "elsewhere")]) is None


def test_cli_large_message_and_source_only_exponent(tmp_path, capsys):
    from sympy import nextprime

    from cryptoscan.cli import main

    exponent = 3
    primes = []
    for offset in (123, 98765):
        prime = int(nextprime((1 << 1023) + offset))
        while prime % exponent != 2:
            prime = int(nextprime(prime))
        primes.append(prime)
    p, q = primes
    n = p * q
    order = (p - 1) * (q - 1)
    private = pow(exponent, -1, order)
    token = "TEST{" + "related" * 35 + "}"
    message = int.from_bytes(token.encode(), "big")
    assert message < n < message ** exponent
    source = corpus(exponent)[0].text.replace(
        "modulus = first * second",
        "first = getStrongPrime(1024, e=public)\n"
        "second = getStrongPrime(1024, e=public)\n"
        "modulus = first * second",
    )
    output = (
        f"modulus = {n}\nalpha = {pow(private, exponent, n)}\n"
        f"beta = {pow(order, exponent, n)}\n"
        f"gamma = {pow(message, exponent, n)}\n"
    )
    (tmp_path / "arbitrary.py").write_text(source, encoding="utf-8")
    (tmp_path / "arbitrary.txt").write_text(output, encoding="utf-8")
    assert main([str(tmp_path), "--format", "json"]) == 0
    assert "RSA-RELATED-KEY-MATERIAL" in capsys.readouterr().out
    assert main([str(tmp_path), "--solve"]) == 0
    assert token in capsys.readouterr().out


def test_detection_does_not_require_payload_ciphertext():
    docs = corpus(3)
    source = docs[0].text.replace("gamma = pow(secret, public, modulus)\n", "")
    profile = source_profiles(Document("only-key-material", source, None))[0]
    assert profile.message_cipher is None
    findings = scan([Document("only-key-material", source, None)])
    assert any(f.rule == "RSA-RELATED-KEY-MATERIAL" for f in findings)


def test_detection_does_not_guess_between_multiple_payloads():
    docs = corpus(3)
    source = docs[0].text + "delta = pow(other_secret, public, modulus)\n"
    profile = source_profiles(Document("several-payloads", source, None))[0]
    assert profile.message_cipher is None
    assert extract_instance([Document("several-payloads", source, None), docs[1]]) is None


def test_large_public_exponent_is_detected_but_not_claimed_solvable():
    docs = corpus(65537)
    profiles = source_profiles(docs[0])
    assert profiles and profiles[0].exponent == 65537
    assert any(f.rule == "RSA-RELATED-KEY-MATERIAL" for f in scan(docs))
    assert extract_instance(docs) is None
