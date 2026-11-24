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
