"""A public residue makes a multiplicative exchange key public."""

import json
from pathlib import Path

import pytest

from cryptoscan.cli import main
from cryptoscan.parser import Document, collect_documents
from cryptoscan.public_residue_exchange import (
    extract_instance,
    recover_flag,
    source_profiles,
)

FIXTURE = Path(__file__).parent / "fixtures" / "joke_cipher"
SOURCE = """
class Exchange:
    def __init__(self, modulus, secret):
        self.modulus = modulus
        self.secret = secret
        self.published = self.secret % self.modulus

    def begin(self, other):
        alpha = self.published * other
        combined = (3 * alpha * other * self.secret) % self.modulus
        self.session = combined

    def seal(self, value):
        shared = self.session
        return value * shared

def prepare(flag):
    return int.from_bytes(flag, 'little')
"""


def _synthetic(flag: bytes) -> tuple[Document, Document]:
    p, public_a, public_b = 65537, 47, 91
    key = 3 * public_a**2 * public_b**2 % p
    ciphertext = int.from_bytes(flag, "little") * key
    source = Document("chall.py", SOURCE, None)
    output = Document(
        "output.txt",
        f"modulus = {p}\npublic_a = {public_a}\n"
        f"public_b = {public_b}\nciphertext = {ciphertext}\n",
        None,
    )
    return source, output


def test_real_handout_recovers_a_verified_flag():
    documents = collect_documents([str(FIXTURE)])
    flag = recover_flag(documents)
    assert flag.startswith("hkcert21{")
    instance = extract_instance(documents)
    assert instance is not None
    shared = (pow(instance.public_a, instance.profile.public_power, instance.p)
              * pow(instance.public_b, instance.profile.peer_power, instance.p)
              * instance.profile.coefficient) % instance.p
    assert int.from_bytes(flag.encode(), "big") * shared == instance.ciphertext


def test_generalized_names_coefficient_and_little_endian(capsys, tmp_path):
    flag = b"flag{public_residue}"
    source, output = _synthetic(flag)
    assert recover_flag([source, output]) == flag.decode()
    (tmp_path / "chall.py").write_text(source.text, encoding="utf-8")
    (tmp_path / "output.txt").write_text(output.text, encoding="utf-8")
    assert main([str(tmp_path), "--plan-attacks", "--format", "json"]) == 0
    plan = json.loads(capsys.readouterr().out)["attack_plan"]
    assert any(row["family"] == "Public-residue multiplicative exchange"
               and row["status"] == "applicable" for row in plan)
    assert main([str(tmp_path), "--solve"]) == 0
    assert "FLAG: flag{public_residue}" in capsys.readouterr().out


def test_missing_or_mismatched_evidence_does_not_activate():
    source, output = _synthetic(b"flag{example}")
    assert extract_instance([output]) is None
    assert extract_instance([source]) is None
    assert extract_instance([
        source, Document(output.path, output.text, None, scope="another")
    ]) is None
    assert source_profiles(Document("chall.py", SOURCE.replace(
        "self.secret % self.modulus", "self.secret % 123"
    ), None)) == []
    assert source_profiles(Document("chall.py", SOURCE.replace(
        "return value * shared", "return (value * shared) % self.modulus"
    ), None)) == []


def test_invalid_ciphertext_and_zero_shared_key_are_rejected():
    source, output = _synthetic(b"flag{example}")
    instance = extract_instance([source, output])
    assert instance is not None
    with pytest.raises(RuntimeError, match="exact multiple"):
        recover_flag([source, Document(output.path, output.text.replace(
            f"ciphertext = {instance.ciphertext}",
            f"ciphertext = {instance.ciphertext + 1}"
        ), None)])
    zero = Document(output.path, output.text.replace("public_a = 47", "public_a = 0"), None)
    with pytest.raises(RuntimeError, match="key is zero"):
        recover_flag([source, zero])


def test_ambiguous_transcripts_and_nonflag_plaintext_fail_closed():
    source, output = _synthetic(b"flag{example}")
    second = Document("another.txt", output.text.replace(
        "public_a = 47", "public_a = 48"
    ), None)
    assert extract_instance([source, output, second]) is None
    other_source, other_output = _synthetic(b"hello world")
    with pytest.raises(RuntimeError, match="flag shape"):
        recover_flag([other_source, other_output])

