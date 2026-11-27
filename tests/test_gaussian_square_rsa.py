"""Gaussian-integer exponent inversion with disclosed squared-modulus factors."""

import ast
import json
import math
from pathlib import Path

import pytest
from sympy import nextprime

from cryptoscan.cli import main
from cryptoscan.gaussian_square_rsa import (
    extract_instance,
    gaussian_power,
    local_unit_order,
    recover_flag,
    source_profiles,
)
from cryptoscan.parser import Document, collect_documents

FIXTURE = Path(__file__).parent / "fixtures" / "gaussian_square_rsa"
SOURCE = (FIXTURE / "source.py").read_text(encoding="utf-8")


def _prime(start: int, residue: int, exponent: int) -> int:
    candidate = int(nextprime(start))
    while candidate % 4 != residue or math.gcd(exponent, local_unit_order(candidate)) != 1:
        candidate = int(nextprime(candidate))
    return candidate


def _synthetic(flag: bytes, exponent: int = 17,
               byteorder: str = "big") -> tuple[Document, Document]:
    p = _prime(1 << 64, 1, exponent)
    q = _prime((1 << 64) + 200, 3, exponent)
    n = p*p*q*q
    half = (n.bit_length() - 1) // 8
    pad = b"A" * (2*half - len(flag) - 1) + b"\x00" + flag
    assert len(pad) == 2*half
    plain = (int.from_bytes(pad[:half], byteorder),
             int.from_bytes(pad[half:], byteorder))
    width = (n.bit_length() + 7) // 8
    encrypted = b"".join(value.to_bytes(width, "big")
                         for value in gaussian_power(plain, exponent, n))
    source = SOURCE.replace("complex_mult", "gaussian_product")
    source = source.replace("complex_pow", "gaussian_exp")
    source = source.replace("65537", str(exponent))
    if byteorder == "little":
        source = source.replace('int.from_bytes(plaintext[:len(plaintext) // 2], "big")',
                                'int.from_bytes(plaintext[:len(plaintext) // 2], "little")')
        source = source.replace('int.from_bytes(plaintext[len(plaintext) // 2:], "big")',
                                'int.from_bytes(plaintext[len(plaintext) // 2:], "little")')
    output = (
        f"factors = {p, q}\nmodulus = {n}\n"
        f"c = {encrypted!r}\n"
    )
    return Document("generator.py", source, None), Document("transcript.txt", output, None)


def test_original_handout_recovers_flag_and_reencrypts():
    documents = collect_documents([str(FIXTURE)])
    flag = recover_flag(documents)
    assert flag.startswith("TetCTF{")
    instance = extract_instance(documents)
    assert instance is not None
    assert instance.p**2 * instance.q**2 == instance.modulus
    assert flag.endswith("}")


@pytest.mark.parametrize("byteorder", ["big", "little"])
def test_renamed_functions_and_source_derived_exponent(byteorder):
    documents = _synthetic(b"flag{gaussian_rsa_variant}", byteorder=byteorder)
    assert recover_flag(documents) == "flag{gaussian_rsa_variant}"
    assert source_profiles(documents[0]) == [
        type(source_profiles(documents[0])[0])(17, byteorder)
    ]


def test_planner_and_cli_solve_original_files(capsys):
    assert main([str(FIXTURE), "--plan-attacks", "--format", "json"]) == 0
    plan = json.loads(capsys.readouterr().out)["attack_plan"]
    assert any(row["family"] == "Gaussian RSA over squared semiprime"
               and row["status"] == "applicable" for row in plan)
    assert main([str(FIXTURE), "--solve"]) == 0
    assert "FLAG: TetCTF{" in capsys.readouterr().out


def test_source_and_transcript_must_match():
    source, transcript = _synthetic(b"flag{example}")
    assert extract_instance([source]) is None
    assert extract_instance([transcript]) is None
    assert extract_instance([
        source, Document(transcript.path, transcript.text, None, scope="other")
    ]) is None
    wrong_modulus = source.text.replace("(p ** 2) * (q ** 2)", "(p ** 2) * q")
    assert source_profiles(Document("generator.py", wrong_modulus, None)) == []
    wrong_multiply = source.text.replace("c1.re * c2.re - c1.im * c2.im",
                                         "c1.re * c2.re + c1.im * c2.im")
    assert source_profiles(Document("generator.py", wrong_multiply, None)) == []


def test_invalid_modulus_ciphertext_and_exponent_fail_closed():
    source, output = _synthetic(b"flag{example}")
    parsed = {stmt.targets[0].id: ast.literal_eval(stmt.value)
              for stmt in ast.parse(output.text).body}
    n, c = parsed["modulus"], parsed["c"]
    assert extract_instance([
        source, Document(output.path, output.text.replace(
            f"modulus = {n}", f"modulus = {n + 1}"), None)
    ]) is None
    invalid = output.text.replace(f"c = {c!r}", f"c = {bytes(len(c))!r}")
    with pytest.raises(RuntimeError, match="flag"):
        recover_flag([source, Document(output.path, invalid, None)])
    bad_exponent = Document(source.path, source.text.replace("17", "2"), None)
    assert source_profiles(bad_exponent) == []

