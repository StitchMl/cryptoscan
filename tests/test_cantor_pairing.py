"""Regression tests for source-gated recursive Cantor decoding."""
import json

import pytest

from cryptoscan.cantor_pairing import decode, encode, extract_instance, recover_flag
from cryptoscan.cli import main
from cryptoscan.parser import Document

SOURCE = """
def pack(data):
    k = len(data)
    if k == 1:
        return data[0]
    elif k == 2:
        x, y = data
        return ((x+y)*(x+y+1))//2+y
    return pack([pack(data[:k-k//2]), pack(data[k-k//2:])])

print(pack(flag))
"""

ORIGINAL_NUMBER = int(
    "2597749519984520018193538914972744028780767067373210633843441892910830749749277631182596420937027368405416666234869030284255514216592219508067528406889067888675964979055810441575553504341722797908073355991646423732420612775191216409926513346494355434293682149298585"
)


def test_pairing_roundtrip_for_even_and_odd_byte_lengths():
    for plain in (b"A", b"ab", b"abc", b"flag{generalized_pairing}"):
        assert decode(encode(plain), len(plain)) == plain


def test_recovers_original_numeric_handout_without_embedded_answer():
    source = Document("challenge.py", SOURCE + f"\n#{ORIGINAL_NUMBER}\n", None)
    recovered = recover_flag([source])
    assert recovered.startswith("zh3r0{")
    assert encode(recovered.encode("ascii")) == ORIGINAL_NUMBER


def test_cli_plans_and_solves_renamed_source_and_separate_output(tmp_path, capsys):
    challenge = tmp_path / "generator.py"
    challenge.write_text(SOURCE, encoding="utf-8")
    number = encode(b"flag{odd_length_test}")
    (tmp_path / "output.txt").write_text(str(number), encoding="utf-8")
    assert main([str(tmp_path), "--plan-attacks", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(item["family"] == "Recursive Cantor pairing of byte sequence"
               and item["status"] == "applicable" for item in report["attack_plan"])
    assert main([str(tmp_path), "--solve"]) == 0
    assert "FLAG: flag{odd_length_test}" in capsys.readouterr().out


def test_source_and_public_integer_are_both_required():
    number = encode(b"flag{example}")
    docs = [Document("plain.txt", str(number), None)]
    assert extract_instance(docs) is None
    assert extract_instance([Document("generator.py", SOURCE, None)]) is None
    assert extract_instance([
        Document("generator.py", SOURCE, None),
        Document("output.txt", str(number), None, scope="other"),
    ]) is None


def test_ambiguous_outputs_and_invalid_plaintext_fail_closed():
    number = encode(b"flag{example}")
    source = Document("generator.py", SOURCE, None)
    outputs = [Document("a.txt", str(number), None),
               Document("b.txt", str(number + 1), None)]
    assert extract_instance([source, *outputs]) is None
    duplicate = extract_instance([
        Document("generator.py", SOURCE + f"\n#{number}\n", None),
        Document("output.txt", str(number), None),
    ])
    assert duplicate is not None
    assert duplicate.number == number
    with pytest.raises(RuntimeError, match="expected one verified flag"):
        recover_flag([source, Document("output.txt", str(encode(b"hello")), None)])

