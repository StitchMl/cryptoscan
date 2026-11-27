from __future__ import annotations

import pytest

from cryptoscan.cli import main
from cryptoscan.modular_exponentiation import (
    ModularExponentiation,
    extract_instance,
    recover_answer,
)
from cryptoscan.parser import Document


def test_extracts_and_solves_generic_modular_power() -> None:
    document = Document(
        "challenge.txt",
        "Find the solution to 101^17 mod 22663.",
        None,
    )

    assert extract_instance([document]) == ModularExponentiation(
        101, 17, 22663, "challenge.txt"
    )
    assert recover_answer([document]) == "19906"


def test_accepts_hexadecimal_operands_and_modulo_wording() -> None:
    document = Document("task.md", "Compute 0x10^3 modulo 0x1001.", None)

    assert recover_answer([document]) == str(pow(16, 3, 0x1001))


def test_identical_expressions_in_multiple_files_are_unambiguous() -> None:
    documents = [
        Document("one.txt", "Calculate 7^8 mod 13.", None),
        Document("two.txt", "Calculate 7^8 mod 13.", None),
    ]

    assert recover_answer(documents) == str(pow(7, 8, 13))


def test_distinct_modular_expressions_are_not_guessed() -> None:
    documents = [
        Document("one.txt", "Calculate 7^8 mod 13.", None),
        Document("two.txt", "Calculate 8^7 mod 13.", None),
    ]

    assert extract_instance(documents) is None


def test_negative_exponent_requires_invertible_base() -> None:
    document = Document("task.txt", "Compute 2^-1 mod 4.", None)

    with pytest.raises(ValueError, match="negative exponent"):
        recover_answer([document])


def test_cli_prints_answer_for_modular_exponentiation(tmp_path, capsys) -> None:
    challenge = tmp_path / "challenge.txt"
    challenge.write_text("Find the solution to 101^17 mod 22663.", encoding="utf-8")

    assert main([str(challenge), "--solve"]) == 0

    assert "ANSWER: 19906" in capsys.readouterr().out
