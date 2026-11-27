from __future__ import annotations

from cryptoscan.cli import main
from cryptoscan.integer_factorization import (
    FactorizationTask,
    extract_instance,
    recover_answer,
    smallest_prime_factor,
)
from cryptoscan.parser import Document


def test_extracts_a_generic_explicit_factorization_request() -> None:
    text = "Factorise the 150-bit number 510143758735509025530880200653196460532653147 into its primes."

    task = extract_instance([Document("challenge.txt", text, None)])

    assert task == FactorizationTask(
        510143758735509025530880200653196460532653147,
        "challenge.txt",
    )


def test_factorization_returns_smallest_certified_prime() -> None:
    task = FactorizationTask(1_000_000_016_000_000_063, "fixture")

    assert smallest_prime_factor(task) == 1_000_000_007


def test_ambiguous_factorization_requests_are_not_guessed() -> None:
    documents = [
        Document("first.txt", "Factorize 1000000007 times 1000000009.", None),
        Document("second.txt", "Factorise 1000000033 into its primes.", None),
    ]

    assert extract_instance(documents) is None


def test_unrelated_integer_is_not_treated_as_a_factorization_task() -> None:
    document = Document("notes.txt", "The modulus is 510143758735509025530880200653196460532653147.", None)

    assert extract_instance([document]) is None


def test_recover_answer_from_explicit_factorization_text() -> None:
    document = Document(
        "challenge.txt",
        "Factorize the integer 1000000016000000063 into prime factors.",
        None,
    )

    assert recover_answer([document]) == "1000000007"


def test_cli_reports_factorization_as_an_answer(tmp_path, capsys) -> None:
    challenge = tmp_path / "challenge.txt"
    challenge.write_text(
        "Factorize the integer 1000000016000000063 into prime factors.",
        encoding="utf-8",
    )

    assert main([str(challenge), "--solve"]) == 0

    assert "ANSWER: 1000000007" in capsys.readouterr().out

