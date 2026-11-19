"""Regression for line-oriented parsing and bounded exception scopes."""
from cryptoscan.parser import assignments, scalar_records


def test_assignments_never_take_values_from_following_line():
    assert assignments("skip =\n key = 23\nindented = 17\n") == {
        "key": 23, "indented": 17,
    }


def test_scalar_records_remain_case_insensitive_and_line_local():
    records = scalar_records("seed: 17\n\nsecret-value: 9\nother = 3\n")
    assert records == [{"seed": 17, "secret_value": 9, "other": 3}]


def test_large_whitespace_does_not_forge_cross_line_assignments():
    source = "q =\n" * 1000 + "n = 127\n"
    assert assignments(source) == {"n": 127}
