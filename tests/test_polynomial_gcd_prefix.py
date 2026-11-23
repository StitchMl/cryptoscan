"""Tests for source-derived polynomial-GCD prefix oracle recovery."""
from __future__ import annotations

import math

from cryptoscan.parser import Document
from cryptoscan.polynomial_gcd_prefix import (
    construct_input, extract_instance, recover_flag,
)


def invented_source(exponent=3, offset=2):
    return f'''
from math import gcd
import os

secret = os.environ.get("PAYLOAD", "TEST{{dummy}}")
user_value = int(input("select = "))
leak_length = gcd(user_value**{exponent} + 37,
                  (user_value + {offset})**{exponent} + 42)
print(secret[:leak_length])
'''


def test_source_derived_polynomial_gcd_attack():
    model = extract_instance([Document("arbitrary_script", invented_source(), None)])
    assert model is not None
    assert model.prompt == "select = "
    assert (model.first.degree(), model.second.degree()) == (3, 3)
    candidate, certified_gcd = construct_input(model)
    assert certified_gcd > 256
    assert certified_gcd == math.gcd(
        candidate**3 + 37, (candidate + 2)**3 + 42,
    )


def test_different_polynomial_exponents_and_offsets():
    for exponent, offset in ((4, 2), (5, 2), (6, 4)):
        model = extract_instance([
            Document("renamed.py", invented_source(exponent, offset), None),
        ])
        assert model is not None
        x, bound = construct_input(model)
        assert bound == math.gcd(
            x**exponent + 37, (x + offset)**exponent + 42,
        )
        assert bound > 256


def test_negative_or_unrelated_source_not_dispatched():
    assert extract_instance([Document("no_gcd", "x = int(input('x = '))", None)]) is None
    assert extract_instance([
        Document("unrelated", invented_source().replace(
            "print(secret[:leak_length])", "print(secret)",
        ), None),
    ]) is None
    assert extract_instance([
        Document("unsafe", invented_source().replace(
            "user_value**3 + 37", "__import__('os').system('echo unsafe')",
        ), None),
    ]) is None


def test_network_exchange_receives_full_flag(monkeypatch):
    import cryptoscan.polynomial_gcd_prefix as module

    class FakeSocket:
        def __init__(self):
            self.replies = [b"select = ", b"TEST{remote_verified}\n", b""]
            self.sent = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, timeout):
            assert timeout == 5

        def recv(self, count):
            return self.replies.pop(0)

        def sendall(self, data):
            self.sent.append(data)

    fake = FakeSocket()
    monkeypatch.setattr(
        module.socket, "create_connection",
        lambda *args, **kwargs: fake,
    )
    docs = [Document("server.py", invented_source(), None)]
    assert recover_flag(docs, "localhost", 1234, timeout=5) == (
        "TEST{remote_verified}"
    )
    candidate = int(fake.sent[0].strip())
    model = extract_instance(docs)
    assert math.gcd(int(model.first.eval(candidate)),
                    int(model.second.eval(candidate))) > 256


def test_cli_reports_and_dispatches_source_verified_oracle(tmp_path, monkeypatch, capsys):
    import cryptoscan.cli as cli

    (tmp_path / "renamed_source.data").write_text(
        invented_source(), encoding="utf-8",
    )
    requests = []

    def fake_recovery(documents, host, port, *, timeout):
        requests.append((host, port, timeout))
        assert extract_instance(documents) is not None
        return "TEST{verified_by_synthetic_server}"

    monkeypatch.setattr(cli, "recover_polynomial_gcd_prefix_flag", fake_recovery)
    status = cli.main([
        str(tmp_path), "--solve", "--host", "127.0.0.1",
        "--port", "34567", "--timeout", "5",
    ])
    assert status == 0
    report = capsys.readouterr().out
    assert "attacker-controlled polynomial GCD" in report
    assert "FLAG: TEST{verified_by_synthetic_server}" in report
    assert requests == [("127.0.0.1", 34567, 5.0)]


def test_math_gcd_import_alias_and_module_alias_are_equivalent():
    """Semantically equal import styles must retain the same attack."""
    source = invented_source()
    variants = (
        source.replace("from math import gcd", "from math import gcd as common")
        .replace("= gcd(", "= common("),
        source.replace("from math import gcd", "import math as arithmetic")
        .replace("= gcd(", "= arithmetic.gcd("),
    )
    for changed in variants:
        model = extract_instance([
            Document("same_vulnerability_unknown_filename", changed, None),
        ])
        assert model is not None
        candidate, measured = construct_input(model)
        assert measured == math.gcd(
            int(model.first.eval(candidate)),
            int(model.second.eval(candidate)),
        )


def test_unrelated_local_gcd_function_is_not_trusted_as_math_gcd():
    changed = invented_source().replace(
        "from math import gcd",
        "def gcd(a, b):\n    return 1000",
    )
    assert extract_instance([Document("shadowed.py", changed, None)]) is None


def test_nonunit_subresultant_can_still_reveal_long_prefix():
    """A linear modular root need not have an invertible coefficient."""
    from sympy import Poly, Symbol, subresultants
    from cryptoscan.polynomial_gcd_prefix import PolynomialGCDPrefix

    variable = Symbol("controlled_input")
    first = Poly(variable**2 - 3*variable + 188, variable)
    second = Poly(variable**2 + 15*variable - 180, variable)
    chain = subresultants(first, second)
    resulting_modulus = abs(int(chain[-1].nth(0)))
    linear = next(p for p in chain if p.degree() == 1)
    assert math.gcd(int(linear.nth(1)), resulting_modulus) > 1
    model = PolynomialGCDPrefix(first, second, "value = ", "value")
    chosen, certified = construct_input(model)
    assert certified > 256
    assert certified == math.gcd(int(first.eval(chosen)), int(second.eval(chosen)))


def test_polynomial_gcd_intermediate_aliases_are_symbolically_propagated():
    """An unseen source may calculate its public polynomials in stages."""
    original = invented_source()
    altered = original.replace(
        "leak_length = gcd(user_value**3 + 37,\n"
        "                  (user_value + 2)**3 + 42)",
        "base = user_value + 2\n"
        "first_public = user_value ** 3 + 37\n"
        "second_public = base ** 3 + 42\n"
        "leak_length = gcd(first_public, second_public)",
    )
    model = extract_instance([
        Document("new_polynomial_program.py", altered, None),
    ])
    assert model is not None
    chosen, certified = construct_input(model)
    assert certified == math.gcd(
        chosen**3 + 37, (chosen+2)**3 + 42,
    )


def test_polynomial_alias_cycle_and_untrusted_call_are_rejected():
    source = invented_source()
    original_gcd = (
        "gcd(user_value**3 + 37,\n"
        "                  (user_value + 2)**3 + 42)"
    )
    cyclic = source.replace(
        original_gcd,
        "gcd(first_public, second_public)",
    ).replace(
        "leak_length =",
        "first_public = second_public\n"
        "second_public = first_public\n"
        "leak_length =",
    )
    assert extract_instance([
        Document("bad_alias.py", cyclic, None),
    ]) is None
    untrusted = source.replace(
        original_gcd,
        "gcd(obscured(user_value), user_value**3 + 42)",
    )
    assert extract_instance([
        Document("bad_call.py", untrusted, None),
    ]) is None
