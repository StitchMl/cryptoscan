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
