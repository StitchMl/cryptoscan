"""Synthetic, source-driven tests for affine EC point-combination leakage."""
from __future__ import annotations

from cryptoscan.parser import Document
from cryptoscan.affine_ec_leak import extract_instance, recover_flag


def invented_source():
    return '''
from Crypto.Util.number import bytes_to_long
secret = bytes_to_long(open("payload.bin", "rb").read()[len("TEST{"):-1])
field_prime = 97
curve_a = 2
curve_b = 3
F = GF(field_prime)
E.<Base> = EllipticCurve(F, [curve_a, curve_b])
r = randrange(Base.order())
A = r * Base
B = secret * A
observations = []
for _ in range(4):
    alpha = randrange(Base.order())
    beta = randrange(Base.order())
    observations.append((alpha, beta, alpha * A + beta * B))
print(observations)
'''


def invented_output():
    return (
        "[(1, 2, (3 : 6 : 1)), "
        "(5, 7, (80 : 10 : 1)), "
        "(9, 11, (3 : 6 : 1))]"
    )


def documents():
    return [
        Document("invented.sage", invented_source(), None),
        Document("public.txt", invented_output(), None),
    ]


def test_source_derived_point_combination_recognition():
    instance = extract_instance(documents())
    assert instance is not None
    assert (instance.prime, instance.curve_a, instance.curve_b) == (97, 2, 3)
    assert len(instance.records) == 3
    assert instance.prefix == "TEST{"
    assert instance.suffix == "}"
    assert instance.records[1] == (5, 7, (80, 10, 1))


def test_no_discrete_log_solver_without_explicit_secret_relation():
    source = invented_source().replace("B = secret * A", "B = r * A")
    assert extract_instance([
        Document("unrelated", source, None),
        Document("public", invented_output(), None),
    ]) is None


def test_no_solver_without_matching_public_corpus():
    assert extract_instance([Document("source", invented_source(), None)]) is None
    assert extract_instance([
        Document("source", invented_source(), None),
        Document("output", "(1, 2, (100 : 6 : 1))", None),
    ]) is None


def test_sage_result_decodes_source_framing(monkeypatch):
    import cryptoscan.affine_ec_leak as module

    class FakeWorker:
        def __init__(self, name):
            assert name == "sage_affine_ec_leak_worker.py"

        def ask(self, request):
            assert request["mode"] == "recover_affine_ec_log"
            assert request["prime"] == 97
            assert len(request["rows"]) == 3
            return {"scalar": int.from_bytes(b"sample", "big")}

        def close(self):
            pass

    monkeypatch.setattr(module, "_SageWorker", FakeWorker)
    assert recover_flag(documents()) == "TEST{sample}"


def test_cli_source_verified_offline_dispatch(tmp_path, monkeypatch, capsys):
    import cryptoscan.cli as cli

    (tmp_path / "unrelated_source.sage").write_text(
        invented_source(), encoding="utf-8",
    )
    (tmp_path / "unrelated_public.txt").write_text(
        invented_output(), encoding="utf-8",
    )
    called = []

    def fake_recovery(docs):
        called.append(len(docs))
        return "TEST{synthetic_dispatch}"

    monkeypatch.setattr(cli, "recover_affine_ec_leak_flag", fake_recovery)
    status = cli.main([str(tmp_path), "--solve"])
    assert status == 0
    output = capsys.readouterr().out
    assert "Detected: public affine combinations" in output
    assert "FLAG: TEST{synthetic_dispatch}" in output
    assert called == [2]
