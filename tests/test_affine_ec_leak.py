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


def test_real_sage_affine_recovery_when_sage_is_available():
    """End-to-end algebra check on a generated small curve, no CTF constants."""
    import importlib.util
    from pathlib import Path

    import pytest

    sage = pytest.importorskip("sage.all")
    curve = sage.EllipticCurve(sage.GF(97), [2, 3])
    base = curve([3, 6])
    secret = 3
    hidden = secret * base
    scalars = ((1, 2), (2, 5), (4, 7), (7, 11))
    rows = []
    for u, v in scalars:
        observed = u * base + v * hidden
        rows.append([u, v, [int(c) for c in observed]])

    path = (Path(__file__).resolve().parents[1] / "src" / "cryptoscan"
            / "sage_affine_ec_leak_worker.py")
    spec = importlib.util.spec_from_file_location("test_affine_ec_sage", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module._recover({
        "prime": 97, "a": 2, "b": 3, "rows": rows,
    })
    assert (result["scalar"] - secret) % int(base.order()) == 0


def test_affine_ec_commutative_term_permutation_preserves_detection():
    """Swapping additive EC summands cannot alter the leakage equation."""
    from cryptoscan.affine_ec_leak import _source_profile

    original = invented_source()
    permuted = original.replace(
        "alpha * A + beta * B",
        "beta * B + alpha * A",
    )
    assert _source_profile(original) == _source_profile(permuted)
    transformed = [
        Document("new_algebraic_source", permuted, None),
        Document("new_transcript", invented_output(), None),
    ]
    assert extract_instance(transformed) is not None


def test_affine_ec_wrong_coefficient_pairing_is_not_accepted():
    original = invented_source()
    wrong = original.replace(
        "alpha * A + beta * B",
        "beta * A + alpha * B",
    )
    assert extract_instance([
        Document("bad_algebraic_source", wrong, None),
        Document("new_transcript", invented_output(), None),
    ]) is None


def test_affine_ec_ast_normalizes_parenthesized_point_sums():
    """The same group relation can be formatted with nested parentheses."""
    source = invented_source().replace(
        "alpha * A + beta * B",
        "(alpha * A) + (beta * B)",
    )
    model = extract_instance([
        Document("unseen_ec_source.sage", source, None),
        Document("unseen_ec_output.txt", invented_output(), None),
    ])
    assert model is not None
    assert len(model.records) == 3


def test_affine_ec_ast_rejects_unrelated_public_equation():
    source = invented_source().replace(
        "alpha * A + beta * B",
        "(alpha * B) + (beta * B)",
    )
    assert extract_instance([
        Document("unrelated_source.sage", source, None),
        Document("unseen_ec_output.txt", invented_output(), None),
    ]) is None
