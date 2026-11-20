"""Generic NTRU folding/worker/CLI regression against independent inputs."""
from pathlib import Path
import json
import subprocess

import pytest

from cryptoscan import ntru_folding
from cryptoscan.cli import main
from cryptoscan.ntru_auto import instances, recover_flag
from cryptoscan.parser import collect_documents

FIXTURE = Path(__file__).parent / "fixtures" / "ntru_origami"


def test_original_public_origami_vectors_are_detected():
    docs = collect_documents([str(FIXTURE)])
    matches = instances(docs)
    assert len(matches) == 1
    context, public, ciphertext = matches[0]
    assert (context.degree, context.plaintext_modulus, context.ciphertext_modulus) == (512, 2, 127)
    assert len(public) == len(ciphertext) == 512
    assert (context.f_weight, context.g_weight, context.r_weight) == (35, 35, 22)


def test_ntru_offline_dispatch_not_tied_to_challenge_name(tmp_path, monkeypatch, capsys):
    source = (FIXTURE / "source.sage").read_text()
    output = (FIXTURE / "output.txt").read_text()
    path = tmp_path / "some_unseen_crypto_task"
    path.mkdir()
    (path / "crypto.sage").write_text(source)
    (path / "values.txt").write_text(output)
    expected = b"CTF{verified_private_key}"
    monkeypatch.setattr(
        "cryptoscan.ntru_auto.solve_isolated",
        lambda *args, **kwargs: [{"plaintext": expected, "public_relation_verified": True}],
    )
    assert main([str(path), "--no-color", "--solve", "--bkz-block", "20"]) == 0
    assert "FLAG: CTF{verified_private_key}" in capsys.readouterr().out


def test_ntru_rejects_unverified_plaintext(monkeypatch):
    docs = collect_documents([str(FIXTURE)])
    monkeypatch.setattr(
        "cryptoscan.ntru_auto.solve_isolated",
        lambda *args, **kwargs: [{"plaintext": b"NNS{fake}", "public_relation_verified": False}],
    )
    with pytest.raises(RuntimeError, match="No verified flag"):
        recover_flag(docs, progress=lambda _: None)


def test_fplll_parser_validates_matrix_shape():
    actual = ntru_folding._parse_fplll_matrix("[[1 2]\n[3 -4]]\n", 2, 2)
    assert actual == [[1, 2], [3, -4]]
    with pytest.raises(RuntimeError, match="unexpected lattice dimensions"):
        ntru_folding._parse_fplll_matrix("[[1 2]]", 2, 2)


def test_fplll_backend_isolated_protocol(monkeypatch):
    rows = [[1, 2], [3, 4]]
    monkeypatch.setattr(ntru_folding, "_fplll_command", lambda: ["fplll"])
    def mock_run(args, **kwargs):
        assert args == ["fplll", "-a", "bkz", "-b", "2"]
        assert kwargs["input"].startswith("[[1 2]")
        return subprocess.CompletedProcess(args, 0, "[[1 2]\n[3 4]]", "")
    monkeypatch.setattr(ntru_folding.subprocess, "run", mock_run)
    assert ntru_folding._reduce(rows, backend="fplll", bkz=2, progress=lambda _: None) == rows


def test_ntru_dispatch_matches_isolated_solver_signature(monkeypatch):
    import inspect

    from cryptoscan import ntru_isolation

    signature = inspect.signature(ntru_isolation.solve_isolated)
    calls = []

    def checked_solver(*args, **kwargs):
        calls.append(signature.bind(*args, **kwargs))
        return [{"plaintext": b"CTF{signature_ok}", "public_relation_verified": True}]

    monkeypatch.setattr("cryptoscan.ntru_auto.solve_isolated", checked_solver)
    docs = collect_documents([str(FIXTURE)])
    assert recover_flag(docs, progress=lambda _: None) == "CTF{signature_ok}"
    assert len(calls) == 1
