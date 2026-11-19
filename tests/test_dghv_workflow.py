"""Regression checks for the opt-in DGHV solver integration."""
import textwrap

from cryptoscan.cli import main
from cryptoscan.dghv_workflow import supported_source
from cryptoscan.parser import Document


DGHV = textwrap.dedent("""
import random
from Crypto.Util.number import getPrime
def dghv_encrypt(p, N, m):
    q = random.getrandbits(1024)
    rmax = 2**128 / N / 4
    r = random.randint(0, rmax)
    return p*q + N*r + m
def dghv_decrypt(p, N, c):
    return (c % p) % N
def challenge():
    p = getPrime(128)
    return [dghv_encrypt(p, 2**7, ord(c)) for c in "CSC{test}"]
""")


def test_source_fingerprint_is_structural():
    assert supported_source([Document("server.py", DGHV, None)])
    assert not supported_source([Document("random.py", "import random\nq = random.getrandbits(1024)\n", None)])
    assert not supported_source([Document("code.py", DGHV.replace("rmax = 2**128 / N / 4", "rmax = 2**192 / N / 4"), None)])


def test_cli_runs_solver_only_with_explicit_endpoint(tmp_path, monkeypatch, capsys):
    path = tmp_path / "server.py"
    path.write_text(DGHV, encoding="utf-8")
    called = []

    def fake_recover(documents, host, port, *, timeout):
        called.append((host, port, timeout))
        return "CSC{test}"

    monkeypatch.setattr("cryptoscan.cli.recover_dghv_flag", fake_recover)
    assert main([str(path), "--solve", "--host", "127.0.0.1", "--port", "21970"]) == 0
    assert called == [("127.0.0.1", 21970, 30.0)]
    assert "FLAG: CSC{test}" in capsys.readouterr().out


def test_cli_refuses_nonmatching_source(tmp_path, capsys):
    path = tmp_path / "safe.py"
    path.write_text("print('safe')\n", encoding="utf-8")
    assert main([str(path), "--solve", "--host", "127.0.0.1", "--port", "21970"]) == 2
    assert "No supported" in capsys.readouterr().err
