"""Diagnostics for Python interpreter and numerical dependencies."""
from cryptoscan.diagnostics import diagnose_runtime


def test_doctor_healthy(capsys):
    assert diagnose_runtime() == 0
    output = capsys.readouterr().out
    assert "CryptoScan runtime interpreter:" in output
    assert "SymPy import: OK" in output
    assert "SymPy LLL: OK" in output


def test_doctor_reports_broken_mpmath(monkeypatch, capsys):
    import builtins
    original = builtins.__import__

    def broken(name, *args, **kwargs):
        if name == "sympy":
            raise ImportError("No module named 'mpmath.libmp.gammazeta'")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", broken)
    assert diagnose_runtime() == 1
    output = capsys.readouterr().out
    assert "mpmath.libmp.gammazeta" in output
    assert "-m pip install --upgrade sympy" in output


def test_doctor_cli_entry_point(monkeypatch):
    from cryptoscan.cli import main
    monkeypatch.setattr("cryptoscan.cli.diagnose_runtime", lambda: 3)
    assert main(["doctor"]) == 3
