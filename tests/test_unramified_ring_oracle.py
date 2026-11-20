"""Synthetic structure tests for unramified ring evaluation recognition.

These tests do not embed any CTF challenge files, flags or parameters.
"""
import ast
from pathlib import Path

from cryptoscan.parser import Document
from cryptoscan.unramified_ring_oracle import _integers, extract_instance


def invented_source(k=4, degrees=None):
    if degrees is None:
        degrees = [2, 4]
    return f'''
import secrets
def construct(k, degrees):
    base = Zmod(2^k)
    residue = GF(2)
    for count in degrees:
        polynomials = residue["b"]
        minimum = polynomials.gen()^count + polynomials(1)
        if minimum.is_irreducible():
            residue = polynomials.quo(minimum)
            base = base["a"].quo(base["a"].gen()^count + 1)
    return base

def evaluate(poly, point):
    return point.parent()["x"](poly)(x=point)

def challenge(precision, degrees):
    tower = construct(precision, degrees)
    flat = construct(precision, [prod(degrees)])
    polynomial = [secrets.randbelow(3) - 1 for _ in range(15)]
    print(tower)
    print(flat)
    input("coordinates: ")
    print(evaluate(polynomial, tower(1)))

if __name__ == "__main__":
    challenge({k}, {degrees})
'''


def test_recognizes_unrelated_symbol_names_and_ring_dimensions():
    source = invented_source()
    model = extract_instance([Document("new_protocol.sage", source, None)])
    assert model is not None
    assert model.rounds == ((4, (2, 4)),)


def test_rejects_non_algebraic_oracle_source():
    text = invented_source().replace("residue = polynomials.quo(minimum)",
                                    "residue = minimum").replace(
        'base = base["a"].quo(base["a"].gen()^count + 1)',
        'base = base["a"].gen()^count + 1',
    )
    assert extract_instance([Document("new_protocol.sage", text, None)]) is None


def test_rejects_unsupported_huge_ring():
    model = extract_instance([Document("big.sage", invented_source(12, [8, 8, 8]), None)])
    assert model is None


def test_rejects_malformed_coordinates():
    assert _integers("1,2,3", 3) == [1, 2, 3]
    import pytest
    with pytest.raises(ValueError):
        _integers("1,2", 3)
    with pytest.raises(ValueError):
        _integers("1,nope,3", 3)


def test_sage_worker_parses_as_python_without_loading_sage():
    worker = Path(__file__).resolve().parents[1] / "src" / "cryptoscan" / "sage_ring_iso_worker.py"
    tree = ast.parse(worker.read_text(encoding="utf-8"))
    assert any(isinstance(node, ast.FunctionDef) and node.name == "safe_expression"
               for node in tree.body)


def test_windows_powershell_delegates_worker_to_wsl(monkeypatch):
    """Windows frontend remains native; only Sage child runs in WSL."""
    from types import SimpleNamespace
    import cryptoscan.unramified_ring_oracle as module

    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.delenv("CRYPTOSCAN_SAGE", raising=False)
    monkeypatch.setattr(module.shutil, "which", lambda name:
                        "C:\\Windows\\System32\\wsl.exe" if name == "wsl.exe" else None)

    commands = []

    def fake_run(command, **_):
        commands.append(command)
        if command[1:3] == ["--exec", "wslpath"]:
            return SimpleNamespace(returncode=0, stdout="/mnt/c/repo/sage_ring_iso_worker.py\n",
                                   stderr="")
        if command[1:4] == ["--exec", "/bin/sh", "-c"]:
            return SimpleNamespace(returncode=0, stdout="/usr/bin/sage\n", stderr="")
        raise AssertionError(f"unexpected subprocess {command!r}")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    command = module._sage_worker_command()
    assert command[:4] == ["C:\\Windows\\System32\\wsl.exe", "--exec",
                           "/usr/bin/sage", "-python"]
    assert command[-1] == "/mnt/c/repo/sage_ring_iso_worker.py"
    assert len(commands) == 2



def test_windows_conda_sage_activates_environment_before_worker(monkeypatch):
    """Sage in Conda requires activation, not merely an absolute sage path."""
    from types import SimpleNamespace
    import cryptoscan.unramified_ring_oracle as module

    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.delenv("CRYPTOSCAN_SAGE", raising=False)
    monkeypatch.setattr(
        module.shutil, "which",
        lambda name: "C:/Windows/System32/wsl.exe" if name == "wsl.exe" else None,
    )

    def fake_run(command, **_):
        if command[1:3] == ["--exec", "wslpath"]:
            return SimpleNamespace(returncode=0, stdout="/mnt/c/worker.py\n", stderr="")
        if command[1:4] == ["--exec", "/bin/sh", "-c"]:
            return SimpleNamespace(
                returncode=0,
                stdout="/home/example/miniforge3/envs/sage/bin/sage\n",
                stderr="",
            )
        raise AssertionError(f"unexpected command: {command!r}")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    command = module._sage_worker_command()
    assert command[:4] == ["C:/Windows/System32/wsl.exe", "--exec", "/bin/bash", "-c"]
    assert "conda activate" in command[4]
    assert command[6] == "/home/example/miniforge3/etc/profile.d/conda.sh"
    assert command[7] == "/home/example/miniforge3/envs/sage"
    assert command[8] == "/home/example/miniforge3/envs/sage/bin/python"
    assert command[9] == "/mnt/c/worker.py"


def test_windows_missing_sage_reports_actionable_error(monkeypatch):
    import pytest
    import cryptoscan.unramified_ring_oracle as module
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.delenv("CRYPTOSCAN_SAGE", raising=False)
    monkeypatch.setattr(module.shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError, match="keep running cryptoscan in PowerShell"):
        module._sage_worker_command()


def test_unix_conda_sage_uses_environment_python(monkeypatch):
    import cryptoscan.unramified_ring_oracle as module
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.delenv("CRYPTOSCAN_SAGE", raising=False)
    monkeypatch.setattr(module.shutil, "which", lambda name:
                        "/opt/miniforge3/envs/math/bin/sage" if name == "sage" else None)
    command = module._sage_worker_command()
    assert command[0] == "/opt/miniforge3/envs/math/bin/python"
    assert command[1].endswith("sage_ring_iso_worker.py")


def test_unix_keeps_native_sage_worker(monkeypatch):
    import cryptoscan.unramified_ring_oracle as module
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.delenv("CRYPTOSCAN_SAGE", raising=False)
    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/sage" if name == "sage" else None)
    command = module._sage_worker_command()
    assert command[0:2] == ["/usr/bin/sage", "-python"]
    assert command[-1].endswith("sage_ring_iso_worker.py")
