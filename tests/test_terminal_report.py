"""Regression tests for compact reports, ANSI controls, and JSON stability."""
import json
import re

from cryptoscan.cli import main
from cryptoscan.model import Finding
from cryptoscan.terminal_report import render_findings


def sample():
    return Finding(
        "NTRU-SYNTHETIC", "Synthetic NTRU polynomial vulnerability",
        "medium", "high", "source.sage:12",
        {"polynomial_degree": 512, "plaintext_weight_mod_q": 92},
        ["Ring is X^512 - 1", "Public polynomial is valid"],
        "Recover the secret polynomial by a suitable reduction strategy.",
        {"kind": "ntru_folding", "implemented": False},
        "Choose cryptographic parameters with validated security.",
        ["Verify public-key relation.", "Try factor-ring projection."],
    )


def test_compact_report_is_scannable():
    result = render_findings([sample()], color=False)
    assert "NTRU-SYNTHETIC" in result
    assert "Recovery: validation-only" in result
    assert "Attack:" in result
    assert "Evidence:" not in result
    assert "Step 1:" not in result
    assert "--verbose" in result
    assert "\x1b[" not in result
    assert max(map(len, result.splitlines())) <= 100


def test_detailed_report_preserves_information():
    finding = sample()
    report = render_findings([finding], color=False, verbose=True)
    assert "Evidence:" in report
    assert "plaintext_weight_mod_q" in report
    assert "Flag path:" in report
    assert "Preconditions:" in report
    assert "Step 1:" in report
    assert "Patch:" in report
    assert "--verbose" not in report
    assert "\x1b[" not in report


def test_colored_severity_and_recovery_state():
    result = render_findings([sample()], color=True)
    assert "\x1b[" in result
    assert "[MEDIUM]" in re.sub(r"\x1b\[[0-9;]*m", "", result)
    assert "Recovery:" in result
    assert result.endswith("\x1b[0m")


def test_cli_verbose_force_color_and_json(tmp_path, capsys, monkeypatch):
    path = tmp_path / "unsafe.py"
    path.write_text("token = md5(message)\n", encoding="utf-8")
    assert main([str(path), "--no-assist", "--no-color"]) == 0
    compact = capsys.readouterr().out
    assert "Evidence:" not in compact
    assert "HASH-WEAK" in compact
    assert main([str(path), "--no-assist", "--verbose", "--no-color"]) == 0
    detailed = capsys.readouterr().out
    assert "Evidence:" in detailed
    assert "Step 1:" in detailed
    assert main([str(path), "--no-assist", "--color"]) == 0
    assert "\x1b[" in capsys.readouterr().out
    monkeypatch.setenv("NO_COLOR", "1")
    assert main([str(path), "--no-assist", "--color"]) == 0
    assert "\x1b[" not in capsys.readouterr().out
    assert main([str(path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule"] == "HASH-WEAK"
