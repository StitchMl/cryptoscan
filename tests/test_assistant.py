"""Regression tests for the generic guided CLI."""
import hashlib
import json

import pytest

from cryptoscan.assistant import assistant_session, inspect_record
from cryptoscan.cli import main


def feed(*answers):
    values = iter(answers)
    return lambda _prompt: next(values)


def test_inspect_semicolon_token_without_assuming_format():
    lines = []
    inspect_record("demo;demo;guest;" + "ab" * 37, lines.append)
    report = "\n".join(lines)
    assert "Fields: 4" in report
    assert "74 hex characters (37 bytes)" in report
    assert "nonstandard digest length" in report


def test_standalone_assistant_with_token_and_digest(capsys):
    sample = "demo;demo;guest;" + "ab" * 37
    assistant_session(read=feed("t", sample, "h", "sha256", "plain", "demo;demo;guest", "", "q"))
    output = capsys.readouterr().out
    assert "Fields: 4" in output
    assert hashlib.sha256(b"demo;demo;guest").hexdigest() in output


def test_missing_secret_is_not_guessed(capsys):
    assistant_session(read=feed("h", "sha256", "hmac", "demo;demo;guest", "", "q"))
    output = capsys.readouterr().out
    assert "Cannot calculate without the secret" in output


def test_xor_rejects_insufficient_keystream(capsys):
    assistant_session(read=feed("x", "010203", "utf8", "abc", "abcd", "q"))
    assert "Target exceeds the known keystream" in capsys.readouterr().out


def test_existing_noninteractive_json_output(tmp_path, capsys):
    source = tmp_path / "sample.py"
    source.write_text("token = md5(message)\n", encoding="utf-8")
    assert main([str(source), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["findings"]


def test_explicit_assist_with_findings(tmp_path, monkeypatch, capsys):
    source = tmp_path / "sample.py"
    source.write_text("token = md5(message)\n", encoding="utf-8")
    monkeypatch.setattr("cryptoscan.cli.assistant_session", lambda findings: print("ASSIST", len(findings)))
    assert main(["assist", str(source)]) == 0
    assert "ASSIST" in capsys.readouterr().out


def test_conflicting_cli_flags(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("token = md5(message)\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        main([str(source), "--assist", "--no-assist"])


def test_rewrite_record_with_declared_digest(capsys):
    assistant_session(read=feed(
        "r", "demo;demo;guest;abc", "", "1,3", "admin", "super_admin",
        "4", "1,2,3", "sha256", "plain", "", "q"
    ))
    output = capsys.readouterr().out
    digest = hashlib.sha256(b"admin;demo;super_admin").hexdigest()
    assert "Computed record: admin;demo;super_admin;" + digest in output


def test_rewrite_hmac_requires_key(capsys):
    assistant_session(read=feed(
        "r", "demo;guest;deadbeef", "", "2", "admin",
        "3", "1,2", "sha256", "hmac", "", "q"
    ))
    assert "MAC key is unknown" in capsys.readouterr().out
