import json

from cryptoscan.aead_diagnostics import unused_validation_flags
from cryptoscan.cli import main
from cryptoscan.cookie import alter_cookie, build_cookie, token_payload


def test_unused_authentication_detected():
    source = """
def verify(gcm, ciphertext, tag):
    plaintext, is_auth = gcm.decrypt(ciphertext, tag)
    return json.loads(plaintext)["role"] == "super_admin"
"""
    assert unused_validation_flags(source) == [3]


def test_checked_authentication_not_reported():
    source = """
def verify(gcm, ciphertext, tag):
    plaintext, is_auth = gcm.decrypt(ciphertext, tag)
    if not is_auth:
        return False
    return True
"""
    assert unused_validation_flags(source) == []


def test_scan_reports_critical_auth_issue(tmp_path, capsys):
    source = tmp_path / "vulnerable.py"
    source.write_text("""
def verify(gcm, ciphertext, tag):
    plaintext, is_auth = gcm.decrypt(ciphertext, tag)
    return json.loads(plaintext)["role"] == "super_admin"
""", encoding="utf-8")
    assert main([str(source), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    entry = next(f for f in report["findings"] if f["rule"] == "AEAD-AUTH-RESULT-IGNORED")
    assert entry["severity"] == "critical"
    assert entry["recovery_status"] == "validation-only"


def test_known_plaintext_edit():
    old = token_payload("a_long_username", "guest")
    stream = bytes((i * 17 + 7) % 256 for i in range(len(old)))
    ciphertext = bytes(x ^ y for x, y in zip(old, stream))
    cookie = ciphertext.hex() + ";" + ("00" * 16)
    updated, new_username = alter_cookie(cookie, "a_long_username", "guest", "super_admin")
    edited = bytes.fromhex(updated.split(";")[0])
    decoded = bytes(x ^ y for x, y in zip(edited, stream))
    assert json.loads(decoded) == {"username": new_username, "role": "super_admin"}


def test_build_token_roundtrip_against_challenge_gcm():
    import pytest
    pytest.importorskip("Crypto")
    from Crypto.Cipher import AES
    from cryptoscan.cookie import _gctr, _ghash

    key = "00112233445566778899aabbccddeeff"
    cookie = build_cookie(key, "demo", "guest")
    ciphertext_hex, tag_hex = cookie.split(";")
    ciphertext = bytes.fromhex(ciphertext_hex)
    aes = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    j0 = bytes(15) + bytes([1])
    decoded = _gctr(aes, j0, ciphertext)
    assert decoded == token_payload("demo", "guest")
    block = ciphertext + bytes(-len(ciphertext) % 16)
    lengths = bytes(8) + (len(ciphertext) * 8).to_bytes(8, "big")
    assert bytes.fromhex(tag_hex) == _gctr(aes, j0, _ghash(aes.encrypt(bytes(16)), block + lengths))


def test_cookie_help_and_scan_help(capsys):
    assert main(["cookie", "--help"]) == 0
    assert "build" in capsys.readouterr().out
    assert main(["--help"]) == 0
    assert "targets" in capsys.readouterr().out
