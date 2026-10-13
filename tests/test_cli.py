import json

from cryptoscan.cli import main


def test_json_cli_and_exit_code(tmp_path, capsys):
    path = tmp_path / "weak.py"
    path.write_text("token = md5(message)\n", encoding="utf-8")
    assert main([str(path), "--format", "json", "--fail-on-findings"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == 1
    assert report["findings"][0]["rule"] == "HASH-WEAK"
    assert report["findings"][0]["recovery_status"] == "validation-only"
    assert "flag_path" in report["findings"][0]


def test_text_cli_displays_recovery_status(tmp_path, capsys):
    path = tmp_path / "weak.py"
    path.write_text("token = md5(message)\n", encoding="utf-8")
    assert main([str(path), "--no-color"]) == 0
    output = capsys.readouterr().out
    assert "Recovery: validation-only" in output
    assert "Flag path:" in output


def test_json_cli_emits_offline_cyberchef_recipe(tmp_path, capsys):
    plaintext = b"flag{single_byte_xor}"
    ciphertext = bytes(value ^ 0x42 for value in plaintext)
    path = tmp_path / "xor.json"
    path.write_text(json.dumps({"ciphertext": ciphertext.hex()}), encoding="utf-8")
    assert main([str(path), "--format", "json"]) == 0
    finding = next(item for item in json.loads(capsys.readouterr().out)["findings"] if item["rule"] == "XOR-SINGLE-BYTE")
    assert finding["cyberchef"]["input"] == ciphertext.hex()
    assert [step["op"] for step in finding["cyberchef"]["recipe"]] == ["From Hex", "XOR"]
    assert "http" not in json.dumps(finding["cyberchef"]).casefold()
