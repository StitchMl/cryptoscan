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


def test_unmatched_binary_input_produces_json_triage(tmp_path, capsys):
    path = tmp_path / "unknown.bin"
    path.write_bytes(b"\x00\x01challenge marker\x00\xff")
    assert main([str(path), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["findings"] == []
    assert report["triage"]["documents_received"] == 1
    assert report["triage"]["binary_artifacts"][0]["path"] == "unknown.bin"
    assert "challenge marker" in report["triage"]["binary_artifacts"][0]["printable_strings"]


def test_explicit_url_is_fetched_without_extra_authorization_flag(monkeypatch, capsys):
    received = {}

    def fake_collect(targets, *, authorized):
        received["targets"] = targets
        received["authorized"] = authorized
        return []

    monkeypatch.setattr("cryptoscan.cli.collect_documents", fake_collect)
    assert main(["https://ctf.example/challenge", "--no-assist", "--no-color"]) == 0
    assert received["targets"] == ["https://ctf.example/challenge"]
    assert received["authorized"] is True
    capsys.readouterr()
