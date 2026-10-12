import json

from cryptoscan.cli import main


def test_json_cli_and_exit_code(tmp_path, capsys):
    path = tmp_path / "weak.py"
    path.write_text("token = md5(message)\n", encoding="utf-8")
    assert main([str(path), "--format", "json", "--fail-on-findings"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == 1
    assert report["findings"][0]["rule"] == "HASH-WEAK"
