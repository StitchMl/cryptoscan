import json

from cryptoscan.parser import collect_documents
from cryptoscan.scanner import scan


def test_scanner_recovers_flag_from_generic_big_endian_integer(tmp_path):
    plaintext = b"crypto{generic_integer_serialization}"
    encoded = int.from_bytes(plaintext, "big")
    challenge = tmp_path / "challenge.json"
    challenge.write_text(json.dumps({"output": encoded}), encoding="utf-8")

    findings = scan(collect_documents([str(challenge)]))

    finding = next(item for item in findings if item.rule == "ENCODING-BIGINT-BYTES")
    assert bytes.fromhex(finding.solver["result_hex"]) == plaintext
    assert finding.recovery_status == "flag-recovered"


def test_bigint_decoder_does_not_report_unrelated_crypto_parameters(tmp_path):
    challenge = tmp_path / "parameters.json"
    challenge.write_text(json.dumps({"n": 0xDEADBEEF, "e": 65537}), encoding="utf-8")

    findings = scan(collect_documents([str(challenge)]))

    assert not any(item.rule == "ENCODING-BIGINT-BYTES" for item in findings)
