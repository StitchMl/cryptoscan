import json

from cryptoscan.model import Finding
from cryptoscan.parser import Document, collect_documents
from cryptoscan.scanner import scan


def test_scanner_decodes_generic_ascii_ordinal_array(tmp_path):
    plaintext = "crypto{transferable_ascii_case}"
    path = tmp_path / "challenge-data.json"
    path.write_text(json.dumps([ord(char) for char in plaintext]), encoding="utf-8")

    findings = scan(collect_documents([str(path)]))

    result = next(item for item in findings if item.rule == "ENCODING-ASCII-ORDINALS")
    assert result.evidence["decoded_text"] == plaintext
    assert result.solver["result_hex"] == plaintext.encode().hex()
    assert result.recovery_status == "flag-recovered"


def test_scanner_finds_nested_byte_arrays_with_encoding_context(tmp_path):
    plaintext = "ordinary readable text"
    path = tmp_path / "challenge.json"
    path.write_text(json.dumps({"result": {"ascii_values": [ord(char) for char in plaintext]}}), encoding="utf-8")

    findings = scan(collect_documents([str(path)]))

    result = next(item for item in findings if item.rule == "ENCODING-ASCII-ORDINALS")
    assert result.evidence["decoded_text"] == plaintext
    assert result.recovery_status == "payload-ready"


def test_scanner_reads_ordinal_list_from_html_challenge_statement():
    plaintext = "crypto{html_ordinal_case}"
    values = ", ".join(str(ord(char)) for char in plaintext)
    document = Document(
        "cryptohack.invalid/challenge/",
        f"<p>ASCII values: [{values}]</p>", None,
    )

    findings = scan([document])

    result = next(item for item in findings if item.rule == "ENCODING-ASCII-ORDINALS")
    assert result.evidence["decoded_text"] == plaintext
    assert result.recovery_status == "flag-recovered"


def test_ordinal_finding_requires_a_supported_proof():
    finding = Finding(
        rule="ENCODING-ASCII-ORDINALS", title="test", severity="info",
        confidence="high", location="x", evidence={"ordinal_values": [65, 66]},
        preconditions=[], attack="decode", solver={"result_hex": "4344"}, patch="none",
    )
    assert finding.recovery_status == "validation-only"
