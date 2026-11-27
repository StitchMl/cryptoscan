import pytest

from cryptoscan.parser import Document
from cryptoscan.scanner import scan
from cryptoscan.transform_pipeline import extract_instance, recover_flag


def test_infers_unlabeled_hex_from_challenge_statement():
    expected = "crypto{generic_hex_fixture}"
    statement = "Decode this hex string to recover the message: " + expected.encode().hex()
    document = Document("statement.txt", statement, None)

    pipeline = extract_instance([document])

    assert pipeline is not None
    assert pipeline.stages == ("hex",)
    assert recover_flag([document]) == expected
    finding = next(item for item in scan([document]) if item.rule == "ENCODING-PIPELINE")
    assert finding.recovery_status == "flag-recovered"
    assert bytes.fromhex(finding.solver["result_hex"]).decode() == expected


def test_infers_base64_when_statement_identifies_encoding():
    import base64

    expected = "flag{generic_base64_fixture}"
    statement = "The base64 payload is " + base64.b64encode(expected.encode()).decode()
    document = Document("challenge.html", statement, None)

    pipeline = extract_instance([document])

    assert pipeline is not None
    assert recover_flag([document]) == expected
    finding = next(item for item in scan([document]) if item.rule == "ENCODING-PIPELINE")
    assert finding.recovery_status == "flag-recovered"


def test_ambiguous_unlabeled_tokens_do_not_select_a_solver():
    first = "crypto{one_candidate}"
    second = "crypto{other_candidate}"
    statement = f"{first.encode().hex()} and {second.encode().hex()}"
    document = Document("ambiguous.txt", statement, None)

    assert extract_instance([document]) is None


def test_declared_bigint_stage_recovers_minimal_big_endian_bytes():
    expected = b"crypto{generic_bigint_fixture}"
    encoded = str(int.from_bytes(expected, "big"))
    document = Document(
        "challenge.txt",
        f"Pipeline: bigint\nRAW BUFFER\n{encoded}\nEND OF RAW BUFFER\n",
        None,
    )

    assert recover_flag([document]) == expected.decode()


def test_declared_utf8_stage_validates_and_recovers_text():
    expected = "crypto{generic_utf8_fixture}"
    document = Document(
        "challenge.txt",
        f"Pipeline: utf-8\nRAW BUFFER\n{expected}\nEND OF RAW BUFFER\n",
        None,
    )

    assert recover_flag([document]) == expected


def test_bigint_stage_rejects_negative_and_oversized_values():
    from cryptoscan.transform_pipeline import _decode_stage

    with pytest.raises(ValueError, match="unsigned"):
        _decode_stage(b"-1", "bigint")
    with pytest.raises(ValueError):
        _decode_stage(b"9" * 5000, "bigint")


def test_typed_encodings_decode_standard_challenge_values():
    import base64
    import codecs

    from cryptoscan.transform_pipeline import decode_typed_encoding

    expected = b"crypto{typed_codec_fixture}"
    values = (
        ("base64", base64.b64encode(expected).decode()),
        ("hex", expected.hex()),
        ("rot13", codecs.encode(expected.decode(), "rot_13")),
        ("bigint", int.from_bytes(expected, "big")),
        ("utf-8", expected.decode()),
    )
    for encoding, encoded in values:
        assert decode_typed_encoding(encoding, encoded) == expected


def test_json_typed_encoding_record_recovers_flag():
    import base64
    import json

    expected = "crypto{typed_record_fixture}"
    record = {
        "type": "base64",
        "encoded": base64.b64encode(expected.encode()).decode(),
    }
    document = Document("transcript.json", json.dumps(record), record)

    finding = next(
        item for item in scan([document])
        if item.rule == "ENCODING-TYPED-RECORD"
    )
    assert finding.recovery_status == "flag-recovered"
    assert bytes.fromhex(finding.solver["result_hex"]).decode() == expected
