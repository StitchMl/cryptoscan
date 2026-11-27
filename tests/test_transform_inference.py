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
