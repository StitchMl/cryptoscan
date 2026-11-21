"""Source-name invariance and evidence-based hypothesis regression tests."""
from __future__ import annotations

from cryptoscan.cli import main
from cryptoscan.crypto_hypotheses import inspect_hypotheses
from cryptoscan.parser import Document
from cryptoscan.source_units import (
    MAX_SOURCE_LENGTH, parse_python, python_sources, rust_sources,
    unique_by_scope,
)


SYNTHETIC_SIGNATURE = """
import secrets, random
from Crypto.Cipher import AES
def make_group():
    curve = EllipticCurve(GF(101), [2, 3])
    return curve
def sign(secret, point):
    nonce = secrets.randbelow(97)
    return nonce * point + secret
def encrypt(message):
    key = bcrypt.kdf(message, b"seed", 16, 5)
    return AES.new(key, AES.MODE_CTR, nonce=b"").encrypt(message)
samples = [sign(2, 3) for _ in range(7)]
random.shuffle(samples)
"""


def test_accepts_python_semantics_without_extension():
    docs = [Document("opaque-dump.bin.txt", SYNTHETIC_SIGNATURE, None)]
    assert len(list(python_sources(docs))) == 1
    assert parse_python(docs[0]) is not None


def test_rejects_unparseable_and_oversize_source():
    examples = [
        Document("garbage.py", "def ???", None),
        Document("oversize", "a" * (MAX_SOURCE_LENGTH + 1), None),
        Document("nul", "value = 1\0", None),
    ]
    assert not list(python_sources(examples))


def test_identifies_rust_by_grammar_not_filename():
    docs = [
        Document("opaque.profile", "impl Prover { fn check(&self) { do_it(); } }", None),
        Document("unrelated.rs", "0xabc123", None),
    ]
    identified = list(rust_sources(docs))
    assert len(identified) == 1
    assert identified[0].path == "opaque.profile"


def test_scope_deduplication_preserves_unrelated_instances():
    source = "value = 1"
    first = Document("x", source, None, scope="a")
    duplicate = Document("y", source, None, scope="a")
    other = Document("z", source, None, scope="b")
    assert len(unique_by_scope([(first, 1), (duplicate, 1), (other, 2)])) == 2


def test_hidden_signature_hypothesis_is_not_a_confirmed_weakness():
    docs = [Document("anonymous-input", SYNTHETIC_SIGNATURE, None)]
    hypotheses = inspect_hypotheses(docs)
    labels = {item.family for item in hypotheses}
    assert "Hidden authentic signature among decoys" in labels
    assert "Derived symmetric key and stream encryption" in labels
    assert not inspect_hypotheses([Document("random.txt", "x = 2", None)])


def test_cli_reports_unverified_hypotheses_from_renamed_input(tmp_path, capsys):
    target = tmp_path / "captured_payload"
    target.write_text(SYNTHETIC_SIGNATURE, encoding="utf-8")
    status = main([str(target), "--no-assist"])
    report = capsys.readouterr().out
    assert status == 0
    assert "Cryptographic attack hypotheses" in report
    assert "Hidden authentic signature" in report
    assert "unverified" in report.lower()
