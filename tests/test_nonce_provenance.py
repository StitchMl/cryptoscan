"""Nonce provenance regression: output data is not source-code nonce reuse."""
from cryptoscan.parser import Document
from cryptoscan.scanner import scan


def test_saved_aes_ctr_nonce_is_not_reuse_evidence():
    source = Document(
        "chall.py",
        "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_CTR)\n"
        "nonce = cipher.nonce\n",
        None,
    )
    output = Document(
        "output.txt",
        "sigs = [(2, 3)]\nct = b'abc'\nnonce = b'12345678'\n",
        None,
    )
    assert "NONCE-CONSTANT" not in {f.rule for f in scan([source, output])}


def test_nonce_literal_in_source_is_still_reported():
    doc = Document("server.py", "nonce = b'12345678'\n", None)
    assert "NONCE-CONSTANT" in {f.rule for f in scan([doc])}
