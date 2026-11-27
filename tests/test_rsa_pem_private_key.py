from Crypto.PublicKey import RSA

from cryptoscan.parser import collect_documents, pem_rsa_private_keys
from cryptoscan.scanner import scan


def test_pkcs1_and_pkcs8_private_pem_extract_rsa_parameters(tmp_path):
    key = RSA.generate(1024)
    pkcs1 = key.export_key(format="PEM", pkcs=1).decode()
    pkcs8 = key.export_key(format="PEM", pkcs=8).decode()

    assert pem_rsa_private_keys(pkcs1) == [{
        "n": key.n,
        "e": key.e,
        "d": key.d,
        "p": key.p,
        "q": key.q,
    }]
    assert pem_rsa_private_keys(pkcs8) == [{
        "n": key.n,
        "e": key.e,
        "d": key.d,
        "p": key.p,
        "q": key.q,
    }]

    challenge_key = tmp_path / "privacy_enhanced_mail.pem"
    challenge_key.write_text(pkcs1, encoding="ascii")
    finding = next(
        item for item in scan(collect_documents([str(challenge_key)]))
        if item.rule == "RSA-PRIVATE-KEY-MATERIAL"
    )
    assert finding.evidence["private_exponent_decimal"] == str(key.d)
    assert finding.solver["kind"] == "rsa_private_key_metadata"


def test_private_pem_parser_ignores_public_malformed_and_encrypted_keys():
    private_key = RSA.generate(1024)
    public_pem = private_key.public_key().export_key().decode()
    encrypted_pem = private_key.export_key(
        passphrase="ctf-test", pkcs=8, protection="scryptAndAES128-CBC"
    ).decode()

    assert pem_rsa_private_keys(public_pem) == []
    assert pem_rsa_private_keys("-----BEGIN RSA PRIVATE KEY-----\n%%%\n-----END RSA PRIVATE KEY-----") == []
    assert pem_rsa_private_keys(encrypted_pem) == []
