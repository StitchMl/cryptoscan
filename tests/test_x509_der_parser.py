import base64

from cryptoscan.parser import (
    der_rsa_public_keys,
    pem_rsa_public_keys,
    ssh_rsa_public_keys,
)


def _length(size: int) -> bytes:
    if size < 128:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def _integer(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _tlv(0x02, encoded)


def _certificate(modulus: int, exponent: int = 65537, oid: bytes = bytes.fromhex("2a864886f70d010101")) -> bytes:
    rsa_public_key = _tlv(0x30, _integer(modulus) + _integer(exponent))
    algorithm = _tlv(0x30, _tlv(0x06, oid) + _tlv(0x05, b""))
    subject_public_key = _tlv(0x30, algorithm + _tlv(0x03, b"\x00" + rsa_public_key))
    signature_algorithm = algorithm
    tbs = _tlv(
        0x30,
        _tlv(0xA0, _integer(2)) + _integer(1) + signature_algorithm
        + _tlv(0x30, b"") + _tlv(0x30, b"") + _tlv(0x30, b"")
        + subject_public_key,
    )
    return _tlv(0x30, tbs + signature_algorithm + _tlv(0x03, b"\x00signature"))


def test_nested_x509_certificate_yields_rsa_parameters():
    certificate = _certificate(0xD5BBB96D30086EC484EBA3D7F9CAEB07)

    assert der_rsa_public_keys(certificate) == [{
        "n": 0xD5BBB96D30086EC484EBA3D7F9CAEB07,
        "e": 65537,
    }]


def test_pem_certificate_block_uses_nested_spki_parser():
    certificate = _certificate(0xD5BBB96D30086EC484EBA3D7F9CAEB07)
    pem = "-----BEGIN CERTIFICATE-----\n" + base64.b64encode(certificate).decode() + "\n-----END CERTIFICATE-----"

    assert pem_rsa_public_keys(pem) == [{
        "n": 0xD5BBB96D30086EC484EBA3D7F9CAEB07,
        "e": 65537,
    }]


def test_nested_non_rsa_subject_public_key_is_ignored():
    certificate = _certificate(0xD5BBB96D30086EC484EBA3D7F9CAEB07, oid=bytes.fromhex("2b81040022"))

    assert der_rsa_public_keys(certificate) == []


def test_der_certificate_scan_reports_the_extracted_modulus(tmp_path):
    from cryptoscan.parser import collect_documents
    from cryptoscan.scanner import scan

    modulus = 0xD5BBB96D30086EC484EBA3D7F9CAEB07
    certificate = tmp_path / "certificate.der"
    certificate.write_bytes(_certificate(modulus))
    findings = scan(collect_documents([str(certificate)]))
    key_info = next(item for item in findings if item.rule == "RSA-PUBLIC-KEY-MATERIAL")

    assert key_info.evidence["modulus_decimal"] == str(modulus)
    assert key_info.evidence["exponent"] == 65537
    assert key_info.solver["kind"] == "rsa_public_key_metadata"


def _ssh_string(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _ssh_mpint(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _ssh_string(raw)


def _ssh_rsa_line(modulus: int, exponent: int = 65537) -> str:
    blob = (_ssh_string(b"ssh-rsa") + _ssh_mpint(exponent) + _ssh_mpint(modulus))
    return "ssh-rsa " + base64.b64encode(blob).decode() + " challenge-key"

def _openssh_private_key(p=61, q=53, e=17, *, checkints=(0x12345678, 0x12345678),
                         cipher=b"none", kdf=b"none", options=b"") -> str:
    import math

    n = p * q
    d = pow(e, -1, math.lcm(p - 1, q - 1))
    iqmp = pow(q, -1, p)
    public = _ssh_string(b"ssh-rsa") + _ssh_mpint(e) + _ssh_mpint(n)
    private = (checkints[0].to_bytes(4, "big") + checkints[1].to_bytes(4, "big")
               + _ssh_string(b"ssh-rsa") + _ssh_mpint(n) + _ssh_mpint(e)
               + _ssh_mpint(d) + _ssh_mpint(iqmp) + _ssh_mpint(p) + _ssh_mpint(q)
               + _ssh_string(b"ctf-fixture"))
    padding_size = (-len(private)) % 8
    if padding_size == 0:
        padding_size = 8
    private += bytes(range(1, padding_size + 1))
    encoded = (b"openssh-key-v1\\x00" + _ssh_string(cipher) + _ssh_string(kdf)
               + _ssh_string(options) + (1).to_bytes(4, "big")
               + _ssh_string(public) + _ssh_string(private))
    body = base64.b64encode(encoded).decode()
    lines = "\\n".join(body[i:i + 70] for i in range(0, len(body), 70))
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\\n{lines}\\n-----END OPENSSH PRIVATE KEY-----\\n"



def test_openssh_rsa_public_key_parses_mpints_and_comment():
    modulus = 0xD5BBB96D30086EC484EBA3D7F9CAEB07

    assert ssh_rsa_public_keys("# public key\n" + _ssh_rsa_line(modulus)) == [{
        "n": modulus,
        "e": 65537,
    }]


def test_openssh_rsa_rejects_malformed_or_mismatched_blobs():
    assert ssh_rsa_public_keys("ssh-rsa !!! invalid") == []
    wrong_algorithm = base64.b64encode(_ssh_string(b"ssh-ed25519") + b"x").decode()
    assert ssh_rsa_public_keys("ssh-rsa " + wrong_algorithm) == []
    trailing_data = base64.b64encode(
        _ssh_string(b"ssh-rsa") + _ssh_mpint(65537) + _ssh_mpint(257) + b"x"
    ).decode()
    assert ssh_rsa_public_keys("ssh-rsa " + trailing_data) == []
def test_openssh_rsa_private_key_extracts_parameters_and_scans(tmp_path):
    from cryptoscan.parser import collect_documents
    from cryptoscan.scanner import scan

    private_key = _openssh_private_key()
    assert openssh_rsa_private_keys(private_key) == [{
        "n": 61 * 53, "e": 17, "d": 413, "p": 61, "q": 53,
    }]
    path = tmp_path / "id_rsa"
    path.write_text(private_key)
    finding = next(item for item in scan(collect_documents([str(path)]))
                   if item.rule == "RSA-PRIVATE-KEY-MATERIAL")
    assert finding.evidence["private_exponent_decimal"] == "413"
    assert finding.evidence["prime1_decimal"] == "61"


def test_openssh_rsa_private_key_rejects_encrypted_and_bad_checkints():
    assert openssh_rsa_private_keys(_openssh_private_key(cipher=b"aes256-ctr", kdf=b"bcrypt",
                                                        options=b"salt/options")) == []
    assert openssh_rsa_private_keys(_openssh_private_key(checkints=(1, 2))) == []



def test_openssh_public_key_scan_reports_decimal_modulus(tmp_path):
    from cryptoscan.parser import collect_documents
    from cryptoscan.scanner import scan

    modulus = 0xD5BBB96D30086EC484EBA3D7F9CAEB07
    public_key = tmp_path / "bruce_rsa.pub"
    public_key.write_text(_ssh_rsa_line(modulus) + "\n")
    findings = scan(collect_documents([str(public_key)]))
    key_info = next(item for item in findings if item.rule == "RSA-PUBLIC-KEY-MATERIAL")

    assert key_info.evidence["modulus_decimal"] == str(modulus)
    assert key_info.evidence["exponent"] == 65537
