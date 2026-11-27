import base64

from cryptoscan.parser import der_rsa_public_keys, pem_rsa_public_keys


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
