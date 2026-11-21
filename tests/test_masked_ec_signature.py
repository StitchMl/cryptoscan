"""Independent Edwards message-recovery signatures with renamed source symbols.

Only standard Ed25519 public-domain curve parameters and invented small
messages are used. No challenge source, transcript, flag or key is embedded.
"""
from __future__ import annotations

import hashlib
import sys
import types

from cryptoscan.masked_ec_signature import (
    _curve_spec, _hash_scheme, _hash_parameters, _kdf_scheme, _source_model, _read_output,
    _point, _multiply, _expand_sha256, _field_eval,
    extract_instance, recover_flag,
)
from cryptoscan.parser import Document

FIELD = 2**255 - 19
ALPHA = FIELD - 1
DELTA = 37095705934669439343138083508754565189542113879843219016388785533085940283555
BASE = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)
ORDER = 7237005577332262213973186563042994240857116359379907606001950938285454250989


def _synthetic_source():
    return f'''
import secrets, hashlib, bcrypt, operator, random
from Crypto.Cipher import AES

def prepare_group():
    prime = {FIELD}
    Finite = GF(prime)
    alpha = Finite({ALPHA})
    delta = Finite({DELTA})
    curve = EllipticCurve(Finite, [0, 1])
    def convert_edwards(xx, yy):
        return ((5*alpha + alpha*yy - 5*delta*yy - delta)/(12 - 12*yy),
                xx/(1 - yy))
    def invert_curve(u, v):
        return (u, v)
    base = curve(*convert_edwards(Finite({BASE[0]}), Finite({BASE[1]})))
    curve.set_order({ORDER} * 8)
    return curve, base

q = 2^255 - 19
curve, base = prepare_group()
group_order = {ORDER}
key_bits = 128
remainder_bits = 128
hash_output_bits = 256

def stretch(value, src_bits, dst_bits, label):
    data = b""
    i = 0
    while len(data) < dst_bits // 8:
        data += hashlib.sha256(value + b"~" + label + i.to_bytes(4, "big")).digest()
        i += 1
    return data[:dst_bits//8]

wrap = lambda value: stretch(value, key_bits, remainder_bits, b"A")
unwrap = lambda value: stretch(value, remainder_bits, key_bits, b"B")
commitment_hash = lambda value: stretch(value, hash_output_bits, hash_output_bits, b"C")

def authenticate(message, private):
    payload = wrap(message) + xor(unwrap(wrap(message)), message)
    seed = secrets.randbelow(group_order)
    masked = xor(int((seed * base)[0]).to_bytes(32, "big"), payload)
    challenge = int.from_bytes(commitment_hash(masked), "big")
    response = (seed + challenge * private) % group_order
    return (masked.hex(), response)

def secure_message():
    token = secrets.token_bytes(key_bits//8)
    derived = bcrypt.kdf(token, b"SYNTHETIC_SALT", 16, 17)
    encrypted = AES.new(derived, AES.MODE_CTR, nonce=b"12345678")
    return encrypted.encrypt(b"generic test")
'''


def _affine(point):
    inverse = pow(point[2], -1, FIELD)
    return point[0]*inverse % FIELD, point[1]*inverse % FIELD


def _hash(data, length, domain):
    return _expand_sha256(data, length, domain, b"~", 4, "big")


def _transcript():
    private, omega = 7, 11
    public = _affine(_multiply(_point(BASE, FIELD), ORDER-private,
                               FIELD, ALPHA, DELTA))
    ephemeral = _affine(_multiply(_point(BASE, FIELD), omega,
                                  FIELD, ALPHA, DELTA))
    y = ephemeral[1]
    coordinate = (
        (5*ALPHA + ALPHA*y - 5*DELTA*y - DELTA)
        * pow((12 - 12*y) % FIELD, -1, FIELD)
    ) % FIELD
    secret = b"0123456789abcdef"
    prefix = _hash(secret, 16, b"A")
    data = prefix + bytes(x ^ y for x, y in zip(
        secret, _hash(prefix, 16, b"B"), strict=True,
    ))
    signature = bytes(x ^ y for x, y in zip(
        coordinate.to_bytes(32, "big"), data, strict=True,
    ))
    challenge = int.from_bytes(_hash(signature, 32, b"C"), "big")
    response = (omega + challenge*private) % ORDER
    ciphertext = bytes.fromhex("11223344")
    output = (
        "Public = " + repr(public) + "\n"
        + "Encrypted = " + ciphertext.hex() + "\n"
        + repr([("ab"*32, 3), (signature.hex(), response), ("c1"*32, 4)])
    )
    return secret, output


def _documents():
    _, output = _transcript()
    return [
        Document("curve_unrelated.extension", _synthetic_source(), None),
        Document("raw_cryptograms", output, None),
    ]


def test_edwards_scalar_and_inverse():
    base = _point(BASE, FIELD)
    assert _affine(_multiply(base, ORDER, FIELD, ALPHA, DELTA)) == (0, 1)
    x, y = _affine(_multiply(base, 7, FIELD, ALPHA, DELTA))
    assert (ALPHA*x*x+y*y-1-DELTA*x*x*y*y) % FIELD == 0


def test_generic_source_extraction_and_input_pairing():
    instance = extract_instance(_documents())
    assert instance is not None
    assert instance.scheme.field == FIELD
    assert instance.scheme.key_bytes == 16
    assert instance.scheme.f1 == b"A"
    assert instance.scheme.f2 == b"B"
    assert instance.scheme.signature_hash == b"C"
    assert instance.scheme.separator == b"~"
    assert len(instance.signatures) == 3


def test_offline_recovery_uses_derived_key_and_ctr(monkeypatch):
    secret, _ = _transcript()
    recovered_secrets = []

    fake_bcrypt = types.ModuleType("bcrypt")

    def derive(*, password, salt, desired_key_bytes, rounds):
        recovered_secrets.append(password)
        assert salt == b"SYNTHETIC_SALT"
        assert rounds == 17
        return hashlib.sha256(password+salt).digest()[:desired_key_bytes]

    fake_bcrypt.kdf = derive
    monkeypatch.setitem(sys.modules, "bcrypt", fake_bcrypt)

    crypto = types.ModuleType("Crypto")
    cipher_package = types.ModuleType("Crypto.Cipher")
    class FakeCipher:
        def __init__(self, key):
            self.key = key
        def decrypt(self, encrypted):
            return b"TST{synthetic}"
    class FakeAES:
        MODE_CTR = 6
        @staticmethod
        def new(key, mode, nonce):
            assert nonce == b"12345678"
            return FakeCipher(key)
    cipher_package.AES = FakeAES
    monkeypatch.setitem(sys.modules, "Crypto", crypto)
    monkeypatch.setitem(sys.modules, "Crypto.Cipher", cipher_package)

    transcript = []
    result = recover_flag(_documents(), progress=transcript.append)
    assert result == "TST{synthetic}"
    assert recovered_secrets == [secret]
    assert "Verified candidate 2/3" in transcript[0]


def test_unrelated_code_and_bad_public_point_not_accepted():
    assert extract_instance([Document("irrelevant", "print('nothing')", None)]) is None
    docs = _documents()
    invalid = docs[1].text.replace("Public = ", "Public = (0, 0) #")
    assert extract_instance([docs[0], Document("raw", invalid, None)]) is None


def test_source_grammar_probes_independently():
    import ast
    source = Document("fresh-content.txt", _synthetic_source(), None)
    tree = ast.parse(source.text)
    assert _hash_scheme(tree) is not None
    assert _hash_parameters(tree) is not None
    assert _kdf_scheme(tree) is not None
    assert _curve_spec(tree) is not None
    assert _source_model(source) is not None
    _, ciphertext = _transcript()
    assert _read_output(Document("records.dat", ciphertext, None), 16) is not None


def test_real_bcrypt_aes_ctr_decrypts_synthetic_inlier():
    import bcrypt
    from Crypto.Cipher import AES

    secret, encoded = _transcript()
    flag = b"TST{verified_generic_corpus}"
    salt = b"SYNTHETIC_SALT"
    rounds = 2
    key = bcrypt.kdf(
        password=secret, salt=salt,
        desired_key_bytes=16, rounds=rounds,
    )
    ciphertext = AES.new(key, AES.MODE_CTR, nonce=b"12345678").encrypt(flag)
    source = _synthetic_source().replace(
        'b"SYNTHETIC_SALT", 16, 17',
        'b"SYNTHETIC_SALT", 16, 2',
    )
    output = encoded.replace(
        "Encrypted = 11223344",
        "Encrypted = " + ciphertext.hex(),
    )
    transcript = [
        Document("generic_sage_source.opaque", source, None),
        Document("sample_output.record", output, None),
    ]
    assert recover_flag(transcript, progress=lambda _: None) == flag.decode()
