import json

from cryptoscan.parser import collect_documents
from cryptoscan.scanner import scan


def rules_for(path):
    return {finding.rule for finding in scan(collect_documents([str(path)]))}


def test_rsa_calculated_attacks(tmp_path):
    m = int.from_bytes(b"flag", "big")
    n1 = 1009 * 1237
    n2 = 1009 * 1423
    common_n = 101 * 113
    common_m = 42
    corpus = [
        {"n": n1, "e": 65537, "c": 7},
        {"n": n2, "e": 65537, "c": 9},
        {"n": 10**30 + 57, "e": 3, "c": m**3},
        {"n": common_n, "e": 7, "c": pow(common_m, 7, common_n)},
        {"n": common_n, "e": 11, "c": pow(common_m, 11, common_n)},
    ]
    path = tmp_path / "rsa.json"
    path.write_text(json.dumps(corpus), encoding="utf-8")
    findings = scan(collect_documents([str(path)]))
    rules = {finding.rule for finding in findings}
    assert {"RSA-SHARED-PRIME", "RSA-E3-EXACT-ROOT", "RSA-COMMON-MODULUS"} <= rules
    cube = next(f for f in findings if f.rule == "RSA-E3-EXACT-ROOT")
    assert cube.evidence["plaintext_utf8"] == "flag"
    common = next(f for f in findings if f.rule == "RSA-COMMON-MODULUS")
    assert common.evidence["m"] == "42"


def test_xor_ecb_and_nonce_reuse(tmp_path):
    plaintext = b"flag{single_byte_xor}"
    encrypted = bytes(value ^ 0x42 for value in plaintext).hex()
    repeated = (b"A" * 16 + b"B" * 16 + b"A" * 16).hex()
    corpus = [
        {"ciphertext": encrypted},
        {"ciphertext": repeated},
        {"mode": "AES-GCM", "key_id": "challenge", "nonce": "000102030405060708090a0b", "ciphertext": "1020304050607080"},
        {"mode": "AES-GCM", "key_id": "challenge", "nonce": "000102030405060708090a0b", "ciphertext": "0011223344556677"},
    ]
    path = tmp_path / "bytes.json"
    path.write_text(json.dumps(corpus), encoding="utf-8")
    rules = rules_for(path)
    assert {"XOR-SINGLE-BYTE", "BLOCK-ECB-REPETITION", "GCM-NONCE-REUSE"} <= rules


def test_source_patterns(tmp_path):
    path = tmp_path / "challenge.py"
    path.write_text(
        "import random, time\n"
        "random.seed(time.time())\n"
        "nonce = b'constant-123'\n"
        "digest = sha1(secret + message)\n"
        "cipher = AES.new(key, AES.MODE_ECB)\n",
        encoding="utf-8",
    )
    rules = rules_for(path)
    assert {"PRNG-PREDICTABLE-SEED", "NONCE-CONSTANT", "MAC-PREFIX-HASH", "CIPHER-ECB"} <= rules


def test_deterministic_json(tmp_path):
    path = tmp_path / "sample.json"
    path.write_text(json.dumps({"ciphertext": bytes(x ^ 7 for x in b"flag{stable}").hex()}), encoding="utf-8")
    first = [finding.to_dict() for finding in scan(collect_documents([str(path)]))]
    second = [finding.to_dict() for finding in scan(collect_documents([str(path)]))]
    assert first == second
    assert all("duration" not in finding and str(tmp_path) not in json.dumps(finding) for finding in first)
