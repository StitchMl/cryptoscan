import json
import base64
import zipfile
import hashlib
import random

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
    assert cube.recovery_status == "payload-ready"
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


def test_hastad_wiener_and_signature_nonce_reuse(tmp_path):
    message = int.from_bytes(b"flag", "big")
    moduli = [1000000007 * 1000000009, 1000000033 * 1000000087, 1000000093 * 1000000097]
    broadcast = [{"n": n, "e": 3, "c": pow(message, 3, n)} for n in moduli]

    p, q, d = 1009, 1013, 5
    n = p * q
    e = pow(d, -1, (p - 1) * (q - 1))
    wiener = {"n": n, "e": e, "c": pow(42, e, n)}

    order, private, nonce, r = 1019, 123, 77, 321
    z1, z2 = 111, 222
    sig1 = {"q": order, "r": r, "s": ((z1 + r * private) * pow(nonce, -1, order)) % order, "z": z1}
    sig2 = {"q": order, "r": r, "s": ((z2 + r * private) * pow(nonce, -1, order)) % order, "z": z2}
    path = tmp_path / "advanced.json"
    path.write_text(json.dumps(broadcast + [wiener, sig1, sig2]), encoding="utf-8")
    findings = scan(collect_documents([str(path)]))
    rules = {finding.rule for finding in findings}
    assert {"RSA-HASTAD-BROADCAST", "RSA-WIENER-SMALL-D", "SIGNATURE-NONCE-REUSE"} <= rules
    signature = next(finding for finding in findings if finding.rule == "SIGNATURE-NONCE-REUSE")
    assert signature.solver["private_key_x"] == str(private)


def test_archive_and_colon_dump_parsing(tmp_path):
    archive_path = tmp_path / "challenge.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("data/weak.py", "digest = md5(flag)\n")
        archive.writestr("data/key.txt", "mode: AES-GCM\nnonce: 000102030405060708090a0b\n")
    documents = collect_documents([str(archive_path)])
    assert [document.path for document in documents] == ["challenge.zip!/data/key.txt", "challenge.zip!/data/weak.py"]
    assert "HASH-WEAK" in {finding.rule for finding in scan(documents)}


def test_false_positive_guards(tmp_path):
    path = tmp_path / "safe.py"
    path.write_text(
        "# digest = md5(flag)\n"
        "cache_name = md5(public_filename)\n"
        "ciphertext = b'plain printable data'\n",
        encoding="utf-8",
    )
    rules = rules_for(path)
    assert "HASH-WEAK" not in rules
    assert "XOR-SINGLE-BYTE" not in rules


def test_nonce_reuse_without_key_id_is_not_certain(tmp_path):
    path = tmp_path / "nonce.json"
    path.write_text(json.dumps([
        {"mode": "AES-GCM", "nonce": "00112233445566778899aabb", "ct": "0011223344556677"},
        {"mode": "AES-GCM", "nonce": "00112233445566778899aabb", "ct": "1021324354657687"},
    ]), encoding="utf-8")
    finding = next(item for item in scan(collect_documents([str(path)])) if item.rule == "GCM-NONCE-REUSE")
    assert finding.confidence == "medium"


def test_repeating_key_xor_recovery(tmp_path):
    plain = b"message=flag{repeating_xor_recovered};padding=english-text"
    key = b"ICE"
    cipher = bytes(value ^ key[index % len(key)] for index, value in enumerate(plain))
    path = tmp_path / "xor.json"
    path.write_text(json.dumps({"ciphertext": cipher.hex()}), encoding="utf-8")
    findings = scan(collect_documents([str(path)]))
    repeated = next(item for item in findings if item.rule == "XOR-REPEATING-KEY")
    assert bytes.fromhex(repeated.solver["result_hex"]) == plain
    assert repeated.recovery_status == "flag-recovered"
    assert [step["op"] for step in repeated.cyberchef["recipe"]] == ["From Hex", "XOR"]


def test_cyberchef_recipe_preserves_base64_input(tmp_path):
    plaintext = b"flag{base64_recipe}"
    ciphertext = bytes(value ^ 0x42 for value in plaintext)
    encoded = base64.b64encode(ciphertext).decode()
    path = tmp_path / "encoded.json"
    path.write_text(json.dumps({"ciphertext": encoded}), encoding="utf-8")
    finding = next(item for item in scan(collect_documents([str(path)])) if item.rule == "XOR-SINGLE-BYTE")
    assert finding.cyberchef["input"] == encoded
    assert finding.cyberchef["input_encoding"] == "base64"
    assert [step["op"] for step in finding.cyberchef["recipe"]] == ["From Base64", "XOR"]


def test_support_files_are_ignored_by_default(tmp_path):
    (tmp_path / "README.md").write_text("digest = md5(flag)\n", encoding="utf-8")
    (tmp_path / "solver.py").write_text("key = b'hardcoded-secret'\n", encoding="utf-8")
    (tmp_path / "writeup.ipynb").write_text('{"cells": [{"source": ["AES.MODE_ECB"]}]}', encoding="utf-8")
    assert collect_documents([str(tmp_path)]) == []


def test_shared_prime_does_not_cross_challenge_boundaries(tmp_path):
    shared = 1009
    first = tmp_path / "challenge_one"
    second = tmp_path / "challenge_two"
    first.mkdir()
    second.mkdir()
    (first / "public.json").write_text(json.dumps({"n": shared * 1013, "e": 65537, "c": 7}), encoding="utf-8")
    (second / "public.json").write_text(json.dumps({"n": shared * 1019, "e": 65537, "c": 9}), encoding="utf-8")
    rules = {finding.rule for finding in scan(collect_documents([str(tmp_path)]))}
    assert "RSA-SHARED-PRIME" not in rules


def test_duplicate_release_server_and_archive_artifacts_are_deduplicated(tmp_path):
    payload = json.dumps({"n": 1009 * 1013, "e": 65537, "c": 7})
    (tmp_path / "release").mkdir()
    (tmp_path / "server").mkdir()
    (tmp_path / "release" / "public.json").write_text(payload, encoding="utf-8")
    (tmp_path / "server" / "public.json").write_text(payload, encoding="utf-8")
    with zipfile.ZipFile(tmp_path / "challenge.zip", "w") as archive:
        archive.writestr("public.json", payload)
    documents = collect_documents([str(tmp_path)])
    assert len(documents) == 1
    assert "!/" not in documents[0].path


def test_secret_prefix_hash_reports_length_extension_not_collision(tmp_path):
    path = tmp_path / "challenge.py"
    path.write_text("digest = sha1(secret + message)\n", encoding="utf-8")
    findings = scan(collect_documents([str(path)]))
    assert {finding.rule for finding in findings} == {"MAC-PREFIX-HASH"}
    finding = findings[0]
    assert "length-extension" in finding.attack


def test_rsa_private_parameter_leaks(tmp_path):
    p, q, e, message = 1009, 1013, 65537, 42
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    ciphertext = pow(message, e, n)
    corpus = [
        {"n": n, "e": e, "c": ciphertext, "p": p},
        {"n": n, "e": e, "c": ciphertext, "dp": d % (p - 1)},
        {"n": n, "e": e, "c": ciphertext, "d": d},
    ]
    path = tmp_path / "leaks.json"
    path.write_text(json.dumps(corpus), encoding="utf-8")
    findings = scan(collect_documents([str(path)]))
    rules = {finding.rule for finding in findings}
    assert {"RSA-PARAMETER-LEAK", "RSA-PRIVATE-EXPONENT-LEAK"} <= rules
    assert all(finding.confidence == "certain" for finding in findings if finding.rule.startswith("RSA-") and "LEAK" in finding.rule)


def test_lcg_dh_and_cbc_calculated_vectors(tmp_path):
    modulus, multiplier, increment, state = 2147483647, 48271, 12345, 987654
    outputs = []
    for _ in range(7):
        state = (multiplier * state + increment) % modulus
        outputs.append(state)
    dh_p, dh_g, alice_private, bob_private = 1019, 2, 123, 77
    known = "role=user;pad=00"
    target = "role=admin;pad=0"
    corpus = [
        {"type": "LCG", "modulus": modulus, "outputs": outputs},
        {"algorithm": "DH", "p": dh_p, "g": dh_g, "public_a": pow(dh_g, alice_private, dh_p), "public_b": pow(dh_g, bob_private, dh_p)},
        {"mode": "AES-CBC", "iv": "00" * 16, "ciphertext": "11" * 32, "known_plaintext": known, "target_plaintext": target},
    ]
    path = tmp_path / "structured.json"
    path.write_text(json.dumps(corpus), encoding="utf-8")
    findings = scan(collect_documents([str(path)]))
    by_rule = {finding.rule: finding for finding in findings}
    assert {"LCG-STATE-RECOVERY", "DH-SMALL-GROUP", "CBC-FIRST-BLOCK-BITFLIP"} <= set(by_rule)
    assert by_rule["LCG-STATE-RECOVERY"].solver["next_output"] == str((multiplier * outputs[-1] + increment) % modulus)
    assert by_rule["LCG-STATE-RECOVERY"].recovery_status == "payload-ready"
    assert by_rule["DH-SMALL-GROUP"].evidence["discrete_log_verified"] is True
    assert by_rule["CBC-FIRST-BLOCK-BITFLIP"].recovery_status == "payload-ready"


def _der(tag, value):
    length = bytes([len(value)]) if len(value) < 128 else bytes([0x81, len(value)])
    return bytes([tag]) + length + value


def _der_integer(value):
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\0" + raw
    return _der(0x02, raw)


def test_pkcs1_pem_public_key_parsing(tmp_path):
    n, e = 1009 * 1013, 65537
    der = _der(0x30, _der_integer(n) + _der_integer(e))
    encoded = base64.b64encode(der).decode()
    path = tmp_path / "public.pem"
    path.write_text(f"-----BEGIN RSA PUBLIC KEY-----\n{encoded}\n-----END RSA PUBLIC KEY-----\n", encoding="utf-8")
    documents = collect_documents([str(path)])
    findings = scan(documents)
    assert any(finding.rule == "RSA-FERMAT-CLOSE-PRIMES" for finding in findings)
    der_path = tmp_path / "public.der"
    der_path.write_bytes(der)
    der_findings = scan(collect_documents([str(der_path)]))
    assert any(finding.rule == "RSA-FERMAT-CLOSE-PRIMES" for finding in der_findings)


def test_structured_attack_negative_guards(tmp_path):
    corpus = [
        {"n": 1009 * 1013, "e": 65537, "c": 7, "p": 17, "dp": 2},
        {"outputs": [1, 8, 2, 19, 4, 7], "modulus": 23},
        {"p": 1019, "g": 2, "public_a": 5},
        {"algorithm": "ECDH", "p": 1019, "g": 2, "public_a": 5},
        {"mode": "AES-CBC", "iv": "00" * 16, "ciphertext": "11" * 32, "known_plaintext": "role=user;pad=00"},
    ]
    path = tmp_path / "negative.json"
    path.write_text(json.dumps(corpus), encoding="utf-8")
    rules = {finding.rule for finding in scan(collect_documents([str(path)]))}
    assert not {"RSA-PARAMETER-LEAK", "LCG-STATE-RECOVERY", "DH-SMALL-GROUP", "CBC-FIRST-BLOCK-BITFLIP"} & rules


def test_general_low_exponent_and_hastad_e5(tmp_path):
    message = int.from_bytes(b"flag{e5}", "big")
    moduli = [10**30 + offset for offset in (57, 61, 69, 87, 91)]
    # A separate wrapped e=3 sample exercises c+k*n root recovery.
    wrapped_n = 101 * 113
    wrapped_m = 30
    corpus = [{"n": n, "e": 5, "c": pow(message, 5, n)} for n in moduli]
    corpus.append({"n": wrapped_n, "e": 3, "c": pow(wrapped_m, 3, wrapped_n)})
    path = tmp_path / "low-exponent.json"
    path.write_text(json.dumps(corpus), encoding="utf-8")
    findings = scan(collect_documents([str(path)]))
    hastad = next(item for item in findings if item.rule == "RSA-HASTAD-BROADCAST" and item.evidence["e"] == 5)
    assert bytes.fromhex(hastad.solver["result_hex"]) == b"flag{e5}"
    assert hastad.recovery_status == "flag-recovered"
    wrapped = next(item for item in findings if item.rule == "RSA-LOW-EXPONENT-SMALL-MESSAGE")
    assert wrapped.evidence["m"] == str(wrapped_m)


def test_known_plaintext_nonce_reuse_recovers_flag(tmp_path):
    nonce = "00" * 12
    key_stream = bytes(range(1, 33))
    known = b"A" * 32
    secret = b"flag{nonce_reuse_recovery}!!!!!!"
    assert len(known) == len(secret) == len(key_stream)
    encrypt = lambda plain: bytes(left ^ right for left, right in zip(plain, key_stream)).hex()
    path = tmp_path / "nonce-reuse.json"
    path.write_text(json.dumps([
        {"mode": "AES-CTR", "key_id": "k1", "nonce": nonce, "ciphertext": encrypt(known), "known_plaintext": known.hex()},
        {"mode": "AES-CTR", "key_id": "k1", "nonce": nonce, "ciphertext": encrypt(secret)},
    ]), encoding="utf-8")
    finding = next(item for item in scan(collect_documents([str(path)])) if item.rule == "CTR-NONCE-REUSE")
    assert bytes.fromhex(finding.solver["result_hex"]) == secret
    assert finding.recovery_status == "flag-recovered"


def test_mt_clone_and_disclosed_signature_nonce(tmp_path):
    generator = random.Random(1337)
    outputs = [generator.getrandbits(32) for _ in range(625)]
    q, private, nonce, r, z = 1019, 123, 77, 321, 456
    s = ((z + r * private) * pow(nonce, -1, q)) % q
    path = tmp_path / "state.json"
    path.write_text(json.dumps([
        {"generator": "MT19937", "outputs": outputs},
        {"q": q, "r": r, "s": s, "z": z, "k": nonce},
    ]), encoding="utf-8")
    by_rule = {item.rule: item for item in scan(collect_documents([str(path)]))}
    assert by_rule["MT19937-STATE-CLONE"].solver["predicted_next"] == str(outputs[624])
    assert by_rule["MT19937-STATE-CLONE"].recovery_status == "payload-ready"
    assert by_rule["SIGNATURE-NONCE-DISCLOSURE"].solver["private_key_x"] == str(private)


def test_sha1_length_extension_vector_is_valid(tmp_path):
    secret = b"hidden-key"
    message = b"role=user"
    suffix = b"&role=admin"
    digest = hashlib.sha1(secret + message).hexdigest()
    path = tmp_path / "extension.json"
    path.write_text(json.dumps({
        "algorithm": "sha1", "digest": digest, "message": message.hex(),
        "append": suffix.hex(), "secret_length": len(secret),
    }), encoding="utf-8")
    finding = next(item for item in scan(collect_documents([str(path)])) if item.rule == "SHA1-LENGTH-EXTENSION")
    forged_message = bytes.fromhex(finding.solver["message_hex"])
    forged_digest = finding.solver["digest_hex"]
    assert hashlib.sha1(secret + forged_message).hexdigest() == forged_digest
    assert finding.recovery_status == "payload-ready"


def test_cbc_iv_reuse_is_diagnostic_only(tmp_path):
    path = tmp_path / "cbc.json"
    path.write_text(json.dumps([
        {"mode": "AES-CBC", "key_id": "same", "iv": "00" * 16, "ciphertext": "11" * 32},
        {"mode": "AES-CBC", "key_id": "same", "iv": "00" * 16, "ciphertext": "22" * 32},
    ]), encoding="utf-8")
    finding = next(item for item in scan(collect_documents([str(path)])) if item.rule == "CBC-IV-REUSE")
    assert finding.recovery_status == "validation-only"


def test_rsa_crt_fault_factors_modulus(tmp_path):
    p, q, e, message = 1009, 1013, 65537, 42
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))
    valid = pow(message, d, n)
    faulty = valid + p
    path = tmp_path / "fault.json"
    path.write_text(json.dumps([
        {"n": n, "e": e, "message_representative": message, "signature": valid},
        {"n": n, "e": e, "message_representative": message, "signature": faulty},
    ]), encoding="utf-8")
    finding = next(item for item in scan(collect_documents([str(path)])) if item.rule == "RSA-CRT-FAULT")
    assert int(finding.solver["p"]) * int(finding.solver["q"]) == n
    assert finding.recovery_status == "payload-ready"


def test_padding_oracle_requires_compound_source_evidence(tmp_path):
    vulnerable = tmp_path / "oracle.py"
    vulnerable.write_text(
        "cipher = AES.new(key, AES.MODE_CBC, iv)\n"
        "try:\n"
        "    value = unpad(cipher.decrypt(data), 16)\n"
        "except ValueError:\n"
        "    return 'invalid padding', 403\n",
        encoding="utf-8",
    )
    finding = next(item for item in scan(collect_documents([str(vulnerable)])) if item.rule == "CBC-PADDING-ORACLE")
    assert finding.recovery_status == "validation-only"

    safe = tmp_path / "safe_cbc.py"
    safe.write_text("cipher = AES.new(key, AES.MODE_CBC, iv)\nvalue = unpad(cipher.decrypt(data), 16)\n", encoding="utf-8")
    assert "CBC-PADDING-ORACLE" not in rules_for(safe)
