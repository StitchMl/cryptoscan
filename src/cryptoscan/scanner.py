from __future__ import annotations

from collections import Counter, defaultdict
import math
import re
from typing import Any

from .mathutil import extended_gcd, fermat_factor, int_to_bytes, integer_nth_root, signed_mod_pow
from .model import Finding
from .parser import Document, assignments, flatten_objects, parse_bytes, parse_int


def _pick(obj: dict[str, Any], *names: str) -> Any | None:
    lowered = {str(k).casefold(): v for k, v in obj.items()}
    for name in names:
        if name in lowered:
            return lowered[name]
    return None


def _records(documents: list[Document]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for doc in documents:
        if doc.data is not None:
            for pointer, obj in flatten_objects(doc.data):
                records.append({"location": f"{doc.path}:{pointer}", "object": obj})
        assigned = assignments(doc.text)
        if assigned:
            records.append({"location": f"{doc.path}:assignments", "object": assigned})
    return records


def _rsa_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for record in records:
        obj = record["object"]
        n = parse_int(_pick(obj, "n", "modulus"))
        e = parse_int(_pick(obj, "e", "exponent", "public_exponent"))
        c = parse_int(_pick(obj, "c", "ciphertext", "ct"))
        if n is not None and n > 3:
            result.append({**record, "n": n, "e": e, "c": c})
    return result


def _bytes_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for record in records:
        obj = record["object"]
        for key, value in sorted(obj.items(), key=lambda item: str(item[0])):
            name = str(key).casefold()
            if any(token in name for token in ("cipher", "ct", "encrypted", "payload", "data")):
                parsed = parse_bytes(value)
                if parsed and len(parsed) >= 4:
                    result.append({**record, "field": str(key), "bytes": parsed})
    return result


def _single_byte_score(data: bytes) -> float:
    common = b" etaoinshrdluETAOINSHRDLU{}_:-0123456789"
    score = 0.0
    for byte in data:
        if byte in common:
            score += 2.0
        elif 32 <= byte <= 126 or byte in (9, 10, 13):
            score += 0.25
        else:
            score -= 4.0
    return score / max(1, len(data))


def scan(documents: list[Document], fermat_steps: int = 100_000) -> list[Finding]:
    records = _records(documents)
    rsa = _rsa_records(records)
    byte_records = _bytes_records(records)
    findings: list[Finding] = []

    # RSA pairwise shared factors.
    for left_index, left in enumerate(rsa):
        for right in rsa[left_index + 1 :]:
            if left["n"] == right["n"]:
                continue
            factor = math.gcd(left["n"], right["n"])
            if 1 < factor < min(left["n"], right["n"]):
                findings.append(Finding(
                    "RSA-SHARED-PRIME", "RSA moduli share a prime", "critical", "certain",
                    f'{left["location"]} + {right["location"]}',
                    {"gcd": str(factor), "n1": str(left["n"]), "n2": str(right["n"]),
                     "q1": str(left["n"] // factor), "q2": str(right["n"] // factor)},
                    ["The moduli belong to RSA public keys.", "At least one matching private key protects the flag."],
                    "Factor both moduli with gcd(n1, n2), derive phi, then compute each private exponent.",
                    {"kind": "rsa_shared_prime", "p": str(factor), "q1": str(left["n"] // factor), "q2": str(right["n"] // factor)},
                    "Generate each RSA prime with an independent CSPRNG and reject duplicate primes across the key corpus."
                ))

    for item in rsa:
        n, e, c = item["n"], item["e"], item["c"]
        if e == 3 and c is not None and 0 <= c < n:
            root, exact = integer_nth_root(c, 3)
            if exact:
                plain = int_to_bytes(root)
                findings.append(Finding(
                    "RSA-E3-EXACT-ROOT", "Unpadded RSA message is an exact cube", "critical", "certain", item["location"],
                    {"n": str(n), "e": 3, "c": str(c), "m": str(root), "plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace")},
                    ["Textbook RSA was used without randomized padding.", "m^3 is smaller than n."],
                    "Take the integer cube root of c. The exact root is the plaintext integer.",
                    {"kind": "integer_root", "degree": 3, "result_int": str(root), "result_hex": plain.hex()},
                    "Use RSA-OAEP with a maintained cryptographic library."
                ))
        factorization = fermat_factor(n, fermat_steps)
        if factorization:
            p, q, steps = factorization
            # Avoid noise for tiny toy values only when factors are not meaningfully close.
            closeness = q - p
            if steps <= fermat_steps and closeness * closeness < n:
                evidence = {"n": str(n), "p": str(p), "q": str(q), "difference": str(closeness), "steps": steps}
                solver: dict[str, Any] = {"kind": "rsa_fermat", "p": str(p), "q": str(q)}
                if e and c is not None and math.gcd(e, (p - 1) * (q - 1)) == 1:
                    d = pow(e, -1, (p - 1) * (q - 1))
                    m = pow(c, d, n)
                    plain = int_to_bytes(m)
                    evidence.update({"d": str(d), "plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace")})
                    solver.update({"d": str(d), "result_hex": plain.hex()})
                findings.append(Finding(
                    "RSA-FERMAT-CLOSE-PRIMES", "RSA primes are close enough for Fermat factorization", "critical", "certain", item["location"],
                    evidence, [f"Fermat search reaches the factors within {fermat_steps} steps."],
                    "Write n as a^2-b^2; recover p=a-b and q=a+b, then derive the private key.", solver,
                    "Generate independent primes with a CSPRNG and enforce an adequate distance between p and q."
                ))

    by_modulus: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for item in rsa:
        if item["e"] is not None and item["c"] is not None:
            by_modulus[item["n"]].append(item)
    for n, group in sorted(by_modulus.items()):
        for i, left in enumerate(group):
            for right in group[i + 1 :]:
                g, a, b = extended_gcd(left["e"], right["e"])
                if g != 1:
                    continue
                try:
                    m = (signed_mod_pow(left["c"], a, n) * signed_mod_pow(right["c"], b, n)) % n
                except ValueError:
                    continue
                plain = int_to_bytes(m)
                findings.append(Finding(
                    "RSA-COMMON-MODULUS", "RSA common-modulus attack recovers plaintext", "critical", "certain",
                    f'{left["location"]} + {right["location"]}',
                    {"n": str(n), "e1": left["e"], "e2": right["e"], "bezout_a": a, "bezout_b": b, "m": str(m), "plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace")},
                    ["Both ciphertexts encrypt the same plaintext under the same modulus.", "The public exponents are coprime."],
                    "Combine c1^a and c2^b modulo n using Bezout coefficients a and b.",
                    {"kind": "rsa_common_modulus", "result_int": str(m), "result_hex": plain.hex()},
                    "Never share an RSA modulus between keys. Use randomized OAEP padding."
                ))

    # Byte-level attacks.
    for record in byte_records:
        data = record["bytes"]
        candidates = []
        for key in range(256):
            plain = bytes(byte ^ key for byte in data)
            candidates.append((_single_byte_score(plain), key, plain))
        score, key, plain = max(candidates, key=lambda row: (row[0], -row[1]))
        if score >= 1.05 and len(data) >= 6:
            findings.append(Finding(
                "XOR-SINGLE-BYTE", "Single-byte XOR key is recoverable", "high", "high", f'{record["location"]}.{record["field"]}',
                {"key_hex": f"{key:02x}", "score": round(score, 4), "plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace")},
                ["Ciphertext represents repeated single-byte XOR.", "Plaintext resembles printable CTF text."],
                "Try all 256 keys and rank decoded text. The highest-scoring key and plaintext are included.",
                {"kind": "xor_single_byte", "key": key, "result_hex": plain.hex()},
                "Replace XOR obfuscation with authenticated encryption and a unique nonce."
            ))
        for block_size in (16, 8):
            blocks = [data[i:i + block_size] for i in range(0, len(data) - block_size + 1, block_size)]
            counts = Counter(blocks)
            repeats = {block.hex(): count for block, count in counts.items() if count > 1}
            if repeats:
                findings.append(Finding(
                    "BLOCK-ECB-REPETITION", "Repeated ciphertext blocks indicate ECB", "high", "high", f'{record["location"]}.{record["field"]}',
                    {"block_size": block_size, "repeated_blocks": dict(sorted(repeats.items()))},
                    ["Ciphertext is aligned to the reported block size.", "Repeated plaintext blocks map to repeated ciphertext blocks."],
                    "Use repeated blocks to infer structure, align controlled input, and mount byte-at-a-time ECB recovery when an oracle exists.",
                    {"kind": "ecb_repetition", "block_size": block_size, "repeat_count": sum(repeats.values())},
                    "Use an AEAD mode such as AES-GCM or ChaCha20-Poly1305 with a unique nonce."
                ))
                break

    for i, left in enumerate(byte_records):
        for right in byte_records[i + 1 :]:
            if left["bytes"] == right["bytes"]:
                continue
            length = min(len(left["bytes"]), len(right["bytes"]))
            xored = bytes(a ^ b for a, b in zip(left["bytes"][:length], right["bytes"][:length]))
            # Space-letter pattern is useful evidence for reused stream keystreams.
            alpha_positions = [idx for idx, b in enumerate(xored) if chr(b ^ 0x20).isalpha()]
            if length >= 8 and len(alpha_positions) / length >= 0.35:
                findings.append(Finding(
                    "XOR-KEYSTREAM-REUSE", "Ciphertexts likely reuse an XOR keystream", "high", "medium",
                    f'{left["location"]}.{left["field"]} + {right["location"]}.{right["field"]}',
                    {"xor_hex": xored.hex(), "length": length, "space_letter_positions": alpha_positions},
                    ["Both values are stream/XOR ciphertexts aligned at offset zero.", "Natural-language plaintext contains spaces."],
                    "C1 xor C2 removes the keystream. Crib-drag likely words to recover both plaintexts and the reused keystream.",
                    {"kind": "xor_crib_drag", "combined_hex": xored.hex()},
                    "Generate a unique nonce for every encryption under a key and reject nonce reuse."
                ))

    # Explicit nonce reuse in structured records.
    nonce_groups: dict[tuple[str, bytes], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        obj = record["object"]
        nonce = parse_bytes(_pick(obj, "nonce", "iv"))
        cipher = parse_bytes(_pick(obj, "ciphertext", "ct", "encrypted"))
        mode = str(_pick(obj, "mode", "algorithm", "alg") or "").casefold()
        key_id = str(_pick(obj, "key_id", "kid", "key", "keyid") or "unknown-key")
        if nonce and cipher and any(token in mode for token in ("ctr", "gcm", "chacha")):
            nonce_groups[(key_id, nonce)].append({**record, "nonce": nonce, "cipher": cipher, "mode": mode})
    for (key_id, nonce), group in sorted(nonce_groups.items(), key=lambda item: (item[0][0], item[0][1])):
        if len(group) < 2:
            continue
        for i, left in enumerate(group):
            for right in group[i + 1 :]:
                length = min(len(left["cipher"]), len(right["cipher"]))
                combined = bytes(a ^ b for a, b in zip(left["cipher"][:length], right["cipher"][:length]))
                is_gcm = "gcm" in left["mode"] or "gcm" in right["mode"]
                rule = "GCM-NONCE-REUSE" if is_gcm else "CTR-NONCE-REUSE"
                findings.append(Finding(
                    rule, f'{"GCM" if is_gcm else "CTR/stream"} nonce reuse', "critical", "certain",
                    f'{left["location"]} + {right["location"]}',
                    {"key_id": key_id, "nonce_hex": nonce.hex(), "ciphertexts_xor_hex": combined.hex()},
                    ["Records use the same key identifier and nonce.", "Ciphertexts start at the same stream offset."],
                    ("XOR ciphertexts to cancel the keystream; crib-drag the result. GCM reuse may also permit authentication forgeries."
                     if is_gcm else "XOR ciphertexts to cancel the keystream, then crib-drag known flag and message formats."),
                    {"kind": "nonce_reuse", "mode": "gcm" if is_gcm else "ctr", "combined_hex": combined.hex()},
                    "Allocate nonces atomically per key, persist the counter, and reject duplicates before encryption."
                ))

    findings.extend(_source_findings(documents))
    unique = {finding.id: finding for finding in findings}
    return sorted(unique.values(), key=lambda finding: (finding.location.casefold(), finding.rule, finding.id))


def _source_findings(documents: list[Document]) -> list[Finding]:
    rules = [
        ("HASH-WEAK", "Weak hash primitive", "medium", r"\b(?:md5|sha1)\s*\(",
         "Collision and chosen-prefix attacks can defeat integrity checks built on this digest.",
         "Use SHA-256 or SHA-3 for digests; use HMAC-SHA-256 for keyed authentication."),
        ("MAC-PREFIX-HASH", "Secret-prefix hash MAC may permit length extension", "high",
         r"(?:md5|sha1|sha256)\s*\(\s*(?:secret|key)\s*\+",
         "Compute a length-extension suffix after guessing secret length; submit the extended message and forged digest.",
         "Use HMAC with a maintained cryptographic library."),
        ("PRNG-PREDICTABLE-SEED", "Predictable PRNG seed", "high",
         r"(?:random\.seed\s*\(\s*(?:time|int\s*\(\s*time)|srand\s*\(\s*time)",
         "Enumerate timestamps around challenge execution, regenerate outputs, then recover the key or token.",
         "Use secrets or an operating-system CSPRNG. Do not seed it with time."),
        ("PRNG-MT-CRYPTO", "Mersenne Twister used in cryptographic path", "high",
         r"\b(?:mt19937|random\.getrandbits|random\.randbytes)\b",
         "Collect enough outputs to clone MT state, then predict later keys, nonces, or tokens.",
         "Use secrets.token_bytes or an operating-system CSPRNG."),
        ("CIPHER-ECB", "ECB mode selected in source", "high", r"\b(?:MODE_ECB|AES[-_]?ECB|\becb\b)",
         "Exploit equal-block leakage; with an encryption oracle, align input for byte-at-a-time secret recovery.",
         "Use AES-GCM or ChaCha20-Poly1305 with a unique nonce."),
        ("NONCE-CONSTANT", "Constant nonce or IV in source", "high",
         r"\b(?:nonce|iv)\s*=\s*(?:b?[\"'][^\"']+[\"']|bytes\s*\(|0x[0-9a-fA-F]+)",
         "Request or collect two encryptions, XOR ciphertexts, and recover plaintext through known format or crib dragging.",
         "Generate a unique nonce per key and store it with the ciphertext."),
    ]
    findings: list[Finding] = []
    for doc in documents:
        for rule, title, severity, pattern, attack, patch in rules:
            regex = re.compile(pattern, re.IGNORECASE)
            for match in regex.finditer(doc.text):
                line = doc.text.count("\n", 0, match.start()) + 1
                excerpt = doc.text.splitlines()[line - 1].strip()[:200]
                findings.append(Finding(
                    rule, title, severity, "medium", f"{doc.path}:{line}",
                    {"match": match.group(0), "line": excerpt},
                    ["Matched code executes in the challenge cryptographic path."], attack,
                    {"kind": "source_guidance", "matched_pattern": rule}, patch
                ))
    return findings
