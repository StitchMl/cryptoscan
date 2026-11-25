from __future__ import annotations

from .source_units import parse_python

import base64
import math
import random
import re
import struct
from collections import Counter, defaultdict
from itertools import combinations, islice, pairwise
from typing import Any

from .mathutil import (
    crt,
    discrete_log_bsgs,
    extended_gcd,
    fermat_factor,
    int_to_bytes,
    integer_nth_root,
    signed_mod_pow,
    small_factor,
    wiener_private_exponent,
)
from .model import Finding
from .rsa_related_key import extract_instance as extract_related_key, source_profiles as related_key_profiles
from .rotated_quadratic_rsa import extract_instance as extract_rotated_rsa, source_profiles as rotated_rsa_profiles
from .eclcg_detector import detect_ec_lcg
from .fischlin_workflow import supported_source as supported_fischlin_source
from .dghv_workflow import supported_source as supported_dghv_source
from .rsa_padding_positives import discover_positive_padding_oracles
from .modular_linear_hash import recognize_linear_hash, solve_linear_hash
from .ntru import recognize_ntru, is_polynomial_coefficients, analyze_ntru_vectors, pair_ntru_records
from .mlwe import recognize_weak_mlwe_ring
from .gcm_overlap_detector import counter_overlap_lines
from .gcm_hidden_state import recognize_gcm_tag_oracle
from .gcm_hidden_live import supports_wire_profile as supports_gcm_wire_profile
from .hamiltonicity_workflow import extract_instance as extract_fiat_shamir_graph
from .fiat_shamir_batch import extract_instance as extract_batch_fiat_shamir
from .aead_diagnostics import unused_validation_flags
from .stream_combiner_workflow import recognize_stream_cipher
from .biased_shamir import _source_profile as biased_shamir_profile
from .cyclotomic_rsa import _source_profile as cyclotomic_rsa_profile, extract_instance as extract_cyclotomic_rsa
from .modular_noise_mixture import _source_profile as modular_noise_profile, extract_instance as extract_modular_noise
from .ec_twist_oracle import _source_profile as ec_twist_profile
from .hyperelliptic_state_leak import _source_profile as hyperelliptic_leak_profile
from .reciprocal_rabin_oracle import _source_profile as reciprocal_rabin_profile
from .weak_seeded_multiprime_rsa import (
    extract_instance as extract_weak_seeded_rsa,
    _source_profile as weak_seeded_rsa_profile,
)
from .rsa_reused_digits import (
    extract_instance as extract_reused_digits,
    source_profile as reused_digits_profile,
)
from .parser import (
    Document,
    flatten_objects,
    parse_bytes,
    parse_int,
    pem_rsa_public_keys,
    scalar_records,
)

_AUTHORIZED_HOST = "authorized host"


def _pick(obj: dict[str, Any], *names: str) -> Any | None:
    lowered = {str(k).casefold(): v for k, v in obj.items()}
    for name in names:
        if name in lowered:
            return lowered[name]
    return None


def _bytes_or_text(value: Any) -> bytes | None:
    parsed = parse_bytes(value)
    if parsed is not None:
        return parsed
    return value.encode() if isinstance(value, str) else None


def _records(documents: list[Document]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for doc in documents:
        if doc.data is not None:
            for pointer, obj in flatten_objects(doc.data):
                records.append({"location": f"{doc.path}:{pointer}", "object": obj, "scope": doc.scope})
        for assigned in scalar_records(doc.text):
            records.append({"location": f"{doc.path}:assignments", "object": assigned, "scope": doc.scope})
        for index, key in enumerate(pem_rsa_public_keys(doc.text)):
            records.append({"location": f"{doc.path}:pem[{index}]", "object": key, "scope": doc.scope})
    return records


def _rsa_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for record in records:
        obj = record["object"]
        n = parse_int(_pick(obj, "n", "modulus"))
        e = parse_int(_pick(obj, "e", "exponent", "public_exponent"))
        c = parse_int(_pick(obj, "c", "ciphertext", "ct"))
        # RSA requires an actual public exponent. A standalone 'n' may be
        # an unrelated ring dimension or modulus (e.g. n=256 in Sage Zmod(n)).
        if n is not None and n > 3 and e is not None and e > 1:
            result.append({**record, "n": n, "e": e, "c": c,
                           "p": parse_int(_pick(obj, "p", "prime1")), "q": parse_int(_pick(obj, "q", "prime2")),
                           "d": parse_int(_pick(obj, "d", "private_exponent")),
                           "dp": parse_int(_pick(obj, "dp", "dmp1")), "dq": parse_int(_pick(obj, "dq", "dmq1"))})
    return result


def _binary_cipher_record(
    record: dict[str, Any], key: Any, value: Any,
    ntru_contexts,
) -> dict[str, Any] | None:
    name = str(key).casefold()
    if not any(token in name for token in ("cipher", "ct", "encrypted", "payload", "data")):
        return None
    if any(
        record["scope"] == context.scope
        and is_polynomial_coefficients(value, context)
        for context in ntru_contexts
    ):
        return None
    parsed = parse_bytes(value)
    if not parsed or len(parsed) < 4:
        return None
    encoding, encoded_input = _cyberchef_input(value, parsed)
    return {
        **record, "field": str(key), "bytes": parsed,
        "input_encoding": encoding, "encoded_input": encoded_input,
    }


def _bytes_records(
    records: list[dict[str, Any]], ntru_contexts=(),
) -> list[dict[str, Any]]:
    result = []
    for record in records:
        for key, value in sorted(record["object"].items(),
                                 key=lambda item: str(item[0])):
            candidate = _binary_cipher_record(record, key, value, ntru_contexts)
            if candidate is not None:
                result.append(candidate)
    return result


def _cyberchef_input(value: Any, parsed: bytes) -> tuple[str, str]:
    """Preserve the artifact's representation for deterministic offline recipes."""
    if isinstance(value, str):
        cleaned = value.strip()
        hexed = cleaned[2:] if cleaned.casefold().startswith("0x") else cleaned
        normalized_hex = re.sub(r"[\s:_-]", "", hexed)
        if len(normalized_hex) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", normalized_hex or ""):
            return "hex", normalized_hex.lower()
        try:
            if base64.b64decode(cleaned, validate=True) == parsed:
                return "base64", cleaned
        except ValueError:
            pass
    return "hex", parsed.hex()


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


def _language_score(data: bytes) -> float:
    frequencies = {
        " ": 0.18, "e": 0.102, "t": 0.075, "a": 0.065, "o": 0.061, "i": 0.057,
        "n": 0.057, "s": 0.053, "h": 0.049, "r": 0.049, "d": 0.034, "l": 0.033, "u": 0.022,
    }
    total = 0.0
    for value in data:
        char = chr(value).casefold()
        if char in frequencies:
            total += math.log(frequencies[char])
        elif "a" <= char <= "z":
            total += math.log(0.012)
        elif char.isdigit() or char in "{}_=-;:,.!?/":
            total += math.log(0.008)
        elif 32 <= value <= 126:
            total += math.log(0.001)
        else:
            total -= 20
    lowered = data.lower()
    total += 2.5 * sum(lowered.count(token) for token in (b"the", b"ing", b"ion", b"message", b"padding", b"text"))
    return total / max(1, len(data))


def _factor_from_crt_exponent(n: int, e: int, reduced_d: int) -> int | None:
    exponent = e * reduced_d
    for base in range(2, 65):
        factor = math.gcd(pow(base, exponent, n) - base, n)
        if 1 < factor < n:
            return factor
    return None


def _recover_lcg(outputs: list[int], modulus: int | None) -> tuple[int, int, int] | None:
    if len(outputs) < 4 or any(value < 0 for value in outputs):
        return None
    if modulus is None:
        differences = [right - left for left, right in pairwise(outputs)]
        zeros = [abs(differences[i + 2] * differences[i] - differences[i + 1] ** 2) for i in range(len(differences) - 2)]
        modulus = 0
        for value in zeros:
            modulus = math.gcd(modulus, value)
    if not modulus or modulus <= max(outputs):
        return None
    try:
        multiplier = ((outputs[2] - outputs[1]) * pow((outputs[1] - outputs[0]) % modulus, -1, modulus)) % modulus
    except ValueError:
        return None
    increment = (outputs[1] - multiplier * outputs[0]) % modulus
    if any((multiplier * left + increment) % modulus != right for left, right in pairwise(outputs)):
        return None
    return modulus, multiplier, increment


def _untemper_mt19937(value: int) -> int:
    """Invert the MT19937 tempering transform for one full 32-bit output."""
    def undo_right(output: int, shift: int) -> int:
        result = output
        for _ in range(32 // shift + 1):
            result = output ^ (result >> shift)
        return result & 0xFFFFFFFF

    def undo_left(output: int, shift: int, mask: int) -> int:
        result = output
        for _ in range(32 // shift + 1):
            result = output ^ ((result << shift) & mask)
        return result & 0xFFFFFFFF

    value = undo_right(value & 0xFFFFFFFF, 18)
    value = undo_left(value, 15, 0xEFC60000)
    value = undo_left(value, 7, 0x9D2C5680)
    return undo_right(value, 11)


def _temper_mt19937(value: int) -> int:
    value ^= value >> 11
    value ^= (value << 7) & 0x9D2C5680
    value ^= (value << 15) & 0xEFC60000
    value ^= value >> 18
    return value & 0xFFFFFFFF


def _clone_mt19937(outputs: list[int]) -> tuple[int, bool] | None:
    if len(outputs) < 624 or any(value < 0 or value > 0xFFFFFFFF for value in outputs[:624]):
        return None
    state = [_untemper_mt19937(value) for value in outputs[:624]]
    verified = all(_temper_mt19937(raw) == output for raw, output in zip(state, outputs[:624], strict=False))
    if not verified:
        return None
    clone = random.Random()
    clone.setstate((3, (*state, 624), None))
    return clone.getrandbits(32), True


def _sha1_compress(block: bytes, state: tuple[int, int, int, int, int]) -> tuple[int, int, int, int, int]:
    words = list(struct.unpack(">16I", block)) + [0] * 64
    for index in range(16, 80):
        word = words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16]
        words[index] = ((word << 1) | (word >> 31)) & 0xFFFFFFFF
    a, b, c, d, e = state
    original = state
    for index, word in enumerate(words):
        if index < 20:
            function, constant = (b & c) | (~b & d), 0x5A827999
        elif index < 40:
            function, constant = b ^ c ^ d, 0x6ED9EBA1
        elif index < 60:
            function, constant = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            function, constant = b ^ c ^ d, 0xCA62C1D6
        rotated = ((a << 5) | (a >> 27)) & 0xFFFFFFFF
        temp = (rotated + function + e + constant + word) & 0xFFFFFFFF
        a, b, c, d, e = temp, a, ((b << 30) | (b >> 2)) & 0xFFFFFFFF, c, d
    return tuple((left + right) & 0xFFFFFFFF for left, right in zip((a, b, c, d, e), original, strict=False))


def _sha1_padding(message_length: int) -> bytes:
    padding = b"\x80"
    padding += b"\0" * ((56 - (message_length + 1) % 64) % 64)
    return padding + struct.pack(">Q", message_length * 8)


def _sha1_length_extend(digest: bytes, message: bytes, secret_length: int, suffix: bytes) -> tuple[bytes, bytes] | None:
    if len(digest) != 20 or secret_length < 0:
        return None
    glue = _sha1_padding(secret_length + len(message))
    forged_message = message + glue + suffix
    state = struct.unpack(">5I", digest)
    total_before_suffix = secret_length + len(message) + len(glue)
    tail = suffix + _sha1_padding(total_before_suffix + len(suffix))
    for offset in range(0, len(tail), 64):
        state = _sha1_compress(tail[offset:offset + 64], state)
    return forged_message, struct.pack(">5I", *state)


def _repeating_xor_keys(data: bytes, key_size: int) -> list[bytes]:
    baseline = bytearray()
    for offset in range(key_size):
        column = data[offset::key_size]
        candidates = [
            (_single_byte_score(bytes(value ^ guess for value in column)), guess)
            for guess in range(256)
        ]
        baseline.append(max(candidates, key=lambda row: (row[0], -row[1]))[1])
    keys = [bytes(baseline)]
    for crib in (b"flag{", b"ctf{"):
        for start in range(len(data) - len(crib) + 1):
            candidate = bytearray(baseline)
            fixed: dict[int, int] = {}
            valid = True
            for index, expected in enumerate(crib):
                position = (start + index) % key_size
                value = data[start + index] ^ expected
                if position in fixed and fixed[position] != value:
                    valid = False
                    break
                fixed[position] = value
                candidate[position] = value
            if valid:
                keys.append(bytes(candidate))
    return keys


def _repeating_xor_plaintext(data: bytes, key: bytes) -> bytes | None:
    plain = bytes(value ^ key[index % len(key)] for index, value in enumerate(data))
    if not re.search(
        rb"(?:flag|ctf|key)\{[a-z0-9_!@#$%+.,:/=\\-]{4,120}\}",
        plain, re.IGNORECASE,
    ):
        return None
    printable = sum(
        value in (9, 10, 13) or 32 <= value <= 126
        for value in plain
    ) / len(plain)
    return plain if printable >= 0.98 else None


def _repeating_xor_candidate(data: bytes) -> tuple[bytes, bytes, float] | None:
    """Return a conservative repeating-key XOR solution with a verified flag token."""
    best: tuple[float, bytes, bytes] | None = None
    for key_size in range(2, min(40, len(data) // 2) + 1):
        for key in _repeating_xor_keys(data, key_size):
            plaintext = _repeating_xor_plaintext(data, key)
            if plaintext is None:
                continue
            score = _language_score(plaintext) - 0.015 * key_size
            if best is None or (score, bytes(key)) > (best[0], best[1]):
                best = score, bytes(key), plaintext
    return (best[1], best[2], best[0]) if best else None


def _shared_prime_finding(left, right):
    factor = math.gcd(left["n"], right["n"])
    if not 1 < factor < min(left["n"], right["n"]):
        return None
    return Finding(
        "RSA-SHARED-PRIME", "RSA moduli share a prime", "critical", "certain",
        f'{left["location"]} + {right["location"]}',
        {"gcd": str(factor), "n1": str(left["n"]), "n2": str(right["n"]),
         "q1": str(left["n"] // factor), "q2": str(right["n"] // factor)},
        ["The moduli belong to RSA public keys.", "At least one matching private key protects the flag."],
        "Factor both moduli with gcd(n1, n2), derive phi, then compute each private exponent.",
        {"kind": "rsa_shared_prime", "p": str(factor), "q1": str(left["n"] // factor), "q2": str(right["n"] // factor)},
        "Generate each RSA prime with an independent CSPRNG and reject duplicate primes across the key corpus."
    )


def _rsa_shared_prime_findings(rsa, findings):
    for left_index, left in enumerate(rsa):
        for right in rsa[left_index + 1 :]:
            if left["scope"] == right["scope"] and left["n"] != right["n"]:
                finding = _shared_prime_finding(left, right)
                if finding is not None:
                    findings.append(finding)


def _rsa_signature_groups(records):
    groups: dict[tuple[str, int, int, int], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        obj = record["object"]
        n = parse_int(_pick(obj, "n", "modulus"))
        e = parse_int(_pick(obj, "e", "exponent", "public_exponent"))
        signature = parse_int(_pick(obj, "signature", "sig", "s"))
        message = parse_int(_pick(obj, "message_representative", "message_int", "m", "hash_int"))
        if not (n and e) or signature is None or message is None:
            continue
        if 0 <= signature < n:
            groups[(record["scope"], n, e, message % n)].append({**record, "signature": signature})
    return groups


def _crt_fault_partner(correct, faulty, n):
    for candidate in faulty:
        factor = math.gcd(abs(correct["signature"] - candidate["signature"]), n)
        if 1 < factor < n:
            return factor, candidate
    return None


def _crt_fault_finding(correct, bad, n, e, message, recovered):
    p, q = recovered, n // recovered
    return Finding(
        "RSA-CRT-FAULT", "RSA CRT fault factors the signing modulus", "critical", "certain",
        f'{correct["location"]} + {bad["location"]}',
        {"n": str(n), "e": e, "message_representative": str(message), "valid_signature": str(correct["signature"]),
         "faulty_signature": str(bad["signature"]), "p": str(p), "q": str(q), "factorization_verified": p * q == n},
        ["Both values are RSA signatures of the same message representative.", "One signature verifies and the other is faulty."],
        "Compute gcd(valid_signature-faulty_signature, n), derive the private key, then sign the flag request.",
        {"kind": "rsa_crt_fault", "p": str(p), "q": str(q)},
        "Verify CRT signatures before release, harden fault handling, and rotate the factored RSA key."
    )


def _rsa_crt_fault_findings(records, findings):
    # Bellcore/Lenstra CRT fault: one valid and one faulty signature of the same
    # representative factor n through gcd(S-S', n).
    for (_, n, e, message), group in sorted(_rsa_signature_groups(records).items()):
        valid = [item for item in group if pow(item["signature"], e, n) == message]
        faulty = [item for item in group if pow(item["signature"], e, n) != message]
        for correct in valid:
            partner = _crt_fault_partner(correct, faulty, n)
            if partner is not None:
                recovered, bad = partner
                findings.append(_crt_fault_finding(correct, bad, n, e, message, recovered))
                break


def _scan_phase_01(records, rsa, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    _rsa_shared_prime_findings(rsa, findings)
    _rsa_crt_fault_findings(records, findings)



def _leaked_rsa_factor(item):
    n, e = item["n"], item["e"]
    for name in ("p", "q"):
        candidate = item[name]
        if candidate and 1 < candidate < n and n % candidate == 0:
            return candidate, name
    if not e:
        return None, None
    for name in ("dp", "dq"):
        candidate = item[name]
        factor = _factor_from_crt_exponent(n, e, candidate) if candidate and candidate > 0 else None
        if factor:
            return factor, name
    return None, None


def _rsa_from_parameters(item, findings):
    n, e, c = item["n"], item["e"], item["c"]
    factor, leak_kind = _leaked_rsa_factor(item)
    if not factor:
        return
    p, q = factor, n // factor
    evidence: dict[str, Any] = {"n": str(n), "leak": leak_kind, "p": str(p), "q": str(q), "factorization_verified": p * q == n}
    solver: dict[str, Any] = {"kind": "rsa_parameter_leak", "p": str(p), "q": str(q)}
    if e and c is not None and math.gcd(e, (p - 1) * (q - 1)) == 1:
        derived_d = pow(e, -1, (p - 1) * (q - 1))
        message = pow(c, derived_d, n)
        plain = int_to_bytes(message)
        verified = pow(message, e, n) == c
        evidence.update({"d": str(derived_d), "plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace"), "reencryption_verified": verified})
        solver.update({"d": str(derived_d), "result_hex": plain.hex()})
    findings.append(Finding(
        "RSA-PARAMETER-LEAK", "Leaked RSA parameter factors the modulus", "critical", "certain", item["location"],
        evidence, [f"The structured {leak_kind} value belongs to this RSA key."],
        "Use the leaked parameter to factor n, derive the private exponent, and decrypt the flag ciphertext.", solver,
        "Remove private primes and CRT exponents from published artifacts. Rotate the RSA key."
    ))


def _rsa_private_exponent(item, findings):
    n, e, c = item["n"], item["e"], item["c"]
    if item["d"] and e and c is not None and 0 <= c < n:
        message = pow(c, item["d"], n)
        if pow(message, e, n) == c:
            plain = int_to_bytes(message)
            findings.append(Finding(
                "RSA-PRIVATE-EXPONENT-LEAK", "Leaked RSA private exponent decrypts ciphertext", "critical", "certain", item["location"],
                {"n": str(n), "e": e, "d": str(item["d"]), "plaintext_hex": plain.hex(),
                 "plaintext_utf8": plain.decode("utf-8", "replace"), "reencryption_verified": True},
                ["The structured d value belongs to this RSA public modulus and exponent."],
                "Compute m=c^d mod n. Re-encryption with e verifies the recovered plaintext.",
                {"kind": "rsa_private_exponent", "d": str(item["d"]), "result_hex": plain.hex()},
                "Never publish the private exponent. Rotate the exposed RSA key."
            ))


def _rsa_exact_cube(item, findings):
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


def _rsa_wrapped_root(item, findings):
    n, e, c = item["n"], item["e"], item["c"]
    if e in {3, 5, 7, 11, 17} and c is not None and 0 <= c < n:
        # Textbook RSA can still be rooted after modular wraparound when m^e=c+k*n
        # for a small k. The exact modular round trip prevents guessed plaintexts.
        wrap_limits = {3: 10_000, 5: 2_000, 7: 256, 11: 32, 17: 4}
        for multiplier in range(0 if e != 3 else 1, wrap_limits[e] + 1):
            root, exact = integer_nth_root(c + multiplier * n, e)
            if not exact or pow(root, e, n) != c:
                continue
            plain = int_to_bytes(root)
            findings.append(Finding(
                "RSA-LOW-EXPONENT-SMALL-MESSAGE", "Unpadded low-exponent RSA plaintext recovered", "critical", "certain", item["location"],
                {"n": str(n), "e": e, "c": str(c), "wrap_multiplier": multiplier, "m": str(root),
                 "plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace"), "reencryption_verified": True},
                ["Textbook RSA was used without randomized padding.", "The message power wraps the modulus only a bounded number of times."],
                "Find the exact e-th root of c+k*n for bounded k; verify the candidate by modular re-encryption.",
                {"kind": "rsa_low_exponent", "degree": e, "wrap_multiplier": multiplier, "result_int": str(root), "result_hex": plain.hex()},
                "Use RSA-OAEP with a maintained cryptographic library."
            ))
            break


def _rsa_wiener(item, findings):
    n, e, c = item["n"], item["e"], item["c"]
    if e is not None and e > 1:
        recovered = wiener_private_exponent(n, e)
        if recovered:
            d, p, q = recovered
            evidence = {"n": str(n), "e": e, "d": str(d), "p": str(p), "q": str(q)}
            solver: dict[str, Any] = {"kind": "rsa_wiener", "d": str(d), "p": str(p), "q": str(q)}
            if c is not None and 0 <= c < n:
                message = pow(c, d, n)
                plain = int_to_bytes(message)
                evidence.update({"plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace")})
                evidence.update({"c": str(c), "reencryption_verified": pow(message, e, n) == c})
                solver["result_hex"] = plain.hex()
            findings.append(Finding(
                "RSA-WIENER-SMALL-D", "RSA private exponent recovered by Wiener attack", "critical", "certain", item["location"],
                evidence, ["The public key is RSA.", "The private exponent is small enough to occur in convergents of e/n."],
                "Expand e/n as a continued fraction. A convergent yields d and factors n exactly.", solver,
                "Generate RSA keys with a maintained library and reject private exponents below the Wiener bound."
            ))


def _rsa_fermat(item, findings, fermat_steps):
    n, e, c = item["n"], item["e"], item["c"]
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
                evidence.update({"d": str(d), "c": str(c), "plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace"),
                                 "reencryption_verified": pow(m, e, n) == c})
                solver.update({"d": str(d), "result_hex": plain.hex()})
            findings.append(Finding(
                "RSA-FERMAT-CLOSE-PRIMES", "RSA primes are close enough for Fermat factorization", "critical", "certain", item["location"],
                evidence, [f"Fermat search reaches the factors within {fermat_steps} steps."],
                "Write n as a^2-b^2; recover p=a-b and q=a+b, then derive the private key.", solver,
                "Generate independent primes with a CSPRNG and enforce an adequate distance between p and q."
            ))


def _rsa_small_factor(item, findings):
    n, e, c = item["n"], item["e"], item["c"]
    if not item["p"] and not item["q"]:
        factor = small_factor(n)
        if factor:
            p, q = factor, n // factor
            closeness = abs(q - p)
            # Fermat already owns close-prime moduli; report only the weak
            # small-factor case here to avoid a duplicate finding.
            if p * q == n and closeness * closeness >= n:
                evidence = {"n": str(n), "p": str(p), "q": str(q), "factorization_verified": True}
                solver = {"kind": "rsa_small_factor", "p": str(p), "q": str(q)}
                if e and c is not None and math.gcd(e, (p - 1) * (q - 1)) == 1:
                    d = pow(e, -1, (p - 1) * (q - 1))
                    m = pow(c, d, n)
                    plain = int_to_bytes(m)
                    evidence.update({"d": str(d), "c": str(c), "plaintext_hex": plain.hex(),
                                     "plaintext_utf8": plain.decode("utf-8", "replace"),
                                     "reencryption_verified": pow(m, e, n) == c})
                    solver.update({"d": str(d), "result_hex": plain.hex()})
                findings.append(Finding(
                    "RSA-SMALL-FACTOR", "RSA modulus has a recoverable small factor", "critical", "certain", item["location"],
                    evidence, ["The modulus is not a product of two large, independent primes."],
                    "Factor n by trial division and bounded Pollard's rho, derive the private key, then decrypt the flag ciphertext.", solver,
                    "Use two large (>=1024-bit) independent primes from a maintained library; never a smooth or small modulus."
                ))

def _common_modulus_finding(left, right, n):
    g, a, b = extended_gcd(left["e"], right["e"])
    if g != 1:
        return None
    try:
        m = (signed_mod_pow(left["c"], a, n) * signed_mod_pow(right["c"], b, n)) % n
    except ValueError:
        return None
    if pow(m, left["e"], n) != left["c"] or pow(m, right["e"], n) != right["c"]:
        return None
    plain = int_to_bytes(m)
    return Finding(
        "RSA-COMMON-MODULUS", "RSA common-modulus attack recovers plaintext", "critical", "certain",
        f'{left["location"]} + {right["location"]}',
        {"n": str(n), "e1": left["e"], "e2": right["e"], "bezout_a": a, "bezout_b": b, "m": str(m), "plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace"), "reencryption_verified": True},
        ["Both ciphertexts encrypt the same plaintext under the same modulus.", "The public exponents are coprime."],
        "Combine c1^a and c2^b modulo n using Bezout coefficients a and b.",
        {"kind": "rsa_common_modulus", "result_int": str(m), "result_hex": plain.hex()},
        "Never share an RSA modulus between keys. Use randomized OAEP padding."
    )


def _rsa_common_modulus_findings(rsa, findings):
    by_modulus: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for item in rsa:
        if item["e"] is not None and item["c"] is not None:
            by_modulus[(item["scope"], item["n"])].append(item)
    for (_, n), group in sorted(by_modulus.items()):
        for left, right in combinations(group, 2):
            finding = _common_modulus_finding(left, right, n)
            if finding is not None:
                findings.append(finding)


def _scan_phase_02(rsa, findings, fermat_steps):
    """Collect a coherent cryptographic attack family without side effects."""
    for item in rsa:
        _rsa_from_parameters(item, findings)
        _rsa_private_exponent(item, findings)
        _rsa_exact_cube(item, findings)
        _rsa_wrapped_root(item, findings)
        _rsa_wiener(item, findings)
        _rsa_fermat(item, findings, fermat_steps)
        _rsa_small_factor(item, findings)
    _rsa_common_modulus_findings(rsa, findings)



def _hastad_e3_finding(group):
    if len({item["scope"] for item in group}) != 1:
        return None
    if any(math.gcd(left["n"], right["n"]) != 1 for left, right in combinations(group, 2)):
        return None
    combined, product = crt((item["c"], item["n"]) for item in group)
    root, exact = integer_nth_root(combined, 3)
    if not exact:
        return None
    plain = int_to_bytes(root)
    return Finding(
        "RSA-HASTAD-BROADCAST", "Hastad broadcast attack recovers plaintext", "critical", "certain",
        " + ".join(item["location"] for item in group),
        {"e": 3, "moduli": [str(item["n"]) for item in group], "crt_value": str(combined),
         "crt_modulus": str(product), "m": str(root), "plaintext_hex": plain.hex(),
         "plaintext_utf8": plain.decode("utf-8", "replace")},
        ["All three ciphertexts encrypt the same plaintext.", "The moduli are pairwise coprime.", "Textbook RSA uses e=3 without randomized padding."],
        "Combine ciphertexts with CRT, then take the exact integer cube root.",
        {"kind": "rsa_hastad", "result_int": str(root), "result_hex": plain.hex()},
        "Use RSA-OAEP. Never encrypt one raw plaintext under several textbook RSA keys."
    )


def _hastad_general_finding(group, exponent):
    if any(math.gcd(left["n"], right["n"]) != 1 for left, right in combinations(group, 2)):
        return None
    combined, product = crt((item["c"], item["n"]) for item in group)
    root, exact = integer_nth_root(combined, exponent)
    if not exact or any(pow(root, exponent, item["n"]) != item["c"] for item in group):
        return None
    plain = int_to_bytes(root)
    return Finding(
        "RSA-HASTAD-BROADCAST", "Hastad broadcast attack recovers plaintext", "critical", "certain",
        " + ".join(item["location"] for item in group),
        {"e": exponent, "moduli": [str(item["n"]) for item in group], "crt_value": str(combined),
         "crt_modulus": str(product), "m": str(root), "plaintext_hex": plain.hex(),
         "plaintext_utf8": plain.decode("utf-8", "replace"), "reencryption_verified": True},
        [f"All {exponent} ciphertexts encrypt the same plaintext.", "The moduli are pairwise coprime.", "Textbook RSA omits randomized padding."],
        "Combine ciphertexts with CRT, then take the exact integer e-th root.",
        {"kind": "rsa_hastad", "degree": exponent, "result_int": str(root), "result_hex": plain.hex()},
        "Use RSA-OAEP. Never encrypt one raw plaintext under several textbook RSA keys."
    )


def _rsa_hastad_e3_findings(rsa, findings):
    # Hastad broadcast: same small-exponent plaintext under independent moduli.
    e3 = [item for item in rsa if item["e"] == 3 and item["c"] is not None and 0 <= item["c"] < item["n"]]
    for group in combinations(e3, 3):
        finding = _hastad_e3_finding(list(group))
        if finding is not None:
            findings.append(finding)


def _rsa_hastad_general_findings(rsa, findings):
    # Generalized Hastad broadcast for other practical small public exponents.
    broadcast_groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for item in rsa:
        if item["e"] in {5, 7} and item["c"] is not None and 0 <= item["c"] < item["n"]:
            broadcast_groups[(item["scope"], item["e"])].append(item)
    for (_, exponent), candidates in sorted(broadcast_groups.items()):
        for group in islice(combinations(candidates[:32], exponent), 10_000):
            finding = _hastad_general_finding(group, exponent)
            if finding is not None:
                findings.append(finding)
                break


def _scan_phase_03(rsa, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    _rsa_hastad_e3_findings(rsa, findings)
    _rsa_hastad_general_findings(rsa, findings)



def _structured_signatures(records):
    signatures: list[dict[str, Any]] = []
    for record in records:
        obj = record["object"]
        r = parse_int(_pick(obj, "r"))
        s = parse_int(_pick(obj, "s"))
        z = parse_int(_pick(obj, "z", "hash", "message_hash", "h"))
        q = parse_int(_pick(obj, "q", "order", "curve_order", "n_order"))
        if any(value is None for value in (r, s, z, q)):
            continue
        if q > 2 and 0 < r < q and 0 < s < q:
            signatures.append({**record, "r": r, "s": s, "z": z, "q": q})
    return signatures


def _nonce_reuse_finding(left, right, q, r):
    if left["s"] == right["s"] or left["z"] == right["z"]:
        return None
    try:
        nonce = ((left["z"] - right["z"]) * pow((left["s"] - right["s"]) % q, -1, q)) % q
        private = ((left["s"] * nonce - left["z"]) * pow(r, -1, q)) % q
    except ValueError:
        return None
    if (left["s"] * nonce - left["z"] - r * private) % q != 0 or (right["s"] * nonce - right["z"] - r * private) % q != 0:
        return None
    return Finding(
        "SIGNATURE-NONCE-REUSE", "DSA/ECDSA nonce reuse exposes private key", "critical", "certain",
        f'{left["location"]} + {right["location"]}',
        {"q": str(q), "r": str(r), "nonce_k": str(nonce), "private_key_x": str(private),
         "z1": str(left["z"]), "s1": str(left["s"]), "z2": str(right["z"]), "s2": str(right["s"])},
        ["Both signatures use the same group order and r value.", "The recorded hashes are the signed message integers."],
        "Compute k=(z1-z2)/(s1-s2) mod q, then x=(s1*k-z1)/r mod q. Use x to sign the flag request.",
        {"kind": "signature_nonce_reuse", "nonce_k": str(nonce), "private_key_x": str(private)},
        "Use deterministic RFC 6979 nonces or a CSPRNG and reject repeated r values."
    )


def _nonce_disclosure_finding(item):
    nonce = parse_int(_pick(item["object"], "k", "nonce", "signature_nonce"))
    if nonce is None or not 0 < nonce < item["q"]:
        return None
    try:
        private = ((item["s"] * nonce - item["z"]) * pow(item["r"], -1, item["q"])) % item["q"]
    except ValueError:
        return None
    if (item["s"] * nonce - item["z"] - item["r"] * private) % item["q"] != 0:
        return None
    return Finding(
        "SIGNATURE-NONCE-DISCLOSURE", "Disclosed DSA/ECDSA nonce exposes private key", "critical", "certain", item["location"],
        {"q": str(item["q"]), "r": str(item["r"]), "s": str(item["s"]), "z": str(item["z"]),
         "nonce_k": str(nonce), "private_key_x": str(private), "signature_equation_verified": True},
        ["The structured k or nonce value belongs to this signature."],
        "Compute x=(s*k-z)/r mod q, then use the recovered key in the challenge's flag-signing path.",
        {"kind": "signature_nonce_disclosure", "nonce_k": str(nonce), "private_key_x": str(private)},
        "Never disclose signature nonces. Use deterministic RFC 6979 nonces and rotate the exposed private key."
    )


def _scan_phase_04(records, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    # Reused DSA/ECDSA nonce: equal r exposes k and private key x.
    signatures = _structured_signatures(records)
    by_signature: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    for item in signatures:
        by_signature[(item["scope"], item["q"], item["r"])].append(item)
    for (_, q, r), group in sorted(by_signature.items()):
        for left, right in combinations(group, 2):
            finding = _nonce_reuse_finding(left, right, q, r)
            if finding is not None:
                findings.append(finding)
    # A disclosed DSA/ECDSA nonce is sufficient for exact private-key recovery.
    for item in signatures:
        finding = _nonce_disclosure_finding(item)
        if finding is not None:
            findings.append(finding)



def _sha1_length_extension_finding(record):
    obj = record["object"]
    algorithm = str(_pick(obj, "algorithm", "hash", "digest_algorithm", "mac_algorithm") or "").casefold().replace("-", "")
    digest = parse_bytes(_pick(obj, "digest", "mac", "signature", "tag"))
    message = _bytes_or_text(_pick(obj, "message", "data", "original_message"))
    suffix = _bytes_or_text(_pick(obj, "append", "suffix", "extension", "additional_data"))
    secret_length = parse_int(_pick(obj, "secret_length", "key_length", "prefix_length"))
    if algorithm != "sha1" or any(value is None for value in (digest, message, suffix, secret_length)):
        return None
    extended = _sha1_length_extend(digest, message, secret_length, suffix)
    if not extended:
        return None
    forged_message, forged_digest = extended
    return Finding(
        "SHA1-LENGTH-EXTENSION", "SHA-1 secret-prefix MAC extension calculated", "critical", "certain", record["location"],
        {"algorithm": "sha1", "digest_hex": digest.hex(), "message_hex": message.hex(), "suffix_hex": suffix.hex(),
         "secret_length": secret_length, "forged_message_hex": forged_message.hex(), "forged_digest_hex": forged_digest.hex(),
         "compression_calculated": True},
        ["The verifier computes SHA1(secret || message).", "The supplied secret length is correct.", "The parser accepts SHA-1 glue padding in the message."],
        "Submit forged_message_hex with forged_digest_hex. The digest continues from the published SHA-1 state without knowing the secret.",
        {"kind": "sha1_length_extension", "message_hex": forged_message.hex(), "digest_hex": forged_digest.hex()},
        "Replace the secret-prefix digest with HMAC-SHA-256 and compare tags in constant time."
    )


def _structured_int_outputs(obj):
    raw_outputs = _pick(obj, "outputs", "states", "samples", "sequence")
    if not isinstance(raw_outputs, list):
        return None
    outputs = [parse_int(value) for value in raw_outputs]
    return None if any(value is None for value in outputs) else outputs


def _lcg_finding(record):
    obj = record["object"]
    outputs = _structured_int_outputs(obj)
    if outputs is None:
        return None
    explicit_modulus = parse_int(_pick(obj, "modulus", "m"))
    recovered = _recover_lcg(outputs, explicit_modulus)
    if not recovered:
        return None
    modulus, multiplier, increment = recovered
    next_value = (multiplier * outputs[-1] + increment) % modulus
    return Finding(
        "LCG-STATE-RECOVERY", "Linear congruential generator state recovered", "high",
        "certain" if explicit_modulus == modulus else "high", record["location"],
        {"outputs": outputs, "modulus": str(modulus), "multiplier": str(multiplier), "increment": str(increment),
         "next_output": str(next_value), "recurrence_verified": True, "modulus_was_explicit": explicit_modulus is not None},
        ["The ordered values are consecutive LCG outputs.", "A derived modulus can be a multiple of the implementation modulus; validate the prediction."],
        "Recover the recurrence from output differences, then predict the next value used for the flag key or token.",
        {"kind": "lcg_recovery", "modulus": str(modulus), "multiplier": str(multiplier), "increment": str(increment), "next_output": str(next_value)},
        "Use an operating-system CSPRNG for secret keys, nonces, and tokens."
    )


def _scan_phase_05(records, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    # Exact SHA-1 secret-prefix length-extension vector when all public inputs and
    # the candidate secret length are structured. The original secret is not needed.
    for builder in (_sha1_length_extension_finding, _lcg_finding):
        for record in records:
            finding = builder(record)
            if finding is not None:
                findings.append(finding)



def _scan_phase_06(records, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    # Full-output MT19937 state cloning. Require an explicit generator label to
    # avoid interpreting arbitrary integer arrays as PRNG state.
    for record in records:
        obj = record["object"]
        generator = str(_pick(obj, "generator", "prng", "algorithm", "type") or "").casefold().replace("-", "")
        raw_outputs = _pick(obj, "outputs", "states", "samples", "sequence")
        if generator not in {"mt19937", "mersennetwister", "pythonrandom"} or not isinstance(raw_outputs, list):
            continue
        outputs = [parse_int(value) for value in raw_outputs]
        if any(value is None for value in outputs):
            continue
        cloned = _clone_mt19937(outputs)
        if not cloned:
            continue
        predicted, verified = cloned
        evidence: dict[str, Any] = {"generator": generator, "observed_outputs": 624,
                                    "state_roundtrip_verified": verified, "predicted_next": str(predicted)}
        if len(outputs) >= 625:
            evidence["observed_next"] = str(outputs[624])
            evidence["prediction_verified"] = predicted == outputs[624]
            if predicted != outputs[624]:
                continue
        findings.append(Finding(
            "MT19937-STATE-CLONE", "MT19937 internal state cloned from outputs", "critical", "certain", record["location"],
            evidence,
            ["The values are consecutive, complete 32-bit MT19937 outputs with no skipped draws."],
            "Restore the recovered 624-word state and predict the next value used for the flag key or token.",
            {"kind": "mt19937_clone", "predicted_next": str(predicted)},
            "Use an operating-system CSPRNG for keys, tokens, nonces, and other secrets."
        ))



def _dh_degenerate_finding(record, p, g):
    return Finding(
        "DH-DEGENERATE-GENERATOR", "Degenerate Diffie-Hellman generator", "critical", "certain", record["location"],
        {"p": str(p), "g": str(g), "g_mod_p": str(g % p)},
        ["The structured parameters are finite-field Diffie-Hellman."],
        "Enumerate the tiny set of possible shared secrets produced by g=0, 1, or -1 modulo p.",
        {"kind": "dh_degenerate_generator", "candidate_shared_secrets": ["0", "1", str(p - 1)]},
        "Use a standardized safe-prime group and validate the peer public key and generator."
    )


def _dh_small_group_finding(record, p, g, public, peer):
    private = discrete_log_bsgs(g % p, public % p, p)
    if private is None:
        return None
    evidence: dict[str, Any] = {"p": str(p), "g": str(g), "public": str(public), "private_exponent": str(private),
                                "discrete_log_verified": pow(g, private, p) == public % p}
    solver: dict[str, Any] = {"kind": "dh_small_group", "private_exponent": str(private)}
    if peer is not None:
        shared = pow(peer, private, p)
        evidence["shared_secret"] = str(shared)
        solver["shared_secret"] = str(shared)
    return Finding(
        "DH-SMALL-GROUP", "Diffie-Hellman discrete log recovered", "critical", "certain", record["location"],
        evidence, ["The structured values are finite-field Diffie-Hellman parameters and public keys.", "The group is within the bounded BSGS limit."],
        "Solve the discrete logarithm with baby-step giant-step, then derive the shared secret and flag encryption key.", solver,
        "Use a standardized group of at least 2048 bits or X25519 and validate peer keys."
    )


def _dh_finding(record):
    obj = record["object"]
    algorithm = str(_pick(obj, "algorithm", "mode", "scheme", "type") or "").casefold()
    p = parse_int(_pick(obj, "p", "prime", "modulus"))
    g = parse_int(_pick(obj, "g", "generator"))
    public_a = parse_int(_pick(obj, "public_a", "alice_public", "a_pub", "a"))
    public_b = parse_int(_pick(obj, "public_b", "bob_public", "b_pub", "b"))
    finite_field_dh = "diffie" in algorithm or algorithm in {"dh", "ffdhe", "finite-field-dh"}
    if not finite_field_dh or "ecdh" in algorithm or p is None or g is None or p <= 3:
        return None
    if g % p in (0, 1, p - 1):
        return _dh_degenerate_finding(record, p, g)
    if public_a is not None:
        return _dh_small_group_finding(record, p, g, public_a, public_b)
    if public_b is not None:
        return _dh_small_group_finding(record, p, g, public_b, public_a)
    return None


def _scan_phase_07(records, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    # Structured finite-field Diffie-Hellman only; generic p/q records are ignored.
    for record in records:
        finding = _dh_finding(record)
        if finding is not None:
            findings.append(finding)



def _scan_phase_08(records, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    # Calculated CBC first-block bit flip, emitted only with explicit known and target plaintext.
    for record in records:
        obj = record["object"]
        mode = str(_pick(obj, "mode", "algorithm", "alg") or "").casefold()
        if "cbc" not in mode or _pick(obj, "authenticated", "aead") is True:
            continue
        iv = parse_bytes(_pick(obj, "iv"))
        cipher = parse_bytes(_pick(obj, "ciphertext", "ct"))
        known_raw = _pick(obj, "known_plaintext", "known_plain", "plaintext")
        target_raw = _pick(obj, "target_plaintext", "desired_plaintext", "target_plain")
        known = parse_bytes(known_raw) or (known_raw.encode() if isinstance(known_raw, str) else None)
        target = parse_bytes(target_raw) or (target_raw.encode() if isinstance(target_raw, str) else None)
        if not iv or not cipher or not known or not target or len(iv) != 16 or len(known) < 16 or len(target) < 16:
            continue
        modified_iv = bytes(iv[i] ^ known[i] ^ target[i] for i in range(16))
        findings.append(Finding(
            "CBC-FIRST-BLOCK-BITFLIP", "CBC first-block bit-flip vector calculated", "high", "high", record["location"],
            {"iv_hex": iv.hex(), "modified_iv_hex": modified_iv.hex(), "known_block_hex": known[:16].hex(),
             "target_block_hex": target[:16].hex(), "ciphertext_prefix_hex": cipher[:16].hex()},
            ["The receiver decrypts unauthenticated CBC.", "The supplied known plaintext matches the first ciphertext block.", "The target block has the same length."],
            "Replace the transmitted IV with modified_iv while keeping the ciphertext. CBC decryption changes the first block to the target.",
            {"kind": "cbc_bitflip", "modified_iv_hex": modified_iv.hex(), "ciphertext_hex": cipher.hex()},
            "Use an AEAD mode and reject messages whose authentication tag fails."
        ))



def _single_byte_xor_finding(record):
    data = record["bytes"]
    candidates = []
    for key in range(256):
        plain = bytes(byte ^ key for byte in data)
        candidates.append((_single_byte_score(plain), key, plain))
    score, key, plain = max(candidates, key=lambda row: (row[0], -row[1]))
    printable_ratio = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in plain) / len(plain)
    runner_up = sorted(candidates, key=lambda row: row[0], reverse=True)[1][0]
    flag_shape = bool(re.search(rb"(?:flag|ctf|key)\{[^\r\n]{1,200}\}", plain, re.IGNORECASE))
    confident = flag_shape or (score >= 1.20 and score - runner_up >= 0.18)
    if key == 0 or len(data) < 6 or printable_ratio < 0.90 or not confident:
        return None
    return Finding(
        "XOR-SINGLE-BYTE", "Single-byte XOR key is recoverable", "high", "certain" if flag_shape else "high", f'{record["location"]}.{record["field"]}',
        {"key_hex": f"{key:02x}", "score": round(score, 4), "score_margin": round(score - runner_up, 4),
         "printable_ratio": round(printable_ratio, 4), "flag_shape": flag_shape,
         "plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace"),
         "roundtrip_verified": bytes(value ^ key for value in plain) == data,
         "input_encoding": record["input_encoding"], "encoded_input": record["encoded_input"]},
        ["Ciphertext represents repeated single-byte XOR.", "Plaintext resembles printable CTF text."],
        "Try all 256 keys and rank decoded text. The highest-scoring key and plaintext are included.",
        {"kind": "xor_single_byte", "key": key, "result_hex": plain.hex()},
        "Replace XOR obfuscation with authenticated encryption and a unique nonce."
    )


def _repeating_xor_finding(record):
    data = record["bytes"]
    repeating = _repeating_xor_candidate(data)
    if not repeating:
        return None
    repeated_key, repeated_plain, repeated_score = repeating
    return Finding(
        "XOR-REPEATING-KEY", "Repeating-key XOR plaintext recovered", "high", "high",
        f'{record["location"]}.{record["field"]}',
        {"key_hex": repeated_key.hex(), "key_length": len(repeated_key), "score": round(repeated_score, 4),
         "plaintext_hex": repeated_plain.hex(), "plaintext_utf8": repeated_plain.decode("utf-8", "replace"),
         "flag_shape": True,
         "roundtrip_verified": bytes(value ^ repeated_key[index % len(repeated_key)] for index, value in enumerate(repeated_plain)) == data,
         "input_encoding": record["input_encoding"], "encoded_input": record["encoded_input"]},
        ["Ciphertext uses a short repeating XOR key.", "Recovered plaintext contains a CTF flag-shaped token and is at least 90% printable."],
        "Transpose ciphertext by candidate key length, solve each column, and repeat the recovered key across the ciphertext.",
        {"kind": "xor_repeating_key", "key_hex": repeated_key.hex(), "result_hex": repeated_plain.hex()},
        "Use authenticated encryption with a random key and a unique nonce."
    )


def _ecb_repetition_finding(record):
    data = record["bytes"]
    for block_size in (16, 8):
        blocks = [data[i:i + block_size] for i in range(0, len(data) - block_size + 1, block_size)]
        counts = Counter(blocks)
        repeats = {block.hex(): count for block, count in counts.items() if count > 1}
        if repeats:
            return Finding(
                "BLOCK-ECB-REPETITION", "Repeated ciphertext blocks indicate ECB", "high", "high", f'{record["location"]}.{record["field"]}',
                {"block_size": block_size, "repeated_blocks": dict(sorted(repeats.items()))},
                ["Ciphertext is aligned to the reported block size.", "Repeated plaintext blocks map to repeated ciphertext blocks."],
                "Use repeated blocks to infer structure, align controlled input, and mount byte-at-a-time ECB recovery when an oracle exists.",
                {"kind": "ecb_repetition", "block_size": block_size, "repeat_count": sum(repeats.values())},
                "Use an AEAD mode such as AES-GCM or ChaCha20-Poly1305 with a unique nonce."
            )
    return None


def _scan_phase_09(byte_records, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    # Byte-level attacks.
    for record in byte_records:
        for builder in (_single_byte_xor_finding, _repeating_xor_finding, _ecb_repetition_finding):
            finding = builder(record)
            if finding is not None:
                findings.append(finding)



def _scan_phase_10(byte_records, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    stream_records = [item for item in byte_records if any(token in item["field"].casefold() for token in ("xor", "stream", "otp"))]
    for i, left in enumerate(stream_records[:512]):
        for right in stream_records[i + 1:512]:
            if left["scope"] != right["scope"]:
                continue
            if left["bytes"] == right["bytes"]:
                continue
            length = min(len(left["bytes"]), len(right["bytes"]))
            xored = bytes(a ^ b for a, b in zip(left["bytes"][:length], right["bytes"][:length], strict=False))
            # Space-letter pattern is useful evidence for reused stream keystreams.
            alpha_positions = [idx for idx, b in enumerate(xored) if chr(b ^ 0x20).isalpha()]
            if length >= 8 and len(alpha_positions) / length >= 0.35:
                findings.append(Finding(
                    "XOR-KEYSTREAM-REUSE", "Ciphertexts likely reuse an XOR keystream", "high", "medium",
                    f'{left["location"]}.{left["field"]} + {right["location"]}.{right["field"]}',
                    {"xor_hex": xored.hex(), "length": length, "space_letter_positions": alpha_positions},
                    ["Field names identify both values as stream, OTP, or XOR ciphertexts.", "Both values align at offset zero.", "Natural-language plaintext contains spaces."],
                    "C1 xor C2 removes the keystream. Crib-drag likely words to recover both plaintexts and the reused keystream.",
                    {"kind": "xor_crib_drag", "combined_hex": xored.hex()},
                    "Generate a unique nonce for every encryption under a key and reject nonce reuse."
                ))



def _stream_nonce_groups(records):
    nonce_groups: dict[tuple[str, str, bytes], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        obj = record["object"]
        nonce = parse_bytes(_pick(obj, "nonce", "iv"))
        cipher = parse_bytes(_pick(obj, "ciphertext", "ct", "encrypted"))
        mode = str(_pick(obj, "mode", "algorithm", "alg") or "").casefold()
        explicit_key_id = _pick(obj, "key_id", "kid", "keyid")
        key_id = str(explicit_key_id or "unknown-key")
        if nonce and cipher and any(token in mode for token in ("ctr", "gcm", "chacha")):
            known = _bytes_or_text(_pick(obj, "known_plaintext", "plaintext", "known_plain"))
            nonce_groups[(record["scope"], key_id, nonce)].append({**record, "nonce": nonce, "cipher": cipher, "mode": mode, "known": known})
    return nonce_groups


def _known_plaintext_recovery(left, right):
    for known_side, target_side in ((left, right), (right, left)):
        known = known_side.get("known")
        target_length = len(target_side["cipher"])
        if not known or len(known) < target_length or len(known_side["cipher"]) < target_length:
            continue
        keystream = bytes(a ^ b for a, b in zip(known_side["cipher"], known, strict=False))
        recovered = bytes(a ^ b for a, b in zip(target_side["cipher"], keystream, strict=False))
        roundtrip = bytes(a ^ b for a, b in zip(known[:target_length], keystream, strict=False)) == known_side["cipher"][:target_length]
        return {"known_plaintext_hex": known[:target_length].hex(),
                "recovered_plaintext_hex": recovered.hex(), "known_plaintext_roundtrip_verified": roundtrip}, recovered
    return None


def _stream_nonce_reuse_finding(left, right, key_id, nonce):
    length = min(len(left["cipher"]), len(right["cipher"]))
    combined = bytes(a ^ b for a, b in zip(left["cipher"][:length], right["cipher"][:length], strict=False))
    is_gcm = "gcm" in left["mode"] or "gcm" in right["mode"]
    rule = "GCM-NONCE-REUSE" if is_gcm else "CTR-NONCE-REUSE"
    evidence: dict[str, Any] = {"key_id": key_id, "nonce_hex": nonce.hex(), "ciphertexts_xor_hex": combined.hex()}
    solver: dict[str, Any] = {"kind": "nonce_reuse", "mode": "gcm" if is_gcm else "ctr", "combined_hex": combined.hex()}
    recovery = _known_plaintext_recovery(left, right)
    if recovery is not None:
        evidence.update(recovery[0])
        solver["result_hex"] = recovery[1].hex()
    known_key = key_id != "unknown-key"
    if known_key:
        preconditions = ["Records use the same explicit key identifier and nonce.", "Ciphertexts start at the same stream offset."]
    else:
        preconditions = ["Records use the same nonce and mode, but omit a key identifier.", "Confirm both records use the same key."]
    if is_gcm:
        attack = "XOR ciphertexts to cancel the keystream; crib-drag the result. GCM reuse may also permit authentication forgeries."
    else:
        attack = "XOR ciphertexts to cancel the keystream, then crib-drag known flag and message formats."
    return Finding(
        rule, f'{"GCM" if is_gcm else "CTR/stream"} nonce reuse', "critical", "certain" if known_key else "medium",
        f'{left["location"]} + {right["location"]}',
        evidence, preconditions, attack, solver,
        "Allocate nonces atomically per key, persist the counter, and reject duplicates before encryption."
    )


def _scan_phase_11(records, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    # Explicit nonce reuse in structured records.
    nonce_groups = _stream_nonce_groups(records)
    for (_, key_id, nonce), group in sorted(nonce_groups.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])):
        for left, right in combinations(group, 2):
            findings.append(_stream_nonce_reuse_finding(left, right, key_id, nonce))



def _scan_phase_12(records, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    # Reusing a CBC IV under one explicit key leaks equality of first plaintext
    # blocks. This is diagnosis only: IV reuse alone does not decrypt a flag.
    cbc_groups: dict[tuple[str, str, bytes], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        obj = record["object"]
        mode = str(_pick(obj, "mode", "algorithm", "alg") or "").casefold()
        key_id = _pick(obj, "key_id", "kid", "keyid")
        iv = parse_bytes(_pick(obj, "iv"))
        cipher = parse_bytes(_pick(obj, "ciphertext", "ct", "encrypted"))
        if "cbc" in mode and key_id is not None and iv and cipher and len(iv) in {8, 16}:
            cbc_groups[(record["scope"], str(key_id), iv)].append({**record, "cipher": cipher})
    for (_, key_id, iv), group in sorted(cbc_groups.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])):
        distinct = {item["cipher"] for item in group}
        if len(distinct) < 2:
            continue
        findings.append(Finding(
            "CBC-IV-REUSE", "CBC IV reused under the same key", "medium", "certain",
            " + ".join(item["location"] for item in group[:8]),
            {"key_id": key_id, "iv_hex": iv.hex(), "ciphertext_count": len(distinct),
             "first_blocks_hex": sorted({item["cipher"][:len(iv)].hex() for item in group})},
            ["The records share an explicit key identifier and IV."],
            "Compare first ciphertext blocks to detect equal first plaintext blocks. Combine only with a separate oracle or known-plaintext flaw.",
            {"kind": "cbc_iv_reuse", "iv_hex": iv.hex()},
            "Generate an unpredictable fresh IV for every CBC encryption, or migrate to an AEAD mode with unique nonces."
        ))



def _scan_phase_13(documents, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    findings.extend(_source_findings(documents))
    for document in documents:
        if parse_python(document) is None:
            continue
        for line in unused_validation_flags(document.text):
            excerpt = document.text.splitlines()[line - 1].strip()[:200]
            findings.append(Finding(
                rule="AEAD-AUTH-RESULT-IGNORED",
                title="Cryptographic authentication status is not checked",
                severity="critical",
                confidence="medium",
                location=f"{document.path}:{line}",
                evidence={"line": excerpt},
                preconditions=[
                    "The second value is an authentication result from authenticated decryption.",
                    "Untrusted ciphertext reaches this code path.",
                ],
                attack="A code path may process unauthenticated plaintext if the status is ignored.",
                solver={"kind": "source_guidance", "matched_pattern": "AEAD-AUTH-RESULT-IGNORED"},
                patch="Reject unauthenticated ciphertext before parsing or using its plaintext.",
                playbook=[
                    "Confirm the function returns both plaintext and an authentication result.",
                    "Check the call path and ensure invalid authentication is rejected.",
                ],
            ))

    for document in documents:
        if parse_python(document) is not None:
            for line in counter_overlap_lines(document.text):
                findings.append(Finding(
                    "GCM-COUNTER-OVERLAP",
                    "Custom GCM reuses the initial counter for data and tag masking",
                    "critical", "high", f"{document.path}:{line}",
                    {"line": document.text.splitlines()[line - 1].strip()},
                    ["The custom GCM uses standard GHASH arithmetic.",
                     "A fresh ciphertext, tag and exact known plaintext are available."],
                    "Recover counter-mask and GHASH parameters from known data.",
                    {"kind": "gcm_counter_overlap"},
                    "Use separate GCM counter blocks and a maintained AEAD implementation."
                ))

    overlap_files = {
        document.path for document in documents
        if parse_python(document) is not None
        and counter_overlap_lines(document.text)
    }
    if overlap_files:
        findings = [
            item for item in findings
            if not (item.rule == "CIPHER-ECB"
                    and item.location.rsplit(":", 1)[0] in overlap_files)
        ]



def _scan_phase_14(documents, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    for context in recognize_weak_mlwe_ring(documents):
        findings.append(Finding(
            rule="MLWE-REDUCIBLE-RING-QUOTIENT",
            title="MLWE distinguisher possible through polynomial evaluation at x=1",
            severity="high",
            confidence="high",
            location=f"{context.path}:{context.line}",
            evidence={
                "q": context.modulus, "polynomial_rank": context.rank,
                "matrix_rows": context.rows, "matrix_columns": context.columns,
                "eta": context.eta, "ring_root": 1,
            },
            preconditions=[
                "The quotient modulus has factor x-1, so evaluation at 1 is a homomorphism.",
                "Small secret and error polynomials are sampled as recognized in source.",
                "The supplied matrix and vector use the same parameters and ring.",
            ],
            attack=(
                "Project A and t at x=1, then distinguish a short LWE residual "
                "from a uniformly sampled vector using a lattice."
            ),
            solver={"kind": "mlwe_x1_lattice", "source_verified": True},
            patch="Use a properly designed MLWE polynomial ring and established lattice cryptography parameters.",
            playbook=[
                "Read q, k, l, N and eta from the analyzed Sage source.",
                "Decode the observed matrix/vector samples (bounded gzip/base64).",
                "Project each polynomial at x=1 modulo q.",
                "Apply LLL and Babai nearest-plane to recover a short residual.",
                "Check the modular relation and classify a short residual as MLWE.",
            ],
        ))



def _scan_phase_15(records, ntru_contexts, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    for context in ntru_contexts:
        matched_pairs = pair_ntru_records(records, context)
        if not matched_pairs:
            findings.append(Finding(
                rule="NTRU-POLYNOMIAL-RING",
                title="NTRU sparse-polynomial encryption recognized; ciphertext is not XOR byte data",
                severity="low",
                confidence="high",
                location=f"{context.path}:{context.line}",
                evidence={
                    "n": context.degree, "p": context.plaintext_modulus,
                    "q": context.ciphertext_modulus,
                    "df": context.f_weight, "dg": context.g_weight,
                    "dr": context.r_weight,
                },
                preconditions=["The source constructs an NTRU public key and ciphertext in a quotient polynomial ring."],
                attack="Inspect coefficient vectors and test source-derived algebraic relations; do not apply byte XOR.",
                solver={"kind": "ntru_source_guidance"},
                patch="Review NTRU parameter selection and the intended polynomial-ring security assumptions.",
                playbook=["Provide the matching public polynomial and ciphertext coefficients.",
                          "Analyze quotient-ring projections or a specialized NTRU lattice attack."],
            ))
        for public, ciphertext in matched_pairs:
            try:
                projection = analyze_ntru_vectors(public["value"], ciphertext["value"], context)
            except ValueError:
                continue
            findings.append(Finding(
                rule="NTRU-X1-HAMMING-LEAK",
                title="NTRU polynomial evaluation at x=1 leaks plaintext Hamming weight modulo q",
                severity="medium",
                confidence="high" if projection.public_relation_verified else "low",
                location=f"{ciphertext['record']['location']}.ct",
                evidence={
                    "source_path": context.path,
                    "n": context.degree, "p": context.plaintext_modulus,
                    "q": context.ciphertext_modulus,
                    "public_at_one": projection.public_evaluation,
                    "expected_public_at_one": projection.expected_public_evaluation,
                    "ciphertext_at_one": projection.ciphertext_evaluation,
                    "message_weight_mod_q": projection.message_weight_residue,
                    "possible_message_weights": list(projection.possible_weights),
                    "public_relation_verified": projection.public_relation_verified,
                },
                preconditions=[
                    "NTRU ciphertext c = p*h*r + m in the ring Z_q[x]/(x^n-1).",
                    "Public key h = g/f and f,g,r have the observed fixed numbers of unit coefficients.",
                    "Plaintext is encoded as a binary polynomial.",
                ],
                attack="Evaluate c and h at x=1 and infer sum(m_i) modulo q; this alone does not recover the message.",
                solver={
                    "kind": "ntru_x1_projection",
                    "message_weight_mod_q": projection.message_weight_residue,
                    "possible_message_weights": list(projection.possible_weights),
                },
                patch="Do not use ad-hoc sparse-polynomial NTRU parameters without proven security.",
                playbook=[
                    "Verify public-key evaluation matches g(1)/f(1) modulo q.",
                    "Calculate sum(c) - p*sum(h)*dr modulo q.",
                    "Treat the result as a limited Hamming-weight leak, not plaintext recovery.",
                ],
            ))



def _scan_phase_16(documents, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    for context in recognize_linear_hash(documents):
        try:
            result = solve_linear_hash(documents, context)
            recovered = list(result.recovered)
            verified = result.verified and len(recovered) == 1
            findings.append(Finding(
                rule="LINEAR-HASH-SMALL-ALPHABET",
                title="Modular matrix hash over a truncated small-alphabet encoding",
                severity="critical" if verified else "high",
                confidence="high",
                location=f"{context.path}:{context.line}",
                evidence={
                    "modulus": context.modulus, "rows": context.rows,
                    "columns": context.columns, "alphabet": list(context.alphabet),
                    "modular_rank": result.modular_rank,
                    "free_variables": result.free_variables,
                    "small_vector_solutions": result.alphabet_solutions,
                    "candidate_count": len(recovered),
                    "unique_flag_verified": verified,
                    "recovered_flag": recovered[0] if verified else None,
                },
                preconditions=[
                    "The matrix, hash and small-alphabet serializer originate from one source scope.",
                    "Unit-pivot elimination over the declared modulus is applicable.",
                    "The source-defined padded-XOR encoding and flag syntax match the recovered vector.",
                ],
                attack=(
                    "Invert the modular matrix under bounded small-alphabet constraints, "
                    "reverse the truncated radix expansion and verify each source-defined candidate."
                ),
                solver={
                    "kind": "modular_small_alphabet",
                    "candidates": recovered[:20],
                    **({"result_hex": recovered[0].encode().hex()} if verified else {}),
                },
                patch="Use a cryptographic hash rather than a reversible modular matrix encoding.",
                playbook=[
                    "Load the matching matrix and digest from the challenge files.",
                    "Reduce the linear system with invertible pivots modulo n.",
                    "Enumerate bounded free variables in the inferred alphabet.",
                    "Invert the source's radix encoding and validate candidate format and digest.",
                ],
            ))
        except (ValueError, OverflowError, TypeError) as exc:
            findings.append(Finding(
                rule="LINEAR-HASH-SMALL-ALPHABET",
                title="Modular small-alphabet matrix hash detected; recovery incomplete",
                severity="medium", confidence="medium",
                location=f"{context.path}:{context.line}",
                evidence={"modulus": context.modulus, "rows": context.rows,
                          "columns": context.columns, "reason": str(exc)},
                preconditions=["Provide a matching matrix and output, or reduce the free-variable search bound."],
                attack="Solve the bounded modular system, then invert its radix encoding.",
                solver={"kind": "source_guidance"},
                patch="Use a cryptographic hash instead of a linear encoding.",
            ))



def _scan_phase_17(documents, findings):
    """Collect a coherent cryptographic attack family without side effects."""
    # A source-proven PKCS#1 v1.5 padding oracle with a transcript of
    # positive blinded ciphertexts is an offline hidden-number problem.
    # Do not run a potentially expensive lattice reduction during scanning.
    for oracle in discover_positive_padding_oracles(documents):
        findings.append(Finding(
            rule="RSA-PKCS1-V15-POSITIVE-PADDING-LEAK",
            title="PKCS#1 v1.5 padding oracle positive transcripts constrain RSA plaintext",
            severity="critical",
            confidence="high",
            location=f"{oracle.source_path}:{oracle.source_line}",
            evidence={
                "n_bits": oracle.modulus.bit_length(),
                "public_exponent": oracle.exponent,
                "positive_multiplier_count": len(oracle.positive_multipliers),
                "ciphertext_hex": format(oracle.ciphertext, "x"),
                "source_verified": True,
            },
            preconditions=[
                "The verifier reports PKCS#1 v1.5 decryption success via a sentinel.",
                "The source asserts each published multiplier produces a valid padded blinded ciphertext.",
                "The supplied ciphertext, positive multipliers and public key share one RSA key.",
            ],
            attack=(
                "Each known-positive multiplier restricts the decrypted integer to "
                "the PKCS#1 00 02 interval; solve the simultaneous modular "
                "inequalities by lattice reduction and verify by RSA re-encryption."
            ),
            solver={"kind": "rsa_pkcs1_positive_padding_lattice",
                    "sample_count": len(oracle.positive_multipliers)},
            patch="Replace PKCS#1 v1.5 encryption with RSA-OAEP; remove decryption validity oracles.",
            playbook=[
                "Parse the matching public key, ciphertext and positive multipliers.",
                "Translate the known-positive oracle outputs into modular intervals.",
                "Use a bounded LLL/Kannan embedding offline.",
                "Require byte-correct PKCS#1 padding, all interval checks and exact RSA re-encryption.",
            ],
        ))



def scan(documents: list[Document], fermat_steps: int = 100_000) -> list[Finding]:
    records = _records(documents)
    ntru_contexts = recognize_ntru(documents)
    rsa = _rsa_records(records)
    byte_records = _bytes_records(records, ntru_contexts)
    findings: list[Finding] = []

    _scan_phase_01(records, rsa, findings)
    _scan_phase_02(rsa, findings, fermat_steps)
    _scan_phase_03(rsa, findings)
    _scan_phase_04(records, findings)
    _scan_phase_05(records, findings)
    _scan_phase_06(records, findings)
    _scan_phase_07(records, findings)
    _scan_phase_08(records, findings)
    _scan_phase_09(byte_records, findings)
    _scan_phase_10(byte_records, findings)
    _scan_phase_11(records, findings)
    _scan_phase_12(records, findings)
    _scan_phase_13(documents, findings)
    _scan_phase_14(documents, findings)
    _scan_phase_15(records, ntru_contexts, findings)
    _scan_phase_16(documents, findings)
    _scan_phase_17(documents, findings)
    findings.extend(_related_key_findings(documents))
    findings.extend(_rotated_rsa_findings(documents))
    unique = {finding.id: finding for finding in findings}
    return sorted(unique.values(), key=lambda finding: (finding.location.casefold(), finding.rule, finding.id))


_SOURCE_PLAYBOOKS: dict[str, list[str]] = {
    "NONCE-CONSTANT": [
        "Confirm the nonce/IV is identical across every ciphertext the challenge gives you.",
        "Collect two or more ciphertexts under this key and nonce: sign up / log in twice, or call the encrypt endpoint repeatedly.",
        "Read the source to learn the plaintext format and where the admin/role field sits.",
        "Stream, CTR or GCM: XOR two ciphertexts to cancel the keystream, then crib-drag the known format to recover plaintext.",
        "GCM auth bypass: recover the authentication key H from two (ciphertext, tag) pairs over GF(2^128), then compute a valid tag for your target plaintext.",
        "Replace the session token/cookie with your forged ciphertext and tag, then submit it to reach the admin panel or flag.",
    ],
    "CIPHER-ECB": [
        "Confirm ECB: send input with two identical adjacent blocks (32 equal bytes) and look for two identical ciphertext blocks.",
        "If you control input next to a secret, pad so one unknown byte sits at the end of a block.",
        "Recover that byte by trying all 256 values and matching the ciphertext block.",
        "Shift by one byte and repeat to peel the whole secret, then read the flag or key.",
    ],
    "HASH-WEAK": [
        "Find where this digest gates access: a comparison, a signature check, or an integrity token.",
        "For MD5/SHA-1 integrity, craft a colliding or chosen-prefix input that keeps the digest the server expects.",
        "Submit the forged input so its digest matches and the check passes.",
    ],
    "MAC-PREFIX-HASH": [
        "Capture one valid (message, digest) pair that the server accepts.",
        "Brute-force a small range for the secret length.",
        "Use a length-extension tool (for example hashpump) to append your payload and get the forged digest.",
        "Submit the extended message with the forged digest.",
    ],
    "PRNG-PREDICTABLE-SEED": [
        "Note the approximate time the secret or token was generated.",
        "Enumerate candidate Unix timestamps around that moment.",
        "Re-seed the same PRNG with each candidate and regenerate the key or token.",
        "Try each regenerated value against the challenge until one is accepted.",
    ],
    "PRNG-MT-CRYPTO": [
        "Collect 624 consecutive 32-bit outputs from the service (or enough raw random bytes).",
        "Feed those outputs to cryptoscan to clone the MT19937 state.",
        "Predict the next key, nonce or token and submit it.",
    ],
    "PRNG-NONCRYPTO-RANDOM": [
        "Identify which secret this value protects: key, nonce, token or OTP.",
        "Collect outputs tied to the same PRNG and reconstruct or brute-force its state.",
        "Predict the target secret and submit it.",
    ],
    "KEY-HARDCODED": [
        "Read the embedded key from the matched line.",
        "Identify the algorithm, mode and IV/nonce used with it.",
        "Decrypt the challenge ciphertext locally with that key and parameters to read the flag.",
    ],
}


def _source_excerpt_relevant(rule: str, excerpt: str) -> bool:
    if excerpt.startswith(("#", "//", "/*", "*")):
        return False
    if rule != "HASH-WEAK":
        return True
    if not re.search(
        r"(?:digest|hash|signature|sign|verify|password|token|flag|secret|mac|checksum)\s*=|==|!=|return\s+",
        excerpt,
        re.IGNORECASE,
    ):
        return False
    return not re.search(r"(?:secret|key)\s*\+", excerpt, re.IGNORECASE)


def _source_pattern_findings(doc: Document, rules, findings: list[Finding]) -> None:
    for rule, title, severity, pattern, attack, patch in rules:
        # A saved nonce in an output artifact is not evidence of reuse.
        # Match nonce construction only in source code, not result dumps.
        if rule == "NONCE-CONSTANT" and not doc.path.split("!/", 1)[-1].casefold().endswith(
            (".py", ".sage", ".sage.py", ".js", ".ts", ".go", ".rs", ".c", ".cpp")
        ):
            continue
        regex = re.compile(pattern, re.IGNORECASE)
        for match in regex.finditer(doc.text):
            line = doc.text.count("\n", 0, match.start()) + 1
            excerpt = doc.text.splitlines()[line - 1].strip()[:200]
            if not _source_excerpt_relevant(rule, excerpt):
                continue
            findings.append(Finding(
                rule, title, severity, "medium", f"{doc.path}:{line}",
                {"match": match.group(0), "line": excerpt},
                ["Matched code executes in the challenge cryptographic path."], attack,
                {"kind": "source_guidance", "matched_pattern": rule}, patch,
                _SOURCE_PLAYBOOKS.get(rule, []),
            ))


def _cbc_source_finding(doc: Document, findings: list[Finding]) -> None:
    # An oracle requires both CBC/unpadding and an externally distinguishable
    # padding failure. Either signal alone is too common to report.
    cbc = re.search(r"(?:MODE_CBC|AES[-_]?CBC|\bcbc\b)", doc.text, re.IGNORECASE)
    unpad = re.search(r"\bunpad\s*\(|padding(?:error|exception)|invalid\s+padding", doc.text, re.IGNORECASE)
    signal = re.search(
        r"(?:return|abort|send|jsonify|raise)[^\r\n]{0,100}(?:padding|decrypt|invalid)|"
        r"except\s+(?:ValueError|PaddingError)[^:]*:",
        doc.text,
        re.IGNORECASE,
    )
    authenticated = re.search(r"(?:MODE_GCM|MODE_EAX|ChaCha20_Poly1305|verify\s*\(\s*tag|decrypt_and_verify)", doc.text, re.IGNORECASE)
    if cbc and unpad and signal and not authenticated:
        line = doc.text.count("\n", 0, signal.start()) + 1
        findings.append(Finding(
            "CBC-PADDING-ORACLE", "Potential distinguishable CBC padding failure", "critical", "medium", f"{doc.path}:{line}",
            {"cbc_match": cbc.group(0), "unpad_match": unpad.group(0), "signal_match": signal.group(0)[:200], "aead_check_seen": False},
            ["The matched failure reaches a client-visible status, body, timing class, or exception path.", "The ciphertext is attacker-controlled."],
            "Modify the preceding ciphertext block and classify padding-valid responses to decrypt blocks or forge a flag-authorized plaintext.",
            {"kind": "cbc_padding_oracle", "block_size": 16},
            "Authenticate ciphertexts before decryption, use one indistinguishable failure response, and migrate to an AEAD mode."
        ))


def _lcg_and_stream_findings(documents: list[Document], findings: list[Finding]) -> None:
    for context in detect_ec_lcg(documents):
        findings.append(Finding(
            "ECDSA-LCG-CORRELATED-NONCES",
            "ECDSA signatures use sequential LCG-generated nonces",
            "critical", "high", f"{context.path}:{context.line}",
            {"message_count": context.signature_count, "source_verified": True,
             "lattice_recovery_implemented": False},
            ["Signed message hashes and complete (r,s) signatures are available.",
             "Signatures use consecutive outputs of the detected LCG.",
             "A suitable lattice solver and independent ECDSA verification are required."],
            "Derive linear relations between ECDSA nonce differences, compute a short "
            "integer lattice orthogonal to the observed signature vectors, recover "
            "the private key, verify it against signatures, then decrypt the flag.",
            {"kind": "ecdsa_lcg_lattice_guidance", "implemented": False},
            "Generate ECDSA nonces with a secure deterministic algorithm (RFC 6979) "
            "or a cryptographically secure independent random source.",
            ["Extract messages and signatures in the order they were signed.",
             "Compute SHA-256 message representatives modulo the curve order.",
             "Recover nonce relations using an orthogonal-lattice attack.",
             "Verify any recovered private key before claiming flag recovery."],
        ))
    for instance in recognize_stream_cipher(documents):
        model = instance.model
        findings.append(Finding(
            "LFSR-FAST-CORRELATION-STREAM-LEAK",
            "Known keystream permits a fast correlation attack on a biased LFSR combiner",
            "critical", "high", model.path + ":stream",
            {"degree": model.degree, "registers": len(model.masks),
             "clock_counts": list(model.clocks),
             "known_keystream_bits": len(instance.known_stream) * 8,
             "sparse_feedback_multiples": True},
            ["Repeated LFSR clocks and public masks are recoverable from the source.",
             "The Boolean combiner has statistically biased output projections.",
             "A known-zero encryption exposes an extended stream."],
            "Find low-weight multiples of each public LFSR feedback polynomial; "
            "recover biased registers using fast correlation, solve remaining "
            "unknown state bits over GF(2), and verify the entire known keystream.",
            {"kind": "lfsr_fast_correlation", "implemented": True,
             "verification": "complete_known_keystream_and_flag_shape"},
            "Use a cryptographically reviewed stream cipher with vetted "
            "nonlinear filtering rather than custom LFSR combiners.",
            ["Derive the combiner truth table from source.",
             "Search sparse GF(2) feedback multiples automatically.",
             "Use fast correlation to recover biased registers.",
             "Solve remaining unknown states and verify every stream bit.",
             "Decrypt the following ciphertext with the recovered keystream."],
        ))


def _fiat_shamir_findings(documents: list[Document], findings: list[Finding]) -> None:
    batch_graph = extract_batch_fiat_shamir(documents)
    if batch_graph is not None:
        findings.append(Finding(
            "FIAT-SHAMIR-AMBIGUOUS-TRANSCRIPT",
            "Unframed commitment encoding permits proof equivocation after batch hashing",
            "critical", "high", f"{batch_graph.source_path}:challenge_bits",
            {"source_verified": True, "serialized_by": "decimal_string_concatenation",
             "non_injective_encoding": True, "batch_rounds": batch_graph.rounds,
             "graph_vertices": len(batch_graph.graph),
             "full_graph_and_cycle_openings": True,
             "live_service_verified": False},
            ["Commitment integers are hashed in decimal form without length framing.",
             "The verifier computes all Fiat-Shamir challenges only after collecting proofs.",
             "The commitment matrix shape is checked without integer-canonicalization checks.",
             "Pedersen commitments are validated modulo the group prime."],
            "Find two distinct integer commitment matrices with identical hash preimages. "
            "Open one to the public graph and the other on an induced Hamiltonian cycle; "
            "derive final Fiat-Shamir challenge bits from the common transcript and select "
            "the matching proof branch for each round.",
            {"kind": "fiat_shamir_decimal_serialization_equivocation",
             "implemented": True, "verified_by": "local Pedersen openings and hash equality",
             "requires": [_AUTHORIZED_HOST, "port"]},
            "Serialize commitments canonically with unambiguous length framing "
            "and reject out-of-range commitment integers before hashing.",
            ["Confirm the unframed decimal serialization and verifier modulus checks.",
             "Generate two collision-equivalent Pedersen commitment matrices.",
             "Verify both opening branches locally and derive all challenge bits.",
             "Submit the matching proofs and require remote confirmation before printing the flag."],
        ))
    fs_graph = extract_fiat_shamir_graph(documents)
    if fs_graph is not None:
        findings.append(Finding(
            "FIAT-SHAMIR-GRINDABLE-CHALLENGE",
            "Low-entropy Fiat-Shamir challenge permits selective commitment grinding",
            "critical", "high", f"{fs_graph.source_path}:challenge",
            {"challenge_bits": 1, "rounds": fs_graph.rounds,
             "graph_vertices": len(fs_graph.graph), "expected_trials_per_round": 2,
             "source_verified": True, "live_server_verified": False},
            ["The prover chooses and hashes commitments before sending each proof.",
             "The challenge is derived from a publicly computable hash bit.",
             "At least one challenge branch can be satisfied using only a public graph opening."],
            "Generate correctly opened Pedersen graph commitments, locally evaluate "
            "the Fiat-Shamir hash, and resample random commitments until the "
            "verifier selects the graph-opening branch. Repeat across rounds.",
            {"kind": "fiat_shamir_challenge_grinding",
             "primitive": "bounded_challenge_grinding",
             "protocol": "pedersen_graph_opening",
             "requires": ["explicit_authorized_host", "port"]},
            "Bind non-interactive proofs to an appropriate soundness-preserving "
            "transformation and account for malicious commitment grinding.",
            ["Extract the active public graph, Pedersen parameters, and hash transcript.",
             "Generate and independently verify a graph-opening transcript.",
             "Grind the challenge hash to the opening branch before submission.",
             "Submit each transcript to an authorized verifier and check its response."],
        ))


def _gcm_oracle_findings(documents: list[Document], findings: list[Finding]) -> None:
    for oracle in recognize_gcm_tag_oracle(documents):
        findings.append(Finding(
            "GCM-HIDDEN-STATE-TAG-ORACLE",
            "Fixed-nonce GCM oracle with randomly mutable hidden AAD/plaintext",
            "critical", "high", f"{oracle.path}:{oracle.line}",
            {"fixed_nonce": True, "hidden_aad": True, "hidden_plaintext": True,
             "tag_oracle": True, "chosen_state_mutations": ["u1", "u2"],
             "timeout_seconds": oracle.timeout_seconds,
             "pow_difficulty": oracle.pow_difficulty,
             "automatic_recovery_implemented": supports_gcm_wire_profile(documents),
             "wire_profile_supported": supports_gcm_wire_profile(documents),
             "live_server_verified": False},
            ["The same key and nonce are used in every AES-GCM instance.",
             "The oracle returns GCM tags for hidden AAD/plaintext.",
             "An authorized interactive service exposes the documented state mutations."],
            "Model each tag using GHASH_H(AAD, ciphertext) xor E_K(J0). "
            "Use tag differences and u1 resets to infer the 128-bit GHASH key "
            "through GF(2)-linear constraints. Then use u2 length extensions "
            "to solve for the hidden state and the empty-message authentication pad.",
            {"kind": "gcm_hidden_state_linear_algebra",
             "implemented": supports_gcm_wire_profile(documents),
             "algebra": "GF(2^128)", "requires": ["tag transcript", "state mutations"]},
            "Use a fresh GCM nonce per encryption and avoid exposing tag oracles "
            "over a hidden, attacker-mutatable authentication state.",
            ["Run cryptoscan . --solve --host archive.cryptohack.org --port 2762.",
             "Solve the 26-bit MD5 proof of work before the service timeout.",
             "Collect tags after many u1 mutations and derive linear constraints on H.",
             "Recover H using binary finite-field linear algebra and validate against additional tags.",
             "Use u2 to extend message lengths and solve for hidden GHASH coefficients.",
             "Compute candidate authentication pads, submit one per session, and only print remotely verified flags."],
        ))


def _per_document_source_findings(documents: list[Document], rules, findings: list[Finding]) -> None:
    for doc in documents:
        if supported_fischlin_source([doc]):
            findings.append(Finding(
                "FISCHLIN-FIRST-HIT-WITNESS-LEAK",
                "Fischlin proof leaks branch identity through first-hit hash selection",
                "critical", "high", f"{doc.path}:fischlin_proof",
                {"hash": "SHA-512", "leading_zero_bits": 6,
                 "max_attempts_per_round": 16, "rounds": 64,
                 "source_verified": True, "online_solver": True},
                ["The service discloses one valid witness per transcript.",
                 "The prover deterministically takes the first hash under threshold.",
                 "Authorized service address must be supplied explicitly."],
                "Use the disclosed witness to reconstruct earlier candidate proof "
                "transcripts under the real-branch hypothesis. If an earlier "
                "candidate meets the hash bound, that branch must be simulated.",
                {"kind": "fischlin_first_hit_tcp", "requires": ["host", "port"]},
                "Avoid publishing witnesses and relying on a deterministic first-hit "
                "sampling transcript as a witness-indistinguishability mechanism.",
                ["Provide the challenge source and group parameters.",
                 "Run cryptoscan . --solve --host HOST --port PORT.",
                 "Skip inconclusive transcripts; never guess a branch without evidence.",
                 "Complete all 64 rounds and parse the returned flag."],
            ))
        if supported_dghv_source([doc]):
            findings.append(Finding(
                "DGHV-NOISE-OVERFLOW", "DGHV positive-noise overflow leaks private modulus",
                "critical", "high", f"{doc.path}:dghv_encrypt",
                {"model": "c=p*q+N*r+m, decrypt=(c%p)%N", "p_bits": 128,
                 "chosen_N": [128, 255], "noise": "nonnegative, bounded"},
                ["Challenge exposes chosen-N encryption/addition and decryption under the same p.",
                 "Network target is an authorized CTF service explicitly supplied to --solve."],
                "Add encryptions of zero until the first modular overflow, infer p mod N, "
                "combine coprime residues by CRT, and decrypt the published flag ciphertexts.",
                {"kind": "dghv_positive_noise_crt", "requires": ["host", "port"]},
                "Use standard authenticated encryption; do not expose decryption oracles or a "
                "noise distribution that exposes modular wraparound.",
                ["Supply the original challenge source and authorized TCP host/port.",
                 "Run cryptoscan server.py --solve --host HOST --port PORT.",
                 "Verify that CRT uniquely determines the 128-bit modulus and recover flag bytes."],
            ))
        _source_pattern_findings(doc, rules, findings)
        _cbc_source_finding(doc, findings)


def _weak_seeded_rsa_findings(documents: list[Document], findings: list[Finding]) -> None:
    weak_model = extract_weak_seeded_rsa(documents)
    # A vulnerable PRNG construction is a meaningful source finding even
    # when the ciphertext/output has not yet been collected. Recovery
    # requires a separately matched public corpus.
    for source in documents:
        profile = weak_seeded_rsa_profile(source.text)
        if profile is None:
            continue
        exponent, length, prime_bits, _, _, first, _ = profile
        matched_output = weak_model is not None and weak_model.exponent == exponent
        evidence = {
            "source_verified": True,
            "first_seed_entropy_bits": first,
            "prime_candidate_bits": prime_bits,
            "rsa_exponent": exponent,
            "plaintext_upper_bound_bits": 8 * length,
            "public_output_matched": matched_output,
        }
        if matched_output:
            evidence["modulus_bits"] = weak_model.modulus.bit_length()
        findings.append(Finding(
            "RSA-WEAK-SEEDED-PRIME-GENERATOR",
            "Deterministic RSA primes generated from limited-entropy seeds",
            "high", "high", source.path,
            evidence,
            [
                "An RSA factor originates from a predictable PRNG initialized "
                "with an enumerable seed.",
                "Candidate primes must be checked by exact divisibility of N.",
                "Partial CRT gives a unique plaintext only when the recovered "
                "factor product exceeds the source-proven plaintext bound.",
            ],
            "Enumerate bounded PRNG seeds; regenerate possible primes and "
            "verify exact divisibility by N. Decrypt modulo each known factor "
            "and reconstruct the bounded plaintext by CRT, then re-encrypt "
            "to verify the result.",
            {
                "kind": "rsa_weak_seed_partial_crt",
                "offline": True,
                "source_verified": True,
                "public_corpus_available": matched_output,
                "requires": ["source", "public modulus", "ciphertext"],
            },
            "Use a cryptographic prime generator with fresh high-entropy "
            "randomness for every prime. Never derive large primes from a "
            "deterministic PRNG seeded by a small secret.",
            [
                "Identify the PRNG, seed entropy and prime sampling loop.",
                "Regenerate candidate primes and verify N % p == 0.",
                "Recover enough independent factors that their product "
                "exceeds the maximum plaintext integer.",
                "Compute residues, combine via CRT and verify re-encryption.",
            ],
        ))


def _reused_digit_rsa_findings(documents: list[Document], findings: list[Finding]) -> None:
    matched = extract_reused_digits(documents)
    for document in documents:
        profile = reused_digits_profile(document)
        if profile is None:
            continue
        has_public = matched is not None
        findings.append(Finding(
            "RSA-REUSED-BASE-DIGITS",
            "RSA factors reuse the same digits in distinct bases",
            "high", "high", document.path,
            {
                "source_verified": True,
                "source_base": profile.source_base,
                "target_base": profile.target_base,
                "prime_draw_bits": profile.prime_bits,
                "public_exponent": profile.exponent,
                "public_modulus_matched": has_public,
                "modulus_bits": matched.modulus.bit_length() if has_public else None,
            },
            [
                "The source draws one RSA factor and forms another by "
                "reinterpreting its digits in a larger base.",
                "Both factors are checked for primality and multiplied into "
                "the RSA modulus.",
            ],
            "The digit mapping is increasing when the target base is at least "
            "the source base. "
            "The public product therefore leaks a constrained relation "
            "between the two factors.",
            {
                "kind": "rsa_reused_base_digits",
                "offline": True,
                "source_verified": True,
                "public_corpus_available": has_public,
                "requires": ["source", "public modulus"],
            },
            "Generate independent RSA primes with fresh cryptographic "
            "randomness; never derive one factor from the other.",
            [
                "Confirm the source and target digit bases and factor roles.",
                "Check that the public modulus belongs to the same source scope.",
                "Replace the correlated key pair and rotate affected keys.",
            ],
        ))


def _biased_shamir_findings(documents: list[Document], findings: list[Finding]) -> None:
    for document in documents:
        profile = biased_shamir_profile(document)
        if profile is None:
            continue
        findings.append(Finding(
            "SHAMIR-COEFFICIENT-SAMPLING-BIAS",
            "Shamir polynomial coefficients exclude valid field elements",
            "high", "high", document.path,
            {
                "source_verified": True,
                "excluded_high_field_elements": profile.excluded_high,
                "secret_bits": profile.secret_bits,
                "minimum_shares": profile.minimum_n,
                "public_share_fraction": "all_but_one",
                "interactive_prime_selection": True,
            },
            [
                "Random nonconstant coefficients are sampled from a strict "
                "subset of the field, rather than uniformly from F_p.",
                "A fixed secret is reused across independently randomized "
                "polynomials and the client chooses the prime field.",
                "The server publishes one fewer evaluation than the "
                "polynomial reconstruction threshold.",
            ],
            "Interpolate each observed polynomial up to its missing degree "
            "of freedom. Exclude constant terms that require a forbidden "
            "nonconstant coefficient, intersect candidates over repeated "
            "samples, then use CRT over independent prime moduli once the "
            "product exceeds the proven secret bound.",
            {
                "kind": "shamir_coefficient_bias_crt",
                "remote": True,
                "source_verified": True,
                "requires": [_AUTHORIZED_HOST, "port"],
            },
            "Sample every nonconstant polynomial coefficient uniformly "
            "over the entire finite field, including p-1. Never allow an "
            "adversary to choose parameters that expose statistical bias "
            "across multiple sharings of the same secret.",
            [
                "Identify the polynomial degree, participant coordinates, "
                "random coefficient support and available share count.",
                "Model missing polynomial coefficients symbolically and "
                "derive forbidden secret residues from support constraints.",
                "Request repeated fresh sharings of the same secret "
                "over the same prime and intersect candidate residues.",
                "Combine uniquely identified residues from coprime fields "
                "using CRT; submit only after a uniqueness certificate.",
            ],
        ))


def _cyclotomic_rsa_findings(documents: list[Document], findings: list[Finding]) -> None:
    related_rsa = extract_cyclotomic_rsa(documents)
    for document in documents:
        related = cyclotomic_rsa_profile(document.text)
        if related is None:
            continue
        _, _, _, bits, degree, exponent = related
        matched_public = (
            related_rsa is not None and related_rsa.degree == degree
        )
        findings.append(Finding(
            "RSA-CYCLOTOMIC-PRIME-RELATION",
            "RSA primes related by a cyclotomic geometric sum",
            "high", "high", document.path,
            {
                "source_verified": True,
                "polynomial_degree": degree,
                "prime_bits": bits,
                "public_exponent": exponent,
                "public_modulus_matched": matched_public,
                "factor_relation": "Q(p) = sum(p**j, j=0..degree-1)",
            },
            [
                "The RSA modulus has two prime factors p and Q(p), "
                "with Q(p) dividing p**degree - 1.",
                "The generator requires primality of both related factors.",
                "A degree-matched finite-field extension can collapse "
                "nonconstant components after exponentiation by N.",
            ],
            "Try monic degree-matched quotient polynomials over Z/NZ. "
            "Exponentiate a nonconstant element to the public modulus; "
            "gcd the resulting nonconstant coefficients with N. Verify "
            "that Q(p) divides N/p and recover the remaining RSA factor.",
            {
                "kind": "rsa_cyclotomic_finite_field_factorization",
                "offline": True,
                "source_verified": True,
                "public_corpus_available": matched_public,
                "requires": ["source", "public modulus", "ciphertext"],
            },
            "Choose independent random primes without algebraic "
            "relationships that expose their group orders.",
            [
                "Extract the prime relation and extension degree.",
                "Construct quotient rings and test finite-field "
                "subgroup collapse using bounded independent polynomials.",
                "Verify gcd-derived factors and the source relation.",
                "Decrypt with the certified factorization and verify "
                "RSA re-encryption.",
            ],
        ))


def _modular_noise_findings(documents: list[Document], findings: list[Finding]) -> None:
    modular_model = extract_modular_noise(documents)
    for document in documents:
        profile = modular_noise_profile(document.text)
        if profile is None:
            continue
        size, modulus, bits, samples, true_bit = profile
        has_public = modular_model is not None and modular_model.key_bytes == size
        findings.append(Finding(
            "LWE-MODULAR-NOISE-SUBGROUP-LEAK",
            "LWE-like samples reveal exact linear equations modulo a small power of two",
            "high", "high", document.path,
            {
                "source_verified": True,
                "key_coordinates": size,
                "sample_modulus": modulus,
                "noise_trailing_zero_bits": bits,
                "samples_per_classification": samples,
                "authentic_selector_bit": true_bit,
                "public_transcript_matched": has_public,
            },
            [
                "The additive noise is shifted left at the end of every "
                "generation round and its offset preserves trailing zeros.",
                "Authentic observations expose exact modular linear equations.",
                "Decoy observations are uniform modulo the public sample modulus.",
                "One reused hidden key provides cross-block consistency.",
            ],
            "Reduce the observations modulo 2**t to eliminate the noise. "
            "Recover secret key residues with bounded block-wise RANSAC over "
            "linear systems, classify genuine observation groups, and "
            "reconstruct the source-defined bit packing.",
            {
                "kind": "lwe_modular_noise_mixture",
                "offline": True,
                "source_verified": True,
                "public_corpus_available": has_public,
                "requires": ["source", "mixed observation transcript"],
            },
            "Do not use a restricted-noise distribution whose support is "
            "contained in a proper additive subgroup modulo the public "
            "arithmetic modulus. Sample full-support noise where appropriate "
            "or use a cryptographically justified LWE parameterization.",
            [
                "Check the additive noise support modulo every small divisor "
                "of the sample modulus.",
                "Eliminate the noise under a supported modular projection.",
                "Solve a subset of coherent blocks for the secret residues.",
                "Validate on independent observations and classify the "
                "true/fake mixture, accounting for accidental decoy matches.",
            ],
        ))


def _ec_twist_findings(documents: list[Document], findings: list[Finding]) -> None:
    for document in documents:
        twist = ec_twist_profile(document)
        if twist is None:
            continue
        findings.append(Finding(
            "EC-UNVALIDATED-X-QUADRATIC-TWIST",
            "Chosen x-coordinates permit quadratic-twist small-subgroup leakage",
            "high", "high", document.path,
            {
                "source_verified": True,
                "prime_field_bits": twist.field_prime.bit_length(),
                "published_main_curve_order": twist.curve_order is not None,
                "twist_order": (
                    2*(twist.field_prime+1)-twist.curve_order
                    if twist.curve_order is not None else None
                ),
                "x_only_arithmetic": True,
                "user_supplied_coordinate": True,
            },
            [
                "A user-provided coordinate is passed to an x-only "
                "elliptic-curve scalar multiplier without membership validation.",
                "Its differential addition law also operates on the "
                "quadratic twist, whose subgroup order differs from "
                "the advertised main curve order.",
                "Twist subgroup factors may expose modular residues "
                "of a reused private scalar.",
            ],
            "Construct a quadratic twist, factor its order when available, "
            "choose a twist point and query the x-only oracle. Recover "
            "the scalar residue via bounded subgroup discrete logarithms "
            "and CRT, explicitly retaining the x-coordinate sign ambiguity.",
            {
                "kind": "ec_chosen_coordinate_twist_subgroup",
                "remote": True,
                "source_verified": True,
                "requires": [_AUTHORIZED_HOST, "port", "twist order"],
            },
            "Reject invalid and twist points before multiplying by a "
            "private scalar, or use a validated prime-order subgroup "
            "with cofactor-safe operations and explicit input checks.",
            [
                "Trace untrusted coordinates into the scalar multiplier.",
                "Determine the main and quadratic-twist group orders.",
                "Analyze the twist's factorization and subgroup sizes.",
                "Use discrete logarithms and CRT to infer scalar residues.",
                "Validate that the recovered residue uniquely identifies "
                "the original secret before claiming a plaintext.",
            ],
        ))


def _hyperelliptic_findings(documents: list[Document], findings: list[Finding]) -> None:
    for document in documents:
        hyper = hyperelliptic_leak_profile(document)
        if hyper is None:
            continue
        findings.append(Finding(
            "HYPERELLIPTIC-MUMFORD-STATE-DISCLOSURE",
            "Chosen plaintext reveals serialized Jacobian divisor coefficients",
            "high", "high", document.path,
            {
                "source_verified": True,
                "finite_field_bits": hyper.prime.bit_length(),
                "genus": hyper.genus,
                "curve_polynomial_degree_bound": hyper.polynomial_degree_bound,
                "state_bytes": hyper.state_bytes,
                "coefficients_per_state": hyper.coefficients_per_state,
                "known_plaintext_suffix": hyper.known_plaintext_suffix is not None,
                "chosen_plaintext": hyper.chosen_plaintext,
                "fixed_scalar_for_flag": hyper.scalar_multiplier_reused_for_flag,
                "full_flag_recovery_implemented": False,
            },
            [
                "An attacker supplies arbitrary plaintext that is XORed "
                "with bytes serializing consecutive Jacobian state coefficients.",
                "Zero plaintext reveals complete Mumford u,v coefficients "
                "from a scalar-multiplied hyperelliptic divisor.",
                "Every disclosed divisor satisfies f(x) congruent to "
                "v(x)**2 modulo u(x), giving linear constraints on "
                "the hidden curve polynomial coefficients.",
                "A fixed nonrandom scalar controls the flag keystream; "
                "known plaintext in that ciphertext may leak partial state.",
            ],
            "Query zero plaintext long enough to expose multiple full "
            "Mumford states. Reconstruct the curve polynomial by finite-field "
            "linear algebra from f modulo u = v**2 modulo u. "
            "Analyze the remaining incomplete flag keystream state with "
            "curve constraints and any known plaintext before attempting "
            "secret recovery. A full flag is not yet certified.",
            {
                "kind": "hyperelliptic_jacobian_mumford_state_leak",
                "remote": True,
                "source_verified": True,
                "recovery_status": "partial_state_and_curve",
                "requires": [_AUTHORIZED_HOST, "port", "chosen plaintext"],
            },
            "Never expose algebraic PRNG internal state through reversible "
            "serialization and XOR with attacker-controlled plaintext. "
            "Use a cryptographically secure stream cipher and derive "
            "keys independently of exposed group elements.",
            [
                "Normalize Sage polynomial rings and identify Jacobian "
                "scalar-multiplication state.",
                "Trace u,v coefficients into binary packing and XOR output.",
                "Exploit chosen zero plaintext to obtain full divisor states.",
                "Use the Mumford congruence to recover the hidden curve.",
                "Determine whether the secret ciphertext can be decrypted "
                "with enough uniquely constrained state information.",
            ],
        ))


def _reciprocal_rabin_findings(documents: list[Document], findings: list[Finding]) -> None:
    for document in documents:
        reciprocal = reciprocal_rabin_profile(document)
        if reciprocal is None:
            continue
        findings.append(Finding(
            "RABIN-RECIPROCAL-CRT-ORACLE-FAULT",
            "Faulty quadratic roots disclose CRT factors through re-encryption",
            "high", "high", document.path,
            {
                "source_verified": True,
                "factor_bits": reciprocal.factor_bits,
                "ciphertext_fields": list(reciprocal.ciphertext_labels),
                "chosen_ciphertext_oracle": True,
                "decrypt_then_reencrypt": True,
                "public_modulus_required_before_attack": False,
            },
            [
                "An attacker can choose the reciprocal-Rabin ciphertext "
                "coefficient and its auxiliary disambiguation bits.",
                "The decryptor solves quadratic equations independently "
                "modulo two secret primes and recombines candidate roots "
                "with CRT, without first proving that roots exist.",
                "An observable decrypt-then-reencrypt service returns "
                "ciphertexts or an explicit exception marker.",
                "Re-encrypted coefficients may differ in only one CRT "
                "component, producing differences divisible by a secret prime.",
            ],
            "Query the same quadratic coefficient with all auxiliary "
            "selector combinations. Collect distinct re-encrypted "
            "coefficients and pairwise gcd their differences to infer "
            "private factors. Derive the unknown reciprocal constant from "
            "the root-sum relation, then decrypt the captured ciphertext "
            "and verify full re-encryption.",
            {
                "kind": "reciprocal_rabin_crt_fault",
                "remote": True,
                "source_verified": True,
                "requires": [_AUTHORIZED_HOST, "port"],
            },
            "Reject ciphertexts whose quadratic discriminants are not "
            "residues for both factors, enforce correct root extraction, "
            "and never expose a decryption/re-encryption discrepancy oracle.",
            [
                "Identify the invertible-message reciprocal equation.",
                "Trace source-specific root solvers and CRT recombination.",
                "Compare four selector responses for identical input r.",
                "Recover private factors from GCD of response differences.",
                "Solve the recovered root-sum system for the public constant.",
                "Certify the final plaintext by re-encrypting it.",
            ],
        ))


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
        ("PRNG-NONCRYPTO-RANDOM", "Non-cryptographic random value protects a secret", "high",
         r"\b(?:key|nonce|token|secret|otp)\s*=\s*random\.(?:randint|randrange|choice|choices)\s*\(",
         "Reconstruct or brute-force the PRNG state, then predict the generated secret value.",
         "Generate keys, nonces, and tokens with secrets or an operating-system CSPRNG."),
        ("KEY-HARDCODED", "Hardcoded cryptographic key", "high",
         r"\b(?:aes_?|encryption_?|secret_?)?key\s*=\s*(?:b|bytes\.fromhex\s*\()?[\"'][^\"']{8,}[\"']",
         "Read the embedded key and decrypt the challenge ciphertext with the declared algorithm and parameters.",
         "Load the key from a secret store or challenge runtime. Rotate the exposed key."),
        ("CIPHER-ECB", "ECB mode selected in source", "high", r"\b(?:MODE_ECB|AES[-_]?ECB|\becb\b)",
         "Exploit equal-block leakage; with an encryption oracle, align input for byte-at-a-time secret recovery.",
         "Use AES-GCM or ChaCha20-Poly1305 with a unique nonce."),
        ("NONCE-CONSTANT", "Constant nonce or IV in source", "high",
         r"\b(?:nonce|iv)\s*=\s*(?:b?[\"'][^\"']+[\"']|bytes\s*\(|0x[0-9a-fA-F]+)",
         "Request or collect two encryptions, XOR ciphertexts, and recover plaintext through known format or crib dragging.",
         "Generate a unique nonce per key and store it with the ciphertext."),
    ]
    findings: list[Finding] = []
    _lcg_and_stream_findings(documents, findings)
    _fiat_shamir_findings(documents, findings)
    _gcm_oracle_findings(documents, findings)
    _per_document_source_findings(documents, rules, findings)
    _weak_seeded_rsa_findings(documents, findings)
    _reused_digit_rsa_findings(documents, findings)
    _biased_shamir_findings(documents, findings)
    _cyclotomic_rsa_findings(documents, findings)
    _modular_noise_findings(documents, findings)
    _ec_twist_findings(documents, findings)
    _hyperelliptic_findings(documents, findings)
    _reciprocal_rabin_findings(documents, findings)
    return findings

def _related_key_findings(documents):
    for document in documents:
        for profile in related_key_profiles(document):
            matched = extract_related_key(documents) is not None
            yield Finding(
                "RSA-RELATED-KEY-MATERIAL",
                "RSA encrypts algebraically related inverse key material",
                "high", "high", document.path,
                {"public_exponent": profile.exponent, "public_corpus_available": matched},
                ["Raw RSA encrypts a modular inverse and its inverse modulus under the same key."],
                "Use modular polynomial GCD with bounded inverse multipliers and verify the totient.",
                {"kind": "rsa_related_key_material", "offline": True},
                "Never publish raw RSA encryptions of private key components; use standard key wrapping.",
            )


def _rotated_rsa_findings(documents):
    instance = extract_rotated_rsa(documents)
    for document in documents:
        for profile in rotated_rsa_profiles(document):
            yield Finding(
                "RSA-ROTATED-QUADRATIC-REPRESENTATIONS",
                "Jointly rotated norm representations leak an RSA factor",
                "high", "high", document.path,
                {"public_corpus_available": instance is not None,
                 "vector_labels": list(profile.vectors)},
                ["Two exact representations x_i? + e y_i? = n share an orthogonal rotation."],
                "Recover e from the rotation-invariant trace, invert the rotation, "
                "and verify the determinant factor and RSA ciphertext.",
                {"kind": "rotated_quadratic_rsa", "offline": True},
                "Do not disclose high-precision rotations of secret representations of an RSA modulus.",
            )

