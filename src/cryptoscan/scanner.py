from __future__ import annotations

from collections import Counter, defaultdict
import math
import re
from typing import Any

from .mathutil import crt, discrete_log_bsgs, extended_gcd, fermat_factor, int_to_bytes, integer_nth_root, signed_mod_pow, wiener_private_exponent
from .model import Finding
from .parser import Document, flatten_objects, parse_bytes, parse_int, pem_rsa_public_keys, scalar_records


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
        if n is not None and n > 3:
            result.append({**record, "n": n, "e": e, "c": c,
                           "p": parse_int(_pick(obj, "p", "prime1")), "q": parse_int(_pick(obj, "q", "prime2")),
                           "d": parse_int(_pick(obj, "d", "private_exponent")),
                           "dp": parse_int(_pick(obj, "dp", "dmp1")), "dq": parse_int(_pick(obj, "dq", "dmq1"))})
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
        differences = [right - left for left, right in zip(outputs, outputs[1:])]
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
    if any((multiplier * left + increment) % modulus != right for left, right in zip(outputs, outputs[1:])):
        return None
    return modulus, multiplier, increment


def _repeating_xor_candidate(data: bytes) -> tuple[bytes, bytes, float] | None:
    """Return a conservative repeating-key XOR solution when it exposes a flag token."""
    best: tuple[float, bytes, bytes] | None = None
    for key_size in range(2, min(40, len(data) // 2) + 1):
        baseline = bytearray()
        for offset in range(key_size):
            column = data[offset::key_size]
            candidates = [(_single_byte_score(bytes(value ^ candidate for value in column)), candidate) for candidate in range(256)]
            baseline.append(max(candidates, key=lambda row: (row[0], -row[1]))[1])
        keys = [bytes(baseline)]
        for crib in (b"flag{", b"ctf{"):
            for start in range(0, len(data) - len(crib) + 1):
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
        for key in keys:
            plain = bytes(value ^ key[index % key_size] for index, value in enumerate(data))
            if not re.search(rb"(?:flag|ctf|key)\{[^\r\n]{1,200}\}", plain, re.IGNORECASE):
                continue
            printable = sum(value in (9, 10, 13) or 32 <= value <= 126 for value in plain) / len(plain)
            if printable < 0.90:
                continue
            score = _language_score(plain) - 0.015 * key_size
            if best is None or (score, bytes(key)) > (best[0], best[1]):
                best = score, bytes(key), plain
    return (best[1], best[2], best[0]) if best else None


def scan(documents: list[Document], fermat_steps: int = 100_000) -> list[Finding]:
    records = _records(documents)
    rsa = _rsa_records(records)
    byte_records = _bytes_records(records)
    findings: list[Finding] = []

    # RSA pairwise shared factors.
    for left_index, left in enumerate(rsa):
        for right in rsa[left_index + 1 :]:
            if left["scope"] != right["scope"] or left["n"] == right["n"]:
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
        factor = None
        leak_kind = None
        for name in ("p", "q"):
            candidate = item[name]
            if candidate and 1 < candidate < n and n % candidate == 0:
                factor, leak_kind = candidate, name
                break
        if factor is None and e:
            for name in ("dp", "dq"):
                candidate = item[name]
                if candidate and candidate > 0:
                    factor = _factor_from_crt_exponent(n, e, candidate)
                    if factor:
                        leak_kind = name
                        break
        if factor:
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
        if e is not None and e > 1:
            recovered = wiener_private_exponent(n, e)
            if recovered:
                d, p, q = recovered
                evidence = {"n": str(n), "e": e, "d": str(d), "p": str(p), "q": str(q)}
                solver: dict[str, Any] = {"kind": "rsa_wiener", "d": str(d), "p": str(p), "q": str(q)}
                if c is not None and 0 <= c < n:
                    plain = int_to_bytes(pow(c, d, n))
                    evidence.update({"plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace")})
                    solver["result_hex"] = plain.hex()
                findings.append(Finding(
                    "RSA-WIENER-SMALL-D", "RSA private exponent recovered by Wiener attack", "critical", "certain", item["location"],
                    evidence, ["The public key is RSA.", "The private exponent is small enough to occur in convergents of e/n."],
                    "Expand e/n as a continued fraction. A convergent yields d and factors n exactly.", solver,
                    "Generate RSA keys with a maintained library and reject private exponents below the Wiener bound."
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

    by_modulus: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for item in rsa:
        if item["e"] is not None and item["c"] is not None:
            by_modulus[(item["scope"], item["n"])].append(item)
    for (_, n), group in sorted(by_modulus.items()):
        for i, left in enumerate(group):
            for right in group[i + 1 :]:
                g, a, b = extended_gcd(left["e"], right["e"])
                if g != 1:
                    continue
                try:
                    m = (signed_mod_pow(left["c"], a, n) * signed_mod_pow(right["c"], b, n)) % n
                except ValueError:
                    continue
                if pow(m, left["e"], n) != left["c"] or pow(m, right["e"], n) != right["c"]:
                    continue
                plain = int_to_bytes(m)
                findings.append(Finding(
                    "RSA-COMMON-MODULUS", "RSA common-modulus attack recovers plaintext", "critical", "certain",
                    f'{left["location"]} + {right["location"]}',
                    {"n": str(n), "e1": left["e"], "e2": right["e"], "bezout_a": a, "bezout_b": b, "m": str(m), "plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace"), "reencryption_verified": True},
                    ["Both ciphertexts encrypt the same plaintext under the same modulus.", "The public exponents are coprime."],
                    "Combine c1^a and c2^b modulo n using Bezout coefficients a and b.",
                    {"kind": "rsa_common_modulus", "result_int": str(m), "result_hex": plain.hex()},
                    "Never share an RSA modulus between keys. Use randomized OAEP padding."
                ))

    # Hastad broadcast: same small-exponent plaintext under independent moduli.
    e3 = [item for item in rsa if item["e"] == 3 and item["c"] is not None and 0 <= item["c"] < item["n"]]
    for i in range(len(e3)):
        for j in range(i + 1, len(e3)):
            for k in range(j + 1, len(e3)):
                group = [e3[i], e3[j], e3[k]]
                if len({item["scope"] for item in group}) != 1:
                    continue
                if any(math.gcd(group[a]["n"], group[b]["n"]) != 1 for a in range(3) for b in range(a + 1, 3)):
                    continue
                combined, product = crt((item["c"], item["n"]) for item in group)
                root, exact = integer_nth_root(combined, 3)
                if not exact:
                    continue
                plain = int_to_bytes(root)
                findings.append(Finding(
                    "RSA-HASTAD-BROADCAST", "Hastad broadcast attack recovers plaintext", "critical", "certain",
                    " + ".join(item["location"] for item in group),
                    {"e": 3, "moduli": [str(item["n"]) for item in group], "crt_value": str(combined),
                     "crt_modulus": str(product), "m": str(root), "plaintext_hex": plain.hex(),
                     "plaintext_utf8": plain.decode("utf-8", "replace")},
                    ["All three ciphertexts encrypt the same plaintext.", "The moduli are pairwise coprime.", "Textbook RSA uses e=3 without randomized padding."],
                    "Combine ciphertexts with CRT, then take the exact integer cube root.",
                    {"kind": "rsa_hastad", "result_int": str(root), "result_hex": plain.hex()},
                    "Use RSA-OAEP. Never encrypt one raw plaintext under several textbook RSA keys."
                ))

    # Reused DSA/ECDSA nonce: equal r exposes k and private key x.
    signatures: list[dict[str, Any]] = []
    for record in records:
        obj = record["object"]
        r = parse_int(_pick(obj, "r"))
        s = parse_int(_pick(obj, "s"))
        z = parse_int(_pick(obj, "z", "hash", "message_hash", "h"))
        q = parse_int(_pick(obj, "q", "order", "curve_order", "n_order"))
        if all(value is not None for value in (r, s, z, q)) and q > 2 and 0 < r < q and 0 < s < q:
            signatures.append({**record, "r": r, "s": s, "z": z, "q": q})
    by_signature: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    for item in signatures:
        by_signature[(item["scope"], item["q"], item["r"])].append(item)
    for (_, q, r), group in sorted(by_signature.items()):
        for i, left in enumerate(group):
            for right in group[i + 1:]:
                if left["s"] == right["s"] or left["z"] == right["z"]:
                    continue
                try:
                    nonce = ((left["z"] - right["z"]) * pow((left["s"] - right["s"]) % q, -1, q)) % q
                    private = ((left["s"] * nonce - left["z"]) * pow(r, -1, q)) % q
                except ValueError:
                    continue
                if (left["s"] * nonce - left["z"] - r * private) % q != 0 or (right["s"] * nonce - right["z"] - r * private) % q != 0:
                    continue
                findings.append(Finding(
                    "SIGNATURE-NONCE-REUSE", "DSA/ECDSA nonce reuse exposes private key", "critical", "certain",
                    f'{left["location"]} + {right["location"]}',
                    {"q": str(q), "r": str(r), "nonce_k": str(nonce), "private_key_x": str(private),
                     "z1": str(left["z"]), "s1": str(left["s"]), "z2": str(right["z"]), "s2": str(right["s"])},
                    ["Both signatures use the same group order and r value.", "The recorded hashes are the signed message integers."],
                    "Compute k=(z1-z2)/(s1-s2) mod q, then x=(s1*k-z1)/r mod q. Use x to sign the flag request.",
                    {"kind": "signature_nonce_reuse", "nonce_k": str(nonce), "private_key_x": str(private)},
                    "Use deterministic RFC 6979 nonces or a CSPRNG and reject repeated r values."
                ))

    # Structured LCG state recovery.
    for record in records:
        obj = record["object"]
        raw_outputs = _pick(obj, "outputs", "states", "samples", "sequence")
        if not isinstance(raw_outputs, list):
            continue
        outputs = [parse_int(value) for value in raw_outputs]
        if any(value is None for value in outputs):
            continue
        explicit_modulus = parse_int(_pick(obj, "modulus", "m"))
        recovered = _recover_lcg(outputs, explicit_modulus)
        if not recovered:
            continue
        modulus, multiplier, increment = recovered
        next_value = (multiplier * outputs[-1] + increment) % modulus
        findings.append(Finding(
            "LCG-STATE-RECOVERY", "Linear congruential generator state recovered", "high",
            "certain" if explicit_modulus == modulus else "high", record["location"],
            {"outputs": outputs, "modulus": str(modulus), "multiplier": str(multiplier), "increment": str(increment),
             "next_output": str(next_value), "recurrence_verified": True, "modulus_was_explicit": explicit_modulus is not None},
            ["The ordered values are consecutive LCG outputs.", "A derived modulus can be a multiple of the implementation modulus; validate the prediction."],
            "Recover the recurrence from output differences, then predict the next value used for the flag key or token.",
            {"kind": "lcg_recovery", "modulus": str(modulus), "multiplier": str(multiplier), "increment": str(increment), "next_output": str(next_value)},
            "Use an operating-system CSPRNG for secret keys, nonces, and tokens."
        ))

    # Structured finite-field Diffie-Hellman only; generic p/q records are ignored.
    for record in records:
        obj = record["object"]
        algorithm = str(_pick(obj, "algorithm", "mode", "scheme", "type") or "").casefold()
        p = parse_int(_pick(obj, "p", "prime", "modulus"))
        g = parse_int(_pick(obj, "g", "generator"))
        public_a = parse_int(_pick(obj, "public_a", "alice_public", "a_pub", "a"))
        public_b = parse_int(_pick(obj, "public_b", "bob_public", "b_pub", "b"))
        finite_field_dh = "diffie" in algorithm or algorithm in {"dh", "ffdhe", "finite-field-dh"}
        if not finite_field_dh or "ecdh" in algorithm or p is None or g is None or p <= 3:
            continue
        if g % p in (0, 1, p - 1):
            findings.append(Finding(
                "DH-DEGENERATE-GENERATOR", "Degenerate Diffie-Hellman generator", "critical", "certain", record["location"],
                {"p": str(p), "g": str(g), "g_mod_p": str(g % p)},
                ["The structured parameters are finite-field Diffie-Hellman."],
                "Enumerate the tiny set of possible shared secrets produced by g=0, 1, or -1 modulo p.",
                {"kind": "dh_degenerate_generator", "candidate_shared_secrets": ["0", "1", str(p - 1)]},
                "Use a standardized safe-prime group and validate the peer public key and generator."
            ))
            continue
        using_a = public_a is not None
        public = public_a if using_a else public_b
        if public is None:
            continue
        private = discrete_log_bsgs(g % p, public % p, p)
        if private is not None:
            evidence: dict[str, Any] = {"p": str(p), "g": str(g), "public": str(public), "private_exponent": str(private),
                                        "discrete_log_verified": pow(g, private, p) == public % p}
            solver: dict[str, Any] = {"kind": "dh_small_group", "private_exponent": str(private)}
            peer = public_b if using_a else public_a
            if peer is not None:
                shared = pow(peer, private, p)
                evidence["shared_secret"] = str(shared)
                solver["shared_secret"] = str(shared)
            findings.append(Finding(
                "DH-SMALL-GROUP", "Diffie-Hellman discrete log recovered", "critical", "certain", record["location"],
                evidence, ["The structured values are finite-field Diffie-Hellman parameters and public keys.", "The group is within the bounded BSGS limit."],
                "Solve the discrete logarithm with baby-step giant-step, then derive the shared secret and flag encryption key.", solver,
                "Use a standardized group of at least 2048 bits or X25519 and validate peer keys."
            ))

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

    # Byte-level attacks.
    for record in byte_records:
        data = record["bytes"]
        candidates = []
        for key in range(256):
            plain = bytes(byte ^ key for byte in data)
            candidates.append((_single_byte_score(plain), key, plain))
        score, key, plain = max(candidates, key=lambda row: (row[0], -row[1]))
        printable_ratio = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in plain) / len(plain)
        runner_up = sorted(candidates, key=lambda row: row[0], reverse=True)[1][0]
        flag_shape = bool(re.search(rb"(?:flag|ctf|key)\{[^\r\n]{1,200}\}", plain, re.IGNORECASE))
        if key != 0 and len(data) >= 6 and printable_ratio >= 0.90 and (flag_shape or (score >= 1.20 and score - runner_up >= 0.18)):
            findings.append(Finding(
                "XOR-SINGLE-BYTE", "Single-byte XOR key is recoverable", "high", "certain" if flag_shape else "high", f'{record["location"]}.{record["field"]}',
                {"key_hex": f"{key:02x}", "score": round(score, 4), "score_margin": round(score - runner_up, 4),
                 "printable_ratio": round(printable_ratio, 4), "flag_shape": flag_shape,
                 "plaintext_hex": plain.hex(), "plaintext_utf8": plain.decode("utf-8", "replace")},
                ["Ciphertext represents repeated single-byte XOR.", "Plaintext resembles printable CTF text."],
                "Try all 256 keys and rank decoded text. The highest-scoring key and plaintext are included.",
                {"kind": "xor_single_byte", "key": key, "result_hex": plain.hex()},
                "Replace XOR obfuscation with authenticated encryption and a unique nonce."
            ))
        repeating = _repeating_xor_candidate(data)
        if repeating:
            repeated_key, repeated_plain, repeated_score = repeating
            findings.append(Finding(
                "XOR-REPEATING-KEY", "Repeating-key XOR plaintext recovered", "high", "high",
                f'{record["location"]}.{record["field"]}',
                {"key_hex": repeated_key.hex(), "key_length": len(repeated_key), "score": round(repeated_score, 4),
                 "plaintext_hex": repeated_plain.hex(), "plaintext_utf8": repeated_plain.decode("utf-8", "replace"),
                 "flag_shape": True},
                ["Ciphertext uses a short repeating XOR key.", "Recovered plaintext contains a CTF flag-shaped token and is at least 90% printable."],
                "Transpose ciphertext by candidate key length, solve each column, and repeat the recovered key across the ciphertext.",
                {"kind": "xor_repeating_key", "key_hex": repeated_key.hex(), "result_hex": repeated_plain.hex()},
                "Use authenticated encryption with a random key and a unique nonce."
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

    stream_records = [item for item in byte_records if any(token in item["field"].casefold() for token in ("xor", "stream", "otp"))]
    for i, left in enumerate(stream_records[:512]):
        for right in stream_records[i + 1:512]:
            if left["scope"] != right["scope"]:
                continue
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
                    ["Field names identify both values as stream, OTP, or XOR ciphertexts.", "Both values align at offset zero.", "Natural-language plaintext contains spaces."],
                    "C1 xor C2 removes the keystream. Crib-drag likely words to recover both plaintexts and the reused keystream.",
                    {"kind": "xor_crib_drag", "combined_hex": xored.hex()},
                    "Generate a unique nonce for every encryption under a key and reject nonce reuse."
                ))

    # Explicit nonce reuse in structured records.
    nonce_groups: dict[tuple[str, str, bytes], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        obj = record["object"]
        nonce = parse_bytes(_pick(obj, "nonce", "iv"))
        cipher = parse_bytes(_pick(obj, "ciphertext", "ct", "encrypted"))
        mode = str(_pick(obj, "mode", "algorithm", "alg") or "").casefold()
        explicit_key_id = _pick(obj, "key_id", "kid", "keyid")
        key_id = str(explicit_key_id or "unknown-key")
        if nonce and cipher and any(token in mode for token in ("ctr", "gcm", "chacha")):
            nonce_groups[(record["scope"], key_id, nonce)].append({**record, "nonce": nonce, "cipher": cipher, "mode": mode})
    for (_, key_id, nonce), group in sorted(nonce_groups.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])):
        if len(group) < 2:
            continue
        for i, left in enumerate(group):
            for right in group[i + 1 :]:
                length = min(len(left["cipher"]), len(right["cipher"]))
                combined = bytes(a ^ b for a, b in zip(left["cipher"][:length], right["cipher"][:length]))
                is_gcm = "gcm" in left["mode"] or "gcm" in right["mode"]
                rule = "GCM-NONCE-REUSE" if is_gcm else "CTR-NONCE-REUSE"
                findings.append(Finding(
                    rule, f'{"GCM" if is_gcm else "CTR/stream"} nonce reuse', "critical", "certain" if key_id != "unknown-key" else "medium",
                    f'{left["location"]} + {right["location"]}',
                    {"key_id": key_id, "nonce_hex": nonce.hex(), "ciphertexts_xor_hex": combined.hex()},
                    (["Records use the same explicit key identifier and nonce.", "Ciphertexts start at the same stream offset."]
                     if key_id != "unknown-key" else ["Records use the same nonce and mode, but omit a key identifier.", "Confirm both records use the same key."]),
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
    for doc in documents:
        for rule, title, severity, pattern, attack, patch in rules:
            regex = re.compile(pattern, re.IGNORECASE)
            for match in regex.finditer(doc.text):
                line = doc.text.count("\n", 0, match.start()) + 1
                excerpt = doc.text.splitlines()[line - 1].strip()[:200]
                if excerpt.startswith(("#", "//", "/*", "*")):
                    continue
                if rule == "HASH-WEAK" and not re.search(
                    r"(?:digest|hash|signature|sign|verify|password|token|flag|secret|mac|checksum)\s*=|==|!=|return\s+",
                    excerpt,
                    re.IGNORECASE,
                ):
                    continue
                if rule == "HASH-WEAK" and re.search(r"(?:secret|key)\s*\+", excerpt, re.IGNORECASE):
                    continue
                findings.append(Finding(
                    rule, title, severity, "medium", f"{doc.path}:{line}",
                    {"match": match.group(0), "line": excerpt},
                    ["Matched code executes in the challenge cryptographic path."], attack,
                    {"kind": "source_guidance", "matched_pattern": rule}, patch
                ))
    return findings
