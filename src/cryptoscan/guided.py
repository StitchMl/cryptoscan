"""Evidence-driven offline CTF workflows independent of challenge names.

Each operation requires the values that prove its computation. No network
requests, external AI, challenge-specific secrets, or guessed encodings.
"""
from __future__ import annotations

import json
import math
from collections.abc import Callable
from typing import Any

Read = Callable[[str], str]
Write = Callable[[str], Any]


def _integer(label: str, read: Read) -> int:
    raw = read(label).strip().replace("_", "")
    if not raw:
        raise ValueError("missing integer")
    return int(raw, 0) if raw.lower().startswith(("0x", "0b", "0o")) else int(raw)


def _hex(label: str, read: Read) -> bytes:
    value = read(label).strip().removeprefix("0x")
    if not value:
        raise ValueError("missing hex value")
    return bytes.fromhex(value)


def _show_bytes(label: str, data: bytes, write: Write) -> None:
    write(f"{label} (hex): {data.hex()}")
    try:
        write(f"{label} (UTF-8): {data.decode('utf-8')}")
    except UnicodeDecodeError:
        write(f"{label}: not valid UTF-8; use hex")


def rsa_factors_workflow(read: Read = input, write: Write = print) -> None:
    """Given verified RSA p/q, compute d and decrypt with modular roundtrip."""
    write("RSA from factors. Supply p, q, e, c from the SAME RSA key.")
    try:
        p = _integer("Prime p (decimal or 0x): ", read)
        q = _integer("Prime q (decimal or 0x): ", read)
        e = _integer("Public exponent e: ", read)
        c = _integer("Ciphertext integer c: ", read)
        if p <= 2 or q <= 2 or p == q:
            raise ValueError("distinct primes greater than 2 are required")
        if c < 0 or c >= p * q:
            raise ValueError("ciphertext must be between 0 and n-1")
        phi = (p - 1) * (q - 1)
        if e <= 1 or math.gcd(e, phi) != 1:
            raise ValueError("public exponent is not invertible modulo phi")
        d = pow(e, -1, phi)
        n = p * q
        plaintext = pow(c, d, n)
        if pow(plaintext, e, n) != c:
            raise ValueError("RSA re-encryption check failed")
        write("Computed modulus n: " + str(n))
        write("Computed private exponent d: " + str(d))
        _show_bytes("Recovered plaintext", plaintext.to_bytes(max(1, (plaintext.bit_length() + 7) // 8), "big"), write)
        write("Proof: pow(m, e, n) == c (PASS). Prime status of p/q not independently proven.")
    except ValueError as exc:
        write("Cannot calculate RSA: " + str(exc))


def cbc_iv_workflow(read: Read = input, write: Write = print) -> None:
    """Derive a first-block IV modification; no decryption or auth bypass claim."""
    write("CBC IV bit-flip. Only applies to unauthenticated CBC with a transmitted IV.")
    try:
        iv = _hex("Original IV (hex): ", read)
        original = _hex("Known first plaintext block (hex): ", read)
        desired = _hex("Desired first plaintext block (hex): ", read)
        if len(iv) not in (8, 16) or len(original) != len(iv) or len(desired) != len(iv):
            raise ValueError("IV, original and desired block must have equal 8/16-byte lengths")
        modified = bytes(a ^ b ^ c for a, b, c in zip(iv, original, desired))
        if bytes(a ^ b ^ c for a, b, c in zip(modified, iv, original)) != desired:
            raise ValueError("CBC XOR proof failed")
        write("Modified IV (hex): " + modified.hex())
        write("Local XOR proof: PASS. No claim of MAC acceptance or reachability.")
    except ValueError as exc:
        write("Cannot calculate CBC: " + str(exc))


def existing_verified_result(finding: Any, write: Write = print) -> bool:
    """Display only the solver already verified by the model's rule-specific checks."""
    status = finding.recovery_status
    if status not in {"payload-ready", "flag-recovered"}:
        return False
    solver = finding.solver
    write("Existing scanner computation: " + status)
    write("Solver kind: " + str(solver.get("kind", "unknown")))
    for key in ("result_hex", "message_hex", "digest_hex", "modified_iv_hex", "combined_hex"):
        value = solver.get(key)
        if isinstance(value, str):
            write(f"Verified {key}: {value}")
            if key == "result_hex":
                try:
                    _show_bytes("Recovered bytes", bytes.fromhex(value), write)
                except ValueError:
                    write("Recovered bytes: invalid hex in solver")
    for key in ("result_int", "p", "q1", "q2", "private_key_x", "nonce_k"):
        value = solver.get(key)
        if value is not None:
            write(f"Solver {key}: {value}")
    if finding.rule == "SHA1-LENGTH-EXTENSION":
        write("Verify the remote parser accepts SHA-1 glue padding and the key length.")
    write("Local mathematical verification is not confirmation of remote challenge acceptance.")
    return True


def selected_finding_workflow(finding: Any, read: Read = input, write: Write = print) -> None:
    """Offer only computations justified by the finding's family and evidence."""
    verified = existing_verified_result(finding, write)
    rule = finding.rule
    if rule.startswith("RSA-"):
        if rule in {"RSA-SHARED-PRIME", "RSA-CRT-FAULT", "RSA-PARAMETER-LEAK",
                    "RSA-WIENER-SMALL-D", "RSA-FERMAT-CLOSE-PRIMES", "RSA-SMALL-FACTOR"}:
            choice = read("Calculate RSA decryption using known p/q/e/c? [y/N]: ").strip().lower()
            if choice in {"y", "yes"}:
                rsa_factors_workflow(read, write)
        elif not verified:
            write("No verified RSA plaintext yet. Supply artifacts with modulus, exponent and ciphertext.")
    elif rule == "CBC-FIRST-BLOCK-BITFLIP":
        choice = read("Recalculate first-block IV modification with known values? [y/N]: ").strip().lower()
        if choice in {"y", "yes"}:
            cbc_iv_workflow(read, write)
    elif rule in {"CTR-NONCE-REUSE", "GCM-NONCE-REUSE"}:
        if not verified:
            write("Only nonce-reuse evidence. Need same key and aligned known plaintext to recover bytes.")
        else:
            write("Confirmed nonce-reuse computation shown above; GCM tag validity is separate.")
    elif rule in {"SIGNATURE-NONCE-REUSE", "SIGNATURE-NONCE-DISCLOSURE",
                  "LCG-STATE-RECOVERY", "MT19937-STATE-CLONE", "DH-SMALL-GROUP",
                  "DH-DEGENERATE-GENERATOR", "SHA1-LENGTH-EXTENSION",
                  "XOR-SINGLE-BYTE", "XOR-REPEATING-KEY"}:
        if not verified:
            write("Insufficient evidence for a verified solver. See finding preconditions.")
    elif not verified:
        write("No mathematically verified solver for this rule; source match alone is not an exploit.")
