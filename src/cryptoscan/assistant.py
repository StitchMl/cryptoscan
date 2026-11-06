"""Interactive, offline cryptanalysis assistant driven by cryptoscan findings.

Workflows are intentionally generic and conservative: a detector match is not
proof of exploitability; the assistant asks for evidence before calculating.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable, Sequence
from typing import Any

HEX = re.compile(r"^[0-9a-fA-F]+$")


def _ask(prompt: str, read: Callable[[str], str]) -> str:
    return read(prompt).strip()


def _bytes(text: str, encoding: str) -> bytes:
    if encoding == "hex":
        return bytes.fromhex(text.removeprefix("0x"))
    return text.encode("utf-8")


def inspect_record(record: str, write: Callable[[str], Any] = print) -> None:
    """Diagnose a delimited token without assuming its layout or MAC scheme."""
    parts = record.split(";")
    write(f"Fields: {len(parts)} (separator: semicolon)")
    for index, value in enumerate(parts, 1):
        is_hex = bool(value) and bool(HEX.fullmatch(value))
        detail = f", {len(value)} hex characters ({len(value) // 2} bytes)" if is_hex and len(value) % 2 == 0 else ""
        if is_hex and len(value) % 2:
            detail = f", {len(value)} hex characters (odd length)"
        write(f"  {index}: {value}{detail}")
    last = parts[-1] if parts else ""
    if HEX.fullmatch(last or ""):
        common = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
        write("Last field: " + (f"length matches {common[len(last)]}, but is not proof of algorithm" if len(last) in common else "nonstandard digest length; inspect encoding, concatenation or truncation"))
    write("No role, password, key, or signature can be inferred solely from the delimiters.")


def _digest(message: bytes, algorithm: str, mode: str, secret: bytes) -> str:
    try:
        hashlib.new(algorithm)
    except ValueError as exc:
        raise ValueError(f"Unsupported digest algorithm: {algorithm}") from exc
    if mode == "plain":
        return hashlib.new(algorithm, message).hexdigest()
    if mode == "prefix":
        return hashlib.new(algorithm, secret + message).hexdigest()
    if mode == "suffix":
        return hashlib.new(algorithm, message + secret).hexdigest()
    if mode == "hmac":
        return hmac.new(secret, message, algorithm).hexdigest()
    raise ValueError("unknown digest mode")


def digest_workflow(read: Callable[[str], str] = input, write: Callable[[str], Any] = print) -> None:
    write("Digest calculator: requires the exact algorithm and signed-byte format.")
    algorithm = _ask("Hash algorithm [sha256]: ", read) or "sha256"
    mode = (_ask("Mode [plain/prefix/suffix/hmac] (plain): ", read) or "plain").lower()
    if mode not in {"plain", "prefix", "suffix", "hmac"}:
        write("Unsupported mode.")
        return
    message = _ask("Exact message to hash (UTF-8; include separators): ", read)
    secret = b""
    if mode != "plain":
        value = _ask("Known key/secret (leave blank if unknown): ", read)
        if not value:
            write("Cannot calculate without the secret. A source finding does not reveal it.")
            return
        encoding = (_ask("Secret encoding [utf8/hex] (utf8): ", read) or "utf8").lower()
        try:
            secret = _bytes(value, encoding)
        except ValueError:
            write("Invalid key encoding.")
            return
    try:
        digest = _digest(message.encode(), algorithm, mode, secret)
    except ValueError as exc:
        write(str(exc))
        return
    write("Calculated digest: " + digest)
    supplied = _ask("Known digest to compare (optional): ", read).lower()
    if supplied:
        write("Digest matches: " + ("YES" if hmac.compare_digest(digest, supplied) else "NO"))


def xor_workflow(read: Callable[[str], str] = input, write: Callable[[str], Any] = print) -> None:
    write("Known-plaintext XOR/stream operation. Requires aligned ciphertext and plaintext.")
    ciphertext_hex = _ask("Known ciphertext (hex): ", read)
    encoding = (_ask("Known plaintext encoding [utf8/hex] (utf8): ", read) or "utf8").lower()
    plaintext = _ask("Known plaintext: ", read)
    target = _ask("Target plaintext (same encoding): ", read)
    try:
        ciphertext = bytes.fromhex(ciphertext_hex.removeprefix("0x"))
        known = _bytes(plaintext, encoding)
        desired = _bytes(target, encoding)
    except ValueError:
        write("Invalid hex encoding.")
        return
    if not known or not ciphertext or len(known) != len(ciphertext):
        write("Known plaintext must cover the ciphertext exactly.")
        return
    if len(desired) > len(known):
        write("Target exceeds the known keystream; acquire more known plaintext.")
        return
    keystream = bytes(a ^ b for a, b in zip(ciphertext, known))
    forged = bytes(a ^ b for a, b in zip(desired, keystream))
    write("Transformed ciphertext (hex): " + forged.hex())
    write("Validity is NOT established: check stream alignment, nonce reuse, tags and application semantics.")


def _show_finding(finding: Any, write: Callable[[str], Any]) -> None:
    write(f"Rule: {finding.rule} | severity: {finding.severity} | recovery: {finding.recovery_status}")
    write("Location: " + finding.location)
    for line in finding.preconditions:
        write("Precondition: " + line)
    for step in finding.playbook:
        write("  - " + step)
    write("Existing solver: " + json.dumps(finding.solver, ensure_ascii=False, sort_keys=True))


def assistant_session(
    findings: Sequence[Any] = (),
    read: Callable[[str], str] = input,
    write: Callable[[str], Any] = print,
) -> None:
    write("Offline CryptoScan assistant (CTF/authorized tasks).")
    write("Findings are evidence, not guarantees. Never assume the MAC/key or token format.")
    while True:
        for index, finding in enumerate(findings, 1):
            write(f"  {index}. [{finding.severity.upper()}] {finding.rule}: {finding.title}")
        write("  t. Inspect a captured token or delimited record")
        write("  h. Calculate / compare a digest (plain, secret prefix/suffix, HMAC)")
        write("  x. Known-plaintext XOR transformation")
        write("  q. Quit")
        try:
            selection = _ask("Choose a finding or operation: ", read).lower()
        except (EOFError, KeyboardInterrupt):
            write("Session ended.")
            return
        if selection in {"q", "quit", "0", ""}:
            return
        if selection == "t":
            inspect_record(_ask("Captured token/record: ", read), write)
        elif selection == "h":
            digest_workflow(read, write)
        elif selection == "x":
            xor_workflow(read, write)
        elif selection.isdecimal() and 1 <= int(selection) <= len(findings):
            finding = findings[int(selection) - 1]
            _show_finding(finding, write)
            if finding.rule in {"CTR-NONCE-REUSE", "GCM-NONCE-REUSE", "NONCE-CONSTANT", "XOR-REPEATING-KEY"}:
                choice = _ask("Try known-plaintext XOR with your own values? [y/N]: ", read)
                if choice.casefold() in {"y", "yes"}:
                    xor_workflow(read, write)
            elif finding.rule in {"MAC-PREFIX-HASH", "HASH-WEAK", "SHA1-LENGTH-EXTENSION"}:
                choice = _ask("Calculate a digest with known values? [y/N]: ", read)
                if choice.casefold() in {"y", "yes"}:
                    digest_workflow(read, write)
            else:
                write("No verified interactive calculator for this rule yet; inspect the solver and preconditions.")
        else:
            write("Unrecognized option.")
