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

from .parser import Document
from .source_context import discover_token_recipes, linked_recipe, relevant_source, TokenRecipe

HEX = re.compile(r"^[0-9a-fA-F]+$")


def _ask(prompt: str, read: Callable[[str], str]) -> str:
    return read(prompt).strip()


def _bytes(text: str, encoding: str) -> bytes:
    if encoding == "hex":
        return bytes.fromhex(text.removeprefix("0x"))
    return text.encode("utf-8")


def auth_evidence_workflow(
    read: Callable[[str], str] = input,
    write: Callable[[str], Any] = print,
) -> dict[str, dict[str, str | None]]:
    """Collect observations independently; never treat their separator as a token format."""
    write("Authentication observations: enter each field separately.")
    write("Leave any unknown value blank. Cookie values are opaque until their codec is established.")
    labels = (
        ("username", "Username"),
        ("password", "Password"),
        ("role", "Role"),
        ("cookie", "Auth cookie"),
    )
    evidence: dict[str, dict[str, str | None]] = {"observed": {}, "target": {}}
    for group, prefix in (("observed", "Observed"), ("target", "Target")):
        for key, label in labels:
            value = _ask(f"{prefix} {label} (blank if unknown): ", read)
            evidence[group][key] = value or None
    write("Evidence captured separately (passwords and cookie values are not printed).")
    for group in ("observed", "target"):
        for key in ("username", "role"):
            write(f"  {group}.{key}: {evidence[group][key] or '<unknown>'}")
        for key in ("password", "cookie"):
            write(f"  {group}.{key}: {'provided' if evidence[group][key] is not None else 'unknown'}")
    write("No cryptographic relationship between these fields has been established.")
    write("Inspect the token-generation/verification code or matching finding before computing a replacement.")
    return evidence


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


def rewrite_record_workflow(read: Callable[[str], str] = input, write: Callable[[str], Any] = print) -> None:
    """Rewrite delimited fields with an explicitly declared checksum/MAC formula."""
    original = _ask("Original delimited record: ", read)
    separator = _ask("Delimiter [;]: ", read) or ";"
    parts = original.split(separator)
    write(f"Detected {len(parts)} fields. Indices are 1-based.")
    for index, value in enumerate(parts, 1):
        write(f"  {index}: {value}")
    try:
        edits = _ask("Fields to change (comma-separated indices): ", read)
        for entry in [item.strip() for item in edits.split(",") if item.strip()]:
            index = int(entry) - 1
            if not 0 <= index < len(parts):
                raise ValueError("field index out of range")
            parts[index] = _ask(f"Replacement for field {index + 1}: ", read)
        digest_index_raw = _ask("Digest/MAC field index (leave blank if none): ", read)
        if not digest_index_raw:
            write("Candidate record (without recomputed integrity): " + separator.join(parts))
            return
        digest_index = int(digest_index_raw) - 1
        if not 0 <= digest_index < len(parts):
            raise ValueError("digest field index out of range")
        message_indices_raw = _ask("Signed field indices (comma-separated, in order): ", read)
        indices = [int(part.strip()) - 1 for part in message_indices_raw.split(",")]
        if not indices or any(not 0 <= index < len(parts) or index == digest_index for index in indices):
            raise ValueError("invalid signed field indices")
        algorithm = _ask("Hash algorithm [sha256]: ", read) or "sha256"
        mode = (_ask("Mode [plain/prefix/suffix/hmac] (plain): ", read) or "plain").lower()
        if mode not in {"plain", "prefix", "suffix", "hmac"}:
            raise ValueError("invalid digest mode")
        secret = b""
        if mode != "plain":
            value = _ask("Known secret/key (blank if unavailable): ", read)
            if not value:
                write("Cannot calculate: MAC key is unknown. Obtain source details or an oracle.")
                return
            encoding = (_ask("Secret encoding [utf8/hex] (utf8): ", read) or "utf8").lower()
            if encoding not in {"utf8", "hex"}:
                raise ValueError("invalid secret encoding")
            secret = _bytes(value, encoding)
        separator_signed = _ask("Separator between signed fields [same]: ", read) or separator
        signed = separator_signed.join(parts[index] for index in indices).encode()
        parts[digest_index] = _digest(signed, algorithm, mode, secret)
        write("Computed record: " + separator.join(parts))
        write("Only valid if the declared digest formula, key and field encoding match the target.")
    except (ValueError, IndexError) as exc:
        write("Cannot calculate: " + str(exc))


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


def source_verified_token_workflow(
    recipe: TokenRecipe,
    read: Callable[[str], str] = input,
    write: Callable[[str], Any] = print,
) -> None:
    """Derive a minimal token solely from source-required JSON fields."""
    from .cookie import transform_json_cookie
    from .http_cookie import cookie_request_header, local_cookie_parse_check

    write(f"Builder: {recipe.build.path}:{recipe.build.line} ({recipe.build.function})")
    write(f"Verifier: {recipe.verify.path}:{recipe.verify.line} ({recipe.verify.function})")
    write(f"Source format: {recipe.format}")
    write("Builder plaintext fields: " + ", ".join(recipe.fields))
    write("Verifier-required fields: " + ", ".join(recipe.required_fields))
    write("Verifier constraints: " + ", ".join(
        f"{name} == {value!r}" for name, value in recipe.required_values
    ))
    if recipe.cookie_name:
        write(f"Cookie name in source: {recipe.cookie_name}")
    write("Only observed builder fields and the cookie are needed; no unverified credentials.")
    write("WARNING: authentication tag will be invalid and is retained only because the verifier ignores it.")
    known_values = {
        name: _ask(f"Observed {name} (exact): ", read) for name in recipe.fields
    }
    cookie = _ask("Observed cookie value (ciphertext_hex;tag_hex): ", read)
    required = dict(recipe.required_values)
    try:
        token, plaintext = transform_json_cookie(cookie, known_values, required)
    except ValueError as exc:
        write("Cannot derive token from current evidence: " + str(exc))
        return
    write("Minimal plaintext: " + plaintext.decode("utf-8"))
    write("Candidate cookie: " + token)
    if recipe.cookie_name:
        write("HTTP header for Burp Repeater: " + cookie_request_header(recipe.cookie_name, token))
        write("Local Cookie header parse roundtrip: " + ("OK" if local_cookie_parse_check(recipe.cookie_name, token) else "FAILED"))
    write("Locally derived, NOT remotely verified. The MAC/tag is invalid for modified ciphertext.")


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
    documents: Sequence[Document] = (),
) -> None:
    recipes = discover_token_recipes(documents)
    write("Offline CryptoScan assistant (CTF/authorized tasks).")
    if documents:
        write(f"Source context loaded: {len(documents)} analyzed documents; {len(recipes)} verified token recipe(s).")
    else:
        write("No analyzed source loaded. Provide a scan target to enable source-derived workflows.")
    write("Findings are evidence, not guarantees. Never assume the MAC/key or token format.")
    while True:
        for index, finding in enumerate(findings, 1):
            write(f"  {index}. [{finding.severity.upper()}] {finding.rule}: {finding.title}")
        write("  e. Enter separate authentication evidence (username/password/role/cookie)")
        write("  t. Inspect a captured token or delimited record")
        write("  h. Calculate / compare a digest (plain, secret prefix/suffix, HMAC)")
        write("  x. Known-plaintext XOR transformation")
        write("  r. Rewrite delimited record with declared digest/MAC formula")
        write("  q. Quit")
        try:
            selection = _ask("Choose a finding or operation: ", read).lower()
        except (EOFError, KeyboardInterrupt):
            write("Session ended.")
            return
        if selection in {"q", "quit", "0", ""}:
            return
        if selection == "e":
            auth_evidence_workflow(read, write)
        elif selection == "t":
            inspect_record(_ask("Captured token/record: ", read), write)
        elif selection == "h":
            digest_workflow(read, write)
        elif selection == "x":
            xor_workflow(read, write)
        elif selection == "r":
            rewrite_record_workflow(read, write)
        elif selection.isdecimal() and 1 <= int(selection) <= len(findings):
            finding = findings[int(selection) - 1]
            _show_finding(finding, write)
            for context in relevant_source(finding, documents):
                write(f"Analyzed source: {context.path}:{context.line} in {context.function}")
                write(f"  {context.excerpt}")
            recipe = linked_recipe(finding, recipes)
            if recipe:
                write("Source-verified token construction and unchecked authentication path found.")
                choice = _ask("Use this source-derived token workflow? [y/N]: ", read)
                if choice.casefold() in {"y", "yes"}:
                    source_verified_token_workflow(recipe, read, write)
                continue
            if finding.rule in {"CTR-NONCE-REUSE", "GCM-NONCE-REUSE", "NONCE-CONSTANT", "XOR-REPEATING-KEY"}:
                write("Source did not establish a compatible token format or verifier.")
                choice = _ask("Run a generic XOR worksheet anyway (not source-verified)? [y/N]: ", read)
                if choice.casefold() in {"y", "yes"}:
                    xor_workflow(read, write)
            elif finding.rule in {"MAC-PREFIX-HASH", "HASH-WEAK", "SHA1-LENGTH-EXTENSION"}:
                write("No source-verified digest serialization for this finding.")
                choice = _ask("Run a generic digest worksheet anyway? [y/N]: ", read)
                if choice.casefold() in {"y", "yes"}:
                    digest_workflow(read, write)
            else:
                write("No verified interactive calculator for this rule yet; inspect the solver and preconditions.")
        else:
            write("Unrecognized option.")
