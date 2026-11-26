"""Decode explicitly described, layered challenge encoding pipelines.

The recognizer takes the stage names and payload from the supplied evidence;
the implementation reverses only known, deterministic codecs and never
evaluates challenge-provided code.
"""
from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class TransformPipeline:
    stages: tuple[str, ...]
    payload: bytes
    source_path: str


_STAGE_ALIASES = {
    "base64": "base64",
    "b64": "base64",
    "base64url": "base64url",
    "base64_url": "base64url",
    "hex": "hex",
    "hexadecimal": "hex",
    "rot13": "rot13",
    "base32": "base32",
    "b32": "base32",
    "base85": "base85",
    "b85": "base85",
    "ascii85": "ascii85",
    "a85": "ascii85",
    "url": "url",
    "urlencode": "url",
    "percent": "url",
}
_ROT13 = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def _normalize_stage(name: str) -> str | None:
    return _STAGE_ALIASES.get(name.strip().casefold().replace("-", "_"))


def _pipeline(source: str) -> tuple[str, ...] | None:
    match = re.search(
        r"(?i)\bpipeline\s*:\s*"
        r"([a-z][a-z0-9_-]*(?:\s*->\s*[a-z][a-z0-9_-]*)+)",
        source,
    )
    if match is None:
        return None
    names = re.split(r"\s*->\s*", match.group(1))
    stages = tuple(_normalize_stage(name) for name in names)
    if any(stage is None for stage in stages):
        return None
    return tuple(stage for stage in stages if stage is not None)


def _payload(source: str) -> bytes | None:
    block = re.search(
        r"(?is)RAW\s+(?:[A-Z0-9_-]+\s+)*BUFFER[^\r\n]*"
        r"(.*?)"
        r"(?:END\s+OF\s+RAW\s+BUFFER|\Z)",
        source,
    )
    if block is not None:
        lines = []
        for line in block.group(1).splitlines():
            line = re.sub(r"^\s*\\?#\s?", "", line).strip()
            # Chat transcripts and shell continuations may add a trailing
            # backslash to each wrapped data line; it is not a codec byte.
            line = line.rstrip("\\").rstrip()
            if line:
                lines.append(line)
        value = "".join(lines)
        if value:
            try:
                return value.encode("ascii")
            except UnicodeEncodeError:
                return None

    # Support common named payload fields when the challenge does not use a
    # delimited raw-buffer block.
    match = re.search(
        r"(?im)^\s*(?:raw[_ -]?buffer|payload|ciphertext|encoded[_ -]?data)"
        r"\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{16,})",
        source,
    )
    if match is not None:
        return match.group(1).encode("ascii")
    return None


def extract_instance(documents: Sequence[object]) -> TransformPipeline | None:
    """Pair a declared codec chain with its payload within one challenge scope."""
    declarations: dict[tuple[str, ...], str] = {}
    payloads: dict[bytes, str] = {}
    for document in documents:
        source = getattr(document, "text", "")
        stages = _pipeline(source)
        payload = _payload(source)
        path = getattr(document, "path", "<document>")
        if stages and payload:
            return TransformPipeline(stages, payload, path)
        if stages:
            declarations.setdefault(stages, path)
        if payload:
            payloads.setdefault(payload, path)

    # Challenge instructions and their attached telemetry dump are often
    # separate files. Pair only when the scope has one unambiguous pipeline
    # and one unambiguous payload; never mix multiple candidate artifacts.
    if len(declarations) == 1 and len(payloads) == 1:
        stages, source_path = next(iter(declarations.items()))
        payload, _ = next(iter(payloads.items()))
        return TransformPipeline(stages, payload, source_path)

    # Some challenge bundles contain only the encoded buffer. In that case,
    # infer a short chain from the supported reversible codecs and require a
    # flag-shaped plaintext before accepting the result.
    if not declarations and len(payloads) == 1:
        payload, source_path = next(iter(payloads.items()))
        inferred = _infer_pipeline(payload)
        if inferred is not None:
            return TransformPipeline(inferred[0], payload, source_path)
    return None

def _decode_stage(data: bytes, stage: str) -> bytes:
    compact = re.sub(rb"\s+", b"", data)
    if stage == "rot13":
        try:
            compact.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("ROT13 stage input is not ASCII") from exc
        return compact.translate(_ROT13)
    if stage == "hex":
        try:
            return bytes.fromhex(data.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("hex stage received malformed hexadecimal data") from exc
    if stage == "base64":
        try:
            return base64.b64decode(compact, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("base64 stage received malformed input") from exc
    if stage == "base64url":
        padded = compact + b"=" * (-len(compact) % 4)
        try:
            return base64.b64decode(padded, altchars=b"-_", validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("base64url stage received malformed input") from exc
    if stage == "base32":
        padded = compact.upper() + b"=" * (-len(compact) % 8)
        try:
            return base64.b32decode(padded, casefold=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("base32 stage received malformed input") from exc
    if stage == "base85":
        try:
            return base64.b85decode(compact)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("base85 stage received malformed input") from exc
    if stage == "ascii85":
        try:
            return base64.a85decode(data, adobe=True, ignorechars=b" \t\n\r\v")
        except (ValueError, base64.binascii.Error) as exc:
            try:
                return base64.a85decode(data, ignorechars=b" \t\n\r\v")
            except (ValueError, base64.binascii.Error) as nested:
                raise ValueError("ascii85 stage received malformed input") from nested
    if stage == "url":
        try:
            return urllib.parse.unquote_to_bytes(data.decode("ascii"))
        except UnicodeDecodeError as exc:
            raise ValueError("URL-encoded stage input is not ASCII") from exc
    raise ValueError(f"unsupported transform stage: {stage}")



def _infer_pipeline(payload: bytes, max_stages: int = 4) -> tuple[tuple[str, ...], bytes] | None:
    """Infer a bounded codec chain only when it yields one unique flag."""
    import itertools

    codecs = tuple(dict.fromkeys(_STAGE_ALIASES.values()))
    found: dict[bytes, list[tuple[str, ...]]] = {}
    for depth in range(1, max_stages + 1):
        for decode_order in itertools.product(codecs, repeat=depth):
            output = payload
            try:
                for stage in decode_order:
                    output = _decode_stage(output, stage)
            except (ValueError, UnicodeError):
                continue
            flag = re.search(
                rb"[A-Za-z][A-Za-z0-9_]{0,31}\{[^\r\n}]{1,200}\}",
                output,
            )
            if flag is not None:
                flag_bytes = flag.group()
                encoding_order = tuple(reversed(decode_order))
                found.setdefault(flag_bytes, []).append(encoding_order)
    if len(found) != 1:
        return None
    flag, chains = next(iter(found.items()))
    chain = min(chains, key=lambda item: (len(item), item))
    return chain, flag

def decode_pipeline(model: TransformPipeline) -> bytes:
    """Reverse the documented encoding order, one codec at a time."""
    output = model.payload
    for stage in reversed(model.stages):
        output = _decode_stage(output, stage)
    return output


def recover_flag(documents: Sequence[object]) -> str:
    """Decode the payload and return its flag, or decoded text if none is present."""
    model = extract_instance(documents)
    if model is None:
        raise ValueError(
            "source does not contain both a supported PIPELINE declaration "
            "and a recognizable payload"
        )
    decoded = decode_pipeline(model)
    flag = re.search(
        rb"[A-Za-z][A-Za-z0-9_]{0,31}\{[^\r\n}]{1,200}\}",
        decoded,
    )
    if flag is not None:
        return flag.group().decode("ascii")
    return decoded.decode("utf-8", errors="replace").strip()
