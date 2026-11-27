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

from .model import FLAG_PATTERN


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
    "bigint": "bigint",
    "big_integer": "bigint",
    "integer": "bigint",
    "bytes_to_long": "bigint",
    "utf8": "utf8",
    "utf_8": "utf8",
}
_ROT13 = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
_UNLABELED_HEX = re.compile(
    r"(?<![A-Za-z0-9])(?:[0-9a-fA-F]{2}){8,}(?![A-Za-z0-9])"
)
_UNLABELED_BASE64 = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{16,}(?![A-Za-z0-9+/=_-])"
)


def _normalize_stage(name: str) -> str | None:
    return _STAGE_ALIASES.get(name.strip().casefold().replace("-", "_"))


def _pipeline(source: str) -> tuple[str, ...] | None:
    match = re.search(
        r"(?i)\bpipeline\s*:\s*"
        r"([a-z][a-z0-9_-]*(?:\s*->\s*[a-z][a-z0-9_-]*)*)",
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
        r"(?ims)^[ \t]*RAW(?:[ \t]+[A-Z][A-Z0-9_-]*)*[ \t]+BUFFER[^\r\n]*"
        r"\r?\n(.*?)(?:^[ \t]*END OF RAW BUFFER[ \t]*$|\Z)",
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
    return _pair_declared(declarations, payloads) or _infer_single_payload(declarations, payloads) or _infer_unlabeled(documents, declarations, payloads)


def _pair_declared(declarations: dict, payloads: dict) -> TransformPipeline | None:
    if len(declarations) != 1 or len(payloads) != 1:
        return None
    stages, path = next(iter(declarations.items()))
    payload = next(iter(payloads))
    return TransformPipeline(stages, payload, path)


def _infer_single_payload(declarations: dict, payloads: dict) -> TransformPipeline | None:
    if declarations or len(payloads) != 1:
        return None
    payload, path = next(iter(payloads.items()))
    inferred = _infer_pipeline(payload)
    return TransformPipeline(inferred[0], payload, path) if inferred else None


def _infer_unlabeled(documents: Sequence[object], declarations: dict,
                     payloads: dict) -> TransformPipeline | None:
    if declarations or payloads:
        return None
    found = _unlabeled_flag_candidates(documents)
    return next(iter(found.values())) if len(found) == 1 else None


def _unlabeled_flag_candidates(documents: Sequence[object]) -> dict[bytes, TransformPipeline]:
    found: dict[bytes, TransformPipeline] = {}
    budget = 32
    for document in documents:
        if budget <= 0:
            break
        source = getattr(document, "text", "")
        path = getattr(document, "path", "<document>")
        for match in _unlabeled_candidates(source)[:budget]:
            budget -= 1
            _record_inferred_candidate(found, match.group().encode("ascii"), path)
    return found


def _unlabeled_candidates(source: str):
    candidates = list(_UNLABELED_HEX.finditer(source))
    if re.search(r"\bbase64(?:url)?\b", source, re.IGNORECASE):
        candidates.extend(_UNLABELED_BASE64.finditer(source))
    return candidates


def _record_inferred_candidate(found: dict, payload: bytes, path: str) -> None:
    inferred = _infer_pipeline(payload)
    if inferred is not None:
        stages, flag = inferred
        found.setdefault(flag, TransformPipeline(stages, payload, path))

def _decode_stage(data: bytes, stage: str) -> bytes:
    decoders = {
        "rot13": _decode_rot13, "hex": _decode_hex,
        "base64": _decode_base64, "base64url": _decode_base64url,
        "base32": _decode_base32, "base85": _decode_base85,
        "ascii85": _decode_ascii85, "url": _decode_url,
        "bigint": _decode_bigint, "utf8": _decode_utf8,
    }
    decoder = decoders.get(stage)
    if decoder is None:
        raise ValueError(f"unsupported transform stage: {stage}")
    return decoder(data)


def _compact(data: bytes) -> bytes:
    return re.sub(rb"\s+", b"", data)


def _decode_rot13(data: bytes) -> bytes:
    compact = _compact(data)
    _require_ascii(compact, "ROT13 stage input is not ASCII")
    return compact.translate(_ROT13)


def _decode_hex(data: bytes) -> bytes:
    try:
        return bytes.fromhex(data.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("hex stage received malformed hexadecimal data") from exc


def _decode_base64(data: bytes) -> bytes:
    return _decode_base64_payload(_compact(data), "base64")


def _decode_base64_payload(data: bytes, label: str, altchars: bytes | None = None) -> bytes:
    try:
        return base64.b64decode(data, altchars=altchars, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError(f"{label} stage received malformed input") from exc


def _decode_base64url(data: bytes) -> bytes:
    compact = _compact(data)
    padded = compact + b"=" * (-len(compact) % 4)
    try:
        return _decode_base64_payload(padded, "base64url", altchars=b"-_")
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("base64url stage received malformed input") from exc


def _decode_base32(data: bytes) -> bytes:
    compact = _compact(data).upper()
    padded = compact + b"=" * (-len(compact) % 8)
    try:
        return base64.b32decode(padded, casefold=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("base32 stage received malformed input") from exc


def _decode_base85(data: bytes) -> bytes:
    try:
        return base64.b85decode(_compact(data))
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("base85 stage received malformed input") from exc


def _decode_ascii85(data: bytes) -> bytes:
    try:
        return base64.a85decode(data, adobe=True, ignorechars=b" \t\n\r\v")
    except (ValueError, base64.binascii.Error):
        return _decode_ascii85_plain(data)


def _decode_ascii85_plain(data: bytes) -> bytes:
    try:
        return base64.a85decode(data, ignorechars=b" \t\n\r\v")
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("ascii85 stage received malformed input") from exc


def _decode_url(data: bytes) -> bytes:
    try:
        return urllib.parse.unquote_to_bytes(data.decode("ascii"))
    except UnicodeDecodeError as exc:
        raise ValueError("URL-encoded stage input is not ASCII") from exc


def _decode_bigint(data: bytes) -> bytes:
    """Convert a decimal or 0x-prefixed unsigned integer to minimal bytes."""
    try:
        text = data.decode("ascii").strip()
        value = int(text, 0 if text.lower().startswith("0x") else 10)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("bigint stage received malformed input") from exc
    if value < 0 or value.bit_length() > 32768:
        raise ValueError("bigint stage accepts unsigned values of at most 32768 bits")
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _decode_utf8(data: bytes) -> bytes:
    """Validate a UTF-8 stage while preserving the exact encoded bytes."""
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("utf8 stage received malformed input") from exc
    return data


def decode_typed_encoding(encoding: str, encoded: object) -> bytes:
    """Decode one explicitly typed challenge value without evaluating source."""
    stage = _normalize_stage(encoding)
    if stage is None:
        raise ValueError("unsupported typed encoding")
    if stage == "bigint":
        if type(encoded) is int:
            raw = str(encoded).encode("ascii")
        elif isinstance(encoded, str):
            raw = encoded.encode("ascii")
        else:
            raise ValueError("bigint payload must be an integer or decimal string")
    elif isinstance(encoded, str):
        raw = encoded.encode("utf-8")
    else:
        raise ValueError("text encoding payload must be a string")
    return _decode_stage(raw, stage)


def _require_ascii(data: bytes, message: str) -> None:
    try:
        data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(message) from exc



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
    recognized_flags = {
        flag: chains for flag, chains in found.items()
        if FLAG_PATTERN.search(flag) is not None
    }
    if recognized_flags:
        found = recognized_flags
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
