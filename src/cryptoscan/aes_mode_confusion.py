"""Cross-mode AES keystream recovery for selectable encryption-mode services.

If one session offers CBC encryption of chosen plaintext and OFB encryption of
a secret under the same AES key and IV, CBC of zero blocks yields exactly the
OFB keystream. The recognizer only enables this online strategy when the
source establishes the shared key/IV and the selectable data/secret interface.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from .network_policy import connect_authorized


@dataclass(frozen=True)
class AESModePickerModel:
    cbc_mode: str
    ofb_mode: str
    data_selector: str
    secret_selector: str
    block_size: int = 16


def _string_list(source: str, variable: str) -> list[str] | None:
    match = re.search(
        rf"\b{re.escape(variable)}\s*=\s*\[([^\]]*)\]",
        source,
        re.DOTALL,
    )
    if match is None:
        return None
    return re.findall(r"['\"]([^'\"]+)['\"]", match.group(1))


def _constructor(source: str, mode: str) -> tuple[str, str | None] | None:
    if mode == "CBC":
        pattern = (
            r"\bAES\s*\.\s*new\s*\(\s*(\w+)\s*,\s*"
            r"AES\s*\.\s*MODE_CBC\s*,\s*(\w+)\s*\)"
        )
    else:
        pattern = (
            r"\bAES\s*\.\s*new\s*\(\s*(\w+)\s*,\s*"
            r"AES\s*\.\s*MODE_OFB\s*,\s*(\w+)\s*\)"
        )
    match = re.search(pattern, source, re.DOTALL)
    if match is None:
        return None
    return match.group(1), match.group(2)


def extract_instance(documents: Sequence[object]) -> AESModePickerModel | None:
    """Recognize a same-key/same-IV CBC-zero versus OFB-secret oracle."""
    source = "\n".join(getattr(document, "text", "") for document in documents)
    if not source:
        return None

    cbc = _constructor(source, "CBC")
    ofb = _constructor(source, "OFB")
    if cbc is None or ofb is None or cbc != ofb:
        return None

    modes = _string_list(source, "options")
    selectors = _string_list(source, "suboptions")
    if modes is None or selectors is None:
        return None
    cbc_mode = next((item for item in modes if item.lower() == "cbc"), None)
    ofb_mode = next((item for item in modes if item.lower() == "ofb"), None)
    data_selector = next((item for item in selectors if item.lower() == "data"), None)
    secret_selector = next((item for item in selectors if item.lower() == "flag"), None)
    if None in (cbc_mode, ofb_mode, data_selector, secret_selector):
        return None

    if not re.search(r"\boptions\s*\.\s*remove\s*\(\s*option\s*\)", source):
        return None
    if not re.search(r"\bmessage\s*=\s*flag\b", source):
        return None
    if not re.search(r"\bbytes\s*\.\s*fromhex\s*\(", source):
        return None
    if not re.search(r"\bcipher\s*\.\s*encrypt\s*\(\s*message\s*\)", source):
        return None

    return AESModePickerModel(cbc_mode, ofb_mode, data_selector, secret_selector)


def _read_until(stream, marker: bytes, limit: int = 8192) -> bytes:
    data = bytearray()
    while len(data) < limit:
        byte = stream.read(1)
        if not byte:
            break
        data.extend(byte)
        if data.endswith(marker):
            return bytes(data)
    raise ValueError("service did not present the expected mode-picker prompt")


def _read_line(stream, limit: int = 65536) -> bytes:
    data = bytearray()
    while len(data) < limit:
        byte = stream.read(1)
        if not byte:
            break
        if byte == b"\n":
            return bytes(data)
        data.extend(byte)
    if data:
        return bytes(data)
    raise ValueError("service closed before returning ciphertext")


def _encrypt_request(stream, mode: str, selector: str, data: bytes | None) -> bytes:
    command = f"{mode} {selector}"
    if data is not None:
        command += " " + data.hex()
    stream.write(command.encode("ascii") + b"\n")
    line = _read_line(stream).strip()
    try:
        return bytes.fromhex(line.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("service returned a non-hexadecimal ciphertext") from exc


def _decode_plaintext(plaintext: bytes) -> str:
    try:
        result = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("recovered plaintext is not UTF-8 text") from exc
    if not result:
        raise ValueError("recovered plaintext is empty")
    return result


def recover_flag(documents: Sequence[object], host: str, port: int,
                 timeout: float = 30.0) -> str:
    """Recover the secret in one session with the CBC/OFB cross-mode relation."""
    model = extract_instance(documents)
    if model is None:
        raise ValueError(
            "source does not establish a selectable shared-key/shared-IV "
            "CBC and OFB encryption oracle"
        )

    with connect_authorized(host, port, timeout) as sock:
        stream = sock.makefile("rwb", buffering=0)
        _read_until(stream, b"> ")
        ofb_ciphertext = _encrypt_request(
            stream, model.ofb_mode, model.secret_selector, None,
        )
        if not ofb_ciphertext:
            raise ValueError("OFB secret ciphertext is empty")
        chosen_length = (
            (len(ofb_ciphertext) + model.block_size - 1) // model.block_size
        ) * model.block_size
        chosen_plaintext = bytes(chosen_length)
        _read_until(stream, b"> ")
        cbc_keystream = _encrypt_request(
            stream, model.cbc_mode, model.data_selector, chosen_plaintext,
        )
        if len(cbc_keystream) < len(ofb_ciphertext):
            raise ValueError("CBC oracle returned fewer keystream bytes than OFB")
        plaintext = bytes(
            ciphertext_byte ^ stream_byte
            for ciphertext_byte, stream_byte
            in zip(ofb_ciphertext, cbc_keystream)
        )
        return _decode_plaintext(plaintext)
