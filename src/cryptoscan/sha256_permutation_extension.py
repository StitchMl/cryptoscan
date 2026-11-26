"""Chosen-permutation SHA-256 length extension for secret-prefix credentials."""
from __future__ import annotations

import ast
import base64
import hashlib
import itertools
import re
from dataclasses import dataclass
from typing import Sequence

from .network_policy import connect_authorized


_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)
_MASK = 0xFFFFFFFF
_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="


@dataclass(frozen=True)
class SHA256PermutationOracle:
    password_length: int
    salt_length: int
    alphabet: bytes
    prompt: bytes
    pbox_prompt: bytes
    salt_prompt: bytes
    hash_prompt: bytes
    flag_label: bytes
    spy_command: str
    auth_command: str


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | None:
    return next((
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    ), None)


def _label(source: str, name: str) -> bytes | None:
    match = re.search(r"\[" + re.escape(name) + r"\]\s*", source)
    if match is None:
        return None
    return ("[" + name + "] ").encode("ascii")

def extract_instance(documents: Sequence[object]) -> SHA256PermutationOracle | None:
    """Detect a chosen-order SHA-256 hash of password||salt in source."""
    for document in documents:
        source = getattr(document, "text", "")
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            continue
        if "hashlib.sha256" not in source or "payload[x] for x in pbox" not in source:
            continue
        if "password + salt" not in source or not _function(tree, "spy") or not _function(tree, "auth"):
            continue
        length_match = re.search(r"assert\s+len\(password\)\s*==\s*(\d+)", source)
        if length_match is None:
            continue
        password_length = int(length_match.group(1))
        preauth = _function(tree, "preauth")
        salt_length = None
        if preauth is not None:
            for node in ast.walk(preauth):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr == "urandom" and node.args and isinstance(node.args[0], ast.Constant):
                    if isinstance(node.args[0].value, int):
                        salt_length = node.args[0].value
                        break
        if salt_length is None:
            continue
        commands = re.findall(r"command\s*==\s*['\"]([^'\"]+)['\"]", source)
        if len(commands) < 2:
            continue
        input_prompts = re.findall(r"input\(\s*['\"](\[[^\]]+\]\s*)['\"]\s*\)", source)
        prompts = {item.strip().strip("[]").strip(): ("[" + item.strip()[1:-1] + "] ").encode() for item in input_prompts}
        required = ("cmd", "pbox", "salt", "hash")
        if any(name not in prompts for name in required):
            continue
        flag_label = _label(source, "flag")
        if flag_label is None:
            continue
        alphabet = _ALPHABET
        if "base64.b64encode" not in source:
            continue
        return SHA256PermutationOracle(
            password_length, salt_length, alphabet,
            prompts["cmd"], prompts["pbox"], prompts["salt"], prompts["hash"],
            flag_label, commands[0], commands[1],
        )
    return None


def _rotate(value: int, shift: int) -> int:
    return ((value >> shift) | (value << (32 - shift))) & _MASK


def _compress(state: list[int], block: bytes) -> list[int]:
    words = list(int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4))
    for index in range(16, 64):
        a = words[index - 15]
        b = words[index - 2]
        sigma0 = _rotate(a, 7) ^ _rotate(a, 18) ^ (a >> 3)
        sigma1 = _rotate(b, 17) ^ _rotate(b, 19) ^ (b >> 10)
        words.append((words[index - 16] + sigma0 + words[index - 7] + sigma1) & _MASK)
    a, b, c, d, e, f, g, h = state
    for index in range(64):
        sum1 = _rotate(e, 6) ^ _rotate(e, 11) ^ _rotate(e, 25)
        choose = (e & f) ^ (~e & g)
        temp1 = (h + sum1 + choose + _K[index] + words[index]) & _MASK
        sum0 = _rotate(a, 2) ^ _rotate(a, 13) ^ _rotate(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (sum0 + majority) & _MASK
        h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & _MASK, c, b, a, (temp1 + temp2) & _MASK
    return [
        (old + new) & _MASK
        for old, new in zip(state, (a, b, c, d, e, f, g, h), strict=True)
    ]


def _sha256_continue(digest: bytes, processed_length: int, suffix: bytes) -> bytes:
    """Continue SHA-256 from a digest after its glue-padding block(s)."""
    state = [int.from_bytes(digest[i:i + 4], "big") for i in range(0, 32, 4)]
    final_length = processed_length + len(suffix)
    tail = suffix + b"\x80"
    tail += b"\x00" * ((56 - (final_length + 1) % 64) % 64)
    tail += (final_length * 8).to_bytes(8, "big")
    for offset in range(0, len(tail), 64):
        state = _compress(state, tail[offset:offset + 64])
    return b"".join(word.to_bytes(4, "big") for word in state)


def _glue_padding(length: int) -> bytes:
    padding = b"\x80"
    padding += b"\x00" * ((56 - (length + 1) % 64) % 64)
    return padding + (length * 8).to_bytes(8, "big")


def _read_until(stream, marker: bytes, limit: int = 1 << 20) -> bytes:
    data = bytearray()
    while len(data) < limit:
        char = stream.read(1)
        if not char:
            raise ValueError("authentication service closed before its prompt")
        data.extend(char)
        if data.endswith(marker):
            return bytes(data)
    raise ValueError("authentication response exceeded the input limit")


def _spy(stream, model: SHA256PermutationOracle, pbox: list[int], salt: bytes) -> str:
    stream.write(model.spy_command.encode() + b"\n")
    _read_until(stream, model.pbox_prompt)
    stream.write((str(pbox) + "\n").encode())
    _read_until(stream, model.salt_prompt)
    stream.write(base64.b64encode(salt) + b"\n")
    response = _read_until(stream, model.prompt)
    match = re.search(rb"\[hash\]\s*([0-9a-fA-F]{64})", response)
    if match is None:
        raise ValueError("spy response did not contain a SHA-256 digest")
    return match.group(1).decode("ascii")


def _recover_password(stream, model: SHA256PermutationOracle) -> bytes:
    message_length = model.password_length + model.salt_length
    if message_length >= 32 or model.salt_length < 2:
        raise ValueError("source lengths exceed the supported one-byte glue-padding profile")
    padding = _glue_padding(message_length)
    if len(set(padding)) > model.salt_length:
        raise ValueError(
            "salt is too short to represent every byte of the SHA-256 glue padding"
        )

    # Pick salt bytes that can be re-indexed to reproduce the exact SHA-256
    # glue padding after the hashed password||salt prefix.
    salt = bytearray(model.salt_length)
    padding_indices: dict[int, int] = {}
    for offset, value in enumerate(dict.fromkeys(padding)):
        salt[offset] = value
        padding_indices[value] = model.password_length + offset

    base_hash = bytes.fromhex(
        _spy(stream, model, list(range(message_length)), bytes(salt))
    )
    processed_length = message_length + len(padding)
    if processed_length % 64:
        raise ValueError("computed SHA-256 glue padding is not block aligned")
    password = bytearray()
    for position in range(0, model.password_length, 2):
        positions = list(range(position, min(position + 2, model.password_length)))
        padding_box = list(range(message_length)) + [
            padding_indices[value] for value in padding
        ]
        target = _spy(stream, model, padding_box + positions, bytes(salt))
        matches = [
            bytes(candidate)
            for candidate in itertools.product(model.alphabet, repeat=len(positions))
            if _sha256_continue(
                base_hash, processed_length, bytes(candidate),
            ).hex() == target
        ]
        if len(matches) != 1:
            raise ValueError(f"expected one password match at offset {position}")
        password.extend(matches[0])
    return bytes(password)


def recover_flag(documents: Sequence[object], host: str, port: int,
                 timeout: float = 30.0) -> str:
    """Recover a permuted secret-prefix SHA-256 password and authenticate."""
    model = extract_instance(documents)
    if model is None:
        raise ValueError("source does not establish the chosen-permutation SHA-256 oracle")
    with connect_authorized(host, port, timeout) as sock:
        stream = sock.makefile("rwb", buffering=0)
        _read_until(stream, model.prompt)
        password = _recover_password(stream, model)
        stream.write(model.auth_command.encode() + b"\n")
        response = _read_until(stream, model.hash_prompt)
        pbox_match = re.search(rb"\[pbox\]\s*(\[[^\r\n]+\])", response)
        salt_match = re.search(rb"\[salt\]\s*([A-Za-z0-9+/=]+)", response)
        if pbox_match is None or salt_match is None:
            raise ValueError("auth challenge omitted its permutation or salt")
        pbox = ast.literal_eval(pbox_match.group(1).decode("ascii"))
        salt = base64.b64decode(salt_match.group(1), validate=True)
        payload = password + salt
        digest = hashlib.sha256(bytes(payload[index] for index in pbox)).hexdigest()
        stream.write(digest.encode("ascii") + b"\n")
        final = _read_until(stream, b"}")
    flag = re.search(
        rb"[a-z][a-z0-9_]{0,31}\{[^\r\n}]{1,200}\}",
        final,
        re.IGNORECASE,
    )
    if flag is None:
        raise ValueError("authentication did not return a flag-shaped token")
    return flag.group().decode("ascii")
