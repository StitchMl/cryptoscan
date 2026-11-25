"""Recover small RSA plaintexts with a known-byte suffix oracle."""
from __future__ import annotations

import ast
import base64
import re
from dataclasses import dataclass
from typing import Sequence

from .network_policy import connect_authorized


@dataclass(frozen=True)
class RSASuffixOracleModel:
    exponent: int = 65537
    prompt: bytes = b"[cmd] "
    public_label: bytes = b"[pkey]"
    ciphertext_label: bytes = b"[shhh]"


def extract_instance(documents: Sequence[object]) -> RSASuffixOracleModel | None:
    """Recognize RSA decryption whose response tests the final plaintext byte."""
    for document in documents:
        source = getattr(document, "text", "")
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            continue
        has_private_pow = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "pow"
            and len(node.args) == 3
            and isinstance(node.args[1], ast.Attribute)
            and node.args[1].attr == "d"
            and isinstance(node.args[2], ast.Attribute)
            and node.args[2].attr == "n"
            for node in ast.walk(tree)
        )
        suffix_oracle = re.search(
            r"message\s*\[\s*-1\s*:\s*\]\s*!=\s*b(['\"])\.\1",
            source,
        )
        strings = {
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        if not has_private_pow or suffix_oracle is None:
            continue
        if not {"pkey", "read", "shhh", "send", "nice"}.issubset(strings):
            continue
        exponent = 65537
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr == "generate":
                for keyword in node.keywords:
                    if keyword.arg == "e" and isinstance(keyword.value, ast.Constant):
                        if isinstance(keyword.value.value, int):
                            exponent = keyword.value.value
        return RSASuffixOracleModel(exponent=exponent)
    return None


def _read_until(stream, marker: bytes, limit: int = 1 << 20) -> bytes:
    data = bytearray()
    while len(data) < limit:
        char = stream.read(1)
        if not char:
            raise ValueError("RSA service closed before returning its prompt")
        data.extend(char)
        if data.endswith(marker):
            return bytes(data)
    raise ValueError("RSA service prompt exceeded the input limit")


def _labeled_base64(response: bytes, label: bytes) -> bytes:
    match = re.search(re.escape(label) + rb"\s*([A-Za-z0-9+/=]+)", response)
    if match is None:
        raise ValueError(f"RSA response omitted {label.decode('ascii')} data")
    return base64.b64decode(match.group(1), validate=True)


def _int_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _query(stream, model: RSASuffixOracleModel, n: int, ciphertext: int,
           multiplier: int) -> bool:
    modified = pow(multiplier, model.exponent, n) * ciphertext % n
    encoded = base64.b64encode(_int_bytes(modified))
    stream.write(b"send " + encoded + b"\n")
    response = _read_until(stream, model.prompt)
    return any(
        line.strip() == b"nice"
        for line in response[:-len(model.prompt)].splitlines()
    )


def _wrap_interval(stream, model: RSASuffixOracleModel, n: int,
                   ciphertext: int) -> tuple[int, int]:
    residue = 0x81  # 0x2e * 0x81 == 0x2e (mod 256)
    if not _query(stream, model, n, ciphertext, residue):
        raise ValueError("secret plaintext does not have the oracle's known suffix")
    low = 0
    high = 1
    while _query(stream, model, n, ciphertext, residue + 256 * high):
        low = high
        high *= 16
        if high.bit_length() > 16384:
            raise ValueError("RSA wrap search exceeded its iteration bound")
    while high - low > 1:
        middle = (low + high) // 2
        if _query(stream, model, n, ciphertext, residue + 256 * middle):
            low = middle
        else:
            high = middle
    return residue + 256 * low, residue + 256 * high


def _recover_integer(n: int, ciphertext: int, exponent: int,
                     before: int, after: int) -> int:
    lower = (n + after - 1) // after
    upper = (n - 1) // before
    if lower > upper or upper - lower > 1_000_000:
        raise ValueError("RSA suffix oracle did not narrow to a bounded interval")
    matches = [
        value for value in range(lower, upper + 1)
        if pow(value, exponent, n) == ciphertext
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one RSA re-encryption match, found {len(matches)}")
    return matches[0]


def recover_flag(documents: Sequence[object], host: str, port: int,
                 timeout: float = 30.0) -> str:
    """Query the source-verified RSA oracle and return its re-encryption-verified flag."""
    model = extract_instance(documents)
    if model is None:
        raise ValueError("source does not establish the RSA suffix oracle")
    with connect_authorized(host, port, timeout) as sock:
        stream = sock.makefile("rwb", buffering=0)
        _read_until(stream, model.prompt)
        stream.write(b"pkey\n")
        public = _read_until(stream, model.prompt)
        n = int.from_bytes(_labeled_base64(public, model.public_label), "big")
        stream.write(b"read\n")
        encrypted = _read_until(stream, model.prompt)
        ciphertext = int.from_bytes(
            _labeled_base64(encrypted, model.ciphertext_label), "big",
        )
        before, after = _wrap_interval(stream, model, n, ciphertext)
        plaintext = _recover_integer(n, ciphertext, model.exponent, before, after)
    flag = re.search(
        rb"[a-z][a-z0-9_]{0,31}\{[^\r\n}]{1,200}\}",
        _int_bytes(plaintext),
        re.IGNORECASE,
    )
    if flag is None:
        raise ValueError("recovered plaintext contains no flag-shaped token")
    return flag.group().decode("ascii")
