from __future__ import annotations

import ast
import base64
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable


@dataclass(frozen=True)
class Document:
    path: str
    text: str
    data: Any | None


INT_NAMES = {"n", "e", "c", "ciphertext", "modulus", "exponent"}
BYTE_NAMES = {"ciphertext", "ct", "data", "encrypted", "nonce", "iv", "tag"}


def collect_documents(targets: Iterable[str]) -> list[Document]:
    files: list[tuple[Path, Path]] = []
    for raw in targets:
        target = Path(raw).resolve()
        if target.is_dir():
            files.extend((target, p) for p in target.rglob("*") if p.is_file())
        elif target.is_file():
            files.append((target.parent, target))
    documents: list[Document] = []
    for root, path in sorted(files, key=lambda pair: pair[1].as_posix().casefold()):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\0" in raw[:4096]:
            continue
        text = raw.decode("utf-8", errors="replace")
        data = None
        if path.suffix.casefold() == ".json" or text.lstrip().startswith(("{", "[")):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                pass
        documents.append(Document(path.relative_to(root).as_posix(), text, data))
    return documents


def flatten_objects(data: Any, prefix: str = "$") -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    if isinstance(data, dict):
        found.append((prefix, data))
        for key in sorted(data):
            found.extend(flatten_objects(data[key], f"{prefix}.{key}"))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            found.extend(flatten_objects(item, f"{prefix}[{index}]"))
    return found


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        cleaned = value.strip().replace("_", "")
        try:
            return int(cleaned, 0)
        except ValueError:
            if cleaned.isdigit():
                return int(cleaned)
    return None


def parse_bytes(value: Any) -> bytes | None:
    if isinstance(value, list) and all(isinstance(x, int) and 0 <= x < 256 for x in value):
        return bytes(value)
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    hexed = cleaned[2:] if cleaned.casefold().startswith("0x") else cleaned
    hexed = re.sub(r"[\s:_-]", "", hexed)
    if len(hexed) >= 2 and len(hexed) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", hexed):
        try:
            return bytes.fromhex(hexed)
        except ValueError:
            pass
    if len(cleaned) >= 8 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", cleaned):
        try:
            return base64.b64decode(cleaned, validate=True)
        except (ValueError, base64.binascii.Error):
            pass
    return None


def assignments(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    pattern = re.compile(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^#\r\n]+)")
    for match in pattern.finditer(text):
        name, literal = match.groups()
        try:
            result[name.casefold()] = ast.literal_eval(literal.strip())
        except (ValueError, SyntaxError):
            value = parse_int(literal)
            if value is not None:
                result[name.casefold()] = value
    return result
