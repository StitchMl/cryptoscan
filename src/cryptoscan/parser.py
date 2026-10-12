from __future__ import annotations

import ast
import base64
from dataclasses import dataclass
import json
from pathlib import Path
import re
import tarfile
from typing import Any, Iterable
import zipfile


@dataclass(frozen=True)
class Document:
    path: str
    text: str
    data: Any | None


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
        suffixes = "".join(path.suffixes).casefold()
        if path.suffix.casefold() == ".zip":
            documents.extend(_zip_documents(raw, path.relative_to(root).as_posix()))
            continue
        if suffixes.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz")):
            documents.extend(_tar_documents(path, path.relative_to(root).as_posix()))
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


def _document_from_bytes(name: str, raw: bytes) -> Document | None:
    if len(raw) > 8 * 1024 * 1024 or b"\0" in raw[:4096]:
        return None
    text = raw.decode("utf-8", errors="replace")
    data = None
    if name.casefold().endswith(".json") or text.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            pass
    return Document(name, text, data)


def _zip_documents(raw: bytes, archive_name: str) -> list[Document]:
    import io
    result: list[Document] = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = sorted((item for item in archive.infolist() if not item.is_dir()), key=lambda item: item.filename.casefold())[:4096]
            for member in members:
                if member.file_size > 8 * 1024 * 1024:
                    continue
                doc = _document_from_bytes(f"{archive_name}!/{member.filename}", archive.read(member))
                if doc:
                    result.append(doc)
    except (OSError, ValueError, zipfile.BadZipFile):
        pass
    return result


def _tar_documents(path: Path, archive_name: str) -> list[Document]:
    result: list[Document] = []
    try:
        with tarfile.open(path, "r:*") as archive:
            members = sorted((item for item in archive.getmembers() if item.isfile()), key=lambda item: item.name.casefold())[:4096]
            for member in members:
                if member.size > 8 * 1024 * 1024:
                    continue
                handle = archive.extractfile(member)
                if handle:
                    doc = _document_from_bytes(f"{archive_name}!/{member.name}", handle.read())
                    if doc:
                        result.append(doc)
    except (OSError, ValueError, tarfile.TarError):
        pass
    return result


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
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
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


def scalar_records(text: str) -> list[dict[str, Any]]:
    """Parse common challenge dumps: Python assignments and key: value lines."""
    result = assignments(text)
    pattern = re.compile(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*([^#\r\n]+)")
    for name, literal in pattern.findall(text):
        key = name.casefold().replace("-", "_")
        raw = literal.strip().rstrip(",")
        try:
            result[key] = ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            integer = parse_int(raw)
            result[key] = integer if integer is not None else raw.strip("\"'")
    return [result] if result else []
