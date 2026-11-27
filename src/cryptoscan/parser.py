from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import json
import re
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from .url_intake import fetch_challenge_inputs


@dataclass(frozen=True)
class Document:
    path: str
    text: str
    data: Any | None
    scope: str = "."
    digest: str = ""
    rsa_private_keys: tuple[dict[str, int], ...] = ()


IGNORED_DIRS = {".git", ".github", ".idea", ".pytest_cache", ".venv", "__pycache__", "docs", "documentation", "node_modules", "tests"}
IGNORED_STEMS = {"readme", "writeup", "solution", "solutions", "solver", "solve", "exploit"}
IGNORED_SUFFIXES = {".md", ".markdown", ".rst", ".ipynb", ".pdf"}
NON_BOUNDARY_DIRS = {"app", "archive", "attachments", "dist", "private", "public", "release", "server", "service", "src"}


def _ignored(name: str) -> bool:
    normalized = name.replace("\\", "/")
    parts = [part.casefold() for part in normalized.split("/")]
    path = Path(normalized)
    return (
        any(part in IGNORED_DIRS for part in parts[:-1])
        or path.suffix.casefold() in IGNORED_SUFFIXES
        or path.stem.casefold() in IGNORED_STEMS
    )


def _scope(relative_name: str, fallback: str = ".") -> str:
    parts = [part for part in relative_name.replace("\\", "/").split("/") if part]
    if len(parts) < 2 or parts[0].casefold() in NON_BOUNDARY_DIRS:
        return fallback
    return parts[0].casefold()


def _documents_in_file(root: Path, path: Path) -> list[Document]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    relative = path.relative_to(root).as_posix()
    scope = _scope(relative)
    suffixes = "".join(path.suffixes).casefold()
    if path.suffix.casefold() == ".zip":
        return _zip_documents(
            raw, relative, _scope(relative, Path(relative).stem.casefold()),
        )
    if suffixes.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz")):
        archive_scope = Path(relative).name.casefold().split(".tar", 1)[0]
        return _tar_documents(
            path, relative, _scope(relative, archive_scope),
        )
    if path.suffix.casefold() in {".der", ".cer"}:
        keys = der_rsa_public_keys(raw)
        private_keys = tuple(der_rsa_private_keys(raw))
        return [Document(
            relative, "", keys, scope, hashlib.sha256(raw).hexdigest(), private_keys,
        )] if keys or private_keys else []
    if raw[:1] == b"\x30":
        private_keys = tuple(der_rsa_private_keys(raw))
        if private_keys:
            return [Document(
                relative, "", None, scope, hashlib.sha256(raw).hexdigest(),
                private_keys,
            )]
    if b"\0" in raw[:4096]:
        digest = hashlib.sha256(raw).hexdigest()
        printable = [item.decode("ascii", errors="replace")
                     for item in re.findall(rb"[ -~]{4,}", raw)[:256]]
        return [Document(
            relative, "\n".join(printable),
            {"binary": True, "size": len(raw), "sha256": digest,
             "printable_strings": printable}, scope, digest,
        )]
    text = raw.decode("utf-8", errors="replace")
    data = None
    if path.suffix.casefold() == ".json" or text.lstrip().startswith(("{", "[")):
        with contextlib.suppress(json.JSONDecodeError):
            data = json.loads(text)
    return [Document(
        relative, text, data, scope, hashlib.sha256(raw).hexdigest(),
    )]


def _pipeline_markdown(path: Path, relative_name: str) -> bool:
    """Include a Markdown challenge statement only when it declares a pipeline."""
    if path.suffix.casefold() not in {".md", ".markdown"}:
        return False
    parts = [part.casefold() for part in relative_name.replace("\\", "/").split("/")]
    if any(part in IGNORED_DIRS for part in parts[:-1]):
        return False
    try:
        raw = path.read_bytes()
        if len(raw) > 8 * 1024 * 1024 or b"\0" in raw[:4096]:
            return False
        text = raw.decode("utf-8", errors="replace")
    except OSError:
        return False
    return re.search(r"(?im)\bPIPELINE\s*:\s*[A-Za-z][A-Za-z0-9_-]*(?:\s*->\s*[A-Za-z][A-Za-z0-9_-]*)+", text) is not None


def _url_documents(target: str) -> list[Document]:
    parsed = urlsplit(target)
    scope = parsed.netloc.casefold()
    documents = []
    for index, (source_url, raw) in enumerate(fetch_challenge_inputs(target)):
        source = urlsplit(source_url)
        name = f"{scope}{source.path or '/'}"
        # A directly supplied challenge page is explicit evidence, even when
        # its URL happens to end in a normally ignored documentation suffix.
        document = _document_from_bytes(name, raw, scope, allow_ignored=index == 0)
        if document is not None:
            documents.append(document)
    return documents


def collect_documents(targets: Iterable[str], *, authorized: bool = False) -> list[Document]:
    """Collect local inputs, or fetch explicitly authorized challenge URLs."""
    files: list[tuple[Path, Path]] = []
    documents: list[Document] = []
    for raw in targets:
        parsed = urlsplit(raw)
        if parsed.scheme.casefold() in {"http", "https"}:
            if not authorized:
                raise ValueError("HTTP(S) challenge inputs require --authorized")
            documents.extend(_url_documents(raw))
            continue
        target = Path(raw).resolve()
        if target.is_dir():
            files.extend(
                (target, path) for path in target.rglob("*")
                if path.is_file()
                and (
                    not _ignored(path.relative_to(target).as_posix())
                    or _pipeline_markdown(
                        path, path.relative_to(target).as_posix(),
                    )
                )
            )
        elif target.is_file():
            # Explicitly selected evidence always wins over filename-based
            # directory-scan exclusions (e.g. source named solve.py).
            files.append((target.parent, target))
    documents.extend(
        document
        for root, path in sorted(
            files, key=lambda pair: pair[1].as_posix().casefold(),
        )
        for document in _documents_in_file(root, path)
    )
    # Do not discard identically named templates from independent challenges.
    unique: dict[tuple[str, str], Document] = {}
    for document in sorted(
        documents, key=lambda item: ("!/" in item.path, item.path.casefold()),
    ):
        unique.setdefault((document.scope, document.digest), document)
    return list(unique.values())


def _document_from_bytes(
    name: str, raw: bytes, scope: str, *, allow_ignored: bool = False,
) -> Document | None:
    if (not allow_ignored and _ignored(name.split("!/", 1)[-1])) or len(raw) > 8 * 1024 * 1024:
        return None
    if Path(name).suffix.casefold() in {".der", ".cer"}:
        keys = der_rsa_public_keys(raw)
        private_keys = tuple(der_rsa_private_keys(raw))
        return Document(name, "", keys, scope, hashlib.sha256(raw).hexdigest(), private_keys) if keys or private_keys else None
    private_keys = tuple(der_rsa_private_keys(raw)) if raw[:1] == b"\x30" else ()
    if private_keys:
        return Document(
            name, "", None, scope, hashlib.sha256(raw).hexdigest(), private_keys,
        )
    digest = hashlib.sha256(raw).hexdigest()
    if b"\0" in raw[:4096]:
        strings = re.findall(rb"[ -~]{4,}", raw)
        printable = [item.decode("ascii", errors="replace") for item in strings[:256]]
        return Document(
            name,
            "\n".join(printable),
            {"binary": True, "size": len(raw), "sha256": digest,
             "printable_strings": printable},
            scope,
            digest,
        )
    text = raw.decode("utf-8", errors="replace")
    data = None
    if name.casefold().endswith(".json") or text.lstrip().startswith(("{", "[")):
        with contextlib.suppress(json.JSONDecodeError):
            data = json.loads(text)
    return Document(name, text, data, scope, digest)


def _zip_documents(raw: bytes, archive_name: str, scope: str) -> list[Document]:
    import io
    result: list[Document] = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = sorted((item for item in archive.infolist() if not item.is_dir()), key=lambda item: item.filename.casefold())[:4096]
            for member in members:
                if member.file_size > 8 * 1024 * 1024:
                    continue
                doc = _document_from_bytes(f"{archive_name}!/{member.filename}", archive.read(member), scope)
                if doc:
                    result.append(doc)
    except (OSError, ValueError, zipfile.BadZipFile):
        pass
    return result


def _tar_documents(path: Path, archive_name: str, scope: str) -> list[Document]:
    result: list[Document] = []
    try:
        with tarfile.open(path, "r:*") as archive:
            members = sorted((item for item in archive.getmembers() if item.isfile()), key=lambda item: item.name.casefold())[:4096]
            for member in members:
                if member.size > 8 * 1024 * 1024:
                    continue
                handle = archive.extractfile(member)
                if handle:
                    doc = _document_from_bytes(f"{archive_name}!/{member.name}", handle.read(), scope)
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
        except ValueError:
            pass
    return None


def assignments(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    pattern = re.compile(r"(?m)^[ \t]*([A-Za-z_](?a:\w)*)[ \t]*=[ \t]*([^#\r\n]+)")
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
    pattern = re.compile(r"(?m)^[ \t]*([A-Za-z_](?a:[\w-])*)[ \t]*:[ \t]*([^#\r\n]+)")
    for name, literal in pattern.findall(text):
        key = name.casefold().replace("-", "_")
        raw = literal.strip().rstrip(",")
        try:
            result[key] = ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            integer = parse_int(raw)
            result[key] = integer if integer is not None else raw.strip("\"'")
    return [result] if result else []


def pem_rsa_public_keys(text: str) -> list[dict[str, int]]:
    """Parse RSA public-key and X.509 certificate PEM without external packages."""
    found: list[dict[str, int]] = []
    pattern = re.compile(r"-----BEGIN (RSA PUBLIC KEY|PUBLIC KEY|CERTIFICATE)-----([A-Za-z0-9+/=\s]{0,32768})-----END \1-----")
    for label, body in pattern.findall(text):
        try:
            der = base64.b64decode(re.sub(r"\s+", "", body), validate=True)
            is_spki = None
            if label == "RSA PUBLIC KEY":
                is_spki = False
            elif label == "PUBLIC KEY":
                is_spki = True
            keys = der_rsa_public_keys(der, spki=is_spki)
            found.extend(keys)
        except ValueError:
            continue
    return found


def pem_rsa_private_keys(text: str) -> list[dict[str, int]]:
    """Extract parameters from unencrypted PKCS#1 or PKCS#8 RSA PEM keys."""
    from Crypto.PublicKey import RSA

    found: list[dict[str, int]] = []
    pattern = re.compile(
        r"-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY)-----"
        r"([A-Za-z0-9+/=\s]{0,65536})-----END \1-----"
    )
    for _label, body in pattern.findall(text):
        try:
            der = base64.b64decode(re.sub(r"\s+", "", body), validate=True)
            key = RSA.import_key(der)
        except (IndexError, TypeError, ValueError):
            continue
        if not key.has_private():
            continue
        found.append({
            "n": key.n, "e": key.e, "d": key.d,
            "p": key.p, "q": key.q,
        })
    return found


def der_rsa_private_keys(der: bytes) -> list[dict[str, int]]:
    """Extract private parameters from raw PKCS#1 or PKCS#8 RSA DER."""
    if len(der) > 1_000_000 or not der or der[0] != 0x30:
        return []
    from Crypto.PublicKey import RSA

    try:
        key = RSA.import_key(der)
    except (IndexError, TypeError, ValueError):
        return []
    if not key.has_private():
        return []
    return [{
        "n": key.n, "e": key.e, "d": key.d,
        "p": key.p, "q": key.q,
    }]


def ssh_rsa_public_keys(text: str) -> list[dict[str, int]]:
    """Parse OpenSSH ``ssh-rsa`` public-key lines without external packages."""
    found: list[dict[str, int]] = []
    for line in text.splitlines():
        if len(line) > 65536:
            continue
        fields = line.split()
        if len(fields) < 2 or fields[0] != "ssh-rsa":
            continue
        try:
            blob = base64.b64decode(fields[1], validate=True)
            algorithm, offset = _ssh_string(blob, 0)
            if algorithm != b"ssh-rsa":
                continue
            exponent_raw, offset = _ssh_string(blob, offset)
            modulus_raw, offset = _ssh_string(blob, offset)
            if offset != len(blob):
                continue
            exponent = _ssh_mpint(exponent_raw)
            modulus = _ssh_mpint(modulus_raw)
            if modulus > 3 and exponent > 1:
                found.append({"n": modulus, "e": exponent})
        except (ValueError, OverflowError):
            continue
    return found


def _ssh_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise ValueError("truncated SSH string length")
    length = int.from_bytes(data[offset:offset + 4], "big")
    start = offset + 4
    end = start + length
    if end > len(data):
        raise ValueError("truncated SSH string")
    return data[start:end], end


def _ssh_mpint(encoded: bytes) -> int:
    if not encoded or encoded[0] & 0x80:
        raise ValueError("invalid or negative SSH mpint")
    if len(encoded) > 1 and encoded[0] == 0 and not encoded[1] & 0x80:
        raise ValueError("non-canonical SSH mpint")
    return int.from_bytes(encoded, "big")


def _parse_rsa_der_variant(der: bytes, is_spki: bool) -> dict[str, int] | None:
    candidate = der
    if is_spki:
        outer, end = _der_value(candidate, 0, 0x30)
        if end != len(candidate):
            return None
        _, offset = _der_value(outer, 0, 0x30)
        bits, offset = _der_value(outer, offset, 0x03)
        if offset != len(outer) or not bits or bits[0] != 0:
            return None
        candidate = bits[1:]
    sequence, end = _der_value(candidate, 0, 0x30)
    if end != len(candidate):
        return None
    n_raw, offset = _der_value(sequence, 0, 0x02)
    e_raw, offset = _der_value(sequence, offset, 0x02)
    if offset != len(sequence):
        return None
    modulus, exponent = int.from_bytes(n_raw, "big"), int.from_bytes(e_raw, "big")
    return {"n": modulus, "e": exponent} if modulus > 3 and exponent > 1 else None


_RSA_ENCRYPTION_OID = bytes.fromhex("2a864886f70d010101")
_MAX_DER_NODES = 20_000


def _parse_rsa_spki(der: bytes) -> dict[str, int] | None:
    try:
        sequence, end = _der_value(der, 0, 0x30)
        if end != len(der):
            return None
        algorithm, _ = _der_value(sequence, 0, 0x30)
        oid, _ = _der_value(algorithm, 0, 0x06)
    except ValueError:
        return None
    if oid != _RSA_ENCRYPTION_OID:
        return None
    try:
        return _parse_rsa_der_variant(der, True)
    except ValueError:
        return None


def _der_children(data: bytes):
    offset = 0
    while offset < len(data):
        tag = data[offset]
        value, end = _der_value(data, offset, tag)
        yield tag, data[offset:end], value
        offset = end


def _nested_rsa_spki_keys(der: bytes) -> list[dict[str, int]]:
    if len(der) > 1_000_000:
        return []
    pending = [der]
    found: dict[tuple[int, int], dict[str, int]] = {}
    visited = 0
    while pending and visited < _MAX_DER_NODES:
        sequence = pending.pop()
        try:
            body, end = _der_value(sequence, 0, 0x30)
        except ValueError:
            continue
        if end != len(sequence):
            continue
        visited = _inspect_der_children(body, pending, found, visited)
    return list(found.values())


def _inspect_der_children(body: bytes, pending: list[bytes], found: dict,
                          visited: int) -> int:
    try:
        for tag, encoded, _value in _der_children(body):
            visited += 1
            if tag == 0x30:
                key = _parse_rsa_spki(encoded)
                if key is not None:
                    found[(key["n"], key["e"])] = key
                pending.append(encoded)
            if visited >= _MAX_DER_NODES:
                break
    except ValueError:
        return _MAX_DER_NODES
    return visited


def der_rsa_public_keys(der: bytes, spki: bool | None = None) -> list[dict[str, int]]:
    attempts = (False, True) if spki is None else (spki,)
    for is_spki in attempts:
        if is_spki:
            parsed = _parse_rsa_spki(der)
            if parsed is not None:
                return [parsed]
            continue
        try:
            parsed = _parse_rsa_der_variant(der, is_spki)
        except ValueError:
            continue
        if parsed is not None:
            return [parsed]
    return _nested_rsa_spki_keys(der)


def _der_value(data: bytes, offset: int, expected_tag: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != expected_tag:
        raise ValueError("unexpected DER tag")
    offset += 1
    if offset >= len(data):
        raise ValueError("truncated DER length")
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return data[offset:end], end
