"""Bounded retrieval of explicitly supplied CTF pages and their file links."""
from __future__ import annotations

import http.client
import re
import ssl
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from .network_policy import connect_authorized

MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ATTACHMENTS = 16
_ATTACHMENT_SUFFIXES = {
    ".bin", ".c", ".csv", ".cer", ".der", ".gz", ".json", ".key",
    ".log", ".out", ".pem", ".py", ".pub", ".sage", ".tar", ".txt",
    ".xz", ".zip", ".7z", ".bz2", ".tgz",
}


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        self.sock = connect_authorized(self.host, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:
        raw = connect_authorized(self.host, self.port, self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except OSError:
            raw.close()
            raise


class _AttachmentLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, bool]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() != "a":
            return
        fields = {name.casefold(): value for name, value in attrs}
        href = fields.get("href")
        if href:
            self.links.append((href, "download" in fields))


def _request_target(url: str) -> tuple[object, str, str]:
    if not isinstance(url, str) or len(url) > 4096 or any(ord(char) < 32 for char in url):
        raise ValueError("invalid challenge URL")
    try:
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    except ValueError as exc:
        raise ValueError("invalid challenge URL") from exc
    if (parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or not 1 <= port <= 65535):
        raise ValueError("challenge URL must be an absolute HTTP(S) URL without credentials")
    path = parsed.path or "/"
    request_target = urlunsplit(("", "", path, parsed.query, ""))
    return parsed, request_target, parsed.hostname


def fetch_url(url: str, *, timeout: float = 10.0, max_bytes: int = MAX_ATTACHMENT_BYTES) -> tuple[bytes, str]:
    """GET one explicitly provided public URL without redirects or proxy lookup."""
    parsed, request_target, host = _request_target(url)
    if not 0 < timeout <= 30 or not 0 < max_bytes <= MAX_TOTAL_BYTES:
        raise ValueError("invalid URL fetch budget")
    port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    if parsed.scheme.casefold() == "https":
        connection = _PinnedHTTPSConnection(
            host, port, timeout=timeout, context=ssl.create_default_context(),
        )
    else:
        connection = _PinnedHTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", request_target, headers={
            "Accept-Encoding": "identity",
            "User-Agent": "cryptoscan/authorized-static-intake",
        })
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"challenge URL returned HTTP {response.status}; redirects are not followed")
        content_encoding = response.getheader("Content-Encoding", "identity").casefold()
        if content_encoding not in {"", "identity"}:
            raise ValueError("compressed HTTP responses are not accepted")
        length = response.getheader("Content-Length")
        if length and length.isdigit() and int(length) > max_bytes:
            raise ValueError("challenge response exceeds the configured byte limit")
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("challenge response exceeds the configured byte limit")
        return data, response.getheader("Content-Type", "")
    except (OSError, http.client.HTTPException) as exc:
        raise ValueError(f"challenge URL retrieval failed: {type(exc).__name__}") from exc
    finally:
        connection.close()


def _same_origin(candidate: str, origin: tuple[str, str]) -> bool:
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    return (
        parsed.scheme.casefold(), parsed.netloc.casefold()
    ) == origin and not parsed.username and not parsed.password


def _artifact_candidate(page_url: str, href: str, origin: tuple[str, str],
                        seen: set[str], allow_unknown: bool) -> str | None:
    try:
        candidate = urljoin(page_url, href)
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if not _same_origin(candidate, origin):
        return None
    path = parsed.path.casefold()
    if not allow_unknown and not any(path.endswith(ext) for ext in _ATTACHMENT_SUFFIXES):
        return None
    normalized = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    if normalized in seen:
        return None
    seen.add(normalized)
    return candidate


def fetch_challenge_inputs(url: str) -> list[tuple[str, bytes]]:
    """Fetch a challenge page and bounded same-origin links that look like artifacts."""
    parsed, _, _ = _request_target(url)
    origin = (parsed.scheme.casefold(), parsed.netloc.casefold())
    page, content_type = fetch_url(url, max_bytes=MAX_PAGE_BYTES)
    inputs = [(url, page)]
    if "html" not in content_type.casefold() and not re.search(rb"<html\b", page[:4096], re.I):
        return inputs
    links = _AttachmentLinks()
    links.feed(page.decode("utf-8", errors="replace"))
    seen = {urlunsplit((origin[0], origin[1], parsed.path or "/", parsed.query, ""))}
    total = len(page)
    fetched = 0
    for href, download in links.links:
        candidate = _artifact_candidate(
            page_url=url, href=href, origin=origin, seen=seen, allow_unknown=download,
        )
        if candidate is None:
            continue
        remaining = MAX_TOTAL_BYTES - total
        if fetched >= MAX_ATTACHMENTS or remaining <= 0:
            break
        try:
            body, _ = fetch_url(candidate, max_bytes=min(MAX_ATTACHMENT_BYTES, remaining))
        except ValueError:
            continue
        inputs.append((candidate, body))
        total += len(body)
        fetched += 1
    return inputs
