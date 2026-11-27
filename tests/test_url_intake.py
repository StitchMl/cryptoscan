from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from cryptoscan.parser import _document_from_bytes, collect_documents


class Handler(BaseHTTPRequestHandler):
    paths: ClassVar[list[str]] = []

    def do_GET(self):
        self.paths.append(self.path)
        if self.path == "/challenge":
            body = (
                '<html><a href="/files/chall.py">challenge source</a>'
                '<a href="https://outside.invalid/secret.py">external</a>'
                '<a href="/not-an-artifact">ordinary route</a></html>'
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        elif self.path == "/files/chall.py":
            body = "pipeline: base64\npayload: Y3Rme2dlbmVyaWN9\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        else:
            body = "not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_args):
        pass


@pytest.fixture
def server():
    Handler.paths = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}/challenge"
    httpd.shutdown()
    thread.join()


def test_url_input_fetches_page_and_same_origin_artifacts(server, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_ALLOW_PRIVATE_NETWORK", "1")
    docs = collect_documents([server], authorized=True)
    assert len(docs) == 2
    assert any("<html>" in item.text for item in docs)
    source = next(item for item in docs if item.path.endswith("/files/chall.py"))
    assert "pipeline: base64" in source.text
    assert Handler.paths == ["/challenge", "/files/chall.py"]


def test_private_url_needs_the_existing_lab_network_opt_in(server, monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_ALLOW_PRIVATE_NETWORK", raising=False)
    with pytest.raises(ValueError, match="Refusing non-public CTF destination"):
        collect_documents([server], authorized=True)
    assert Handler.paths == []


def test_unrecognized_binary_is_preserved_as_triage_evidence():
    document = _document_from_bytes(
        "challenge.bin", b"\x00\x01flag{visible_string}\x00\xff", "challenge",
    )
    assert document is not None
    assert document.data["binary"] is True
    assert "flag{visible_string}" in document.data["printable_strings"]
    assert document.data["size"] == 24


def test_explicit_markdown_url_document_is_not_filtered_by_filename():
    document = _document_from_bytes(
        "challenge.invalid/statement.md", b"Ciphertext: 1234", "challenge.invalid",
        allow_ignored=True,
    )
    assert document is not None
    assert "Ciphertext: 1234" in document.text
