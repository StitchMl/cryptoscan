"""SSRF safety tests: reject internal destinations, prevent DNS rebinding."""
import socket

import pytest

from cryptoscan.network_policy import connect_authorized


def test_refuse_private_and_metadata_addresses(monkeypatch):
    for destination in ("127.0.0.1", "10.1.2.3", "169.254.169.254",
                        "172.16.0.2", "192.168.1.2", "::1", "fe80::1"):
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *args, target=destination, **kwargs: [
                (socket.AF_INET6 if ":" in target else socket.AF_INET,
                 socket.SOCK_STREAM, 6, "", (target, 9000)),
            ],
        )
        monkeypatch.delenv("CRYPTOSCAN_ALLOW_PRIVATE_NETWORK", raising=False)
        with pytest.raises(ValueError, match="non-public"):
            connect_authorized("example.test", 9000, 5)


def test_connect_verified_public_ip_without_dns_rebinding(monkeypatch):
    resolutions = []
    attempted = []

    def lookup(*args, **kwargs):
        resolutions.append(args)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 9000))]

    class Socket:
        def settimeout(self, seconds):
            assert seconds == 5
        def connect(self, address):
            attempted.append(address)
        def close(self):
            pass

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    monkeypatch.setattr(socket, "socket", lambda *args: Socket())
    session = connect_authorized("example.test", 9000, 5)
    assert session is not None
    assert len(resolutions) == 1
    assert attempted == [("8.8.8.8", 9000)]


def test_allow_private_only_with_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_ALLOW_PRIVATE_NETWORK", "1")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9000))
    ])
    class Socket:
        def settimeout(self, seconds):
            pass
        def connect(self, address):
            assert address == ("127.0.0.1", 9000)
        def close(self):
            pass
    monkeypatch.setattr(socket, "socket", lambda *args: Socket())
    assert connect_authorized("127.0.0.1", 9000, 5)
