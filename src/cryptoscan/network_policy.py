"""Network safety boundary for explicit, authorized online CTF attacks.

Resolve the destination once and connect to the verified numeric address.
This avoids DNS-rebinding between an IP range check and a socket connection.
By default private, loopback, link-local and cloud metadata endpoints are
refused. Offline scanners never connect to a network destination.
"""
from __future__ import annotations

import ipaddress
import os
import socket


def _validated_addresses(host: str, port: int) -> list[tuple]:
    """Validate the complete DNS answer before opening any socket."""
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses or len(addresses) > 64:
        raise ValueError("CTF host did not resolve to a bounded address set")
    permitted_private = os.environ.get("CRYPTOSCAN_ALLOW_PRIVATE_NETWORK") == "1"
    validated = []
    for family, socktype, protocol, _canonical, sockaddr in addresses:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError("Unsupported resolved address family")
        destination = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        if not destination.is_global and not permitted_private:
            raise ValueError(
                "Refusing non-public CTF destination; explicitly set "
                "CRYPTOSCAN_ALLOW_PRIVATE_NETWORK=1 only for your own lab"
            )
        validated.append((family, socktype, protocol, sockaddr))
    return validated


def connect_authorized(host: str, port: int, timeout: float) -> socket.socket:
    """Connect only to a globally routable address unless explicitly opted in."""
    if not isinstance(host, str) or not host or len(host) > 253:
        raise ValueError("Invalid CTF host")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Invalid CTF TCP port")
    if not 0 < timeout <= 120:
        raise ValueError("Invalid socket timeout")

    validated = _validated_addresses(host, port)

    last_error: OSError | None = None
    for family, socktype, protocol, sockaddr in validated:
        client = socket.socket(family, socktype, protocol)
        client.settimeout(timeout)
        try:
            client.connect(sockaddr)
            return client
        except OSError as exc:
            last_error = exc
            client.close()
    raise ConnectionError("Could not connect to the validated CTF destination") from last_error
