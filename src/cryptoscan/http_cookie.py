"""Transport-safe HTTP Cookie header construction.

This module has no knowledge of cryptographic formats or CTF-specific roles.
"""
from __future__ import annotations

from http.cookies import SimpleCookie


def cookie_request_header(name: str, value: str) -> str:
    if not name or any(ch in name for ch in (";", "=", chr(13), chr(10))):
        raise ValueError("invalid cookie name")
    if any(ch in value for ch in (chr(13), chr(10))):
        raise ValueError("cookie value cannot contain line breaks")
    jar = SimpleCookie()
    jar[name] = value
    return "Cookie: " + jar[name].OutputString()


def local_cookie_parse_check(name: str, value: str) -> bool:
    """Verify the encoded header roundtrips via Python's cookie parser."""
    header = cookie_request_header(name, value)
    jar = SimpleCookie()
    jar.load(header[len("Cookie: "):])
    return name in jar and jar[name].value == value
