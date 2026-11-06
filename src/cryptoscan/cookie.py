"""Offline cookie helper for the Authentification-1 CTF token format.

Not a generic cookie converter. A known key enables token generation.
A known plaintext token enables XOR changes only when its verifier ignores
authentication status. This helper does not recover an AES key.
"""
from __future__ import annotations

import argparse
import json
import sys


def token_payload(username: str, role: str) -> bytes:
    return json.dumps({"username": username, "role": role}).encode()


def parse_cookie(cookie: str) -> tuple[bytes, bytes]:
    parts = cookie.strip().split(";")
    if len(parts) != 2:
        raise ValueError("expected cookie format ciphertext_hex;tag_hex")
    try:
        ciphertext, tag = (bytes.fromhex(value) for value in parts)
    except ValueError as exc:
        raise ValueError("ciphertext and tag must be hexadecimal") from exc
    if len(tag) != 16:
        raise ValueError("tag must be exactly 16 bytes")
    return ciphertext, tag


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def alter_cookie(
    cookie: str, username: str, role: str, target_role: str,
    target_username: str | None = None,
) -> tuple[str, str]:
    ciphertext, tag = parse_cookie(cookie)
    known = token_payload(username, role)
    if len(ciphertext) != len(known):
        raise ValueError("original username/role do not match ciphertext length")
    if target_username is None:
        if not username.isascii():
            raise ValueError("for non-ASCII usernames specify --target-user")
        adjustment = len(token_payload("", target_role)) - len(token_payload("", role))
        if len(username) < adjustment:
            raise ValueError("insufficient known bytes for target role: use a longer username")
        target_username = username[:len(username) - adjustment]
    wanted = token_payload(target_username, target_role)
    if len(wanted) > len(known):
        raise ValueError("target exceeds known plaintext length")
    stream = _xor(ciphertext, known)
    edited = _xor(wanted, stream[:len(wanted)])
    return edited.hex() + ";" + tag.hex(), target_username


def transform_json_cookie(
    cookie: str,
    known_values: dict[str, str],
    required_values: dict[str, str],
) -> tuple[str, bytes]:
    """Use source-established JSON serialization and only verifier-required fields.

    The format must already be verified in source. A valid 16-byte tag is
    retained, but becomes *invalid* after the ciphertext is modified.
    This is only applicable when the verifier ignores the tag result.
    """
    ciphertext, tag = parse_cookie(cookie)
    original = json.dumps(known_values).encode()
    if len(original) != len(ciphertext):
        raise ValueError(
            f"observed ciphertext is {len(ciphertext)} bytes but source-derived "
            f"plaintext is {len(original)} bytes; check observed fields"
        )
    candidate = json.dumps(required_values).encode()
    if len(candidate) > len(original):
        raise ValueError(
            f"minimal candidate requires {len(candidate)} known keystream bytes; "
            f"only {len(original)} bytes are available"
        )
    keystream = _xor(ciphertext, original)
    modified = _xor(candidate, keystream[:len(candidate)])
    # Roundtrip is a deterministic local consistency check, not proof that the
    # target service will accept the altered cookie.
    if _xor(modified, keystream[:len(modified)]) != candidate:
        raise ValueError("local keystream consistency check failed")
    return modified.hex() + ";" + tag.hex(), candidate


def _multiply(x: int, y: int) -> int:
    result = 0
    value = y
    for bit in range(128):
        if (x >> (127 - bit)) & 1:
            result ^= value
        value = (value >> 1) ^ (0xe1000000000000000000000000000000 if value & 1 else 0)
    return result


def _ghash(h: bytes, data: bytes) -> bytes:
    state = 0
    factor = int.from_bytes(h, "big")
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        state = _multiply(state ^ int.from_bytes(block, "big"), factor)
    return state.to_bytes(16, "big")


def _gctr(cipher, j0: bytes, data: bytes) -> bytes:
    prefix, count = j0[:12], int.from_bytes(j0[12:], "big")
    output = bytearray()
    for start in range(0, len(data), 16):
        mask = cipher.encrypt(prefix + count.to_bytes(4, "big"))
        output.extend(_xor(data[start:start + 16], mask))
        count = (count + 1) % (1 << 32)
    return bytes(output)


def build_cookie(masterkey: str, username: str, role: str) -> str:
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise RuntimeError("install pycryptodome with: python -m pip install pycryptodome") from exc
    try:
        key = bytes.fromhex(masterkey.removeprefix("0x"))
    except ValueError as exc:
        raise ValueError("master key must be in hex") from exc
    if len(key) != 16:
        raise ValueError("master key must be 16 bytes (32 hexadecimal digits)")
    cipher = AES.new(key, AES.MODE_ECB)
    j0 = bytes(15) + b"\x01"
    data = token_payload(username, role)
    ciphertext = _gctr(cipher, j0, data)
    blocks = ciphertext + bytes(-len(ciphertext) % 16)
    length_block = bytes(8) + (8 * len(ciphertext)).to_bytes(8, "big")
    auth = _ghash(cipher.encrypt(bytes(16)), blocks + length_block)
    tag = _gctr(cipher, j0, auth)
    return ciphertext.hex() + ";" + tag.hex()


def main(args: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="cryptoscan cookie", description="Offline Authentification-1 cookie operations")
    sub = parser.add_subparsers(dest="action", required=True)
    build = sub.add_parser("build", help="build a cookie from a known master key")
    build.add_argument("--masterkey", required=True)
    build.add_argument("--user", required=True)
    build.add_argument("--role", required=True)
    alter = sub.add_parser("forge", help="alter known plaintext if token authentication is ignored")
    alter.add_argument("--cookie", required=True)
    alter.add_argument("--user", required=True)
    alter.add_argument("--role", required=True)
    alter.add_argument("--target-role", default="super_admin")
    alter.add_argument("--target-user")
    options = parser.parse_args(args)
    try:
        if options.action == "build":
            token = build_cookie(options.masterkey, options.user, options.role)
        else:
            token, name = alter_cookie(
                options.cookie, options.user, options.role,
                options.target_role, options.target_user,
            )
            print(f"Target username: {name}", file=sys.stderr)
            print("WARNING: the original tag is not valid for modified ciphertext.", file=sys.stderr)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(f"auth={token}")
    return 0
