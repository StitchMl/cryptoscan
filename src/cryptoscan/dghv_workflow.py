"""Opt-in TCP solver for source-verified DGHV positive-noise overflow CTFs."""
from __future__ import annotations

import ast
import re
from collections.abc import Callable, Sequence

from .network_policy import connect_authorized
from .parser import Document

# Pairwise-coprime choices accepted by the server's 128 <= N < 256 restriction.
HEX_INPUT_PROMPT = b"Message to encode (converted to hexadecimal): "

MODULI = (131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
          191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251)


def supported_source(documents: Sequence[Document]) -> bool:
    """Refuse to run a network solver unless the supplied source proves its model."""
    for doc in documents:
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        encrypt = functions.get("dghv_encrypt")
        decrypt = functions.get("dghv_decrypt")
        if encrypt is None or decrypt is None:
            continue
        enc = re.sub(r"\s+", "", ast.unparse(encrypt))
        dec = re.sub(r"\s+", "", ast.unparse(decrypt))
        full = re.sub(r"\s+", "", ast.unparse(tree))
        if (("returnp*q+N*r+m" in enc)
                and ("returnc%p%N" in dec)
                and "random.randint(0,rmax)" in enc
                and "rmax=2**128/N/4" in enc
                and "getPrime(128)" in full
                and "dghv_encrypt(p,2**7,ord(c))" in full):
            return True
    return False


class _LineConnection:
    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.sock = connect_authorized(host, port, timeout)
        self.sock.settimeout(timeout)
        self.buffer = b""

    def until(self, marker: bytes) -> bytes:
        while marker not in self.buffer:
            block = self.sock.recv(4096)
            if not block:
                raise ConnectionError("CTF server disconnected")
            self.buffer += block
            if len(self.buffer) > 2_000_000:
                raise ValueError("CTF response exceeds safety limit")
        end = self.buffer.index(marker) + len(marker)
        result, self.buffer = self.buffer[:end], self.buffer[end:]
        return result

    def send(self, text: str | int) -> None:
        self.sock.sendall(str(text).encode("ascii") + b"\n")

    def close(self) -> None:
        self.sock.close()


def _read_encrypted_flag(session: _LineConnection) -> list[int]:
    """Parse a bounded decimal-ciphertext greeting without backtracking."""
    greeting = session.until(b"Choose N: ")
    matched = re.search(
        rb"encrypted our secret flag with it:[ \t]*\r?\n"
        rb"((?:[ \t]*[0-9]+[ \t]*\r?\n){1,4096})",
        greeting,
    )
    if matched is None:
        raise ValueError("Encrypted flag not found in challenge greeting")
    ciphertexts = [int(line.strip()) for line in matched.group(1).splitlines()
                   if line.strip()]
    if not 1 <= len(ciphertexts) <= 4096:
        raise ValueError("Unexpected encrypted flag length")
    return ciphertexts


def _read_noise_overflow_residue(
    session: _LineConnection, modulus: int, max_adds: int,
) -> int:
    """Detect the first positive-noise overflow and recover one CRT residue."""
    session.send(1)
    session.until(b"Choose N: ")
    session.send(modulus)
    session.until(HEX_INPUT_PROMPT)
    session.send("00")
    session.until(b"> ")
    for _ in range(max_adds):
        session.send(2)
        session.until(HEX_INPUT_PROMPT)
        session.send("00")
        session.until(b"> ")
        session.send(3)
        reply = session.until(b"> ")
        found = re.search(rb"Decrypted message:[ \t]*([0-9a-fA-F]{2})", reply)
        if found is None:
            raise ValueError("Unexpected decryption response")
        observed = int(found.group(1), 16)
        if observed:
            return (-observed) % modulus
    raise RuntimeError(
        f"No positive noise overflow at N={modulus}; try larger max_adds"
    )


def _recover_private_modulus(
    session: _LineConnection, max_adds: int,
    progress: Callable[[str], object],
) -> int:
    session.send(128)
    session.until(HEX_INPUT_PROMPT)
    session.send("00")
    session.until(b"> ")

    value, product = 0, 1
    for modulus in MODULI:
        residue = _read_noise_overflow_residue(session, modulus, max_adds)
        value += (
            (residue - value) * pow(product, -1, modulus) % modulus
        ) * product
        product *= modulus
        progress(
            f"[DGHV] N={modulus}: p mod N={residue}, CRT bits={product.bit_length()}"
        )
        if product > 2**128:
            break
    if product <= 2**128 or not 2**127 <= value < 2**128:
        raise RuntimeError("CRT could not uniquely recover a 128-bit private key")
    return value


def recover_flag(
    documents: Sequence[Document],
    host: str,
    port: int,
    *,
    timeout: float = 30.0,
    max_adds: int = 50,
    progress: Callable[[str], object] = print,
) -> str:
    """Recover a 128-bit DGHV secret through positive noise and CRT."""
    if not supported_source(documents):
        raise ValueError("Source does not establish the supported DGHV 128-bit noise-overflow model")
    if not (1 <= port <= 65535 and 0 < timeout <= 120 and 1 <= max_adds <= 1000):
        raise ValueError("Invalid solver limits")
    session = _LineConnection(host, port, timeout)
    try:
        ciphertexts = _read_encrypted_flag(session)
        progress(f"[DGHV] Collected {len(ciphertexts)} ciphertexts")
        secret = _recover_private_modulus(session, max_adds, progress)
        plaintext = bytes((ciphertext % secret) % 128 for ciphertext in ciphertexts)
        try:
            result = plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("Recovered plaintext is not UTF-8") from exc
        if not re.fullmatch(r"CSC\{[^\r\n]{1,256}\}", result):
            raise RuntimeError("Recovered plaintext does not match the expected flag shape")
        progress(
            f"[DGHV] Recovered 128-bit private key and {len(plaintext)} plaintext bytes"
        )
        return result
    finally:
        session.close()
