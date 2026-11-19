"""Opt-in TCP solver for source-verified DGHV positive-noise overflow CTFs."""
from __future__ import annotations

import ast
import re
import socket
from collections.abc import Callable, Sequence

from .parser import Document

# Pairwise-coprime choices accepted by the server's 128 <= N < 256 restriction.
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
        enc = re.sub(r"\\s+", "", ast.unparse(encrypt))
        dec = re.sub(r"\\s+", "", ast.unparse(decrypt))
        full = re.sub(r"\\s+", "", ast.unparse(tree))
        if (("returnp*q+N*r+m" in enc)
                and ("return(c%p)%N" in dec)
                and "random.randint(0,rmax)" in enc
                and "rmax=2**128/N/4" in enc
                and "getPrime(128)" in full
                and "dghv_encrypt(p,2**7,ord(c))" in full):
            return True
    return False


class _LineConnection:
    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
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


def recover_flag(
    documents: Sequence[Document],
    host: str,
    port: int,
    *,
    timeout: float = 30.0,
    max_adds: int = 50,
    progress: Callable[[str], object] = print,
) -> str:
    """Recover one session's 128-bit secret via positive noise overflow and CRT.

    Requires a source-verified DGHV challenge, explicit host/port, and a server
    exposing chosen-N, add-zero, and decrypt operations. No challenge-specific
    flag or secret is embedded. A failed assumption raises instead of guessing.
    """
    if not supported_source(documents):
        raise ValueError("Source does not establish the supported DGHV 128-bit noise-overflow model")
    if not (1 <= port <= 65535 and 0 < timeout <= 120 and 1 <= max_adds <= 1000):
        raise ValueError("Invalid solver limits")
    session = _LineConnection(host, port, timeout)
    try:
        intro = session.until(b"Choose N: ")
        match = re.search(rb"encrypted our secret flag with it:\s*\n(.*?)\n\s*\n", intro, re.S)
        if match is None:
            raise ValueError("Encrypted flag not found in challenge greeting")
        ciphertexts = [int(line.strip()) for line in match.group(1).splitlines() if line.strip()]
        if not ciphertexts or len(ciphertexts) > 4096:
            raise ValueError("Unexpected encrypted flag length")
        progress(f"[DGHV] Collected {len(ciphertexts)} ciphertexts")

        # The first round starts in 'new' state automatically.
        session.send(128)
        session.until(b"Message to encode (converted to hexadecimal): ")
        session.send("00")
        session.until(b"> ")

        value, product = 0, 1
        for n in MODULI:
            session.send(1)
            session.until(b"Choose N: ")
            session.send(n)
            session.until(b"Message to encode (converted to hexadecimal): ")
            session.send("00")
            session.until(b"> ")
            residue = None
            for index in range(max_adds):
                session.send(2)
                session.until(b"Message to encode (converted to hexadecimal): ")
                session.send("00")
                session.until(b"> ")
                session.send(3)
                reply = session.until(b"> ")
                found = re.search(rb"Decrypted message:\s*([0-9a-fA-F]{2})", reply)
                if found is None:
                    raise ValueError("Unexpected decryption response")
                observed = int(found.group(1), 16)
                if observed:
                    # First crossing of p: before crossing output is zero,
                    # and each nonnegative noise increment is < p.
                    residue = (-observed) % n
                    break
            if residue is None:
                raise RuntimeError(f"No positive noise overflow at N={n}; try larger max_adds")
            # All selected N values are prime, so incremental CRT is exact.
            value += (((residue - value) * pow(product, -1, n)) % n) * product
            product *= n
            progress(f"[DGHV] N={n}: p mod N={residue}, CRT bits={product.bit_length()}")
            if product > 2**128:
                break

        if product <= 2**128 or not (2**127 <= value < 2**128):
            raise RuntimeError("CRT could not uniquely recover a 128-bit private key")
        plaintext = bytes((c % value) % 128 for c in ciphertexts)
        try:
            result = plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("Recovered plaintext is not UTF-8") from exc
        if not re.fullmatch(r"CSC\\{[^\\r\\n]{1,256}\\}", result):
            raise RuntimeError("Recovered plaintext does not match the expected flag shape")
        progress(f"[DGHV] Recovered 128-bit private key and {len(plaintext)} plaintext bytes")
        return result
    finally:
        session.close()
