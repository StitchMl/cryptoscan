"""Explicit opt-in TCP attack for the CODEGATE hidden-state GCM CTF."""
from __future__ import annotations

import ast
import hashlib
import re
import socket
from collections.abc import Callable, Sequence

from .gcm_hidden_state import (
    recognize_gcm_tag_oracle, recover_ghash_key_from_u1_tag_differences,
)
from .gcm_hidden_growth import identify_growth_prefix, recover_empty_gcm_tag_candidates
from .parser import Document


class _Connection:
    def __init__(self, host: str, port: int, timeout: float):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buffer = b""

    def until(self, marker: bytes, *, max_bytes: int = 500000) -> bytes:
        while marker not in self.buffer:
            chunk = self.sock.recv(8192)
            if not chunk:
                raise ConnectionError("CTF server disconnected")
            self.buffer += chunk
            if len(self.buffer) > max_bytes:
                raise ValueError("Unexpectedly large response")
        end = self.buffer.index(marker) + len(marker)
        result, self.buffer = self.buffer[:end], self.buffer[end:]
        return result

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def tags(self, count: int) -> list[bytes]:
        results = []
        for _ in range(count):
            self.until(b"tag: ")
            line = self.until(b"\n").strip()
            if not re.fullmatch(rb"[a-fA-F0-9]{32}", line):
                raise ValueError("Malformed AES-GCM tag reply")
            results.append(bytes.fromhex(line.decode("ascii")))
        return results

    def rest(self) -> bytes:
        data = self.buffer
        self.buffer = b""
        while True:
            try:
                block = self.sock.recv(8192)
            except socket.timeout:
                break
            if not block:
                break
            data += block
            if len(data) > 500000:
                break
        return data

    def close(self) -> None:
        self.sock.close()


def _solve_pow(greeting: bytes) -> int:
    match = re.search(
        rb"md5\(str\(n\)\.encode\(\) \+ (b'[^']{20}')\)\.hexdigest\(\) = ([0-9a-fA-F]{32})",
        greeting,
    )
    if not match or b"range(2**26)" not in greeting:
        raise ValueError("Unsupported proof-of-work banner")
    challenge = ast.literal_eval(match.group(1).decode("ascii"))
    target = bytes.fromhex(match.group(2).decode("ascii"))
    for n in range(1 << 26):
        if hashlib.md5(str(n).encode("ascii") + challenge).digest() == target:
            return n
    raise RuntimeError("Proof of work has no matching value")


def _read_flag(data: bytes) -> str | None:
    uncolored = re.sub(rb"\x1b\[[0-9;]*m", b"", data)
    found = re.search(rb"[a-zA-Z0-9_-]{2,32}\{[^\r\n{}]{1,256}\}", uncolored)
    if found:
        return found.group(0).decode("utf-8", "replace")
    return None


def recover_flag(
    documents: Sequence[Document], host: str, port: int, *,
    timeout: float = 15.0, max_sessions: int = 25, max_growth_trials: int = 90,
    progress: Callable[[str], object] = print,
) -> str:
    """Return a flag only if the remote service confirms the tag.

    The PoW is solved before the 20-second challenge alarm. TCP command
    batches avoid network round-trips per tag. Inconclusive transcripts,
    rejected guesses, or large nullspaces trigger fresh sessions.
    """
    if not recognize_gcm_tag_oracle(documents):
        raise ValueError("No verified hidden-state GCM oracle in source")
    if not 1 <= port <= 65535 or not 0 < timeout <= 120:
        raise ValueError("Invalid network settings")
    if not 1 <= max_sessions <= 100 or not 1 <= max_growth_trials <= 200:
        raise ValueError("Invalid retry limits")
    for session_index in range(1, max_sessions+1):
        conn = _Connection(host, port, timeout)
        try:
            greeting = conn.until(b"): ")
            conn.send(f"{_solve_pow(greeting)}\n".encode("ascii"))
            conn.until(b"> ")

            conn.send(b"tag\n" + b"u1\ntag\n" * 150)
            tags = conn.tags(151)
            deltas = [bytes(a^b for a,b in zip(tags[i-1], tags[i]))
                      for i in range(1, len(tags))]
            h = recover_ghash_key_from_u1_tag_differences(deltas)
            progress(f"[GCM] Session {session_index}: GHASH key recovered")

            for attempt in range(max_growth_trials):
                conn.send(b"u1\n"*50 + b"tag\n" + b"u2\ntag\n"*6)
                captured = conn.tags(7)
                if identify_growth_prefix(h, captured) is None:
                    continue
                conn.send(b"u2\ntag\n"*5)
                captured += conn.tags(5)
                try:
                    candidates = recover_empty_gcm_tag_candidates(h, captured)
                except (RuntimeError, ValueError):
                    break
                if not candidates:
                    break
                candidate = min(candidates)
                progress(f"[GCM] Session {session_index}: {len(candidates)} tag candidates")
                conn.send(b"\n")
                conn.until(b"tag: ")
                conn.send(f"{candidate:032x}\n".encode("ascii"))
                answer = conn.rest()
                flag = _read_flag(answer)
                if flag:
                    progress("[GCM] Remote tag verification succeeded")
                    return flag
                break
        except (OSError, ValueError, RuntimeError, ConnectionError, TimeoutError) as exc:
            progress(f"[GCM] Session {session_index}: retry ({exc})")
        finally:
            conn.close()
    raise RuntimeError("No remotely verified flag recovered within the session limit")
