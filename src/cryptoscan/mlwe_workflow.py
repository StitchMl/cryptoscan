"""User-triggered MLWE sample evaluation and optional CTF challenge interaction."""
from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Callable, Sequence

from .mlwe import MLWEContext, classify_capture, recognize_weak_mlwe_ring
from .parser import Document


def _context_for_finding(
    location: str, documents: Sequence[Document]
) -> MLWEContext | None:
    path, _, raw_line = location.rpartition(":")
    matches = [
        item for item in recognize_weak_mlwe_ring(documents)
        if item.path == path and str(item.line) == raw_line
    ]
    return matches[0] if len(matches) == 1 else None


def _read_to_prompt(sock: socket.socket, maximum: int = 1_000_000) -> bytes:
    data = bytearray()
    while b"> " not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > maximum:
            raise ValueError("remote challenge prompt exceeds bounded capture limit")
    return bytes(data)


def classify_file(
    capture_file: str, context: MLWEContext,
    write: Callable[[str], Any] = print,
) -> int:
    raw = Path(capture_file).read_bytes()
    if len(raw) > 1_000_000:
        raise ValueError("capture file exceeds 1 MB")
    result = classify_capture(raw.decode("utf8", errors="replace"), context)
    write("Mathematical LWE-vs-uniform prediction: " + str(result.answer))
    write("Residual max: " + str(result.error_max))
    write("Residual norm: " + f"{result.norm:.2f}")
    write("Internal modular consistency: " + ("PASS" if result.verified else "FAIL"))
    write(result.note)
    write("This is a local statistical decision, not a verified remote answer.")
    return result.answer


def play_ctf_tcp(
    host: str, port: int, context: MLWEContext,
    write: Callable[[str], Any] = print,
    max_rounds: int = 256,
) -> None:
    """Only connect after the user explicitly supplies a CTF server host/port."""
    if not host or not 1 <= port <= 65535:
        raise ValueError("enter a valid explicit CTF host and port")
    with socket.create_connection((host, port), timeout=30) as sock:
        sock.settimeout(30)
        for count in range(max_rounds):
            prompt = _read_to_prompt(sock)
            if b"sanitize_mat(A)" not in prompt or b"sanitize_vec(t)" not in prompt:
                if prompt:
                    write("Server response: " + prompt.decode("utf8", errors="replace")[-3000:])
                return
            result = classify_capture(prompt.decode("utf8", errors="replace"), context)
            if not result.verified:
                raise ValueError("local modular verification failed; no answer sent")
            sock.sendall(str(result.answer).encode("ascii") + b"\n")
            write(f"Round {count + 1}: submitted {result.answer} "
                  f"(residual max {result.error_max})")
        write("Maximum configured rounds reached; no further answers were sent.")


def interactive_mlwe_workflow(
    finding: Any, documents: Sequence[Document],
    read: Callable[[str], str] = input,
    write: Callable[[str], Any] = print,
) -> None:
    context = _context_for_finding(finding.location, documents)
    if context is None:
        write("No unique source-derived MLWE parameters for this finding.")
        return
    write(f"Source ring: {context.path}:{context.line}")
    write(f"q={context.modulus}, polynomial rank={context.rank}, "
          f"matrix={context.rows}x{context.columns}, eta={context.eta}")
    write("Source condition: x^N - 1 has the root x=1.")
    write("The solver projects polynomials at x=1 and solves a bounded LWE lattice.")
    write("Choose: file = analyze saved capture, tcp = run authorized CTF rounds.")
    mode = read("Mode [file/tcp]: ").strip().casefold()
    try:
        if mode == "file":
            path = read("Path to saved server transcript (.txt): ").strip().strip('"')
            classify_file(path, context, write)
        elif mode == "tcp":
            host = read("CTF hostname (explicit): ").strip()
            port = int(read("CTF port: ").strip())
            play_ctf_tcp(host, port, context, write)
        else:
            write("Cancelled; no network activity.")
    except (OSError, TimeoutError, ValueError, RuntimeError) as exc:
        write("MLWE workflow stopped: " + str(exc))
