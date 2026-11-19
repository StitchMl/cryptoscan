"""Opt-in, source-verified Fischlin witness-discrimination CTF workflow.

Uses the leaked witness to disprove the hypothesis that this witness was the
real branch: an earlier accepted hash is impossible for the real branch,
because the prover selects the *first* acceptable hash. An inconclusive
transcript is always skipped, never guessed.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import socket
from collections.abc import Callable, Sequence

from .network_policy import connect_authorized
from .parser import Document


def supported_source(documents: Sequence[Document]) -> bool:
    for doc in documents:
        try:
            tree = ast.parse(doc.text)
        except SyntaxError:
            continue
        functions = {node.name: node for node in tree.body
                     if isinstance(node, ast.FunctionDef)}
        if not {"Totally_a_random_oracle", "fischlin_proof", "gen_round"} <= functions.keys():
            continue
        oracle = "".join(ast.unparse(functions["Totally_a_random_oracle"]).split())
        prover = "".join(ast.unparse(functions["fischlin_proof"]).split())
        whole = "".join(ast.unparse(tree).split())
        if (all(s in oracle for s in ("sha512(", "str(a0).encode()", "str(z1).encode()"))
                and all(s in prover for s in ("e^e_sim", "z_b=(r_b+e_b*w_b)%q",
                                               "res<2**(512-B)", "t=2**10", "B=6"))
                and all(s in whole for s in ("attempts=2**4", "range(64)",
                                              "whichwitnessdoyouwanttosee?",
                                              "doyouthinkyoucanguessmywitness?"))):
            return True
    return False


def _ro(a0: int, a1: int, e: int, e0: int, e1: int, z0: int, z1: int) -> int:
    parts = (b"my", str(a0).encode(), b"very", str(a1).encode(),
             b"cool", str(e).encode(), b"random", str(e0).encode(),
             b"oracle", str(e1).encode(), b"for", str(z0).encode(),
             b"fischlin", str(z1).encode())
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "big")


def identify_simulated_branch(proof: dict[str, int], leaked_witness: int,
                              leaked_index: int, q: int) -> int | None:
    """Return the *other* branch only when a counterfactual hash proves it.

    Under the hypothesis that the leaked branch is real, its commitment
    a_i=g^r and response z_i=r+e_i*w are fixed by its leaked witness.
    Recreate all prior attempts of that hypothesis. One earlier acceptable
    hash contradicts first-hit selection, so the other branch must be real.
    """
    if leaked_index not in (0, 1) or q <= 2:
        raise ValueError("Invalid witness index or group order")
    required = {"a0", "a1", "e", "e0", "e1", "z0", "z1"}
    if set(proof) != required or not all(type(proof[k]) is int for k in required):
        raise ValueError("Malformed Fischlin transcript")
    chosen_e = proof["e"]
    if not 0 <= chosen_e < 1024 or proof["e0"] ^ proof["e1"] != chosen_e:
        raise ValueError("Invalid Fischlin challenge")
    other = 1 - leaked_index
    r = (proof[f"z{leaked_index}"] - proof[f"e{leaked_index}"] * leaked_witness) % q
    for candidate_e in range(chosen_e):
        simulated_e = proof[f"e{other}"]
        real_e = candidate_e ^ simulated_e
        real_z = (r + real_e * leaked_witness) % q
        e0, e1 = ((real_e, simulated_e) if leaked_index == 0
                  else (simulated_e, real_e))
        z0, z1 = ((real_z, proof["z1"]) if leaked_index == 0
                  else (proof["z0"], real_z))
        if _ro(proof["a0"], proof["a1"], candidate_e, e0, e1, z0, z1) < 2**506:
            return other
    return None


class _Connection:
    def __init__(self, host: str, port: int, timeout: float):
        self.sock = connect_authorized(host, port, timeout)
        self.sock.settimeout(timeout)
        self.buffer = b""

    def until_one(self, markers: tuple[bytes, ...]) -> tuple[bytes, bytes]:
        while True:
            found = [(self.buffer.find(marker), marker) for marker in markers
                     if marker in self.buffer]
            if found:
                index, marker = min(found, key=lambda item: item[0])
                end = index + len(marker)
                result, self.buffer = self.buffer[:end], self.buffer[end:]
                return result, marker
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("CTF server closed the TCP connection")
            self.buffer += chunk
            if len(self.buffer) > 200000:
                raise ValueError("Unexpectedly large server response")

    def send(self, value: int | str):
        self.sock.sendall(f"{value}\n".encode("ascii"))

    def read_tail(self) -> bytes:
        output = self.buffer
        self.buffer = b""
        while True:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            output += chunk
            if len(output) > 200000:
                break
        return output

    def close(self):
        self.sock.close()


def recover_flag(
    documents: Sequence[Document], host: str, port: int, *,
    timeout: float = 20.0, max_sessions: int = 16,
    progress: Callable[[str], object] = print
) -> str:
    if not supported_source(documents):
        raise ValueError("Source does not match the supported Fischlin first-hit protocol")
    if not (1 <= port <= 65535 and 0 < timeout <= 120 and 1 <= max_sessions <= 100):
        raise ValueError("Invalid networking or retry limits")
    params = None
    for doc in documents:
        try:
            vals = {}
            for node in ast.parse(doc.text).body:
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    try:
                        vals[node.targets[0].id] = ast.literal_eval(node.value)
                    except (TypeError, ValueError, SyntaxError):
                        pass
            if all(isinstance(vals.get(x), int) for x in ("p", "q", "g")):
                params = vals
                break
        except SyntaxError:
            continue
    if params is None:
        raise ValueError("Challenge group parameters p, q, g are required")
    p, q, g = params["p"], params["q"], params["g"]
    if p != 2*q+1 or g != 2 or not (2**500 < q < 2**520):
        raise ValueError("Unexpected group parameters; unsupported attack instance")

    prompt = b"which witness do you want to see?"
    follow = b"do you think you can guess my witness? (y,n)"
    guess = b"which witness did the prover use?"
    successful = b"well done, you distinguished all the witnesses!"
    failed = b"you didn't guess the right witness"

    for session_no in range(1, max_sessions+1):
        conn = _Connection(host, port, timeout)
        try:
            _, marker = conn.until_one((prompt, failed))
            if marker == failed:
                continue
            for round_no in range(64):
                committed = False
                for attempt_no in range(16):
                    # Always request w0. Source code proves both witnesses
                    # satisfy y=g^w, so this revelation alone cannot tell b.
                    conn.send(0)
                    response, marker = conn.until_one((follow, failed))
                    if marker == failed:
                        break
                    witness_match = re.search(rb"w0\s*=\s*(\d+)", response)
                    transcript_match = re.search(rb"\{[^\r\n]+\}", response)
                    if witness_match is None or transcript_match is None:
                        raise ValueError("Server changed the expected transcript format")
                    w0 = int(witness_match.group(1))
                    proof = json.loads(transcript_match.group(0))
                    decision = identify_simulated_branch(proof, w0, 0, q)
                    if decision is None:
                        conn.send("n")
                        if attempt_no < 15:
                            conn.until_one((prompt,))
                        continue
                    conn.send("y")
                    conn.until_one((guess,))
                    conn.send(decision)
                    committed = True
                    break
                if not committed:
                    # After all 16 rejections, the server is at its mandatory
                    # guess prompt. Reconnect instead of sending an unproven guess.
                    progress(f"[FISCHLIN] Session {session_no}, round {round_no}: inconclusive; restarting")
                    break
                response, marker = conn.until_one((prompt, successful, failed))
                if marker == failed:
                    progress(f"[FISCHLIN] Session {session_no}: wrong decision; restarting")
                    break
                if marker == successful:
                    tail = conn.read_tail()
                    combined = response + tail
                    match = re.search(rb"\w{2,32}\{[^\r\n{}]+\}", combined)
                    if match:
                        flag = match.group(0).decode("ascii")
                        progress("[FISCHLIN] All 64 witness challenges solved")
                        return flag
                    raise RuntimeError("All rounds passed, but no parseable flag was returned")
                progress(f"[FISCHLIN] Session {session_no}: solved round {round_no+1}/64")
        except OSError as exc:
            progress(f"[FISCHLIN] Session {session_no}: connection interrupted ({exc})")
        finally:
            conn.close()
    raise RuntimeError("No complete 64-round session obtained within retry limit")
