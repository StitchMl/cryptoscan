"""Source-gated forgery of an unsound two-equation pairing confirmation proof.

Curve and wire parameters come from inspected Sage source and remote public
data; no challenge parameters are bundled.
"""
from __future__ import annotations

from .source_units import MAX_SOURCE_LENGTH

import json
import re
import socket
from dataclasses import dataclass
from typing import Sequence

from .parser import Document
from .unramified_ring_oracle import _SageWorker


@dataclass(frozen=True)
class PairingConfirmation:
    prime: int
    curve_b: int
    embedding_degree: int
    twist_coefficient: tuple[int, int]
    user_prompt: str
    signature_prompt: str
    message_prompt: str
    signer_prompt: str
    response_prompt: str
    identity: str
    message_template: str
    username_variable: str


def _assignment(source: str, name: str) -> int | None:
    matches = re.findall(
        r"(?m)^\s*self\." + re.escape(name) + r"\s*=\s*(\d+)\s*$", source
    )
    return int(matches[0]) if len(matches) == 1 else None


def _twist(source: str) -> tuple[int, int] | None:
    match = re.search(
        r"(?m)^\s*Fp2\.<([a-zA-Z]\w*)>\s*=\s*GF\(self\.p\s*\^\s*2\)\s*$",
        source,
    )
    if not match:
        return None
    symbol = re.escape(match.group(1))
    found = re.findall(
        r"(?m)^\s*self\.eps\s*=\s*(\d+)\s*\*\s*" + symbol
        + r"\s*\+\s*(\d+)\s*$",
        source,
    )
    return tuple(map(int, found[0])) if len(found) == 1 else None


def _protocol(source: str):
    tail = source.rsplit("pkg = PKG()", 1)
    if len(tail) != 2:
        return None
    code = tail[1]
    matches = re.findall(r"\binput\(('[^'\n]*'|\"[^\"\n]*\")\)", code)
    if len(matches) != 5:
        return None
    prompts = tuple(item[1:-1] for item in matches)
    username = re.search(r"\b(\w+)\s*=\s*input\(", code)
    template = re.search(r"(?m)^\s*target\s*=\s*f(['\"])(.*?)\1\s*$", code)
    role = re.search(
        r"\bcase\s+True\s*,\s*(['\"])([^'\"]{1,80})\1\s*,\s*True", code
    )
    if not username or not template or not role:
        return None
    user_var = username.group(1)
    if template.group(2).count("{" + user_var + "}") != 1:
        return None
    return prompts, role.group(2), template.group(2), user_var


def _proof_shape(source: str) -> bool:
    required = (
        "ate_pairing", "trace_of_frobenius", "self.y_inv", "self.x * self.y",
        "self.sig['R']", "self.sig['S']", "self.sig['Qid']",
        "self.curve.e(self.Q, self.sig['Qid'])",
        "self.curve.e(self.P_G1, self.sig['Qid'])",
        "self.curve.e(self.sig['R'] + self.Q, self.P_G2)",
        "self.H(self.sig['m'])", "r ^ self.y_inv", "t ^ self.x",
        "self.h", "self.curve.h *", "sha256(uid.encode())", "self.curve.e(C,",
    )
    return all(token in source for token in required)


def extract_instance(documents: Sequence[Document]) -> PairingConfirmation | None:
    found = []
    for document in documents:
        source = document.text
        if not source or len(source) > MAX_SOURCE_LENGTH:
            continue
        if not _proof_shape(source):
            continue
        p, b, k = (_assignment(source, name) for name in ("p", "b", "k"))
        twist = _twist(source)
        protocol = _protocol(source)
        if not all((p, b, k, twist, protocol)):
            continue
        if not (p > 3 and p.bit_length() <= 512 and 2 <= k <= 24):
            continue
        prompts, role, template, user_var = protocol
        found.append(
            PairingConfirmation(p, b, k, twist, *prompts, role, template, user_var)
        )
    return found[0] if len(found) == 1 else None


class _Dialogue:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = bytearray()

    def until(self, delimiter: bytes) -> bytes:
        while delimiter not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError(
                    f"pairing verifier closed awaiting {delimiter!r}; "
                    f"tail={bytes(self.buffer[-160:])!r}"
                )
            self.buffer.extend(chunk)
            if len(self.buffer) > 262144:
                raise ValueError("pairing verifier response exceeds size limit")
        end = self.buffer.index(delimiter) + len(delimiter)
        data = bytes(self.buffer[:end])
        del self.buffer[:end]
        return data

    def send(self, value: str) -> None:
        self.sock.sendall(value.encode("utf-8") + b"\n")


def _public_parameters(wire: _Dialogue, user_prompt: str) -> dict:
    data = wire.until(user_prompt.encode("utf-8"))
    for line in data.splitlines():
        line = line.strip()
        if line.startswith(b"{") and line.endswith(b"}"):
            parsed = json.loads(line)
            if (isinstance(parsed, dict)
                    and {"P_G1", "Q", "P_G2"} <= parsed.keys()):
                return parsed
    raise RuntimeError("no public pairing parameters in service banner")


def recover_flag(documents: Sequence[Document], host: str, port: int, *,
                 timeout: float = 120.0) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("source does not match supported pairing-confirmation flaw")
    username = "cryptoscan_participant"
    if username.lower() == instance.identity.lower():
        raise RuntimeError("chosen participant collides with privileged identity")
    message = instance.message_template.replace(
        "{" + instance.username_variable + "}", username
    )
    worker = _SageWorker("sage_pairing_confirmation_worker.py")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            wire = _Dialogue(sock)
            parameters = _public_parameters(wire, instance.user_prompt)
            wire.send(username)
            first = worker.ask({
                "mode": "begin", "prime": instance.prime,
                "b": instance.curve_b, "k": instance.embedding_degree,
                "eps": instance.twist_coefficient, "public": parameters,
                "identity": instance.identity, "message": message,
            })
            wire.until(instance.signature_prompt.encode("utf-8"))
            wire.send(json.dumps(first["signature"]))
            wire.until(instance.message_prompt.encode("utf-8"))
            wire.send(message)
            wire.until(instance.signer_prompt.encode("utf-8"))
            wire.send(instance.identity)
            wire.until(b"C = ")
            challenge = json.loads(wire.until(b"\n").strip())
            second = worker.ask({"mode": "challenge", "point": challenge})
            wire.until(instance.response_prompt.encode("utf-8"))
            wire.send(json.dumps(second["response"]))
            result = wire.until(b"\n").decode("utf-8", "replace")
    finally:
        worker.close()
    flag = re.search(r"\b\w{2,32}\{[^\r\n{}]{1,200}\}", result)
    if flag is None:
        raise RuntimeError(
            "pairing verifier did not return flag-shaped output: "
            + result.strip()[:160]
        )
    return flag.group(0)
