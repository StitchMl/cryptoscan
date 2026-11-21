"""Generic Groth16 proof-rerandomization attack against proof-hash ticket IDs.

For a prime-order bilinear pairing, e(k*A, k^-1*B) = e(A,B).
This backend reads/writes canonical compressed arkworks 0.3 BN254 points.
"""
from __future__ import annotations

from .source_units import rust_sources

import json
import re
import socket
from dataclasses import dataclass
from typing import Sequence

from .parser import Document

# BN254 standard curve parameters, independent of any service.
BASE_FIELD = 21888242871839275222246405745257275088696311157297823662689037894645226208583
SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
FQ2_B = (
    19485874751759354771024239261021720505790618469301721065564631296452457478373,
    266929791119991161246907387137283842545076965332900288569378510910307636690,
)


@dataclass(frozen=True)
class ReusableProofIdentity:
    starting_balance: int
    ticket_cost: int
    redemption_value: int
    flag_cost: int
    buy_command: str = "BuyTicket"
    redeem_command: str = "Redeem"
    flag_command: str = "BuyFlag"
    ticket_response: str = "Ticket"
    accepted_response: str = "GoodTicket"
    flag_response: str = "Flag"
    proof_field: str = "proof"

    @property
    def redemptions_needed(self) -> int:
        deficit = self.flag_cost - self.starting_balance + self.ticket_cost
        return max(1, (deficit + self.redemption_value - 1)
                   // self.redemption_value)


def _constants(source: str) -> dict[str, int]:
    values = {}
    for line in source.splitlines():
        match = re.fullmatch(
            r"[ \t]*const[ \t]+([A-Z][A-Z0-9_]*)[ \t]*:[ \t]*"
            r"i64[ \t]*=[ \t]*([^;\r\n]{1,160});[ \t]*",
            line,
        )
        if match is None:
            continue
        name, expression = match.groups()
        expression = expression.strip()
        if expression.isdecimal():
            values[name] = int(expression)
        elif (product := re.fullmatch(r"(\d+)[ \t]*\*[ \t]*([A-Z][A-Z0-9_]*)", expression)):
            if product.group(2) in values:
                values[name] = int(product.group(1)) * values[product.group(2)]
    return values


def _proof_identity_is_malleable(source: str) -> bool:
    """Require Groth16 BN254 verification plus a hash of serialized proof data."""
    if not all(token in source for token in (
        "Groth16", "Bn254", "Proof", "CanonicalSerialize",
        "CanonicalDeserialize", "Blake2b", "HashSet",
    )):
        return False
    if not all(re.search(expression, source) for expression in (
        r"Groth16\s*::\s*<\s*Bn254\s*>\s*::\s*verify",
        r"Groth16\s*::\s*<\s*Bn254\s*>\s*::\s*prove",
        r"Proof\s*::\s*<\s*Bn254\s*>\s*::\s*deserialize",
        r"\.insert\s*\(",
    )):
        return False
    serializations = re.findall(
        r"\b([A-Za-z_]\w*)\.serialize\s*\(\s*&mut\s+([A-Za-z_]\w*)\s*\)",
        source,
    )
    destinations: dict[str, set[str]] = {}
    for value, destination in serializations:
        destinations.setdefault(destination, set()).add(value)
    # The serialised proof and the public statement are both hashed, rather
    # than a stable ticket nonce, and inserted as spent identity.
    return any(
        len(values) >= 2
        and re.search(
            r"\b(?:digest|hash)\s*\(\s*&" + re.escape(destination) + r"\s*\)",
            source,
        )
        for destination, values in destinations.items()
    )


def _request_arms(source: str) -> dict[str, str]:
    matches = list(re.finditer(r"\bRequest::([A-Za-z_]\w*)\s*=>", source))
    return {
        match.group(1): source[match.end():matches[index + 1].start()]
        if index + 1 < len(matches) else source[match.end():]
        for index, match in enumerate(matches)
    }


def _response_variant(arm: str, pattern: str) -> str | None:
    match = re.search(
        r"\bResponse::([A-Za-z_]\w*)\b" + pattern, arm
    )
    return match.group(1) if match else None


def _economy_profile(source: str) -> tuple | None:
    """Infer JSON command variants and numeric relationships from Rust arms."""
    constants = _constants(source)
    arms = _request_arms(source)
    balance_declaration = re.search(
        r"\blet\s+mut\s+([A-Za-z_]\w*)\s*:\s*i64\s*=\s*([A-Z][A-Z0-9_]*)\s*;",
        source,
    )
    if balance_declaration is None:
        return None
    balance, balance_constant = balance_declaration.groups()
    if balance_constant not in constants:
        return None
    ticket_candidates = []
    redeem_candidates = []
    flag_candidates = []
    for command, body in arms.items():
        debit = re.search(
            r"\b" + re.escape(balance) + r"\s*-=\s*([A-Z][A-Z0-9_]*)\s*;",
            body,
        )
        credit = re.search(
            r"\b" + re.escape(balance) + r"\s*\+=\s*([A-Z][A-Z0-9_]*)\s*;",
            body,
        )
        price = re.search(
            r"\b" + re.escape(balance) + r"\s*>=\s*([A-Z][A-Z0-9_]*)",
            body,
        )
        if debit and ("issue(" in body or ".prove(" in body):
            ticket_candidates.append((command, debit.group(1), body))
        if credit and (".redeem(" in body or ".verify(" in body):
            redeem_candidates.append((command, credit.group(1), body))
        if price:
            flag_candidates.append((command, price.group(1), body))
    if any(len(group) != 1 for group in (
        ticket_candidates, redeem_candidates, flag_candidates,
    )):
        return None
    ticket_command, ticket_const, ticket_arm = ticket_candidates[0]
    redeem_command, redeem_const, redeem_arm = redeem_candidates[0]
    flag_command, flag_const, flag_arm = flag_candidates[0]
    if any(name not in constants for name in (
        ticket_const, redeem_const, flag_const,
    )):
        return None
    ticket_resp = _response_variant(ticket_arm, r"\s*\(")
    flag_resp = _response_variant(flag_arm, r"\s*\(")
    success = re.search(r"\bResponse::([A-Za-z_]\w*)\s*[;,\n]", redeem_arm)
    if not ticket_resp or not flag_resp or not success:
        return None
    return (
        constants[balance_constant], constants[ticket_const],
        constants[redeem_const], constants[flag_const],
        ticket_command, redeem_command, flag_command,
        ticket_resp, success.group(1), flag_resp,
    )


def _ticket_proof_field(source: str) -> str | None:
    structs = re.findall(
        r"\bstruct\s+[A-Za-z_]\w*\s*\{([^{}]{1,1024})\}", source
    )
    fields = [
        field for declaration in structs
        for field in re.findall(
            r"\b(?:pub\s+)?([A-Za-z_]\w*)\s*:\s*String\s*[,}]?", declaration
        )
    ]
    return fields[0] if len(fields) == 1 else None


def extract_instance(documents: Sequence[Document]) -> ReusableProofIdentity | None:
    sources: dict[str, list[str]] = {}
    for document in rust_sources(documents):
        sources.setdefault(document.scope, []).append(document.text)
    matches = []
    for code in sources.values():
        proofs = [item for item in code if _proof_identity_is_malleable(item)]
        economies = [(item, profile) for item in code
                     if (profile := _economy_profile(item)) is not None]
        if len(proofs) != 1 or len(economies) != 1:
            continue
        field = _ticket_proof_field(proofs[0])
        if field is None:
            continue
        model = ReusableProofIdentity(*economies[0][1], field)
        if (0 < model.ticket_cost < model.starting_balance
                and 0 < model.redemption_value
                and 2 <= model.redemptions_needed <= 64):
            matches.append(model)
    return matches[0] if len(matches) == 1 else None


def _add(a, b):
    if isinstance(a, tuple):
        return ((a[0] + b[0]) % BASE_FIELD,
                (a[1] + b[1]) % BASE_FIELD)
    return (a + b) % BASE_FIELD


def _neg(a):
    if isinstance(a, tuple):
        return (-a[0] % BASE_FIELD, -a[1] % BASE_FIELD)
    return -a % BASE_FIELD


def _sub(a, b):
    return _add(a, _neg(b))


def _mul(a, b):
    if isinstance(a, tuple):
        c, d = a
        e, f = b
        return ((c*e - d*f) % BASE_FIELD,
                (c*f + d*e) % BASE_FIELD)
    return (a*b) % BASE_FIELD


def _inv(a):
    if isinstance(a, tuple):
        c, d = a
        factor = pow((c*c + d*d) % BASE_FIELD, -1, BASE_FIELD)
        return (c*factor % BASE_FIELD, -d*factor % BASE_FIELD)
    return pow(a, -1, BASE_FIELD)


def _pow(a, exponent):
    result = (1, 0) if isinstance(a, tuple) else 1
    while exponent:
        if exponent & 1:
            result = _mul(result, a)
        a = _mul(a, a)
        exponent >>= 1
    return result


def _sqrt_p(value):
    value %= BASE_FIELD
    candidate = pow(value, (BASE_FIELD + 1)//4, BASE_FIELD)
    return candidate if candidate*candidate % BASE_FIELD == value else None


def _sqrt_fq2(value):
    a, b = value
    if b == 0:
        x = _sqrt_p(a)
        if x is not None:
            return (x, 0)
        y = _sqrt_p(-a)
        return (0, y) if y is not None else None
    norm = _sqrt_p((a*a + b*b) % BASE_FIELD)
    if norm is None:
        return None
    for delta in (norm, -norm):
        x = _sqrt_p((a + delta) * pow(2, -1, BASE_FIELD))
        if x:
            y = b * pow(2*x, -1, BASE_FIELD) % BASE_FIELD
            if _mul((x, y), (x, y)) == value:
                return (x, y)
    return None


def _larger(value):
    opposite = _neg(value)
    if isinstance(value, tuple):
        return (value[1], value[0]) > (opposite[1], opposite[0])
    return value > opposite


def _decompress(encoded: bytes, degree: int):
    if len(encoded) != 32*degree:
        raise ValueError("unexpected compressed point length")
    if encoded[-1] & 0x40:
        raise ValueError("identity point cannot be rerandomized")
    value = bytearray(encoded)
    greatest = bool(value[-1] & 0x80)
    value[-1] &= 0x3f
    parts = [int.from_bytes(value[index:index+32], "little")
             for index in range(0, len(value), 32)]
    if any(number >= BASE_FIELD for number in parts):
        raise ValueError("noncanonical compressed coordinate")
    x = parts[0] if degree == 1 else tuple(parts)
    b = 3 if degree == 1 else FQ2_B
    rhs = _add(_pow(x, 3), b)
    root = _sqrt_p(rhs) if degree == 1 else _sqrt_fq2(rhs)
    if root is None:
        raise ValueError("compressed point is not on BN254")
    y = root if _larger(root) == greatest else _neg(root)
    return x, y


def _compress(point, degree):
    x, y = point
    parts = [x] if degree == 1 else list(x)
    result = bytearray(b"".join(number.to_bytes(32, "little")
                                for number in parts))
    if _larger(y):
        result[-1] |= 0x80
    return bytes(result)


def _double(point):
    if point is None:
        return None
    x, y, z = point
    if y == 0 or y == (0, 0):
        return None
    xx = _mul(x, x)
    yy = _mul(y, y)
    yyyy = _mul(yy, yy)
    s = _mul(_mul(x, yy), (4, 0) if isinstance(x, tuple) else 4)
    m = _mul(xx, (3, 0) if isinstance(x, tuple) else 3)
    new_x = _sub(_mul(m, m), _add(s, s))
    new_y = _sub(_mul(m, _sub(s, new_x)),
                 _mul(yyyy, (8, 0) if isinstance(x, tuple) else 8))
    return new_x, new_y, _mul(_add(y, y), z)


def _add_jac(first, second):
    if first is None:
        return second
    if second is None:
        return first
    x1, y1, z1 = first
    x2, y2, z2 = second
    z1sq, z2sq = _mul(z1, z1), _mul(z2, z2)
    u1, u2 = _mul(x1, z2sq), _mul(x2, z1sq)
    s1 = _mul(y1, _mul(z2sq, z2))
    s2 = _mul(y2, _mul(z1sq, z1))
    if u1 == u2:
        return _double(first) if s1 == s2 else None
    h, r = _sub(u2, u1), _sub(s2, s1)
    h2 = _mul(h, h)
    h3 = _mul(h, h2)
    u1h2 = _mul(u1, h2)
    new_x = _sub(_sub(_mul(r, r), h3), _add(u1h2, u1h2))
    new_y = _sub(_mul(r, _sub(u1h2, new_x)), _mul(s1, h3))
    return new_x, new_y, _mul(h, _mul(z1, z2))


def _scalar_mul(point, scalar):
    x, y = point
    one = (1, 0) if isinstance(x, tuple) else 1
    current, result = (x, y, one), None
    while scalar:
        if scalar & 1:
            result = _add_jac(result, current)
        current = _double(current)
        scalar >>= 1
    if result is None:
        raise ValueError("group multiplication resulted in identity")
    xx, yy, zz = result
    inverse_z = _inv(zz)
    inverse_z2 = _mul(inverse_z, inverse_z)
    return (_mul(xx, inverse_z2),
            _mul(yy, _mul(inverse_z2, inverse_z)))


def rerandomize_proof(proof_hex: str, scalar: int) -> str:
    """Preserve verification while changing the serialized Groth16 proof."""
    if not 1 <= scalar < SCALAR_FIELD:
        raise ValueError("scalar out of subgroup range")
    try:
        encoded = bytes.fromhex(proof_hex)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid proof hex") from exc
    if len(encoded) != 128:
        raise ValueError("expected 128-byte compressed BN254 proof")
    first = _decompress(encoded[:32], 1)
    second = _decompress(encoded[32:96], 2)
    transformed_a = _compress(_scalar_mul(first, scalar), 1)
    transformed_b = _compress(
        _scalar_mul(second, pow(scalar, -1, SCALAR_FIELD)), 2,
    )
    return (transformed_a + transformed_b + encoded[96:]).hex()


class _LineSocket:
    def __init__(self, connection):
        self.connection = connection
        self.buffer = bytearray()

    def line(self):
        while b"\n" not in self.buffer:
            chunk = self.connection.recv(65536)
            if not chunk:
                raise ConnectionError("ticket service ended before a response")
            self.buffer.extend(chunk)
            if len(self.buffer) > 1048576:
                raise ValueError("oversized ticket service response")
        end = self.buffer.index(b"\n") + 1
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return json.loads(result)

    def request(self, payload):
        self.connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        return self.line()


def recover_flag(documents: Sequence[Document], host: str, port: int, *,
                 timeout: float = 60.0) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("source does not show Groth16 proof-hash redemption")
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        wire = _LineSocket(connection)
        wire.line()  # greeting
        ticket = wire.request("BuyTicket")
        try:
            proof = ticket["Ticket"]["proof"]
        except (KeyError, TypeError) as exc:
            raise RuntimeError(f"ticket purchase failed: {ticket!r}") from exc
        if wire.request({"Redeem": {"proof": proof}}) != "GoodTicket":
            raise RuntimeError("original proof redemption was refused")
        for scalar in range(2, instance.redemptions_needed + 1):
            altered = rerandomize_proof(proof, scalar)
            response = wire.request({"Redeem": {"proof": altered}})
            if response != "GoodTicket":
                raise RuntimeError(
                    f"new Groth16 proof refused at scalar {scalar}: {response!r}"
                )
        outcome = wire.request("BuyFlag")
        if not isinstance(outcome, dict) or not isinstance(outcome.get("Flag"), str):
            raise RuntimeError(f"ticket economy refused: {outcome!r}")
    return outcome["Flag"]
