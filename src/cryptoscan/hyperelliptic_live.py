"""Verified chosen-plaintext Jacobian analysis and conditional flag recovery.

Recover the hidden hyperelliptic curve polynomial from disclosed Mumford
divisors. If the known-plaintext suffix reveals a complete v(x) in the
first flag stream state, enumerate monic degree-g divisors of f-v² and
validate reconstructed candidate plaintexts. Never guess missing bytes.
"""
from __future__ import annotations

import ast
import re
import struct
from dataclasses import dataclass

from .hyperelliptic_state_leak import (
    _sage_tree,
    _source_profile,
    curve_from_divisors,
    extract_instance,
    unpack_state,
)
from .network_policy import connect_authorized

_TOKEN = re.compile(rb"[A-Za-z][A-Za-z0-9_-]{1,39}\{[^{}\r\n]{1,256}\}\Z")
_HEX_LINE = re.compile(rb"(?m)^[ \t]*([0-9a-fA-F]{2,})[ \t]*$")


@dataclass(frozen=True)
class JacobianRecovery:
    polynomial: tuple[int, ...]
    states: int
    ciphertext_bytes: int
    recovered_flag: str | None
    candidates: int
    explanation: str
    public_ciphertext_hex: str = ""
    chosen_keystream_hex: str = ""

    def report(self):
        return {
            "curve_polynomial": [str(x) for x in self.polynomial],
            "independent_mumford_states": self.states,
            "public_ciphertext_bytes": self.ciphertext_bytes,
            "public_ciphertext_hex": self.public_ciphertext_hex,
            "chosen_keystream_hex": self.chosen_keystream_hex,
            "recovered_flag": self.recovered_flag,
            "candidate_count": self.candidates,
            "status": "flag-recovered" if self.recovered_flag else "partial",
            "reason": self.explanation,
        }


def _word_format(model):
    if model.coefficient_encoding not in ("Q", "I", "H", "B"):
        raise ValueError("unsupported Mumford binary serializer")
    return ("<" if model.byte_order == "little" else ">") + model.coefficient_encoding


class _FactorSearch:
    """Bounded enumeration of monic degree-g products of modular factors."""

    def __init__(self, components, genus, prime, variable, max_factors):
        self.components = components
        self.genus = genus
        self.prime = prime
        self.variable = variable
        self.max_factors = max_factors
        self.explored = 0
        self.count = 0

    def visit(self, index, degree, current):
        from sympy import Poly

        if index == len(self.components):
            if degree == self.genus:
                self.count += 1
                if self.count > self.max_factors:
                    raise RuntimeError("too many candidate Mumford divisors")
                yield current.monic()
            return
        factor, multiplicity = self.components[index]
        power = Poly(1, self.variable, modulus=self.prime)
        for used in range(multiplicity + 1):
            if degree + used*factor.degree() > self.genus:
                break
            self.explored += 1
            if self.explored > self.max_factors*64:
                raise RuntimeError("factor-combination budget exceeded")
            yield from self.visit(index+1, degree+used*factor.degree(),
                                  current*power)
            power *= factor


def _degree_divisors(polynomial, prime, genus, *, max_factors=1024):
    """Enumerate bounded monic degree-g factors over the source field.

    A modular factorization is never accepted alone as a plaintext proof:
    every candidate is checked against all disclosed keystream bytes.
    """
    from sympy import Poly, symbols

    x = symbols("z")
    expr = sum(int(c) * x**i for i, c in enumerate(polynomial))
    _, factor_list = Poly(expr, x, modulus=prime).factor_list()
    components = [(factor.monic(), int(power))
                  for factor, power in factor_list]
    search = _FactorSearch(components, genus, prime, x, max_factors)
    yield from (
        tuple(int(poly.nth(i)) % prime for i in range(genus)) + (1,)
        for poly in search.visit(0, 0, Poly(1, x, modulus=prime))
    )


def _disclosed_v(ciphertext, model, secret_size):
    """Return (v, disclosed, reason); reason explains why v is unavailable."""
    suffix = model.known_plaintext_suffix
    genus = model.genus
    word = model.coefficient_bytes
    v_start, v_end = genus*word, genus*2*word
    if secret_size > v_start or len(ciphertext) < v_end:
        return None, None, ("the disclosed suffix does not expose the full "
                            "first Mumford v polynomial; more algebraic "
                            "constraints needed")
    disclosed = {
        secret_size+i: ciphertext[secret_size+i] ^ value
        for i, value in enumerate(suffix)
    }
    if not all(i in disclosed for i in range(v_start, v_end)):
        return None, None, ("known suffix does not include all first-state "
                            "v coefficients")
    word_format = _word_format(model)
    fmt = word_format[0] + word_format[1]*genus
    v = struct.unpack(
        fmt, bytes(disclosed[i] for i in range(v_start, v_end))
    )
    if any(x >= model.prime for x in v):
        return None, None, ("known plaintext produces out-of-field "
                            "Jacobian coefficients")
    return v, disclosed, None


def _state_plaintext(state, disclosed, ciphertext, suffix, secret_size):
    if any(state[i] != byte for i, byte in disclosed.items()
           if i < len(state)):
        return None
    plaintext = bytes(
        c ^ state[i] for i, c in enumerate(ciphertext[:secret_size])
    )
    if not _TOKEN.fullmatch(plaintext):
        return None
    # Only first-state bytes are reconstructed here. Later stream
    # states may also contain known plaintext, but cannot be checked
    # against this state's Mumford divisor.
    if any((ciphertext[i] ^ state[i]) != suffix[i-secret_size]
           for i in range(secret_size,
                          min(len(ciphertext), len(state)))):
        return None
    return plaintext.decode("ascii")


def derive_flag_candidates(ciphertext, polynomial, model, *, max_factors=1024):
    """Try a full verified plaintext when the first v polynomial is known.

    This is one mathematically sufficient disclosure pattern, not a claim
    that all partial Mumford states are solvable this way.
    """
    suffix = model.known_plaintext_suffix
    if suffix is None:
        return (), "source does not establish a known-plaintext suffix"
    if len(ciphertext) < len(suffix):
        raise ValueError("ciphertext shorter than source-proven known suffix")
    secret_size = len(ciphertext)-len(suffix)
    if secret_size < 1:
        raise ValueError("empty secret")
    genus = model.genus
    v, disclosed, reason = _disclosed_v(ciphertext, model, secret_size)
    if v is None:
        return (), reason
    word_format = _word_format(model)
    fmt = word_format[0] + word_format[1]*genus
    square = [0]*(2*genus-1)
    for i, left in enumerate(v):
        for j, right in enumerate(v):
            square[i+j] = (square[i+j]+left*right) % model.prime
    difference = [
        (int(polynomial[i]) if i < len(polynomial) else 0)
        - (square[i] if i < len(square) else 0)
        for i in range(max(len(polynomial), len(square)))
    ]
    found = set()
    for u in _degree_divisors(
        difference, model.prime, genus, max_factors=max_factors,
    ):
        state = struct.pack(fmt.replace(word_format[1]*genus,
                                        word_format[1]*(2*genus)),
                            *u[:-1], *v)
        plaintext = _state_plaintext(
            state, disclosed, ciphertext, suffix, secret_size)
        if plaintext is not None:
            found.add(plaintext)
    return tuple(sorted(found)), (
        "verified candidate Mumford factors of f-v² against every "
        "known plaintext byte in the reconstructed first state"
    )


def analyze_transcript(chosen_stream, public_ciphertext, model, *,
                       max_factors=1024):
    if not model.chosen_plaintext:
        raise ValueError("source does not establish chosen-plaintext access")
    if len(chosen_stream) < 3*model.state_bytes:
        raise RuntimeError("need at least three complete Jacobian states")
    if len(chosen_stream) % model.state_bytes:
        raise ValueError("chosen stream is not a whole number of states")
    states = [
        unpack_state(
            chosen_stream[i:i+model.state_bytes], model,
        ) for i in range(0, len(chosen_stream), model.state_bytes)
    ]
    polynomial = curve_from_divisors(states, model)
    possibilities, explanation = derive_flag_candidates(
        public_ciphertext, polynomial, model, max_factors=max_factors,
    )
    recovered = possibilities[0] if len(possibilities) == 1 else None
    return JacobianRecovery(
        tuple(polynomial), len(states), len(public_ciphertext),
        recovered, len(possibilities),
        explanation if recovered else (
            explanation + "; " + str(len(possibilities)) +
            " verified flag candidates (requires uniqueness)"
        ),
        public_ciphertext.hex(), chosen_stream.hex(),
    )


def source_input_prompt(documents):
    """Extract the input() delimiter from the *same* verified source."""
    prompts = []
    for doc in documents:
        if _source_profile(doc) is None:
            continue
        tree = _sage_tree(doc.text)
        if tree is None:
            continue
        matches = {
            call.args[0].value
            for call in ast.walk(tree)
            if (isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "input"
                and len(call.args) == 1
                and isinstance(call.args[0], ast.Constant)
                and isinstance(call.args[0].value, str))
        }
        if len(matches) == 1:
            prompts.append(next(iter(matches)))
    return prompts[0] if len(prompts) == 1 else None


def _read_prompt(conn, marker, *, limit=2_000_000):
    data = bytearray()
    while marker not in data:
        if len(data) > limit:
            raise RuntimeError("oracle transcript too large")
        received = conn.recv(8192)
        if not received:
            raise ConnectionError("oracle closed connection before input prompt")
        data.extend(received)
    return bytes(data)


def _parse_ciphertext(data):
    found = _HEX_LINE.findall(data)
    if len(found) != 1 or len(found[0]) % 2:
        raise ValueError("expected one valid hexadecimal ciphertext line")
    return bytes.fromhex(found[0].decode("ascii"))


def collect_oracle(host, port, model, prompt, *, timeout=30, states=4):
    """Collect public ciphertext and chosen-zero keystream in one TCP session."""
    if not 3 <= states <= 16:
        raise ValueError("state count outside bounded budget")
    if not isinstance(prompt, str) or not 0 < len(prompt) <= 256:
        raise ValueError("missing source-derived input prompt")
    marker = prompt.encode()
    with connect_authorized(host, port, timeout) as conn:
        conn.settimeout(timeout)
        first = _read_prompt(conn, marker)
        ciphertext = _parse_ciphertext(first.split(marker, 1)[0])
        conn.sendall(b"00" * (model.state_bytes * states) + b"\n")
        second = _read_prompt(conn, marker)
        keystream = _parse_ciphertext(second.split(marker, 1)[0])
    if len(keystream) != states*model.state_bytes:
        raise RuntimeError("chosen-zero response has unexpected byte count")
    return keystream, ciphertext


def investigate(documents, host, port, *, timeout=30, states=4,
                max_factors=1024):
    model = extract_instance(documents)
    if model is None:
        raise ValueError("source does not prove Jacobian state disclosure")
    prompt = source_input_prompt(documents)
    if prompt is None:
        raise RuntimeError("no unique source-derived chosen-plaintext prompt")
    stream, ciphertext = collect_oracle(
        host, port, model, prompt, timeout=timeout, states=states,
    )
    return analyze_transcript(
        stream, ciphertext, model, max_factors=max_factors,
    )


def recover_flag(documents, host, port, *, timeout=30):
    result = investigate(documents, host, port, timeout=timeout)
    if result.recovered_flag is None:
        raise RuntimeError(
            "partial Jacobian reconstruction verified but plaintext "
            "is not unique: " + result.explanation
        )
    return result.recovered_flag
