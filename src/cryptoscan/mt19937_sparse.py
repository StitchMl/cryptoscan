"""Sparse-output prediction for Python's MT19937-based random.getrandbits.

When a challenge exposes two selectable 32-bit outputs from a consecutive
stream, the MT recurrence can recover the next output without cloning the
whole generator. The index derivation is parameterized by the target draw.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from .network_policy import connect_authorized


_WORD_MASK = 0xFFFFFFFF
_UPPER_MASK = 0x80000000
_LOWER_MASK = 0x7FFFFFFF
_MATRIX_A = 0x9908B0DF
_TEMPER_B = 0x9D2C5680
_TEMPER_C = 0xEFC60000


@dataclass(frozen=True)
class SparseMT19937Model:
    output_count: int
    target_index: int


def extract_instance(documents: Sequence[object]) -> SparseMT19937Model | None:
    """Recognize a consecutive 32-bit Python PRNG stream and its next draw."""
    source = "\n".join(getattr(doc, "text", "") for doc in documents)
    if not re.search(r"\brandom\s*\.\s*getrandbits\s*\(\s*32\s*\)", source):
        return None
    counts = re.findall(r"\brange\s*\(\s*(\d{2,7})\s*\)", source)
    if not counts:
        return None
    # The largest bounded range commonly encloses the generated output list.
    output_count = max(map(int, counts))
    if output_count <= 624:
        return None
    target = output_count
    if not 0 <= target - 624 + 1 < output_count:
        return None
    return SparseMT19937Model(output_count, target)


def _undo_right(value: int, shift: int) -> int:
    result = value
    for _ in range(6):
        result = value ^ (result >> shift)
    return result & _WORD_MASK


def _undo_left(value: int, shift: int, mask: int) -> int:
    result = value
    for _ in range(6):
        result = value ^ ((result << shift) & mask)
    return result & _WORD_MASK


def untemper(value: int) -> int:
    """Invert the four MT19937 output tempering steps."""
    value = _undo_right(value, 18)
    value = _undo_left(value, 15, _TEMPER_C)
    value = _undo_left(value, 7, _TEMPER_B)
    return _undo_right(value, 11)


def temper(value: int) -> int:
    """Apply the MT19937 output tempering transform."""
    value ^= value >> 11
    value ^= (value << 7) & _TEMPER_B
    value ^= (value << 15) & _TEMPER_C
    value ^= value >> 18
    return value & _WORD_MASK


def twist_word(known_msb: int, following: int, offset_state: int) -> int:
    """Compute one twist word from a known high bit, next word, and offset word."""
    joined = (known_msb & _UPPER_MASK) | (following & _LOWER_MASK)
    result = offset_state ^ (joined >> 1)
    if following & 1:
        result ^= _MATRIX_A
    return result & _WORD_MASK


def predict_from_sparse_outputs(target_index: int, first_output: int,
                                second_output: int) -> int:
    """Predict output[target_index] from the two recurrence source words."""
    first_index = target_index - 624 + 1
    second_index = target_index - 624 + 397
    if first_index < 0 or second_index <= first_index:
        raise ValueError("target draw is too early for the sparse MT19937 recurrence")
    first_state = untemper(first_output)
    second_state = untemper(second_output)
    return temper(twist_word(0, first_state, second_state))


def _read_line(stream, limit: int = 4096) -> bytes:
    data = bytearray()
    while len(data) < limit:
        char = stream.read(1)
        if not char:
            break
        data.extend(char)
        if char == b"\n":
            break
    return bytes(data)


def recover_flag(documents: Sequence[object], host: str, port: int,
                 timeout: float = 30.0) -> str:
    """Use two chosen-index leaks, predict the target, and return the flag."""
    model = extract_instance(documents)
    if model is None:
        raise ValueError("source does not establish a consecutive 32-bit MT19937 stream")
    first_index = model.target_index - 624 + 1
    second_index = model.target_index - 624 + 397
    with connect_authorized(host, port, timeout) as sock:
        stream = sock.makefile("rwb", buffering=0)
        banner = bytearray()
        while b"number!\n" not in banner and len(banner) < 16384:
            line = _read_line(stream)
            if not line:
                break
            banner.extend(line)
        if b"number!\n" not in banner:
            raise ValueError("service did not expose the expected selectable-number prompt")
        stream.write(f"{first_index}\n{second_index}\n".encode("ascii"))
        selected = {}
        requested = {first_index, second_index}
        for output_index in range(model.output_count):
            line = _read_line(stream)
            if not line:
                raise ValueError("service closed before returning the generated sequence")
            if output_index not in requested:
                continue
            try:
                selected[output_index] = int(line.strip())
            except ValueError as exc:
                raise ValueError(
                    f"service did not reveal the requested output at index {output_index}"
                ) from exc
        if set(selected) != requested:
            raise ValueError("service did not return both requested indexed outputs")
        guess = predict_from_sparse_outputs(
            model.target_index, selected[first_index], selected[second_index],
        )
        stream.write(f"{guess}\n".encode("ascii"))
        response = bytearray()
        while len(response) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            if b"}" in response:
                break
    match = re.search(rb"(?:flag|ctf|tetctf)\{[^\r\n}]{1,200}\}",
                      bytes(response), re.IGNORECASE)
    if match is None:
        raise ValueError("predicted value was submitted but no flag-shaped response was returned")
    return match.group().decode("ascii")
