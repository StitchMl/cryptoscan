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
    # The prompt's Nth number is zero-based index N-1.
    target = output_count - 1
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


def predict_sparse_candidates(target_index: int, first_output: int,
                               second_output: int) -> tuple[int, int]:
    """Return both outputs allowed by the one unknown MT state MSB."""
    first_index = target_index - 624 + 1
    second_index = target_index - 624 + 397
    if first_index < 0 or second_index <= first_index:
        raise ValueError("target draw is too early for the sparse MT19937 recurrence")
    first_state = untemper(first_output)
    second_state = untemper(second_output)
    return tuple(
        temper(twist_word(msb, first_state, second_state))
        for msb in (0, _UPPER_MASK)
    )


def predict_from_sparse_outputs(target_index: int, first_output: int,
                                second_output: int) -> int:
    """Return the candidate corresponding to a zero guess for the missing MSB."""
    return predict_sparse_candidates(
        target_index, first_output, second_output,
    )[0]

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


def _recover_once(documents: Sequence[object], model: SparseMT19937Model,
                  host: str, port: int, timeout: float,
                  candidate_index: int) -> bytes:
    """Collect the selectable sparse outputs and submit one MSB candidate."""
    first_index = model.target_index - 624 + 1
    second_index = model.target_index - 624 + 397
    requested = {first_index, second_index}
    with connect_authorized(host, port, timeout) as sock:
        stream = sock.makefile("rwb", buffering=0)
        _select_prompt(stream)
        stream.write(f"{first_index}\n{second_index}\n".encode("ascii"))
        selected = _read_selected(stream, model.target_index, requested)
        candidates = predict_sparse_candidates(
            model.target_index, selected[first_index], selected[second_index],
        )
        guess = candidates[candidate_index]
        stream.write(f"{guess}\n".encode("ascii"))
        return _read_submission(sock)


def _select_prompt(stream) -> None:
    banner = bytearray()
    while b"number!\n" not in banner and len(banner) < 16384:
        line = _read_line(stream)
        if not line:
            break
        banner.extend(line)
    if b"number!\n" not in banner:
        raise ValueError("service did not expose the expected selectable-number prompt")


def _read_selected(stream, target_index: int, requested: set[int]) -> dict[int, int]:
    selected = {}
    for output_index in range(target_index):
        line = _read_line(stream)
        if not line:
            raise ValueError(f"service stopped after {output_index} of {target_index} indexed outputs")
        if output_index in requested:
            _save_selected_output(selected, output_index, line)
    if set(selected) != requested:
        raise ValueError("service did not return both selected MT19937 outputs")
    return selected


def _save_selected_output(selected: dict[int, int], index: int, line: bytes) -> None:
    match = re.search(rb"-?\d+", line)
    if match is None:
        raise ValueError(f"service did not reveal the selected output at index {index}")
    selected[index] = int(match.group())


def _read_submission(sock) -> bytes:
    response = bytearray()
    while len(response) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response.extend(chunk)
        if b"}" in response or _submission_rejected(response):
            break
    return bytes(response)


def _submission_rejected(response: bytearray) -> bool:
    lowered = response.lower()
    return b"nope" in lowered or b"wrong" in lowered


def recover_flag(documents: Sequence[object], host: str, port: int,
                 timeout: float = 30.0) -> str:
    """Retry independent seeds until one of the two MT twist candidates wins."""
    model = extract_instance(documents)
    if model is None:
        raise ValueError("source does not establish a consecutive 32-bit MT19937 stream")

    last_response = b""
    # Each session leaves one unknown state MSB, so either candidate succeeds
    # with probability 1/2. Independent connections make retries effective.
    for attempt in range(64):
        response = _recover_once(
            documents, model, host, port, timeout, candidate_index=attempt & 1,
        )
        match = re.search(
            rb"(?:flag|ctf|tetctf)\{[^\r\n}]{1,200}\}",
            response, re.IGNORECASE,
        )
        if match is not None:
            return match.group().decode("ascii")
        last_response = response

    excerpt = last_response.decode("ascii", "replace")[:160].strip()
    raise ValueError(
        "MT19937 candidate was rejected in 64 independent sessions"
        + (f" (last response: {excerpt})" if excerpt else "")
    )
