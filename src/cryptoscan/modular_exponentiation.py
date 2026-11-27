"""Recognize explicit modular exponentiation exercises."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence


_INTEGER = r"[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)"
_MODULAR_POWER = re.compile(
    rf"(?<![0-9A-Za-z_])({_INTEGER})\s*\^\s*({_INTEGER})"
    rf"\s+(?:mod|modulo)\s+({_INTEGER})(?![0-9A-Za-z_])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ModularExponentiation:
    base: int
    exponent: int
    modulus: int
    location: str


def _integer(token: str) -> int:
    return int(token, 0) if token.lower().startswith(("0x", "+0x", "-0x")) else int(token)


def extract_instance(documents: Sequence[object]) -> ModularExponentiation | None:
    """Extract one unambiguous a^e mod n exercise from supplied text."""
    matches: dict[tuple[int, int, int], str] = {}
    for document in documents:
        text = getattr(document, "text", "")
        if not isinstance(text, str):
            continue
        for match in _MODULAR_POWER.finditer(text):
            base, exponent, modulus = (_integer(token) for token in match.groups())
            if modulus > 1:
                matches.setdefault(
                    (base, exponent, modulus),
                    str(getattr(document, "path", "input")),
                )
    if len(matches) != 1:
        return None
    (base, exponent, modulus), location = next(iter(matches.items()))
    return ModularExponentiation(base, exponent, modulus, location)


def recover_answer(documents: Sequence[object]) -> str:
    task = extract_instance(documents)
    if task is None:
        raise ValueError("no unique modular exponentiation expression found")
    try:
        answer = pow(task.base, task.exponent, task.modulus)
    except ValueError as exc:
        raise ValueError("negative exponent requires an invertible base") from exc
    return str(answer)
