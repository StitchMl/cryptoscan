"""Explicit offline RSA PKCS#1 v1.5 known-positive padding workflow."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from .parser import Document
from .rsa_padding_positives import (
    discover_positive_padding_oracles, recover_pkcs1_positive_padding,
)


def positive_padding_workflow(
    finding: Any, documents: Sequence[Document],
    read: Callable[[str], str] = input,
    write: Callable[[str], Any] = print,
) -> None:
    oracles = [
        item for item in discover_positive_padding_oracles(documents)
        if f"{item.source_path}:{item.source_line}" == finding.location
    ]
    if len(oracles) != 1:
        write("A unique source-linked RSA padding oracle transcript was not found.")
        return
    oracle = oracles[0]
    write(f"Source-proven PKCS#1 v1.5 padding oracle: {oracle.modulus.bit_length()}-bit RSA")
    write(f"Known positive blinded decryptions: {len(oracle.positive_multipliers)}")
    write("Each positive sample constrains the unknown plaintext to the 00 02 interval.")
    write("The attack is offline and requires an LLL lattice reduction; success is not guaranteed.")
    if read("Attempt RSA plaintext recovery? [y/N]: ").strip().casefold() not in {"y", "yes"}:
        write("No lattice operation started.")
        return
    try:
        candidates = recover_pkcs1_positive_padding(oracle, progress=write)
    except (RuntimeError, ValueError, MemoryError, OverflowError) as exc:
        write("RSA padding-oracle lattice recovery stopped: " + str(exc))
        return
    if not candidates:
        write("No RSA plaintext representative was recovered and re-encryption verified.")
        write("Do not treat this finding as a recovered flag; stronger reduction may be necessary.")
        return
    write(f"Recovered {len(candidates)} RSA-verified candidate(s).")
    for candidate in candidates:
        write("Recovered plaintext (UTF-8): " + candidate["plaintext_utf8"])
        write("Recovered plaintext (hex): " + candidate["plaintext_hex"])
        write("RSA re-encryption: PASS")
        write(f"Known-positive interval constraints verified: "
              f"{candidate['positive_constraints_verified']}")
    write("This verifies the offline RSA relation, not a remote flag submission.")
