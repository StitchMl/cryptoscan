"""Finding-driven NTRU lattice attack. No CTF-specific flag or key material."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from .ntru import recognize_ntru, pair_ntru_records
from .ntru_lattice import solve
from .parser import Document, scalar_records


def ntru_lattice_workflow(
    finding: Any, documents: Sequence[Document],
    read: Callable[[str], str] = input,
    write: Callable[[str], Any] = print,
) -> None:
    source_path = finding.evidence.get("source_path")
    contexts = [
        context for context in recognize_ntru(documents)
        if context.path == source_path
    ]
    if len(contexts) != 1:
        write("Cannot identify a unique source-derived NTRU implementation.")
        return
    context = contexts[0]
    records = []
    for document in documents:
        for record in scalar_records(document.text):
            records.append({
                "scope": document.scope,
                "location": document.path + ":assignments",
                "object": record,
            })
    pairs = pair_ntru_records(records, context)
    if len(pairs) != 1:
        write("Need exactly one matching public polynomial and ciphertext in scan evidence.")
        return
    public, encrypted = pairs[0]
    write(
        f"Source-derived NTRU: n={context.degree}, p={context.plaintext_modulus}, "
        f"q={context.ciphertext_modulus}, df={context.f_weight}, dg={context.g_weight}"
    )
    write(
        f"Constrained sparse-key lattice dimension: {2 * context.degree - 1}. "
        "This is expensive and not guaranteed to recover the key."
    )
    if context.degree > 32:
        write("Large-degree lattice backend: fpylll (optional; Linux/WSL/Sage recommended).")
    if read("Attempt lattice private-key recovery? [y/N]: ").strip().lower() not in {"y", "yes"}:
        write("No computation started.")
        return
    bkz_value = read("Optional BKZ block size [0=LLL only]: ").strip() or "0"
    try:
        bkz = int(bkz_value)
        results = solve(
            public["value"], encrypted["value"],
            context.degree, context.plaintext_modulus, context.ciphertext_modulus,
            context.f_weight, context.g_weight,
            bkz=bkz, progress=write,
        )
    except (ValueError, RuntimeError, ImportError, MemoryError) as exc:
        write("NTRU key recovery stopped: " + str(exc))
        return
    if not results:
        write(
            "No source-compatible private key with printable plaintext was recovered. "
            "This does NOT imply the instance is secure; a stronger lattice reduction "
            "or a different attack may be required."
        )
        return
    write(f"Recovered {len(results)} mathematically checked plaintext candidate(s).")
    for index, result in enumerate(results, 1):
        write(f"Candidate {index}: " + result["plaintext"].decode("ascii"))
        write(
            "Public-key relation verified: YES; flag-shaped: "
            + ("YES" if result["flag_shaped"] else "NO")
        )
    write("Candidate recovery is offline; it is not a verified remote flag submission.")
