"""Isolated process entry point for expensive lattice reductions.

It only accepts bounded JSON on stdin and emits bounded result summaries.
The parent process retains no FLINT matrix or large reduced basis.
"""
from __future__ import annotations

import json
import sys

from .ntru_lattice import solve


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(131073)
        if len(raw) > 131072:
            raise ValueError("NTRU input exceeds process safety limit")
        data = json.loads(raw)
        required = {"h", "ct", "n", "p", "q", "df", "dg", "bkz"}
        if not isinstance(data, dict) or set(data) != required:
            raise ValueError("invalid NTRU worker input")
        n = data["n"]
        h, ct = data["h"], data["ct"]
        if not (type(n) is int and 2 <= n <= 2048
                and isinstance(h, list) and isinstance(ct, list)
                and len(h) == n and len(ct) == n):
            raise ValueError("invalid NTRU vector dimensions")
        results = solve(
            h, ct, n, data["p"], data["q"], data["df"], data["dg"],
            bkz=data["bkz"],
            progress=lambda message: print(message, file=sys.stderr, flush=True),
        )
        safe = [
            {
                "plaintext_hex": result["plaintext"].hex(),
                "public_relation_verified": bool(result["public_relation_verified"]),
                "flag_shaped": bool(result["flag_shaped"]),
            }
            for result in results[:16]
        ]
        print(json.dumps({"results": safe}))
        return 0
    except (ValueError, RuntimeError, ImportError, MemoryError, TypeError) as exc:
        print("NTRU worker error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
