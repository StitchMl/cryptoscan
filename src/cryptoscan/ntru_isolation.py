"""Subprocess boundary ensures native FLINT memory is returned to Windows.

Large lattice matrices are never retained by the interactive CLI process.
"""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from typing import Any


def solve_isolated(
    h: list[int], ct: list[int], n: int, p: int, q: int,
    df: int, dg: int, *, bkz: int = 0,
    timeout_seconds: int = 300,
    progress: Callable[[str], None] = print,
) -> list[dict[str, Any]]:
    if not 1 <= timeout_seconds <= 3600:
        raise ValueError("worker timeout must be between 1 and 3600 seconds")
    data = json.dumps({
        "h": h, "ct": ct, "n": n, "p": p, "q": q,
        "df": df, "dg": dg, "bkz": bkz,
    })
    progress(
        "Launching isolated NTRU worker with Python " + sys.executable
        + f"; timeout {timeout_seconds}s. Native memory will be released on exit."
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "cryptoscan.ntru_worker"],
            input=data, capture_output=True, text=True,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"NTRU worker stopped after {timeout_seconds}s; resources released. "
            "The attack did not recover a key."
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip()[-2000:]
        raise RuntimeError(
            f"NTRU worker exited ({completed.returncode}): "
            + (detail or "no details; system may have terminated it")
        )
    try:
        response = json.loads(completed.stdout)
        results = response["results"]
        if not isinstance(results, list) or len(results) > 16:
            raise ValueError("invalid worker result")
        decoded = []
        for item in results:
            if not isinstance(item, dict):
                raise ValueError("invalid worker candidate")
            plaintext = bytes.fromhex(item["plaintext_hex"])
            if len(plaintext) > 4096 or not item["public_relation_verified"]:
                raise ValueError("invalid worker plaintext")
            decoded.append({
                "plaintext": plaintext,
                "public_relation_verified": True,
                "flag_shaped": bool(item["flag_shaped"]),
            })
        progress("Isolated NTRU process exited; native FLINT memory released.")
        return decoded
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("Invalid response from isolated NTRU worker") from exc
