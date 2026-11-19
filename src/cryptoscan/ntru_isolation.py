"""Subprocess boundary ensures native FLINT memory is returned to Windows.

Large lattice matrices are never retained by the interactive CLI process.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import Any


def _run_streamed_worker(
    data: str,
    timeout_seconds: int,
    progress: Callable[[str], None],
) -> subprocess.CompletedProcess[str]:
    """Stream solver stages while keeping native matrices outside the CLI process.

    On timeout terminate the entire OS process group, including nested
    fplll/WSL children, rather than just the small Python wrapper.
    """
    command = [sys.executable, "-m", "cryptoscan.ntru_worker"]
    options = (
        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        if os.name == "nt" else {"start_new_session": True}
    )
    worker = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1, **options,
    )
    output: list[str] = []
    logs: list[str] = []

    def consume_output() -> None:
        assert worker.stdout is not None
        for line in worker.stdout:
            if line.lstrip().startswith('{"results":'):
                output.append(line)
            else:
                logs.append(line)
                if line.strip():
                    progress(line.rstrip())

    reader = threading.Thread(target=consume_output, daemon=True)
    reader.start()
    try:
        assert worker.stdin is not None
        worker.stdin.write(data)
        worker.stdin.close()
        status = worker.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(worker.pid), "/T", "/F"],
                capture_output=True, text=True, check=False,
            )
        else:
            try:
                os.killpg(worker.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        worker.wait()
        raise RuntimeError(
            f"NTRU worker stopped after {timeout_seconds}s; process group terminated."
        ) from exc
    finally:
        reader.join(timeout=5)
    return subprocess.CompletedProcess(command, status, "".join(output), "".join(logs))


def solve_isolated(
    h: list[int], ct: list[int], n: int, p: int, q: int,
    df: int, dg: int, *, bkz: int = 0,
    timeout_seconds: int = 300,
    method: str = "full",
    backend: str = "auto",
    initial_degree: int = 64,
    stream: bool = False,
    progress: Callable[[str], None] = print,
) -> list[dict[str, Any]]:
    if method not in {"full", "fold"}:
        raise ValueError("NTRU method must be full or fold")
    if backend not in {"auto", "sympy", "flint", "fpylll", "fplll"}:
        raise ValueError("Unsupported lattice backend")
    if type(initial_degree) is not int or not 2 <= initial_degree <= 2048:
        raise ValueError("Invalid initial folding degree")
    if not 1 <= timeout_seconds <= 3600:
        raise ValueError("worker timeout must be between 1 and 3600 seconds")
    data = json.dumps({
        "h": h, "ct": ct, "n": n, "p": p, "q": q,
        "df": df, "dg": dg, "bkz": bkz, "method": method,
        "backend": backend, "initial_degree": initial_degree,
    })
    progress(
        "Launching isolated NTRU worker with Python " + sys.executable
        + f"; timeout {timeout_seconds}s. Native memory will be released on exit."
    )
    try:
        completed = (
            _run_streamed_worker(data, timeout_seconds, progress)
            if stream else subprocess.run(
                [sys.executable, "-m", "cryptoscan.ntru_worker"],
                input=data, capture_output=True, text=True,
                timeout=timeout_seconds, check=False,
            )
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
