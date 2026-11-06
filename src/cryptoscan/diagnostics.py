"""Diagnose the exact Python interpreter used by the cryptoscan entry point."""
from __future__ import annotations

import importlib.util
import sys
from typing import Any, Callable


def diagnose_runtime(write: Callable[[str], Any] = print) -> int:
    write("CryptoScan runtime interpreter: " + sys.executable)
    write("Python version: " + sys.version.split()[0])
    write("Install dependencies for THIS interpreter:")
    write('  "' + sys.executable + '" -m pip install --upgrade -e .')
    try:
        import sympy
    except ImportError as exc:
        write("SymPy import: FAILED (" + str(exc) + ")")
        write('  "' + sys.executable + '" -m pip install --upgrade sympy')
        return 1
    write("SymPy import: OK")
    write("SymPy version: " + sympy.__version__)
    write("SymPy location: " + str(sympy.__file__))
    try:
        from sympy import Matrix
        _ = Matrix([[1, 0], [0, 1]]).lll()
    except (ImportError, AttributeError, ValueError) as exc:
        write("SymPy LLL: FAILED (" + str(exc) + ")")
        return 1
    write("SymPy LLL: OK")
    return 0
