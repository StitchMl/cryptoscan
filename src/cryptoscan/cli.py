from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .cookie import main as cookie_main
from .assistant import assistant_session
from .diagnostics import diagnose_runtime
from .dghv_workflow import recover_flag as recover_dghv_flag, supported_source as supported_dghv_source
from .eclcg_workflow import extract_instance as extract_eclcg_instance, recover_flag as recover_eclcg_flag
from .fischlin_workflow import recover_flag as recover_fischlin_flag, supported_source as supported_fischlin_source
from .gcm_hidden_state import recognize_gcm_tag_oracle
from .gcm_hidden_live import (
    recover_flag as recover_gcm_hidden_flag,
    supports_wire_profile as supports_gcm_wire_profile,
)
from .hamiltonicity_workflow import extract_instance as extract_fiat_shamir_graph, recover_flag as recover_fs_graph_flag
from .fiat_shamir_batch import extract_instance as extract_batch_fiat_shamir, recover_flag as recover_batch_fs_flag
from .parser import collect_documents
from .scanner import scan
from .ntru_auto import instances as ntru_instances, recover_flag as recover_ntru_flag
from .stream_combiner_workflow import recognize_stream_cipher, recover_stream_cipher
from .terminal_report import render_findings

COLORS = {"critical": "\033[91m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET = "\033[0m"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptoscan", description="Deterministic offline CTF cryptography scanner")
    parser.add_argument("targets", nargs="+", help="files or directories to scan; use cryptoscan cookie --help for cookie tools")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    colors = parser.add_mutually_exclusive_group()
    colors.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    colors.add_argument("--color", action="store_true", help="force ANSI colors (useful with redirected output)")
    parser.add_argument("--verbose", "-v", action="store_true", help="show full evidence, solver data and recovery steps")
    parser.add_argument("--assist", action="store_true", help="start guided CLI after scanning, including in non-TTY sessions")
    parser.add_argument("--no-assist", action="store_true", help="never start guided CLI")
    parser.add_argument("--fermat-steps", type=int, default=100_000, help="maximum Fermat iterations per RSA modulus")
    parser.add_argument("--fail-on-findings", action="store_true", help="return exit status 1 when findings exist")
    parser.add_argument("--solve", action="store_true", help="run a source-verified supported CTF solver (opt-in network)")
    parser.add_argument("--host", help="authorized CTF service hostname for --solve")
    parser.add_argument("--port", type=int, help="authorized CTF service TCP port for --solve")
    parser.add_argument("--timeout", type=float, default=30.0, help="network socket timeout for --solve")
    parser.add_argument("--bkz-block", type=int, default=20,
                        help="BKZ block size for offline lattice recovery (0 means LLL only)")
    parser.add_argument("--lattice-timeout", type=int, default=900,
                        help="maximum offline lattice worker duration in seconds")
    parser.add_argument("--lattice-backend", choices=("auto", "fplll", "fpylll", "flint", "sympy"),
                        default="auto", help="lattice reduction backend for offline solving")
    parser.add_argument("--initial-fold", type=int, default=64,
                        help="initial NTRU folding degree, must divide n by a power of two")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _text(findings, color: bool, *, verbose: bool = True) -> str:
    """Compatibility wrapper: direct callers retain the detailed report."""
    return render_findings(findings, color=color, verbose=verbose)


def _execute_recovery(label, solver, *parameters, **options) -> int:
    """Run exactly one proven strategy and report a remotely/locally verified flag."""
    try:
        flag = solver(*parameters, **options)
    except (RuntimeError, ValueError, OSError, ImportError, ArithmeticError) as exc:
        print(f"{label} solver failed: {exc}", file=sys.stderr)
        return 2
    print(f"FLAG: {flag}")
    return 0


def _solve_documents(args, documents) -> int:
    """Separate solver selection from parsing, scanning and presentation."""
    if args.host and args.port:
        remote = (
            (extract_batch_fiat_shamir, recover_batch_fs_flag, "Fiat-Shamir transcript-collision"),
            (extract_fiat_shamir_graph, recover_fs_graph_flag, "Fiat-Shamir grinding"),
            (supports_gcm_wire_profile, recover_gcm_hidden_flag, "GCM hidden-state"),
            (supported_fischlin_source, recover_fischlin_flag, "Fischlin"),
            (supported_dghv_source, recover_dghv_flag, "DGHV"),
        )
        for matches, solver, label in remote:
            if matches(documents):
                return _execute_recovery(
                    label, solver, documents, args.host, args.port,
                    timeout=args.timeout,
                )
    else:
        streams = recognize_stream_cipher(documents)
        if streams:
            return _execute_recovery("LFSR correlation", recover_stream_cipher, streams[0])
        if extract_eclcg_instance(documents) is not None:
            return _execute_recovery("ECDSA-LCG", recover_eclcg_flag, documents)
        if ntru_instances(documents):
            return _execute_recovery(
                "NTRU lattice", recover_ntru_flag, documents,
                bkz=args.bkz_block, backend=args.lattice_backend,
                initial_degree=args.initial_fold,
                timeout_seconds=args.lattice_timeout,
            )
    print(
        "No supported source-verified solver for these files and endpoint.",
        file=sys.stderr,
    )
    return 2


def _validate_arguments(args) -> None:
    if args.fermat_steps < 0:
        _parser().error("--fermat-steps must be non-negative")
    if args.assist and args.no_assist:
        _parser().error("--assist and --no-assist cannot be combined")
    if args.solve and (args.format == "json" or args.assist or args.no_assist):
        _parser().error("--solve cannot be combined with --format json, --assist, or --no-assist")
    if args.solve and bool(args.host) != bool(args.port):
        _parser().error("--host and --port must be supplied together")
    if args.assist and args.format == "json":
        _parser().error("--assist cannot be combined with --format json")


def _print_report(args, findings) -> None:
    if args.format == "json":
        print(json.dumps({"schema_version": 1, "findings": [item.to_dict() for item in findings]}, sort_keys=True, indent=2, ensure_ascii=False))
    else:
        color = not args.no_color and os.environ.get("NO_COLOR") is None and (args.color or sys.stdout.isatty())
        print(_text(findings, color, verbose=args.verbose))


def _should_assist(args, findings) -> bool:
    if args.no_assist or args.format != "text":
        return False
    return bool(args.assist or (findings and sys.stdin.isatty() and sys.stdout.isatty()))


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "doctor":
        return diagnose_runtime()
    if arguments and arguments[0] == "cookie":
        return cookie_main(arguments[1:])
    if arguments and arguments[0] == "assist":
        if len(arguments) == 1:
            assistant_session()
            return 0
        arguments = arguments[1:] + ["--assist"]
    args = _parser().parse_args(arguments)
    _validate_arguments(args)
    documents = collect_documents(args.targets)
    findings = scan(documents, args.fermat_steps)
    _print_report(args, findings)
    if args.solve:
        return _solve_documents(args, documents)
    if _should_assist(args, findings):
        assistant_session(findings, documents=documents)
    return 1 if args.fail_on_findings and findings else 0
