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
from .parser import collect_documents
from .scanner import scan

COLORS = {"critical": "\033[91m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET = "\033[0m"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptoscan", description="Deterministic offline CTF cryptography scanner")
    parser.add_argument("targets", nargs="+", help="files or directories to scan; use cryptoscan cookie --help for cookie tools")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--assist", action="store_true", help="start guided CLI after scanning, including in non-TTY sessions")
    parser.add_argument("--no-assist", action="store_true", help="never start guided CLI")
    parser.add_argument("--fermat-steps", type=int, default=100_000, help="maximum Fermat iterations per RSA modulus")
    parser.add_argument("--fail-on-findings", action="store_true", help="return exit status 1 when findings exist")
    parser.add_argument("--solve", action="store_true", help="run a source-verified supported CTF solver (opt-in network)")
    parser.add_argument("--host", help="authorized CTF service hostname for --solve")
    parser.add_argument("--port", type=int, help="authorized CTF service TCP port for --solve")
    parser.add_argument("--timeout", type=float, default=30.0, help="network socket timeout for --solve")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _text(findings, color: bool) -> str:
    if not findings:
        return "No cryptographic weaknesses found."
    output = []
    for finding in findings:
        prefix = COLORS.get(finding.severity, "") if color else ""
        suffix = RESET if prefix else ""
        output.append(f"{prefix}[{finding.severity.upper()}] {finding.rule} {finding.id}{suffix}")
        output.append(f"  {finding.title} at {finding.location}")
        output.append(f"  Evidence: {json.dumps(finding.evidence, sort_keys=True, ensure_ascii=False)}")
        output.append(f"  Recovery: {finding.recovery_status}")
        output.append(f"  Flag path: {finding.flag_path}")
        output.append(f"  Preconditions: {'; '.join(finding.preconditions)}")
        output.append(f"  Attack: {finding.attack}")
        for index, step in enumerate(finding.playbook, 1):
            output.append(f"  Step {index}: {step}")
        output.append(f"  Solver: {json.dumps(finding.solver, sort_keys=True, ensure_ascii=False)}")
        if finding.cyberchef is not None:
            output.append(f"  CyberChef input: {finding.cyberchef['input']}")
            output.append(f"  CyberChef recipe: {json.dumps(finding.cyberchef['recipe'], separators=(',', ':'), ensure_ascii=False)}")
            output.append("  CyberChef use: import into a trusted local/offline instance; never upload challenge data to a public instance.")
        output.append(f"  Patch: {finding.patch}")
    return "\n".join(output)


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
    documents = collect_documents(args.targets)
    findings = scan(documents, args.fermat_steps)
    if args.format == "json":
        print(json.dumps({"schema_version": 1, "findings": [item.to_dict() for item in findings]}, sort_keys=True, indent=2, ensure_ascii=False))
    else:
        color = not args.no_color and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        print(_text(findings, color))
    if args.solve:
        if args.host and args.port and extract_fiat_shamir_graph(documents) is not None:
            try:
                flag = recover_fs_graph_flag(documents, args.host, args.port, timeout=args.timeout)
            except (RuntimeError, ValueError, OSError, ConnectionError) as exc:
                print(f"Fiat-Shamir grinding solver failed: {exc}", file=sys.stderr)
                return 2
            print(f"FLAG: {flag}")
            return 0
        if args.host and args.port and supports_gcm_wire_profile(documents):
            try:
                flag = recover_gcm_hidden_flag(documents, args.host, args.port, timeout=args.timeout)
            except (RuntimeError, ValueError, OSError, ConnectionError) as exc:
                print(f"GCM hidden-state solver failed: {exc}", file=sys.stderr)
                return 2
            print(f"FLAG: {flag}")
            return 0
        if args.host and args.port and supported_fischlin_source(documents):
            try:
                flag = recover_fischlin_flag(documents, args.host, args.port, timeout=args.timeout)
            except (RuntimeError, ValueError, OSError, ConnectionError) as exc:
                print(f"Fischlin solver failed: {exc}", file=sys.stderr)
                return 2
            print(f"FLAG: {flag}")
            return 0
        if not args.host and extract_eclcg_instance(documents) is not None:
            try:
                flag = recover_eclcg_flag(documents)
            except (RuntimeError, ValueError, ImportError, ArithmeticError) as exc:
                print(f"ECDSA-LCG solver failed: {exc}", file=sys.stderr)
                return 2
            print(f"FLAG: {flag}")
            return 0
        if not (args.host and args.port and supported_dghv_source(documents)):
            print("No supported source-verified solver for these files and endpoint.", file=sys.stderr)
            return 2
        if not supported_dghv_source(documents):
            print("No supported source-verified automatic solver for these files.", file=sys.stderr)
            return 2
        try:
            flag = recover_dghv_flag(documents, args.host, args.port, timeout=args.timeout)
        except (ConnectionError, OSError, RuntimeError, ValueError) as exc:
            print(f"DGHV solver failed: {exc}", file=sys.stderr)
            return 2
        print(f"FLAG: {flag}")
        return 0
    if not args.no_assist and args.format == "text" and (args.assist or (findings and sys.stdin.isatty() and sys.stdout.isatty())):
        assistant_session(findings, documents=documents)
    return 1 if args.fail_on_findings and findings else 0
