from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .parser import collect_documents
from .scanner import scan


COLORS = {"critical": "\033[91m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET = "\033[0m"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cryptoscan", description="Deterministic offline CTF cryptography scanner")
    parser.add_argument("targets", nargs="+", help="files or directories to scan")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--fermat-steps", type=int, default=100_000, help="maximum Fermat iterations per RSA modulus")
    parser.add_argument("--fail-on-findings", action="store_true", help="return exit status 1 when findings exist")
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
        output.append(f"  Solver: {json.dumps(finding.solver, sort_keys=True, ensure_ascii=False)}")
        output.append(f"  Patch: {finding.patch}")
    return "\n".join(output)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.fermat_steps < 0:
        _parser().error("--fermat-steps must be non-negative")
    documents = collect_documents(args.targets)
    findings = scan(documents, args.fermat_steps)
    if args.format == "json":
        print(json.dumps({"schema_version": 1, "findings": [item.to_dict() for item in findings]}, sort_keys=True, indent=2, ensure_ascii=False))
    else:
        color = not args.no_color and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        print(_text(findings, color))
    return 1 if args.fail_on_findings and findings else 0
