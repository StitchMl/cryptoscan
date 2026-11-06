from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .cookie import main as cookie_main
from .assistant import assistant_session
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
    if args.assist and args.format == "json":
        _parser().error("--assist cannot be combined with --format json")
    documents = collect_documents(args.targets)
    findings = scan(documents, args.fermat_steps)
    if args.format == "json":
        print(json.dumps({"schema_version": 1, "findings": [item.to_dict() for item in findings]}, sort_keys=True, indent=2, ensure_ascii=False))
    else:
        color = not args.no_color and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        print(_text(findings, color))
    if not args.no_assist and args.format == "text" and (args.assist or (findings and sys.stdin.isatty() and sys.stdout.isatty())):
        assistant_session(findings)
    return 1 if args.fail_on_findings and findings else 0
