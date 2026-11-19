"""Readable terminal reporting, independent of scanner and solver logic.

Text output is human-focused; JSON remains the complete machine-readable API.
"""
from __future__ import annotations

import json
import textwrap
from collections import Counter
from collections.abc import Sequence

from .model import Finding

RESET = "\x1b[0m"
STYLES = {
    "critical": "\x1b[1;91m",
    "high": "\x1b[1;31m",
    "medium": "\x1b[1;33m",
    "low": "\x1b[1;36m",
    "muted": "\x1b[90m",
    "title": "\x1b[1;96m",
    "good": "\x1b[1;32m",
    "label": "\x1b[1;37m",
    "warning": "\x1b[1;33m",
}


def paint(value: str, style: str, enabled: bool) -> str:
    if not enabled:
        return value
    return STYLES.get(style, "") + value + RESET


def _wrapped(label: str, value: str, *, width: int = 100, indent: int = 4) -> list[str]:
    prefix = "  " + label + ": "
    continuation = " " * max(indent, len(prefix))
    return textwrap.wrap(
        str(value), width=width, initial_indent=prefix,
        subsequent_indent=continuation, break_long_words=False,
        break_on_hyphens=False,
    ) or [prefix]


def _summary(finding: Finding, *, width: int = 100) -> list[str]:
    lines = _wrapped("Location", finding.location, width=width)
    lines.extend(_wrapped("Recovery", finding.recovery_status, width=width))
    lines.extend(_wrapped("Attack", finding.attack, width=width))
    return lines


def _details(finding: Finding, *, width: int = 100) -> list[str]:
    lines: list[str] = []
    lines.extend(_wrapped("Evidence", json.dumps(finding.evidence, sort_keys=True,
                                                   ensure_ascii=False), width=width))
    lines.extend(_wrapped("Flag path", finding.flag_path, width=width))
    if finding.preconditions:
        lines.append("  Preconditions:")
        for index, item in enumerate(finding.preconditions, 1):
            lines.extend(textwrap.wrap(
                f"{index}. {item}", width=width,
                initial_indent="    ", subsequent_indent="       ",
                break_long_words=False,
            ))
    if finding.playbook:
        lines.append("  Steps:")
        for index, step in enumerate(finding.playbook, 1):
            lines.extend(_wrapped(f"Step {index}", step, width=width))
    lines.extend(_wrapped("Solver", json.dumps(finding.solver, sort_keys=True,
                                                ensure_ascii=False), width=width))
    if finding.cyberchef is not None:
        lines.extend(_wrapped("CyberChef input", finding.cyberchef["input"], width=width))
        lines.extend(_wrapped("CyberChef recipe", json.dumps(
            finding.cyberchef["recipe"], separators=(",", ":"), ensure_ascii=False), width=width))
        lines.append("  CyberChef: use a trusted local/offline instance.")
    lines.extend(_wrapped("Patch", finding.patch, width=width))
    return lines


def render_findings(
    findings: Sequence[Finding],
    *,
    color: bool = False,
    verbose: bool = False,
    width: int = 100,
) -> str:
    if not findings:
        return paint("No cryptographic weaknesses found.", "good", color)
    width = max(68, min(width, 150))
    counts = Counter(f.severity for f in findings)
    count_parts = " | ".join(f"{counts[level]} {level.upper()}" for level in
                             ("critical", "high", "medium", "low") if counts[level])
    lines = [paint("CRYPTOSCAN  /  CRYPTO ANALYSIS", "title", color),
             paint("-" * min(width, 98), "muted", color),
             f"Findings: {len(findings)}  |  {count_parts}",
             ""]
    for index, finding in enumerate(findings, 1):
        severity = paint(finding.severity.upper(), finding.severity, color)
        heading = f"{index:02d}  [{severity}] {finding.rule}"
        lines.append(heading)
        lines.append("    " + finding.title)
        lines.extend(_summary(finding, width=width))
        if verbose:
            lines.extend(_details(finding, width=width))
        lines.append(paint("-" * min(width, 98), "muted", color))
        lines.append("")
    if not verbose:
        lines.append(paint("Tip: use --verbose for evidence, conditions, recovery steps, and patches.",
                           "muted", color))
    return "\n".join(lines).rstrip()
