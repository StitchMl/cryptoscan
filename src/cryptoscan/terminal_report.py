"""Colorful, readable terminal reports without changing the JSON API.

Formatting is isolated from analysis and recovery. Width accounting uses
visible characters; ANSI escapes never influence wrapping or alignment.
"""
from __future__ import annotations

import json
import re
import textwrap
from collections import Counter
from collections.abc import Sequence

from .model import Finding

RESET = "\x1b[0m"
STYLES = {
    "critical": "\x1b[1;91m",  # bright red
    "high": "\x1b[1;31m",
    "medium": "\x1b[1;33m",
    "low": "\x1b[1;36m",
    "muted": "\x1b[90m",
    "title": "\x1b[1;96m",
    "good": "\x1b[1;32m",
    "label": "\x1b[1;37m",
    "warning": "\x1b[1;33m",
    "accent": "\x1b[96m",
    "value": "\x1b[97m",
}
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_VERIFIED = {"flag-recovered", "payload-ready"}


def paint(value: str, style: str, enabled: bool) -> str:
    sequence = STYLES.get(style, "")
    return sequence + value + RESET if enabled and sequence else value


def visible_width(value: str) -> int:
    return len(_ANSI.sub("", value))


def _wrap(
    label: str,
    value: object,
    width: int,
    color: bool,
    *,
    indent: int = 2,
    style: str = "value",
) -> list[str]:
    lead = " " * indent
    prefix = label + ": "
    usable = max(24, width - indent - len(prefix))
    segments = textwrap.wrap(
        str(value), width=usable, break_long_words=False,
        break_on_hyphens=False, replace_whitespace=True,
    ) or [""]
    lines = [lead + paint(label, "muted", color) + ": " +
             paint(segments[0], style, color)]
    lines.extend(" " * (indent + len(prefix)) + paint(segment, style, color)
                 for segment in segments[1:])
    return lines


def _kv_section(
    title: str, content: dict, width: int, color: bool,
    *,
    indent: int = 4,
) -> list[str]:
    lines = ["  " + paint(title, "accent", color)]
    for key, value in content.items():
        lines.extend(_wrap(str(key), json.dumps(value, ensure_ascii=False)
                           if isinstance(value, (list, dict)) else str(value),
                           width, color, indent=indent))
    return lines


def _summary(finding: Finding, width: int, color: bool) -> list[str]:
    status = finding.recovery_status
    return [
        *_wrap("Location", finding.location, width, color, style="accent"),
        *_wrap("Recovery", status, width, color,
               style="good" if status in _VERIFIED else "warning"),
        *_wrap("Attack", finding.attack, width, color),
        *_wrap("Flag path", finding.flag_path, width, color),
    ]


def _details(finding: Finding, width: int, color: bool) -> list[str]:
    lines: list[str] = []
    if finding.evidence:
        lines.extend(_kv_section("EVIDENCE", finding.evidence, width, color))
    if finding.preconditions:
        lines.append("  " + paint("PRECONDITIONS", "accent", color))
        for index, item in enumerate(finding.preconditions, 1):
            lines.extend(_wrap(f"{index:02d}", item, width, color, indent=4))
    if finding.playbook:
        lines.append("  " + paint("RECOVERY STEPS", "accent", color))
        for index, step in enumerate(finding.playbook, 1):
            lines.extend(_wrap(f"Step {index}", step, width, color, indent=4))
    if finding.solver:
        lines.extend(_kv_section("SOLVER", finding.solver, width, color))
    if finding.cyberchef is not None:
        lines.extend(_kv_section("CYBERCHEF", finding.cyberchef, width, color))
        lines.append("    " + paint("Use a trusted offline CyberChef instance.",
                                   "warning", color))
    lines.extend(_wrap("Patch", finding.patch, width, color))
    return lines


def render_findings(
    findings: Sequence[Finding],
    *,
    color: bool = False,
    verbose: bool = False,
    width: int = 100,
) -> str:
    """Render severity-grouped finding cards; --verbose expands technical detail."""
    if not findings:
        return paint("No cryptographic weaknesses found.", "good", color)
    width = max(68, min(width, 150))
    separator = "─" * (width - 2)
    counts = Counter(finding.severity for finding in findings)
    counts_text = "   ".join(
        paint(f"{counts[level]} {level.upper()}", level, color)
        for level in ("critical", "high", "medium", "low") if counts[level]
    )
    lines = [
        paint("CRYPTOSCAN", "title", color) + paint("  /  CRYPTO ANALYSIS", "muted", color),
        paint(separator, "muted", color),
        paint("FINDINGS", "label", color) + f"  {len(findings)}   |   " + counts_text,
        "",
    ]
    for index, finding in enumerate(findings, 1):
        severity = paint(finding.severity.upper(), finding.severity, color)
        lines.append(f"{index:02d}  [{severity}] " + paint(finding.rule, "label", color))
        for line in textwrap.wrap(finding.title, width=width - 4,
                                  break_long_words=False) or [""]:
            lines.append("    " + line)
        lines.extend(_summary(finding, width, color))
        if verbose:
            lines.append("")
            lines.extend(_details(finding, width, color))
        lines.append(paint(separator, "muted", color))
        lines.append("")
    if not verbose:
        lines.append(paint("Tip: use --verbose for evidence, conditions, recovery steps, and patches.",
                           "muted", color))
    # For compatibility with existing terminal tests, finish colored output
    # with the standard reset code; monochrome output has no escapes.
    answer = "\n".join(lines).rstrip()
    return answer + RESET if color else answer
