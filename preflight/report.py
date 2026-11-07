"""Output: a table for humans, JSON for machines.

Colour is applied only when stdout is a TTY, so piping into CI logs or a file
never produces escape sequences that make the report unreadable.
"""

from __future__ import annotations

import json
import sys
from typing import Sequence

from .checks import Finding, Severity

ICONS = {
    Severity.PASS: ("PASS", "\033[32m"),
    Severity.WARN: ("WARN", "\033[33m"),
    Severity.FAIL: ("FAIL", "\033[31m"),
    Severity.SKIP: ("SKIP", "\033[90m"),
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _use_colour(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def render_table(findings: Sequence[Finding], *, url: str = "", stream=None) -> str:
    stream = stream or sys.stdout
    colour = _use_colour(stream)
    lines = []

    if url:
        header = f"preflight  {url}"
        lines.append(f"{BOLD}{header}{RESET}" if colour else header)
        lines.append("")

    width = max((len(f.check) for f in findings), default=5)
    for finding in sorted(findings, key=lambda f: (-f.severity.rank, f.check)):
        label, tint = ICONS[finding.severity]
        badge = f"{tint}{label}{RESET}" if colour else label
        line = f"  {badge}  {finding.check:<{width}}  {finding.message}"
        lines.append(line)
        if finding.detail:
            detail = finding.detail.replace("\n", " ")
            if len(detail) > 120:
                detail = detail[:120] + "…"
            lines.append(f"              {detail}")

    counts = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
    lines.append("")
    summary = (
        f"{counts[Severity.PASS]} passed, "
        f"{counts[Severity.WARN]} warning(s), "
        f"{counts[Severity.FAIL]} failed"
    )
    if counts[Severity.SKIP]:
        summary += f", {counts[Severity.SKIP]} skipped"
    lines.append(summary)
    return "\n".join(lines)


def render_json(findings: Sequence[Finding], *, url: str = "") -> str:
    return json.dumps(
        {
            "url": url,
            "summary": {
                s.value: sum(1 for f in findings if f.severity == s) for s in Severity
            },
            "findings": [
                {
                    "check": f.check,
                    "severity": f.severity.value,
                    "message": f.message,
                    "detail": f.detail,
                }
                for f in findings
            ],
        },
        indent=2,
    )
