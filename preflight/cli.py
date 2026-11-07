"""Command line interface.

    0  nothing at or above the fail threshold
    1  something at or above the fail threshold
    2  the invocation was invalid

The threshold defaults to `fail`, so a warning does not break a pipeline that
has not yet fixed its headers, but `--fail-on warn` tightens it when it has.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence

from . import __version__
from .checks import Severity, worst
from .report import render_json, render_table
from .checks import run_checks

EXIT_OK = 0
EXIT_BELOW_THRESHOLD = 1
EXIT_INVALID = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deploy-preflight",
        description="Check a live URL for the failures a deploy log will not show you.",
    )
    parser.add_argument("url", help="URL to check, e.g. https://example.com")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--fail-on",
        choices=["fail", "warn", "never"],
        default="fail",
        help="severity that produces a non-zero exit (default: fail)",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip certificate verification (checks TLS but accepts bad certs)",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.url.startswith(("http://", "https://")):
        print("error: url must start with http:// or https://", file=sys.stderr)
        return EXIT_INVALID

    try:
        findings = run_checks(args.url, timeout=args.timeout, verify=not args.insecure)
    except Exception as exc:  # noqa: BLE001 - top-level guard
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID

    if args.json:
        print(render_json(findings, url=args.url))
    else:
        print(render_table(findings, url=args.url))

    if args.fail_on == "never":
        return EXIT_OK

    threshold = Severity.WARN if args.fail_on == "warn" else Severity.FAIL
    return EXIT_BELOW_THRESHOLD if worst(findings).rank >= threshold.rank else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
