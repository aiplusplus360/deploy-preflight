"""Pre-deploy checks for an HTTP target.

The classes of failure this catches are the ones that are invisible in a deploy
log and obvious to a customer: an expired certificate, a redirect loop, a
missing security header, an HTML page cached for a year, a sitemap pointing at
staging.
"""

__version__ = "0.1.0"

from .checks import Finding, Severity, run_checks
from .report import render_json, render_table

__all__ = [
    "Finding",
    "Severity",
    "render_json",
    "render_table",
    "run_checks",
]
