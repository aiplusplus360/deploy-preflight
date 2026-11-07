"""The checks themselves.

Each check is a small pure function over a `Target` so it can be tested without
a network. Severity is deliberately three-valued: a check that has no opinion
is `SKIP`, not `PASS` — an unreachable host must never be reported as healthy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Sequence
from urllib.parse import urlparse

from .http import Response, TlsInfo, fetch, is_https, tls_info


class Severity(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"

    @property
    def rank(self) -> int:
        return {"pass": 0, "skip": 1, "warn": 2, "fail": 3}[self.value]


@dataclass
class Finding:
    check: str
    severity: Severity
    message: str
    detail: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.severity, str) and not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity)


@dataclass
class Target:
    """Everything a check is allowed to look at."""

    url: str
    response: Optional[Response] = None
    bare: Optional[Response] = None
    tls: Optional[TlsInfo] = None
    robots: Optional[Response] = None
    sitemap: Optional[Response] = None
    error: str = ""

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""


# --------------------------------------------------------------- individual --

HSTS_MIN_SECONDS = 15_777_600  # 6 months; below this HSTS is not preload-eligible


def check_tls(target: Target) -> List[Finding]:
    if not is_https(target.url):
        return [Finding("tls", Severity.FAIL, "target is not HTTPS")]
    if not target.tls:
        return [Finding("tls", Severity.SKIP, "no TLS handshake was attempted")]
    if not target.tls.ok:
        return [Finding("tls", Severity.FAIL, "TLS handshake failed", target.tls.error)]

    findings: List[Finding] = []
    days = target.tls.days_remaining
    if days is None:
        if target.tls.ok and "verification disabled" in (target.tls.subject or ""):
            findings.append(
                Finding(
                    "tls",
                    Severity.WARN,
                    "handshake succeeded but trust was not verified (--insecure)",
                )
            )
        else:
            findings.append(
                Finding("tls", Severity.WARN, "certificate expiry could not be parsed")
            )
    elif days < 0:
        findings.append(
            Finding("tls", Severity.FAIL, f"certificate expired {-days} day(s) ago")
        )
    elif days <= 7:
        findings.append(
            Finding("tls", Severity.FAIL, f"certificate expires in {days} day(s)")
        )
    elif days <= 30:
        findings.append(
            Finding("tls", Severity.WARN, f"certificate expires in {days} day(s)")
        )
    else:
        findings.append(
            Finding("tls", Severity.PASS, f"certificate valid for {days} day(s)")
        )

    if target.tls.protocol and target.tls.protocol not in {"TLSv1.2", "TLSv1.3"}:
        findings.append(
            Finding("tls", Severity.FAIL, f"obsolete protocol {target.tls.protocol}")
        )
    return findings


def check_status(target: Target) -> List[Finding]:
    if not target.response:
        return [Finding("status", Severity.FAIL, "no response", target.error)]
    status = target.response.status
    if status >= 500:
        return [Finding("status", Severity.FAIL, f"server error {status}")]
    if status >= 400:
        return [Finding("status", Severity.FAIL, f"client error {status}")]
    return [Finding("status", Severity.PASS, f"{status} in {target.response.elapsed_ms:.0f}ms")]


def check_redirects(target: Target) -> List[Finding]:
    if not target.response:
        return [Finding("redirects", Severity.SKIP, "no response")]

    chain = target.response.chain
    hops = len(chain) - 1
    findings: List[Finding] = []

    if hops == 0:
        findings.append(Finding("redirects", Severity.PASS, "no redirects"))
    elif hops > 3:
        findings.append(
            Finding("redirects", Severity.WARN, f"{hops} redirect hops", " -> ".join(chain))
        )
    else:
        findings.append(Finding("redirects", Severity.PASS, f"{hops} redirect hop(s)"))

    # A redirect that leaves the expected host is the classic way a deploy
    # silently sends users to staging or a bare-IP origin.
    origin = urlparse(target.url).netloc
    for hop in chain[1:]:
        hop_host = urlparse(hop).netloc
        if hop_host and hop_host != origin:
            findings.append(
                Finding(
                    "redirects",
                    Severity.FAIL,
                    f"redirect leaves the origin: {hop_host}",
                    hop,
                )
            )
            break

    if is_https(target.url) and chain:
        for hop in chain[1:]:
            if hop.startswith("http://"):
                findings.append(
                    Finding("redirects", Severity.FAIL, "HTTPS downgraded to HTTP", hop)
                )
                break
    return findings


SECURITY_HEADERS = {
    "strict-transport-security": ("hsts", Severity.WARN),
    "x-content-type-options": ("nosniff", Severity.WARN),
    "referrer-policy": ("referrer-policy", Severity.WARN),
    "x-frame-options": ("frame-options", Severity.WARN),
    "content-security-policy": ("csp", Severity.WARN),
}


def check_security_headers(target: Target) -> List[Finding]:
    if not target.response:
        return [Finding("headers", Severity.SKIP, "no response")]

    findings: List[Finding] = []
    for header, (label, severity) in SECURITY_HEADERS.items():
        value = target.response.header(header)
        if not value:
            if header == "content-security-policy":
                # Documented as optional: a wrong CSP breaks a page silently.
                findings.append(
                    Finding("headers", Severity.WARN, "no Content-Security-Policy")
                )
            else:
                findings.append(Finding("headers", severity, f"missing {header}"))
            continue

        if header == "strict-transport-security":
            match = re.search(r"max-age=(\d+)", value)
            if not match:
                findings.append(
                    Finding("headers", Severity.FAIL, "HSTS without max-age", value)
                )
            elif int(match.group(1)) < HSTS_MIN_SECONDS:
                findings.append(
                    Finding(
                        "headers",
                        Severity.WARN,
                        f"HSTS max-age below 6 months ({match.group(1)})",
                        value,
                    )
                )
            else:
                findings.append(Finding("headers", Severity.PASS, "HSTS configured", value))

    if not any(f.check == "headers" and "HSTS" in f.message for f in findings):
        findings.append(Finding("headers", Severity.SKIP, "HSTS not evaluated"))
    return findings


def check_caching(target: Target) -> List[Finding]:
    """HTML must not be cached long; hashed assets should be."""
    if not target.response:
        return [Finding("caching", Severity.SKIP, "no response")]

    content_type = (target.response.header("content-type") or "").lower()
    cache = (target.response.header("cache-control") or "").lower()

    if "text/html" not in content_type:
        return [Finding("caching", Severity.SKIP, "target is not HTML")]

    if not cache:
        return [Finding("caching", Severity.WARN, "no Cache-Control on HTML")]

    match = re.search(r"max-age=(\d+)", cache)
    if match and int(match.group(1)) > 86_400:
        return [
            Finding(
                "caching",
                Severity.FAIL,
                f"HTML cached for {match.group(1)}s — a deploy will serve stale markup",
                cache,
            )
        ]
    return [Finding("caching", Severity.PASS, "HTML revalidates", cache)]


def check_compression(target: Target) -> List[Finding]:
    if not target.response:
        return [Finding("compression", Severity.SKIP, "no response")]
    encoding = target.response.header("content-encoding")
    if encoding:
        return [Finding("compression", Severity.PASS, f"compressed ({encoding})")]
    length = target.response.header("content-length")
    size = int(length) if length and length.isdigit() else len(target.response.body.encode())
    if size > 1024:
        return [Finding("compression", Severity.WARN, f"uncompressed {size}B response")]
    return [Finding("compression", Severity.PASS, "small response, compression moot")]


ROBOTS_UA = "deploy-preflight"


def _parse_robots(body: str):
    """Parse robots.txt into ordered (agents, rules) groups.

    Grouping matters: `Disallow: /` under `User-agent: SomeCrawler` blocks that
    crawler only. Treating it as site-wide is a false positive, and a checker
    that cries wolf gets switched off.
    """
    groups = []
    agents: List[str] = []
    rules: List[tuple] = []
    expecting_agents = False

    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()

        if field in {"user-agent", "useragent"}:
            if not expecting_agents:
                # A user-agent line after rules starts a new group.
                if agents or rules:
                    groups.append((agents, rules))
                agents, rules = [], []
                expecting_agents = True
            agents.append(value.lower())
        elif field in {"allow", "disallow"}:
            expecting_agents = False
            # `Disallow:` with an empty value means "nothing blocked".
            if value:
                rules.append((field, value))

    if agents or rules:
        groups.append((agents, rules))
    return groups


def _select_rules(groups, user_agent: str):
    """Pick the group for this agent: longest matching token, else `*`."""
    ua = user_agent.lower()
    best_len = -1
    best = []
    for agents, rules in groups:
        for agent in agents:
            if agent == "*":
                if best_len < 0:
                    best_len, best = 0, rules
            elif agent and agent in ua and len(agent) > best_len:
                best_len, best = len(agent), rules
    return best


def _matches(path: str, pattern: str) -> bool:
    if pattern == "/":
        return True
    # Support the two wildcards RFC 9309 defines; otherwise prefix match.
    regex = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\$", "$")
    return re.match(regex, path) is not None


def _allowed(rules, path: str = "/") -> bool:
    """Longest matching rule wins; Allow wins ties (RFC 9309 §2.2.2)."""
    best_len = -1
    allowed = True
    for field, pattern in rules:
        if not _matches(path, pattern):
            continue
        length = len(pattern)
        if length > best_len or (length == best_len and field == "allow"):
            best_len = length
            allowed = field == "allow"
    return allowed


def check_robots(target: Target) -> List[Finding]:
    if not target.robots:
        return [Finding("robots", Severity.SKIP, "robots.txt not fetched")]
    if target.robots.status >= 400:
        return [Finding("robots", Severity.WARN, f"robots.txt returned {target.robots.status}")]

    body = target.robots.body
    groups = _parse_robots(body)
    findings = [Finding("robots", Severity.PASS, "robots.txt served")]

    if groups and not _allowed(_select_rules(groups, ROBOTS_UA), "/"):
        findings.append(
            Finding("robots", Severity.FAIL, "robots.txt blocks the whole site")
        )

    if target.sitemap and target.sitemap.status < 400 and "sitemap:" not in body.lower():
        findings.append(
            Finding("robots", Severity.WARN, "sitemap exists but robots.txt does not list it")
        )
    return findings


def check_sitemap(target: Target) -> List[Finding]:
    if not target.sitemap:
        return [Finding("sitemap", Severity.SKIP, "sitemap.xml not fetched")]
    if target.sitemap.status >= 400:
        return [Finding("sitemap", Severity.WARN, f"sitemap.xml returned {target.sitemap.status}")]

    body = target.sitemap.body
    if "<urlset" not in body and "<sitemapindex" not in body:
        return [Finding("sitemap", Severity.FAIL, "sitemap.xml is not a sitemap")]

    findings = [Finding("sitemap", Severity.PASS, f"{body.count('<url>')} URLs")]
    host = target.host
    if host:
        # A sitemap pointing at localhost or staging is a very common copy/paste
        # failure and it poisons search results instead of failing loudly.
        stale = [
            h
            for h in ("localhost", "127.0.0.1", "staging.", "dev.")
            if h in body and h not in host
        ]
        if stale:
            findings.append(
                Finding("sitemap", Severity.FAIL, f"sitemap contains {stale[0]} URLs")
            )
    return findings


CHECKS: Sequence[Callable[[Target], List[Finding]]] = (
    check_tls,
    check_status,
    check_redirects,
    check_security_headers,
    check_caching,
    check_compression,
    check_robots,
    check_sitemap,
)


def collect(url: str, *, timeout: float = 15.0, verify: bool = True) -> Target:
    """Fetch everything the checks need, once."""
    target = Target(url=url)
    try:
        target.response = fetch(url, timeout=timeout, verify=verify)
    except Exception as exc:  # noqa: BLE001 - reported as a failure, not raised
        target.error = str(exc)
        # A missing CA bundle looks like a site outage. It isn't, and the
        # difference matters when this runs inside a slim CI container.
        if "CERTIFICATE_VERIFY_FAILED" in target.error or "certificate verify failed" in target.error:
            target.error += (
                "\n  hint: the local trust store has no CA bundle. Install one "
                "(`pip install certifi`, or add ca-certificates to the image) or "
                "run with --insecure to check everything except trust."
            )
        return target

    if is_https(url):
        target.tls = tls_info(target.host, timeout=timeout, verify=verify)

    base = target.response.final_url or url
    base = base.rstrip("/")
    try:
        target.robots = fetch(f"{base}/robots.txt", timeout=timeout, verify=verify)
    except Exception:  # noqa: BLE001 - optional
        pass
    try:
        target.sitemap = fetch(f"{base}/sitemap.xml", timeout=timeout, verify=verify)
    except Exception:  # noqa: BLE001 - optional
        pass

    return target


def run_checks(
    url: str, *, timeout: float = 15.0, verify: bool = True
) -> List[Finding]:
    target = collect(url, timeout=timeout, verify=verify)
    findings: List[Finding] = []
    for check in CHECKS:
        findings.extend(check(target))
    return findings


def worst(findings: Sequence[Finding]) -> Severity:
    if not findings:
        return Severity.SKIP
    return max((f.severity for f in findings), key=lambda s: s.rank)
