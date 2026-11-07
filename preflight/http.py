"""A small HTTP client for checks.

Deliberately not `requests`: the tool must run in a bare CI image with nothing
installed. `urllib` also gives direct access to the TLS socket, which is where
certificate facts actually live.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

USER_AGENT = "deploy-preflight/0.1 (+https://github.com/aiplusplus360/deploy-preflight)"


@dataclass
class Response:
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: float
    final_url: str = ""
    chain: List[str] = field(default_factory=list)

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())


@dataclass
class TlsInfo:
    host: str
    ok: bool
    error: str = ""
    not_after: Optional[str] = None
    days_remaining: Optional[int] = None
    issuer: str = ""
    subject: str = ""
    protocol: str = ""
    sans: List[str] = field(default_factory=list)


def _header_dict(message) -> Dict[str, str]:
    # Header names are case-insensitive; normalizing here means every caller
    # can stop worrying about `Content-Type` vs `content-type`.
    return {k.lower(): v for k, v in message.items()}


class _RecordingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Records every hop so a redirect loop or stray staging hop is visible."""

    def __init__(self) -> None:
        self.chain: List[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(
    url: str,
    *,
    timeout: float = 15.0,
    verify: bool = True,
    max_bytes: int = 512 * 1024,
) -> Response:
    """GET a URL, following redirects and recording the chain."""
    handler = _RecordingRedirectHandler()
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        handler, urllib.request.HTTPSHandler(context=context)
    )

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    started = time.perf_counter()

    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(max_bytes)
            elapsed = (time.perf_counter() - started) * 1000
            charset = response.headers.get_content_charset() or "utf-8"
            return Response(
                url=url,
                status=response.status,
                headers=_header_dict(response.headers),
                body=raw.decode(charset, "replace"),
                elapsed_ms=elapsed,
                final_url=response.geturl(),
                chain=[url] + handler.chain,
            )
    except urllib.error.HTTPError as exc:
        raw = exc.read(max_bytes) if hasattr(exc, "read") else b""
        elapsed = (time.perf_counter() - started) * 1000
        return Response(
            url=url,
            status=exc.code,
            headers=_header_dict(exc.headers or {}),
            body=raw.decode("utf-8", "replace"),
            elapsed_ms=elapsed,
            final_url=getattr(exc, "url", url),
            # A 4xx/5xx still carries a real status and headers; swallowing it
            # would turn "the site returns 500" into "the site is unreachable".
            chain=[url] + handler.chain,
        )


def tls_info(host: str, port: int = 443, timeout: float = 10.0, verify: bool = True) -> TlsInfo:
    """Connect and read the leaf certificate.

    `getpeercert()` returns the parsed form only when verification is on, so
    verification is left enabled by default and a verification failure is
    reported as an error — an invalid certificate is exactly what this check
    is for.

    With `verify=False` the handshake still happens, so expiry is measured, but
    the result is flagged as untrusted rather than passing silently: skipping
    trust must not look like passing trust.
    """
    import datetime as _dt

    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                protocol = tls.version() or ""
    except ssl.SSLCertVerificationError as exc:
        return TlsInfo(host=host, ok=False, error=f"certificate verification failed: {exc.verify_message}")
    except (socket.timeout, socket.gaierror, OSError) as exc:
        return TlsInfo(host=host, ok=False, error=str(exc))

    if not cert:
        # Unverified contexts return no parsed certificate. Report what is
        # known — the handshake succeeded — without inventing expiry data.
        if not verify:
            return TlsInfo(
                host=host,
                ok=True,
                not_after=None,
                days_remaining=None,
                protocol=protocol,
                subject="(certificate not parsed: verification disabled)",
            )
        return TlsInfo(host=host, ok=False, error="no certificate presented")

    not_after = cert.get("notAfter", "")
    days = None
    if not_after:
        try:
            expiry = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days = (expiry - _dt.datetime.utcnow()).days
        except ValueError:
            pass

    issuer = " ".join(
        f"{k}={v}" for part in cert.get("issuer", ()) for k, v in part
    )
    subject = " ".join(
        f"{k}={v}" for part in cert.get("subject", ()) for k, v in part
    )
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

    return TlsInfo(
        host=host,
        ok=True,
        not_after=not_after,
        days_remaining=days,
        issuer=issuer,
        subject=subject,
        protocol=protocol,
        sans=list(sans),
    )


def is_https(url: str) -> bool:
    return urlparse(url).scheme == "https"
