"""Tests for the checks.

Most are unit tests over a hand-built `Target`, because that is where the rules
live and it keeps them fast. There is also one real integration test against a
local HTTP server, so the fetch path and header normalization are exercised for
real rather than mocked.
"""

import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from preflight.checks import (
    Severity,
    Target,
    check_caching,
    check_compression,
    check_redirects,
    check_robots,
    check_security_headers,
    check_sitemap,
    check_status,
    check_tls,
    run_checks,
    worst,
)
from preflight.http import Response, TlsInfo


def response(status=200, headers=None, body="", chain=None):
    return Response(
        url="https://example.com/",
        status=status,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        body=body,
        elapsed_ms=12.0,
        final_url="https://example.com/",
        chain=chain or ["https://example.com/"],
    )


def target(**kwargs):
    return Target(url="https://example.com/", **kwargs)


def severities(findings):
    return [f.severity for f in findings]


class TestTls(unittest.TestCase):
    def test_non_https_fails(self):
        found = check_tls(Target(url="http://example.com/"))
        self.assertEqual(found[0].severity, Severity.FAIL)

    def test_expired_cert_fails(self):
        found = check_tls(target(tls=TlsInfo("example.com", True, days_remaining=-3)))
        self.assertEqual(found[0].severity, Severity.FAIL)

    def test_expiring_soon_fails(self):
        found = check_tls(target(tls=TlsInfo("example.com", True, days_remaining=5)))
        self.assertEqual(found[0].severity, Severity.FAIL)

    def test_expiring_within_month_warns(self):
        found = check_tls(target(tls=TlsInfo("example.com", True, days_remaining=20)))
        self.assertEqual(found[0].severity, Severity.WARN)

    def test_healthy_cert_passes(self):
        found = check_tls(target(tls=TlsInfo("example.com", True, days_remaining=90)))
        self.assertEqual(found[0].severity, Severity.PASS)

    def test_handshake_failure_fails(self):
        found = check_tls(target(tls=TlsInfo("example.com", False, error="boom")))
        self.assertEqual(found[0].severity, Severity.FAIL)

    def test_obsolete_protocol_fails(self):
        found = check_tls(
            target(tls=TlsInfo("example.com", True, days_remaining=90, protocol="TLSv1"))
        )
        self.assertIn(Severity.FAIL, severities(found))


class TestStatus(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(check_status(target(response=response(200)))[0].severity, Severity.PASS)

    def test_server_error(self):
        self.assertEqual(check_status(target(response=response(503)))[0].severity, Severity.FAIL)

    def test_client_error(self):
        self.assertEqual(check_status(target(response=response(404)))[0].severity, Severity.FAIL)

    def test_no_response_fails_not_skips(self):
        # An unreachable host must never be reported as anything but a failure.
        self.assertEqual(check_status(target())[0].severity, Severity.FAIL)


class TestRedirects(unittest.TestCase):
    def test_no_redirects(self):
        found = check_redirects(target(response=response()))
        self.assertEqual(found[0].severity, Severity.PASS)

    def test_many_hops_warns(self):
        chain = ["https://example.com/"] + [f"https://example.com/{i}" for i in range(4)]
        found = check_redirects(target(response=response(chain=chain)))
        self.assertIn(Severity.WARN, severities(found))

    def test_offsite_redirect_fails(self):
        chain = ["https://example.com/", "https://staging.example.com/"]
        found = check_redirects(target(response=response(chain=chain)))
        self.assertIn(Severity.FAIL, severities(found))
        self.assertTrue(any("leaves the origin" in f.message for f in found))

    def test_https_downgrade_fails(self):
        chain = ["https://example.com/", "http://example.com/"]
        found = check_redirects(target(response=response(chain=chain)))
        self.assertTrue(any("downgraded" in f.message for f in found))


class TestSecurityHeaders(unittest.TestCase):
    def test_missing_headers_warn(self):
        found = check_security_headers(target(response=response()))
        self.assertTrue(all(f.severity in (Severity.WARN, Severity.SKIP) for f in found))

    def test_good_hsts_passes(self):
        found = check_security_headers(
            target(
                response=response(
                    headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
                )
            )
        )
        self.assertTrue(any(f.severity == Severity.PASS and "HSTS" in f.message for f in found))

    def test_short_hsts_warns(self):
        found = check_security_headers(
            target(response=response(headers={"Strict-Transport-Security": "max-age=300"}))
        )
        self.assertTrue(any("below 6 months" in f.message for f in found))

    def test_hsts_without_max_age_fails(self):
        found = check_security_headers(
            target(response=response(headers={"Strict-Transport-Security": "includeSubDomains"}))
        )
        self.assertIn(Severity.FAIL, severities(found))


class TestCaching(unittest.TestCase):
    def test_long_cached_html_fails(self):
        found = check_caching(
            target(response=response(headers={"content-type": "text/html", "cache-control": "public, max-age=604800"}))
        )
        self.assertEqual(found[0].severity, Severity.FAIL)

    def test_short_cached_html_passes(self):
        found = check_caching(
            target(response=response(headers={"content-type": "text/html", "cache-control": "no-cache"}))
        )
        self.assertEqual(found[0].severity, Severity.PASS)

    def test_missing_cache_control_warns(self):
        found = check_caching(target(response=response(headers={"content-type": "text/html"})))
        self.assertEqual(found[0].severity, Severity.WARN)

    def test_non_html_is_skipped(self):
        found = check_caching(
            target(response=response(headers={"content-type": "application/json"}))
        )
        self.assertEqual(found[0].severity, Severity.SKIP)


class TestCompression(unittest.TestCase):
    def test_compressed_passes(self):
        found = check_compression(target(response=response(headers={"content-encoding": "gzip"})))
        self.assertEqual(found[0].severity, Severity.PASS)

    def test_large_uncompressed_warns(self):
        found = check_compression(target(response=response(body="x" * 5000)))
        self.assertEqual(found[0].severity, Severity.WARN)

    def test_small_uncompressed_passes(self):
        found = check_compression(target(response=response(body="x" * 10)))
        self.assertEqual(found[0].severity, Severity.PASS)


class TestRobotsAndSitemap(unittest.TestCase):
    def test_robots_disallowing_all_fails(self):
        found = check_robots(
            target(robots=response(200, body="User-agent: *\nDisallow: /\n"))
        )
        self.assertIn(Severity.FAIL, severities(found))

    def test_scoped_disallow_is_not_site_wide(self):
        # python.org does exactly this: blocks one crawler, not everyone.
        # Treating it as site-wide is a false positive.
        found = check_robots(
            target(
                robots=response(
                    200,
                    body=(
                        "User-agent: *\nAllow: /\n\n"
                        "User-agent: SomeBadBot\nDisallow: /\n"
                    ),
                )
            )
        )
        self.assertNotIn(Severity.FAIL, severities(found))

    def test_path_prefix_is_not_site_wide(self):
        found = check_robots(
            target(robots=response(200, body="User-agent: *\nDisallow: /private\n"))
        )
        self.assertNotIn(Severity.FAIL, severities(found))

    def test_longest_match_allow_wins(self):
        # `/public` is longer than `/`, so the narrower Allow wins.
        found = check_robots(
            target(
                robots=response(
                    200, body="User-agent: *\nDisallow: /\nAllow: /public\n"
                )
            )
        )
        # "/" is still disallowed for a request to "/", so this must fail.
        self.assertIn(Severity.FAIL, severities(found))

    def test_missing_sitemap_reference_warns_only_when_sitemap_exists(self):
        found = check_robots(
            target(
                robots=response(200, body="User-agent: *\nAllow: /\n"),
                sitemap=response(200, body="<urlset/>"),
            )
        )
        self.assertTrue(any("does not list it" in f.message for f in found))

    def test_sitemap_with_localhost_fails(self):
        found = check_sitemap(
            target(
                sitemap=response(
                    200, body="<urlset><url><loc>http://localhost/a</loc></url></urlset>"
                )
            )
        )
        self.assertIn(Severity.FAIL, severities(found))

    def test_valid_sitemap_passes(self):
        found = check_sitemap(
            target(
                sitemap=response(
                    200,
                    body="<urlset><url><loc>https://example.com/a</loc></url></urlset>",
                )
            )
        )
        self.assertEqual(found[0].severity, Severity.PASS)

    def test_non_sitemap_body_fails(self):
        found = check_sitemap(target(sitemap=response(200, body="<html>nope</html>")))
        self.assertEqual(found[0].severity, Severity.FAIL)


class TestWorst(unittest.TestCase):
    def test_empty_is_skip(self):
        self.assertEqual(worst([]), Severity.SKIP)

    def test_fail_dominates(self):
        from preflight.checks import Finding

        self.assertEqual(
            worst([Finding("a", Severity.PASS, ""), Finding("b", Severity.FAIL, "")]),
            Severity.FAIL,
        )


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib API
        if self.path == "/robots.txt":
            body = b"User-agent: *\nAllow: /\nSitemap: http://127.0.0.1/sitemap.xml\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        elif self.path == "/sitemap.xml":
            body = b"<urlset><url><loc>http://127.0.0.1/</loc></url></urlset>"
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
        else:
            body = b"<html><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Encoding", "identity")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence the test output
        pass


class TestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_runs_end_to_end_against_a_real_server(self):
        url = f"http://127.0.0.1:{self.port}/"
        findings = run_checks(url, timeout=5.0)
        self.assertTrue(findings)
        # Plain HTTP against a local server: honest failures, no crash.
        self.assertIn(Severity.FAIL, severities(findings))
        # The sitemap and robots checks really did fetch and parse.
        self.assertTrue(any(f.check == "sitemap" and f.severity == Severity.PASS for f in findings))

    def test_unreachable_host_reports_failures_not_exceptions(self):
        findings = run_checks("http://127.0.0.1:1/", timeout=1.0)
        self.assertEqual(worst(findings), Severity.FAIL)


if __name__ == "__main__":
    unittest.main()
