# deploy-preflight

**Check a live URL for the failures a deploy log never shows you — expired certificate, redirect loop, missing security header, HTML cached for a year, sitemap pointing at staging. Fails CI before a customer finds it.**

[![CI](https://github.com/aiplusplus360/deploy-preflight/actions/workflows/ci.yml/badge.svg)](https://github.com/aiplusplus360/deploy-preflight/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](pyproject.toml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```console
$ deploy-preflight https://www.python.org

preflight  https://www.python.org

  WARN  caching      no Cache-Control on HTML
  WARN  compression  uncompressed 53040B response
  WARN  headers      missing x-content-type-options
  WARN  headers      missing referrer-policy
  WARN  headers      no Content-Security-Policy
  WARN  sitemap      sitemap.xml returned 404
  PASS  headers      HSTS configured
              max-age=63072000; includeSubDomains; preload
  PASS  redirects    no redirects
  PASS  robots       robots.txt served
  PASS  status       200 in 583ms
  PASS  tls          certificate valid for 98 day(s)

5 passed, 6 warning(s), 0 failed
```

---

## Why this exists

A deploy pipeline answers *"did the process start?"*. It does not answer the questions that actually page someone at 2am:

- Is the certificate valid for more than the next 30 days?
- Does the redirect chain leave my origin, or land on staging?
- Is my HTML cached for a year, so this deploy serves stale markup?
- Did the sitemap ship with `localhost` in it?
- Is `robots.txt` blocking the whole site? (A `Disallow: /` pasted under the wrong user-agent does exactly that.)

All of these are visible in five seconds with `curl` — and therefore never checked, because nobody curls production on every deploy.

## Install

No dependencies. `urllib` and `ssl` only.

```bash
pip install git+https://github.com/aiplusplus360/deploy-preflight
```

Or run it straight from a checkout with no install:

```bash
python -m preflight.cli https://example.com
```

## Usage

```bash
deploy-preflight https://example.com
deploy-preflight https://example.com --json
deploy-preflight https://example.com --fail-on warn
deploy-preflight https://example.com --insecure   # check everything except trust
```

| Flag | Effect |
|---|---|
| `--json` | Machine-readable report, for dashboards and PR comments |
| `--fail-on fail\|warn\|never` | Severity that produces a non-zero exit (default `fail`) |
| `--timeout` | Per-request timeout in seconds |
| `--insecure` | Skip certificate *trust* verification (expiry is still measured) |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | nothing at or above the threshold |
| `1` | something at or above the threshold |
| `2` | invalid invocation (bad URL, unreachable in a way that prevented checks) |

## In CI

```yaml
- name: Preflight
  run: |
    pip install git+https://github.com/aiplusplus360/deploy-preflight
    deploy-preflight https://staging.example.com --fail-on warn
```

Run it against staging before promoting, and against production after. `--fail-on warn` once the headers are clean keeps them clean.

## What it checks

| Check | Fails when | Warns when |
|---|---|---|
| **tls** | cert expired, expiring within 7 days, TLS < 1.2, handshake fails | expiring within 30 days |
| **status** | 4xx or 5xx | — |
| **redirects** | redirect leaves the origin, HTTPS downgraded to HTTP | more than 3 hops |
| **headers** | HSTS without `max-age` | missing HSTS, `nosniff`, `referrer-policy`, `x-frame-options`, CSP; HSTS `max-age` under 6 months |
| **caching** | HTML cached over 24h (stale markup after a deploy) | no `Cache-Control` on HTML |
| **compression** | — | uncompressed response over 1KB |
| **robots** | `robots.txt` blocks the whole site | missing, 4xx, or sitemap not listed |
| **sitemap** | not a sitemap, contains `localhost`/`staging`/`dev` | missing, 4xx |

## Design notes

**Unreachable is a failure, not a skip.** A DNS failure returns `FAIL`, never `PASS`. A checker that reports healthy when it could not connect is worse than no checker.

**`--insecure` does not mean "trust this".** It skips *trust* verification but still measures expiry, and reports `WARN: trust was not verified`. Skipping a check must never look like passing it.

**`robots.txt` is parsed, not grepped.** Grouping is scoped by `User-agent`, and the longest matching path rule wins (RFC 9309). A `Disallow: /` under a specific crawler — which is exactly what python.org ships — is *not* a site-wide block. This was a false positive found by running the tool against real sites, and it is now a regression test.

**A missing CA bundle gets a hint, not a mystery.** In a slim container, `CERTIFICATE_VERIFY_FAILED` looks identical to an outage. The error says so and points at `certifi` or `--insecure`.

**No colour when piped.** Escape codes in a CI log are noise. The reporter checks `isatty`.

## Development

```bash
python -m unittest discover -s tests -v   # 38 tests
```

Tests are unit tests over hand-built response objects — where the rules live — plus one integration test against a real local `http.server`, so the fetch path and header normalization are exercised for real rather than mocked.

## License

[MIT](LICENSE)
