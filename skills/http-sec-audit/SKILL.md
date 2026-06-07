---
name: http-sec-audit
description: >-
  Audit a website's HTTP security headers and cookie flags — CSP, HSTS,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
  COOP/COEP, version-leaking banners, and Secure/HttpOnly/SameSite cookies. Use
  when the user asks to "check my site's security headers", "audit HTTP headers",
  "is my CSP/HSTS configured right", or "scan a URL for header misconfigs".
license: MIT
---

# HTTP Security Header Audit

Checks a site's response headers against modern web-security best practices and
returns prioritized findings with concrete fixes. The analysis core is pure and
offline-testable; live scanning uses only Python's stdlib `urllib`.

## When to use this skill

- "Audit the security headers on https://example.com."
- "Is my CSP / HSTS / cookie config correct?"
- "Why is this site flagged for missing headers?"

## What it checks

- **Content-Security-Policy** — presence, `unsafe-inline`, wildcards.
- **Strict-Transport-Security** — presence and `max-age` length.
- **X-Content-Type-Options: nosniff**, **X-Frame-Options** / `frame-ancestors`.
- **Referrer-Policy**, **Permissions-Policy**.
- **Information disclosure** — `Server` / `X-Powered-By` version banners.
- **Cookies** — `Secure`, `HttpOnly`, `SameSite` (incl. `SameSite=None`
  without `Secure`).

## How to run it

```bash
# Live scan
python skills/http-sec-audit/audit.py https://example.com

# JSON output
python skills/http-sec-audit/audit.py https://example.com --json

# Offline: audit a saved raw header block (no network)
python skills/http-sec-audit/audit.py --headers-file response_headers.txt
```

**Exit codes:** `0` no high issues · `1` findings present · `2` fetch/usage error.

## Recommended workflow for Claude

1. Run the audit (live, or offline against captured headers).
2. Group findings by severity and present each with its one-line fix.
3. Offer ready-to-paste header snippets for the user's stack (nginx, Apache,
   Express, etc.) for the missing headers.
4. Only scan sites the user owns or is authorized to test.
