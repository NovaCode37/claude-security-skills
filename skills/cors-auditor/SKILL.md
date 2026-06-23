---
name: cors-auditor
description: >-
  Audit a site's Cross-Origin Resource Sharing (CORS) configuration for
  misconfigurations — wildcard origin with credentials, reflected arbitrary
  Origin, the 'null' origin, overly broad allowed methods, and risky
  credentialed CORS. Use when the user asks to "check my CORS config", "is my
  API's CORS safe", "test for CORS misconfiguration", or "why can any site call
  my API".
license: MIT
---

# CORS Misconfiguration Auditor

Inspects CORS response headers and reports exploitable misconfigurations with
fixes. The analysis core is pure and offline-testable; live probing uses only
stdlib `urllib` and sends a throwaway `Origin` header to detect origin
reflection.

## When to use this skill

- "Audit the CORS configuration of https://api.example.com."
- "Is it safe that my API returns Access-Control-Allow-Origin: *?"
- "Does my server reflect any Origin back?"

## What it checks

- **Wildcard + credentials** — `Allow-Origin: *` with
  `Allow-Credentials: true` (`cors-wildcard-credentials`).
- **Reflected origin** — server echoes the request Origin back
  (`cors-reflected-origin`); critical when combined with credentials.
- **Null origin** — `Allow-Origin: null` (`cors-null-origin`).
- **Wildcard origin** — `Allow-Origin: *` without credentials (`cors-wildcard`).
- **Credentialed CORS** — informational note when credentials are enabled
  (`cors-credentials-enabled`).
- **Wildcard methods** — `Allow-Methods: *` (`cors-methods-wildcard`).

## How to run it

```bash
# Live probe (sends a throwaway Origin to test reflection)
python skills/cors-auditor/auditor.py https://api.example.com

# Probe with a specific origin
python skills/cors-auditor/auditor.py https://api.example.com --origin https://evil.example

# Offline: audit a captured header block; pass --origin to test reflection
python skills/cors-auditor/auditor.py --headers-file resp.txt --origin https://evil.example
```

**Exit codes:** `0` no high issues · `1` critical/high findings · `2` fetch/usage
error.

## Recommended workflow for Claude

1. Probe the endpoint (live) or audit captured headers (offline).
2. Explain each finding and why it is exploitable (e.g. reflected origin +
   credentials = cross-origin data theft).
3. Recommend an explicit origin allowlist and dropping credentials where not
   needed.
4. Only test APIs the user owns or is authorized to test.
