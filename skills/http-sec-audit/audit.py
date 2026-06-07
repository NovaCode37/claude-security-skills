from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    id: str
    severity: str
    header: str
    message: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


def _lower_keys(headers: dict) -> dict:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def audit_headers(headers: dict, cookies: list[str] | None = None,
                  is_https: bool = True) -> list[Finding]:
    h = _lower_keys(headers)
    cookies = cookies or []
    findings: list[Finding] = []

    def miss(id_, sev, header, msg, rec):
        findings.append(Finding(id_, sev, header, msg, rec))

    if "content-security-policy" not in h:
        miss("csp-missing", "high", "Content-Security-Policy",
             "No Content-Security-Policy — primary defense against XSS is absent.",
             "Add a restrictive CSP, e.g. default-src 'self'.")
    else:
        csp = h["content-security-policy"]
        if "unsafe-inline" in csp:
            miss("csp-unsafe-inline", "medium", "Content-Security-Policy",
                 "CSP allows 'unsafe-inline', weakening XSS protection.",
                 "Remove 'unsafe-inline'; use nonces or hashes.")
        if "*" in csp.split():
            miss("csp-wildcard", "low", "Content-Security-Policy",
                 "CSP contains a wildcard source.",
                 "Restrict sources to explicit origins.")

    if is_https:
        if "strict-transport-security" not in h:
            miss("hsts-missing", "high", "Strict-Transport-Security",
                 "No HSTS — connections can be downgraded to HTTP.",
                 "Add Strict-Transport-Security: max-age=31536000; "
                 "includeSubDomains.")
        else:
            hsts = h["strict-transport-security"]
            maxage = _parse_max_age(hsts)
            if maxage is not None and maxage < 15552000:
                miss("hsts-short", "low", "Strict-Transport-Security",
                     f"HSTS max-age is short ({maxage}s).",
                     "Use max-age >= 31536000 (1 year).")

    if h.get("x-content-type-options", "").lower() != "nosniff":
        miss("xcto-missing", "medium", "X-Content-Type-Options",
             "Missing 'nosniff' — browser may MIME-sniff responses.",
             "Set X-Content-Type-Options: nosniff.")

    has_fa = ("content-security-policy" in h
              and "frame-ancestors" in h["content-security-policy"])
    if "x-frame-options" not in h and not has_fa:
        miss("xfo-missing", "medium", "X-Frame-Options",
             "No clickjacking protection (X-Frame-Options / frame-ancestors).",
             "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.")

    if "referrer-policy" not in h:
        miss("referrer-missing", "low", "Referrer-Policy",
             "No Referrer-Policy — full URLs may leak to other origins.",
             "Set Referrer-Policy: strict-origin-when-cross-origin.")

    if "permissions-policy" not in h and "feature-policy" not in h:
        miss("permissions-missing", "low", "Permissions-Policy",
             "No Permissions-Policy — powerful browser features unrestricted.",
             "Set a Permissions-Policy limiting camera, microphone, geolocation, etc.")

    for banner in ("server", "x-powered-by", "x-aspnet-version"):
        if banner in h and any(ch.isdigit() for ch in h[banner]):
            miss("info-disclosure", "low", banner.title(),
                 f"'{banner}: {h[banner]}' reveals software/version.",
                 "Remove or genericize version banners.")

    for raw in cookies:
        findings.extend(_audit_cookie(raw, is_https))

    findings.sort(key=lambda f: SEV_RANK.get(f.severity, 9))
    return findings


def _parse_max_age(hsts: str):
    for part in hsts.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None


def _audit_cookie(raw: str, is_https: bool) -> list[Finding]:
    name = raw.split("=", 1)[0].strip()
    low = raw.lower()
    out: list[Finding] = []
    if is_https and "secure" not in low:
        out.append(Finding("cookie-no-secure", "medium", "Set-Cookie",
                           f"Cookie '{name}' lacks the Secure flag.",
                           "Add Secure so the cookie is HTTPS-only."))
    if "httponly" not in low:
        out.append(Finding("cookie-no-httponly", "medium", "Set-Cookie",
                           f"Cookie '{name}' lacks HttpOnly — readable by JS.",
                           "Add HttpOnly to mitigate XSS cookie theft."))
    if "samesite" not in low:
        out.append(Finding("cookie-no-samesite", "low", "Set-Cookie",
                           f"Cookie '{name}' has no SameSite attribute.",
                           "Add SameSite=Lax or Strict to mitigate CSRF."))
    elif "samesite=none" in low and "secure" not in low:
        out.append(Finding("cookie-samesite-none-insecure", "medium",
                           "Set-Cookie",
                           f"Cookie '{name}' is SameSite=None without Secure.",
                           "SameSite=None requires the Secure flag."))
    return out


def fetch_headers(url: str, timeout: float = 10.0):
    import urllib.request
    import urllib.error

    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "http-sec-audit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = dict(resp.headers.items())
            cookies = resp.headers.get_all("Set-Cookie") or []
            final_url = resp.geturl()
    except urllib.error.HTTPError as exc:
        headers = dict(exc.headers.items()) if exc.headers else {}
        cookies = exc.headers.get_all("Set-Cookie") if exc.headers else []
        final_url = url
    return headers, list(cookies), final_url.startswith("https://")


def parse_raw_headers(text: str):
    headers: dict = {}
    cookies: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("HTTP/"):
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key, val = key.strip(), val.strip()
        if key.lower() == "set-cookie":
            cookies.append(val)
        else:
            headers[key] = val
    return headers, cookies


def render(findings: list[Finding], target: str) -> str:
    if not findings:
        return f"[http-sec-audit] {target}: no issues found. [OK]"
    out = [f"[http-sec-audit] {target}: {len(findings)} finding(s):\n"]
    for f in findings:
        out.append(f"  [{f.severity.upper():<8}] {f.id}  ({f.header})")
        out.append(f"             {f.message}")
        out.append(f"             fix: {f.recommendation}")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    out.append("\nSummary: " + ", ".join(
        f"{k}={counts[k]}" for k in sorted(counts, key=lambda s: SEV_RANK[s])))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="http-sec-audit",
        description="Audit HTTP security headers and cookie flags.")
    p.add_argument("url", nargs="?", help="URL to scan (https://...)")
    p.add_argument("--headers-file",
                   help="offline: file with a raw HTTP response header block")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args(argv)

    if args.headers_file:
        try:
            with open(args.headers_file, "r", encoding="utf-8", errors="ignore") as fh:
                headers, cookies = parse_raw_headers(fh.read())
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        target = args.headers_file
        is_https = True
    elif args.url:
        try:
            headers, cookies, is_https = fetch_headers(args.url)
        except Exception as exc:
            print(f"error: could not fetch {args.url}: {exc}", file=sys.stderr)
            return 2
        target = args.url
    else:
        p.error("provide a URL or --headers-file")
        return 2

    findings = audit_headers(headers, cookies, is_https=is_https)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print(render(findings, target))
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
