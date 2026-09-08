import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit


SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
    "Server": "nginx",
}
SECURE_COOKIE = ["session=abc; Secure; HttpOnly; SameSite=Lax"]


def ids(headers, cookies=None, is_https=True):
    return {f.id for f in audit.audit_headers(headers, cookies, is_https)}


def test_secure_site_is_clean():
    found = audit.audit_headers(SECURE_HEADERS, SECURE_COOKIE)
    assert found == [], [f.to_dict() for f in found]


def test_missing_csp_flagged():
    assert "csp-missing" in ids({})


def test_missing_hsts_flagged_on_https():
    assert "hsts-missing" in ids({}, is_https=True)


def test_hsts_not_required_on_http():
    assert "hsts-missing" not in ids({}, is_https=False)


def test_csp_unsafe_inline_flagged():
    h = dict(SECURE_HEADERS)
    h["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'"
    assert "csp-unsafe-inline" in ids(h, SECURE_COOKIE)


def test_short_hsts_flagged():
    h = dict(SECURE_HEADERS)
    h["Strict-Transport-Security"] = "max-age=3600"
    assert "hsts-short" in ids(h, SECURE_COOKIE)


def test_nosniff_missing_flagged():
    h = dict(SECURE_HEADERS)
    del h["X-Content-Type-Options"]
    assert "xcto-missing" in ids(h, SECURE_COOKIE)


def test_frame_ancestors_satisfies_clickjacking():
    h = dict(SECURE_HEADERS)
    del h["X-Frame-Options"]
    assert "xfo-missing" not in ids(h, SECURE_COOKIE)


def test_version_banner_flagged():
    h = dict(SECURE_HEADERS)
    h["Server"] = "nginx/1.18.0"
    assert "info-disclosure" in ids(h, SECURE_COOKIE)


def test_cookie_missing_flags():
    found = ids(SECURE_HEADERS, ["session=abc"])
    assert "cookie-no-secure" in found
    assert "cookie-no-httponly" in found
    assert "cookie-no-samesite" in found


def test_samesite_none_without_secure():
    found = ids(SECURE_HEADERS, ["s=1; HttpOnly; SameSite=None"])
    assert "cookie-samesite-none-insecure" in found


def test_case_insensitive_headers():
    h = {k.lower(): v for k, v in SECURE_HEADERS.items()}
    assert audit.audit_headers(h, SECURE_COOKIE) == []


def test_parse_raw_headers():
    raw = ("HTTP/1.1 200 OK\r\n"
           "Content-Type: text/html\r\n"
           "Set-Cookie: a=1; HttpOnly\r\n"
           "Set-Cookie: b=2\r\n")
    headers, cookies = audit.parse_raw_headers(raw)
    assert headers["Content-Type"] == "text/html"
    assert len(cookies) == 2


def test_findings_sorted_by_severity():
    found = audit.audit_headers({}, ["s=1"])
    ranks = [audit.SEV_RANK[f.severity] for f in found]
    assert ranks == sorted(ranks)


def test_cli_headers_file(tmp_path, capsys):
    f = tmp_path / "h.txt"
    f.write_text("HTTP/1.1 200 OK\nContent-Type: text/html\n")
    rc = audit.main(["--headers-file", str(f), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert any(d["id"] == "csp-missing" for d in data)
    assert rc == 1


LOW_ONLY_HEADERS = (
    "HTTP/1.1 200 OK\n"
    "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n"
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
    "X-Content-Type-Options: nosniff\n"
    "Referrer-Policy: strict-origin-when-cross-origin\n"
)


def test_cli_low_only_findings_exit_one(tmp_path, capsys):
    """LOW findings are still findings, so the build fails (issue #46)."""
    f = tmp_path / "h.txt"
    f.write_text(LOW_ONLY_HEADERS)
    rc = audit.main(["--headers-file", str(f), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert [d["severity"] for d in data] == ["low"]
    assert rc == 1


def test_cli_min_severity_filters_report_and_exit(tmp_path, capsys):
    f = tmp_path / "h.txt"
    f.write_text(LOW_ONLY_HEADERS)
    rc = audit.main(["--headers-file", str(f), "--min-severity", "medium",
                     "--json"])
    assert json.loads(capsys.readouterr().out) == []
    assert rc == 0


def test_filter_by_severity():
    findings = audit.audit_headers({}, [])
    assert audit.filter_by_severity(findings, "info") == findings
    assert all(f.severity in ("critical", "high")
               for f in audit.filter_by_severity(findings, "high"))
