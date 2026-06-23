import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import auditor


def _ids(headers, sent_origin=None):
    return {f.id for f in auditor.audit_cors(headers, sent_origin)}


def test_no_cors_headers_clean():
    assert auditor.audit_cors({"Content-Type": "text/html"}) == []


def test_wildcard_with_credentials_critical():
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    findings = auditor.audit_cors(headers)
    assert any(f.id == "cors-wildcard-credentials"
               and f.severity == "critical" for f in findings)


def test_wildcard_without_credentials_medium():
    findings = auditor.audit_cors({"Access-Control-Allow-Origin": "*"})
    assert any(f.id == "cors-wildcard" and f.severity == "medium"
               for f in findings)


def test_null_origin_flagged():
    assert "cors-null-origin" in _ids({"Access-Control-Allow-Origin": "null"})


def test_null_origin_with_credentials_critical():
    headers = {
        "Access-Control-Allow-Origin": "null",
        "Access-Control-Allow-Credentials": "true",
    }
    findings = auditor.audit_cors(headers)
    assert any(f.id == "cors-null-origin" and f.severity == "critical"
               for f in findings)


def test_reflected_origin_detected():
    origin = "https://evil.example"
    headers = {"Access-Control-Allow-Origin": origin}
    assert "cors-reflected-origin" in _ids(headers, sent_origin=origin)


def test_reflected_origin_with_credentials_critical():
    origin = "https://evil.example"
    headers = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
    }
    findings = auditor.audit_cors(headers, sent_origin=origin)
    assert any(f.id == "cors-reflected-origin" and f.severity == "critical"
               for f in findings)


def test_fixed_origin_no_reflection():
    headers = {"Access-Control-Allow-Origin": "https://app.example.com"}
    assert "cors-reflected-origin" not in _ids(
        headers, sent_origin="https://evil.example")


def test_credentialed_fixed_origin_info():
    headers = {
        "Access-Control-Allow-Origin": "https://app.example.com",
        "Access-Control-Allow-Credentials": "true",
    }
    assert "cors-credentials-enabled" in _ids(headers)


def test_methods_wildcard_flagged():
    headers = {
        "Access-Control-Allow-Origin": "https://app.example.com",
        "Access-Control-Allow-Methods": "*",
    }
    assert "cors-methods-wildcard" in _ids(headers)


def test_parse_raw_headers():
    text = (
        "HTTP/1.1 200 OK\n"
        "Access-Control-Allow-Origin: *\n"
        "Content-Type: application/json\n"
    )
    headers = auditor.parse_raw_headers(text)
    assert headers["Access-Control-Allow-Origin"] == "*"


def test_cli_exit_code_high(tmp_path):
    f = tmp_path / "resp.txt"
    f.write_text("Access-Control-Allow-Origin: *\n"
                 "Access-Control-Allow-Credentials: true\n")
    assert auditor.main(["--headers-file", str(f)]) == 1


def test_cli_exit_code_clean(tmp_path):
    f = tmp_path / "resp.txt"
    f.write_text("Access-Control-Allow-Origin: https://app.example.com\n")
    assert auditor.main(["--headers-file", str(f)]) == 0


def test_cli_json(tmp_path, capsys):
    import json
    f = tmp_path / "resp.txt"
    f.write_text("Access-Control-Allow-Origin: null\n")
    auditor.main(["--headers-file", str(f), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list) and data[0]["id"] == "cors-null-origin"
