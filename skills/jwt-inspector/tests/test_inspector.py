import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import inspector


def _b64(obj):
    return inspector.b64url_encode(json.dumps(obj).encode())


def test_b64url_roundtrip():
    data = b"hello world!?"
    assert inspector.b64url_decode(inspector.b64url_encode(data)) == data


def test_decode_valid():
    token = inspector.sign_hs256({"alg": "HS256", "typ": "JWT"},
                                 {"sub": "1", "exp": int(time.time()) + 60},
                                 "secret")
    jwt = inspector.decode(token)
    assert jwt.header["alg"] == "HS256"
    assert jwt.payload["sub"] == "1"


def test_decode_rejects_malformed():
    with pytest.raises(ValueError):
        inspector.decode("not.a.valid.jwt.token")
    with pytest.raises(ValueError):
        inspector.decode("only-one-part")


def test_alg_none_is_critical():
    token = f'{_b64({"alg": "none", "typ": "JWT"})}.{_b64({"sub": "1"})}.'
    jwt = inspector.decode(token)
    issues = inspector.audit(jwt)
    assert any(i.id == "alg-none" and i.severity == "critical" for i in issues)


def test_missing_exp_flagged():
    token = inspector.sign_hs256({"alg": "HS256"}, {"sub": "1"}, "x")
    issues = inspector.audit(inspector.decode(token))
    assert any(i.id == "exp-missing" for i in issues)


def test_expired_token_noted():
    token = inspector.sign_hs256({"alg": "HS256"},
                                 {"exp": int(time.time()) - 100}, "x")
    issues = inspector.audit(inspector.decode(token))
    assert any(i.id == "exp-past" for i in issues)


def test_excessive_lifetime_flagged():
    token = inspector.sign_hs256(
        {"alg": "HS256"}, {"exp": int(time.time()) + 60 * 60 * 24 * 800}, "x")
    issues = inspector.audit(inspector.decode(token))
    assert any(i.id == "exp-far" for i in issues)


def test_symmetric_alg_flagged():
    token = inspector.sign_hs256({"alg": "HS256"},
                                 {"exp": int(time.time()) + 60}, "x")
    issues = inspector.audit(inspector.decode(token))
    assert any(i.id == "alg-symmetric" for i in issues)


def test_crack_weak_secret():
    token = inspector.sign_hs256({"alg": "HS256"},
                                 {"sub": "1", "exp": int(time.time()) + 60},
                                 "secret")
    result = inspector.inspect(token)
    assert result["cracked_secret"] == "secret"
    assert any(i["id"] == "weak-secret" for i in result["issues"])


@pytest.mark.parametrize("secret", ["password123", "P@ssw0rd", "welcome"])
def test_crack_extended_weak_secret_candidates(secret):
    token = inspector.sign_hs256({"alg": "HS256"},
                                 {"sub": "1", "exp": int(time.time()) + 60},
                                 secret)
    result = inspector.inspect(token)
    assert result["cracked_secret"] == secret
    assert any(issue["id"] == "weak-secret" for issue in result["issues"])


def test_strong_secret_not_cracked():
    token = inspector.sign_hs256(
        {"alg": "HS256"}, {"sub": "1", "exp": int(time.time()) + 60},
        "f3Kd9Lm2Qx8Zp1Rt7Vw4Bn6Cs0Hj5-not-in-wordlist")
    result = inspector.inspect(token)
    assert result["cracked_secret"] is None


def test_inspect_returns_decoded():
    token = inspector.sign_hs256({"alg": "HS256"},
                                 {"sub": "abc", "exp": int(time.time()) + 60},
                                 "secret")
    result = inspector.inspect(token)
    assert result["payload"]["sub"] == "abc"


def test_cli_exit_code_high_issue(capsys):
    token = f'{_b64({"alg": "none"})}.{_b64({"sub": "1"})}.'
    assert inspector.main([token]) == 1


def test_cli_bad_input():
    assert inspector.main(["garbage"]) == 2


def test_cli_json(capsys):
    token = inspector.sign_hs256({"alg": "HS256"},
                                 {"sub": "1", "exp": int(time.time()) + 60},
                                 "secret")
    inspector.main([token, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "header" in data and "issues" in data


def _low_only_token():
    """RS256 token whose only findings are LOW claim-hygiene issues."""
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"sub": "user-1", "iat": now - 60, "exp": now + 3600}
    return "{}.{}.{}".format(_b64(header), _b64(payload),
                            inspector.b64url_encode(b"sig"))


def test_cli_low_only_issues_exit_one(capsys):
    """Reported LOW issues fail the build too (issue #46)."""
    rc = inspector.main([_low_only_token(), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["issues"] and all(i["severity"] == "low" for i in data["issues"])
    assert rc == 1


def test_cli_min_severity_filters_report_and_exit(capsys):
    rc = inspector.main([_low_only_token(), "--min-severity", "medium",
                         "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["issues"] == []
    assert rc == 0


def test_inspect_min_severity():
    token = f'{_b64({"alg": "none"})}.{_b64({"sub": "1"})}.'
    all_issues = inspector.inspect(token, min_severity="info")
    high_only = inspector.inspect(token, min_severity="high")
    assert len(high_only["issues"]) < len(all_issues["issues"])
    assert all(i["severity"] in ("critical", "high")
               for i in high_only["issues"])


def _info_only_token():
    """RS256 token with every claim present but expired: one INFO issue."""
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iss": "https://issuer.example", "aud": "api", "sub": "user-1",
               "iat": now - 7200, "nbf": now - 7200, "exp": now - 3600}
    return "{}.{}.{}".format(_b64(header), _b64(payload),
                            inspector.b64url_encode(b"sig"))


def test_cli_info_issue_reported_by_default(capsys):
    """INFO issues stay in the default report and still fail the build."""
    rc = inspector.main([_info_only_token(), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert [i["id"] for i in data["issues"]] == ["exp-past"]
    assert [i["severity"] for i in data["issues"]] == ["info"]
    assert rc == 1


def test_cli_min_severity_low_hides_info(capsys):
    rc = inspector.main([_info_only_token(), "--min-severity", "low", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["issues"] == []
    assert rc == 0


def test_inspect_reports_info_by_default():
    ids = {i["id"] for i in inspector.inspect(_info_only_token())["issues"]}
    assert "exp-past" in ids
