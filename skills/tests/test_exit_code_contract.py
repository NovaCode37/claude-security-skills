"""Cross-skill exit-code contract.

Every engine documents the same CI contract:

    0 = nothing reported, 1 = findings reported, 2 = usage/input error

These tests pin that contract for all eight engines at once so it cannot drift
per skill again (issue #46). Advisory noise is controlled by ``--min-severity``
(the filter sast-lite already shipped), never by a hidden severity gate on the
exit code: whatever the run *reports* is what the exit code reflects.

All fixtures are inert and local; nothing here touches the network.
"""

import json
import os
import sys
import time

import pytest

SKILLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _skill in ("secret-scanner", "sast-lite", "dockerfile-scan",
               "dependency-check", "http-sec-audit", "cors-auditor",
               "jwt-inspector", "prompt-injection-tester"):
    sys.path.insert(0, os.path.join(SKILLS_DIR, _skill))

import analyzer      # sast-lite
import attacker      # prompt-injection-tester
import audit         # http-sec-audit
import auditor       # cors-auditor
import checker       # dependency-check
import engine        # secret-scanner
import inspector     # jwt-inspector
import scanner       # dockerfile-scan


# --- inert fixtures ---------------------------------------------------------

# AWS's own published example key; not a live credential.
FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

SECURE_HEADER_BLOCK = (
    "HTTP/1.1 200 OK\n"
    "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n"
    "Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
    "X-Content-Type-Options: nosniff\n"
    "Referrer-Policy: strict-origin-when-cross-origin\n"
    "Permissions-Policy: camera=(), microphone=()\n"
)

# Identical, minus Permissions-Policy: exactly one LOW finding and nothing else.
LOW_ONLY_HEADER_BLOCK = SECURE_HEADER_BLOCK.replace(
    "Permissions-Policy: camera=(), microphone=()\n", "")


def _b64(obj):
    return inspector.b64url_encode(json.dumps(obj).encode())


def _clean_jwt():
    """An RS256 token with every hygiene claim present: nothing to report."""
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iss": "https://issuer.example", "aud": "api",
               "sub": "user-1", "iat": now - 60, "nbf": now - 60,
               "exp": now + 3600}
    return f"{_b64(header)}.{_b64(payload)}.{inspector.b64url_encode(b'sig')}"


def _low_only_jwt():
    """RS256 token missing only optional claims: LOW findings, no HIGH."""
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"sub": "user-1", "iat": now - 60, "exp": now + 3600}
    return f"{_b64(header)}.{_b64(payload)}.{inspector.b64url_encode(b'sig')}"


def _rc(module, argv):
    """Run an engine's main() and normalize argparse's SystemExit to an int."""
    try:
        return module.main(argv)
    except SystemExit as exc:
        return exc.code


def _cases(tmp_path):
    """Build (clean, findings, error) invocations for every skill.

    Each entry is (module, clean_argv, findings_argv, error_argv, count_json)
    where count_json maps parsed --json output to a number of reported findings.
    """
    clean_py = tmp_path / "clean.py"
    clean_py.write_text("x = 1\n")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "cfg.py").write_text(f"key = '{FAKE_AWS_KEY}'\n")
    clean_dir = tmp_path / "cleandir"
    clean_dir.mkdir()
    (clean_dir / "ok.py").write_text("x = 1\n")
    bad_py = tmp_path / "bad.py"
    bad_py.write_text("eval(x)\n")

    bad_docker = tmp_path / "Dockerfile"
    bad_docker.write_text("FROM ubuntu:latest\nRUN echo hi\n")
    good_docker = tmp_path / "clean.dockerfile"
    good_docker.write_text("FROM python:3.11-slim\nUSER app\n")

    pinned = tmp_path / "pinned"
    pinned.mkdir()
    (pinned / "requirements.txt").write_text("flask==2.0.0\n")
    unpinned = tmp_path / "unpinned"
    unpinned.mkdir()
    # No known CVE for these; the only thing to report is the loose pinning.
    (unpinned / "requirements.txt").write_text("httpx\nrich>=13.0\n")
    empty_dir = tmp_path / "nomanifest"
    empty_dir.mkdir()

    secure_headers = tmp_path / "secure.headers"
    secure_headers.write_text(SECURE_HEADER_BLOCK)
    low_headers = tmp_path / "low.headers"
    low_headers.write_text(LOW_ONLY_HEADER_BLOCK)
    cors_clean = tmp_path / "cors-clean.headers"
    cors_clean.write_text("Access-Control-Allow-Origin: https://app.example.com\n")
    cors_wildcard = tmp_path / "cors-wildcard.headers"
    cors_wildcard.write_text("Access-Control-Allow-Origin: *\n")
    missing = str(tmp_path / "does-not-exist")

    return {
        "secret-scanner": (
            engine, [str(clean_dir)], [str(secrets_dir)], [missing], len),
        "sast-lite": (
            analyzer, [str(clean_py)], [str(bad_py)], [missing], len),
        "dockerfile-scan": (
            scanner, [str(good_docker)], [str(bad_docker)], [missing], len),
        "dependency-check": (
            checker, [str(pinned)], [str(unpinned)], [str(empty_dir)],
            lambda d: len(d["vulnerabilities"]) + len(d["unpinned"])),
        "http-sec-audit": (
            audit,
            ["--headers-file", str(secure_headers)],
            ["--headers-file", str(low_headers)],
            ["--headers-file", missing], len),
        "cors-auditor": (
            auditor,
            ["--headers-file", str(cors_clean)],
            ["--headers-file", str(cors_wildcard)],
            ["--headers-file", missing], len),
        "jwt-inspector": (
            inspector, [_clean_jwt()], [_low_only_jwt()], ["garbage"],
            lambda d: len(d["issues"])),
        "prompt-injection-tester": (
            attacker, ["--demo", "--hardened"], ["--demo"],
            ["--category", "not-a-category"],
            lambda d: 1 if d["summary"]["vulnerable"] else 0),
    }


SKILL_IDS = [
    "secret-scanner", "sast-lite", "dockerfile-scan", "dependency-check",
    "http-sec-audit", "cors-auditor", "jwt-inspector",
    "prompt-injection-tester",
]


@pytest.mark.parametrize("skill", SKILL_IDS)
def test_clean_input_exits_zero(skill, tmp_path, capsys):
    module, clean_argv, _, _, _ = _cases(tmp_path)[skill]
    assert _rc(module, list(clean_argv)) == 0
    capsys.readouterr()


@pytest.mark.parametrize("skill", SKILL_IDS)
def test_reported_findings_exit_one(skill, tmp_path, capsys):
    module, _, findings_argv, _, _ = _cases(tmp_path)[skill]
    assert _rc(module, list(findings_argv)) == 1
    capsys.readouterr()


@pytest.mark.parametrize("skill", SKILL_IDS)
def test_usage_or_input_error_exits_two(skill, tmp_path, capsys):
    module, _, _, error_argv, _ = _cases(tmp_path)[skill]
    assert _rc(module, list(error_argv)) == 2
    capsys.readouterr()


@pytest.mark.parametrize("skill", SKILL_IDS)
def test_json_report_matches_exit_code(skill, tmp_path, capsys):
    """The JSON report and the exit code never disagree."""
    module, clean_argv, findings_argv, _, count_json = _cases(tmp_path)[skill]
    for argv, expected in ((clean_argv, 0), (findings_argv, 1)):
        rc = _rc(module, list(argv) + ["--json"])
        data = json.loads(capsys.readouterr().out)
        assert rc == expected
        assert (count_json(data) > 0) == (rc == 1)
