import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import checker


def test_cmp():
    assert checker._cmp("1.2.3", "1.2.4") < 0
    assert checker._cmp("2.0.0", "1.9.9") > 0
    assert checker._cmp("1.0", "1.0.0") == 0


def test_version_matches():
    assert checker.version_matches("0.12.2", "<0.12.3")
    assert not checker.version_matches("0.12.3", "<0.12.3")
    assert checker.version_matches("1.0.0", "==1.0.0")
    assert checker.version_matches("2.0.0", ">=1.0.0")


def test_parse_requirements_pinned():
    deps = checker.parse_requirements("flask==0.12.2\nrequests>=2.0\n# comment\n")
    flask = next(d for d in deps if d.name == "flask")
    assert flask.pinned and flask.version == "0.12.2"
    req = next(d for d in deps if d.name == "requests")
    assert not req.pinned


def test_parse_requirements_skips_blank_and_flags():
    deps = checker.parse_requirements("\n-r other.txt\n--index-url x\nflask==1.0\n")
    assert {d.name for d in deps} == {"flask"}


def test_parse_package_json():
    pkg = json.dumps({
        "dependencies": {"lodash": "4.17.20", "axios": "^0.21.0"},
        "devDependencies": {"jest": "27.0.0"},
    })
    deps = checker.parse_package_json(pkg)
    names = {d.name for d in deps}
    assert {"lodash", "axios", "jest"} <= names
    lodash = next(d for d in deps if d.name == "lodash")
    assert lodash.pinned and lodash.version == "4.17.20"
    axios = next(d for d in deps if d.name == "axios")
    assert not axios.pinned


def test_parse_package_json_invalid():
    assert checker.parse_package_json("{not json") == []


def test_vulnerable_flask_detected():
    deps = checker.parse_requirements("flask==0.12.2\n")
    findings = checker.check_offline(deps)
    assert any(f.id == "CVE-2018-1000656" for f in findings)


def test_patched_flask_not_detected():
    deps = checker.parse_requirements("flask==1.0.0\n")
    assert checker.check_offline(deps) == []


def test_vulnerable_lodash_detected():
    deps = checker.parse_package_json(
        json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    findings = checker.check_offline(deps)
    assert any(f.id == "CVE-2021-23337" for f in findings)


def test_findings_sorted_by_severity():
    deps = checker.parse_requirements("django==2.0.0\njinja2==2.10.0\n")
    findings = checker.check_offline(deps)
    ranks = [checker.SEV_RANK[f.severity] for f in findings]
    assert ranks == sorted(ranks)


def test_unpinned_warnings():
    deps = checker.parse_requirements("requests>=2.0\nflask==1.0\n")
    warns = checker.unpinned_warnings(deps)
    assert any(w.package == "requests" for w in warns)
    assert not any(w.package == "flask" for w in warns)


def test_run_directory(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\n")
    result = checker.run(str(tmp_path))
    assert result["dependency_count"] == 1
    assert result["vulnerabilities"]


def test_cli_exit_code_vuln(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==0.12.2\n")
    assert checker.main([str(f)]) == 1


def test_cli_exit_code_clean(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==2.0.0\n")
    assert checker.main([str(f)]) == 0


def test_cli_no_manifest(tmp_path):
    assert checker.main([str(tmp_path)]) == 2


def test_cli_json(tmp_path, capsys):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==0.12.2\n")
    checker.main([str(f), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["vulnerabilities"]
