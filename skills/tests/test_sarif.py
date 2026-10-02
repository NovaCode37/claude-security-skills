import importlib.util
import json
import os
import sys

import pytest

jsonschema = pytest.importorskip("jsonschema")

SKILLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(SKILLS_DIR, "tests", "fixtures", "sarif-schema-2.1.0.json")

FAKE_KEY = "AKIA" + "Q7P2MZ4XKD8RN3TB"


def _load(skill: str, module: str):
    path = os.path.join(SKILLS_DIR, skill, module + ".py")
    spec = importlib.util.spec_from_file_location(f"{skill}_{module}_sarif", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def schema():
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def project(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(
        "import os\nimport hashlib\n"
        "os.system(user_input)\n"
        "hashlib.md5(data)\n"
        f"aws_key = '{FAKE_KEY}'\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _run(module, argv, capsys):
    code = module.main(argv)
    return code, json.loads(capsys.readouterr().out)


def test_sast_lite_sarif_is_valid(project, schema, capsys):
    sast = _load("sast-lite", "analyzer")
    code, sarif = _run(sast, ["app.py", "--sarif"], capsys)
    jsonschema.validate(sarif, schema)
    assert code == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "sast-lite"
    by_rule = {r["ruleId"]: r for r in run["results"]}
    assert by_rule["py.os-system"]["level"] == "error"
    assert by_rule["py.weak-hash"]["level"] == "warning"
    loc = by_rule["py.os-system"]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.py"
    assert loc["region"]["startLine"] == 3
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert "external/cwe/cwe-78" in rules["py.os-system"]["properties"]["tags"]
    assert rules["py.os-system"]["properties"]["security-severity"] == "8.0"


def test_secret_scanner_sarif_is_valid_and_leaks_nothing(project, schema, capsys):
    scanner = _load("secret-scanner", "engine")
    code, sarif = _run(scanner, ["app.py", "--sarif"], capsys)
    jsonschema.validate(sarif, schema)
    assert code == 1
    results = sarif["runs"][0]["results"]
    assert any(r["ruleId"] == "aws-access-key-id" for r in results)
    text = json.dumps(sarif)
    assert FAKE_KEY not in text
    assert FAKE_KEY[4:12] not in text
    for r in results:
        assert "snippet" not in r["locations"][0]["physicalLocation"]["region"]


def test_clean_scan_gives_empty_valid_sarif_and_exit_zero(tmp_path, schema, capsys, monkeypatch):
    (tmp_path / "ok.py").write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    for skill, module in (("sast-lite", "analyzer"), ("secret-scanner", "engine")):
        code, sarif = _run(_load(skill, module), ["ok.py", "--sarif"], capsys)
        jsonschema.validate(sarif, schema)
        assert code == 0
        assert sarif["runs"][0]["results"] == []


def test_sarif_uses_forward_slashes_for_nested_paths(tmp_path, capsys, monkeypatch):
    sub = tmp_path / "pkg" / "mod"
    sub.mkdir(parents=True)
    (sub / "x.py").write_text("eval(data)\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _, sarif = _run(_load("sast-lite", "analyzer"), [".", "--sarif"], capsys)
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in sarif["runs"][0]["results"]}
    assert uris == {"pkg/mod/x.py"}


def test_json_and_sarif_are_mutually_exclusive(project):
    sast = _load("sast-lite", "analyzer")
    with pytest.raises(SystemExit):
        sast.main(["app.py", "--json", "--sarif"])
