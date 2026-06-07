import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import analyzer


def ids(src):
    return {i.rule_id for i in analyzer.analyze_source(src)}


def test_eval_flagged():
    assert "py.eval-exec" in ids("eval(user_input)")


def test_exec_flagged():
    assert "py.eval-exec" in ids("exec(payload)")


def test_os_system_flagged():
    assert "py.os-system" in ids("import os\nos.system(cmd)")


def test_subprocess_shell_true_flagged():
    src = "import subprocess\nsubprocess.run(cmd, shell=True)"
    assert "py.subprocess-shell" in ids(src)


def test_pickle_loads_flagged():
    assert "py.insecure-deserialization" in ids("import pickle\npickle.loads(data)")


def test_yaml_load_flagged():
    assert "py.yaml-load" in ids("import yaml\nyaml.load(data)")


def test_weak_hash_flagged():
    assert "py.weak-hash" in ids("import hashlib\nhashlib.md5(x)")


def test_tls_verify_false_flagged():
    src = "import requests\nrequests.get(url, verify=False)"
    assert "py.tls-verify-disabled" in ids(src)


def test_hardcoded_secret_flagged():
    assert "py.hardcoded-secret" in ids("password = 'hunter2pass'")


def test_sql_fstring_flagged():
    src = "cur.execute(f'SELECT * FROM t WHERE id = {uid}')"
    assert "py.sql-injection" in ids(src)


def test_sql_concat_flagged():
    src = "cur.execute('SELECT * FROM t WHERE id = ' + uid)"
    assert "py.sql-injection" in ids(src)


def test_sql_format_flagged():
    src = "cur.execute('SELECT * FROM t WHERE id = {}'.format(uid))"
    assert "py.sql-injection" in ids(src)


def test_flask_debug_flagged():
    assert "py.flask-debug" in ids("app.run(debug=True)")


def test_mktemp_flagged():
    assert "py.insecure-temp" in ids("import tempfile\ntempfile.mktemp()")


def test_assert_security_flagged():
    assert "py.assert-security" in ids("assert user.is_admin")


def test_jinja_autoescape_flagged():
    src = "from jinja2 import Environment\nEnvironment(autoescape=False)"
    assert "py.jinja-autoescape" in ids(src)


def test_safe_subprocess_not_flagged():
    src = "import subprocess\nsubprocess.run(['ls', '-la'])"
    assert "py.subprocess-shell" not in ids(src)


def test_yaml_safe_load_not_flagged():
    assert "py.yaml-load" not in ids("import yaml\nyaml.safe_load(data)")


def test_yaml_load_with_safeloader_not_flagged():
    src = "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)"
    assert "py.yaml-load" not in ids(src)


def test_tls_verify_true_not_flagged():
    src = "import requests\nrequests.get(url, verify=True)"
    assert "py.tls-verify-disabled" not in ids(src)


def test_parameterized_sql_not_flagged():
    src = "cur.execute('SELECT * FROM t WHERE id = ?', (uid,))"
    assert "py.sql-injection" not in ids(src)


def test_sha256_not_flagged():
    assert "py.weak-hash" not in ids("import hashlib\nhashlib.sha256(x)")


def test_normal_assert_not_flagged():
    assert "py.assert-security" not in ids("assert len(items) == 3")


def test_clean_code_no_issues():
    src = "def add(a, b):\n    return a + b\n"
    assert analyzer.analyze_source(src) == []


def test_syntax_error_reported():
    issues = analyzer.analyze_source("def (:\n")
    assert any(i.rule_id == "py.syntax-error" for i in issues)


def test_severity_filter(tmp_path):
    f = tmp_path / "v.py"
    f.write_text("import hashlib\nhashlib.md5(x)\neval(y)\n")
    high_only = analyzer.analyze_paths([str(tmp_path)], min_severity="high")
    rule_ids = {i.rule_id for i in high_only}
    assert "py.eval-exec" in rule_ids
    assert "py.weak-hash" not in rule_ids


def test_cli_exit_codes(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1\n")
    assert analyzer.main([str(clean)]) == 0
    bad = tmp_path / "bad.py"
    bad.write_text("eval(x)\n")
    assert analyzer.main([str(bad)]) == 1


def test_cli_json(tmp_path, capsys):
    f = tmp_path / "bad.py"
    f.write_text("eval(x)\n")
    analyzer.main([str(f), "--json"])
    import json
    data = json.loads(capsys.readouterr().out)
    assert data and data[0]["cwe"]
