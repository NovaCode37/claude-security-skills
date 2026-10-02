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


# --- random used for security values (issue #34) ----------------------------

def test_random_token_flagged():
    src = "import random\ntoken = random.choice(alphabet)\n"
    assert "py.insecure-random" in ids(src)


def test_random_randint_otp_flagged():
    src = "import random\notp = random.randint(100000, 999999)\n"
    assert "py.insecure-random" in ids(src)


def test_random_shuffle_on_a_list_not_flagged():
    src = "import random\ndeck = list(range(52))\nrandom.shuffle(deck)\n"
    assert "py.insecure-random" not in ids(src)


def test_random_sample_for_ordinary_values_not_flagged():
    src = "import random\nwinners = random.sample(players, 3)\n"
    assert "py.insecure-random" not in ids(src)


def test_secrets_module_not_flagged():
    src = "import secrets\ntoken = secrets.choice(alphabet)\n"
    assert "py.insecure-random" not in ids(src)


def test_insecure_random_carries_cwe_330():
    src = "import random\nsession_token = random.random()\n"
    issue = next(i for i in analyzer.analyze_source(src)
                 if i.rule_id == "py.insecure-random")
    assert issue.cwe == "CWE-330"


# --- min-severity default (issue #48) ---------------------------------------

def test_min_severity_defaults_to_info(tmp_path):
    """Every engine starts at info, so one pipeline filters the same way."""
    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n")
    assert any(i.rule_id == "py.syntax-error"
               for i in analyzer.analyze_paths([str(tmp_path)]))


def test_cli_json(tmp_path, capsys):
    f = tmp_path / "bad.py"
    f.write_text("eval(x)\n")
    analyzer.main([str(f), "--json"])
    import json
    data = json.loads(capsys.readouterr().out)
    assert data and data[0]["cwe"]


def test_platform_system_not_flagged():
    assert "py.os-system" not in ids("import platform\nplatform.system()")


def test_other_dot_system_not_flagged():
    assert "py.os-system" not in ids("client.system('status')\nos_info.popen()")


def test_os_alias_flagged():
    assert "py.os-system" in ids("import os as o\no.system(cmd)")


def test_from_os_import_flagged():
    assert "py.os-system" in ids("from os import system\nsystem(cmd)")
    assert "py.os-system" in ids("from os import popen as run_shell\nrun_shell(cmd)")


def test_bare_system_without_os_import_not_flagged():
    assert "py.os-system" not in ids("system(cmd)")


def test_md5_not_for_security_not_flagged():
    assert "py.weak-hash" not in ids(
        "import hashlib\nhashlib.md5(data, usedforsecurity=False)")


def test_md5_for_security_still_flagged():
    assert "py.weak-hash" in ids("import hashlib\nhashlib.md5(data, usedforsecurity=True)")


@pytest.mark.parametrize("method", ["get", "post", "put", "patch", "delete", "head", "options", "request"])
@pytest.mark.parametrize("receiver", ["requests", "requests.Session()", "session"])
@pytest.mark.parametrize("arguments", ["url", "url, timeout=None"])
def test_requests_without_timeout_flagged(method, receiver, arguments):
    src = f"import requests\nsession = requests.Session()\n{receiver}.{method}({arguments})"
    issues = [i for i in analyzer.analyze_source(src) if i.rule_id == "py.request-no-timeout"]
    assert len(issues) == 1
    assert issues[0].cwe == "CWE-400"
    assert issues[0].severity == "medium"


@pytest.mark.parametrize("arguments", ["url, timeout=5", "url, timeout=(3, 10)", "url, **kwargs", "url, timeout=None, **kwargs"])
def test_requests_with_timeout_or_unknown_kwargs_not_flagged(arguments):
    assert "py.request-no-timeout" not in ids(f"requests.get({arguments})")


def test_unrelated_get_call_not_flagged():
    assert "py.request-no-timeout" not in ids("cache.get(key)\nclient.get(url)")


def test_requests_alias_and_assigned_session_flagged():
    src = "import requests as http\nclient = http.Session()\nclient.get(url)\nhttp.post(url)"
    assert sum(i.rule_id == "py.request-no-timeout" for i in analyzer.analyze_source(src)) == 2


def test_request_timeout_sarif_metadata():
    report = analyzer.to_sarif(analyzer.analyze_source("requests.get(url)", "example.py"))
    run = report["runs"][0]
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "py.request-no-timeout")
    assert rule["shortDescription"]["text"] == "HTTP request without a timeout"
    assert run["results"][0]["level"] == "warning"


def test_reassigned_session_is_not_treated_as_requests():
    src = "import requests\nclient = requests.Session()\nclient = cache\nclient.get(key)"
    assert "py.request-no-timeout" not in ids(src)


@pytest.mark.parametrize("call", [
    "urllib.request.urlopen(url)",
    "request.urlopen(url, timeout=None)",
    "open_url(url)",
])
def test_urllib_without_timeout_flagged(call):
    src = (
        "import urllib.request\n"
        "from urllib import request\n"
        "from urllib.request import urlopen as open_url\n"
        f"{call}"
    )
    assert "py.request-no-timeout" in ids(src)


@pytest.mark.parametrize("call", [
    "urllib.request.urlopen(url, timeout=5)",
    "urllib.request.urlopen(url, None, 5)",
    "urllib.request.urlopen(url, **kwargs)",
])
def test_urllib_with_timeout_or_unknown_kwargs_not_flagged(call):
    assert "py.request-no-timeout" not in ids(f"import urllib.request\n{call}")


@pytest.mark.parametrize("call", [
    "httpx.get(url, timeout=None)",
    "httpx.Client(timeout=None)",
    "httpx.AsyncClient(timeout=None)",
    "client.get(url, timeout=None)",
])
def test_httpx_explicitly_disabled_timeout_flagged(call):
    src = f"import httpx\nclient = httpx.Client()\n{call}"
    assert "py.request-no-timeout" in ids(src)


@pytest.mark.parametrize("call", [
    "httpx.get(url)",
    "httpx.Client()",
    "httpx.AsyncClient(timeout=5)",
    "httpx.get(url, timeout=None, **kwargs)",
])
def test_httpx_defaults_finite_timeout_and_skips_unknown_kwargs(call):
    assert "py.request-no-timeout" not in ids(f"import httpx\n{call}")
