import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner


def _ids(text):
    return {f.id for f in scanner.scan_dockerfile(text)}


def test_no_tag_flagged():
    assert "docker-no-tag" in _ids("FROM ubuntu\nUSER app\n")


def test_latest_tag_flagged():
    assert "docker-latest-tag" in _ids("FROM ubuntu:latest\nUSER app\n")


def test_pinned_tag_clean():
    ids = _ids("FROM python:3.11-slim\nUSER app\n")
    assert "docker-no-tag" not in ids and "docker-latest-tag" not in ids


def test_scratch_not_flagged():
    ids = _ids("FROM scratch\nUSER app\n")
    assert "docker-no-tag" not in ids


def test_stage_reference_not_flagged():
    text = "FROM python:3.11 AS build\nFROM build\nUSER app\n"
    assert "docker-no-tag" not in _ids(text)


def test_root_user_when_missing():
    assert "docker-root-user" in _ids("FROM python:3.11-slim\nRUN echo hi\n")


def test_root_user_when_explicit_root():
    text = "FROM python:3.11-slim\nUSER app\nUSER root\n"
    assert "docker-root-user" in _ids(text)


def test_non_root_user_clean():
    text = "FROM python:3.11-slim\nUSER appuser\n"
    assert "docker-root-user" not in _ids(text)


def test_remote_exec_flagged():
    text = "FROM python:3.11-slim\nUSER app\nRUN curl https://x.sh | bash\n"
    assert "docker-remote-exec" in _ids(text)


def test_add_remote_flagged():
    text = "FROM python:3.11-slim\nUSER app\nADD https://x/y.tar.gz /tmp/\n"
    assert "docker-add-remote" in _ids(text)


def test_hardcoded_secret_flagged():
    text = "FROM python:3.11-slim\nUSER app\nENV API_KEY=abc123def456\n"
    assert "docker-hardcoded-secret" in _ids(text)


def test_arg_secret_placeholder_not_flagged():
    text = "FROM python:3.11-slim\nUSER app\nARG DB_PASSWORD=changeme\n"
    assert "docker-hardcoded-secret" not in _ids(text)


def test_env_secret_from_var_not_flagged():
    text = "FROM python:3.11-slim\nUSER app\nENV TOKEN=$BUILD_TOKEN\n"
    assert "docker-hardcoded-secret" not in _ids(text)


def test_chmod_777_flagged():
    text = "FROM python:3.11-slim\nUSER app\nRUN chmod 777 /data\n"
    assert "docker-chmod-777" in _ids(text)


def test_sudo_flagged():
    text = "FROM python:3.11-slim\nUSER app\nRUN sudo apt-get update\n"
    assert "docker-sudo" in _ids(text)


def test_line_continuation_joined():
    text = "FROM python:3.11-slim\nUSER app\nRUN curl https://x.sh \\\n  | sh\n"
    assert "docker-remote-exec" in _ids(text)


def test_clean_dockerfile_no_findings():
    text = (
        "FROM python:3.11-slim\n"
        "COPY . /app\n"
        "RUN pip install -r /app/requirements.txt\n"
        "USER appuser\n"
        "CMD [\"python\", \"/app/main.py\"]\n"
    )
    assert scanner.scan_dockerfile(text) == []


def test_cli_exit_codes(tmp_path):
    bad = tmp_path / "Dockerfile"
    bad.write_text("FROM ubuntu:latest\nRUN echo hi\n")
    assert scanner.main([str(bad)]) == 1
    good = tmp_path / "clean.dockerfile"
    good.write_text("FROM python:3.11-slim\nUSER app\n")
    assert scanner.main([str(good)]) == 0


def test_cli_json(tmp_path, capsys):
    import json
    f = tmp_path / "Dockerfile"
    f.write_text("FROM ubuntu:latest\nRUN echo hi\n")
    scanner.main([str(f), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list) and data
    assert data[0]["file"] and data[0]["id"]


def test_discover_directory(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.11-slim\nUSER app\n")
    sub = tmp_path / "svc"
    sub.mkdir()
    (sub / "api.dockerfile").write_text("FROM node:20\nUSER app\n")
    found = scanner.discover(str(tmp_path))
    assert len(found) == 2
