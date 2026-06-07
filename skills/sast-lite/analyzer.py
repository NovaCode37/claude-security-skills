from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from dataclasses import dataclass, asdict
from typing import Iterable, Iterator

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".mypy_cache", ".pytest_cache", "site-packages",
}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Issue:
    rule_id: str
    cwe: str
    message: str
    severity: str
    path: str
    line: int
    col: int
    snippet: str

    def to_dict(self) -> dict:
        return asdict(self)


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ".".join(reversed(parts)) if parts else ""


def _kw(call: ast.Call, name: str):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_const_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_const_false(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_string_constant(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


PASSWORD_NAMES = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_key", "secret_key", "private_key", "auth_token",
}


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, path: str, source_lines: list[str]):
        self.path = path
        self.lines = source_lines
        self.issues: list[Issue] = []

    def _add(self, node: ast.AST, rule_id: str, cwe: str, msg: str, sev: str):
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.issues.append(Issue(rule_id, cwe, msg, sev, self.path, line,
                                 col + 1, snippet[:200]))

    def visit_Call(self, node: ast.Call):
        target = ""
        if isinstance(node.func, ast.Name):
            target = node.func.id
        elif isinstance(node.func, ast.Attribute):
            target = _attr_chain(node.func)
        last = target.split(".")[-1] if target else ""

        if target in ("eval", "exec") or last in ("eval", "exec"):
            dynamic = bool(node.args) and not _is_string_constant(node.args[0])
            sev = "critical" if dynamic else "high"
            self._add(node, "py.eval-exec", "CWE-95",
                      f"Use of {last}() can execute arbitrary code.", sev)
        if last == "compile" and target in ("compile",):
            self._add(node, "py.compile", "CWE-95",
                      "compile() of dynamic source can lead to code execution.",
                      "medium")

        if target in ("os.system", "os.popen") or last in ("system", "popen"):
            if target.startswith("os.") or last in ("system", "popen"):
                self._add(node, "py.os-system", "CWE-78",
                          f"{target or last}() invokes a shell — command "
                          f"injection risk.", "high")

        if "subprocess" in target or last in (
                "call", "run", "Popen", "check_output", "check_call"):
            if _is_const_true(_kw(node, "shell")):
                self._add(node, "py.subprocess-shell", "CWE-78",
                          "subprocess called with shell=True — command "
                          "injection risk.", "high")

        if last in ("loads", "load") and any(
                target.startswith(m + ".") or target == m + "." + last
                for m in ("pickle", "cPickle", "marshal", "_pickle")):
            self._add(node, "py.insecure-deserialization", "CWE-502",
                      f"{target}() deserializes untrusted data unsafely.",
                      "high")

        if target.endswith("yaml.load") or (last == "load" and "yaml" in target):
            loader = _kw(node, "Loader")
            safe = False
            if loader is not None:
                lname = _attr_chain(loader) if isinstance(
                    loader, (ast.Attribute, ast.Name)) else ""
                safe = "Safe" in lname or "CSafe" in lname
            if not safe:
                self._add(node, "py.yaml-load", "CWE-20",
                          "yaml.load() without SafeLoader can execute "
                          "arbitrary objects; use yaml.safe_load().", "high")

        if last in ("md5", "sha1") and (
                "hashlib" in target or target in ("md5", "sha1")):
            self._add(node, "py.weak-hash", "CWE-327",
                      f"{last} is cryptographically broken; use SHA-256+.",
                      "medium")

        if _is_const_false(_kw(node, "verify")) and (
                "requests" in target or last in (
                    "get", "post", "put", "delete", "patch", "head",
                    "request", "Session")):
            self._add(node, "py.tls-verify-disabled", "CWE-295",
                      "TLS certificate verification disabled (verify=False).",
                      "high")

        if target.endswith("tempfile.mktemp") or last == "mktemp":
            self._add(node, "py.insecure-temp", "CWE-377",
                      "tempfile.mktemp() is race-prone; use mkstemp()/"
                      "NamedTemporaryFile.", "medium")

        if last == "run" and _is_const_true(_kw(node, "debug")):
            self._add(node, "py.flask-debug", "CWE-489",
                      "Flask app.run(debug=True) exposes the Werkzeug "
                      "debugger in production.", "medium")

        if last == "Environment" and _is_const_false(_kw(node, "autoescape")):
            self._add(node, "py.jinja-autoescape", "CWE-79",
                      "Jinja2 Environment(autoescape=False) enables XSS.",
                      "medium")

        if last in ("execute", "executemany", "executescript") and node.args:
            arg0 = node.args[0]
            if isinstance(arg0, ast.JoinedStr):
                self._add(node, "py.sql-injection", "CWE-89",
                          "SQL query built with an f-string — use "
                          "parameterized queries.", "high")
            elif isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Add):
                self._add(node, "py.sql-injection", "CWE-89",
                          "SQL query built with string concatenation — use "
                          "parameterized queries.", "high")
            elif (isinstance(arg0, ast.Call)
                  and isinstance(arg0.func, ast.Attribute)
                  and arg0.func.attr == "format"):
                self._add(node, "py.sql-injection", "CWE-89",
                          "SQL query built with str.format() — use "
                          "parameterized queries.", "high")
            elif isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Mod):
                self._add(node, "py.sql-injection", "CWE-89",
                          "SQL query built with %-formatting — use "
                          "parameterized queries.", "high")

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        if _is_string_constant(node.value) and node.value.value:
            for tgt in node.targets:
                name = tgt.id if isinstance(tgt, ast.Name) else (
                    tgt.attr if isinstance(tgt, ast.Attribute) else "")
                if name.lower() in PASSWORD_NAMES and len(node.value.value) >= 4:
                    self._add(node, "py.hardcoded-secret", "CWE-798",
                              f"Hardcoded secret in variable '{name}'.",
                              "high")
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        src = ast.dump(node.test).lower()
        if any(k in src for k in (
                "auth", "permission", "is_admin", "isadmin", "role",
                "access", "allowed", "verify", "valid")):
            self._add(node, "py.assert-security", "CWE-617",
                      "assert used for a security check — asserts are removed "
                      "with python -O.", "medium")
        self.generic_visit(node)


def analyze_source(source: str, path: str = "<string>") -> list[Issue]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [Issue("py.syntax-error", "CWE-000",
                      f"Could not parse file: {exc.msg}", "info",
                      path, exc.lineno or 0, (exc.offset or 0), "")]
    visitor = SecurityVisitor(path, source.splitlines())
    visitor.visit(tree)
    return visitor.issues


def iter_py_files(paths: Iterable[str]) -> Iterator[str]:
    for root in paths:
        if os.path.isfile(root):
            if root.endswith(".py"):
                yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(".py"):
                    yield os.path.join(dirpath, name)


def analyze_paths(paths: Iterable[str],
                  min_severity: str = "low") -> list[Issue]:
    threshold = SEVERITY_RANK.get(min_severity, 3)
    issues: list[Issue] = []
    for path in iter_py_files(paths):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                src = fh.read()
        except OSError:
            continue
        for issue in analyze_source(src, path):
            if SEVERITY_RANK.get(issue.severity, 3) <= threshold:
                issues.append(issue)
    issues.sort(key=lambda i: (SEVERITY_RANK.get(i.severity, 9), i.path, i.line))
    return issues


_SEV_COLOR = {
    "critical": "\033[1;91m", "high": "\033[91m",
    "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m",
}
_RESET = "\033[0m"


def render_pretty(issues: list[Issue]) -> str:
    if not issues:
        return "[sast-lite] No issues found. [OK]"
    color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    out = [f"[sast-lite] {len(issues)} issue(s) found:\n"]
    for i in issues:
        tag = i.severity.upper()
        if color:
            tag = f"{_SEV_COLOR.get(i.severity, '')}{tag}{_RESET}"
        out.append(f"  {tag:<10} {i.path}:{i.line}:{i.col}  [{i.rule_id} / {i.cwe}]")
        out.append(f"             {i.message}")
        if i.snippet:
            out.append(f"             > {i.snippet}")
    counts: dict[str, int] = {}
    for i in issues:
        counts[i.severity] = counts.get(i.severity, 0) + 1
    out.append("\nSummary: " + ", ".join(
        f"{k}={counts[k]}" for k in sorted(counts, key=lambda s: SEVERITY_RANK.get(s, 9))))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="sast-lite",
        description="Lightweight AST-based Python security analyzer.")
    p.add_argument("paths", nargs="+", help="files or directories to scan")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.add_argument("--min-severity", default="low",
                   choices=list(SEVERITY_RANK),
                   help="report issues at or above this severity")
    args = p.parse_args(argv)

    for path in args.paths:
        if not os.path.exists(path):
            print(f"error: path not found: {path}", file=sys.stderr)
            return 2

    issues = analyze_paths(args.paths, min_severity=args.min_severity)
    if args.json:
        print(json.dumps([i.to_dict() for i in issues], indent=2))
    else:
        print(render_pretty(issues))
    return 1 if issues else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
