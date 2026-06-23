from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SECRET_NAME_RE = re.compile(
    r"(?i)(PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|"
    r"PRIVATE[_-]?KEY|AWS[_-]?SECRET)")

PIPE_SHELL_RE = re.compile(
    r"(?i)\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|ash)\b")

CHMOD_777_RE = re.compile(r"(?i)\bchmod\b[^;&|]*\b(0?777|a\+rwx|ugo\+rwx)\b")

PLACEHOLDERS = {"", "changeme", "example", "dummy", "test", "xxx", "none"}


@dataclass
class Finding:
    id: str
    severity: str
    line: int
    instruction: str
    message: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


def _logical_lines(text: str):
    lines = text.splitlines()
    out = []
    i, n = 0, len(lines)
    while i < n:
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start = i + 1
        parts = [raw.rstrip()]
        while parts[-1].endswith("\\") and i + 1 < n:
            parts[-1] = parts[-1][:-1]
            i += 1
            parts.append(lines[i].rstrip())
        joined = " ".join(p.strip() for p in parts).strip()
        out.append((start, joined))
        i += 1
    return out


def _split_instr(text: str):
    m = re.match(r"(?i)([A-Za-z]+)\s+(.*)", text)
    if not m:
        return text.strip().upper(), ""
    return m.group(1).upper(), m.group(2).strip()


def _stage_names(instrs) -> set:
    names = set()
    for _, full in instrs:
        kw, rest = _split_instr(full)
        if kw == "FROM":
            m = re.search(r"(?i)\bAS\s+([A-Za-z0-9_.\-]+)\s*$", rest)
            if m:
                names.add(m.group(1).lower())
    return names


def _check_from(rest: str, lineno: int, stages: set, out: list):
    tokens = [t for t in rest.split() if not t.startswith("--")]
    if not tokens:
        return
    image = tokens[0]
    if "$" in image or image.lower() == "scratch" or image.lower() in stages:
        return
    ref = image.split("@", 1)[0]
    tail = ref.split("/")[-1]
    if ":" not in tail:
        out.append(Finding(
            "docker-no-tag", "medium", lineno, "FROM",
            f"Base image '{image}' has no explicit tag (defaults to latest).",
            "Pin a version tag or digest, e.g. python:3.11-slim."))
    elif tail.rsplit(":", 1)[1].lower() == "latest":
        out.append(Finding(
            "docker-latest-tag", "medium", lineno, "FROM",
            f"Base image '{image}' uses the ':latest' tag.",
            "Pin a specific version tag or digest for reproducible builds."))


def _check_secret(kw: str, rest: str, lineno: int, out: list):
    pairs = re.findall(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)", rest)
    if not pairs and kw == "ENV":
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s+(.+)", rest)
        if m:
            pairs = [(m.group(1), m.group(2))]
    for name, val in pairs:
        v = val.strip().strip("\"'")
        if v.startswith("$") or v.lower() in PLACEHOLDERS:
            continue
        if SECRET_NAME_RE.search(name):
            out.append(Finding(
                "docker-hardcoded-secret", "high", lineno, kw,
                f"{kw} '{name}' appears to hardcode a secret value.",
                "Inject secrets at runtime or via build secrets, not in the image."))


def _check_run(rest: str, lineno: int, out: list):
    if PIPE_SHELL_RE.search(rest):
        out.append(Finding(
            "docker-remote-exec", "high", lineno, "RUN",
            "Pipes a downloaded script straight into a shell (curl|wget | sh).",
            "Download, verify a checksum/signature, then execute."))
    if CHMOD_777_RE.search(rest):
        out.append(Finding(
            "docker-chmod-777", "medium", lineno, "RUN",
            "Grants world-writable 777 permissions.",
            "Use least-privilege permissions (e.g. 750/640)."))
    if re.search(r"(?i)\bsudo\b", rest):
        out.append(Finding(
            "docker-sudo", "low", lineno, "RUN",
            "Uses sudo inside the build; containers already run as root by default.",
            "Drop sudo and set the needed USER explicitly."))


def scan_dockerfile(text: str) -> list:
    instrs = _logical_lines(text)
    stages = _stage_names(instrs)
    out: list = []
    users: list = []
    first_line = instrs[0][0] if instrs else 1
    for lineno, full in instrs:
        kw, rest = _split_instr(full)
        if kw == "FROM":
            _check_from(rest, lineno, stages, out)
        elif kw == "USER":
            users.append((lineno, rest.strip()))
        elif kw == "ADD":
            if re.search(r"https?://", rest):
                out.append(Finding(
                    "docker-add-remote", "medium", lineno, "ADD",
                    "ADD fetches a remote URL without integrity checks.",
                    "Use COPY for local files, or RUN curl with checksum "
                    "verification."))
        elif kw in ("ENV", "ARG"):
            _check_secret(kw, rest, lineno, out)
        elif kw == "RUN":
            _check_run(rest, lineno, out)
    if not users:
        out.append(Finding(
            "docker-root-user", "high", first_line, "USER",
            "No USER instruction — the container runs as root.",
            "Add a non-root user, e.g. 'USER appuser'."))
    else:
        ln, last = users[-1]
        if last.split(":", 1)[0].strip().lower() in ("root", "0"):
            out.append(Finding(
                "docker-root-user", "high", ln, "USER",
                "Final USER is root — the container runs with full privileges.",
                "Switch to a non-root user before the entrypoint."))
    out.sort(key=lambda f: (SEV_RANK.get(f.severity, 9), f.line))
    return out


def discover(path: str) -> list:
    if os.path.isfile(path):
        return [path]
    found = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        for name in files:
            low = name.lower()
            if low == "dockerfile" or low.endswith(".dockerfile") \
                    or low.startswith("dockerfile."):
                found.append(os.path.join(root, name))
    return sorted(found)


def render(path: str, findings: list) -> str:
    if not findings:
        return f"[dockerfile-scan] {path}: no issues found. [OK]"
    out = [f"[dockerfile-scan] {path}: {len(findings)} finding(s):\n"]
    for f in findings:
        out.append(f"  [{f.severity.upper():<8}] {f.id}  ({f.instruction} "
                   f"line {f.line})")
        out.append(f"             {f.message}")
        out.append(f"             fix: {f.recommendation}")
    counts: dict = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    out.append("\nSummary: " + ", ".join(
        f"{k}={counts[k]}" for k in sorted(counts, key=lambda s: SEV_RANK[s])))
    return "\n".join(out)


def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="dockerfile-scan",
        description="Scan Dockerfiles for insecure build patterns.")
    p.add_argument("path", help="a Dockerfile or a directory to search")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    files = discover(args.path)
    if not files:
        print("error: no Dockerfile found.", file=sys.stderr)
        return 2

    all_findings = []
    blocks = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                findings = scan_dockerfile(fh.read())
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        all_findings.extend(findings)
        blocks.append((f, findings))

    if args.json:
        print(json.dumps(
            [{"file": f, **fi.to_dict()} for f, fs in blocks for fi in fs],
            indent=2))
    else:
        print("\n\n".join(render(f, fs) for f, fs in blocks))

    return 1 if all_findings else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
