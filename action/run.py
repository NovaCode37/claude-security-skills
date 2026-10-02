from __future__ import annotations

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ENGINES = {
    "secret-scanner": {"script": "skills/secret-scanner/engine.py", "multi": True,
                       "min_severity": False, "sarif": True},
    "sast-lite": {"script": "skills/sast-lite/analyzer.py", "multi": True,
                  "min_severity": True, "sarif": True},
    "dependency-check": {"script": "skills/dependency-check/checker.py", "multi": False,
                         "min_severity": True, "sarif": False},
    "dockerfile-scan": {"script": "skills/dockerfile-scan/scanner.py", "multi": False,
                        "min_severity": False, "sarif": False},
}

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _write_output(key: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")


def _write_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)
    else:
        print(text)


def _command(name: str, spec: dict, paths: list[str], fmt: str, min_sev: str) -> list[str]:
    cmd = [sys.executable, os.path.join(ROOT, spec["script"])]
    cmd += paths if spec["multi"] else paths[:1]
    cmd.append(fmt)
    if spec["min_severity"] and min_sev:
        cmd += ["--min-severity", min_sev]
    return cmd


def _location(item: dict) -> str:
    if item.get("package"):
        return f"{item['package']} {item.get('version', '')}".strip()
    path = item.get("path") or item.get("file") or ""
    line = item.get("line")
    return f"{path}:{line}" if path and line else path


def _items(data) -> list:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        out = []
        for key in ("findings", "issues", "vulnerabilities", "unpinned"):
            if isinstance(data.get(key), list):
                out += data[key]
        return out
    return []


def main() -> int:
    requested = [s.strip() for s in _env("INPUT_SKILLS", "secret-scanner,sast-lite").split(",") if s.strip()]
    unknown = [s for s in requested if s not in ENGINES]
    if unknown:
        print(f"::error::Unknown skill(s): {', '.join(unknown)}. "
              f"Available in the action: {', '.join(ENGINES)}", file=sys.stderr)
        return 2

    paths = _env("INPUT_PATH", ".").split() or ["."]
    min_sev = _env("INPUT_MIN_SEVERITY", "info")
    if min_sev not in SEVERITIES:
        print(f"::error::min-severity must be one of {', '.join(SEVERITIES)}", file=sys.stderr)
        return 2
    want_sarif = _env("INPUT_SARIF", "true").lower() in ("1", "true", "yes")
    sarif_dir = _env("SARIF_DIR") or os.path.join(os.environ.get("RUNNER_TEMP", "."), "claude-security-skills-sarif")

    rows: list[tuple[str, int, str]] = []
    details: list[str] = []
    total = 0
    worst = 0

    for name in requested:
        spec = ENGINES[name]
        res = subprocess.run(_command(name, spec, paths, "--json", min_sev),
                             capture_output=True, text=True, encoding="utf-8")
        if res.returncode not in (0, 1):
            rows.append((name, 0, "error"))
            details.append(f"\n<details><summary>{name} failed</summary>\n\n```\n"
                           f"{(res.stderr or res.stdout)[-2000:]}\n```\n</details>\n")
            worst = 2
            continue
        try:
            data = json.loads(res.stdout or "[]")
        except json.JSONDecodeError:
            data = []
        items = _items(data)
        total += len(items)
        rows.append((name, len(items), "findings" if res.returncode == 1 else "clean"))
        if res.returncode == 1:
            worst = max(worst, 1)
        if items:
            lines = ["| Severity | Rule | Location |", "|---|---|---|"]
            for item in items[:50]:
                rule = item.get("rule_id") or item.get("id") or item.get("rule") or ""
                lines.append(f"| {item.get('severity', '')} | `{rule}` | `{_location(item)}` |")
            more = f"\n_{len(items) - 50} more not shown._\n" if len(items) > 50 else ""
            details.append(f"\n<details><summary>{name}: {len(items)} finding(s)</summary>\n\n"
                           + "\n".join(lines) + "\n" + more + "</details>\n")

        if want_sarif and spec["sarif"]:
            os.makedirs(sarif_dir, exist_ok=True)
            sres = subprocess.run(_command(name, spec, paths, "--sarif", min_sev),
                                  capture_output=True, text=True, encoding="utf-8")
            if sres.returncode in (0, 1) and sres.stdout.strip():
                with open(os.path.join(sarif_dir, f"{name}.sarif"), "w", encoding="utf-8") as fh:
                    fh.write(sres.stdout)

    table = ["## Claude Security Skills", "", "| Skill | Findings | Result |", "|---|---|---|"]
    table += [f"| {n} | {c} | {r} |" for n, c, r in rows]
    _write_summary("\n".join(table) + "\n" + "".join(details) + "\n")

    _write_output("findings", str(total))
    _write_output("sarif-dir", sarif_dir if want_sarif else "")
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
