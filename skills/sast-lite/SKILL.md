---
name: sast-lite
description: >-
  Static security analysis for Python source via AST walking — finds command
  injection, insecure deserialization, eval/exec, weak crypto, SQL injection,
  disabled TLS verification, hardcoded secrets and more, each tagged with a
  CWE. Use when the user asks to "audit this code for vulnerabilities", "run a
  SAST scan", "security review this Python file", or before merging untrusted
  code.
license: MIT
---

# SAST Lite

An AST-based static analyzer for Python. Instead of fragile regex matching, it
parses each file into an abstract syntax tree and inspects how dangerous APIs
are actually called — so `subprocess.run(cmd, shell=True)` is flagged while
`subprocess.run(["ls"])` is not. **No third-party dependencies.**

## When to use this skill

- "Audit / security-review this Python code."
- "Run a SAST scan on the project."
- Reviewing a PR or untrusted snippet before running it.
- A pre-merge CI gate for security regressions.

## What it detects

| Rule | CWE | Severity |
|------|-----|----------|
| `eval()` / `exec()` on dynamic input | CWE-95 | critical/high |
| `os.system` / `subprocess(shell=True)` | CWE-78 | high |
| `pickle`/`marshal` deserialization | CWE-502 | high |
| `yaml.load` without SafeLoader | CWE-20 | high |
| SQL via f-string / concat / `.format` / `%` | CWE-89 | high |
| `requests(verify=False)` | CWE-295 | high |
| Hardcoded password/secret literal | CWE-798 | high |
| Weak hash (md5/sha1) | CWE-327 | medium |
| `tempfile.mktemp` | CWE-377 | medium |
| `Flask(debug=True)` | CWE-489 | medium |
| Jinja2 `autoescape=False` | CWE-79 | medium |
| `assert` used for a security check | CWE-617 | medium |

## How to run it

```bash
# Scan a directory
python skills/sast-lite/analyzer.py src/

# JSON for tooling / CI
python skills/sast-lite/analyzer.py . --json

# Only show high+ severity
python skills/sast-lite/analyzer.py . --min-severity high
```

**Exit codes:** `0` clean · `1` issues found · `2` usage/parse error — ready
for CI gating.

## Recommended workflow for Claude

1. Run with `--json` and parse the issue list.
2. For each issue, open `path:line` and confirm the data flow is genuinely
   attacker-controllable (the analyzer is intra-procedural, so it may flag
   patterns that are safe in context).
3. Propose a concrete fix per finding — e.g. parameterized queries for
   `py.sql-injection`, `yaml.safe_load` for `py.yaml-load`,
   list-form `subprocess` calls for `py.subprocess-shell`.
4. Summarize by severity and CWE.

## Limitations

This is a *lite* analyzer: single-file, no cross-function taint tracking. It is
designed for fast, high-signal triage — not a replacement for a full SAST
suite. Treat findings as leads to verify, not automatic verdicts.
