---
name: dependency-check
description: >-
  Audit project dependencies for known-vulnerable versions and risky pinning.
  Parses requirements.txt and package.json, matches a bundled offline advisory
  DB, optionally queries OSV.dev live, and warns about unpinned versions. Use
  when the user asks to "check dependencies for vulnerabilities", "audit my
  requirements.txt / package.json", "scan for vulnerable packages", or "is my
  dependency tree secure".
license: MIT
---

# Dependency Check

Scans Python (`requirements.txt`) and npm (`package.json`) manifests for
known-vulnerable versions and supply-chain risks. **Offline by default** — it
ships a bundled advisory database so it runs in air-gapped CI — with an optional
live OSV.dev lookup. Pure standard library.

## When to use this skill

- "Are any of my dependencies vulnerable?"
- "Audit requirements.txt / package.json."
- "Check for vulnerable / outdated packages before release."

## What it reports

- **Known vulnerabilities** — version matches against the bundled advisory DB
  (or OSV.dev with `--online`), with CVE/ID, severity and summary.
- **Unpinned dependencies** — ranges (`^`, `~`, `>=`) or missing pins that make
  builds non-reproducible and widen supply-chain exposure.

## How to run it

```bash
# Offline scan (bundled advisory DB)
python skills/dependency-check/checker.py requirements.txt
python skills/dependency-check/checker.py package.json

# Scan a directory (auto-discovers both manifest types)
python skills/dependency-check/checker.py .

# Live advisory lookup via OSV.dev
python skills/dependency-check/checker.py requirements.txt --online

# JSON output
python skills/dependency-check/checker.py . --json
```

**Exit codes:** `0` no known vulns · `1` vulnerabilities found · `2` no
manifest / usage error.

## Recommended workflow for Claude

1. Run offline first for a fast baseline, then `--online` for full coverage if
   the user has network access.
2. For each vulnerable package, recommend the **minimum fixed version** and
   note breaking-change risk.
3. Encourage exact pins (`==` / lockfiles) for reproducible, auditable builds.

## Note

The bundled DB is intentionally small (well-known historical CVEs) so the tool
is self-contained and testable. For comprehensive coverage use `--online`
(OSV.dev) or integrate a dedicated scanner; treat the offline DB as a fast
first pass.
