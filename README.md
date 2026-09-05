# Claude Security Skills

Security skills for [Claude Code](https://claude.com/claude-code). Install them
once and ask Claude, in plain language, to scan a repo for leaked secrets,
review Python code, red-team an LLM for prompt injection, or audit HTTP headers,
JWTs, Dockerfiles, CORS, and dependencies. Claude picks the right skill, runs
it, and explains what it found.

Everything here runs on the Python standard library — no packages to install,
nothing phoning home. The analysis runs offline; only the few skills that need
to hit a URL use the network, and only when you ask them to.

[![CI](https://github.com/NovaCode37/claude-security-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/NovaCode37/claude-security-skills/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-158%20passing-brightgreen)](#tests)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Zero deps](https://img.shields.io/badge/runtime%20deps-0-success)](#design-principles)
[![License: MIT](https://img.shields.io/badge/license-MIT-black)](LICENSE)

Other languages: [Español](README.es.md) · [Русский](README.ru.md)

## The skills

| Skill | What it does | Engine |
|-------|--------------|--------|
| [secret-scanner](skills/secret-scanner) | Finds hardcoded API keys, tokens and private keys using vendor patterns plus Shannon-entropy analysis, tuned for few false positives | Custom entropy engine |
| [sast-lite](skills/sast-lite) | AST-based static analysis for Python: command injection, eval/exec, insecure deserialization, SQLi, weak crypto, disabled TLS — each tagged with a CWE | Python `ast` walker |
| [prompt-injection-tester](skills/prompt-injection-tester) | Red-teams your own LLM app with a categorized payload library and canary detection, then scores resilience 0–100 | Canary harness |
| [http-sec-audit](skills/http-sec-audit) | Checks HTTP security headers and cookie flags (CSP, HSTS, SameSite, …) and gives concrete fixes | urllib + pure core |
| [jwt-inspector](skills/jwt-inspector) | Decodes and audits JWTs (alg=none, weak expiry, claim hygiene) and cracks weak HMAC secrets offline | HMAC + checks |
| [dependency-check](skills/dependency-check) | Flags known-vulnerable and unpinned deps in `requirements.txt`, `package.json` and `pyproject.toml`; offline DB plus optional OSV.dev | Version matcher |
| [dockerfile-scan](skills/dockerfile-scan) | Catches insecure Dockerfile patterns: running as root, `:latest` base images, `curl \| sh`, remote `ADD`, baked-in secrets | Dockerfile parser |
| [cors-auditor](skills/cors-auditor) | Audits CORS config for wildcard-with-credentials, reflected origins, `null` origin and overly broad methods | Header analyzer |

Each skill is self-contained, has its own tests, and exits non-zero when it
finds something — so it also works as a CI step.

## Install

As a plugin, from inside Claude Code:

```
/plugin marketplace add NovaCode37/claude-security-skills
/plugin install claude-security-skills
```

All eight skills arrive together and update with the marketplace.

Or copy them in by hand, which works the same way:

```bash
git clone https://github.com/NovaCode37/claude-security-skills.git
cp -r claude-security-skills/skills/* .claude/skills/
```

Use `~/.claude/skills/` instead to have them in every project. Restart Claude
Code and it discovers them from each `SKILL.md`. There's nothing else to
install either way.

## Usage

Just ask Claude. For example:

| You say | Claude runs |
|---------|-------------|
| "Any secrets committed in here?" | secret-scanner |
| "Security-review this Python file." | sast-lite |
| "Is my AI assistant jailbreakable?" | prompt-injection-tester |
| "Check example.com's security headers." | http-sec-audit |
| "Decode and audit this JWT." | jwt-inspector |
| "Are my dependencies vulnerable?" | dependency-check |
| "Review my Dockerfile." | dockerfile-scan |
| "Is my API's CORS safe?" | cors-auditor |

Every engine also runs on its own from the command line:

```bash
python skills/secret-scanner/engine.py .            --json
python skills/sast-lite/analyzer.py src/            --min-severity high
python skills/prompt-injection-tester/attacker.py   --demo
python skills/http-sec-audit/audit.py https://example.com
python skills/jwt-inspector/inspector.py "<token>"
python skills/dependency-check/checker.py requirements.txt
python skills/dockerfile-scan/scanner.py Dockerfile
python skills/cors-auditor/auditor.py https://api.example.com
```

Here's what a run looks like:

```console
$ python skills/secret-scanner/engine.py .
[secret-scanner] 2 potential secret(s) found:

  CRITICAL   src/config.py:14:18
             Stripe secret key [stripe-secret]  value=sk_l...k1L2 (len=32)
  HIGH       src/config.py:12:11
             AWS Access Key ID [aws-access-key-id]  value=AKIA...MPLE (len=20)

Summary: critical=1, high=1
```

## Tests

```bash
pip install pytest
pytest skills/ -q
```

158 tests, all offline, run in under a second.

## Design principles

- **No runtime dependencies.** Pure Python 3.9+ stdlib, so the skills run in
  locked-down CI and are easy to read and audit.
- **Offline by default.** The analysis logic takes data in and returns
  findings; network access is optional and explicit.
- **Few false positives.** Entropy thresholds, keyword anchoring and
  placeholder allowlists keep the noise down.
- **CI-friendly.** Consistent exit codes (`0` clean, `1` findings, `2` error)
  and `--json` on every skill.
- **Safe by default.** Secrets are redacted in output, and the offensive
  skills are meant for systems you own or are allowed to test.

## Contributing

New skills and rules are welcome. The good first issues in
[docs/GOOD_FIRST_ISSUES.md](docs/GOOD_FIRST_ISSUES.md) each say which file to
edit and how to know you're done, and [CONTRIBUTING.md](CONTRIBUTING.md) has the
skill template and conventions. If you have an idea, open a
[discussion](https://github.com/NovaCode37/claude-security-skills/discussions).

## Legal

These tools are for authorized security testing, learning and defensive work.
Only scan systems and data you own or have permission to test. The maintainers
aren't responsible for misuse.

## License

[MIT](LICENSE)
