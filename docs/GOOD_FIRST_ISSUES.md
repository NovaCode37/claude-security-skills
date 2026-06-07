# Good First Issues — paste-ready

Maintainer: open these as separate issues and add the labels
`good first issue` + `help wanted`. They're scoped so a newcomer can land a PR
in under an hour. Each links to the file to touch and ships with acceptance
criteria.

---

## 1. secret-scanner: add a DigitalOcean PAT rule
**Labels:** `good first issue`, `secret-scanner`

DigitalOcean personal access tokens have the form `dop_v1_<64 hex>`. Add a rule
so we flag them.

- **File:** [`skills/secret-scanner/engine.py`](../skills/secret-scanner/engine.py) → `RULES`
- **Add:** `Rule("digitalocean-pat", "DigitalOcean PAT", "high", _c(r"\b(dop_v1_[a-f0-9]{64})\b"), 1)` and add the id to `NO_ENTROPY_RULES`.
- **Test:** add a parametrized case in `tests/test_engine.py::test_rule_detects`.
- ✅ Done when: the new test passes and `pytest skills/secret-scanner` is green.

## 2. secret-scanner: add Mailgun / SendGrid-style API keys
**Labels:** `good first issue`, `secret-scanner`

Add patterns for Mailgun (`key-<32 hex>`) and Postmark server tokens. Anchor
with the `mailgun` / `postmark` keyword to keep false positives low.

- **File:** `skills/secret-scanner/engine.py`
- ✅ Done when: TP test added and the placeholder test still passes.

## 3. sast-lite: flag `random` module used for security
**Labels:** `good first issue`, `sast-lite`

`random.random()/randint()` is not cryptographically secure. Flag calls to
`random.*` when the surrounding name suggests security (`token`, `password`,
`secret`, `otp`, `nonce`). Recommend `secrets`.

- **File:** [`skills/sast-lite/analyzer.py`](../skills/sast-lite/analyzer.py) → `visit_Call`
- **CWE:** CWE-330
- ✅ Done when: a TP and TN test are added to `tests/test_analyzer.py`.

## 4. sast-lite: detect `xml.etree`/`lxml` XXE-prone parsing
**Labels:** `good first issue`, `sast-lite`

Flag `xml.etree.ElementTree.parse/fromstring` and recommend `defusedxml`.

- **File:** `skills/sast-lite/analyzer.py`
- **CWE:** CWE-611
- ✅ Done when: tests cover a parse call (TP) and a `defusedxml` call (TN).

## 5. http-sec-audit: add COOP/COEP/CORP checks
**Labels:** `good first issue`, `http-sec-audit`

Warn when `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, or
`Cross-Origin-Resource-Policy` are missing (low severity, advisory).

- **File:** [`skills/http-sec-audit/audit.py`](../skills/http-sec-audit/audit.py) → `audit_headers`
- ✅ Done when: tests in `tests/test_audit.py` cover present vs missing.

## 6. http-sec-audit: flag missing `Cache-Control: no-store` heuristic
**Labels:** `good first issue`, `http-sec-audit`

Add an opt-in check that flags responses lacking `Cache-Control` directives
(advisory/low). Keep it off the default high-severity gate.

- **File:** `skills/http-sec-audit/audit.py`

## 7. jwt-inspector: detect `jku`/`x5u`/`kid` header injection vectors
**Labels:** `good first issue`, `jwt-inspector`

If the JWT header contains `jku`, `x5u`, or a `kid` that looks path-like
(`../`, `http`), flag it as a key-confusion / SSRF vector.

- **File:** [`skills/jwt-inspector/inspector.py`](../skills/jwt-inspector/inspector.py) → `audit`
- ✅ Done when: tests cover a header with `jku` (TP) and a normal header (TN).

## 8. dependency-check: grow the bundled advisory DB
**Labels:** `good first issue`, `dependency-check`

Add 5+ well-known historical advisories (with CVE + fixed version) to
`ADVISORIES`. One PR per ecosystem is fine.

- **File:** [`skills/dependency-check/checker.py`](../skills/dependency-check/checker.py) → `ADVISORIES`
- ✅ Done when: each new entry has a matching detection test.

## 9. dependency-check: parse `Pipfile` / `pyproject.toml` deps
**Labels:** `good first issue`, `dependency-check`

Add a parser for `[project].dependencies` in `pyproject.toml` (stdlib
`tomllib` on 3.11+, graceful skip otherwise).

- **File:** `skills/dependency-check/checker.py`

## 10. prompt-injection-tester: add a payload category
**Labels:** `good first issue`, `prompt-injection-tester`

Add 2–3 public payloads in a new or existing category (e.g. `tool-abuse`,
`unicode-obfuscation`). Include success markers so scoring works.

- **File:** [`skills/prompt-injection-tester/attacker.py`](../skills/prompt-injection-tester/attacker.py) → `_payloads()`
- ✅ Done when: `tests/test_attacker.py::test_payload_ids_unique` still passes
  and the new payloads have markers.

## 11. docs: record a terminal demo (GIF / asciinema)
**Labels:** `good first issue`, `documentation`

Record one skill finding a real issue and embed it at the top of the README.

## 12. docs: translate the README
**Labels:** `good first issue`, `documentation`, `help wanted`

Add `README.<lang>.md` and link it from the top of the English README.
