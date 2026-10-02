# Changelog

All notable changes to these skills are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.3.0] — 2026-10-02

### Added
- **A GitHub Action.** `uses: NovaCode37/claude-security-skills@v1` runs `secret-scanner`, `sast-lite`, `dependency-check` and `dockerfile-scan` against a checkout, writes a findings table to the job summary and outputs the count. A finding fails the step, the same contract as the engines; the action never swallows the exit code, so carrying on after a finding is the caller's `continue-on-error` decision. Inputs reach the script through environment variables rather than being interpolated into the shell command, so a crafted input cannot inject a command (#57).
- **SARIF 2.1.0 output** with `--sarif` on `secret-scanner` and `sast-lite`, validated against the official schema in the test suite. Uploaded with `github/codeql-action/upload-sarif`, findings appear in the Security tab and on the line of the pull request diff. Rules carry a CWE tag and a `security-severity`, so GitHub ranks them. The `secret-scanner` SARIF never includes the secret, redacted or not, or a snippet of the line, only file, line and column, because that file is uploaded to GitHub. `dependency-check` and `dockerfile-scan` do not emit SARIF yet; URL- and token-based engines are out of scope, since a finding about a URL has no file to point at (#49).

### Fixed
- **`sast-lite` flagged `platform.system()` as a shell call** at high severity, which failed any build that used `--min-severity high` and checked the OS. The rule matched any call ending in `.system` or `.popen`. It now tracks how `os` was imported, including `import os as o` and `from os import system as run`, and only flags those.
- **`sast-lite` flagged `hashlib.md5(..., usedforsecurity=False)`** as a weak hash. That argument is how Python 3.9+ marks a hash as not used for security, so it is no longer reported.

---

## [1.2.0] — 2026-09-28

### Added
- **secret-scanner and sast-lite as pre-commit hooks.** Both engines already took several paths, so they now run over the staged files and stop a commit before a leaked key or a dangerous call lands, instead of catching it later in CI. The hooks are console entry points backed by minimal packaging metadata, so they resolve from a separate checkout and add no runtime dependencies. `.pre-commit-hooks.yaml` and a pinned-revision config, with the local hook being bypassable and CI being the enforcement, are in the README (#55, #56).
- **`npx skills add` as an install path.** The repo is laid out as `skills/<name>/SKILL.md`, which is exactly what the skills CLI expects, so one command installs all eight into Claude Code, Cursor, Codex and Copilot. Checked against a clean directory.

### Changed
- README leads with the terminal sample and the CI angle, since running these in a pipeline is what sets them apart from a prompt collection. Test count is 229.

---

## [1.1.0] — 2026-09-19

### Added
- **secret-scanner knows the model providers now.** A repo of AI-security skills that missed AI provider keys was an odd gap. Hugging Face (`hf_`), Replicate (`r8_`) and Groq (`gsk_`) have distinctive prefixes, so they are matched on shape alone. Cohere keys are 40 plain alphanumerics with nothing to anchor on, so that rule needs the word `cohere` nearby and stays entropy-gated, otherwise it would fire on every long random string in a repo (#42).
- **DigitalOcean personal access tokens** (`dop_v1_` plus 64 hex). Specific enough to skip entropy gating, and it does not fire on an ordinary hex digest of the same length (#33).
- **sast-lite flags the `random` module used for secrets**, tagged CWE-330, recommending `secrets` instead. It only fires when the value is assigned to something that reads like a credential (`token`, `password`, `otp`, `nonce`, `salt`, …). Flagging every `random.choice` would have buried the finding under sampling and shuffling (#34).
- **http-sec-audit `--advisory`**: cross-origin isolation (COOP, COEP, CORP) and a missing `Cache-Control` (#36, #37).

### Changed
- **`--advisory` is off by default, on purpose.** Since 1.0 the exit code reflects whatever the run reports, so an always-on check for headers that most sites have good reason not to set would have turned every such site into a failed build. The findings are `info` severity and only appear when you ask for them.

### Breaking
- **sast-lite `--min-severity` now defaults to `info`, not `low`**, so all five engines that take the flag agree and one pipeline filters the same way everywhere (#48). In practice this means unparseable files are now reported where they used to be skipped in silence, and since a reported finding fails the run, a repository containing a file sast-lite cannot parse will start failing CI. Pass `--min-severity low` to get the old behaviour back.

---

## [1.0.0] — 2026-09-05

First release. Eight skills, each self-contained, tested, and runnable from the command line as well as through Claude: `secret-scanner`, `sast-lite`, `prompt-injection-tester`, `http-sec-audit`, `jwt-inspector`, `dependency-check`, `dockerfile-scan`, `cors-auditor`.
