# Changelog

All notable changes to these skills are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

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
