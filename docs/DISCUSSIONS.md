# Discussions — setup & starter posts

Enable **Settings → General → Features → Discussions**, create the categories
below, then paste the starter posts to seed activity (an empty Discussions tab
looks dead — seed it before launch).

## Suggested categories

| Category | Format | Purpose |
|----------|--------|---------|
| 📣 Announcements | Announcement | Releases, roadmap updates (maintainers post) |
| 💡 Ideas | Open-ended | Propose new skills / rules before opening an issue |
| 🙏 Q&A | Question/Answer | Install help, "how do I scan X?" |
| 🛠️ Show and tell | Open-ended | "I found a leaked key with this" / integrations |
| 🗳️ Polls | Poll | Vote on what to build next |

---

## Starter post 1 — pin in 📣 Announcements

**Title:** 👋 Welcome to Claude Security Skills — start here

> Hi, and thanks for stopping by!
>
> This repo turns **Claude Code** into a security toolkit: secret scanning,
> Python SAST, LLM prompt-injection testing, HTTP header / JWT / dependency
> auditing — all dependency-free and CI-tested.
>
> **New here?**
> - ⭐ Star the repo if it's useful — it genuinely helps.
> - 🧰 Browse the [skills](../skills) and try one: `python skills/secret-scanner/engine.py .`
> - 🌱 Want to contribute? Check the [good first issues](GOOD_FIRST_ISSUES.md).
> - 💬 Have an idea for a new skill? Post it in **Ideas**.
>
> Tell us below: **what would you scan first?**

---

## Starter post 2 — 🗳️ Polls

**Title:** Which skill should we build next?

> Vote for the next addition:
> - [ ] `cors-auditor` — misconfigured CORS detection
> - [ ] `dockerfile-lint` — insecure Dockerfile patterns
> - [ ] `ssl-cert-check` — cert expiry / weak TLS
> - [ ] `iac-scan` — Terraform/K8s misconfigs
> - [ ] `sbom-gen` — generate a CycloneDX SBOM
>
> Comment if you want something not listed.

---

## Starter post 3 — 🛠️ Show and tell

**Title:** Did a skill catch something real? Show us 👀

> Found a committed key, a vulnerable dep, or a jailbreakable prompt?
> Share a (redacted!) screenshot of the output. Best finds get pinned.

---

## Starter post 4 — 💡 Ideas

**Title:** Wishlist: rules & checks you want

> Drop the secret types, SAST checks, advisories, or injection payloads you
> wish we detected. Upvote others. Anything with traction becomes a
> `good first issue`.

---

## Starter post 5 — 🙏 Q&A (pin)

**Title:** Install & usage FAQ

> **Q: How do I install the skills?**
> Copy `skills/*` into `.claude/skills/` (project) or `~/.claude/skills/`
> (global), then restart Claude Code.
>
> **Q: Do I need to install dependencies?**
> No — the engines are pure Python stdlib. `pytest` is only needed to run tests.
>
> **Q: Can I run them without Claude?**
> Yes, every engine is a standalone CLI with `--json` and exit codes.
>
> **Q: Network features?**
> `http-sec-audit <url>` and `dependency-check --online` need internet;
> everything else is fully offline.
>
> Ask anything else below.
