# Contributing to Claude Security Skills

Thanks for helping grow this toolkit! Contributions of all sizes are welcome —
a single new detection rule is just as valuable as a whole new skill.

## Ways to contribute

- **Add a rule** to an existing skill (e.g. a new secret type, SAST check, or
  dependency advisory).
- **Add a whole new skill** (see the template below).
- **Reduce false positives / negatives** with a failing test + fix.
- **Improve docs** in a `SKILL.md` or this README.

## Ground rules

1. **No runtime dependencies.** Engines must run on the Python 3.9+ standard
   library only. (Dev/test tooling like `pytest` is fine.)
2. **Tests required.** Every behavior change ships with tests. Aim for a true
   positive *and* a true negative per new rule.
3. **Offline-first.** Core analysis must be testable without network access.
   Network features are opt-in behind an explicit flag (e.g. `--online`).
4. **Consistent UX.** Provide a `--json` output and use the standard exit codes:
   `0` = clean, `1` = findings, `2` = usage/error.
5. **Safety.** Never print full secrets — redact. Offensive tooling must be
   scoped to authorized targets and say so in its `SKILL.md`.

## Adding a new skill

Create `skills/<your-skill>/` with:

```
skills/your-skill/
├── SKILL.md            # front matter + instructions for Claude
├── your_engine.py      # stdlib-only implementation, with a main()/CLI
└── tests/
    └── test_your_engine.py
```

### `SKILL.md` template

```markdown
---
name: your-skill
description: >-
  One or two sentences describing what the skill does AND when Claude should
  use it. Include trigger phrases a user might say. This text is how Claude
  decides to invoke the skill, so be specific.
license: MIT
---

# Your Skill

## When to use this skill
- "Trigger phrase one"
- "Trigger phrase two"

## How to run it
\`\`\`bash
python skills/your-skill/your_engine.py <args> [--json]
\`\`\`

## Recommended workflow for Claude
1. ...
2. ...

## Limitations
...
```

### Engine conventions

- Expose a `main(argv=None) -> int` and guard with
  `if __name__ == "__main__": raise SystemExit(main())`.
- Keep the analysis core as pure functions (data in → findings out) so it can be
  unit-tested directly, separate from the CLI/IO layer.
- Use `@dataclass` finding objects with a `to_dict()` for clean JSON.

## Running the test suite

```bash
pip install pytest
pytest skills/ -q
```

CI runs the full suite on Python 3.9–3.12 across Linux/macOS/Windows. PRs must
be green to merge.

## Commit & PR style

- Keep PRs focused; one skill or one logical change at a time.
- Describe the threat the change addresses and include sample output.
- By contributing you agree your work is licensed under the project's MIT
  license.

Happy hacking — and thanks for making the toolkit better. 🛡️
