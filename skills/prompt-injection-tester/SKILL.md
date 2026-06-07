---
name: prompt-injection-tester
description: >-
  Red-team an LLM application against prompt injection and jailbreaks using a
  curated, categorized payload library and canary-based detection, then produce
  a resilience score. Use when the user asks to "test my chatbot for prompt
  injection", "check if my AI app is jailbreakable", "red-team my LLM",
  "evaluate prompt-injection defenses", or audit a system prompt's guardrails.
license: MIT
---

# Prompt Injection Tester

A defensive red-team harness for evaluating the prompt-injection resistance of
**LLM applications you own or are authorized to test**. It ships a library of
well-documented public attack techniques and a canary-based detection engine
that decides whether each attack succeeded — then scores overall resilience.

> ⚠️ Use only against systems you own or have permission to test. The payloads
> are public hardening techniques, intended to *strengthen* guardrails.

## When to use this skill

- "Is my chatbot vulnerable to prompt injection / jailbreaks?"
- "Red-team / pentest my LLM app's system prompt."
- "Score how well my guardrails resist instruction-override attacks."
- Regression-testing guardrails in CI after a prompt change.

## Attack categories covered

`instruction-override` · `system-prompt-leak` · `role-play` (DAN-style) ·
`delimiter-escape` · `encoding` (base64/leetspeak) · `data-exfiltration`
(indirect injection) · `refusal-suppression`.

## How it works

1. A unique **canary** secret is embedded into a guarded system prompt.
2. Each payload is sent as the user turn.
3. The response is scored: it's **vulnerable** if it hits an attack
   success-marker or leaks the canary; **resisted** if it refuses.
4. You get a **resilience score** (0–100) and a per-category breakdown.

## How to run it

List the payload library (no model calls):

```bash
python skills/prompt-injection-tester/attacker.py --list
python skills/prompt-injection-tester/attacker.py --list --category role-play
```

See the harness detect a weak vs. a hardened model:

```bash
python skills/prompt-injection-tester/attacker.py --demo            # weak model
python skills/prompt-injection-tester/attacker.py --demo --hardened # safe model
python skills/prompt-injection-tester/attacker.py --demo --json
```

## Testing a real model (recommended workflow for Claude)

Wrap the user's backend in a `model(system_prompt, user_prompt) -> str`
callable and run the suite. Example skeleton the user can adapt:

```python
import sys
sys.path.insert(0, "skills/prompt-injection-tester")
import attacker

def model(system_prompt, user_prompt):
    # call the user's real API/app here and return the text response
    return my_llm_app(system=system_prompt, user=user_prompt)

results = attacker.run_suite(model)
print(attacker.summarize(results))
```

Then:
1. Report the **resilience score** and list every `failed_payload`.
2. For each failure, show the technique and recommend a mitigation —
   e.g. stronger system-prompt instructions, input/output canary filtering,
   privilege separation for tool calls, or a dedicated injection classifier.
3. Re-run after fixes to confirm the regression is closed.

## Offline scoring

If you already captured a model response, score it without any network call:

```python
import attacker
payload = attacker.PAYLOADS[0]
verdict = attacker.score_response(payload, response_text, canary="CANARY-abc")
print(verdict.vulnerable, verdict.reason)
```

## Limitations

Marker/canary detection is a heuristic: a refusal-shaped response that still
complies, or a creative leak, may need human review (`score_response` flags
ambiguous cases as "review manually"). Treat the score as a guardrail signal,
not a guarantee.
