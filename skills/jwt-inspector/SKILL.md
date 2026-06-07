---
name: jwt-inspector
description: >-
  Decode and security-audit a JSON Web Token — flag alg=none, missing/excessive
  expiry, symmetric-alg confusion risk, missing claims — and attempt an offline
  HMAC secret crack against a wordlist to detect weak signing keys. Use when the
  user asks to "decode this JWT", "is this token secure?", "audit a JWT", or
  "check if this token uses a weak secret".
license: MIT
---

# JWT Inspector

Decode and audit JSON Web Tokens with **no third-party dependencies**. It
splits the token, decodes header + payload, evaluates them against a set of
security checks, and (for HMAC tokens) tries a fast offline crack of the
signing secret against a wordlist.

## When to use this skill

- "Decode / inspect this JWT."
- "Is this token configured securely?"
- "Does this JWT use a weak/guessable secret?"
- Auditing auth tokens during a security review.

## Checks performed

- **alg=none** (critical) — unsigned, forgeable token.
- **Symmetric alg (HS*)** — HMAC verification key == signing secret; HS/RS
  confusion and brute-force risk.
- **Missing `exp`** / token never expires; **excessively long** lifetime.
- **`iat` in the future**, missing `nbf`, missing `iss`/`aud`/`sub`.
- **Weak HMAC secret** (critical) — cracked from a built-in or supplied wordlist.

## How to run it

```bash
# Decode + audit
python skills/jwt-inspector/inspector.py "<token>"

# Read token from stdin
echo "<token>" | python skills/jwt-inspector/inspector.py -

# Try cracking the HMAC secret with a custom wordlist
python skills/jwt-inspector/inspector.py "<token>" --secret-list rockyou.txt

# JSON output
python skills/jwt-inspector/inspector.py "<token>" --json
```

**Exit codes:** `0` no high-severity issues · `1` high/critical issue found ·
`2` malformed input.

## Recommended workflow for Claude

1. Run the inspector and read the decoded payload to understand the token.
2. Report findings ordered by severity; explain the impact of each.
3. If a secret was cracked, stress that the key is compromised — rotate it and
   move to an asymmetric algorithm (RS256/ES256) where feasible.
4. Never treat a decoded payload as trusted: decoding ≠ verifying. Remind the
   user that signature verification with the correct key is what matters.

## Note

Cracking only runs for HMAC algorithms and only against the provided
wordlist — it is a weak-key *detector*, not a brute-forcer. Only inspect
tokens you are authorized to handle.
