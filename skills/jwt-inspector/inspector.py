from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
from dataclasses import dataclass, asdict


def b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class DecodedJWT:
    header: dict
    payload: dict
    signature_b64: str
    signing_input: bytes


def decode(token: str) -> DecodedJWT:
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Not a well-formed JWT: expected 3 dot-separated parts, got "
            f"{len(parts)}.")
    h_b64, p_b64, s_b64 = parts
    try:
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"Could not decode header/payload: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("Header and payload must be JSON objects.")
    return DecodedJWT(header, payload, s_b64,
                      f"{h_b64}.{p_b64}".encode("ascii"))


@dataclass
class Issue:
    id: str
    severity: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


WEAK_ALGS = {"none", "hs256", "hs384", "hs512"}


def audit(jwt: DecodedJWT) -> list[Issue]:
    issues: list[Issue] = []
    alg = str(jwt.header.get("alg", "")).strip()
    alg_lower = alg.lower()

    if alg_lower == "none":
        issues.append(Issue("alg-none", "critical",
                            "alg=none: token is unsigned and trivially "
                            "forgeable if the server accepts it."))
    elif not alg:
        issues.append(Issue("alg-missing", "high",
                            "No 'alg' in header — ambiguous verification."))

    if "typ" not in jwt.header:
        issues.append(Issue("typ-missing", "low",
                            "Header has no 'typ' field."))

    if alg_lower.startswith("hs"):
        issues.append(Issue("alg-symmetric", "medium",
                            f"{alg} is symmetric (HMAC): the verification key "
                            "is the signing secret. Risk of HS/RS confusion "
                            "and brute-forceable weak secrets."))

    payload = jwt.payload
    now = int(time.time())

    if "exp" not in payload:
        issues.append(Issue("exp-missing", "high",
                            "No 'exp' claim: token never expires."))
    else:
        try:
            exp = int(payload["exp"])
            if exp < now:
                issues.append(Issue("exp-past", "info",
                                    f"Token expired at {_ts(exp)}."))
            elif exp - now > 60 * 60 * 24 * 365:
                issues.append(Issue("exp-far", "medium",
                                    "Token lifetime exceeds 1 year — overly "
                                    "long-lived."))
        except (TypeError, ValueError):
            issues.append(Issue("exp-malformed", "medium",
                                "'exp' is not a numeric timestamp."))

    if "iat" in payload:
        try:
            if int(payload["iat"]) > now + 300:
                issues.append(Issue("iat-future", "medium",
                                    "'iat' is in the future (clock skew or "
                                    "forged token)."))
        except (TypeError, ValueError):
            pass

    if "nbf" not in payload:
        issues.append(Issue("nbf-missing", "low",
                            "No 'nbf' (not-before) claim."))

    for claim in ("iss", "aud", "sub"):
        if claim not in payload:
            issues.append(Issue(f"{claim}-missing", "low",
                                f"No '{claim}' claim — weakens validation."))

    return issues


def _ts(epoch: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(epoch))


DEFAULT_WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "jwt", "token",
    "secretkey", "supersecret", "key", "your-256-bit-secret", "test",
    "qwerty", "letmein", "default", "root", "private", "s3cr3t",
]

_HASH_BY_ALG = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                "HS512": hashlib.sha512}


def crack_hmac_secret(jwt: DecodedJWT, candidates) -> str | None:
    alg = str(jwt.header.get("alg", "")).upper()
    hashfn = _HASH_BY_ALG.get(alg)
    if not hashfn:
        return None
    try:
        expected = b64url_decode(jwt.signature_b64)
    except Exception:
        return None
    for cand in candidates:
        key = cand.encode("utf-8") if isinstance(cand, str) else cand
        sig = hmac.new(key, jwt.signing_input, hashfn).digest()
        if hmac.compare_digest(sig, expected):
            return cand if isinstance(cand, str) else cand.decode("utf-8", "ignore")
    return None


def sign_hs256(header: dict, payload: dict, secret: str) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def inspect(token: str, secret_candidates=None) -> dict:
    jwt = decode(token)
    issues = audit(jwt)
    cracked = None
    if str(jwt.header.get("alg", "")).upper() in _HASH_BY_ALG:
        cands = list(secret_candidates) if secret_candidates else DEFAULT_WEAK_SECRETS
        cracked = crack_hmac_secret(jwt, cands)
        if cracked is not None:
            issues.append(Issue("weak-secret", "critical",
                                f"HMAC secret cracked from wordlist: '{cracked}'. "
                                "Anyone can forge valid tokens."))
    issues.sort(key=lambda i: SEV_RANK.get(i.severity, 9))
    return {
        "header": jwt.header,
        "payload": jwt.payload,
        "issues": [i.to_dict() for i in issues],
        "cracked_secret": cracked,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="jwt-inspector",
        description="Decode and audit a JWT; detect weak HMAC secrets.")
    p.add_argument("token", help="the JWT, or '-' to read from stdin")
    p.add_argument("--secret-list", help="wordlist file for HMAC cracking")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args(argv)

    token = sys.stdin.read() if args.token == "-" else args.token
    cands = None
    if args.secret_list:
        try:
            with open(args.secret_list, "r", encoding="utf-8", errors="ignore") as fh:
                cands = [ln.strip() for ln in fh if ln.strip()]
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    try:
        result = inspect(token, cands)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("== Header ==");  print(json.dumps(result["header"], indent=2))
        print("\n== Payload ==");  print(json.dumps(result["payload"], indent=2))
        print("\n== Findings ==")
        if not result["issues"]:
            print("  No issues found. [OK]")
        for i in result["issues"]:
            print(f"  [{i['severity'].upper():<8}] {i['id']}: {i['message']}")

    high = any(i["severity"] in ("critical", "high") for i in result["issues"])
    return 1 if high else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
