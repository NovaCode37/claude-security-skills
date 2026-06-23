from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

PROBE_ORIGIN = "https://cors-probe.invalid"


@dataclass
class Finding:
    id: str
    severity: str
    message: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


def _lower(headers: dict) -> dict:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def audit_cors(headers: dict, sent_origin: str | None = None) -> list:
    h = _lower(headers)
    out: list = []
    if "access-control-allow-origin" not in h:
        return out
    acao = h["access-control-allow-origin"].strip()
    acac = h.get("access-control-allow-credentials", "").strip().lower() == "true"
    acam = h.get("access-control-allow-methods", "")

    if acao == "*":
        if acac:
            out.append(Finding(
                "cors-wildcard-credentials", "critical",
                "Access-Control-Allow-Origin is '*' together with "
                "Allow-Credentials: true.",
                "Never combine a wildcard origin with credentials; echo a "
                "vetted origin from an allowlist instead."))
        else:
            out.append(Finding(
                "cors-wildcard", "medium",
                "Access-Control-Allow-Origin is '*' — any site can read "
                "responses.",
                "Restrict to an explicit allowlist of trusted origins."))
    elif acao.lower() == "null":
        out.append(Finding(
            "cors-null-origin", "critical" if acac else "high",
            "Access-Control-Allow-Origin allows 'null', reachable from sandboxed "
            "iframes and local files.",
            "Never allow the 'null' origin; use explicit https origins."))
    elif sent_origin and acao == sent_origin:
        out.append(Finding(
            "cors-reflected-origin", "critical" if acac else "high",
            f"The server reflects an arbitrary Origin ({sent_origin}) back in "
            "Access-Control-Allow-Origin.",
            "Validate Origin against an allowlist; do not echo it blindly."))

    if acac and acao == "*":
        pass
    elif acac and acao not in ("", "*") and acao.lower() != "null" \
            and not (sent_origin and acao == sent_origin):
        out.append(Finding(
            "cors-credentials-enabled", "info",
            f"Credentialed CORS is enabled for origin '{acao}'.",
            "Confirm this origin is fully trusted; credentials expose "
            "authenticated data."))

    if "*" in [m.strip() for m in acam.split(",")]:
        out.append(Finding(
            "cors-methods-wildcard", "low",
            "Access-Control-Allow-Methods is '*'.",
            "List only the methods the endpoint actually needs."))

    out.sort(key=lambda f: SEV_RANK.get(f.severity, 9))
    return out


def fetch_cors(url: str, origin: str = PROBE_ORIGIN, timeout: float = 10.0):
    import urllib.request

    req = urllib.request.Request(
        url, method="GET",
        headers={"Origin": origin, "User-Agent": "cors-auditor/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return dict(resp.headers.items())


def parse_raw_headers(text: str) -> dict:
    headers: dict = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("HTTP/") or ":" not in line:
            continue
        key, val = line.split(":", 1)
        headers[key.strip()] = val.strip()
    return headers


def render(target: str, findings: list) -> str:
    if not findings:
        return f"[cors-auditor] {target}: no CORS misconfigurations found. [OK]"
    out = [f"[cors-auditor] {target}: {len(findings)} finding(s):\n"]
    for f in findings:
        out.append(f"  [{f.severity.upper():<8}] {f.id}")
        out.append(f"             {f.message}")
        out.append(f"             fix: {f.recommendation}")
    return "\n".join(out)


def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="cors-auditor",
        description="Audit a site's CORS configuration for misconfigurations.")
    p.add_argument("url", nargs="?", help="URL to probe (https://...)")
    p.add_argument("--origin", default=PROBE_ORIGIN,
                   help="Origin header to send when probing reflection")
    p.add_argument("--headers-file",
                   help="offline: file with a raw HTTP response header block")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args(argv)

    if args.headers_file:
        try:
            with open(args.headers_file, "r", encoding="utf-8",
                      errors="ignore") as fh:
                headers = parse_raw_headers(fh.read())
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        target = args.headers_file
        sent_origin = args.origin if args.origin != PROBE_ORIGIN else None
    elif args.url:
        try:
            headers = fetch_cors(args.url, args.origin)
        except Exception as exc:
            print(f"error: could not fetch {args.url}: {exc}", file=sys.stderr)
            return 2
        target = args.url
        sent_origin = args.origin
    else:
        p.error("provide a URL or --headers-file")
        return 2

    findings = audit_cors(headers, sent_origin=sent_origin)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print(render(target, findings))
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
