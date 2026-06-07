from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


ADVISORIES = {
    "pypi": {
        "flask": [("<0.12.3", "CVE-2018-1000656", "high",
                   "Flask < 0.12.3 DoS via crafted JSON.")],
        "django": [("<2.2.28", "CVE-2022-28346", "critical",
                    "Django SQL injection via QuerySet.annotate (<2.2.28).")],
        "requests": [("<2.20.0", "CVE-2018-18074", "high",
                      "requests < 2.20.0 leaks Authorization on redirect.")],
        "pyyaml": [("<5.4", "CVE-2020-14343", "critical",
                    "PyYAML < 5.4 arbitrary code execution via full_load.")],
        "jinja2": [("<2.11.3", "CVE-2020-28493", "medium",
                    "Jinja2 < 2.11.3 ReDoS in urlize filter.")],
        "urllib3": [("<1.26.5", "CVE-2021-33503", "high",
                     "urllib3 < 1.26.5 ReDoS via crafted URL authority.")],
        "cryptography": [("<3.3.2", "CVE-2020-36242", "high",
                          "cryptography < 3.3.2 buffer overflow in Fernet.")],
    },
    "npm": {
        "lodash": [("<4.17.21", "CVE-2021-23337", "high",
                    "lodash < 4.17.21 command injection via template.")],
        "minimist": [("<1.2.6", "CVE-2021-44906", "critical",
                      "minimist < 1.2.6 prototype pollution.")],
        "axios": [("<0.21.2", "CVE-2021-3749", "high",
                   "axios < 0.21.2 ReDoS via trim regex.")],
        "node-fetch": [("<2.6.7", "CVE-2022-0235", "medium",
                        "node-fetch < 2.6.7 leaks cookies/Authorization on redirect.")],
    },
}


@dataclass
class Finding:
    ecosystem: str
    package: str
    version: str
    id: str
    severity: str
    summary: str

    def to_dict(self) -> dict:
        return asdict(self)


def _norm(v: str) -> tuple:
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums) if nums else (0,)


def _cmp(a: str, b: str) -> int:
    ta, tb = _norm(a), _norm(b)
    length = max(len(ta), len(tb))
    ta += (0,) * (length - len(ta))
    tb += (0,) * (length - len(tb))
    return (ta > tb) - (ta < tb)


def version_matches(version: str, spec: str) -> bool:
    m = re.match(r"\s*(<=|>=|==|<|>)\s*(.+)\s*$", spec)
    if not m:
        return False
    op, target = m.group(1), m.group(2).strip()
    c = _cmp(version, target)
    return {
        "<": c < 0, "<=": c <= 0, "==": c == 0,
        ">": c > 0, ">=": c >= 0,
    }[op]


@dataclass
class Dep:
    ecosystem: str
    name: str
    version: str | None
    raw: str
    pinned: bool


def parse_requirements(text: str) -> list[Dep]:
    deps: list[Dep] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<|!=)?\s*([^\s;,]+)?",
                     line)
        if not m:
            continue
        name = m.group(1).lower()
        op, ver = m.group(2), m.group(3)
        pinned = op == "==" and bool(ver)
        deps.append(Dep("pypi", name, ver if pinned else (ver if op else None),
                        line, pinned))
    return deps


def parse_package_json(text: str) -> list[Dep]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps: list[Dep] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            pinned = bool(re.match(r"^\d+\.\d+\.\d+", spec)) and not any(
                c in spec for c in "^~*x ><||")
            ver = re.sub(r"^[\^~>=<\s]+", "", spec)
            ver = ver if re.match(r"^\d", ver) else None
            deps.append(Dep("npm", name.lower(), ver, f"{name}: {spec}", pinned))
    return deps


def check_offline(deps: list[Dep]) -> list[Finding]:
    findings: list[Finding] = []
    for dep in deps:
        if not dep.version:
            continue
        eco_db = ADVISORIES.get(dep.ecosystem, {})
        for spec, cve, sev, summary in eco_db.get(dep.name, []):
            if version_matches(dep.version, spec):
                findings.append(Finding(dep.ecosystem, dep.name, dep.version,
                                        cve, sev, summary))
    findings.sort(key=lambda f: SEV_RANK.get(f.severity, 9))
    return findings


def check_online_osv(deps: list[Dep], timeout: float = 10.0) -> list[Finding]:
    import urllib.request

    eco_map = {"pypi": "PyPI", "npm": "npm"}
    findings: list[Finding] = []
    for dep in deps:
        if not dep.version:
            continue
        body = json.dumps({
            "version": dep.version,
            "package": {"name": dep.name, "ecosystem": eco_map[dep.ecosystem]},
        }).encode()
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query", data=body,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
        except Exception:
            continue
        for vuln in data.get("vulns", []):
            sev = _osv_severity(vuln)
            findings.append(Finding(dep.ecosystem, dep.name, dep.version,
                                    vuln.get("id", "OSV"), sev,
                                    (vuln.get("summary") or "")[:200]))
    findings.sort(key=lambda f: SEV_RANK.get(f.severity, 9))
    return findings


def _osv_severity(vuln: dict) -> str:
    db = (vuln.get("database_specific") or {})
    sev = str(db.get("severity", "")).lower()
    if sev in SEV_RANK:
        return sev
    return "medium"


def unpinned_warnings(deps: list[Dep]) -> list[Finding]:
    out: list[Finding] = []
    for dep in deps:
        if not dep.pinned:
            out.append(Finding(dep.ecosystem, dep.name, dep.version or "*",
                               "unpinned", "low",
                               "Dependency is not pinned to an exact version "
                               "— non-reproducible builds and supply-chain risk."))
    return out


def parse_file(path: str) -> list[Dep]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        text = fh.read()
    base = os.path.basename(path).lower()
    if base == "package.json":
        return parse_package_json(text)
    if base.endswith(".txt") or "requirements" in base:
        return parse_requirements(text)
    return parse_requirements(text)


def discover(path: str) -> list[str]:
    if os.path.isfile(path):
        return [path]
    found = []
    for name in ("requirements.txt", "package.json"):
        candidate = os.path.join(path, name)
        if os.path.isfile(candidate):
            found.append(candidate)
    return found


def run(path: str, online: bool = False, show_unpinned: bool = True) -> dict:
    files = discover(path)
    deps: list[Dep] = []
    for f in files:
        deps.extend(parse_file(f))
    findings = check_offline(deps)
    if online:
        findings.extend(check_online_osv(deps))
    warnings = unpinned_warnings(deps) if show_unpinned else []
    return {
        "files": files,
        "dependency_count": len(deps),
        "vulnerabilities": [f.to_dict() for f in findings],
        "unpinned": [w.to_dict() for w in warnings],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="dependency-check",
        description="Check dependencies for known vulns and risky pinning.")
    p.add_argument("path", help="requirements.txt, package.json, or a directory")
    p.add_argument("--online", action="store_true",
                   help="also query the OSV.dev advisory API (network)")
    p.add_argument("--no-unpinned", action="store_true",
                   help="suppress unpinned-dependency warnings")
    p.add_argument("--json", action="store_true", help="emit JSON")
    args = p.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    result = run(args.path, online=args.online,
                 show_unpinned=not args.no_unpinned)

    if not result["files"]:
        print("error: no requirements.txt or package.json found.",
              file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        vulns = result["vulnerabilities"]
        print(f"[dependency-check] scanned {result['dependency_count']} "
              f"dependencies from {len(result['files'])} file(s)\n")
        if vulns:
            print(f"Known vulnerabilities ({len(vulns)}):")
            for v in vulns:
                print(f"  [{v['severity'].upper():<8}] {v['package']} "
                      f"{v['version']}  {v['id']}: {v['summary']}")
        else:
            print("No known vulnerabilities in the offline DB. [OK]")
        if result["unpinned"]:
            print(f"\nUnpinned dependencies ({len(result['unpinned'])}):")
            for w in result["unpinned"]:
                print(f"  - {w['package']} ({w['version']})")

    return 1 if result["vulnerabilities"] else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
