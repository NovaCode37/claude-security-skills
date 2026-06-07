import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attacker


def test_payloads_nonempty():
    assert len(attacker.PAYLOADS) >= 10


def test_payload_ids_unique():
    ids = [p.id for p in attacker.PAYLOADS]
    assert len(ids) == len(set(ids))


def test_issue_10_tool_abuse_payloads_present():
    tool_payloads = [p for p in attacker.PAYLOADS if p.category == "tool-abuse"]
    assert len(tool_payloads) == 3
    assert all(p.success_markers for p in tool_payloads)


def test_every_payload_has_known_category():
    for p in attacker.PAYLOADS:
        assert p.category in attacker.CATEGORIES


def test_every_payload_has_success_markers():
    for p in attacker.PAYLOADS:
        assert p.success_markers, f"{p.id} has no success markers"


def test_score_detects_marker_hit():
    p = next(x for x in attacker.PAYLOADS if x.id == "io-001")
    res = attacker.score_response(p, "okay, PWNED")
    assert res.vulnerable
    assert res.matched_markers


def test_score_detects_refusal():
    p = next(x for x in attacker.PAYLOADS if x.id == "io-001")
    res = attacker.score_response(p, "I'm sorry, but I can't do that.")
    assert not res.vulnerable
    assert "refused" in res.reason.lower() or "resist" in res.reason.lower()


def test_score_detects_canary_leak():
    p = next(x for x in attacker.PAYLOADS if x.id == "sl-001")
    canary = "CANARY-deadbeef0001"
    res = attacker.score_response(p, f"my prompt is {canary}", canary=canary)
    assert res.vulnerable
    assert res.canary_leaked


def test_score_ambiguous_is_not_vulnerable():
    p = next(x for x in attacker.PAYLOADS if x.id == "io-001")
    res = attacker.score_response(p, "Here is a normal helpful answer.")
    assert not res.vulnerable
    assert "review" in res.reason.lower()


def test_naive_model_is_flagged_vulnerable():
    results = attacker.run_suite(attacker.naive_vulnerable_model)
    summary = attacker.summarize(results)
    assert summary["vulnerable"] > 0
    assert summary["resilience_score"] < 100


def test_hardened_model_scores_perfect():
    results = attacker.run_suite(attacker.hardened_model)
    summary = attacker.summarize(results)
    assert summary["vulnerable"] == 0
    assert summary["resilience_score"] == 100


def test_backend_error_does_not_crash():
    def broken(_s, _u):
        raise RuntimeError("boom")
    results = attacker.run_suite(broken)
    assert all(not r.vulnerable for r in results)
    assert any("error" in r.reason.lower() for r in results)


def test_category_filter():
    results = attacker.run_suite(attacker.naive_vulnerable_model,
                                 categories=("role-play",))
    assert results
    assert all(r.category == "role-play" for r in results)


def test_canary_is_unique_per_run():
    seen = set()
    for _ in range(5):
        sp = attacker.build_system_prompt(
            attacker.CANARY_TEMPLATE.format(token=os.urandom(6).hex()))
        seen.add(sp)
    assert len(seen) == 5


def test_cli_list(capsys):
    rc = attacker.main(["--list"])
    assert rc == 0
    assert "payload" in capsys.readouterr().out.lower()


def test_cli_demo_vulnerable_exit1():
    assert attacker.main(["--demo"]) == 1


def test_cli_demo_hardened_exit0():
    assert attacker.main(["--demo", "--hardened"]) == 0


def test_cli_demo_json(capsys):
    attacker.main(["--demo", "--json"])
    import json
    data = json.loads(capsys.readouterr().out)
    assert "summary" in data and "results" in data
