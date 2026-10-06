"""Time windows, baselines and severity of the detections (added after the director's review).

Mutation spot-checks showed that changing a detection window (spray 60 -> 180 min, BEC 24 h ->
1000 h, MFA success 60 min -> unlimited), dropping the per-user country baseline of DET-005 or
the "medium if no success" downgrade of DET-002 left every test green. Each test below kills
one of those mutations.
"""
import pytest

from conftest import write_jsonl
from m365audit.cli import detect_files


def _s(t, user, ip="203.0.113.5", result=50126, client="Browser", country="NL", **kw):
    ev = {"time": t, "userPrincipalName": user, "ipAddress": ip, "resultType": result,
          "clientAppUsed": client, "country": country}
    ev.update(kw)
    return ev


def _run(tmp_path, cfg, signins, audit=()):
    return detect_files(write_jsonl(tmp_path, list(signins), "s.jsonl"),
                        write_jsonl(tmp_path, list(audit), "a.jsonl"), cfg)["alerts"]


def _rules(alerts):
    return sorted(a["rule"] for a in alerts)


@pytest.mark.parametrize("step,expected", [(5, ["DET-001"]), (15, [])])
def test_spray_window_is_60_minutes(tmp_path, cfg, step, expected):
    # 10 users: every 5 min = 45 min burst (alert); every 15 min = 135 min, max 5 per hour
    ev = [_s(f"2026-09-24T{2 + (step * i) // 60:02d}:{(step * i) % 60:02d}:00Z", f"u{i}@x.ma")
          for i in range(10)]
    assert _rules(_run(tmp_path, cfg, ev)) == expected


def test_spray_ignores_mfa_failures(tmp_path, cfg):
    ev = [_s(f"2026-09-24T02:{i:02d}:00Z", f"u{i}@x.ma", result=500121) for i in range(10)]
    assert _rules(_run(tmp_path, cfg, ev)) == []


@pytest.mark.parametrize("success_after,severity", [(59, "high"), (61, "medium")])
def test_mfa_fatigue_success_window_and_severity(tmp_path, cfg, success_after, severity):
    ev = [_s(f"2026-09-25T10:{i:02d}:00Z", "g@x.ma", result=500121) for i in range(5)]
    last = 4
    ev.append(_s(f"2026-09-25T{10 + (last + success_after) // 60:02d}:"
                 f"{(last + success_after) % 60:02d}:00Z", "g@x.ma", result=0))
    alerts = _run(tmp_path, cfg, ev)
    assert _rules(alerts) == ["DET-002"] and alerts[0]["severity"] == severity


def _rule(t, user="f@agrisouss.ma", to="pirate@mail-externe.example"):
    return {"time": t, "workload": "Exchange", "operation": "New-InboxRule", "userId": user,
            "parameters": {"Name": ".", "ForwardTo": to}}


@pytest.mark.parametrize("rule_time,expected", [
    ("2026-09-26T07:05:00Z", ["DET-005"]),   # 15 min after the unusual sign-in
    ("2026-09-27T06:00:00Z", ["DET-005"]),   # 23 h 10 after
    ("2026-09-27T08:00:00Z", []),            # 25 h 10 after: outside the 24 h window
    ("2026-09-26T06:40:00Z", []),            # BEFORE the sign-in: not caused by it
])
def test_bec_window_is_24h_after_the_signin(tmp_path, cfg, rule_time, expected):
    s = [_s("2026-09-26T06:50:00Z", "f@agrisouss.ma", result=0, country="GB")]
    assert _rules(_run(tmp_path, cfg, s, [_rule(rule_time)])) == expected


def test_bec_country_already_seen_for_this_user_is_not_unusual(tmp_path, cfg):
    # GB first seen on the 20th (no rule within 24 h); the GB sign-in on the 26th is no longer
    # "new for this user", so the rule created after it does not raise DET-005.
    s = [_s("2026-09-20T09:00:00Z", "f@agrisouss.ma", result=0, country="GB"),
         _s("2026-09-26T06:50:00Z", "f@agrisouss.ma", result=0, country="GB")]
    assert _rules(_run(tmp_path, cfg, s, [_rule("2026-09-26T07:05:00Z")])) == []
