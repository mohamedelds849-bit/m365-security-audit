"""Detections (part B), scoring of the AgriSouss exports, secret refusal and CLI exit codes."""
import os

import pytest

from conftest import HARD, LOGS, QUICK, VULN, MINIMAL, write_json, write_jsonl
from m365audit.cli import audit_file, detect_files, main
from m365audit.model import SchemaError

SIGN_A, AUD_A = os.path.join(LOGS, "signins_attack.jsonl"), os.path.join(LOGS, "audit_attack.jsonl")
SIGN_B, AUD_B = os.path.join(LOGS, "signins_benign.jsonl"), os.path.join(LOGS, "audit_benign.jsonl")


def rules(report):
    return sorted(a["rule"] for a in report["alerts"])


def test_attack_logs_raise_one_alert_per_rule(cfg):
    r = detect_files(SIGN_A, AUD_A, cfg)
    assert rules(r) == [f"DET-00{i}" for i in range(1, 7)]
    sev = {a["rule"]: a["severity"] for a in r["alerts"]}
    assert sev["DET-005"] == "critical" and sev["DET-004"] == "medium"


def test_benign_logs_with_near_misses_raise_nothing(cfg):
    assert detect_files(SIGN_B, AUD_B, cfg)["alerts"] == []


def _s(t, user, ip="203.0.113.5", result=50126, client="Browser", country="NL", **kw):
    ev = {"time": t, "userPrincipalName": user, "ipAddress": ip, "resultType": result,
          "clientAppUsed": client, "country": country}
    ev.update(kw)
    return ev


@pytest.mark.parametrize("users,expected", [(9, []), (10, ["DET-001"])])
def test_spray_threshold(tmp_path, cfg, users, expected):
    ev = [_s(f"2026-09-24T02:{i:02d}:00Z", f"u{i}@x.ma") for i in range(users)]
    r = detect_files(write_jsonl(tmp_path, ev, "s.jsonl"), write_jsonl(tmp_path, [], "a.jsonl"), cfg)
    assert rules(r) == expected


@pytest.mark.parametrize("denials,expected", [(4, []), (5, ["DET-002"])])
def test_mfa_fatigue_threshold(tmp_path, cfg, denials, expected):
    ev = [_s(f"2026-09-25T23:{i:02d}:00Z", "g@x.ma", result=500121) for i in range(denials)]
    ev.append(_s("2026-09-25T23:40:00Z", "g@x.ma", result=0))
    r = detect_files(write_jsonl(tmp_path, ev, "s.jsonl"), write_jsonl(tmp_path, [], "a.jsonl"), cfg)
    assert rules(r) == expected


def test_failed_legacy_attempt_is_not_an_alert(tmp_path, cfg):
    ev = [_s("2026-09-24T02:00:00Z", "b@x.ma", client="IMAP4")]
    r = detect_files(write_jsonl(tmp_path, ev, "s.jsonl"), write_jsonl(tmp_path, [], "a.jsonl"), cfg)
    assert rules(r) == []


def test_internal_forwarding_after_unusual_signin_is_not_bec(tmp_path, cfg):
    s = [_s("2026-09-26T06:50:00Z", "f@agrisouss.ma", result=0, country="GB")]
    a = [{"time": "2026-09-26T07:05:00Z", "workload": "Exchange", "operation": "New-InboxRule",
          "userId": "f@agrisouss.ma", "parameters": {"ForwardTo": "compta@agrisouss.ma"}}]
    r = detect_files(write_jsonl(tmp_path, s, "s.jsonl"), write_jsonl(tmp_path, a, "a.jsonl"), cfg)
    assert rules(r) == []


def test_invalid_log_line_names_the_line(tmp_path, cfg):
    p = tmp_path / "s.jsonl"
    p.write_text('{"time": "2026-09-24T02:00:00Z"}\n', encoding="utf-8")
    with pytest.raises(SchemaError, match="s.jsonl:1"):
        detect_files(str(p), write_jsonl(tmp_path, [], "a.jsonl"), cfg)


@pytest.mark.parametrize("path,score,count", [(VULN, 80, 24), (QUICK, 48, 10), (HARD, 0, 0)])
def test_agrisouss_scores(cfg, path, score, count):
    r = audit_file(path, cfg)
    assert (r["score"]["global"], len(r["findings"])) == (score, count)


def test_export_with_secret_is_refused(tmp_path, cfg):
    data = dict(MINIMAL, applications=[{"displayName": "App", "appId": "a-1",
                                        "passwordCredentials": [{"hint": "abc"}]}])
    with pytest.raises(SchemaError, match="secret"):
        audit_file(write_json(tmp_path, data), cfg)


def test_cli_exit_codes(tmp_path):
    assert main(["audit", HARD, "--quiet", "--fail-on", "low"]) == 0
    assert main(["audit", VULN, "--quiet", "--fail-on", "critical"]) == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main(["audit", str(bad), "--quiet"]) == 2
    assert main(["detect", "--signins", SIGN_A, "--audit", AUD_A, "--quiet", "--fail-on", "critical"]) == 1
