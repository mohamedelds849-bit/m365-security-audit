"""Regression tests added during the security review (REVIEW.md): HTML escaping, the full
legacy client list, ATT&CK mapping of M365-COL-002 and static safety of the export script."""
import copy
import os
import re

import pytest

from conftest import MINIMAL, ROOT, write_json, write_jsonl
from m365audit.cli import audit_file, detect_files
from m365audit.detect.report import render_html as render_detect_html
from m365audit.engine import all_checks
from m365audit.report import render_html

XSS = '<script>alert(1)</script>"><img src=x onerror=alert(1)>'
PS1 = os.path.join(ROOT, "tools", "Export-M365Config.ps1")


def test_audit_html_escapes_export_values(tmp_path, cfg):
    data = copy.deepcopy(MINIMAL)
    data["applications"] = [{"displayName": XSS, "appId": "a-1", "publisherVerified": False,
                             "permissions": [{"name": "Mail.ReadWrite", "type": "Application"}]}]
    report = audit_file(write_json(tmp_path, data), cfg)
    assert any(XSS in ev for f in report["findings"] for ev in f["evidence"])
    page = render_html(report)
    assert "<script>alert" not in page and "<img src=x" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "default-src 'none'" in page  # strict CSP, no script allowed


def test_detection_html_escapes_log_values(tmp_path, cfg):
    s = [{"time": "2026-09-24T02:00:00Z", "userPrincipalName": XSS + "@x.ma",
          "ipAddress": "203.0.113.9", "resultType": 0, "clientAppUsed": "IMAP4"}]
    report = detect_files(write_jsonl(tmp_path, s, "s.jsonl"), write_jsonl(tmp_path, [], "a.jsonl"), cfg)
    assert [a["rule"] for a in report["alerts"]] == ["DET-003"]
    page = render_detect_html(report)
    assert "<script>alert" not in page and "<img src=x" not in page


@pytest.mark.parametrize("client", ["Outlook Anywhere (RPC over HTTP)", "Exchange Online PowerShell",
                                    "Reporting Web Services", "Outlook Service", "Authenticated SMTP"])
def test_every_documented_legacy_client_is_detected(tmp_path, cfg, client):
    s = [{"time": "2026-09-24T02:00:00Z", "userPrincipalName": "b@x.ma", "ipAddress": "203.0.113.9",
          "resultType": 0, "clientAppUsed": client}]
    report = detect_files(write_jsonl(tmp_path, s, "s.jsonl"), write_jsonl(tmp_path, [], "a.jsonl"), cfg)
    assert [a["rule"] for a in report["alerts"]] == ["DET-003"]


@pytest.mark.parametrize("client", ["Browser", "Mobile Apps and Desktop clients"])
def test_modern_clients_are_not_legacy(tmp_path, cfg, client):
    s = [{"time": "2026-09-24T02:00:00Z", "userPrincipalName": "b@x.ma", "ipAddress": "203.0.113.9",
          "resultType": 0, "clientAppUsed": client}]
    report = detect_files(write_jsonl(tmp_path, s, "s.jsonl"), write_jsonl(tmp_path, [], "a.jsonl"), cfg)
    assert report["alerts"] == []


def test_email_auth_check_maps_to_email_spoofing_not_internal_spearphishing():
    check = next(c for c in all_checks() if c.id == "M365-COL-002")
    ids = {m[0] for m in check.mitre}
    assert "T1684.002" in ids and "T1534" not in ids


def test_export_script_is_read_only():
    src = open(PS1, encoding="utf-8").read()
    code = re.sub(r"<#.*?#>", "", src, flags=re.S)           # drop the comment-based help
    code = "\n".join(line.split("#", 1)[0] for line in code.splitlines())
    verbs = set(re.findall(r"\b(New|Set|Update|Remove|Add|Grant|Revoke|Invoke|Enable|Disable)-(\w+)", code))
    local_only = {("Set", "StrictMode"), ("Set", "Content")}  # Add-Perm is a local function
    assert {v for v in verbs if v not in local_only and v != ("Add", "Perm")} == set()
    for secret in ("PasswordCredentials", "KeyCredentials", "Get-MgApplication "):
        assert secret not in code
    assert "AUTHORIZATION WARNING" in src


def test_export_script_guest_role_ids_match_microsoft_learn():
    src = open(PS1, encoding="utf-8").read()
    # values from learn.microsoft.com "Restrict guest user access permissions"
    assert "'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'sameAsMember'" in src
    assert "'10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'limited'" in src
    assert "'2af84b1e-32c8-42b7-82bc-daa82404023b' = 'restricted'" in src
