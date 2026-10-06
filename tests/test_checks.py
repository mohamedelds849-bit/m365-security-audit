"""Per-check tests.

1. every check fires on the vulnerable AgriSouss export and is silent on the hardened one;
2. starting from a minimal clean export, ONE targeted change makes exactly the expected
   check(s) fire (one check, except the umbrella check M365-CA-001);
3. boundaries of every numeric threshold and licence-dependent behaviour.
"""
import pytest

from conftest import ADM, BG1, BG2, U1, _ca, _u, fired
from m365audit.engine import all_checks

ALL_IDS = [c.id for c in all_checks()]


def test_24_checks_registered():
    assert len(ALL_IDS) == 24 and len(set(ALL_IDS)) == 24


def test_minimal_export_is_clean(minimal, cfg):
    assert fired(minimal, cfg) == {}


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_fires_on_vulnerable(check_id, vuln, cfg):
    f = fired(vuln, cfg)
    assert check_id in f, f"{check_id} devrait se déclencher sur l'export vulnérable"
    assert f[check_id].evidence, "un constat doit toujours avoir des preuves"


@pytest.mark.parametrize("check_id", ALL_IDS)
def test_silent_on_hardened(check_id, hard, cfg):
    assert check_id not in fired(hard, cfg)


def _pol(d, name):
    return next(p for p in d["conditionalAccessPolicies"] if p["displayName"] == name)


def _drop_pol(d, name):
    d["conditionalAccessPolicies"] = [p for p in d["conditionalAccessPolicies"] if p["displayName"] != name]


def _user(d, upn):
    return next(u for u in d["users"] if u["userPrincipalName"] == upn)


def _ra(d, upn):
    return next(a for a in d["directoryRoleAssignments"] if a["principal"] == upn)


def _add_admin(d, upn, role="Global Administrator"):
    d["users"].append(_u(upn))
    d["directoryRoleAssignments"].append({"roleName": role, "principal": upn, "assignmentType": "eligible"})


def _disable_all_ca(d):
    for p in d["conditionalAccessPolicies"]:
        p["state"] = "disabled"


def _add_app(d, **kw):
    app = {"displayName": "Outil X", "appId": "app-x", "publisherVerified": False,
           "permissions": [{"name": "Mail.ReadWrite", "type": "Delegated"}]}
    app.update(kw)
    d["applications"].append(app)


# mutation -> (function, set of checks expected to fire)
MUTATIONS = {
    "M365-CA-001": (_disable_all_ca, {"M365-CA-001", "M365-CA-002", "M365-CA-003",
                                      "M365-CA-004", "M365-CA-005"}),
    "M365-CA-002": (lambda d: _drop_pol(d, "CA03 mfa all"), None),
    "M365-CA-003": (lambda d: (_drop_pol(d, "CA01 admins"),
                               _pol(d, "CA03 mfa all")["excludeUsers"].append(ADM)), None),
    "M365-CA-004": (lambda d: _drop_pol(d, "CA02 legacy"), None),
    "M365-CA-005": (lambda d: _drop_pol(d, "CA04 sign-in risk"), None),
    "M365-CA-006": (lambda d: _pol(d, "CA03 mfa all")["excludeUsers"].extend(
        ["x1@test.ma", "x2@test.ma", "x3@test.ma"]), None),
    "M365-PRIV-001": (lambda d: (_add_admin(d, f"adm.b@{BG1.split('@')[1]}"),
                                 _add_admin(d, f"adm.c@{BG1.split('@')[1]}")), None),
    "M365-PRIV-002": (lambda d: _ra(d, ADM).update(assignmentType="active"), None),
    "M365-PRIV-003": (lambda d: _user(d, ADM).update(hasMailbox=True), None),
    "M365-PRIV-004": (lambda d: d["monitoring"].update(breakGlassSignInAlert=False), None),
    "M365-ACC-001": (lambda d: d["authorizationPolicy"].update(guestUserAccess="sameAsMember"), None),
    "M365-ACC-002": (lambda d: _user(d, U1).update(lastSignInDateTime="2026-05-01T00:00:00Z"), None),
    "M365-ACC-003": (lambda d: d["sspr"].update(methodsRequired=1), None),
    "M365-ACC-004": (lambda d: d["passwordPolicy"].update(expirationDays=90), None),
    "M365-ACC-005": (lambda d: _user(d, U1).update(authMethods=["sms"]), None),
    "M365-APP-001": (lambda d: d["authorizationPolicy"].update(userConsent="allowAll"), None),
    "M365-APP-002": (_add_app, None),
    "M365-APP-003": (lambda d: d["authorizationPolicy"].update(usersCanRegisterApps=True), None),
    "M365-LOG-001": (lambda d: d["audit"].update(unifiedAuditLogEnabled=False), None),
    "M365-LOG-002": (lambda d: d["audit"].update(auditBypassMailboxes=["scan@test.ma"]), None),
    "M365-COL-001": (lambda d: d["exchange"].update(autoForwardingMode="On"), None),
    "M365-COL-002": (lambda d: d["domains"][1].update(dmarcPolicy="none"), None),
    "M365-COL-003": (lambda d: d["teams"].update(externalAccess="allowAll"), None),
    "M365-COL-004": (lambda d: d["sharepoint"].update(sharingCapability="ExternalUserAndGuestSharing"), None),
}


def test_every_check_has_a_mutation():
    assert set(MUTATIONS) == set(ALL_IDS)


@pytest.mark.parametrize("check_id", sorted(MUTATIONS))
def test_single_mutation_fires_expected_checks(check_id, minimal, cfg):
    fn, expected = MUTATIONS[check_id]
    fn(minimal)
    assert set(fired(minimal, cfg)) == (expected or {check_id})


# ------------------------------------------------------------------ boundaries
def test_global_admin_boundaries(minimal, cfg):
    _add_admin(minimal, "adm.b@test.onmicrosoft.com")          # 4 GA (bg1, bg2, adm.a, adm.b)
    assert "M365-PRIV-001" not in fired(minimal, cfg)
    _add_admin(minimal, "adm.c@test.onmicrosoft.com")          # 5 GA
    assert "M365-PRIV-001" in fired(minimal, cfg)


def test_too_few_global_admins(minimal, cfg):
    minimal["directoryRoleAssignments"] = [{"roleName": "Global Administrator", "principal": BG1}]
    f = fired(minimal, cfg)
    assert "M365-PRIV-001" in f and "1 Global Administrator" in f["M365-PRIV-001"].evidence[0]


def test_eligible_global_admins_are_counted(minimal, cfg):
    for i in range(3):
        _add_admin(minimal, f"elig{i}@test.onmicrosoft.com")
    assert "M365-PRIV-001" in fired(minimal, cfg)


def test_disabled_admin_not_counted(minimal, cfg):
    for i in range(2):
        _add_admin(minimal, f"old{i}@test.onmicrosoft.com")
        _user(minimal, f"old{i}@test.onmicrosoft.com")["accountEnabled"] = False
    assert "M365-PRIV-001" not in fired(minimal, cfg)


@pytest.mark.parametrize("days,fires", [(90, False), (91, True)])
def test_stale_boundary(minimal, cfg, days, fires):
    from datetime import datetime, timedelta, timezone
    last = datetime(2026, 9, 30, 8, tzinfo=timezone.utc) - timedelta(days=days)
    _user(minimal, U1)["lastSignInDateTime"] = last.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert ("M365-ACC-002" in fired(minimal, cfg)) is fires


def test_never_signed_in_recent_account_not_stale(minimal, cfg):
    _user(minimal, U1).update(lastSignInDateTime=None, createdDateTime="2026-09-01T00:00:00Z")
    assert "M365-ACC-002" not in fired(minimal, cfg)
    _user(minimal, U1).update(createdDateTime="2026-01-01T00:00:00Z")
    assert "M365-ACC-002" in fired(minimal, cfg)


def test_break_glass_never_reported_stale(minimal, cfg):
    _user(minimal, BG1)["lastSignInDateTime"] = "2024-01-01T00:00:00Z"
    assert "M365-ACC-002" not in fired(minimal, cfg)


def test_disabled_stale_account_ignored(minimal, cfg):
    _user(minimal, U1).update(lastSignInDateTime="2025-01-01T00:00:00Z", accountEnabled=False)
    assert "M365-ACC-002" not in fired(minimal, cfg)


@pytest.mark.parametrize("excluded,fires", [(2, False), (3, True)])
def test_ca_exclusion_boundary(minimal, cfg, excluded, fires):
    _pol(minimal, "CA03 mfa all")["excludeUsers"].extend(f"x{i}@test.ma" for i in range(excluded))
    assert ("M365-CA-006" in fired(minimal, cfg)) is fires


@pytest.mark.parametrize("days,fires", [(30, False), (31, True), (0, True)])
def test_anyone_link_expiration_boundary(minimal, cfg, days, fires):
    minimal["sharepoint"].update(sharingCapability="ExternalUserAndGuestSharing",
                                 anyoneLinkExpirationDays=days)
    assert ("M365-COL-004" in fired(minimal, cfg)) is fires


def test_anyone_default_link_type_flagged(minimal, cfg):
    minimal["sharepoint"].update(sharingCapability="ExternalUserAndGuestSharing",
                                 anyoneLinkExpirationDays=7, defaultSharingLinkType="AnonymousAccess")
    assert "M365-COL-004" in fired(minimal, cfg)


def test_security_defaults_satisfy_mfa_and_legacy_checks(minimal, cfg):
    minimal["securityDefaults"]["enabled"] = True
    minimal["conditionalAccessPolicies"] = []
    minimal["tenant"]["entraIdP2"] = False  # risk policies need P2
    assert fired(minimal, cfg) == {}


def test_risk_policies_only_evaluated_with_p2(minimal, cfg):
    _drop_pol(minimal, "CA04 sign-in risk")
    _drop_pol(minimal, "CA05 user risk")
    assert "M365-CA-005" in fired(minimal, cfg)
    minimal["tenant"]["entraIdP2"] = False
    assert "M365-CA-005" not in fired(minimal, cfg)


def test_report_only_policy_does_not_protect(minimal, cfg):
    _pol(minimal, "CA02 legacy")["state"] = "enabledForReportingButNotEnforced"
    f = fired(minimal, cfg)
    assert {"M365-CA-004", "M365-CA-006"} <= set(f)
    assert any("non appliquée" in e for e in f["M365-CA-004"].evidence)


def test_legacy_policy_must_cover_both_client_types(minimal, cfg):
    _pol(minimal, "CA02 legacy")["clientAppTypes"] = ["exchangeActiveSync"]
    assert "M365-CA-004" in fired(minimal, cfg)


def test_mfa_policy_limited_to_some_apps_is_partial(minimal, cfg):
    _pol(minimal, "CA03 mfa all")["includeApplications"] = ["Office365"]
    f = fired(minimal, cfg)
    assert "M365-CA-002" in f and any("partielles" in e for e in f["M365-CA-002"].evidence)


def test_admin_without_any_mfa_method(minimal, cfg):
    _user(minimal, ADM)["authMethods"] = []
    f = fired(minimal, cfg)
    assert "M365-CA-003" in f and "M365-ACC-005" in f


def test_sso_password_expiration_zero_ok_and_one_flagged(minimal, cfg):
    minimal["passwordPolicy"]["expirationDays"] = 1
    assert "M365-ACC-004" in fired(minimal, cfg)


def test_sspr_disabled_not_flagged(minimal, cfg):
    minimal["sspr"].update(enabled="none", methodsRequired=1, methods=["securityQuestions"])
    assert "M365-ACC-003" not in fired(minimal, cfg)


def test_sspr_security_questions_flagged(minimal, cfg):
    minimal["sspr"]["methods"].append("securityQuestions")
    assert "M365-ACC-003" in fired(minimal, cfg)


def test_guest_users_not_required_to_have_mfa_registration(minimal, cfg):
    minimal["users"].append(_u("g#EXT#@test.onmicrosoft.com", userType="Guest", authMethods=[]))
    assert "M365-ACC-005" not in fired(minimal, cfg)


def test_verified_admin_consented_app_is_accepted(minimal, cfg):
    _add_app(minimal, publisherVerified=True,
             permissions=[{"name": "Mail.Read", "type": "Application"}])
    assert "M365-APP-002" not in fired(minimal, cfg)


def test_verified_but_user_consented_app_flagged(minimal, cfg):
    _add_app(minimal, publisherVerified=True, consentedBy=U1,
             permissions=[{"name": "Mail.ReadWrite", "type": "Delegated", "consentType": "Principal"}])
    assert "M365-APP-002" in fired(minimal, cfg)


def test_low_privilege_unverified_app_not_flagged(minimal, cfg):
    _add_app(minimal, permissions=[{"name": "User.Read", "type": "Delegated"}])
    assert "M365-APP-002" not in fired(minimal, cfg)


def test_first_party_app_ignored(minimal, cfg):
    _add_app(minimal, isMicrosoftFirstParty=True)
    assert "M365-APP-002" not in fired(minimal, cfg)


def test_permission_names_case_insensitive(minimal, cfg):
    _add_app(minimal, permissions=[{"name": "mail.readwrite", "type": "Delegated"}])
    assert "M365-APP-002" in fired(minimal, cfg)


@pytest.mark.parametrize("spf,fires", [
    ("v=spf1 include:spf.protection.outlook.com -all", False),
    ("v=spf1 include:spf.protection.outlook.com ~all", False),
    ("v=spf1 include:spf.protection.outlook.com ?all", True),
    ("v=spf1 include:spf.protection.outlook.com +all", True),
    ("v=spf1 include:spf.protection.outlook.com", True),
    ("", True),
])
def test_spf_strictness(minimal, cfg, spf, fires):
    minimal["domains"][1]["spfRecord"] = spf
    assert ("M365-COL-002" in fired(minimal, cfg)) is fires


def test_onmicrosoft_domain_not_checked_for_dmarc(minimal, cfg):
    assert minimal["domains"][0].get("dmarcPolicy") is None
    assert "M365-COL-002" not in fired(minimal, cfg)


def test_auto_forwarding_automatic_is_accepted(minimal, cfg):
    minimal["exchange"]["autoForwardingMode"] = "Automatic"
    assert "M365-COL-001" not in fired(minimal, cfg)


def test_teams_consumer_access_alone_flagged(minimal, cfg):
    minimal["teams"]["consumerAccess"] = True
    assert "M365-COL-003" in fired(minimal, cfg)


def test_break_glass_requirements(minimal, cfg):
    _user(minimal, BG2)["accountEnabled"] = False
    f = fired(minimal, cfg)
    assert "M365-PRIV-004" in f and "1 compte(s) break-glass" in f["M365-PRIV-004"].evidence[0]


def test_break_glass_must_be_global_admin(minimal, cfg):
    minimal["directoryRoleAssignments"] = [a for a in minimal["directoryRoleAssignments"]
                                           if a["principal"] != BG2]
    minimal["directoryRoleAssignments"].append(
        {"roleName": "Global Administrator", "principal": "adm.z@test.onmicrosoft.com",
         "assignmentType": "eligible"})
    minimal["users"].append(_u("adm.z@test.onmicrosoft.com"))
    f = fired(minimal, cfg)
    assert any(BG2 in e and "Global Administrator" in e for e in f["M365-PRIV-004"].evidence)


def test_privileged_role_with_end_date_not_permanent(minimal, cfg):
    minimal["users"].append(_u("adm.t@test.onmicrosoft.com"))
    minimal["directoryRoleAssignments"].append(
        {"roleName": "Exchange Administrator", "principal": "adm.t@test.onmicrosoft.com",
         "endDateTime": "2026-10-30T00:00:00Z"})
    assert "M365-PRIV-002" not in fired(minimal, cfg)


def test_admin_synced_from_on_prem_flagged(minimal, cfg):
    _user(minimal, ADM)["onPremisesSyncEnabled"] = True
    f = fired(minimal, cfg)
    assert "M365-PRIV-003" in f and "AD local" in f["M365-PRIV-003"].evidence[0]


def test_policy_excluding_admin_breaks_coverage(minimal, cfg):
    _pol(minimal, "CA01 admins")["excludeUsers"].append(ADM)
    _pol(minimal, "CA03 mfa all")["excludeUsers"].append(ADM)
    assert "M365-CA-003" in fired(minimal, cfg)


def test_quickwins_keep_only_non_quick_findings(cfg):
    from conftest import QUICK
    from m365audit.engine import all_checks as checks
    from m365audit.model import load_export
    effort = {c.id: c.effort for c in checks()}
    remaining = fired(load_export(QUICK), cfg)
    assert remaining and all(effort[i] != "quick" for i in remaining)


def test_evidence_is_capped(minimal, cfg):
    from m365audit.engine import MAX_EVIDENCE
    for i in range(40):
        minimal["users"].append(_u(f"s{i}@test.ma", authMethods=[]))
    f = fired(minimal, cfg)["M365-ACC-005"]
    assert f.affected == 40 and len(f.evidence) == MAX_EVIDENCE + 1
    assert "autre(s)" in f.evidence[-1]


def test_risk_conditioned_mfa_policy_is_not_baseline_mfa(minimal, cfg):
    # regression: a "user risk = high -> MFA" policy must not count as "MFA for everyone"
    _drop_pol(minimal, "CA03 mfa all")
    _drop_pol(minimal, "CA01 admins")
    f = fired(minimal, cfg)
    assert {"M365-CA-002", "M365-CA-003"} <= set(f)
