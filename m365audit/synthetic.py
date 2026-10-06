"""Deterministic SYNTHETIC Microsoft 365 / Entra ID exports for the fictional SME "AgriSouss SARL".

All names, accounts, domains, application IDs and tenant IDs below are invented. Nothing comes
from a real tenant. The same seed always produces byte-identical files, so tests can rely on them.

Three exports are produced from one base:
- agrisouss_m365_vulnerable.json : the tenant "as found", with realistic SME weaknesses
- agrisouss_m365_quickwins.json  : vulnerable + only the "quick win" fixes applied
- agrisouss_m365_hardened.json   : vulnerable + every fix applied (all checks silent)

Each fix is keyed by the check id it remediates, so the quick-wins export is built from the
same `effort` buckets as the remediation plan. Fixes are applied in check-id order and are
written so that any subset can be applied (they never assume another fix ran before).
"""
from __future__ import annotations

import copy
import json
import os
import random

SEED = 20261005
EXPORTED_AT = "2026-09-30T08:00:00Z"
TENANT_DOMAIN = "agrisouss.onmicrosoft.com"
MAIL_DOMAIN = "agrisouss.ma"
EXPORT_DOMAIN = "agrisouss-export.com"

FIRST = ["Youssef", "Fatima", "Khadija", "Hassan", "Aicha", "Omar", "Salma", "Rachid",
         "Nadia", "Karim", "Imane", "Brahim", "Leila", "Hamid", "Zineb", "Said", "Meryem",
         "Abdellah", "Samira", "Mustapha", "Houda", "Driss", "Siham", "Anas", "Ghizlane",
         "Yassine", "Hajar", "Ayoub", "Soukaina", "Hicham"]
LAST = ["Benali", "Idrissi", "Bakkali", "Alaoui", "Berrada", "Chraibi", "Haddad",
        "Ait Lahcen", "Ouali", "Bouzid", "Lahlou", "Naciri", "Zahiri", "Ait Baha", "Belkadi",
        "Mansouri", "Ouazzani", "Rami", "Sabri", "Tahiri", "Ziani", "Moussaoui", "Kettani"]
BP = "O365_BUSINESS_PREMIUM"  # licence label used in the synthetic data


def _d(y, m, day, h=9):
    return f"{y:04d}-{m:02d}-{day:02d}T{h:02d}:00:00Z"


def _upn(first, last, domain=MAIL_DOMAIN):
    return f"{first[0].lower()}.{last.lower().replace(' ', '')}@{domain}"


def _user(upn, display, *, last=_d(2026, 9, 29), created=_d(2023, 2, 1), methods=None,
          mailbox=True, licenses=(BP,), **kw):
    u = {
        "userPrincipalName": upn, "displayName": display, "accountEnabled": True,
        "userType": "Member", "createdDateTime": created, "lastSignInDateTime": last,
        "onPremisesSyncEnabled": True, "assignedLicenses": list(licenses),
        "hasMailbox": mailbox, "authMethods": list(methods or []), "isBreakGlass": False,
    }
    u.update(kw)
    return u


# Named accounts that the checks and tests rely on.
DIRECTOR = "h.alaoui@agrisouss.ma"
IT_ADMIN = "y.benali@agrisouss.ma"
IT_ADMIN2 = "k.idrissi@agrisouss.ma"
ACCOUNTANT = "f.bakkali@agrisouss.ma"
CONSULTANT = "s.mansouri@agrisouss.ma"
BREAK_GLASS_1 = f"bg.secours1@{TENANT_DOMAIN}"
BREAK_GLASS_2 = f"bg.secours2@{TENANT_DOMAIN}"
SCANNER = "scanner@agrisouss.ma"


def base_tenant() -> dict:
    """The vulnerable AgriSouss tenant (every check fires)."""
    rnd = random.Random(SEED)
    users = [
        _user(DIRECTOR, "Hassan Alaoui (Gérant)", methods=["sms"]),
        _user(IT_ADMIN, "Youssef Benali (IT)", methods=["microsoftAuthenticator"]),
        _user(IT_ADMIN2, "Khadija Idrissi (IT)", methods=[]),
        _user(ACCOUNTANT, "Fatima Bakkali (Comptabilité)", methods=["sms"]),
        _user(CONSULTANT, "Said Mansouri (prestataire IT)", methods=[], onPremisesSyncEnabled=False),
        _user(BREAK_GLASS_1, "Compte de secours 1", last=_d(2026, 1, 15), mailbox=False,
              licenses=(), methods=["fido2"], onPremisesSyncEnabled=False, isBreakGlass=True),
        _user(SCANNER, "Scanner multifonction", methods=[], licenses=(BP,)),
        # stale accounts (checked by M365-ACC-002)
        _user("i.naciri@agrisouss.ma", "Imane Naciri (ex-stagiaire)", last=_d(2025, 8, 30),
              methods=["sms"]),
        _user("b.zahiri@agrisouss.ma", "Brahim Zahiri (parti)", last=None, created=_d(2025, 3, 1)),
        _user("partner_logistique.example#EXT#@agrisouss.onmicrosoft.com",
              "Contact transporteur (invité)", last=_d(2025, 11, 2), userType="Guest",
              licenses=(), mailbox=False, onPremisesSyncEnabled=False),
        _user("audit.cabinet.example#EXT#@agrisouss.onmicrosoft.com", "Cabinet d'audit (invité)",
              last=_d(2026, 9, 10), userType="Guest", licenses=(), mailbox=False,
              onPremisesSyncEnabled=False),
    ]
    taken = {u["userPrincipalName"] for u in users}
    choices = [["microsoftAuthenticator"], ["microsoftAuthenticator", "sms"], ["sms"], [],
               ["microsoftAuthenticator"], ["voice"], ["microsoftAuthenticator", "softwareOath"]]
    while len(users) < 34:
        f, l = rnd.choice(FIRST), rnd.choice(LAST)
        upn = _upn(f, l)
        if upn in taken:
            continue
        taken.add(upn)
        users.append(_user(upn, f"{f} {l}", last=_d(2026, 9, rnd.randint(1, 29), rnd.randint(7, 18)),
                           created=_d(rnd.randint(2021, 2025), rnd.randint(1, 12), rnd.randint(1, 28)),
                           methods=rnd.choice(choices)))

    def ra(role, principal, **kw):
        a = {"roleName": role, "principal": principal, "principalType": "user",
             "assignmentType": "active", "endDateTime": None}
        a.update(kw)
        return a

    return {
        "schemaVersion": "1.0",
        "exportedAt": EXPORTED_AT,
        "tenant": {"id": "00000000-aaaa-4bbb-8ccc-000000000001", "defaultDomain": TENANT_DOMAIN,
                   "displayName": "AgriSouss SARL", "licenses": [BP, "AAD_PREMIUM_P2"],
                   "entraIdP1": True, "entraIdP2": True},
        "securityDefaults": {"enabled": False},
        "conditionalAccessPolicies": [
            {"displayName": "CA10 - MFA tous les utilisateurs (test)",
             "state": "enabledForReportingButNotEnforced", "includeUsers": ["All"],
             "excludeUsers": [BREAK_GLASS_1, DIRECTOR, ACCOUNTANT, SCANNER],
             "includeApplications": ["All"], "clientAppTypes": ["all"], "grantControls": ["mfa"]},
            {"displayName": "CA11 - Bloquer l'authentification héritée (brouillon)",
             "state": "disabled", "includeUsers": ["All"], "excludeUsers": [BREAK_GLASS_1],
             "includeApplications": ["All"], "clientAppTypes": ["exchangeActiveSync", "other"],
             "grantControls": ["block"]},
        ],
        "users": users,
        "directoryRoleAssignments": [
            ra("Global Administrator", DIRECTOR), ra("Global Administrator", IT_ADMIN),
            ra("Global Administrator", IT_ADMIN2), ra("Global Administrator", ACCOUNTANT),
            ra("Global Administrator", CONSULTANT), ra("Global Administrator", BREAK_GLASS_1),
            ra("Exchange Administrator", IT_ADMIN),
        ],
        "authorizationPolicy": {"userConsent": "allowAll", "guestUserAccess": "sameAsMember",
                                "allowInvitesFrom": "everyone", "usersCanRegisterApps": True},
        "passwordPolicy": {"expirationDays": 90},
        "sspr": {"enabled": "all", "methodsRequired": 1, "methods": ["email", "sms", "securityQuestions"]},
        "audit": {"unifiedAuditLogEnabled": False, "mailboxAuditByDefault": False,
                  "auditBypassMailboxes": [SCANNER]},
        "exchange": {"autoForwardingMode": "On", "remoteDomainAutoForward": True},
        "domains": [
            {"name": TENANT_DOMAIN, "isDefault": False, "dkimEnabled": True,
             "dmarcPolicy": None, "spfRecord": "v=spf1 include:spf.protection.outlook.com -all"},
            {"name": MAIL_DOMAIN, "isDefault": True, "dkimEnabled": False, "dmarcPolicy": "none",
             "spfRecord": "v=spf1 include:spf.protection.outlook.com ?all"},
            {"name": EXPORT_DOMAIN, "isDefault": False, "dkimEnabled": False,
             "dmarcPolicy": None, "spfRecord": ""},
        ],
        "applications": [
            {"displayName": "Microsoft Teams", "appId": "11111111-2222-4333-8444-555555555500",
             "isMicrosoftFirstParty": True, "publisherVerified": True,
             "permissions": [{"name": "Files.ReadWrite.All", "type": "Delegated"}]},
            {"displayName": "PDF Convert Express", "appId": "11111111-2222-4333-8444-555555555501",
             "publisherVerified": False, "consentedBy": "f.bakkali@agrisouss.ma",
             "createdDateTime": _d(2026, 6, 3),
             "permissions": [{"name": "Mail.ReadWrite", "type": "Delegated", "consentType": "Principal"},
                             {"name": "Files.ReadWrite.All", "type": "Delegated", "consentType": "Principal"},
                             {"name": "offline_access", "type": "Delegated", "consentType": "Principal"}]},
            {"displayName": "SyncCRM Connector", "appId": "11111111-2222-4333-8444-555555555502",
             "publisherVerified": False, "consentedBy": IT_ADMIN, "createdDateTime": _d(2024, 4, 9),
             "permissions": [{"name": "Directory.ReadWrite.All", "type": "Application"},
                             {"name": "User.Read.All", "type": "Application"}]},
            {"displayName": "SauvegardePlus M365 Backup", "appId": "11111111-2222-4333-8444-555555555503",
             "publisherVerified": True, "consentedBy": IT_ADMIN, "createdDateTime": _d(2025, 1, 20),
             "permissions": [{"name": "Mail.Read", "type": "Application"},
                             {"name": "Sites.ReadWrite.All", "type": "Application"}]},
        ],
        "teams": {"externalAccess": "allowAll", "allowedDomains": [], "consumerAccess": True},
        "sharepoint": {"sharingCapability": "ExternalUserAndGuestSharing",
                       "anyoneLinkExpirationDays": 0, "defaultSharingLinkType": "AnonymousAccess"},
        "monitoring": {"breakGlassSignInAlert": False},
    }


# ------------------------------------------------------------------------------- fixes
def _policy(t, name):
    return next((p for p in t["conditionalAccessPolicies"] if p["displayName"] == name), None)


def _add_policy(t, policy):
    if _policy(t, policy["displayName"]) is None:
        t["conditionalAccessPolicies"].append(policy)


def _users(t):
    return {u["userPrincipalName"]: u for u in t["users"]}


ADMIN_ROLES_CA = ["Global Administrator", "Privileged Role Administrator", "Security Administrator",
                  "Exchange Administrator", "SharePoint Administrator", "User Administrator",
                  "Billing Administrator", "Conditional Access Administrator"]


def fix_ca_001(t):
    _add_policy(t, {"displayName": "CA01 - MFA pour les rôles d'administration", "state": "enabled",
                    "includeRoles": ADMIN_ROLES_CA, "excludeUsers": [BREAK_GLASS_1, BREAK_GLASS_2],
                    "includeApplications": ["All"], "clientAppTypes": ["all"],
                    "grantControls": ["mfa"]})


def fix_ca_002(t):
    _add_policy(t, {"displayName": "CA03 - MFA tous les utilisateurs", "state": "enabled",
                    "includeUsers": ["All"], "excludeUsers": [BREAK_GLASS_1, BREAK_GLASS_2],
                    "includeApplications": ["All"], "clientAppTypes": ["all"],
                    "grantControls": ["mfa"]})


def fix_ca_003(t):
    fix_ca_001(t)
    users = _users(t)
    for a in t["directoryRoleAssignments"]:
        u = users.get(a["principal"])
        if u is not None and not u["isBreakGlass"]:
            u["authMethods"] = sorted(set(u["authMethods"]) | {"microsoftAuthenticator"})


def fix_ca_004(t):
    p = _policy(t, "CA11 - Bloquer l'authentification héritée (brouillon)")
    if p is not None:
        p["displayName"] = "CA02 - Bloquer l'authentification héritée"
        p["state"] = "enabled"
    _add_policy(t, {"displayName": "CA02 - Bloquer l'authentification héritée", "state": "enabled",
                    "includeUsers": ["All"], "excludeUsers": [BREAK_GLASS_1],
                    "includeApplications": ["All"], "clientAppTypes": ["exchangeActiveSync", "other"],
                    "grantControls": ["block"]})


def fix_ca_005(t):
    _add_policy(t, {"displayName": "CA04 - Risque de connexion élevé : bloquer", "state": "enabled",
                    "includeUsers": ["All"], "excludeUsers": [BREAK_GLASS_1, BREAK_GLASS_2],
                    "includeApplications": ["All"], "signInRiskLevels": ["high"],
                    "grantControls": ["block"]})
    _add_policy(t, {"displayName": "CA05 - Risque utilisateur élevé : changement de mot de passe",
                    "state": "enabled", "includeUsers": ["All"],
                    "excludeUsers": [BREAK_GLASS_1, BREAK_GLASS_2], "includeApplications": ["All"],
                    "userRiskLevels": ["high"], "grantControls": ["mfa", "passwordChange"]})


def fix_ca_006(t):
    t["conditionalAccessPolicies"] = [p for p in t["conditionalAccessPolicies"]
                                      if p["state"] != "enabledForReportingButNotEnforced"]


def fix_priv_001(t):
    downgrade = {DIRECTOR: None, IT_ADMIN2: "User Administrator",
                 ACCOUNTANT: "Billing Administrator", CONSULTANT: "Exchange Administrator"}
    kept = []
    for a in t["directoryRoleAssignments"]:
        if a["roleName"] == "Global Administrator" and a["principal"] in downgrade:
            new_role = downgrade[a["principal"]]
            if new_role:
                kept.append(dict(a, roleName=new_role))
            continue
        kept.append(a)
    t["directoryRoleAssignments"] = kept


def fix_priv_002(t):
    users = _users(t)
    for a in t["directoryRoleAssignments"]:
        u = users.get(a["principal"])
        if u is None or not u["isBreakGlass"]:
            a["assignmentType"] = "eligible"


def fix_priv_003(t):
    """Move every privileged role to a dedicated cloud-only admin account."""
    users = _users(t)
    for a in t["directoryRoleAssignments"]:
        u = users.get(a["principal"])
        if u is None or u["isBreakGlass"]:
            continue
        local = a["principal"].split("@")[0]
        adm = f"adm.{local}@{TENANT_DOMAIN}"
        if adm not in users:
            users[adm] = _user(adm, f"Admin - {u['displayName']}", mailbox=False, licenses=(),
                               methods=["fido2", "microsoftAuthenticator"],
                               onPremisesSyncEnabled=False, created=_d(2026, 9, 15))
            t["users"].append(users[adm])
        a["principal"] = adm


def fix_priv_004(t):
    users = _users(t)
    if BREAK_GLASS_2 not in users:
        t["users"].append(_user(BREAK_GLASS_2, "Compte de secours 2", last=_d(2026, 1, 15),
                                mailbox=False, licenses=(), methods=["fido2"],
                                onPremisesSyncEnabled=False, isBreakGlass=True))
        t["directoryRoleAssignments"].append(
            {"roleName": "Global Administrator", "principal": BREAK_GLASS_2,
             "principalType": "user", "assignmentType": "active", "endDateTime": None})
    t["monitoring"]["breakGlassSignInAlert"] = True


def fix_acc_001(t):
    t["authorizationPolicy"].update(guestUserAccess="limited", allowInvitesFrom="adminsAndGuestInviters")


STALE = {"i.naciri@agrisouss.ma", "b.zahiri@agrisouss.ma",
         "partner_logistique.example#EXT#@agrisouss.onmicrosoft.com"}


def fix_acc_002(t):
    for u in t["users"]:
        if u["userPrincipalName"] in STALE:
            u["accountEnabled"] = False


def fix_acc_003(t):
    t["sspr"].update(methodsRequired=2, methods=["microsoftAuthenticator", "sms", "email"])


def fix_acc_004(t):
    t["passwordPolicy"]["expirationDays"] = 0


def fix_acc_005(t):
    for u in t["users"]:
        if u["userType"] == "Member" and not u["isBreakGlass"]:
            u["authMethods"] = sorted(set(u["authMethods"]) | {"microsoftAuthenticator"})


def fix_app_001(t):
    t["authorizationPolicy"]["userConsent"] = "allowVerifiedLowRisk"


def fix_app_002(t):
    t["applications"] = [a for a in t["applications"] if a["displayName"] != "PDF Convert Express"]
    for a in t["applications"]:
        if a["displayName"] == "SyncCRM Connector":
            a["permissions"] = [{"name": "User.Read.All", "type": "Application"}]


def fix_app_003(t):
    t["authorizationPolicy"]["usersCanRegisterApps"] = False


def fix_log_001(t):
    t["audit"]["unifiedAuditLogEnabled"] = True


def fix_log_002(t):
    t["audit"].update(mailboxAuditByDefault=True, auditBypassMailboxes=[])


def fix_col_001(t):
    t["exchange"].update(autoForwardingMode="Off", remoteDomainAutoForward=False)


def fix_col_002(t):
    for d in t["domains"]:
        d.update(dkimEnabled=True, dmarcPolicy="reject",
                 spfRecord="v=spf1 include:spf.protection.outlook.com -all")


def fix_col_003(t):
    t["teams"].update(externalAccess="allowList", allowedDomains=["transporteur-souss.example"],
                      consumerAccess=False)


def fix_col_004(t):
    t["sharepoint"].update(sharingCapability="ExistingExternalUserSharingOnly",
                           anyoneLinkExpirationDays=30, defaultSharingLinkType="Direct")


FIXES = {
    "M365-CA-001": fix_ca_001, "M365-CA-002": fix_ca_002, "M365-CA-003": fix_ca_003,
    "M365-CA-004": fix_ca_004, "M365-CA-005": fix_ca_005, "M365-CA-006": fix_ca_006,
    "M365-PRIV-001": fix_priv_001, "M365-PRIV-002": fix_priv_002,
    "M365-PRIV-003": fix_priv_003, "M365-PRIV-004": fix_priv_004,
    "M365-ACC-001": fix_acc_001, "M365-ACC-002": fix_acc_002, "M365-ACC-003": fix_acc_003,
    "M365-ACC-004": fix_acc_004, "M365-ACC-005": fix_acc_005,
    "M365-APP-001": fix_app_001, "M365-APP-002": fix_app_002, "M365-APP-003": fix_app_003,
    "M365-LOG-001": fix_log_001, "M365-LOG-002": fix_log_002,
    "M365-COL-001": fix_col_001, "M365-COL-002": fix_col_002, "M365-COL-003": fix_col_003,
    "M365-COL-004": fix_col_004,
}


def apply_fixes(data: dict, check_ids) -> dict:
    out = copy.deepcopy(data)
    for cid in sorted(check_ids):
        FIXES[cid](out)
    return out


def build_all() -> dict[str, dict]:
    from .engine import all_checks
    vuln = base_tenant()
    quick = [c.id for c in all_checks() if c.effort == "quick"]
    return {
        "agrisouss_m365_vulnerable.json": vuln,
        "agrisouss_m365_quickwins.json": apply_fixes(vuln, quick),
        "agrisouss_m365_hardened.json": apply_fixes(vuln, FIXES),
    }


def write_all(folder: str) -> list[str]:
    os.makedirs(folder, exist_ok=True)
    paths = []
    for name, data in build_all().items():
        path = os.path.join(folder, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        paths.append(path)
    return paths
